// Package podwatch maintains bounded, read-only node-local Pod metadata.
package podwatch

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"ztunnel-ebpf-collector/internal/discovery"
)

type Pod struct {
	Metadata struct {
		UID, Name, Namespace, ResourceVersion string
		Labels, Annotations                   map[string]string
		DeletionTimestamp                     *string
	}
	Spec struct {
		NodeName    string
		HostNetwork bool
		Containers  []struct {
			Name  string
			Ports []struct {
				ContainerPort uint16
				Protocol      string
			}
		}
	}
	Status struct {
		Phase, PodIP      string
		ContainerStatuses []struct {
			Name, ContainerID string
			RestartCount      int
			State             struct{ Running *json.RawMessage }
		}
	}
}

const maxBytes = 4 * 1024 * 1024

func Decode(b []byte) (Pod, error) {
	var p Pod
	if len(b) > 256*1024 {
		return p, errors.New("Pod event budget exceeded")
	}
	if err := json.Unmarshal(b, &p); err != nil {
		return p, errors.New("invalid Pod metadata")
	}
	if p.Metadata.UID == "" || p.Metadata.Name == "" || p.Metadata.Namespace == "" {
		return p, errors.New("missing Pod identity")
	}
	return p, nil
}
func (p Pod) Ports() ([]uint16, error) {
	ports := map[uint16]bool{}
	if text, ok := p.Metadata.Annotations["collector.ztunnel.io/ports"]; ok {
		for _, part := range strings.Split(text, ",") {
			n, e := strconv.ParseUint(part, 10, 16)
			if e != nil || n == 0 || strconv.FormatUint(n, 10) != part || ports[uint16(n)] {
				return nil, errors.New("invalid collector ports annotation")
			}
			ports[uint16(n)] = true
		}
	} else {
		for _, c := range p.Spec.Containers {
			for _, port := range c.Ports {
				if (port.Protocol == "" || port.Protocol == "TCP") && port.ContainerPort > 0 {
					ports[port.ContainerPort] = true
				}
			}
		}
	}
	if len(ports) > 32 {
		return nil, errors.New("Pod port budget exceeded")
	}
	out := make([]uint16, 0, len(ports))
	for n := range ports {
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}
func (p Pod) Selected(node string, namespaces []string, key, value string) bool {
	return p.Spec.NodeName == node && slices.Contains(namespaces, p.Metadata.Namespace) && p.Metadata.Labels[key] == value && p.Metadata.DeletionTimestamp == nil && p.Status.Phase == "Running" && !p.Spec.HostNetwork && p.Status.PodIP != ""
}
func (p Pod) Processes() []discovery.Pod {
	var out []discovery.Pod
	if p.Status.Phase != "Running" || p.Metadata.DeletionTimestamp != nil {
		return out
	}
	for _, c := range p.Status.ContainerStatuses {
		if c.State.Running != nil {
			out = append(out, discovery.Pod{UID: p.Metadata.UID, Name: p.Metadata.Name, Namespace: p.Metadata.Namespace, Node: p.Spec.NodeName, IP: p.Status.PodIP, ContainerID: c.ContainerID})
		}
	}
	return out
}

type Cache struct {
	client          *http.Client
	base, node      string
	token           func() (string, error)
	mu              sync.RWMutex
	pods            map[string]Pod
	sizes           map[string]int
	valid           bool
	versions        map[string]peerVersion
	serial          uint64
	resourceVersion string
}

func New(client *http.Client, base, node string, token func() (string, error)) *Cache {
	return &Cache{client: client, base: base, node: node, token: token}
}

// Peer identity never uses labels, annotations or declared listening ports.
// Local discovery needs only the collector's port override annotation.
func (c *Cache) project(p Pod) Pod {
	if c.node == "" {
		p.Metadata.Labels = nil
		p.Metadata.Annotations = nil
		p.Spec.Containers = nil
	} else if ports, ok := p.Metadata.Annotations["collector.ztunnel.io/ports"]; ok {
		p.Metadata.Annotations = map[string]string{"collector.ztunnel.io/ports": ports}
	} else {
		p.Metadata.Annotations = nil
	}
	return p
}
func (c *Cache) Snapshot() ([]Pod, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.valid {
		return nil, false
	}
	out := make([]Pod, 0, len(c.pods))
	for _, p := range c.pods {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Metadata.UID < out[j].Metadata.UID })
	return out, true
}
func (c *Cache) invalidate() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.valid = false
	c.resourceVersion = ""
	c.pods = nil
	c.sizes = nil
	c.versions = nil
}
func (c *Cache) Run(ctx context.Context) {
	defer c.invalidate()
	failures := 0
	for ctx.Err() == nil {
		err := c.cycle(ctx)
		if err != nil {
			c.invalidate()
			failures = min(failures+1, 5)
		} else {
			failures = 0
		}
		delay := time.Second
		if err != nil {
			base := min(5*time.Second<<uint(failures-1), time.Minute)
			delay = base + time.Duration(rand.Int64N(int64(base/5)+1))
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
func (c *Cache) get(ctx context.Context, q url.Values) (*http.Response, error) {
	if c.node != "" {
		q.Set("fieldSelector", "spec.nodeName="+c.node)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/api/v1/pods?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	token, err := c.token()
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(token))
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("Pod API status %d", resp.StatusCode)
	}
	return resp, nil
}
func (c *Cache) cycle(ctx context.Context) error {
	c.mu.RLock()
	rv, valid := c.resourceVersion, c.valid
	c.mu.RUnlock()
	if !valid || rv == "" {
		var err error
		rv, err = c.list(ctx)
		if err != nil {
			return err
		}
	}
	watchCtx, stop := context.WithTimeout(ctx, 35*time.Second)
	defer stop()
	resp, err := c.get(watchCtx, url.Values{"watch": {"true"}, "resourceVersion": {rv}, "timeoutSeconds": {"30"}, "allowWatchBookmarks": {"true"}})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	watchStarted := time.Now()
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 4096), 256*1024)
	for scanner.Scan() {
		var event struct {
			Type   string
			Object json.RawMessage
		}
		if json.Unmarshal(scanner.Bytes(), &event) != nil {
			return errors.New("invalid watch event")
		}
		if event.Type == "BOOKMARK" {
			var bookmark struct {
				Metadata struct{ ResourceVersion string }
			}
			if json.Unmarshal(event.Object, &bookmark) != nil || bookmark.Metadata.ResourceVersion == "" {
				return errors.New("invalid watch bookmark")
			}
			c.mu.Lock()
			c.resourceVersion = bookmark.Metadata.ResourceVersion
			c.mu.Unlock()
			continue
		}
		if event.Type != "ADDED" && event.Type != "MODIFIED" && event.Type != "DELETED" {
			return errors.New("watch reset required")
		}
		p, e := Decode(event.Object)
		if e != nil {
			return e
		}
		if c.node != "" && p.Spec.NodeName != c.node {
			return errors.New("watch node filter violated")
		}
		p = c.project(p)
		compact, _ := json.Marshal(p)
		if e = c.apply(event.Type, p, len(compact)); e != nil {
			return e
		}
		if p.Metadata.ResourceVersion != "" {
			c.mu.Lock()
			c.resourceVersion = p.Metadata.ResourceVersion
			c.mu.Unlock()
		}
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if time.Since(watchStarted) < 25*time.Second {
		return errors.New("watch disconnected before server timeout")
	}
	return nil
}
func (c *Cache) apply(kind string, p Pod, size int) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if kind == "DELETED" {
		delete(c.pods, p.Metadata.UID)
		delete(c.sizes, p.Metadata.UID)
		delete(c.versions, p.Metadata.UID)
		return nil
	}
	total := size
	for uid, n := range c.sizes {
		if uid != p.Metadata.UID {
			total += n
		}
	}
	if total > maxBytes || (len(c.pods) >= 2048 && c.pods[p.Metadata.UID].Metadata.UID == "") {
		return errors.New("Pod cache budget exceeded")
	}
	c.version(p)
	c.pods[p.Metadata.UID] = p
	c.sizes[p.Metadata.UID] = size
	return nil
}

func (c *Cache) Pod(uid string) (Pod, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	p, ok := c.pods[uid]
	return p, ok && c.valid
}

// Stage a complete bounded snapshot before publishing. Old+new compact caches
// are each <=4MiB; one page is <=4MiB, at most 2048 identities and 64 pages.
func (c *Cache) list(ctx context.Context) (string, error) {
	listCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	pods := map[string]Pod{}
	sizes := map[string]int{}
	token, rv := "", ""
	total := 0
	seen := map[string]bool{}
	for page := 0; page < 64; page++ {
		q := url.Values{"limit": {"128"}}
		if token != "" {
			q.Set("continue", token)
		}
		resp, err := c.get(listCtx, q)
		if err != nil {
			return "", err
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
		resp.Body.Close()
		if err != nil {
			return "", err
		}
		if len(b) > maxBytes {
			return "", errors.New("Pod page budget exceeded")
		}
		var list struct {
			Metadata struct{ ResourceVersion, Continue string }
			Items    []json.RawMessage
		}
		if json.Unmarshal(b, &list) != nil || list.Metadata.ResourceVersion == "" {
			return "", errors.New("invalid Pod list")
		}
		if rv != "" && rv != list.Metadata.ResourceVersion {
			return "", errors.New("inconsistent Pod snapshot")
		}
		rv = list.Metadata.ResourceVersion
		for _, raw := range list.Items {
			p, err := Decode(raw)
			if err != nil {
				return "", err
			}
			if c.node != "" && p.Spec.NodeName != c.node {
				return "", errors.New("node filter violated")
			}
			if _, ok := pods[p.Metadata.UID]; ok {
				return "", errors.New("duplicate Pod identity")
			}
			p = c.project(p)
			compact, _ := json.Marshal(p)
			total += len(compact)
			if len(pods) >= 2048 || total > maxBytes {
				return "", errors.New("Pod cache budget exceeded")
			}
			pods[p.Metadata.UID] = p
			sizes[p.Metadata.UID] = len(compact)
		}
		token = list.Metadata.Continue
		if token == "" {
			c.mu.Lock()
			defer c.mu.Unlock()
			for _, p := range pods {
				c.version(p)
			}
			for uid := range c.versions {
				if _, ok := pods[uid]; !ok {
					delete(c.versions, uid)
				}
			}
			c.pods, c.sizes, c.valid, c.resourceVersion = pods, sizes, true, rv
			return rv, nil
		}
		if seen[token] {
			return "", errors.New("repeated Pod page token")
		}
		seen[token] = true
	}
	return "", errors.New("Pod page count budget exceeded")
}
