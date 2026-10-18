package podwatch

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"ztunnel-ebpf-collector/internal/monotime"
)

type Peer struct {
	UID, Name, Namespace, IP string
	Version                  uint64
}
type peerVersion struct {
	fingerprint    string
	version, since uint64
}

func fingerprint(p Pod) string {
	cs := make([]string, 0, len(p.Status.ContainerStatuses))
	for _, c := range p.Status.ContainerStatuses {
		running := ""
		if c.State.Running != nil {
			var v struct {
				StartedAt string `json:"startedAt"`
			}
			_ = json.Unmarshal(*c.State.Running, &v)
			running = "running:" + v.StartedAt
		}
		cs = append(cs, c.Name+"\x00"+c.ContainerID+"\x00"+strconv.Itoa(c.RestartCount)+"\x00"+running)
	}
	sort.Strings(cs)
	b, _ := json.Marshal([]any{p.Metadata.UID, p.Metadata.Name, p.Metadata.Namespace, p.Status.PodIP, p.Spec.NodeName, p.Spec.HostNetwork, p.Status.Phase, p.Metadata.DeletionTimestamp, cs})
	return string(b)
}
func peerEligible(p Pod) bool {
	if p.Status.Phase != "Running" || p.Metadata.DeletionTimestamp != nil || p.Spec.HostNetwork || len(p.Status.ContainerStatuses) == 0 {
		return false
	}
	for _, c := range p.Status.ContainerStatuses {
		if c.ContainerID == "" || c.State.Running == nil {
			return false
		}
	}
	return true
}
func (c *Cache) version(p Pod) {
	if c.versions == nil {
		c.versions = map[string]peerVersion{}
	}
	f := fingerprint(p)
	if old, ok := c.versions[p.Metadata.UID]; ok && old.fingerprint == f {
		return
	}
	c.serial++
	c.versions[p.Metadata.UID] = peerVersion{f, c.serial, monotime.Now()}
}
func (c *Cache) Peer(ip netip.Addr, before uint64) (Peer, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.valid || !ip.Is4() || ip.IsLoopback() || ip.IsUnspecified() || before == 0 {
		return Peer{}, false
	}
	var match Pod
	count := 0
	for _, p := range c.pods {
		if p.Status.PodIP == ip.String() {
			match = p
			count++
		}
	}
	v, ok := c.versions[match.Metadata.UID]
	if count != 1 || !ok || v.since == 0 || v.since > before || !peerEligible(match) {
		return Peer{}, false
	}
	return Peer{match.Metadata.UID, match.Metadata.Name, match.Metadata.Namespace, match.Status.PodIP, v.version}, true
}
func (c *Cache) PeerValid(p Peer) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.valid {
		return false
	}
	live, ok := c.pods[p.UID]
	v := c.versions[p.UID]
	if !ok || v.version != p.Version || !peerEligible(live) || live.Status.PodIP != p.IP {
		return false
	}
	n := 0
	for _, x := range c.pods {
		if x.Status.PodIP == p.IP {
			n++
		}
	}
	return n == 1
}

// Verify confirms a frozen candidate using a fresh API read started after the
// completed pair. It never replaces that candidate with another UID.
func (c *Cache) Verify(ctx context.Context, p Peer, after uint64) bool {
	if !c.PeerValid(p) || after == 0 || monotime.Now() < after {
		return false
	}
	c.mu.RLock()
	f := c.versions[p.UID].fingerprint
	c.mu.RUnlock()
	path := c.base + "/api/v1/namespaces/" + url.PathEscape(p.Namespace) + "/pods/" + url.PathEscape(p.Name)
	req, err := newPeerRequest(ctx, path, c.token)
	if err != nil {
		return false
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return false
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024+1))
	if err != nil {
		return false
	}
	actual, err := Decode(b)
	return err == nil && actual.Metadata.UID == p.UID && fingerprint(actual) == f && c.PeerValid(p)
}

func newPeerRequest(ctx context.Context, path string, token func() (string, error)) (*http.Request, error) {
	r, e := http.NewRequestWithContext(ctx, "GET", path, nil)
	if e != nil {
		return nil, e
	}
	t, e := token()
	if e != nil {
		return nil, e
	}
	if t != "" {
		r.Header.Set("Authorization", "Bearer "+strings.TrimSpace(t))
	}
	return r, nil
}
