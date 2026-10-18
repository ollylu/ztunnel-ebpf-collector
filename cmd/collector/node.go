package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"ztunnel-ebpf-collector/internal/discovery"
	"ztunnel-ebpf-collector/internal/livehttp"
	"ztunnel-ebpf-collector/internal/monotime"
	"ztunnel-ebpf-collector/internal/podwatch"
	"ztunnel-ebpf-collector/internal/replay"
	"ztunnel-ebpf-collector/internal/tcpcapture"
)

const readyPath = "/run/collector/ready"

// A missing or invalid scope must never become an all-namespace selection.
type namespaceFlags []string

var namespaceName = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

func (n *namespaceFlags) String() string { return strings.Join(*n, ",") }
func (n *namespaceFlags) Set(value string) error {
	if len(*n) >= 32 || len(value) > 63 || !namespaceName.MatchString(value) || slices.Contains(*n, value) {
		return errors.New("namespace must be a unique DNS label; at most 32 namespaces")
	}
	*n = append(*n, value)
	return nil
}

func runNode(args []string, out, diag io.Writer) int {
	fs := flag.NewFlagSet("node", flag.ContinueOnError)
	fs.SetOutput(diag)
	node := fs.String("node", "", "local Kubernetes node")
	var namespaces namespaceFlags
	fs.Var(&namespaces, "namespace", "selected business namespace; repeat for multiple (max 32)")
	direction := fs.String("direction", "inbound", "inbound, outbound or both")
	selector := fs.String("selector", "", "required single label key=value")
	header := fs.String("marker-header", "", "request marker header")
	value := fs.String("marker-value", "", "exact marker value")
	if fs.Parse(args) != nil || fs.NArg() != 0 {
		return exitUsage
	}
	key, val, ok := strings.Cut(*selector, "=")
	marker := replay.Marker{Header: *header, Value: *value}
	if (*direction != "inbound" && *direction != "outbound" && *direction != "both") || !ok || key == "" || val == "" || strings.ContainsAny(*selector, " ,\t\n") || strings.Contains(val, "=") || *node == "" || len(namespaces) == 0 || marker.Validate() != nil {
		fmt.Fprintln(diag, "node requires --node, --namespace, --selector key=value and request marker")
		return exitUsage
	}
	host := os.Getenv("KUBERNETES_SERVICE_HOST")
	port := os.Getenv("KUBERNETES_SERVICE_PORT_HTTPS")
	if port == "" {
		port = "443"
	}
	if host == "" {
		fmt.Fprintln(diag, "in-cluster Kubernetes endpoint required")
		return exitInputError
	}
	ca, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
	if err != nil {
		fmt.Fprintln(diag, "Kubernetes CA unavailable")
		return exitInputError
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		fmt.Fprintln(diag, "invalid Kubernetes CA")
		return exitInputError
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, DialContext: (&net.Dialer{Timeout: 3 * time.Second}).DialContext, ResponseHeaderTimeout: 5 * time.Second, IdleConnTimeout: 40 * time.Second, MaxConnsPerHost: 3, DisableCompression: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("API redirect rejected") }}
	cache := podwatch.New(client, "https://"+net.JoinHostPort(host, port), *node, func() (string, error) {
		b, e := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
		return string(b), e
	})
	peers := podwatch.New(client, "https://"+net.JoinHostPort(host, port), "", func() (string, error) {
		b, e := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
		return string(b), e
	})
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	done := make(chan struct{})
	go func() { defer close(done); cache.Run(ctx) }()
	peerDone := make(chan struct{})
	go func() { defer close(peerDone); peers.Run(ctx) }()
	defer func() { stop(); <-done; <-peerDone }()
	bounded, closeOut, err := boundedOutput(out)
	if err != nil {
		fmt.Fprintln(diag, "stdout unavailable")
		return exitInputError
	}
	defer closeOut()
	boundedDiag, closeDiag, err := boundedOutput(diag)
	if err != nil {
		return exitInputError
	}
	defer closeDiag()
	diagnostics := newDiagnosticWriter(boundedDiag)
	defer diagnostics.close()
	diag = diagnostics
	os.Remove(readyPath)
	defer os.Remove(readyPath)
	fmt.Fprintln(diag, "node_waiting source=ztunnel discovery=list-watch")
	for ctx.Err() == nil {
		pods, valid := cache.Snapshot()
		var observer discovery.Process
		if valid {
			var ps []discovery.Pod
			for _, p := range pods {
				ps = append(ps, p.Processes()...)
			}
			scan, cancel := context.WithTimeout(ctx, 3*time.Second)
			found, e := discovery.Find(scan, "/proc", ps, *node)
			cancel()
			if e == nil && len(found) == 1 {
				observer = found[0]
			}
		}
		if observer.PID == 0 {
			if !nodeWait(ctx, 5*time.Second) {
				break
			}
			continue
		}
		err = observeNode(ctx, cache, peers, observer, *node, namespaces, key, val, *direction, marker, bounded, diag)
		os.Remove(readyPath)
		if ctx.Err() != nil {
			break
		}
		if tcpcapture.CanRestartObserver(err) {
			fmt.Fprintln(diag, "node_waiting observer generation ended")
			if !nodeWait(ctx, 5*time.Second) {
				break
			}
			continue
		}
		// A protection trip is latched. Kubernetes must not repeatedly reload a bad
		// probe, overwhelm a slow output consumer, or mask a capture gap with restarts.
		fmt.Fprintln(diag, "node_stopped protection:", err)
		<-ctx.Done()
		break
	}
	fmt.Fprintln(diag, "node_done")
	return exitOK
}
func nodeWait(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func eligible(p podwatch.Pod, b targetBinding, node string, namespaces []string, key, value string) bool {
	if !p.Selected(node, namespaces, key, value) || p.Metadata.UID != b.Process.Pod.UID || p.Status.PodIP != b.Process.Pod.IP {
		return false
	}
	ports, err := p.Ports()
	if b.Endpoint.Outbound {
		if !b.Discovered || b.Endpoint.Server.Port() != 15001 || b.Endpoint.Server.Addr().String() != p.Status.PodIP {
			return false
		}
		ports = nil
		err = nil
	}
	if err != nil {
		return false
	}
	found := len(ports) == 0 && b.Discovered
	for _, port := range ports {
		if port == b.Endpoint.Server.Port() {
			found = true
		}
	}
	if !found {
		return false
	}
	for _, proc := range p.Processes() {
		if proc.ContainerID == b.Process.Pod.ContainerID {
			return true
		}
	}
	return false
}

func observeNode(ctx context.Context, cache, peers *podwatch.Cache, observer discovery.Process, node string, namespaces []string, key, value, direction string, marker replay.Marker, out, diag io.Writer) (result error) {
	a := livehttp.Analyzer{Marker: marker}
	state := targetState{}
	tracker := newPeerTracker()
	sink := newPeerOutput(ctx, out, peers)
	defer func() { result = peerOutputResult(result, sink.close()) }()
	var nextScan time.Time
	ready := false
	continuity := metadataContinuity{}
	lastCount := -1
	outboundScanner := &discovery.OutboundScanner{}
	defer outboundScanner.Close()
	worker := newScanWorker(ctx)
	defer worker.close()
	var scanKey [32]byte
	var scanGeneration uint64
	skipped := map[string]string{} // owned only by the scan worker

	refresh := func() (map[tcpcapture.Endpoint]uint64, error) {
		now := time.Now()
		a.Sweep(now)
		tracker.sweep(monotime.Now())
		pods, valid := cache.Snapshot()
		continuity.observe(valid, diag)
		byUID := map[string]podwatch.Pod{}
		var selected []discovery.Pod
		desired := map[string]targetArgs{}
		if valid {
			for _, p := range pods {
				if !p.Selected(node, namespaces, key, value) {
					continue
				}
				var ports []uint16
				var err error
				if direction != "outbound" {
					ports, err = p.Ports()
				}
				if err != nil {
					continue
				}

				byUID[p.Metadata.UID] = p
				selected = append(selected, p.Processes()...)
				desired[p.Metadata.UID] = nil
				for _, port := range ports {
					desired[p.Metadata.UID] = append(desired[p.Metadata.UID], p.Metadata.Namespace+"/"+p.Metadata.Name+":"+strconv.Itoa(int(port)))
				}
			}
		}
		fingerprint, _ := json.Marshal(struct {
			Valid bool
			Pods  map[string]podwatch.Pod
		}{valid, byUID})
		nextKey := sha256.Sum256(fingerprint)
		if nextKey != scanKey {
			scanKey = nextKey
			scanGeneration++
			nextScan = time.Time{}
		}
		count := 0
		for _, args := range desired {
			count += len(args)
		}
		if count > tcpcapture.MaxTargets {
			return nil, errors.New("selected target budget exhausted (32)")
		}
		retained := []captureTarget{}
		for _, b := range state.bindings {
			p, ok := byUID[b.Process.Pod.UID]
			if !ok || !eligible(p, b, node, namespaces, key, value) || b.Process.Validate("/proc") != nil {
				continue
			}
			retained = append(retained, b.captureTarget)
		}
		// Revoke known-invalid identities before a potentially slow proc scan.
		removed, replaceErr := state.replace(retained)
		if replaceErr != nil {
			return nil, replaceErr
		}
		for _, ep := range removed {
			a.Forget(ep)
			tracker.forget(ep)
		}
		if scanned, ok := worker.poll(scanGeneration); ok && valid {
			if scanned.err != nil {
				if errors.Is(scanned.err, discovery.ErrProcessEnded) {
					return nil, tcpcapture.ErrObserverEnded
				}
				// A bounded discovery timeout leaves validated bindings intact.
				if !errors.Is(scanned.err, context.DeadlineExceeded) {
					return nil, scanned.err
				}
			} else {
				current := scanned.targets[:0]
				for _, target := range scanned.targets {
					p, exists := byUID[target.Process.Pod.UID]
					if exists && eligible(p, targetBinding{captureTarget: target}, node, namespaces, key, value) && target.Process.Validate("/proc") == nil {
						current = append(current, target)
					}
				}
				removed, err := state.replace(current)
				if err != nil {
					return nil, err
				}
				for _, ep := range removed {
					a.Forget(ep)
					tracker.forget(ep)
				}
			}
		}
		if valid && !now.Before(nextScan) {
			job := scanWork{generation: scanGeneration, run: func(parent context.Context) ([]captureTarget, error) {
				scan, cancel := context.WithTimeout(parent, 3*time.Second)
				defer cancel()
				for uid := range skipped {
					if _, ok := byUID[uid]; !ok {
						delete(skipped, uid)
					}
				}
				return scanNodeTargets(scan, "/proc", selected, node, byUID, desired, skipped, diag, observer, direction, outboundScanner)
			}}
			if worker.submit(job) {
				nextScan = now.Add(5 * time.Second)
			}
		}
		if valid && !ready {
			if err := os.WriteFile(readyPath, []byte("ready\n"), 0600); err != nil {
				return nil, err
			}
			ready = true
		}
		if !valid && ready {
			os.Remove(readyPath)
			ready = false
		}
		if len(state.bindings) != lastCount {
			fmt.Fprintf(diag, "node_targets count=%d source=ztunnel\n", len(state.bindings))
			lastCount = len(state.bindings)
		}
		return state.generations(), nil
	}
	cfg := tcpcapture.Config{Suppressions: func() []tcpcapture.Event {
		es := a.DrainSuppressed()
		for _, e := range es {
			tracker.reject(e)
		}
		if len(es) > 0 {
			fmt.Fprintf(diag, "node_connections_rejected count=%d reason=unparseable_connection\n", len(es))
		}
		return es
	}, PID: observer.PID, StartTime: observer.StartTime, Continuous: true, Refresh: refresh, Check: func() error {
		if e := sink.err(); e != nil {
			return e
		}
		if err := observer.Validate("/proc"); err != nil {
			if errors.Is(err, discovery.ErrProcessEnded) {
				return tcpcapture.ErrObserverEnded
			}
			return err
		}
		return nil
	}, Ready: func() { fmt.Fprintf(diag, "node_capture_ready pid=%d source=ztunnel\n", observer.PID) }}
	return tcpcapture.Run(ctx, cfg, func(ev tcpcapture.Event) error {
		ep := ev.Target()
		if !state.accept(ep, ev.Generation) {
			return nil
		}
		b := state.bindings[ep]
		p, valid := cache.Pod(b.Process.Pod.UID)
		if !valid || !eligible(p, b, node, namespaces, key, value) {
			a.Forget(ep)
			tracker.forget(ep)
			return nil
		}
		if ev.Connected || ev.OriginalDestination.IsValid() {
			a.Begin(ev)
		}
		tracker.observe(ev)
		if ev.Connected {
			return nil
		}
		rs, err := a.Push(ev)
		if err != nil {
			return err
		}
		for i, r := range rs {
			r.PodIP = b.Process.Pod.IP
			r.PodName = b.Process.Pod.Name
			r.PodNamespace = b.Process.Pod.Namespace
			r.PodUID = b.Process.Pod.UID
			known := &replay.PodIdentity{IP: r.PodIP, Name: r.PodName, Namespace: r.PodNamespace, UID: r.PodUID}
			unknown := &replay.PodIdentity{IP: "unknown", Name: "unknown", Namespace: "unknown", UID: "unknown"}
			r.ObservationSide = "inbound"
			r.Server = known
			r.Client = unknown
			if ev.Outbound {
				r.ObservationSide = "outbound"
				r.Client = known
				r.Server = unknown
			}
			rs[i] = r
		}
		if len(rs) > 0 {
			return sink.submit(rs, tracker.connection(ev), ev.TimestampNS)
		}
		return nil
	})
}

func scanNodeTargets(ctx context.Context, root string, selected []discovery.Pod, node string, byUID map[string]podwatch.Pod, desired map[string]targetArgs, diagnostics map[string]string, diag io.Writer, observer discovery.Process, direction string, scanners ...*discovery.OutboundScanner) ([]captureTarget, error) {
	workers, err := discovery.FindWorkload(ctx, root, selected, node)
	if err != nil {
		return nil, err
	}
	var outbound map[string]bool
	if direction != "inbound" {
		if len(scanners) > 0 {
			outbound, err = scanners[0].Scan(ctx, root, observer, workers)
		} else {
			outbound, err = discovery.OutboundListeners(ctx, root, observer, workers)
		}
		if err != nil {
			return nil, err
		}
	}
	var result []captureTarget
	for uid, args := range desired {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var candidates []discovery.Process
		for _, w := range workers {
			if w.Pod.UID == uid {
				candidates = append(candidates, w)
			}
		}
		if len(candidates) == 0 {
			continue
		}
		if outbound[uid] {
			p := byUID[uid]
			bound, e := bindCaptureTargets(targetArgs{p.Metadata.Namespace + "/" + p.Metadata.Name + ":15001"}, candidates)
			if e != nil {
				return nil, e
			}
			bound[0].Endpoint.Outbound = true
			bound[0].Discovered = true
			result = append(result, bound[0])
		}
		if direction == "outbound" {
			if !outbound[uid] && diagnostics[uid] != "no_verified_outbound_listener" {
				p := byUID[uid]
				fmt.Fprintf(diag, "node_skipped pod=%s/%s reason=no_verified_outbound_listener\n", p.Metadata.Namespace, p.Metadata.Name)
				diagnostics[uid] = "no_verified_outbound_listener"
			}
			continue
		}
		discovered := len(args) == 0
		if discovered {
			p := byUID[uid]
			ports, e := discovery.ListeningPorts(ctx, root, candidates)
			if e != nil || len(ports) == 0 {
				reason := "no_owned_tcp_listener"
				if e != nil {
					reason = "listener_discovery_unavailable"
				}
				if diagnostics[uid] != reason {
					fmt.Fprintf(diag, "node_skipped pod=%s/%s reason=%s\n", p.Metadata.Namespace, p.Metadata.Name, reason)
					diagnostics[uid] = reason
				}
				continue
			}
			detail := fmt.Sprint(ports)
			if diagnostics[uid] != detail {
				fmt.Fprintf(diag, "node_ports_discovered pod=%s/%s ports=%s\n", p.Metadata.Namespace, p.Metadata.Name, detail)
				diagnostics[uid] = detail
			}
			for _, port := range ports {
				args = append(args, p.Metadata.Namespace+"/"+p.Metadata.Name+":"+strconv.Itoa(int(port)))
			}
		}
		bound, err := bindCaptureTargets(args, candidates)
		if err != nil {
			return nil, err
		}
		for i := range bound {
			bound[i].Discovered = discovered
		}
		result = append(result, bound...)
	}
	return result, ctx.Err()
}
