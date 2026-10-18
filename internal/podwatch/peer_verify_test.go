package podwatch

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
	"ztunnel-ebpf-collector/internal/monotime"
)

func peerFixture() Pod {
	p, _ := Decode([]byte(`{"metadata":{"uid":"u","name":"app","namespace":"ns"},"spec":{"nodeName":"remote"},"status":{"phase":"Running","podIP":"10.0.0.2","containerStatuses":[{"name":"app","containerID":"container://one","state":{"running":{}}}]}}`))
	return p
}
func TestPeerVerifierRejectsChangeDuringFreshRead(t *testing.T) {
	p := peerFixture()
	body, _ := json.Marshal(p)
	started, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/namespaces/ns/pods/app" {
			t.Error("unexpected API path")
		}
		if calls.Add(1) == 2 {
			close(started)
			<-release
		}
		w.Write(body)
	}))
	defer srv.Close()
	c := New(srv.Client(), srv.URL, "", func() (string, error) { return "", nil })
	c.pods = map[string]Pod{}
	c.sizes = map[string]int{}
	c.valid = true
	_ = c.apply("ADDED", p, len(body))
	peer, ok := c.Peer(netip.MustParseAddr(p.Status.PodIP), ^uint64(0))
	if !ok {
		t.Fatal("peer missing")
	}
	if !c.Verify(context.Background(), peer, monotime.Now()) {
		t.Fatal("unchanged fresh candidate rejected")
	}
	done := make(chan bool, 1)
	go func() { done <- c.Verify(context.Background(), peer, monotime.Now()) }()
	<-started
	p.Status.ContainerStatuses[0].ContainerID = "container://restarted"
	_ = c.apply("MODIFIED", p, len(body))
	close(release)
	if <-done {
		t.Fatal("stale GET response resurrected old container generation")
	}
	duplicate := peerFixture()
	duplicate.Metadata.UID = "other"
	_ = c.apply("ADDED", duplicate, len(body))
	if _, ok := c.Peer(netip.MustParseAddr(p.Status.PodIP), ^uint64(0)); ok {
		t.Fatal("duplicate IP trusted")
	}
}
func TestPeerCacheListHasNoLocalNodeFilter(t *testing.T) {
	p := peerFixture()
	var wrong atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("fieldSelector") != "" {
			wrong.Store(true)
		}
		if r.URL.Query().Get("watch") == "true" {
			w.(http.Flusher).Flush()
			<-r.Context().Done()
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"metadata": map[string]string{"resourceVersion": "1"}, "items": []Pod{p}})
	}))
	defer srv.Close()
	c := New(srv.Client(), srv.URL, "", func() (string, error) { return "", nil })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); c.Run(ctx) }()
	defer func() { cancel(); <-done }()
	end := time.Now().Add(time.Second)
	for time.Now().Before(end) {
		if peer, ok := c.Peer(netip.MustParseAddr(p.Status.PodIP), ^uint64(0)); ok {
			if wrong.Load() || peer.UID != "u" {
				t.Fatal("cross-node filter violated")
			}
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("remote node peer never became available")
}

func TestFreshReadRejectsReusedIPBeforeWatchUpdate(t *testing.T) {
	p := peerFixture()
	actual := p
	actual.Metadata.UID = "replacement"
	body, _ := json.Marshal(actual)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(body) }))
	defer srv.Close()
	c := New(srv.Client(), srv.URL, "", func() (string, error) { return "", nil })
	c.pods = map[string]Pod{}
	c.sizes = map[string]int{}
	c.valid = true
	_ = c.apply("ADDED", p, len(body))
	peer, ok := c.Peer(netip.MustParseAddr(p.Status.PodIP), ^uint64(0))
	if !ok {
		t.Fatal("candidate missing")
	}
	if c.Verify(context.Background(), peer, monotime.Now()) {
		t.Fatal("IP reuse was attributed to stale UID before watch update")
	}
}
