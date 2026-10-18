package podwatch

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const podJSON = `{"metadata":{"uid":"u1","name":"app","namespace":"demo","resourceVersion":"1","labels":{"observe":"yes"}},"spec":{"nodeName":"node-a","containers":[{"name":"app","ports":[{"containerPort":8080}]},{"name":"daprd","ports":[{"containerPort":50002}]}]},"status":{"phase":"Running","podIP":"10.0.0.2","containerStatuses":[{"name":"app","containerID":"containerd://abc","state":{"running":{}}}]}}`

func TestSelectionAndPorts(t *testing.T) {
	p, err := Decode([]byte(podJSON))
	if err != nil {
		t.Fatal(err)
	}
	ports, err := p.Ports()
	if err != nil || len(ports) != 2 || ports[0] != 8080 || ports[1] != 50002 {
		t.Fatal(ports, err)
	}
	if !p.Selected("node-a", []string{"demo"}, "observe", "yes") || p.Selected("node-b", []string{"demo"}, "observe", "yes") || p.Selected("node-a", []string{"other"}, "observe", "yes") {
		t.Fatal("selection boundary")
	}
	p.Metadata.Annotations = map[string]string{"collector.ztunnel.io/ports": "50002"}
	ports, err = p.Ports()
	if err != nil || len(ports) != 1 || ports[0] != 50002 {
		t.Fatal("annotation override", ports, err)
	}
	p.Metadata.Annotations["collector.ztunnel.io/ports"] = "8080,bad"
	if _, err = p.Ports(); err == nil {
		t.Fatal("invalid override accepted")
	}
}
func TestWatchDeleteAndDisconnectInvalidate(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("fieldSelector") != "spec.nodeName=node-a" {
			t.Error("missing node filter")
		}
		if r.URL.Query().Get("watch") == "true" {
			fmt.Fprintf(w, "{\"type\":\"DELETED\",\"object\":%s}\n", podJSON)
			w.(http.Flusher).Flush()
			select {
			case <-release:
			case <-r.Context().Done():
			}
			return
		}
		fmt.Fprintf(w, "{\"metadata\":{\"resourceVersion\":\"1\"},\"items\":[%s]}", podJSON)
	}))
	defer srv.Close()
	c := New(srv.Client(), srv.URL, "node-a", func() (string, error) { return "", nil })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Run(ctx)
	deadline := time.Now().Add(time.Second)
	for {
		s, ok := c.Snapshot()
		if ok && len(s) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("delete not applied")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	deadline = time.Now().Add(time.Second)
	for {
		_, ok := c.Snapshot()
		if !ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("disconnect retained trusted metadata")
		}
		time.Sleep(time.Millisecond)
	}
}
func TestMetadataBounds(t *testing.T) {
	if _, err := Decode([]byte(strings.Repeat("x", 256*1024+1))); err == nil {
		t.Fatal("oversized event")
	}
}

func TestEarlyWatchEOFRevokesCache(t *testing.T) {
	cut := make(chan struct{})
	watching := make(chan struct{})
	serve := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("watch") == "true" {
			w.WriteHeader(200)
			w.(http.Flusher).Flush()
			close(watching)
			select {
			case <-cut:
			case <-r.Context().Done():
			}
			return
		}
		serve++
		if serve > 1 {
			<-r.Context().Done()
			return
		}
		fmt.Fprintf(w, "{\"metadata\":{\"resourceVersion\":\"1\"},\"items\":[%s]}", podJSON)
	}))
	defer srv.Close()
	c := New(srv.Client(), srv.URL, "node-a", func() (string, error) { return "", nil })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Run(ctx)
	select {
	case <-watching:
	case <-time.After(time.Second):
		t.Fatal("watch not started")
	}
	close(cut)
	deadline := time.Now().Add(300 * time.Millisecond)
	for {
		_, ok := c.Snapshot()
		if !ok {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("disconnected watch retained trusted identities")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestMultipleNamespaceSelection(t *testing.T) {
	p, err := Decode([]byte(podJSON))
	if err != nil {
		t.Fatal(err)
	}
	for _, ns := range []string{"orders", "payments", "orders-other", "excluded"} {
		p.Metadata.Namespace = ns
		want := ns == "orders" || ns == "payments"
		if p.Selected("node-a", []string{"orders", "payments"}, "observe", "yes") != want {
			t.Fatal("namespace boundary", ns)
		}
		if p.Selected("node-a", nil, "observe", "yes") || p.Selected("other-node", []string{ns}, "observe", "yes") || p.Selected("node-a", []string{ns}, "observe", "no") {
			t.Fatal("scope bypass", ns)
		}
	}
}
