package podwatch

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestPeerSnapshotDoesNotRetainIrrelevantAnnotations(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start, _ := strconv.Atoi(r.URL.Query().Get("continue"))
		next := ""
		if start < 40 {
			next = strconv.Itoa(start + 20)
		}
		items := make([]map[string]any, 0, 20)
		for i := start; i < start+20; i++ {
			items = append(items, map[string]any{"metadata": map[string]any{"uid": fmt.Sprint(i), "name": fmt.Sprint(i), "namespace": "outside-scope", "annotations": map[string]string{"unrelated": strings.Repeat("x", 100000)}}, "status": map[string]string{"podIP": fmt.Sprintf("10.0.0.%d", i+1)}})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"metadata": map[string]string{"resourceVersion": "9", "continue": next}, "items": items})
	}))
	defer server.Close()
	c := New(server.Client(), server.URL, "", func() (string, error) { return "", nil })
	if _, err := c.list(context.Background()); err != nil {
		t.Fatal(err)
	}
	ps, valid := c.Snapshot()
	if !valid || len(ps) != 60 {
		t.Fatalf("valid=%v count=%d", valid, len(ps))
	}
	for _, p := range ps {
		if len(p.Metadata.Annotations) > 0 {
			t.Fatal("irrelevant annotations retained in peer identity index")
		}
	}
}

func TestAPIFailureRetryBackoffIsBounded(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(503) }))
	defer server.Close()
	c := New(server.Client(), server.URL, "", func() (string, error) { return "", nil })
	ctx, cancel := context.WithTimeout(context.Background(), 19*time.Second)
	defer cancel()
	c.Run(ctx)
	if n := calls.Load(); n < 2 || n > 3 {
		t.Fatalf("persistent API failure: got %d requests; expected 2..3 with increasing bounded delay", n)
	}
}
