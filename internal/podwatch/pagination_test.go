package podwatch

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPaginatedSnapshotIsAtomicAndConsistent(t *testing.T) {
	var c *Cache
	pages := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("watch") == "true" {
			return
		}
		pages++
		if r.URL.Query().Get("limit") == "" {
			t.Error("unbounded list")
		}
		switch r.URL.Query().Get("continue") {
		case "":
			fmt.Fprint(w, `{"metadata":{"resourceVersion":"10","continue":"next"},"items":[{"metadata":{"uid":"a","name":"a","namespace":"ns"}}]}`)
		case "next":
			if _, ok := c.Snapshot(); ok {
				t.Error("partial snapshot exposed")
			}
			fmt.Fprint(w, `{"metadata":{"resourceVersion":"10"},"items":[{"metadata":{"uid":"b","name":"b","namespace":"ns"}}]}`)
		default:
			t.Error("unexpected token")
		}
	}))
	defer server.Close()
	c = New(server.Client(), server.URL, "", func() (string, error) { return "", nil })
	_ = c.cycle(context.Background()) // immediate watch EOF is deliberately not a successful watch.
	pods, valid := c.Snapshot()
	if pages != 2 || !valid || len(pods) != 2 {
		t.Fatalf("pages=%d valid=%v pods=%d", pages, valid, len(pods))
	}
}
func TestListCompactsUnusedLargeFields(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("watch") == "true" {
			return
		}
		fmt.Fprintf(w, `{"metadata":{"resourceVersion":"10"},"items":[{"metadata":{"uid":"a","name":"a","namespace":"ns","managedFields":[{"unused":"%s"}]}}]}`, strings.Repeat("x", 100000))
	}))
	defer server.Close()
	c := New(server.Client(), server.URL, "", func() (string, error) { return "", nil })
	_ = c.cycle(context.Background())
	if c.sizes["a"] > 4096 {
		t.Fatalf("retained accounting includes unused fields: %d", c.sizes["a"])
	}
}
