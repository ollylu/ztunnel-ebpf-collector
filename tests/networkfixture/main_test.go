package main

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestControlledNetworkResponses(t *testing.T) {
	s := httptest.NewServer(handler())
	defer s.Close()
	for _, tc := range []struct {
		path   string
		status int
		want   string
	}{{"/ok/marked", 200, "fixture-ok"}, {"/status503/marked", 503, "fixture-unavailable"}} {
		t.Run(tc.path, func(t *testing.T) {
			r, e := http.Get(s.URL + tc.path)
			if e != nil {
				t.Fatal(e)
			}
			defer r.Body.Close()
			b, e := io.ReadAll(r.Body)
			if e != nil || r.StatusCode != tc.status || string(b) != tc.want {
				t.Fatalf("status=%d body=%q err=%v", r.StatusCode, b, e)
			}
		})
	}
}
func TestControlledNetworkFailures(t *testing.T) {
	s := httptest.NewServer(handler())
	defer s.Close()
	t.Run("abort", func(t *testing.T) {
		_, e := http.Get(s.URL + "/abort/marked")
		if e == nil || !strings.Contains(e.Error(), "EOF") {
			t.Fatalf("need genuine no-response EOF, got %v", e)
		}
	})
	t.Run("partial", func(t *testing.T) {
		r, e := http.Get(s.URL + "/partial/marked")
		if e != nil {
			t.Fatal(e)
		}
		defer r.Body.Close()
		b, e := io.ReadAll(r.Body)
		if !errors.Is(e, io.ErrUnexpectedEOF) || string(b) != "ab" {
			t.Fatalf("body=%q err=%v", b, e)
		}
	})
	t.Run("deadline", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		req, e := http.NewRequestWithContext(ctx, "GET", s.URL+"/slow/marked", nil)
		if e != nil {
			t.Fatal(e)
		}
		_, e = http.DefaultClient.Do(req)
		if !errors.Is(e, context.DeadlineExceeded) {
			t.Fatalf("need client deadline, got %v", e)
		}
	})
}

// A canceled/half-closed client must not make the slow fixture accidentally
// generate net/http's implicit empty HTTP200 response.
func TestSlowHalfCloseDoesNotGenerateResponse(t *testing.T) {
	s := httptest.NewServer(handler())
	defer s.Close()
	c, e := net.Dial("tcp4", s.Listener.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	if _, e = io.WriteString(c, "GET /slow/marked HTTP/1.1\r\nHost: fixture\r\nConnection: close\r\n\r\n"); e != nil {
		t.Fatal(e)
	}
	if e = c.(*net.TCPConn).CloseWrite(); e != nil {
		t.Fatal(e)
	}
	if e = c.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); e != nil {
		t.Fatal(e)
	}
	var b [128]byte
	n, e := c.Read(b[:])
	var ne net.Error
	if n != 0 || !errors.As(e, &ne) || !ne.Timeout() {
		t.Fatalf("slow fixture emitted response after half-close: n=%d bytes=%q err=%v", n, b[:n], e)
	}
}
