package main

import (
	"context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	health "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestOptInFaultMetadataAndDeadline(t *testing.T) {
	t.Setenv("TEST_FAULTS", "true")
	c := checkFunc(func(ctx context.Context, _ *health.HealthCheckRequest, _ ...grpc.CallOption) (*health.HealthCheckResponse, error) {
		m, _ := metadata.FromOutgoingContext(ctx)
		if len(m.Get("test-fault")) != 1 || m.Get("test-fault")[0] != "grpc-timeout" {
			t.Fatal(m)
		}
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 100*time.Millisecond {
			t.Fatal("fault deadline missing")
		}
		return nil, status.Error(codes.DeadlineExceeded, "injected")
	})
	r := httptest.NewRequest("POST", "/api/query", nil)
	r.Header.Set("X-Test-Fault", "grpc-timeout")
	w := httptest.NewRecorder()
	api(c).ServeHTTP(w, r)
	if w.Code != 504 || w.Header().Get("X-Test-Outcome") != "grpc-timeout" {
		t.Fatal(w.Code, w.Header())
	}
}
func TestFaultUnavailableSkipsDatabase(t *testing.T) {
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("test-fault", "grpc-unavailable"))
	// nil DB proves the injected error exits before attempting SQL.
	t.Setenv("TEST_FAULTS", "true")
	_, e := (dataService{}).Check(ctx, &health.HealthCheckRequest{})
	if status.Code(e) != codes.Unavailable {
		t.Fatal(e)
	}
}
func TestFaultHTTPDelayHasNoImplicitResponse(t *testing.T) {
	t.Setenv("TEST_FAULTS", "true")
	s := httptest.NewServer(api(checkFunc(func(context.Context, *health.HealthCheckRequest, ...grpc.CallOption) (*health.HealthCheckResponse, error) {
		t.Error("HTTP timeout must not call grpc")
		return nil, nil
	})))
	defer s.Close()
	req, _ := http.NewRequest("POST", s.URL+"/api/query", nil)
	req.Header.Set("X-Test-Fault", "http-timeout")
	client := http.Client{Timeout: 40 * time.Millisecond}
	r, e := client.Do(req)
	if r != nil {
		r.Body.Close()
	}
	if e == nil {
		t.Fatal("injected delay unexpectedly completed")
	}
}

func TestConnectionFaultRequiresEndToEndEvidence(t *testing.T) {
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	go func() {
		c, e := l.Accept()
		if e == nil {
			c.Close()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if e := probeConnection(ctx, l.Addr().String()); e == nil {
		t.Fatal("proxy accepting TCP is not end-to-end success; need terminal failure")
	}
}
