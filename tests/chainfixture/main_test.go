package main

import (
	"context"
	"errors"
	"google.golang.org/grpc"
	health "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"net/http/httptest"
	"testing"
)

type checkFunc func(context.Context, *health.HealthCheckRequest, ...grpc.CallOption) (*health.HealthCheckResponse, error)

func (f checkFunc) Check(c context.Context, r *health.HealthCheckRequest, o ...grpc.CallOption) (*health.HealthCheckResponse, error) {
	return f(c, r, o...)
}
func TestAPIPropagatesOnlyRequestMarkerAndRequiresDatabaseSuccess(t *testing.T) {
	for _, marked := range []bool{false, true} {
		for _, fail := range []bool{false, true} {
			called := false
			c := checkFunc(func(ctx context.Context, q *health.HealthCheckRequest, _ ...grpc.CallOption) (*health.HealthCheckResponse, error) {
				called = true
				m, _ := metadata.FromOutgoingContext(ctx)
				want := 0
				if marked {
					want = 1
				}
				if len(m.Get("debug-token")) != want || m.Get("dapr-app-id")[0] != "go-data" {
					t.Fatal("metadata", m)
				}
				if fail {
					return nil, errors.New("DB unavailable")
				}
				return &health.HealthCheckResponse{Status: health.HealthCheckResponse_SERVING}, nil
			})
			q := httptest.NewRequest("POST", "/api/query", nil)
			if marked {
				q.Header.Set("Debug-Token", "yes")
			}
			w := httptest.NewRecorder()
			api(c).ServeHTTP(w, q)
			want := 200
			if fail {
				want = 502
			}
			if !called || w.Code != want {
				t.Fatal("business result not verified", called, w.Code, w.Body.String())
			}
		}
	}
}

func TestDaprBootstrapDoesNotInvokeBusinessChain(t *testing.T) {
	for _, path := range []string{"/dapr/config", "/dapr/subscribe", "/other", "/api/query"} {
		t.Run(path, func(t *testing.T) {
			calls := 0
			c := checkFunc(func(context.Context, *health.HealthCheckRequest, ...grpc.CallOption) (*health.HealthCheckResponse, error) {
				calls++
				return &health.HealthCheckResponse{Status: health.HealthCheckResponse_SERVING}, nil
			})
			w := httptest.NewRecorder()
			api(c).ServeHTTP(w, httptest.NewRequest("GET", path, nil))
			want := 404
			if path == "/api/query" {
				want = 405
			}
			if calls != 0 || w.Code != want {
				t.Fatalf("non-business request invoked database chain: calls=%d status=%d want=%d", calls, w.Code, want)
			}
		})
	}
}
