// Real bounded ACK test chain: HTTP -> native Dapr gRPC proxy -> MySQL SELECT 1.
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	health "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"log"
	"net"
	"net/http"
	"os"
	"sync/atomic"
	"time"
)

var mysqlCompleted atomic.Int64

type checker interface {
	Check(context.Context, *health.HealthCheckRequest, ...grpc.CallOption) (*health.HealthCheckResponse, error)
}

func api(c checker) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
			w.WriteHeader(200)
			return
		}
		// Dapr fetches /dapr/config and /dapr/subscribe during startup. Those
		// callbacks must not establish business gRPC connections before capture.
		if r.URL.Path != "/api/query" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		fault := ""
		if os.Getenv("TEST_FAULTS") == "true" {
			fault = r.Header.Get("X-Test-Fault")
		}
		w.Header().Set("X-Test-Outcome", "normal")
		if fault == "http-timeout" {
			h, ok := w.(http.Hijacker)
			if !ok {
				http.Error(w, "fixture hijack unavailable", 500)
				return
			}
			conn, _, e := h.Hijack()
			if e != nil {
				return
			}
			defer conn.Close()
			time.Sleep(250 * time.Millisecond)
			return
		}
		if fault == "connect-fail" {
			ctx, c := context.WithTimeout(r.Context(), 100*time.Millisecond)
			defer c()
			// Test-only fixed target; never accept a target address from a request.
			e := probeConnection(ctx, "go-data-dapr.collector-demo.svc.cluster.local:18099")
			if e != nil {
				w.Header().Set("X-Test-Outcome", "connect-fail")
				http.Error(w, "injected connect failure", 502)
				return
			}
			http.Error(w, "fixture closed port unexpectedly reachable", 500)
			return
		}
		timeout := 2 * time.Second
		if fault == "grpc-timeout" {
			timeout = 80 * time.Millisecond
		}
		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()
		m := metadata.Pairs("dapr-app-id", "go-data", "x-request-id", r.Header.Get("X-Request-Id"))
		if fault == "grpc-timeout" || fault == "grpc-unavailable" {
			m.Set("test-fault", fault)
		}
		if v := r.Header.Values("Debug-Token"); len(v) == 1 && v[0] == "yes" {
			m.Set("debug-token", "yes")
		}
		reply, err := c.Check(metadata.NewOutgoingContext(ctx, m), &health.HealthCheckRequest{Service: r.Header.Get("X-Request-Id")})
		if err != nil || reply.GetStatus() != health.HealthCheckResponse_SERVING {
			code := 502
			if fault == "grpc-timeout" && (status.Code(err) == codes.DeadlineExceeded || errors.Is(ctx.Err(), context.DeadlineExceeded)) {
				code = 504
				w.Header().Set("X-Test-Outcome", fault)
			}
			if fault == "grpc-unavailable" && status.Code(err) == codes.Unavailable {
				w.Header().Set("X-Test-Outcome", fault)
			}
			http.Error(w, "database chain failed", code)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"mysql": 1, "id": r.Header.Get("X-Request-Id")})
	})
}

type dataService struct {
	health.UnimplementedHealthServer
	db *sql.DB
}

func (s dataService) Check(ctx context.Context, q *health.HealthCheckRequest) (*health.HealthCheckResponse, error) {
	if os.Getenv("TEST_FAULTS") == "true" {
		m, _ := metadata.FromIncomingContext(ctx)
		if len(m.Get("test-fault")) == 1 {
			switch m.Get("test-fault")[0] {
			case "grpc-unavailable":
				return nil, status.Error(codes.Unavailable, "injected unavailable")
			case "grpc-timeout":
				select {
				case <-ctx.Done():
					return nil, status.FromContextError(ctx.Err()).Err()
				case <-time.After(250 * time.Millisecond):
					return nil, status.Error(codes.DeadlineExceeded, "injected deadline")
				}
			}
		}
	}
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	var n int
	if err := s.db.QueryRowContext(ctx, "SELECT 1").Scan(&n); err != nil || n != 1 {
		return nil, status.Error(codes.Unavailable, "mysql query failed")
	}
	mysqlCompleted.Add(1)
	return &health.HealthCheckResponse{Status: health.HealthCheckResponse_SERVING}, nil
}
func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
func run() error {
	if len(os.Args) > 1 && os.Args[1] == "soak" {
		return soak()
	}
	if len(os.Args) == 3 && os.Args[1] == "maintenance" {
		return setMaintenance(os.Args[2])
	}
	if len(os.Args) > 1 && os.Args[1] == "view" {
		return view()
	}
	if len(os.Args) > 1 && os.Args[1] == "load" {
		return load()
	}
	if os.Getenv("ROLE") == "data" {
		db, err := sql.Open("mysql", os.Getenv("MYSQL_DSN"))
		if err != nil {
			return fmt.Errorf("mysql configuration invalid")
		}
		defer db.Close()
		db.SetMaxOpenConns(16)
		db.SetMaxIdleConns(16)
		db.SetConnMaxLifetime(5 * time.Minute)
		g := grpc.NewServer(grpc.MaxConcurrentStreams(64))
		health.RegisterHealthServer(g, dataService{db: db})
		l, err := net.Listen("tcp", ":8080")
		if err != nil {
			return err
		}
		go func() {
			s := http.Server{Addr: ":8081", ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/test/stats" {
					json.NewEncoder(w).Encode(map[string]any{"mysql_completed": mysqlCompleted.Load()})
					return
				}
				ctx, c := context.WithTimeout(r.Context(), 500*time.Millisecond)
				defer c()
				if db.PingContext(ctx) != nil {
					http.Error(w, "database unavailable", 503)
					return
				}
				w.WriteHeader(200)
			})}
			if err := s.ListenAndServe(); err != nil {
				log.Print("health server stopped")
			}
		}()
		return g.Serve(l)
	}
	c, err := grpc.NewClient("127.0.0.1:50001", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return err
	}
	defer c.Close()
	s := http.Server{Addr: ":8080", Handler: api(health.NewHealthClient(c)), ReadHeaderTimeout: time.Second, ReadTimeout: 3 * time.Second, WriteTimeout: 3 * time.Second, MaxHeaderBytes: 8192}
	return s.ListenAndServe()
}
