// h2fixture generates bounded real HTTP/2 and protobuf gRPC test traffic.
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	health "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type service struct {
	health.UnimplementedHealthServer
}

func (service) Check(ctx context.Context, r *health.HealthCheckRequest) (*health.HealthCheckResponse, error) {
	if r.Service == "error" {
		return nil, status.Error(codes.NotFound, "fixture")
	}
	return &health.HealthCheckResponse{Status: health.HealthCheckResponse_SERVING}, nil
}
func (service) Watch(r *health.HealthCheckRequest, s health.Health_WatchServer) error {
	for _, v := range []health.HealthCheckResponse_ServingStatus{health.HealthCheckResponse_SERVING, health.HealthCheckResponse_NOT_SERVING} {
		if e := s.Send(&health.HealthCheckResponse{Status: v}); e != nil {
			return e
		}
	}
	return nil
}
func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func run() error {
	if len(os.Args) > 1 && os.Args[1] == "idle" {
		time.Sleep(20 * time.Minute)
		return nil
	}
	if len(os.Args) > 2 && os.Args[1] == "http2-client" {
		tr := &http2.Transport{AllowHTTP: true, DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		}}
		defer tr.CloseIdleConnections()
		client := &http.Client{Transport: tr, Timeout: 8 * time.Second}
		var wg sync.WaitGroup
		errs := make(chan error, 2)
		for _, path := range []string{"marked", "hidden"} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				req, e := http.NewRequest("GET", os.Args[2]+"/"+path, nil)
				if e != nil {
					errs <- e
					return
				}
				if path == "marked" {
					req.Header.Set("debug-token", "yes")
				}
				r, e := client.Do(req)
				if e != nil {
					errs <- e
					return
				}
				b, e := io.ReadAll(io.LimitReader(r.Body, 1024))
				r.Body.Close()
				if e != nil || r.ProtoMajor != 2 || r.StatusCode != 200 || string(b) != "reply:/"+path {
					errs <- fmt.Errorf("bad HTTP2 response %s %s", r.Status, b)
					return
				}
				fmt.Println(path, "HTTP/2", r.StatusCode)
			}()
		}
		wg.Wait()
		close(errs)
		for e := range errs {
			if e != nil {
				return e
			}
		}
		return nil
	}
	if len(os.Args) > 2 && (os.Args[1] == "grpc-client" || os.Args[1] == "grpc-client-native") {
		cc, e := grpc.NewClient(os.Args[2], grpc.WithTransportCredentials(insecure.NewCredentials()))
		if e != nil {
			return e
		}
		defer cc.Close()
		c := health.NewHealthClient(cc)
		var wg sync.WaitGroup
		errs := make(chan error, 4)
		for _, name := range []string{"marked", "hidden", "error", "stream"} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
				defer cancel()
				if name != "hidden" {
					ctx = metadata.AppendToOutgoingContext(ctx, "debug-token", "yes")
				}
				if len(os.Args) > 3 {
					ctx = metadata.AppendToOutgoingContext(ctx, "dapr-app-id", os.Args[3])
					if os.Args[1] == "grpc-client" || name == "stream" {
						ctx = metadata.AppendToOutgoingContext(ctx, "dapr-stream", "true")
					}
				}
				if name == "stream" {
					s, e := c.Watch(ctx, &health.HealthCheckRequest{Service: name})
					if e != nil {
						errs <- e
						return
					}
					count := 0
					for {
						r, e := s.Recv()
						if e == io.EOF {
							break
						}
						if e != nil {
							errs <- e
							return
						}
						if count == 0 && r.Status != health.HealthCheckResponse_SERVING || count == 1 && r.Status != health.HealthCheckResponse_NOT_SERVING {
							errs <- fmt.Errorf("incorrect stream response")
							return
						}
						count++
					}
					if count != 2 {
						errs <- fmt.Errorf("want 2 messages, got %d", count)
						return
					}
					fmt.Println(name, "grpc-status=0 messages=2")
					return
				}
				r, e := c.Check(ctx, &health.HealthCheckRequest{Service: name})
				if name == "error" {
					if status.Code(e) != codes.NotFound {
						errs <- fmt.Errorf("want NotFound: %v", e)
						return
					}
					fmt.Println(name, "grpc-status=5")
					return
				}
				if e != nil {
					errs <- e
					return
				}
				if r.Status != health.HealthCheckResponse_SERVING {
					errs <- fmt.Errorf("bad health response")
					return
				}
				fmt.Println(name, "grpc-status=0")
			}()
		}
		wg.Wait()
		close(errs)
		for e := range errs {
			if e != nil {
				return e
			}
		}
		return nil
	}
	// Test-only short connection age yields fresh HPACK state after capture starts.
	// The collector never closes or restarts production connections.
	gs := grpc.NewServer(grpc.KeepaliveParams(keepalive.ServerParameters{MaxConnectionAge: 5 * time.Second, MaxConnectionAgeGrace: time.Second}))
	health.RegisterHealthServer(gs, service{})
	l, e := net.Listen("tcp", ":8082")
	if e != nil {
		return e
	}
	defer l.Close()
	defer gs.Stop()
	go gs.Serve(l)
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := "reply:" + r.URL.Path
		w.Header().Set("Content-Length", fmt.Sprint(len(b)))
		_, _ = io.WriteString(w, b)
	})
	srv := http.Server{Addr: ":8081", Handler: h2c.NewHandler(h, &http2.Server{}), ReadHeaderTimeout: 3 * time.Second}
	return srv.ListenAndServe()
}
