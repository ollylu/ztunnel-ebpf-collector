// Bounded ACK-only integration fixture. Business payloads are verified in memory;
// stdout contains receipts, never persistent request/response dumps.
package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	_ "google.golang.org/grpc/encoding/gzip"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const maxSize = 5_000_000

func echo(_ any, ctx context.Context, dec func(any) error, _ grpc.UnaryServerInterceptor) (any, error) {
	var r wrapperspb.BytesValue
	if e := dec(&r); e != nil {
		return nil, e
	}
	return &r, nil
}
func server() error {
	g := grpc.NewServer(grpc.MaxRecvMsgSize(maxSize+1024), grpc.MaxSendMsgSize(maxSize+1024))
	g.RegisterService(&grpc.ServiceDesc{ServiceName: "test.Large", HandlerType: (*interface{})(nil), Methods: []grpc.MethodDesc{{MethodName: "Echo", Handler: echo}}}, struct{}{})
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor == 2 && strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc") {
			g.ServeHTTP(w, r)
			return
		}
		if r.URL.Path == "/healthz" {
			w.WriteHeader(200)
			return
		}
		rd := io.Reader(r.Body)
		if r.Header.Get("Content-Encoding") == "gzip" {
			z, e := gzip.NewReader(r.Body)
			if e != nil {
				http.Error(w, "invalid gzip", 400)
				return
			}
			defer z.Close()
			rd = z
		}
		b, e := io.ReadAll(io.LimitReader(rd, maxSize+1))
		if e != nil || len(b) > maxSize {
			http.Error(w, "payload limit", 413)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		if r.Header.Get("Accept-Encoding") == "gzip" {
			var compressed bytes.Buffer
			z := gzip.NewWriter(&compressed)
			z.Write(b)
			z.Close()
			b = compressed.Bytes()
			w.Header().Set("Content-Encoding", "gzip")
		}
		w.Header().Set("Content-Length", fmt.Sprint(len(b)))
		w.Write(b)
	})
	s := http.Server{Addr: ":8080", Handler: h2c.NewHandler(h, &http2.Server{MaxConcurrentStreams: 8}), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, MaxHeaderBytes: 1 << 20}
	return s.ListenAndServe()
}
func zip(b []byte) []byte {
	var out bytes.Buffer
	z := gzip.NewWriter(&out)
	z.Write(b)
	z.Close()
	return out.Bytes()
}
func client(target string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	conn, e := grpc.NewClient(target, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if e != nil {
		return e
	}
	defer conn.Close()
	h1 := &http.Transport{MaxConnsPerHost: 1, MaxIdleConnsPerHost: 1, DisableCompression: true}
	defer h1.CloseIdleConnections()
	h2 := &http2.Transport{AllowHTTP: true, DisableCompression: true, DialTLSContext: func(ctx context.Context, n, a string, _ *tls.Config) (net.Conn, error) {
		return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, n, a)
	}}
	defer h2.CloseIdleConnections()
	for _, protocol := range []string{"HTTP/1.1", "HTTP/2", "gRPC"} {
		for _, compressed := range []bool{false, true} {
			for _, size := range []int{5000, 1 << 20, maxSize} {
				started := time.Now()
				marked := 0
				for seq := 0; seq < 40; seq++ {
					if e := ctx.Err(); e != nil {
						return e
					}
					n := 128
					if seq == 0 {
						n = size
					}
					body := bytes.Repeat([]byte("a"), n)
					want := sha256.Sum256(body)
					isMarked := seq%20 == 0
					if isMarked {
						marked++
					}
					id := fmt.Sprintf("i15-%s-%v-%d-%d", strings.ReplaceAll(protocol, "/", "-"), compressed, size, seq)
					var got []byte
					if protocol == "gRPC" {
						md := metadata.Pairs("x-request-id", id)
						if isMarked {
							md.Set("debug-token", "yes")
						}
						opts := []grpc.CallOption{grpc.MaxCallRecvMsgSize(maxSize + 1024), grpc.MaxCallSendMsgSize(maxSize + 1024)}
						if compressed {
							opts = append(opts, grpc.UseCompressor("gzip"))
						}
						var reply wrapperspb.BytesValue
						e = conn.Invoke(metadata.NewOutgoingContext(ctx, md), "/test.Large/Echo", &wrapperspb.BytesValue{Value: body}, &reply, opts...)
						got = reply.Value
					} else {
						input := body
						if compressed {
							input = zip(body)
						}
						req, _ := http.NewRequestWithContext(ctx, "POST", "http://"+target+"/echo", bytes.NewReader(input))
						req.Header.Set("X-Request-Id", id)
						if isMarked {
							req.Header.Set("Debug-Token", "yes")
						}
						if compressed {
							req.Header.Set("Content-Encoding", "gzip")
							req.Header.Set("Accept-Encoding", "gzip")
						}
						tr := http.RoundTripper(h1)
						if protocol == "HTTP/2" {
							tr = h2
						}
						cl := http.Client{Transport: tr, Timeout: 15 * time.Second}
						var r *http.Response
						r, e = cl.Do(req)
						if e == nil {
							rd := io.Reader(r.Body)
							if r.Header.Get("Content-Encoding") == "gzip" {
								var z *gzip.Reader
								z, e = gzip.NewReader(r.Body)
								if e == nil {
									defer z.Close()
									rd = z
								}
							}
							if e == nil {
								got, e = io.ReadAll(io.LimitReader(rd, maxSize+1))
							}
							r.Body.Close()
							if r.StatusCode != 200 {
								e = fmt.Errorf("HTTP %d", r.StatusCode)
							}
						}
					}
					if e != nil {
						return fmt.Errorf("%s: %w", id, e)
					}
					if sha256.Sum256(got) != want {
						return fmt.Errorf("%s body mismatch", id)
					}
					time.Sleep(100 * time.Millisecond)
				}
				json.NewEncoder(os.Stdout).Encode(map[string]any{"protocol": protocol, "gzip": compressed, "size": size, "sent": 40, "marked": marked, "success": 40, "millis": time.Since(started).Milliseconds()})
			}
		}
	}
	return nil
}
func main() {
	var e error
	if len(os.Args) == 3 && os.Args[1] == "client" {
		e = client(os.Args[2])
	} else {
		e = server()
	}
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
