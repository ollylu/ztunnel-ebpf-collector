// Controlled Go-only network fixture. It is never a capture-event source.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/abort/"), strings.HasPrefix(r.URL.Path, "/partial/"), strings.HasPrefix(r.URL.Path, "/reset/"):
			h, ok := w.(http.Hijacker)
			if !ok {
				http.Error(w, "hijack unavailable", 500)
				return
			}
			c, _, e := h.Hijack()
			if e != nil {
				return
			}
			defer c.Close()
			if strings.HasPrefix(r.URL.Path, "/reset/") {
				if tcp, ok := c.(*net.TCPConn); ok {
					_ = tcp.SetLinger(0)
				}
			}
			if strings.HasPrefix(r.URL.Path, "/partial/") {
				_ = c.SetWriteDeadline(time.Now().Add(time.Second))
				_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\nab")
			}
			return
		case strings.HasPrefix(r.URL.Path, "/slow/"):
			// Own the raw socket so handler cancellation cannot cause net/http
			// to synthesize an implicit HTTP200 when no response was written.
			h, ok := w.(http.Hijacker)
			if !ok {
				http.Error(w, "hijack unavailable", 500)
				return
			}
			c, _, e := h.Hijack()
			if e != nil {
				return
			}
			defer c.Close()
			time.Sleep(2 * time.Second)
			return
		}
		code, body := 200, "fixture-ok"
		if strings.HasPrefix(r.URL.Path, "/status503/") {
			code, body = 503, "fixture-unavailable"
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(code)
		_, _ = io.WriteString(w, body)
	})
}

type result struct {
	URL    string `json:"url"`
	Host   string `json:"host"`
	Marked bool   `json:"marked"`
	Status int    `json:"status,omitempty"`
	Error  string `json:"error,omitempty"`
	Bytes  int    `json:"bytes"`
	Millis int64  `json:"millis"`
}

func errorKind(e error) string {
	if e == nil {
		return ""
	}
	var d *net.DNSError
	if errors.As(e, &d) {
		if d.IsNotFound {
			return "dns_not_found"
		}
		if d.IsTimeout {
			return "dns_timeout"
		}
		return "dns_error"
	}
	if errors.Is(e, syscall.ECONNREFUSED) {
		return "connection_refused"
	}
	if errors.Is(e, syscall.ECONNRESET) {
		return "connection_reset"
	}
	if errors.Is(e, syscall.ENETUNREACH) || errors.Is(e, syscall.EHOSTUNREACH) {
		return "unreachable"
	}
	if errors.Is(e, context.DeadlineExceeded) {
		return "client_deadline"
	}
	var n net.Error
	if errors.As(e, &n) && n.Timeout() {
		return "timeout"
	}
	if errors.Is(e, io.ErrUnexpectedEOF) {
		return "unexpected_eof"
	}
	if errors.Is(e, io.EOF) {
		return "eof"
	}
	return "other_error"
}
func client(base, host string) error {
	tr := &http.Transport{DialContext: (&net.Dialer{Timeout: 700 * time.Millisecond}).DialContext, DisableKeepAlives: true, MaxConnsPerHost: 1}
	defer tr.CloseIdleConnections()
	c := http.Client{Timeout: 700 * time.Millisecond, Transport: tr}
	for _, marked := range []bool{true, false} {
		suffix := "unmarked"
		if marked {
			suffix = "marked"
		}
		url := strings.TrimRight(base, "/") + "/" + suffix
		req, e := http.NewRequest(http.MethodGet, url, nil)
		if e != nil {
			return e
		}
		if host != "" {
			req.Host = host
		}
		req.Header.Set("X-Request-ID", "network-"+suffix+"-"+strconv.FormatInt(time.Now().UnixNano(), 10))
		if marked {
			req.Header.Set("Debug-Token", "yes")
		}
		start := time.Now()
		r, e := c.Do(req)
		out := result{URL: url, Host: req.Host, Marked: marked}
		if r != nil {
			out.Status = r.StatusCode
			b, readErr := io.ReadAll(io.LimitReader(r.Body, 8193))
			closeErr := r.Body.Close()
			out.Bytes = len(b)
			if e == nil {
				e = errors.Join(readErr, closeErr)
			}
		}
		out.Error = errorKind(e)
		out.Millis = time.Since(start).Milliseconds()
		if e := json.NewEncoder(os.Stdout).Encode(out); e != nil {
			return e
		}
	}
	return nil
}
func run() error {
	if len(os.Args) >= 3 && os.Args[1] == "client" {
		host := ""
		if len(os.Args) > 3 {
			host = os.Args[3]
		}
		return client(os.Args[2], host)
	}
	if len(os.Args) == 2 && os.Args[1] == "idle" {
		time.Sleep(3 * time.Minute)
		return nil
	}
	if len(os.Args) == 3 && os.Args[1] == "server" {
		s := http.Server{Addr: os.Args[2], Handler: handler(), ReadHeaderTimeout: time.Second, ReadTimeout: 3 * time.Second, WriteTimeout: 3 * time.Second, MaxHeaderBytes: 8192}
		go func() {
			time.Sleep(3 * time.Minute)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_ = s.Shutdown(ctx)
		}()
		e := s.ListenAndServe()
		if errors.Is(e, http.ErrServerClosed) {
			return nil
		}
		return e
	}
	return errors.New("usage: fixture server ADDR | client URL [HOST] | idle")
}
func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
