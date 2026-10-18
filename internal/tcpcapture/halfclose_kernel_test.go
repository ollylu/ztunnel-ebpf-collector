//go:build linux && amd64 && kernel

package tcpcapture

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
	"ztunnel-ebpf-collector/internal/discovery"
)

// EOF on one direction must not end capture of the still-open reverse stream.
// Repeating beyond the 64-entry budget exposes missing final socket releases.
func TestRealHalfCloseKeepsReplyAndReleases(t *testing.T) {
	for _, outbound := range []bool{false, true} {
		t.Run(fmt.Sprint(outbound), func(t *testing.T) {
			ln, e := net.Listen("tcp4", "127.0.0.200:0")
			if e != nil {
				t.Fatal(e)
			}
			defer ln.Close()
			nst, e := os.Readlink("/proc/self/ns/net")
			if e != nil {
				t.Fatal(e)
			}
			ns, e := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(nst, "net:["), "]"), 10, 32)
			if e != nil {
				t.Fatal(e)
			}
			st, e := discovery.StartTime("/proc", os.Getpid())
			if e != nil {
				t.Fatal(e)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			ready := make(chan struct{})
			result := make(chan error, 1)
			closed := make(chan struct{}, 1)
			go func() {
				select {
				case <-ready:
				case <-ctx.Done():
					result <- ctx.Err()
					return
				}
				work := func() error {
					for i := 0; i < 70; i++ {
						c, e := (&net.Dialer{Timeout: time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.201")}}).Dial("tcp4", ln.Addr().String())
						if e != nil {
							return e
						}
						p, e := ln.Accept()
						if e != nil {
							c.Close()
							return e
						}
						c.SetDeadline(time.Now().Add(time.Second))
						p.SetDeadline(time.Now().Add(time.Second))
						e = func() error {
							defer c.Close()
							defer p.Close()
							if _, e := c.Write([]byte("request")); e != nil {
								return e
							}
							if e := c.(*net.TCPConn).CloseWrite(); e != nil {
								return e
							}
							b, e := io.ReadAll(p)
							if e != nil || string(b) != "request" {
								return fmt.Errorf("request EOF: %q %v", b, e)
							}
							if _, e = p.Write([]byte("reply-after-fin")); e != nil {
								return e
							}
							if e = p.(*net.TCPConn).CloseWrite(); e != nil {
								return e
							}
							b, e = io.ReadAll(c)
							if e != nil || string(b) != "reply-after-fin" {
								return fmt.Errorf("reply EOF: %q %v", b, e)
							}
							return nil
						}()
						if e != nil {
							return e
						}
						select {
						case <-closed:
						case <-ctx.Done():
							return ctx.Err()
						}
					}
					return nil
				}
				result <- work()
				cancel()
			}()
			ep := Endpoint{NetNS: uint32(ns), Server: netip.MustParseAddrPort(ln.Addr().String())}
			if outbound {
				ep.Server = netip.AddrPortFrom(netip.MustParseAddr("127.0.0.201"), ep.Server.Port())
				ep.Outbound = true
			}
			req, resp, nclose := 0, 0, 0
			e = Run(ctx, Config{PID: os.Getpid(), StartTime: st, Duration: 20 * time.Second, Targets: []Endpoint{ep}, Ready: func() { close(ready) }}, func(ev Event) error {
				if string(ev.Data) == "request" {
					req++
				}
				if string(ev.Data) == "reply-after-fin" {
					resp++
				}
				if ev.Closed {
					nclose++
					closed <- struct{}{}
				}
				return nil
			})
			if e != nil && ctx.Err() == nil {
				t.Fatal(e)
			}
			select {
			case e := <-result:
				if e != nil {
					t.Fatal(e)
				}
			case <-time.After(time.Second):
				t.Fatal("worker did not finish")
			}
			if req != 70 || resp != 70 || nclose != 70 {
				t.Fatalf("halfclose lost data or cleanup: request=%d reply=%d closed=%d", req, resp, nclose)
			}
		})
	}
}
