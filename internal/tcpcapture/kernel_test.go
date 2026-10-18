//go:build linux && amd64 && kernel

package tcpcapture

import (
	"bytes"
	"context"
	"encoding/binary"
	"github.com/cilium/ebpf/asm"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"ztunnel-ebpf-collector/internal/discovery"
)

func TestRealMultipleTargetFilter(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	var listeners []net.Listener
	for i := 0; i < 4; i++ {
		ln, err := net.Listen("tcp4", "127.0.0.200:0")
		if err != nil {
			t.Fatal(err)
		}
		listeners = append(listeners, ln)
		defer ln.Close()
	}
	nsText, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	ns, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(nsText, "net:["), "]"), 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	st, err := discovery.StartTime("/proc", os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	ready := make(chan struct{})
	errs := make(chan error, 8)
	var wg sync.WaitGroup
	for _, ln := range listeners {
		wg.Add(2)
		go func() {
			defer wg.Done()
			conn, e := ln.Accept()
			if e != nil {
				return
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(3 * time.Second))
			b := make([]byte, 64)
			if _, e = conn.Read(b); e != nil {
				errs <- e
				return
			}
			_, e = conn.Write([]byte("reply"))
			if e != nil {
				errs <- e
			}
		}()
		go func() {
			defer wg.Done()
			select {
			case <-ready:
			case <-ctx.Done():
				return
			}
			conn, e := net.DialTimeout("tcp4", ln.Addr().String(), time.Second)
			if e != nil {
				errs <- e
				return
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(3 * time.Second))
			if _, e = conn.Write([]byte("request")); e != nil {
				errs <- e
				return
			}
			b := make([]byte, 64)
			if _, e = conn.Read(b); e != nil {
				errs <- e
			}
		}()
	}
	selected := []Endpoint{{NetNS: uint32(ns), Server: netip.MustParseAddrPort(listeners[0].Addr().String())}, {NetNS: uint32(ns), Server: netip.MustParseAddrPort(listeners[1].Addr().String())}, {NetNS: uint32(ns) ^ 1, Server: netip.MustParseAddrPort(listeners[3].Addr().String())}}
	got := map[Endpoint][2]string{}
	err = Run(ctx, Config{PID: os.Getpid(), StartTime: st, Targets: selected, Duration: 4 * time.Second, Ready: func() { close(ready) }}, func(ev Event) error {
		key := Endpoint{NetNS: ev.NetNS, Server: netip.AddrPortFrom(ev.RemoteIP, ev.RemotePort)}
		b := got[key]
		i := 0
		if !ev.Write {
			i = 1
		}
		b[i] += string(ev.Data)
		got[key] = b
		return nil
	})
	cancel()
	for _, ln := range listeners {
		ln.Close()
	}
	wg.Wait()
	close(errs)
	if err != nil {
		t.Fatal(err)
	}
	for err := range errs {
		t.Error(err)
	}
	if len(got) != 2 {
		t.Fatalf("wrong port/namespace admitted or target missing: %+v", got)
	}
	for _, key := range selected[:2] {
		if got[key] != [2]string{"request", "reply"} {
			t.Fatalf("missing target bytes: %v %+v", key, got)
		}
	}
}

func TestRealSocketBytes(t *testing.T) {
	ln, e := net.Listen("tcp4", "127.0.0.200:0")
	if e != nil {
		t.Fatal(e)
	}
	defer ln.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go func() {
		c, e := ln.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		b := make([]byte, 1024)
		_, _ = c.Read(b)
		_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"))
	}()
	ready := make(chan struct{})
	go func() {
		select {
		case <-ready:
		case <-ctx.Done():
			return
		}
		c, e := net.Dial("tcp4", ln.Addr().String())
		if e != nil {
			return
		}
		defer c.Close()
		_, _ = c.Write([]byte("GET /kernel-proof HTTP/1.1\r\nHost: local\r\nDebug-Token: yes\r\n\r\n"))
		b := make([]byte, 1024)
		_, _ = c.Read(b)
	}()
	st, e := discovery.StartTime("/proc", os.Getpid())
	if e != nil {
		t.Fatal(e)
	}
	nsText, e := os.Readlink("/proc/self/ns/net")
	if e != nil {
		t.Fatal(e)
	}
	ns, e := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(nsText, "net:["), "]"), 10, 32)
	if e != nil {
		t.Fatal(e)
	}
	var req, resp bool
	e = Run(ctx, Config{NetNS: uint32(ns), Ready: func() { close(ready) }, PID: os.Getpid(), StartTime: st, Server: netip.MustParseAddrPort(ln.Addr().String()), Duration: 10 * time.Second}, func(ev Event) error {
		if ev.Write && strings.Contains(string(ev.Data), "/kernel-proof") {
			req = true
		}
		if !ev.Write && strings.Contains(string(ev.Data), "200 OK") {
			resp = true
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	if !req || !resp {
		t.Fatalf("missing real socket bytes: request=%v response=%v", req, resp)
	}
}

func TestInstructionEncoding(t *testing.T) {
	l, e := loadLayout()
	if e != nil {
		t.Fatal(e)
	}
	a, b := programs(Config{PID: 123, StartTime: 1234, Server: netip.MustParseAddrPort("127.0.0.200:8080"), NetNS: 4026532581}, l, 1, 2, 3, 4, 5, 6)
	for _, ins := range []asm.Instructions{a, b} {
		var buf bytes.Buffer
		if e := ins.Marshal(&buf, binary.LittleEndian); e != nil {
			t.Fatal(e)
		}
	}
}

// A retained TCP connection must receive new target generations without reloading
// the probes; removing its endpoint must prevent byte collection.
func TestRealDynamicTargetsAndClose(t *testing.T) { testDynamicTargetsAndClose(t, false) }
func TestRealSuppressionRevocation(t *testing.T)  { testDynamicTargetsAndClose(t, true) }
func testDynamicTargetsAndClose(t *testing.T, suppress bool) {
	ln, err := net.Listen("tcp4", "127.0.0.200:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	nsText, _ := os.Readlink("/proc/self/ns/net")
	ns, _ := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(nsText, "net:["), "]"), 10, 32)
	st, _ := discovery.StartTime("/proc", os.Getpid())
	ep := Endpoint{NetNS: uint32(ns), Server: netip.MustParseAddrPort(ln.Addr().String())}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	phase := 0
	var start time.Time
	done := make(chan error, 1)
	go func() {
		c, e := ln.Accept()
		if e != nil {
			done <- e
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		b := make([]byte, 16)
		for {
			_, e = c.Read(b)
			if e != nil {
				done <- nil
				return
			}
		}
	}()
	var pending []Event
	got := map[uint64]string{}
	closed := false
	err = Run(ctx, Config{Suppressions: func() []Event { es := pending; pending = nil; return es }, PID: os.Getpid(), StartTime: st, Targets: []Endpoint{ep}, Duration: 4 * time.Second,
		Refresh: func() (map[Endpoint]uint64, error) {
			if start.IsZero() {
				return map[Endpoint]uint64{ep: 7}, nil
			}
			if time.Since(start) > 2*time.Second {
				phase = 2
				return map[Endpoint]uint64{ep: 9}, nil
			}
			if time.Since(start) > time.Second {
				phase = 1
				return map[Endpoint]uint64{}, nil
			}
			return map[Endpoint]uint64{ep: 7}, nil
		}, Ready: func() {
			start = time.Now()
			go func() {
				c, e := net.Dial("tcp4", ln.Addr().String())
				if e != nil {
					return
				}
				defer c.Close()
				for i := 0; i < 6; i++ {
					c.Write([]byte("x"))
					time.Sleep(500 * time.Millisecond)
				}
			}()
		}}, func(ev Event) error {
		if ev.Closed {
			closed = true
			return nil
		}
		if ev.Connected {
			return nil
		} // Birth metadata is not a payload to quarantine.
		if suppress && ev.Generation == 7 && len(got[7]) == 0 {
			pending = []Event{ev}
		}
		got[ev.Generation] += string(ev.Data)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if phase != 2 || got[7] == "" || got[9] == "" || got[0] != "" || !closed {
		t.Fatalf("missing dynamic generation/close: phase=%d got=%v closed=%v", phase, got, closed)
	}
	if suppress && got[7] != "x" {
		t.Fatal("rejection did not suppress old generation", got)
	}
	if len(got[7])+len(got[9]) >= 6 {
		t.Fatal("removed target still captured", got)
	}
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("server did not finish")
	}
}

// Reads on a ztunnel accepted socket are requests. Only the selected peer IP
// and listener port in the selected socket netns may enter the ring.
func TestRealOutboundSocketFilter(t *testing.T) {
	for _, network := range []string{"tcp4", "tcp"} {
		t.Run(network, func(t *testing.T) { testOutboundSocketFilter(t, network) })
	}
}
func testOutboundSocketFilter(t *testing.T, network string) {
	address := "127.0.0.200:0"
	if network == "tcp" {
		address = "[::]:0"
	}
	ln, err := net.Listen(network, address)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	nsText, _ := os.Readlink("/proc/self/ns/net")
	ns, _ := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(nsText, "net:["), "]"), 10, 32)
	st, err := discovery.StartTime("/proc", os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	port := netip.MustParseAddrPort(ln.Addr().String()).Port()
	reserved, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	sourcePort := netip.MustParseAddrPort(reserved.Addr().String()).Port()
	reserved.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	ready := make(chan struct{})
	var readyOnce sync.Once
	signalReady := func() { readyOnce.Do(func() { close(ready) }) }
	errs := make(chan error, 4)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-ready
		peers := []string{"127.0.0.1", "127.0.0.2"}
		if network == "tcp" {
			peers = append(peers, "::1")
		}
		for _, ip := range peers {
			d := net.Dialer{Timeout: time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP(ip), Port: int(sourcePort)}}
			netType, host := "tcp4", "127.0.0.200"
			if ip == "::1" {
				netType, host = "tcp6", "::1"
			}
			client, e := d.Dial(netType, net.JoinHostPort(host, strconv.Itoa(int(port))))
			if e != nil {
				errs <- e
				return
			}
			server, e := ln.Accept()
			if e != nil {
				client.Close()
				errs <- e
				return
			}
			client.SetDeadline(time.Now().Add(time.Second))
			server.SetDeadline(time.Now().Add(time.Second))
			if _, e = client.Write([]byte("request:" + ip)); e != nil {
				errs <- e
			}
			b := make([]byte, 64)
			if _, e = server.Read(b); e != nil {
				errs <- e
			}
			if _, e = server.Write([]byte("reply:" + ip)); e != nil {
				errs <- e
			}
			if _, e = client.Read(b); e != nil {
				errs <- e
			}
			client.Close()
			server.Close()
		}
	}()
	var requests, responses string
	closed := false
	ep := Endpoint{Outbound: true, NetNS: uint32(ns), Server: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port)}
	err = Run(ctx, Config{PID: os.Getpid(), StartTime: st, Targets: []Endpoint{ep, {NetNS: uint32(ns), Server: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), sourcePort)}}, Duration: 3 * time.Second, Ready: signalReady}, func(ev Event) error {
		if !ev.Outbound || ev.Target() != ep {
			t.Error("wrong direction/target", ev)
		}
		if ev.Closed {
			closed = true
			return nil
		}
		if ev.Write {
			responses += string(ev.Data)
		} else {
			requests += string(ev.Data)
		}
		return nil
	})
	if err != nil {
		signalReady()
		t.Fatal(err)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
	if requests != "request:127.0.0.1" || responses != "reply:127.0.0.1" || !closed {
		t.Fatalf("missing/leaked outbound bytes or close: req=%q resp=%q close=%v", requests, responses, closed)
	}
}
