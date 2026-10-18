//go:build linux && amd64 && kernel

package tcpcapture

import (
	"context"
	"errors"
	"fmt"
	"github.com/cilium/ebpf"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"ztunnel-ebpf-collector/internal/discovery"
)

// A real socket keeps carrying business bytes after rejection. Those bytes must
// no longer reach ringbuf, while a different connection and close still do.
func TestRealSuppressedSocketKeepsBusinessAlive(t *testing.T) {
	for _, outbound := range []bool{false, true} {
		t.Run(fmt.Sprint("outbound=", outbound), func(t *testing.T) { testSuppressedSocket(t, outbound) })
	}
}
func testSuppressedSocket(t *testing.T, outbound bool) {
	ln, err := net.Listen("tcp4", "127.0.0.200:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
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
	drained := make(chan struct{})
	barrier := make(chan struct{})
	closed := make(chan struct{})
	failures := make(chan error, 1)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer c.Close()
				c.SetDeadline(time.Now().Add(8 * time.Second))
				b := make([]byte, 16384)
				for {
					n, e := c.Read(b)
					if n > 0 {
						if _, w := c.Write(b[:n]); w != nil {
							return
						}
					}
					if e != nil {
						return
					}
				}
			}()
		}
	}()
	go func() {
		fail := func(e error) { failures <- e; cancel() }
		select {
		case <-ready:
		case <-ctx.Done():
			fail(ctx.Err())
			return
		}
		bad, e := (&net.Dialer{Timeout: time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.201")}}).Dial("tcp4", ln.Addr().String())
		if e != nil {
			fail(e)
			return
		}
		defer bad.Close()
		bad.SetDeadline(time.Now().Add(7 * time.Second))
		exchange := func(c net.Conn, s string) error {
			if _, e := io.WriteString(c, s); e != nil {
				return e
			}
			b := make([]byte, len(s))
			_, e := io.ReadFull(c, b)
			if e == nil && string(b) != s {
				return fmt.Errorf("business echo mismatch")
			}
			return e
		}
		if e = exchange(bad, "reject"); e != nil {
			fail(e)
			return
		}
		select {
		case <-drained:
		case <-ctx.Done():
			fail(fmt.Errorf("rejection feedback never drained"))
			return
		}
		good, e := (&net.Dialer{Timeout: time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.201")}}).Dial("tcp4", ln.Addr().String())
		if e != nil {
			fail(e)
			return
		}
		defer good.Close()
		good.SetDeadline(time.Now().Add(7 * time.Second))
		if e = exchange(good, "barrier"); e != nil {
			fail(e)
			return
		}
		select {
		case <-barrier:
		case <-ctx.Done():
			fail(ctx.Err())
			return
		}
		for i := 0; i < 8; i++ {
			if e = exchange(bad, strings.Repeat("x", 8192)); e != nil {
				fail(e)
				return
			}
		}
		if e = exchange(good, "still-supported"); e != nil {
			fail(e)
			return
		}
		bad.Close()
		select {
		case <-closed:
		case <-ctx.Done():
			fail(fmt.Errorf("suppressed close missing"))
			return
		}
		// Leave enough time to drain the final healthy response; no arbitrary load.
		time.Sleep(100 * time.Millisecond)
		failures <- nil
		cancel()
	}()
	var pending []Event
	var rejected uint64
	extra, healthy := 0, 0
	barrierOnce := false
	closeOnce := false
	ep := Endpoint{NetNS: uint32(ns), Server: netip.MustParseAddrPort(ln.Addr().String())}
	if outbound {
		ep.Outbound = true
		ep.Server = netip.AddrPortFrom(netip.MustParseAddr("127.0.0.201"), ep.Server.Port())
	}
	err = Run(ctx, Config{PID: os.Getpid(), StartTime: st, Targets: []Endpoint{ep}, Duration: 9 * time.Second, Ready: func() { close(ready) }, Suppressions: func() []Event {
		p := pending
		pending = nil
		if len(p) > 0 {
			close(drained)
		}
		return p
	}}, func(ev Event) error {
		if rejected == 0 && string(ev.Data) == "reject" && ev.Write != outbound {
			rejected = ev.Inode
			ev.Data = nil
			pending = []Event{ev}
			return nil
		}
		if ev.Inode == rejected {
			if ev.Closed && !closeOnce {
				closeOnce = true
				close(closed)
			}
			if strings.Contains(string(ev.Data), "xxx") {
				extra++
			}
		} else {
			if string(ev.Data) == "barrier" && !barrierOnce {
				barrierOnce = true
				close(barrier)
			}
			if string(ev.Data) == "still-supported" {
				healthy++
			}
		}
		return nil
	})
	cancel()
	ln.Close()
	wg.Wait()
	if err != nil {
		t.Fatal(err)
	}
	if e := <-failures; e != nil {
		t.Fatal(e)
	}
	if rejected == 0 || extra != 0 || healthy != 2 || !closeOnce {
		t.Fatalf("rejected=%d leaked=%d healthy=%d close=%v", rejected, extra, healthy, closeOnce)
	}
}

// A deliberately tiny real map injects ENOSPC without host pressure. The owner
// must report failure and never claim the second identity was installed.
func TestRealSuppressionMapFailure(t *testing.T) {
	m, err := ebpf.NewMap(&ebpf.MapSpec{Name: "zc_test_reject", Type: ebpf.Hash, KeySize: 16, ValueSize: 40, MaxEntries: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	s := suppressionSet{put: func(k [40]byte) error { return m.Put(suppressionMapKey(k), k) }, remove: func(k [40]byte) error { return m.Delete(suppressionMapKey(k)) }}
	e := suppressionEvent()
	active := map[Endpoint]uint64{e.Target(): 1}
	if err := s.add([]Event{e}, active); err != nil {
		t.Fatal(err)
	}
	e.Inode++
	if err := s.add([]Event{e}, active); err == nil || len(s.entries) != 1 {
		t.Fatal("map-full failure lost", err, len(s.entries))
	}
	if err := s.reconcile(nil); err != nil || len(s.entries) != 0 {
		t.Fatal("map cleanup failed", err)
	}
}

func TestRealRefusedConnectionCloseIsHarmless(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.200:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
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
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	dialErr := make(chan error, 1)
	var closes []Event
	err = Run(ctx, Config{PID: os.Getpid(), StartTime: st, Server: netip.MustParseAddrPort(addr), NetNS: uint32(ns), Duration: 2 * time.Second, Ready: func() {
		go func() {
			c, e := net.DialTimeout("tcp4", addr, time.Second)
			if c != nil {
				c.Close()
			}
			dialErr <- e
		}()
	}}, func(e Event) error {
		if e.Closed {
			closes = append(closes, e)
		}
		return nil
	})
	if e := <-dialErr; !errors.Is(e, syscall.ECONNREFUSED) {
		t.Fatal("expected refused connection", e)
	}
	if err != nil {
		t.Fatal(err)
	}
	if len(closes) != 1 || closes[0].LocalPort != 0 {
		t.Fatal("did not observe reset local tuple", closes)
	}
	t.Logf("actual close inode=%d netns=%d local=%s:%d remote=%s:%d generation=%d", closes[0].Inode, closes[0].NetNS, closes[0].LocalIP, closes[0].LocalPort, closes[0].RemoteIP, closes[0].RemotePort, closes[0].Generation)
}
