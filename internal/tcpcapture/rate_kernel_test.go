//go:build linux && amd64 && kernel

package tcpcapture

import (
	"context"
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

// A single bounded connection generates the event rate required by the chain.
// Payload is synthetic and never logged. This is a real kernel capacity check,
// not a production node-performance or business latency acceptance.
func TestRealContinuousSmallEventCapacity(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.200:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	ready := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		c, e := ln.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(15 * time.Second))
		io.Copy(c, c)
	}()
	go func() {
		select {
		case <-ready:
		case <-ctx.Done():
			done <- ctx.Err()
			return
		}
		c, e := net.DialTimeout("tcp4", ln.Addr().String(), time.Second)
		if e != nil {
			done <- e
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(12 * time.Second))
		b := make([]byte, 8)
		for i := 0; i < 5000; i++ {
			if _, e = c.Write(b); e != nil {
				done <- e
				return
			}
			if _, e = io.ReadFull(c, b); e != nil {
				done <- e
				return
			}
		}
		done <- nil
	}()
	nsText, _ := os.Readlink("/proc/self/ns/net")
	ns, _ := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(nsText, "net:["), "]"), 10, 32)
	st, err := discovery.StartTime("/proc", os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	reads, writes := 0, 0
	checks := 0
	started := time.Now()
	err = Run(ctx, Config{PID: os.Getpid(), StartTime: st, Continuous: true, Check: func() error { checks++; return nil }, Server: netip.MustParseAddrPort(ln.Addr().String()), NetNS: uint32(ns), Ready: func() { close(ready) }}, func(e Event) error {
		if e.Write {
			writes += len(e.Data)
		} else {
			reads += len(e.Data)
		}
		if reads == 40000 && writes == 40000 {
			cancel()
		}
		return nil
	})
	cancel()
	if err != nil {
		t.Fatalf("continuous small-event capture failed: %v, bytes read=%d written=%d elapsed=%s", err, reads, writes, time.Since(started))
	}
	if reads != 40000 || writes != 40000 {
		t.Fatalf("incomplete: read=%d write=%d", reads, writes)
	}
	select {
	case e := <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("client did not finish")
	}
	if checks > 100 {
		t.Fatalf("redundant lifecycle polling: %d checks for 5000 short calls", checks)
	}
	t.Logf("5000 round trips, 10000 payload events, duration=%s", time.Since(started))
}
