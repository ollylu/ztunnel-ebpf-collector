//go:build linux && amd64 && kernel

package tcpcapture

import (
	"bytes"
	"context"
	"golang.org/x/sys/unix"
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

func TestRealLargePayloadPreservesSubsequentBytes(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.200:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(io.Discard, c) }()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ready := make(chan struct{})
	business := make(chan error, 1)
	go func() {
		<-ready
		c, e := net.DialTimeout("tcp4", ln.Addr().String(), time.Second)
		if e != nil {
			business <- e
			return
		}
		defer c.Close()
		_, e = c.Write(make([]byte, 5_000_000))
		if e == nil {
			_, e = c.Write([]byte("healthy-after-large"))
		}
		business <- e
	}()
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
	damaged, healthy, total := 0, false, 0
	err = Run(ctx, Config{PID: os.Getpid(), StartTime: st, Duration: 3 * time.Second, Server: netip.MustParseAddrPort(ln.Addr().String()), NetNS: uint32(ns), Ready: func() { close(ready) }}, func(e Event) error {
		if e.Damaged {
			damaged++
		}
		total += len(e.Data)
		if bytes.Contains(e.Data, []byte("healthy-after-large")) {
			healthy = true
		}
		return nil
	})
	if err != nil || damaged != 0 || !healthy || total != 5_000_000+len("healthy-after-large") {
		t.Fatalf("large connection affected healthy: err=%v damaged=%d healthy=%v bytes=%d", err, damaged, healthy, total)
	}
	select {
	case e := <-business:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("business write blocked")
	}
}

func TestAdmissionFieldReasonIsUnambiguous(t *testing.T) {
	if e := captureFailure(uint64(9)<<32 | 1); !strings.Contains(e.Error(), "reason=admission_generation") {
		t.Fatal(e)
	}
	if e := captureFailure(uint64(9)<<32 | 2); !strings.Contains(e.Error(), "reason=multiple") {
		t.Fatal(e)
	}
}

func TestRealHighNumberedFDIsCaptured(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.200:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ready := make(chan struct{})
	business := make(chan error, 1)
	go func() {
		<-ready
		c, e := net.Dial("tcp4", ln.Addr().String())
		if e != nil {
			business <- e
			return
		}
		defer c.Close()
		raw, e := c.(*net.TCPConn).SyscallConn()
		if e != nil {
			business <- e
			return
		}
		high := -1
		_ = raw.Control(func(fd uintptr) { high, e = unix.FcntlInt(fd, unix.F_DUPFD_CLOEXEC, 6000) })
		if e == nil {
			defer unix.Close(high)
			_, e = unix.Write(high, []byte("high-fd-proof"))
		}
		business <- e
	}()
	nsText, _ := os.Readlink("/proc/self/ns/net")
	ns, _ := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(nsText, "net:["), "]"), 10, 32)
	st, _ := discovery.StartTime("/proc", os.Getpid())
	seen := false
	err = Run(ctx, Config{PID: os.Getpid(), StartTime: st, Duration: 2 * time.Second, Server: netip.MustParseAddrPort(ln.Addr().String()), NetNS: uint32(ns), Ready: func() { close(ready) }}, func(e Event) error {
		if e.FD >= 6000 && bytes.Contains(e.Data, []byte("high-fd-proof")) {
			seen = true
		}
		return nil
	})
	if err != nil || !seen {
		t.Fatalf("high FD not captured: %v seen=%v", err, seen)
	}
	if e := <-business; e != nil {
		t.Fatal(e)
	}
}
