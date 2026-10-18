//go:build linux && amd64 && kernel

package tcpcapture

import (
	"context"
	"errors"
	"golang.org/x/sys/unix"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
	"ztunnel-ebpf-collector/internal/discovery"
)

// Characterize the current boundary: a failed connect has no readable HTTP
// marker. EINPROGRESS is only an attempt timestamp, not handshake success.
func TestRefusedConnectHasNoRequestEvidence(t *testing.T) {
	ln, e := net.Listen("tcp4", "127.0.0.201:0")
	if e != nil {
		t.Fatal(e)
	}
	target := netip.MustParseAddrPort(ln.Addr().String())
	if e = ln.Close(); e != nil {
		t.Fatal(e)
	}
	ns, e := os.Readlink("/proc/self/ns/net")
	if e != nil {
		t.Fatal(e)
	}
	n, e := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(ns, "net:["), "]"), 10, 32)
	if e != nil {
		t.Fatal(e)
	}
	start, e := discovery.StartTime("/proc", os.Getpid())
	if e != nil {
		t.Fatal(e)
	}
	ready := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		<-ready
		c, e := net.DialTimeout("tcp4", target.String(), 200*time.Millisecond)
		if c != nil {
			_ = c.Close()
		}
		done <- e
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	data, birth := 0, 0
	e = Run(ctx, Config{PID: os.Getpid(), StartTime: start, Server: target, NetNS: uint32(n), Duration: time.Second, Ready: func() { close(ready) }}, func(ev Event) error {
		if ev.Connected {
			birth++
		}
		data += len(ev.Data)
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	if e := <-done; !errors.Is(e, unix.ECONNREFUSED) {
		t.Fatalf("need real refusal, got %v", e)
	}
	if data != 0 {
		t.Fatalf("failed connect produced request payload: attempt=%d bytes=%d", birth, data)
	}
	t.Logf("real ECONNREFUSED; %d connect-attempt timestamps, zero request bytes; no terminal errno event implemented", birth)
}

// No global route changes: only this locked test thread briefly enters its own
// empty network namespace, then restores the original before unlocking.
func TestIsolatedNetworkUnreachable(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	old, e := unix.Open("/proc/thread-self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer unix.Close(old)
	if e = unix.Unshare(unix.CLONE_NEWNET); e != nil {
		t.Fatal(e)
	}
	defer func() {
		if e := unix.Setns(old, unix.CLONE_NEWNET); e != nil {
			t.Errorf("restore own network namespace: %v", e)
		}
	}()
	fd, e := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer unix.Close(fd)
	e = unix.Connect(fd, &unix.SockaddrInet4{Port: 18090, Addr: [4]byte{198, 51, 100, 1}})
	if !errors.Is(e, unix.ENETUNREACH) {
		t.Fatalf("need real ENETUNREACH, got %v", e)
	}
	t.Log("real ENETUNREACH in isolated empty network namespace, no HTTP bytes; this is not a ztunnel integration result")
}
