//go:build linux && amd64 && kernel

package tcpcapture

import (
	"context"
	"golang.org/x/sys/unix"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
	"ztunnel-ebpf-collector/internal/discovery"
	"ztunnel-ebpf-collector/internal/monotime"
)

func TestPeerConnectionBirthEvidence(t *testing.T)       { testPeerConnectionBirth(t, false) }
func TestPeerMappedConnectionBirthEvidence(t *testing.T) { testPeerConnectionBirth(t, true) }
func testPeerConnectionBirth(t *testing.T, mapped bool) {
	ln, err := net.Listen("tcp4", "127.0.0.200:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	nsText, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	ns, _ := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(nsText, "net:["), "]"), 10, 32)
	st, err := discovery.StartTime("/proc", os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	go func() {
		c, e := ln.Accept()
		if e == nil {
			defer c.Close()
			c.SetDeadline(time.Now().Add(time.Second))
			var b [8]byte
			c.Read(b[:])
			c.Write([]byte("reply"))
		}
	}()
	ready := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		<-ready
		if mapped {
			fd, e := unix.Socket(unix.AF_INET6, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, unix.IPPROTO_TCP)
			if e != nil {
				done <- e
				return
			}
			defer unix.Close(fd)
			_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 1})
			target := netip.MustParseAddrPort(ln.Addr().String())
			v6 := netip.AddrFrom16(target.Addr().As16())
			e = unix.Connect(fd, &unix.SockaddrInet6{Port: int(target.Port()), Addr: v6.As16()})
			if e == nil {
				_, e = unix.Write(fd, []byte("request"))
			}
			if e == nil {
				var b [8]byte
				_, e = unix.Read(fd, b[:])
			}
			done <- e
			return
		}
		c, e := net.DialTimeout("tcp4", ln.Addr().String(), time.Second)
		if e != nil {
			done <- e
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(time.Second))
		_, e = c.Write([]byte("request"))
		if e == nil {
			var b [8]byte
			_, e = c.Read(b[:])
		}
		done <- e
	}()
	before := monotime.Now()
	births := 0
	err = Run(ctx, Config{PID: os.Getpid(), StartTime: st, Server: netip.MustParseAddrPort(ln.Addr().String()), NetNS: uint32(ns), Duration: 2 * time.Second, Ready: func() { close(ready) }}, func(ev Event) error {
		if ev.Connected {
			births++
			if ev.TimestampNS < before || ev.TimestampNS > monotime.Now() || ev.LocalIP.IsUnspecified() || ev.RemotePort == 0 {
				t.Errorf("invalid connection proof: %+v", ev)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	if births != 1 {
		t.Fatalf("need one proved connect, got %d", births)
	}
}
