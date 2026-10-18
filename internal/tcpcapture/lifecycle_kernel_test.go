//go:build linux && amd64 && kernel

package tcpcapture

import (
	"context"
	"errors"
	"fmt"
	"github.com/cilium/ebpf"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
	"ztunnel-ebpf-collector/internal/discovery"
)

// A parsed (never suppressed) socket must release its admission after a peer
// reset. Linux clears its local port before close; endpoint lookup then fails.
func TestRealParsedSocketResetClose(t *testing.T) {
	for _, outbound := range []bool{false, true} {
		t.Run(fmt.Sprint(outbound), func(t *testing.T) { testParsedReset(t, outbound, false) })
	}
}
func TestRealBufferedReplyAfterReset(t *testing.T) { testParsedReset(t, false, true) }
func testParsedReset(t *testing.T, outbound, buffered bool) {
	ln, err := net.Listen("tcp4", "127.0.0.200:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
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
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	ready, captured := make(chan struct{}), make(chan struct{}, 1)
	reclaimed := make(chan struct{}, 1)
	result := make(chan error, 1)
	go func() {
		<-ready
		for round := 0; round < 70; round++ {
			c, e := (&net.Dialer{Timeout: time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.201")}}).Dial("tcp4", ln.Addr().String())
			if e != nil {
				result <- e
				cancel()
				return
			}
			defer c.Close()
			peer, e := ln.Accept()
			if e != nil {
				result <- e
				cancel()
				return
			}
			defer peer.Close()
			c.SetDeadline(time.Now().Add(3 * time.Second))
			if _, e = c.Write([]byte("GET / HTTP/1.1\r\nHost: test\r\n\r\n")); e != nil {
				result <- e
				cancel()
				return
			}
			if outbound {
				peer.SetReadDeadline(time.Now().Add(time.Second))
				var b [4096]byte
				if _, e = peer.Read(b[:]); e != nil {
					result <- e
					cancel()
					return
				}
			}
			select {
			case <-captured:
			case <-ctx.Done():
				result <- ctx.Err()
				return
			}
			resetter, reader := peer, c
			if outbound {
				resetter, reader = c, peer
			}
			if buffered {
				if _, e = peer.Write([]byte("buffered-reply")); e != nil {
					result <- e
					cancel()
					return
				}
				time.Sleep(20 * time.Millisecond)
			}
			resetter.(*net.TCPConn).SetLinger(0)
			resetter.Close()
			reader.SetDeadline(time.Now().Add(time.Second))
			var b [4096]byte
			n, readErr := reader.Read(b[:])
			e = readErr
			if buffered && n > 0 && string(b[:n]) == "buffered-reply" {
				_, e = reader.Read(b[:])
			}
			if e == nil {
				result <- fmt.Errorf("reset missing")
				cancel()
				return
			}
			reader.Close()
			select {
			case <-reclaimed:
			case <-ctx.Done():
				result <- ctx.Err()
				return
			}
		}
		result <- nil
		cancel()
	}()
	target := Endpoint{NetNS: uint32(ns), Server: netip.MustParseAddrPort(ln.Addr().String())}
	if outbound {
		target.Server = netip.AddrPortFrom(netip.MustParseAddr("127.0.0.201"), target.Server.Port())
		target.Outbound = true
	}
	var inode uint64
	closed := 0
	bufferedSeen := 0
	err = Run(ctx, Config{PID: os.Getpid(), StartTime: st, Duration: 20 * time.Second, Targets: []Endpoint{target}, Ready: func() { close(ready) }}, func(e Event) error {
		if buffered && !e.Write && string(e.Data) == "buffered-reply" {
			bufferedSeen++
		}
		if len(e.Data) > 0 && e.Inode != inode {
			inode = e.Inode
			captured <- struct{}{}
		}
		if e.Closed && e.Inode == inode {
			closed++
			reclaimed <- struct{}{}
		}
		return nil
	})
	if err != nil && ctx.Err() == nil {
		t.Fatal(err)
	}
	select {
	case e := <-result:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("business reset did not finish")
	}
	if buffered && bufferedSeen != 70 {
		t.Fatalf("buffered replies silently lost: %d", bufferedSeen)
	}
	if inode == 0 || closed != 70 {
		t.Fatalf("parsed socket close lost after reset: inode=%d closed=%d", inode, closed)
	}
}

func TestRealAdmissionRevocationAndOldClose(t *testing.T) {
	m, err := ebpf.NewMap(&ebpf.MapSpec{Name: "zc_test_admit", Type: ebpf.Hash, KeySize: 16, ValueSize: 40, MaxEntries: 64})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	e := suppressionEvent()
	active := map[Endpoint]uint64{e.Target(): 1}
	for i := uint64(1); i <= 64; i++ {
		e.Inode = i
		k, _ := suppressionKey(e)
		if err := m.Put(suppressionMapKey(k), k); err != nil {
			t.Fatal(err)
		}
	}
	e.Inode = 65
	k, _ := suppressionKey(e)
	if err := m.Put(suppressionMapKey(k), k); err == nil {
		t.Fatal("admission capacity bypass")
	}
	e.Inode = 1
	old, _ := suppressionKey(e)
	e.Generation = 2
	newer, _ := suppressionKey(e)
	if err := m.Put(suppressionMapKey(newer), newer); err != nil {
		t.Fatal(err)
	}
	if err := removeAdmission(m, old); err != nil {
		t.Fatal(err)
	}
	var got [40]byte
	if err := m.Lookup(suppressionMapKey(newer), &got); err != nil || got != newer {
		t.Fatal("old close removed new generation", err)
	}
	if err := revokeAdmissions(m, active); err != nil {
		t.Fatal(err)
	}
	if err := m.Lookup(suppressionMapKey(newer), &got); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatal("revoked admission retained", err)
	}
	if err := revokeAdmissions(m, nil); err != nil {
		t.Fatal(err)
	}
	iter := m.Iterate()
	var id [16]byte
	if iter.Next(&id, &got) || iter.Err() != nil {
		t.Fatal("normal admissions leaked", iter.Err())
	}
}
