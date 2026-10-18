package livehttp

import (
	"net/netip"
	"testing"
	"time"
	"ztunnel-ebpf-collector/internal/replay"
	"ztunnel-ebpf-collector/internal/tcpcapture"
)

func TestCloseReleasesConnectionBudget(t *testing.T) {
	a := Analyzer{Marker: replay.Marker{Header: "debug-token", Value: "yes"}}
	e := tcpcapture.Event{NetNS: 1, LocalIP: netip.MustParseAddr("10.0.0.1"), RemoteIP: netip.MustParseAddr("10.0.0.2"), RemotePort: 8080, Write: true}
	for i := 1; i <= 130; i++ {
		e.Inode = uint64(i)
		e.Closed = false
		e.Data = []byte("invalid\r\n\r\n")
		if _, err := a.Push(e); err != nil {
			t.Fatalf("closed connections consumed budget at %d: %v", i, err)
		}
		e.Closed = true
		e.Data = nil
		if rs, err := a.Push(e); err != nil || len(rs) != 0 {
			t.Fatal(rs, err)
		}
	}
	if len(a.streams) != 0 {
		t.Fatal("closed state retained", len(a.streams))
	}
}
func TestSweepDropsIncompletePayloadWithoutResynchronizing(t *testing.T) {
	a := Analyzer{Marker: replay.Marker{Header: "debug-token", Value: "yes"}}
	k := key{inode: 1}
	a.streams = map[key]*connection{k: {seen: time.Now().Add(-6 * time.Second), request: []byte("secret")}}
	a.Sweep(time.Now())
	c := a.streams[k]
	if c == nil || !c.poison || len(c.request) != 0 {
		t.Fatal("incomplete payload retained or unsafe resync allowed")
	}
}
