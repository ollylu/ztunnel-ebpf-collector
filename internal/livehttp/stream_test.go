package livehttp

import (
	"net/netip"
	"testing"
	"ztunnel-ebpf-collector/internal/replay"
	"ztunnel-ebpf-collector/internal/tcpcapture"
)

func TestRealStreamFramingAndConfigurableMarker(t *testing.T) {
	a := Analyzer{Marker: replay.Marker{Header: "Debug-Token", Value: "yes"}}
	req := []byte("GET /live HTTP/1.1\r\nHost: demo\r\nDebug-Token: yes\r\n\r\n")
	resp := []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
	for _, b := range [][]byte{req[:20], req[20:]} {
		r, e := a.Push(tcpcapture.Event{Inode: 1, NetNS: 2, Write: true, Data: b})
		if e != nil || len(r) != 0 {
			t.Fatal(r, e)
		}
	}
	r, e := a.Push(tcpcapture.Event{Inode: 1, NetNS: 2, Data: resp})
	if e != nil || len(r) != 2 || r[1].Body != "OK" {
		t.Fatalf("pair not reconstructed: %+v %v", r, e)
	}
	// Same connection, next unmarked request must not inherit the previous marker.
	_, e = a.Push(tcpcapture.Event{Inode: 1, NetNS: 2, Write: true, Data: []byte("GET /plain HTTP/1.1\r\nHost: demo\r\n\r\n")})
	if e != nil {
		t.Fatal(e)
	}
	r, e = a.Push(tcpcapture.Event{Inode: 1, NetNS: 2, Data: resp})
	if e != nil || len(r) != 0 {
		t.Fatalf("connection taint leaked: %+v %v", r, e)
	}
}

func TestOutboundReadIsRequest(t *testing.T) {
	a := Analyzer{Marker: replay.Marker{Header: "Debug-Token", Value: "yes"}}
	e := tcpcapture.Event{Inode: 9, NetNS: 2, Outbound: true, Data: []byte("GET /out HTTP/1.1\r\nHost: b\r\nDebug-Token: yes\r\n\r\n")}
	if rs, err := a.Push(e); err != nil || len(rs) != 0 {
		t.Fatal(rs, err)
	}
	e.Write = true
	e.Data = []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
	rs, err := a.Push(e)
	if err != nil || len(rs) != 2 || rs[0].Path != "/out" || rs[1].Body != "OK" {
		t.Fatalf("outbound pair missing: %+v %v", rs, err)
	}
	e.Write = false
	e.Data = []byte("GET /plain HTTP/1.1\r\nHost: b\r\n\r\n")
	a.Push(e)
	e.Write = true
	e.Data = []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
	if rs, err := a.Push(e); err != nil || len(rs) != 0 {
		t.Fatal("connection marker leaked", rs, err)
	}
}

func TestOutboundMetadataAndRevocation(t *testing.T) {
	a := Analyzer{Marker: replay.Marker{Header: "Debug-Token", Value: "yes"}}
	e := tcpcapture.Event{Outbound: true, Inode: 3, NetNS: 1, LocalIP: netip.MustParseAddr("127.0.0.1"), LocalPort: 15001, RemoteIP: netip.MustParseAddr("10.0.0.2"), RemotePort: 42000, OriginalDestination: netip.MustParseAddrPort("10.96.0.1:8080")}
	if rs, err := a.Push(e); err != nil || len(rs) != 0 {
		t.Fatal(rs, err)
	}
	e.OriginalDestination = netip.AddrPort{}
	e.Data = []byte("GET /meta HTTP/1.1\r\nHost: b\r\nDebug-Token: yes\r\n\r\n")
	a.Push(e)
	e.Write = true
	e.Data = []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
	rs, err := a.Push(e)
	if err != nil || len(rs) != 2 || rs[0].OriginalDestination != "10.96.0.1:8080" || rs[1].OriginalDestination != "10.96.0.1:8080" {
		t.Fatal(rs, err)
	}
	a.Forget(e.Target())
	if len(a.streams) != 0 {
		t.Fatal("outbound parser retained after revocation")
	}
	// Reused tuple/inode has no authority to inherit original-destination metadata.
	e.Write = false
	e.Data = []byte("GET /new HTTP/1.1\r\nHost: b\r\nDebug-Token: yes\r\n\r\n")
	a.Push(e)
	e.Write = true
	e.Data = []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
	rs, err = a.Push(e)
	if err != nil || len(rs) != 2 || rs[0].OriginalDestination != "unknown" {
		t.Fatal("stale destination reused", rs, err)
	}
}

func TestBeginDropsOldSocketIncarnation(t *testing.T) {
	a := Analyzer{Marker: replay.Marker{Header: "Debug-Token", Value: "yes"}}
	e := tcpcapture.Event{Inode: 1, NetNS: 2, Generation: 3, Write: true, Data: []byte("GE")}
	a.Push(e)
	a.Begin(e)
	e.Data = []byte("GET /new HTTP/1.1\r\nHost: demo\r\nDebug-Token: yes\r\n\r\n")
	a.Push(e)
	e.Write = false
	e.Data = []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
	rs, err := a.Push(e)
	if err != nil || len(rs) != 2 || rs[0].Method != "GET" || rs[0].Path != "/new" {
		t.Fatal("old socket bytes leaked into new connection", rs, err)
	}
}
