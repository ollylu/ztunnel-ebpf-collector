package livehttp

import (
	"net/netip"
	"testing"
	"ztunnel-ebpf-collector/internal/replay"
	"ztunnel-ebpf-collector/internal/tcpcapture"
)

func TestMixedProtocolsSeparateConnectionState(t *testing.T) {
	a := Analyzer{Marker: replay.Marker{Header: "Debug-Token", Value: "yes"}}
	h2q, h2r := wire(true), wire(false)
	h2q.request(1, true, "text/plain")
	_ = h2q.fr.WriteData(1, true, []byte("h2"))
	h2r.headers(1, false, ":status", "200")
	_ = h2r.fr.WriteData(1, true, []byte("h2reply"))
	gq, gr := wire(true), wire(false)
	gq.request(1, true, "application/grpc")
	_ = gq.fr.WriteData(1, true, envelope("rpc"))
	gr.headers(1, false, ":status", "200", "content-type", "application/grpc")
	_ = gr.fr.WriteData(1, false, envelope("rpcreply"))
	gr.headers(1, true, "grpc-status", "0")
	requests := [][]byte{[]byte("GET /h1 HTTP/1.1\r\nHost: demo\r\nDebug-Token: yes\r\n\r\n"), h2q.Bytes(), gq.Bytes()}
	responses := [][]byte{[]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"), h2r.Bytes(), gr.Bytes()}
	protocols := []string{"HTTP/1.1", "HTTP/2", "gRPC"}
	ids := map[string]bool{}
	// Same inode/netns deliberately reused with distinct endpoints: stale
	// connection state must not cross to another endpoint or HTTP/2 table.
	event := func(i int, b []byte, write bool) tcpcapture.Event {
		return tcpcapture.Event{Inode: 1, NetNS: 2, LocalIP: netip.MustParseAddr("10.0.0.1"), LocalPort: 1234, RemoteIP: netip.MustParseAddr("10.0.0.2"), RemotePort: uint16(8080 + i), Data: b, Write: write}
	}
	for offset := 0; offset < 500; offset += 3 {
		for i, b := range requests {
			if offset < len(b) {
				rs, err := a.Push(event(i, b[offset:min(offset+3, len(b))], true))
				if err != nil || len(rs) != 0 {
					t.Fatalf("request fragment: %v %v", rs, err)
				}
			}
		}
	}
	for _, i := range []int{2, 0, 1} {
		rs, err := a.Push(event(i, responses[i], false))
		if err != nil || len(rs) != 2 || rs[0].Protocol != protocols[i] || rs[0].RequestID != rs[1].RequestID || ids[rs[0].RequestID] {
			t.Fatalf("mixed connection %d: %+v %v", i, rs, err)
		}
		ids[rs[0].RequestID] = true
	}
}

func TestUnknownProtocolAndGlobalConnectionBudget(t *testing.T) {
	a := Analyzer{Marker: replay.Marker{Header: "Debug-Token", Value: "yes"}}
	for i := uint64(1); i <= 64; i++ {
		rs, err := a.Push(tcpcapture.Event{Inode: i, NetNS: 2, Write: true, Data: []byte("unknown protocol\r\n\r\n")})
		if err != nil || len(rs) != 0 {
			t.Fatalf("unknown protocol emitted or early budget failure: %v %v", rs, err)
		}
	}
	if _, err := a.Push(tcpcapture.Event{Inode: 65, NetNS: 2, Write: true, Data: []byte("GET / HTTP/1.1\r\n")}); err == nil {
		t.Fatal("global connection budget exceeded without reporting")
	}
}
