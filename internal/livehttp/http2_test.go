package livehttp

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"testing"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
	"ztunnel-ebpf-collector/internal/replay"
	"ztunnel-ebpf-collector/internal/tcpcapture"
)

type h2wire struct {
	bytes.Buffer
	table bytes.Buffer
	enc   *hpack.Encoder
	fr    *http2.Framer
}

func wire(client bool) *h2wire {
	w := &h2wire{}
	w.enc = hpack.NewEncoder(&w.table)
	w.fr = http2.NewFramer(&w.Buffer, nil)
	if client {
		w.WriteString(http2.ClientPreface)
	}
	_ = w.fr.WriteSettings()
	return w
}
func (w *h2wire) headers(id uint32, end bool, fields ...string) {
	w.table.Reset()
	for i := 0; i < len(fields); i += 2 {
		_ = w.enc.WriteField(hpack.HeaderField{Name: fields[i], Value: fields[i+1]})
	}
	_ = w.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, EndStream: end, EndHeaders: true, BlockFragment: w.table.Bytes()})
}
func (w *h2wire) request(id uint32, marked bool, ct string) {
	f := []string{":method", "POST", ":scheme", "http", ":authority", "demo", ":path", "/demo.Echo/Call", "content-type", ct}
	if marked {
		f = append(f, "debug-token", "yes")
	}
	w.headers(id, false, f...)
}
func envelope(s string) []byte {
	b := make([]byte, 5+len(s))
	binary.BigEndian.PutUint32(b[1:], uint32(len(s)))
	copy(b[5:], s)
	return b
}
func feed(t *testing.T, a *Analyzer, b []byte, write bool) []replay.Record {
	t.Helper()
	var out []replay.Record
	for len(b) > 0 {
		n := min(7, len(b))
		r, e := a.Push(tcpcapture.Event{Inode: 1, NetNS: 2, Write: write, Data: b[:n]})
		if e != nil {
			t.Fatal(e)
		}
		out = append(out, r...)
		b = b[n:]
	}
	return out
}
func TestHTTP2MultiplexedMarkerIsolation(t *testing.T) {
	a := Analyzer{Marker: replay.Marker{Header: "Debug-Token", Value: "yes"}}
	req, resp := wire(true), wire(false)
	req.request(1, true, "text/plain")
	req.request(3, false, "text/plain")
	_ = req.fr.WriteData(3, true, []byte("secret"))
	_ = req.fr.WriteData(1, true, []byte("hello"))
	resp.headers(3, false, ":status", "200")
	_ = resp.fr.WriteData(3, true, []byte("hidden"))
	resp.headers(1, false, ":status", "200")
	_ = resp.fr.WriteData(1, true, []byte("world"))
	feed(t, &a, req.Bytes(), true)
	r := feed(t, &a, resp.Bytes(), false)
	if len(r) != 2 || r[0].Protocol != "HTTP/2" || r[0].Path != "/demo.Echo/Call" || r[0].RequestID != r[1].RequestID {
		t.Fatalf("missing/misassociated HTTP2 marked pair: %+v", r)
	}
	if r[0].Body != "aGVsbG8=" || r[1].Body != "d29ybGQ=" {
		t.Fatalf("binary bytes not preserved: %+v", r)
	}
}
func TestGRPCMessagesTrailersAndDynamicHPACK(t *testing.T) {
	a := Analyzer{Marker: replay.Marker{Header: "Debug-Token", Value: "yes"}}
	req, resp := wire(true), wire(false)
	// Repeated indexed headers across streams must keep both HPACK tables in sync.
	for _, id := range []uint32{1, 3, 5} {
		req.request(id, id != 3, "application/grpc+proto")
		_ = req.fr.WriteData(id, true, envelope("request"))
	}
	for _, id := range []uint32{3, 5, 1} {
		resp.headers(id, false, ":status", "200", "content-type", "application/grpc")
		_ = resp.fr.WriteData(id, false, append(envelope("one"), envelope("two")...))
		resp.headers(id, true, "grpc-status", "0")
	}
	feed(t, &a, req.Bytes(), true)
	r := feed(t, &a, resp.Bytes(), false)
	if len(r) != 4 {
		t.Fatalf("want 2 marked RPC pairs, got %+v", r)
	}
	for i := 0; i < len(r); i += 2 {
		b, _ := json.Marshal(r[i+1])
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		msgs, _ := m["grpc_messages"].([]any)
		if r[i].Protocol != "gRPC" || r[i].RequestID != r[i+1].RequestID || m["grpc_status"] != float64(0) || len(msgs) != 2 || msgs[0] != "b25l" || msgs[1] != "dHdv" {
			t.Fatalf("missing RPC framing/status: %s", b)
		}
	}
}

func TestHTTP2ContinuationAndTrailersOnlyError(t *testing.T) {
	a := Analyzer{Marker: replay.Marker{Header: "Debug-Token", Value: "yes"}}
	req, resp := wire(true), wire(false)
	req.table.Reset()
	for _, f := range []hpack.HeaderField{{Name: ":method", Value: "POST"}, {Name: ":scheme", Value: "http"}, {Name: ":path", Value: "/demo.Echo/Call"}, {Name: "content-type", Value: "application/grpc"}, {Name: "debug-token", Value: "yes"}} {
		_ = req.enc.WriteField(f)
	}
	block := append([]byte{}, req.table.Bytes()...)
	_ = req.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: block[:3]})
	_ = req.fr.WriteContinuation(1, true, block[3:])
	_ = req.fr.WriteData(1, true, envelope("error"))
	resp.headers(1, true, ":status", "200", "content-type", "application/grpc", "grpc-status", "5")
	feed(t, &a, req.Bytes(), true)
	r := feed(t, &a, resp.Bytes(), false)
	if len(r) != 2 || r[1].GRPCStatus == nil || *r[1].GRPCStatus != 5 {
		t.Fatalf("trailers-only error missing: %+v", r)
	}
}
func TestHTTP2RejectsUntrustedPairs(t *testing.T) {
	for _, kind := range []string{"duplicate-marker", "trailer-marker", "reset", "missing-preface", "compressed", "truncated-grpc", "missing-grpc-status", "oversized-body", "goaway", "bad-continuation"} {
		t.Run(kind, func(t *testing.T) {
			a := Analyzer{Marker: replay.Marker{Header: "debug-token", Value: "yes"}}
			req, resp := wire(true), wire(false)
			fields := []string{":method", "POST", ":scheme", "http", ":path", "/demo.Echo/Call", "content-type", "application/grpc"}
			if kind != "trailer-marker" {
				fields = append(fields, "debug-token", "yes")
			}
			if kind == "duplicate-marker" {
				fields = append(fields, "debug-token", "yes")
			}
			req.headers(1, false, fields...)
			body := envelope("hello")
			if kind == "compressed" {
				body[0] = 1
			}
			if kind == "truncated-grpc" {
				body = body[:len(body)-1]
			}
			if kind == "oversized-body" {
				body = bytes.Repeat([]byte{0}, 8193)
			}
			_ = req.fr.WriteData(1, kind != "trailer-marker", body)
			if kind == "trailer-marker" {
				req.headers(1, true, "debug-token", "yes")
			}
			if kind == "bad-continuation" {
				_ = req.fr.WriteContinuation(1, true, []byte{0})
			}
			resp.headers(1, false, ":status", "200", "content-type", "application/grpc")
			if kind == "reset" {
				_ = resp.fr.WriteRSTStream(1, http2.ErrCodeCancel)
			}
			if kind == "goaway" {
				_ = resp.fr.WriteGoAway(0, http2.ErrCodeNo, nil)
			}
			_ = resp.fr.WriteData(1, kind == "missing-grpc-status", envelope("reply"))
			if kind != "missing-grpc-status" {
				resp.headers(1, true, "grpc-status", "0")
			}
			b := req.Bytes()
			if kind == "missing-preface" {
				b = b[len(http2.ClientPreface):]
			}
			r := feed(t, &a, b, true)
			r = append(r, feed(t, &a, resp.Bytes(), false)...)
			if len(r) != 0 {
				t.Fatalf("unsafe pair emitted: %+v", r)
			}
		})
	}
}

func TestGRPCFiniteBidirectionalWaitsForBothEnds(t *testing.T) {
	a := Analyzer{Marker: replay.Marker{Header: "debug-token", Value: "yes"}}
	req, resp := wire(true), wire(false)
	req.request(1, true, "application/grpc")
	_ = req.fr.WriteData(1, false, envelope("first"))
	feed(t, &a, req.Bytes(), true)
	resp.headers(1, false, ":status", "200", "content-type", "application/grpc")
	_ = resp.fr.WriteData(1, false, envelope("reply"))
	resp.headers(1, true, "grpc-status", "0")
	if r := feed(t, &a, resp.Bytes(), false); len(r) != 0 {
		t.Fatal("emitted before request END_STREAM")
	}
	req.Reset()
	_ = req.fr.WriteData(1, true, envelope("second"))
	r := feed(t, &a, req.Bytes(), true)
	if len(r) != 2 || len(r[0].GRPCMessages) != 2 || r[0].GRPCMessages[0] != "Zmlyc3Q=" || r[0].GRPCMessages[1] != "c2Vjb25k" {
		t.Fatalf("client messages not reassembled: %+v", r)
	}
}

// A cancelled RPC must not remove other marked streams sharing its HTTP/2 socket.
func TestCancelledStreamDoesNotPoisonOtherRPC(t *testing.T) {
	a := Analyzer{Marker: replay.Marker{Header: "Debug-Token", Value: "yes"}}
	req, resp := wire(true), wire(false)
	for _, id := range []uint32{1, 3, 5} {
		req.request(id, id != 5, "application/grpc")
		_ = req.fr.WriteData(id, true, envelope("request"))
	}
	_ = resp.fr.WriteRSTStream(1, http2.ErrCodeCancel)
	for _, id := range []uint32{5, 3} {
		resp.headers(id, false, ":status", "200", "content-type", "application/grpc")
		_ = resp.fr.WriteData(id, false, envelope("reply"))
		resp.headers(id, true, "grpc-status", "0")
	}
	feed(t, &a, req.Bytes(), true)
	got := feed(t, &a, resp.Bytes(), false)
	if len(got) != 2 || got[0].StreamID != 3 || got[1].StreamID != 3 {
		t.Fatalf("cancelled/unmarked stream leaked or other RPC lost: %+v", got)
	}
}
