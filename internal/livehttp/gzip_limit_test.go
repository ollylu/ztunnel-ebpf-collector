package livehttp

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"testing"
	"ztunnel-ebpf-collector/internal/replay"
)

func gzipBytes(t testing.TB, raw []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	z := gzip.NewWriter(&b)
	if _, e := z.Write(raw); e != nil {
		t.Fatal(e)
	}
	if e := z.Close(); e != nil {
		t.Fatal(e)
	}
	return b.Bytes()
}

func TestGzipFiveKBOutputBoundaryAndFollowingRequest(t *testing.T) {
	for _, n := range []int{5119, 5120, 5121, 5_000_000} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			a := Analyzer{Marker: replay.Marker{Header: "debug-token", Value: "yes"}}
			for _, size := range []int{n, 7} {
				raw := bytes.Repeat([]byte("a"), size)
				body := gzipBytes(t, raw)
				req := append([]byte(fmt.Sprintf("POST / HTTP/1.1\r\nHost: demo\r\nDebug-Token: yes\r\nContent-Encoding: gzip\r\nContent-Length: %d\r\n\r\n", len(body))), body...)
				resp := append([]byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: %d\r\n\r\n", len(body))), body...)
				pushLarge(t, &a, req, true)
				got := pushLarge(t, &a, resp, false)
				if len(got) != 2 {
					t.Fatalf("missing pair: %d", len(got))
				}
				for _, r := range got {
					if r.Body != string(raw[:min(size, 5120)]) || r.Truncated != (size > 5120) || r.ContentDecoding != "gzip" {
						t.Fatalf("size %d: retained=%d truncated=%v decoding=%s", size, len(r.Body), r.Truncated, r.ContentDecoding)
					}
				}
			}
			if len(a.DrainSuppressed()) != 0 {
				t.Fatal("printing limit suppressed connection")
			}
		})
	}
}

func TestGRPCGzipFiveKBTotalAcrossMessages(t *testing.T) {
	var g grpcPrefix
	for _, size := range []int{3000, 3000, 5_000_000} {
		body := gzipBytes(t, bytes.Repeat([]byte("a"), size))
		msg := envelope(string(body))
		msg[0] = 1
		if e := g.add(msg, true, "gzip"); e != nil {
			t.Fatal(e)
		}
	}
	total := 0
	for _, s := range g.messages {
		b, e := base64.StdEncoding.DecodeString(s)
		if e != nil {
			t.Fatal(e)
		}
		total += len(b)
	}
	if total != 5120 || !g.cut || !g.complete() {
		t.Fatalf("retained=%d cut=%v complete=%v", total, g.cut, g.complete())
	}
}

func BenchmarkGzipMarkedPrefix(b *testing.B) {
	raw := bytes.Repeat([]byte("a"), 5_000_000)
	wire := gzipBytes(b, raw)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p := bodyPrefix{compressed: true, selected: true}
		p.add(wire)
		_, _, e := p.output()
		if e != nil {
			b.Fatal(e)
		}
	}
}
