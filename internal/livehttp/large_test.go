package livehttp

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"strings"
	"testing"
	"time"
	"ztunnel-ebpf-collector/internal/replay"
	"ztunnel-ebpf-collector/internal/tcpcapture"
)

func pushLarge(t *testing.T, a *Analyzer, b []byte, write bool) []replay.Record {
	t.Helper()
	var out []replay.Record
	for len(b) > 0 {
		n := min(16000, len(b))
		rs, e := a.Push(tcpcapture.Event{Inode: 7, NetNS: 2, Write: write, Data: b[:n]})
		if e != nil {
			t.Fatal(e)
		}
		out = append(out, rs...)
		b = b[n:]
	}
	return out
}
func TestLargeHTTPTruncatesOutputKeepsSameConnection(t *testing.T) {
	for _, compressed := range []bool{false, true} {
		t.Run(fmt.Sprint(compressed), func(t *testing.T) {
			a := Analyzer{Marker: replay.Marker{Header: "debug-token", Value: "yes"}}
			body := []byte(strings.Repeat("a", 5_000_000))
			encoding := ""
			if compressed {
				var b bytes.Buffer
				w := gzip.NewWriter(&b)
				w.Write(body)
				w.Close()
				body = b.Bytes()
				encoding = "Content-Encoding: gzip\r\n"
			}
			for _, marked := range []bool{true, false, true} {
				marker := ""
				if marked {
					marker = "Debug-Token: yes\r\n"
				}
				req := append([]byte(fmt.Sprintf("POST /large HTTP/1.1\r\nHost: demo\r\n%s%sContent-Length: %d\r\n\r\n", marker, encoding, len(body))), body...)
				resp := append([]byte(fmt.Sprintf("HTTP/1.1 200 OK\r\n%sContent-Length: %d\r\n\r\n", encoding, len(body))), body...)
				pushLarge(t, &a, req, true)
				got := pushLarge(t, &a, resp, false)
				if !marked {
					if len(got) != 0 {
						t.Fatal("unmarked body leaked")
					}
					continue
				}
				if len(got) != 2 || len(got[0].Body) != 5120 || len(got[1].Body) != 5120 || !got[0].Truncated || !got[1].Truncated {
					t.Fatalf("expected bounded pair, got %d records", len(got))
				}
			}
			if len(a.DrainSuppressed()) != 0 {
				t.Fatal("large body quarantined connection")
			}
		})
	}
}

func TestLargeGRPCKeepsSubsequentStreams(t *testing.T) {
	for _, compressed := range []bool{false, true} {
		t.Run(fmt.Sprint(compressed), func(t *testing.T) {
			a := Analyzer{Marker: replay.Marker{Header: "debug-token", Value: "yes"}}
			req, resp := wire(true), wire(false)
			raw := []byte(strings.Repeat("a", 5_000_000))
			body := raw
			encoding := "identity"
			if compressed {
				var b bytes.Buffer
				w := gzip.NewWriter(&b)
				w.Write(raw)
				w.Close()
				body = b.Bytes()
				encoding = "gzip"
			}
			for _, id := range []uint32{1, 3, 5} {
				fields := []string{":method", "POST", ":scheme", "http", ":path", "/large", ":authority", "demo", "content-type", "application/grpc", "grpc-encoding", encoding}
				if id != 3 {
					fields = append(fields, "debug-token", "yes")
				}
				req.headers(id, false, fields...)
				msg := envelope(string(body))
				if compressed {
					msg[0] = 1
				}
				for len(msg) > 0 {
					n := min(16000, len(msg))
					_ = req.fr.WriteData(id, n == len(msg), msg[:n])
					msg = msg[n:]
				}
				resp.headers(id, false, ":status", "200", "content-type", "application/grpc", "grpc-encoding", encoding)
				msg = envelope(string(body))
				if compressed {
					msg[0] = 1
				}
				for len(msg) > 0 {
					n := min(16000, len(msg))
					_ = resp.fr.WriteData(id, false, msg[:n])
					msg = msg[n:]
				}
				resp.headers(id, true, "grpc-status", "0")
				pushLarge(t, &a, req.Bytes(), true)
				req.Reset()
				got := pushLarge(t, &a, resp.Bytes(), false)
				resp.Reset()
				if id == 3 {
					if len(got) != 0 {
						t.Fatal("unmarked gRPC leaked")
					}
					continue
				}
				if len(got) != 2 || len(got[0].GRPCMessages) != 1 || !got[0].Truncated || !got[1].Truncated {
					t.Fatalf("large gRPC missing pair: %d", len(got))
				}
			}
			if len(a.DrainSuppressed()) != 0 {
				t.Fatal("large RPC quarantined connection")
			}
		})
	}
}

func TestLargeHeadersStillCheckDuplicateMarkerBeyondOutput(t *testing.T) {
	for _, duplicate := range []bool{false, true} {
		a := Analyzer{Marker: replay.Marker{Header: "debug-token", Value: "yes"}}
		head := "POST /headers HTTP/1.1\r\nHost: demo\r\nDebug-Token: yes\r\nX-Large: " + strings.Repeat("a", 600000) + "\r\n"
		if duplicate {
			head += "Debug-Token: yes\r\n"
		}
		head += "Content-Length: 0\r\n\r\n"
		pushLarge(t, &a, []byte(head), true)
		got := pushLarge(t, &a, []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"), false)
		if duplicate {
			if len(got) != 0 {
				t.Fatal("duplicate marker beyond output budget leaked")
			}
			continue
		}
		if len(got) != 2 || !got[0].Truncated {
			t.Fatal("truncated headers missing")
		}
		n := 0
		for k, vs := range got[0].Headers {
			for _, v := range vs {
				n += len(k) + len(v)
			}
		}
		if n > 512<<10 {
			t.Fatal("header retention exceeds limit")
		}
	}
}
func TestChunkedBodyTruncationKeepsNextRequest(t *testing.T) {
	a := Analyzer{Marker: replay.Marker{Header: "debug-token", Value: "yes"}}
	body := strings.Repeat("a", 2<<20)
	for i := 0; i < 2; i++ {
		pushLarge(t, &a, []byte("POST /chunk HTTP/1.1\r\nHost: demo\r\nDebug-Token: yes\r\nTransfer-Encoding: chunked\r\n\r\n"), true)
		pushLarge(t, &a, []byte(fmt.Sprintf("%x\r\n%s\r\n0\r\n\r\n", len(body), body)), true)
		got := pushLarge(t, &a, []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"), false)
		if len(got) != 2 || !got[0].Truncated || len(got[0].Body) != 5120 {
			t.Fatalf("chunked pair missing: %d", len(got))
		}
	}
}

func TestHTTP2LargeNegotiatedDataFrameStreamsWithoutQuarantine(t *testing.T) {
	a := Analyzer{Marker: replay.Marker{Header: "debug-token", Value: "yes"}}
	req, resp := wire(true), wire(false)
	for _, id := range []uint32{1, 3} {
		req.request(id, true, "text/plain")
		b := bytes.Repeat([]byte("a"), 5_000_000)
		if id == 3 {
			b = []byte("after")
		}
		if e := req.fr.WriteData(id, true, b); e != nil {
			t.Fatal(e)
		}
		resp.headers(id, false, ":status", "200")
		if e := resp.fr.WriteData(id, true, b); e != nil {
			t.Fatal(e)
		}
		pushLarge(t, &a, req.Bytes(), true)
		req.Reset()
		got := pushLarge(t, &a, resp.Bytes(), false)
		resp.Reset()
		if len(got) != 2 {
			t.Fatalf("stream %d missing; rejected=%d", id, len(a.DrainSuppressed()))
		}
	}
}

func TestHTTP2PaddedLargeFrameKeepsBoundary(t *testing.T) {
	a := Analyzer{Marker: replay.Marker{Header: "debug-token", Value: "yes"}}
	req, resp := wire(true), wire(false)
	req.request(1, true, "text/plain")
	_ = req.fr.WriteDataPadded(1, true, bytes.Repeat([]byte("a"), 100000), make([]byte, 255))
	resp.headers(1, true, ":status", "200")
	pushLarge(t, &a, req.Bytes(), true)
	got := pushLarge(t, &a, resp.Bytes(), false)
	if len(got) != 2 {
		t.Fatal("padded frame lost")
	}
}

func TestExpiredH2StreamReleasesNodeRetentionAccounting(t *testing.T) {
	a := Analyzer{Marker: replay.Marker{Header: "debug-token", Value: "yes"}}
	req := wire(true)
	req.request(1, true, "text/plain")
	_ = req.fr.WriteData(1, true, bytes.Repeat([]byte("a"), 1<<20))
	pushLarge(t, &a, req.Bytes(), true)
	before := map[*connection]int{}
	for _, c := range a.streams {
		if c.retained < 5120 {
			t.Fatal("missing initial accounting")
		}
		before[c] = c.retained
		c.h2.streams[1].seen = time.Now().Add(-6 * time.Second)
	}
	a.Sweep(time.Now())
	for _, c := range a.streams {
		if before[c]-c.retained < 5120 {
			t.Fatalf("expired stream still charged %d bytes", c.retained)
		}
	}
}
