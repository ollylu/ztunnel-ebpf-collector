package livehttp

import (
	"golang.org/x/net/http2"
	"testing"
	"time"
	"ztunnel-ebpf-collector/internal/replay"
)

// Regression tests for independent stream expiry and graceful drain.
// No kernel, cluster or network required. Existing package wire/feed helpers used.
func TestReviewSlowRPCIsolation(t *testing.T) {
	for _, expire := range []bool{false, true} {
		name := "control"
		if expire {
			name = "one_idle_RPC"
		}
		t.Run(name, func(t *testing.T) {
			a := Analyzer{Marker: replay.Marker{Header: "debug-token", Value: "yes"}}
			req, resp := wire(true), wire(false)
			req.request(1, true, "application/grpc")
			_ = req.fr.WriteData(1, true, envelope("waiting"))
			feed(t, &a, req.Bytes(), true)
			req.Reset()
			feed(t, &a, resp.Bytes(), false)
			resp.Reset()
			if expire {
				for _, c := range a.streams {
					c.h2.streams[1].seen = time.Now().Add(-6 * time.Second)
				}
				a.Sweep(time.Now())
			}
			req.request(3, true, "application/grpc")
			_ = req.fr.WriteData(3, true, envelope("healthy"))
			resp.headers(3, false, ":status", "200", "content-type", "application/grpc")
			_ = resp.fr.WriteData(3, false, envelope("OK"))
			resp.headers(3, true, "grpc-status", "0")
			feed(t, &a, req.Bytes(), true)
			got := feed(t, &a, resp.Bytes(), false)
			if len(got) != 2 {
				t.Fatalf("healthy stream 3: want request+response, got %d; quarantined connections=%d", len(got), len(a.DrainSuppressed()))
			}
		})
	}
}

func TestReviewGracefulGOAWAYDrain(t *testing.T) {
	for _, draining := range []bool{false, true} {
		name := "control"
		if draining {
			name = "NO_ERROR_GOAWAY"
		}
		t.Run(name, func(t *testing.T) {
			a := Analyzer{Marker: replay.Marker{Header: "debug-token", Value: "yes"}}
			req, resp := wire(true), wire(false)
			req.request(1, true, "application/grpc")
			_ = req.fr.WriteData(1, true, envelope("request"))
			if draining {
				_ = resp.fr.WriteGoAway(1, http2.ErrCodeNo, nil)
			}
			resp.headers(1, false, ":status", "200", "content-type", "application/grpc")
			_ = resp.fr.WriteData(1, false, envelope("OK"))
			resp.headers(1, true, "grpc-status", "0")
			feed(t, &a, req.Bytes(), true)
			got := feed(t, &a, resp.Bytes(), false)
			if len(got) != 2 {
				t.Fatalf("accepted stream 1 draining: want request+response, got %d; quarantined connections=%d", len(got), len(a.DrainSuppressed()))
			}
		})
	}
}

func TestRetiredStreamLateHeadersKeepHPACKWithoutReopening(t *testing.T) {
	a := Analyzer{Marker: replay.Marker{Header: "debug-token", Value: "yes"}}
	req, resp := wire(true), wire(false)
	req.request(1, true, "application/grpc")
	feed(t, &a, req.Bytes(), true)
	req.Reset()
	for _, c := range a.streams {
		c.h2.streams[1].seen = time.Now().Add(-6 * time.Second)
	}
	a.Sweep(time.Now())
	req.headers(1, true, "late-trailer", "must-not-reopen")
	req.request(3, true, "application/grpc")
	_ = req.fr.WriteData(3, true, envelope("fresh"))
	resp.headers(1, true, ":status", "200")
	resp.headers(3, false, ":status", "200", "content-type", "application/grpc")
	_ = resp.fr.WriteData(3, false, envelope("ok"))
	resp.headers(3, true, "grpc-status", "0")
	feed(t, &a, req.Bytes(), true)
	got := feed(t, &a, resp.Bytes(), false)
	if len(got) != 2 || got[0].StreamID != 3 || len(a.DrainSuppressed()) != 0 {
		t.Fatalf("retired stream affected fresh stream: %+v", got)
	}
}
func TestServerGOAWAYRejectsOnlyUnacceptedStreams(t *testing.T) {
	a := Analyzer{Marker: replay.Marker{Header: "debug-token", Value: "yes"}}
	req, resp := wire(true), wire(false)
	for _, id := range []uint32{1, 3} {
		req.request(id, true, "text/plain")
		_ = req.fr.WriteData(id, true, []byte("body"))
	}
	feed(t, &a, req.Bytes(), true)
	_ = resp.fr.WriteGoAway(1, http2.ErrCodeNo, nil)
	for _, id := range []uint32{3, 1} {
		resp.headers(id, true, ":status", "200")
	}
	got := feed(t, &a, resp.Bytes(), false)
	if len(got) != 2 || got[0].StreamID != 1 {
		t.Fatalf("wrong drain result: %+v", got)
	}
}
