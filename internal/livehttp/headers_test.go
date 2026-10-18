package livehttp

import (
	"encoding/json"
	"strings"
	"testing"

	"ztunnel-ebpf-collector/internal/replay"
)

func TestHTTP2AndGRPCCompleteHeadersAndTrailers(t *testing.T) {
	for _, ct := range []string{"text/plain", "application/grpc"} {
		t.Run(ct, func(t *testing.T) {
			a := Analyzer{Marker: replay.Marker{Header: "debug-token", Value: "yes"}}
			req, resp := wire(true), wire(false)
			req.headers(1, false, ":method", "POST", ":scheme", "https", ":authority", "service:443", ":path", "/demo.Echo/Call", "content-type", ct, "debug-token", "yes", "authorization", "Bearer test-only", "x-multi", "one", "x-multi", "two", "dapr-app-id", "go-data", "custom-bin", "AAE=")
			payload := []byte("hello")
			if ct == "application/grpc" {
				payload = envelope("hello")
			}
			_ = req.fr.WriteData(1, true, payload)
			resp.headers(1, false, ":status", "200", "content-type", ct, "x-response", "present")
			_ = resp.fr.WriteData(1, false, payload)
			resp.headers(1, true, "grpc-status", "0", "x-trailer", "one", "x-trailer", "two")
			feed(t, &a, req.Bytes(), true)
			rs := feed(t, &a, resp.Bytes(), false)
			if len(rs) != 2 {
				t.Fatal("marked pair absent")
			}
			var records [2]struct {
				Headers  map[string][]string `json:"headers"`
				Trailers map[string][]string `json:"trailers"`
			}
			for i := range rs {
				b, err := json.Marshal(rs[i])
				if err != nil {
					t.Fatal(err)
				}
				if err := json.Unmarshal(b, &records[i]); err != nil {
					t.Fatal(err)
				}
			}
			h := records[0].Headers
			for name, want := range map[string]string{":method": "POST", ":scheme": "https", ":authority": "service:443", ":path": "/demo.Echo/Call", "authorization": "Bearer test-only", "x-multi": "one,two", "custom-bin": "AAE=", "dapr-app-id": "go-data"} {
				if strings.Join(h[name], ",") != want {
					t.Fatalf("missing request header %s: %+v", name, h)
				}
			}
			if strings.Join(records[1].Headers["x-response"], ",") != "present" || strings.Join(records[1].Trailers["x-trailer"], ",") != "one,two" {
				t.Fatalf("response headers/trailers incomplete: %+v", records[1])
			}
		})
	}
}
