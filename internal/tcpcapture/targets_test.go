package tcpcapture

import (
	"net/netip"
	"testing"
)

func TestEndpointSetIsolationAndBounds(t *testing.T) {
	a := Endpoint{NetNS: 4026532222, Server: netip.MustParseAddrPort("10.0.0.1:8080")}
	b := Endpoint{NetNS: 4026532223, Server: a.Server}
	c := Endpoint{NetNS: a.NetNS, Server: netip.MustParseAddrPort("10.0.0.1:50002")}
	d := Endpoint{NetNS: a.NetNS, Server: netip.MustParseAddrPort("10.0.0.2:8080")}
	got, err := (Config{Targets: []Endpoint{a, b, c, d}}).Endpoints()
	if err != nil || len(got) != 4 {
		t.Fatalf("valid target set rejected: %v %v", got, err)
	}
	seen := map[[12]byte]bool{}
	for _, e := range got {
		if seen[e.Key()] {
			t.Fatal("namespace/IP/port key collision")
		}
		seen[e.Key()] = true
	}
	// Little-endian netns, raw IPv4, network-order port and zero padding.
	if got := a.Key(); got != [12]byte{126, 1, 0, 240, 10, 0, 0, 1, 31, 144, 0, 0} {
		t.Fatalf("map ABI: %v", got)
	}
	legacy, err := (Config{NetNS: a.NetNS, Server: a.Server}).Endpoints()
	if err != nil || len(legacy) != 1 || legacy[0] != a {
		t.Fatal("single target regression", legacy, err)
	}
	for _, cfg := range []Config{{}, {Targets: []Endpoint{a, a}}, {Targets: make([]Endpoint, MaxTargets+1)}, {Targets: []Endpoint{{NetNS: 0, Server: a.Server}}}, {Targets: []Endpoint{{NetNS: 1, Server: netip.MustParseAddrPort("[::1]:80")}}}, {Targets: []Endpoint{{NetNS: 1, Server: netip.MustParseAddrPort("10.0.0.1:0")}}}, {Targets: []Endpoint{a}, Server: a.Server}, {Targets: []Endpoint{a}, NetNS: a.NetNS}} {
		if _, err := cfg.Endpoints(); err == nil {
			t.Fatalf("invalid/ambiguous set accepted: %+v", cfg)
		}
	}
}
