package main

import (
	"context"
	"encoding/json"
	"net/netip"
	"testing"
	"ztunnel-ebpf-collector/internal/podwatch"
	"ztunnel-ebpf-collector/internal/replay"
	"ztunnel-ebpf-collector/internal/tcpcapture"
)

type fakePeerSource struct {
	p      podwatch.Peer
	valid  bool
	checks int
}

func (f *fakePeerSource) Peer(netip.Addr, uint64) (podwatch.Peer, bool) { return f.p, f.valid }
func (f *fakePeerSource) PeerValid(p podwatch.Peer) bool {
	return f.valid && p.Version == f.p.Version && p.UID == f.p.UID
}
func (f *fakePeerSource) Verify(context.Context, podwatch.Peer, uint64) bool {
	f.checks++
	return f.valid
}
func peerEvent() tcpcapture.Event {
	return tcpcapture.Event{Connected: true, TimestampNS: 100, Inode: 1, NetNS: 2, Generation: 3, LocalIP: netip.MustParseAddr("10.0.0.1"), RemoteIP: netip.MustParseAddr("10.0.0.2"), RemotePort: 8080}
}
func TestPeerConnectionNeverRebindsAfterIPReuse(t *testing.T) {
	f := &fakePeerSource{p: podwatch.Peer{UID: "old", IP: "10.0.0.1", Name: "old", Namespace: "ns", Version: 1}, valid: true}
	tr := newPeerTracker()
	e := peerEvent()
	tr.observe(e)
	c := tr.connection(e)
	got := c.identity(context.Background(), f, 200, true)
	if got.UID != "old" {
		t.Fatal("proved peer not resolved", got)
	}
	f.p.UID = "new"
	f.p.Version = 2
	got = c.identity(context.Background(), f, 300, true)
	if got.UID != "unknown" {
		t.Fatal("old connection rebound after IP reuse", got)
	}
	e.TimestampNS = 400
	tr.observe(e)
	fresh := tr.connection(e)
	got = fresh.identity(context.Background(), f, 500, true)
	if got.UID != "new" {
		t.Fatal("new connection did not get new UID", got)
	}
	if c.identity(context.Background(), f, 600, true).UID != "unknown" {
		t.Fatal("retained old connection rebound")
	}
}
func TestPeerMissingProofAndChangedDestinationStayUnknown(t *testing.T) {
	f := &fakePeerSource{p: podwatch.Peer{UID: "u", IP: "10.0.0.1", Version: 1}, valid: true}
	tr := newPeerTracker()
	e := peerEvent()
	e.Connected = false
	tr.observe(e)
	got := tr.connection(e).identity(context.Background(), f, 200, true)
	if got.UID != "unknown" || got.IP != "10.0.0.1" {
		t.Fatal("midstream peer was guessed", got)
	}
	e = peerEvent()
	e.Connected = false
	e.Outbound = true
	e.OriginalDestination = netip.MustParseAddrPort("10.0.0.1:8080")
	tr = newPeerTracker()
	tr.observe(e)
	c := tr.connection(e)
	if c.identity(context.Background(), f, 200, true).UID != "u" {
		t.Fatal("outbound proof not used")
	}
	e.OriginalDestination = netip.MustParseAddrPort("10.0.0.3:8080")
	tr.observe(e)
	if c.identity(context.Background(), f, 300, true).UID != "unknown" {
		t.Fatal("changed destination trusted")
	}
}
func TestPairUsesOneFrozenPeerIdentity(t *testing.T) {
	f := &fakePeerSource{p: podwatch.Peer{UID: "u", IP: "10.0.0.1", Version: 1}, valid: true}
	tr := newPeerTracker()
	e := peerEvent()
	tr.observe(e)
	rs := []replay.Record{{Direction: "request", ObservationSide: "inbound"}, {Direction: "response", ObservationSide: "inbound"}}
	applyPeer(rs, tr.connection(e).identity(context.Background(), f, 200, true))
	if rs[0].Client == nil || rs[0].Client != rs[1].Client || rs[0].Client.UID != "u" {
		t.Fatal("pair identity differed", rs)
	}
}

func TestPeerNewOriginalDestinationIncarnationDoesNotInherit(t *testing.T) {
	f := &fakePeerSource{p: peerPod(), valid: true}
	tr := newPeerTracker()
	e := peerEvent()
	e.Connected = false
	e.Outbound = true
	e.OriginalDestination = netip.MustParseAddrPort("10.0.0.1:8080")
	tr.observe(e)
	old := tr.connection(e)
	if old.identity(context.Background(), f, 200, true).UID != "old" {
		t.Fatal("initial peer missing")
	}
	f.p.UID = "new"
	f.p.Version = 2
	e.TimestampNS = 400
	tr.observe(e)
	fresh := tr.connection(e)
	if fresh == old || fresh.identity(context.Background(), f, 500, true).UID != "new" {
		t.Fatal("reused inode inherited previous connection")
	}
	if old.identity(context.Background(), f, 600, true).UID != "unknown" {
		t.Fatal("old queued pair rebound to new peer")
	}
}

func TestPeerOutputDistinguishesIPOnlyAndPodMapping(t *testing.T) {
	for _, side := range []string{"inbound", "outbound"} {
		rs := []replay.Record{{ObservationSide: side}, {ObservationSide: side}}
		applyPeer(rs, &replay.PodIdentity{IP: "10.0.0.1", UID: "unknown", Name: "unknown", Namespace: "unknown"})
		b, _ := json.Marshal(rs[0])
		var v map[string]any
		json.Unmarshal(b, &v)
		want := "socket_ip_only"
		if side == "outbound" {
			want = "original_destination_only"
		}
		if v["peer_identity_source"] != want {
			t.Fatal("IP-only observation presented without provenance", string(b))
		}
	}
}

// Regression: a rejected connection must not discard another HTTP/2 socket's
// original-destination proof just because both belong to the same target.
func TestPeerRejectionPreservesOtherConnections(t *testing.T) {
	f := &fakePeerSource{p: peerPod(), valid: true}
	tr := newPeerTracker()
	e := peerEvent()
	e.Connected = false
	e.Outbound = true
	e.OriginalDestination = netip.MustParseAddrPort("10.0.0.1:50002")
	tr.observe(e)
	if got := tr.connection(e).identity(context.Background(), f, 200, true); got.UID != "old" {
		t.Fatal("initial peer", got)
	}
	rejected := e
	rejected.Inode = 99
	tr.observe(rejected)
	tr.reject(rejected)
	// The real follow-up data event has no SO_ORIGINAL_DST metadata.
	e.TimestampNS = 300
	e.OriginalDestination = netip.AddrPort{}
	tr.observe(e)
	if got := tr.connection(e).identity(context.Background(), f, 400, true); got.UID != "old" || got.IP != "10.0.0.1" {
		t.Fatal("unrelated rejection erased live peer", got)
	}
	if _, ok := tr.connections[socketIdentity(rejected)]; ok {
		t.Fatal("rejected connection retained")
	}
}
