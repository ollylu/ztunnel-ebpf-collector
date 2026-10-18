package main

import (
	"context"
	"net/netip"
	"sync/atomic"
	"ztunnel-ebpf-collector/internal/podwatch"
	"ztunnel-ebpf-collector/internal/replay"
	"ztunnel-ebpf-collector/internal/tcpcapture"
)

type peerSource interface {
	Peer(netip.Addr, uint64) (podwatch.Peer, bool)
	PeerValid(podwatch.Peer) bool
	Verify(context.Context, podwatch.Peer, uint64) bool
}
type peerSocket struct {
	inode, generation uint64
	netns             uint32
	outbound          bool
}
type peerConnection struct {
	ip      netip.Addr
	born    uint64
	target  tcpcapture.Endpoint
	last    uint64 // capture-owner only
	invalid atomic.Bool
	// The following fields are output-worker only. A candidate is selected once.
	selected, attempted, verified bool
	candidate                     podwatch.Peer
}
type peerTracker struct {
	connections map[peerSocket]*peerConnection
}

func newPeerTracker() *peerTracker {
	return &peerTracker{connections: map[peerSocket]*peerConnection{}}
}
func socketIdentity(e tcpcapture.Event) peerSocket {
	return peerSocket{e.Inode, e.Generation, e.NetNS, e.Outbound}
}
func (t *peerTracker) observe(e tcpcapture.Event) {
	key := socketIdentity(e)
	if e.Closed {
		delete(t.connections, key)
		return
	}
	c := t.connections[key]
	// ztunnel obtains SO_ORIGINAL_DST for each newly accepted outbound socket.
	// A later proof is a new incarnation even when inode and tuple are recycled.
	if e.Outbound && e.OriginalDestination.IsValid() && c != nil && e.TimestampNS > c.born && c.born != 0 {
		c = &peerConnection{ip: e.OriginalDestination.Addr(), born: e.TimestampNS, last: e.TimestampNS, target: e.Target()}
		t.connections[key] = c
		return
	}
	if e.Connected && !e.Outbound {
		if c != nil || len(t.connections) < 64 {
			t.connections[key] = &peerConnection{ip: e.LocalIP, born: e.TimestampNS, last: e.TimestampNS, target: e.Target()}
		}
		return
	}
	if c == nil {
		c = &peerConnection{ip: e.LocalIP, target: e.Target(), last: e.TimestampNS}
		if e.Outbound {
			c.ip = netip.Addr{}
			if e.OriginalDestination.IsValid() {
				c.ip = e.OriginalDestination.Addr()
				c.born = e.TimestampNS
			}
		}
		if len(t.connections) < 64 {
			t.connections[key] = c
		}
	} else if e.Outbound && e.OriginalDestination.IsValid() && c.ip != e.OriginalDestination.Addr() {
		c.invalid.Store(true)
	}
	c.last = e.TimestampNS
}
func (t *peerTracker) connection(e tcpcapture.Event) *peerConnection {
	if c := t.connections[socketIdentity(e)]; c != nil {
		return c
	}
	ip := e.LocalIP
	if e.Outbound {
		ip = netip.Addr{}
	}
	return &peerConnection{ip: ip}
}
func (t *peerTracker) reject(e tcpcapture.Event) {
	delete(t.connections, socketIdentity(e))
}
func (t *peerTracker) forget(ep tcpcapture.Endpoint) {
	for k, c := range t.connections {
		if c.target == ep {
			delete(t.connections, k)
		}
	}
}
func (t *peerTracker) sweep(now uint64) {
	for k, c := range t.connections {
		if now > c.last && now-c.last > 60_000_000_000 {
			delete(t.connections, k)
		}
	}
}
func (c *peerConnection) identity(ctx context.Context, source peerSource, after uint64, allow bool) *replay.PodIdentity {
	id := &replay.PodIdentity{IP: "unknown", UID: "unknown", Name: "unknown", Namespace: "unknown"}
	if c.ip.IsValid() && !c.ip.IsUnspecified() {
		id.IP = c.ip.String()
	}
	if c.born == 0 || c.invalid.Load() {
		return id
	}
	if !c.selected {
		c.selected = true
		p, ok := source.Peer(c.ip, c.born)
		if !ok {
			c.invalid.Store(true)
			return id
		}
		c.candidate = p
	}
	if !source.PeerValid(c.candidate) {
		c.invalid.Store(true)
		return id
	}
	if !c.verified && !c.attempted && allow {
		c.attempted = true
		c.verified = source.Verify(ctx, c.candidate, after)
	}
	if c.verified && source.PeerValid(c.candidate) {
		return &replay.PodIdentity{IP: c.candidate.IP, Name: c.candidate.Name, Namespace: c.candidate.Namespace, UID: c.candidate.UID}
	}
	return id
}
func applyPeer(rs []replay.Record, p *replay.PodIdentity) {
	for i := range rs {
		// A non-transparent proxy may use the observed workload's own address.
		// That does not prove the business caller was the same Pod.
		if p.UID != "unknown" && p.UID == rs[i].PodUID {
			p = &replay.PodIdentity{IP: p.IP, UID: "unknown", Name: "unknown", Namespace: "unknown"}
		}
		rs[i].PeerIdentitySource = "unknown"
		if p.UID != "unknown" && p.UID != "" {
			rs[i].PeerIdentitySource = "pod_api_verified"
		} else if p.IP != "unknown" && p.IP != "" {
			rs[i].PeerIdentitySource = "socket_ip_only"
			if rs[i].ObservationSide == "outbound" {
				rs[i].PeerIdentitySource = "original_destination_only"
			}
		}
		if rs[i].ObservationSide == "outbound" {
			rs[i].Server = p
		} else {
			rs[i].Client = p
		}
	}
}
