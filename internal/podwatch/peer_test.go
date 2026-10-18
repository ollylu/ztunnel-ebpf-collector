package podwatch

import (
	"net/netip"
	"testing"
)

func TestPeerRejectsIPReuseRestartAndLateObservation(t *testing.T) {
	c := &Cache{pods: map[string]Pod{}, sizes: map[string]int{}, valid: true}
	p, _ := Decode([]byte(`{"metadata":{"uid":"old","name":"app","namespace":"ns"},"spec":{"nodeName":"remote"},"status":{"phase":"Running","podIP":"10.0.0.2","containerStatuses":[{"name":"app","containerID":"container://one","state":{"running":{}}}]}}`))
	if err := c.apply("ADDED", p, 200); err != nil {
		t.Fatal(err)
	}
	peer, ok := c.Peer(netip.MustParseAddr("10.0.0.2"), ^uint64(0))
	if !ok || peer.UID != "old" {
		t.Fatal("unique remote peer not resolved", peer, ok)
	}
	if _, ok := c.Peer(netip.MustParseAddr("10.0.0.2"), 1); ok {
		t.Fatal("Pod observed after connection must not be attributed")
	}
	newer := p
	newer.Metadata.UID = "new"
	if err := c.apply("DELETED", p, 200); err != nil {
		t.Fatal(err)
	}
	if err := c.apply("ADDED", newer, 200); err != nil {
		t.Fatal(err)
	}
	if c.PeerValid(peer) {
		t.Fatal("old peer remained valid after IP reassignment")
	}
	current, ok := c.Peer(netip.MustParseAddr("10.0.0.2"), ^uint64(0))
	if !ok || current.UID != "new" {
		t.Fatal("new connection cannot resolve new UID")
	}
	newer.Status.ContainerStatuses[0].ContainerID = "container://two"
	if err := c.apply("MODIFIED", newer, 200); err != nil {
		t.Fatal(err)
	}
	if c.PeerValid(current) {
		t.Fatal("same UID restart did not revoke previous generation")
	}
	c.invalidate()
	if c.PeerValid(current) {
		t.Fatal("invalid cache trusted")
	}
}
