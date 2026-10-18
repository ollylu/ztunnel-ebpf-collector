package main

import (
	"net/netip"
	"testing"
	"ztunnel-ebpf-collector/internal/discovery"
	"ztunnel-ebpf-collector/internal/podwatch"
	"ztunnel-ebpf-collector/internal/tcpcapture"
)

func TestTargetGenerationPreservesUnchangedAndRejectsOld(t *testing.T) {
	ep := tcpcapture.Endpoint{NetNS: 1, Server: netip.MustParseAddrPort("10.0.0.2:8080")}
	p := discovery.Process{PID: 20, StartTime: 5, Pod: discovery.Pod{UID: "old", IP: "10.0.0.2", ContainerID: "c1"}}
	s := targetState{}
	s.replace([]captureTarget{{Endpoint: ep, Process: p}})
	first := s.generations()[ep]
	if first == 0 {
		t.Fatal("missing generation")
	}
	s.replace([]captureTarget{{Endpoint: ep, Process: p}})
	if s.generations()[ep] != first {
		t.Fatal("unchanged target restarted")
	}
	p.Pod.UID = "new"
	s.replace([]captureTarget{{Endpoint: ep, Process: p}})
	if s.generations()[ep] == first || s.accept(ep, first) {
		t.Fatal("stale Pod event admitted")
	}
	current := s.generations()[ep]
	s.replace(nil)
	if s.accept(ep, current) {
		t.Fatal("removed target admitted")
	}
	s.replace([]captureTarget{{Endpoint: ep, Process: p}})
	if s.generations()[ep] == current {
		t.Fatal("readded generation reused")
	}
}

func TestPortRemovalRevokesQueuedEvent(t *testing.T) {
	p, err := podwatch.Decode([]byte(`{"metadata":{"uid":"u","name":"app","namespace":"demo","labels":{"observe":"yes"},"annotations":{"collector.ztunnel.io/ports":"9090"}},"spec":{"nodeName":"n"},"status":{"phase":"Running","podIP":"10.0.0.2","containerStatuses":[{"containerID":"id","state":{"running":{}}}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	b := targetBinding{captureTarget: captureTarget{Endpoint: tcpcapture.Endpoint{NetNS: 1, Server: netip.MustParseAddrPort("10.0.0.2:8080")}, Process: discovery.Process{Pod: discovery.Pod{UID: "u", IP: "10.0.0.2", ContainerID: "id"}}}, generation: 1}
	if eligible(p, b, "n", []string{"demo"}, "observe", "yes") {
		t.Fatal("queued bytes from revoked port admitted")
	}
}

func TestDuplicateEndpointIdentityRejected(t *testing.T) {
	ep := tcpcapture.Endpoint{NetNS: 1, Server: netip.MustParseAddrPort("10.0.0.2:8080")}
	s := targetState{}
	if _, err := s.replace([]captureTarget{{Endpoint: ep, Process: discovery.Process{Pod: discovery.Pod{UID: "a"}}}, {Endpoint: ep, Process: discovery.Process{Pod: discovery.Pod{UID: "b"}}}}); err == nil {
		t.Fatal("ambiguous endpoint accepted")
	}
}

func TestUndeclaredPortRequiresDiscoveryProof(t *testing.T) {
	p, err := podwatch.Decode([]byte(`{"metadata":{"uid":"u","name":"app","namespace":"demo","labels":{"observe":"yes"}},"spec":{"nodeName":"n"},"status":{"phase":"Running","podIP":"10.0.0.2","containerStatuses":[{"containerID":"id","state":{"running":{}}}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	b := targetBinding{captureTarget: captureTarget{Discovered: true, Endpoint: tcpcapture.Endpoint{NetNS: 1, Server: netip.MustParseAddrPort("10.0.0.2:8080")}, Process: discovery.Process{Pod: discovery.Pod{UID: "u", IP: "10.0.0.2", ContainerID: "id"}}}, generation: 1}
	if !eligible(p, b, "n", []string{"demo"}, "observe", "yes") {
		t.Fatal("verified listener rejected solely because YAML has no ports")
	}
	if eligible(p, b, "n", []string{"other", "excluded"}, "observe", "yes") {
		t.Fatal("queued event from excluded namespace admitted")
	}
	b.Discovered = false
	if eligible(p, b, "n", []string{"demo"}, "observe", "yes") {
		t.Fatal("unverified port admitted")
	}
	b.Discovered = true
	p.Metadata.Annotations = map[string]string{"collector.ztunnel.io/ports": "9090"}
	if eligible(p, b, "n", []string{"demo"}, "observe", "yes") {
		t.Fatal("explicit override ignored")
	}
}

func TestOutboundPodNeedsNoBusinessListener(t *testing.T) {
	p, err := podwatch.Decode([]byte(`{"metadata":{"uid":"u","name":"a","namespace":"demo","labels":{"observe":"yes"}},"spec":{"nodeName":"n"},"status":{"phase":"Running","podIP":"10.0.0.2","containerStatuses":[{"containerID":"id","state":{"running":{}}}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	b := targetBinding{captureTarget: captureTarget{Discovered: true, Endpoint: tcpcapture.Endpoint{Outbound: true, NetNS: 1, Server: netip.MustParseAddrPort("10.0.0.2:15001")}, Process: discovery.Process{Pod: discovery.Pod{UID: "u", IP: "10.0.0.2", ContainerID: "id"}}}, generation: 1}
	// Annotation controls inbound ports and must not redefine the outbound scope.
	p.Metadata.Annotations = map[string]string{"collector.ztunnel.io/ports": "8080"}
	if !eligible(p, b, "n", []string{"demo"}, "observe", "yes") {
		t.Fatal("outbound requires a business listener")
	}
	b.Discovered = false
	if eligible(p, b, "n", []string{"demo"}, "observe", "yes") {
		t.Fatal("unverified proxy listener admitted")
	}
}
