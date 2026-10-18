package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
	"ztunnel-ebpf-collector/internal/podwatch"
	"ztunnel-ebpf-collector/internal/replay"
	"ztunnel-ebpf-collector/internal/tcpcapture"
)

func TestPeerOutputFlushesFrozenPairAndPropagatesFailure(t *testing.T) {
	f := &fakePeerSource{p: peerPod(), valid: true}
	tr := newPeerTracker()
	e := peerEvent()
	tr.observe(e)
	var b bytes.Buffer
	s := newPeerOutput(context.Background(), &b, f)
	rs := []replay.Record{{Direction: "request", ObservationSide: "inbound"}, {Direction: "response", ObservationSide: "inbound"}}
	if err := s.submit(rs, tr.connection(e), 200); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for s.written.Load() < 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if err := s.close(); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(b.String()), "\n")
	if len(lines) != 2 {
		t.Fatal("pair not written", b.String())
	}
	for _, line := range lines {
		var r replay.Record
		if err := json.Unmarshal([]byte(line), &r); err != nil || r.Client == nil || r.Client.UID != "old" {
			t.Fatal("identity missing", line, err)
		}
	}
	bad := newPeerOutput(context.Background(), failingPeerWriter{}, f)
	_ = bad.submit(rs, tr.connection(e), 200)
	deadline = time.Now().Add(time.Second)
	for bad.err() == nil && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if bad.close() == nil {
		t.Fatal("write error not propagated")
	}
}
func peerPod() podwatch.Peer {
	return podwatch.Peer{UID: "old", IP: "10.0.0.1", Name: "old", Namespace: "ns", Version: 1}
}

type failingPeerWriter struct{}

func (failingPeerWriter) Write([]byte) (int, error) { return 0, errors.New("closed output") }

type blockedPeerSource struct {
	fakePeerSource
	started chan struct{}
}

func (f *blockedPeerSource) Verify(ctx context.Context, _ podwatch.Peer, _ uint64) bool {
	close(f.started)
	<-ctx.Done()
	return false
}
func TestPeerOutputQueueBudgetAndCancellation(t *testing.T) {
	f := &blockedPeerSource{fakePeerSource: fakePeerSource{p: peerPod(), valid: true}, started: make(chan struct{})}
	tr := newPeerTracker()
	e := peerEvent()
	tr.observe(e)
	var b bytes.Buffer
	s := newPeerOutput(context.Background(), &b, f)
	rs := []replay.Record{{Direction: "request", ObservationSide: "inbound"}, {Direction: "response", ObservationSide: "inbound"}}
	if err := s.submit(rs, tr.connection(e), 200); err != nil {
		t.Fatal(err)
	}
	<-f.started
	for i := 0; i < 16; i++ {
		if err := s.submit(rs, tr.connection(e), 200); err != nil {
			t.Fatal("queue rejected before limit", i, err)
		}
	}
	if err := s.submit(rs, tr.connection(e), 200); err == nil {
		t.Fatal("queue limit bypassed")
	}
	start := time.Now()
	_ = s.close()
	if time.Since(start) > time.Second || s.pending != 0 {
		t.Fatal("cancel did not release queue", s.pending)
	}
	if err := s.submit(rs, tr.connection(e), 200); err == nil {
		t.Fatal("closed output accepted work")
	}
}

func TestOutputFailureOverridesObserverRestart(t *testing.T) {
	writeErr := errors.New("stdout closed")
	if err := peerOutputResult(tcpcapture.ErrObserverEnded, writeErr); !errors.Is(err, writeErr) || errors.Is(err, tcpcapture.ErrObserverEnded) {
		t.Fatal("output failure must latch, not silently reload observer", err)
	}
}
