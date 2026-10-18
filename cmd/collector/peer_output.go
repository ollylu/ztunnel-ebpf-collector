package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"
	"ztunnel-ebpf-collector/internal/replay"
)

type peerBatch struct {
	records    []replay.Record
	connection *peerConnection
	after      uint64
	bytes      int
}
type peerOutput struct {
	ctx     context.Context
	cancel  context.CancelFunc
	done    chan struct{}
	queue   chan peerBatch
	mu      sync.Mutex
	failure error
	pending int
	closed  bool
	written atomic.Uint64
}

func newPeerOutput(parent context.Context, out io.Writer, source peerSource) *peerOutput {
	ctx, cancel := context.WithCancel(parent)
	s := &peerOutput{ctx: ctx, cancel: cancel, done: make(chan struct{}), queue: make(chan peerBatch, 16)}
	go s.run(out, source)
	return s
}
func (s *peerOutput) submit(rs []replay.Record, c *peerConnection, after uint64) error {
	weight := 1024
	for _, r := range rs {
		b, e := json.Marshal(r)
		if e != nil {
			return e
		}
		weight += len(b) + 128*(len(r.Headers)+len(r.Trailers)) + 64*len(r.GRPCMessages)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ctx.Err() != nil {
		return s.ctx.Err()
	}
	if s.closed {
		return errors.New("peer output closed")
	}
	if s.failure != nil {
		return s.failure
	}
	if weight > 24*1024*1024-s.pending {
		return errors.New("peer output memory budget exhausted")
	}
	select {
	case s.queue <- peerBatch{rs, c, after, weight}:
		s.pending += weight
		return nil
	default:
		return errors.New("peer output queue budget exhausted")
	}
}
func (s *peerOutput) release(n int) { s.mu.Lock(); s.pending -= n; s.mu.Unlock() }
func (s *peerOutput) run(out io.Writer, source peerSource) {
	defer close(s.done)
	window := time.Now()
	tokens := 2
	defer func() {
		for {
			select {
			case b := <-s.queue:
				s.release(b.bytes)
			default:
				return
			}
		}
	}()
	for s.ctx.Err() == nil {
		var batch peerBatch
		select {
		case <-s.ctx.Done():
			return
		case batch = <-s.queue:
		}
		if time.Since(window) >= time.Second {
			window = time.Now()
			tokens = 2
		}
		attempt := batch.connection.attempted
		ctx, cancel := context.WithTimeout(s.ctx, 200*time.Millisecond)
		id := batch.connection.identity(ctx, source, batch.after, tokens > 0)
		cancel()
		if !attempt && batch.connection.attempted {
			tokens--
		}
		if s.ctx.Err() != nil {
			s.release(batch.bytes)
			return
		}
		applyPeer(batch.records, id)
		var err error
		for _, r := range batch.records {
			if err = replay.WriteRecord(out, r); err != nil {
				break
			}
		}
		s.release(batch.bytes)
		if err != nil {
			s.mu.Lock()
			s.failure = err
			s.mu.Unlock()
			return
		}
		s.written.Add(1)
	}
}
func (s *peerOutput) err() error { s.mu.Lock(); defer s.mu.Unlock(); return s.failure }
func (s *peerOutput) close() error {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	s.cancel()
	<-s.done
	return s.err()
}

func peerOutputResult(runErr, outputErr error) error {
	if outputErr != nil {
		return outputErr
	}
	return runErr
}
