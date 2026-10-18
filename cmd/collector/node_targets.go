package main

import "ztunnel-ebpf-collector/internal/tcpcapture"

type targetBinding struct {
	captureTarget
	generation uint64
}
type targetState struct {
	bindings map[tcpcapture.Endpoint]targetBinding
	next     uint64
}

// replace is single-reader owned, like the analyzer. Removed or changed endpoints
// are returned for parser invalidation; unrelated HPACK state remains intact.
func (s *targetState) replace(ts []captureTarget) ([]tcpcapture.Endpoint, error) {
	eps := make([]tcpcapture.Endpoint, 0, len(ts))
	for _, t := range ts {
		eps = append(eps, t.Endpoint)
	}
	if len(eps) > 0 {
		if _, err := (tcpcapture.Config{Targets: eps}).Endpoints(); err != nil {
			return nil, err
		}
	}
	next := make(map[tcpcapture.Endpoint]targetBinding, len(ts))
	for _, t := range ts {
		b, ok := s.bindings[t.Endpoint]
		if !ok || b.Process != t.Process || b.Discovered != t.Discovered {
			s.next++
			b = targetBinding{t, s.next}
		}
		next[t.Endpoint] = b
	}
	var removed []tcpcapture.Endpoint
	for ep, b := range s.bindings {
		if next[ep].generation != b.generation {
			removed = append(removed, ep)
		}
	}
	s.bindings = next
	return removed, nil
}
func (s *targetState) generations() map[tcpcapture.Endpoint]uint64 {
	m := make(map[tcpcapture.Endpoint]uint64, len(s.bindings))
	for ep, b := range s.bindings {
		m[ep] = b.generation
	}
	return m
}
func (s *targetState) accept(ep tcpcapture.Endpoint, g uint64) bool {
	b, ok := s.bindings[ep]
	return ok && g != 0 && b.generation == g
}
