package tcpcapture

import (
	"encoding/binary"
	"errors"
)

// Run owns this mirror and its kernel map. Its BPF programs register admissions;
// the reader applies rejection flags and removes closed/revoked identities.
// No LRU eviction: losing a rejection would silently resume payload capture.
type suppressionSet struct {
	entries  map[[40]byte]Event
	filtered map[[40]byte]bool
	put      func([40]byte) error
	remove   func([40]byte) error
}

func suppressionKey(e Event) ([40]byte, error) {
	var k [40]byte
	if e.Inode == 0 || e.Generation == 0 || e.NetNS == 0 || !e.LocalIP.Is4() || !e.RemoteIP.Is4() || e.LocalPort == 0 || e.RemotePort == 0 {
		return k, errors.New("invalid suppression identity")
	}
	binary.LittleEndian.PutUint64(k[0:8], e.Inode)
	binary.LittleEndian.PutUint64(k[8:16], e.Generation)
	binary.LittleEndian.PutUint32(k[16:20], e.NetNS)
	a, b := e.LocalIP.As4(), e.RemoteIP.As4()
	copy(k[20:24], a[:])
	copy(k[24:28], b[:])
	binary.LittleEndian.PutUint16(k[28:30], e.LocalPort)
	binary.BigEndian.PutUint16(k[30:32], e.RemotePort)
	if e.Outbound {
		binary.LittleEndian.PutUint32(k[32:36], 1)
	}
	return k, nil
}
func (s *suppressionSet) add(events []Event, active map[Endpoint]uint64) error {
	if len(events) > 64 {
		return errors.New("suppression batch budget exhausted")
	}
	for _, e := range events {
		if e.Generation == 0 || active[e.Target()] != e.Generation {
			continue
		}
		k, err := suppressionKey(e)
		if err != nil {
			return err
		}
		if s.filtered[k] {
			continue
		}
		if _, exists := s.entries[k]; !exists && len(s.entries) >= 64 {
			return errors.New("suppression budget exhausted")
		}
		if err := s.put(k); err != nil {
			return err
		}
		if s.entries == nil {
			s.entries = make(map[[40]byte]Event)
		}
		e.Data = nil
		s.entries[k] = e
		if s.filtered == nil {
			s.filtered = make(map[[40]byte]bool)
		}
		s.filtered[k] = true
	}
	return nil
}

// A failed connect or TCP teardown can reset local addresses/ports before close.
// Within this observer generation, inode+netns identifies the live socket;
// target generation and direction prevent closing another admission generation.
func (s *suppressionSet) close(e Event) error {
	matched := false
	for k, stored := range s.entries {
		if stored.Inode != e.Inode || stored.NetNS != e.NetNS || stored.Generation != e.Generation || stored.Outbound != e.Outbound {
			continue
		}
		if err := s.remove(k); err != nil {
			return err
		}
		matched = true
		delete(s.entries, k)
		delete(s.filtered, k)
	}
	if !matched {
		if k, err := suppressionKey(e); err == nil {
			return s.remove(k)
		}
	}
	return nil
}
func (s *suppressionSet) reconcile(active map[Endpoint]uint64) error {
	for k, e := range s.entries {
		if active[e.Target()] == e.Generation {
			continue
		}
		if err := s.remove(k); err != nil {
			return err
		}
		delete(s.entries, k)
		delete(s.filtered, k)
	}
	return nil
}

// Stable lookup survives TCP clearing the endpoint tuple at close. The value
// still contains the full generation/direction/tuple and is checked for data.
func suppressionMapKey(k [40]byte) [16]byte {
	var id [16]byte
	copy(id[:8], k[:8])
	copy(id[8:12], k[16:20])
	return id
}

// Mirror only identities already registered by BPF before event emission.
func (s *suppressionSet) track(e Event, active map[Endpoint]uint64) error {
	if active[e.Target()] != e.Generation {
		return nil
	}
	k, err := suppressionKey(e)
	if err != nil {
		return err
	}
	if _, ok := s.entries[k]; ok {
		return nil
	}
	if len(s.entries) >= 64 {
		return errors.New("connection identity budget exhausted")
	}
	if s.entries == nil {
		s.entries = make(map[[40]byte]Event)
	}
	e.Data = nil
	s.entries[k] = e
	return nil
}
