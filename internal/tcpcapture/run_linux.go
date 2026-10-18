//go:build linux && amd64

package tcpcapture

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"net/netip"
	"os"
	"time"
	"ztunnel-ebpf-collector/internal/discovery"
)

func Run(ctx context.Context, c Config, consume func(Event) error) (err error) {
	if c.PID <= 0 || c.StartTime == 0 || (!c.Continuous && (c.Duration <= 0 || c.Duration > 30*time.Second)) || (c.Continuous && c.Duration != 0) {
		return errors.New("invalid bounded capture configuration")
	}
	targets, e := c.Endpoints()
	if e != nil {
		return e
	}
	st, e := discovery.StartTime("/proc", c.PID)
	if e != nil || st != c.StartTime {
		return errors.New("target generation mismatch")
	}
	l, e := loadLayout()
	if e != nil {
		return e
	}
	maps := []*ebpf.Map{}
	progs := []*ebpf.Program{}
	links := []link.Link{}
	var reader *ringbuf.Reader
	defer func() {
		for i := len(links) - 1; i >= 0; i-- {
			err = CleanupResult(err, links[i].Close())
		}
		if reader != nil {
			err = CleanupResult(err, reader.Close())
		}
		for i := len(progs) - 1; i >= 0; i-- {
			err = CleanupResult(err, progs[i].Close())
		}
		for i := len(maps) - 1; i >= 0; i-- {
			err = CleanupResult(err, maps[i].Close())
		}
	}()
	specs := []*ebpf.MapSpec{
		{Name: "zc_inflight", Type: ebpf.Hash, KeySize: 8, ValueSize: valueSize, MaxEntries: 64},
		{Name: "zc_zero", Type: ebpf.Array, KeySize: 4, ValueSize: valueSize, MaxEntries: 1},
		{Name: "zc_events", Type: ebpf.RingBuf, MaxEntries: 8 * 1024 * 1024},
		{Name: "zc_loss", Type: ebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: 1},
		{Name: "zc_targets", Type: ebpf.Hash, KeySize: 12, ValueSize: 8, MaxEntries: MaxTargets},
		{Name: "zc_suppressed", Type: ebpf.Hash, KeySize: 16, ValueSize: 40, MaxEntries: 64},
	}
	for _, s := range specs {
		m, e := ebpf.NewMap(s)
		if e != nil {
			return e
		}
		maps = append(maps, m)
	}
	for _, target := range targets {
		if e := maps[4].Put(target.Key(), uint64(1)); e != nil {
			return e
		}
	}
	if c.Refresh == nil {
		if e := maps[4].Freeze(); e != nil {
			return e
		}
	}
	enter, exit := programs(c, l, maps[0].FD(), maps[1].FD(), maps[2].FD(), maps[3].FD(), maps[4].FD(), maps[5].FD())
	p, e := ebpf.NewProgramWithOptions(&ebpf.ProgramSpec{Name: "zc_enter", Type: ebpf.TracePoint, Instructions: enter, License: "GPL"}, ebpf.ProgramOptions{LogSizeStart: 64 * 1024, LogDisabled: os.Getenv("ZC_VERIFIER_DIAGNOSTIC") != "1"})
	if e != nil {
		return fmt.Errorf("enter: %+v", e)
	}
	progs = append(progs, p)
	p, e = ebpf.NewProgramWithOptions(&ebpf.ProgramSpec{Name: "zc_exit", Type: ebpf.TracePoint, Instructions: exit, License: "GPL"}, ebpf.ProgramOptions{LogSizeStart: 64 * 1024, LogDisabled: os.Getenv("ZC_VERIFIER_DIAGNOSTIC") != "1"})
	if e != nil {
		return fmt.Errorf("exit: %+v", e)
	}
	progs = append(progs, p)
	reader, e = ringbuf.NewReader(maps[2])
	if e != nil {
		return e
	}
	// Exit attaches first; no entry is produced until both hooks exist.
	ex, e := link.Tracepoint("raw_syscalls", "sys_exit", progs[1], nil)
	if e != nil {
		return e
	}
	links = append(links, ex)
	en, e := link.Tracepoint("raw_syscalls", "sys_enter", progs[0], nil)
	if e != nil {
		return e
	}
	links = append(links, en)
	if !c.Continuous {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.Duration)
		defer cancel()
	}
	ready := false
	budget := eventBudget{continuous: c.Continuous}
	var nextRefresh, nextCheck time.Time
	active := map[Endpoint]uint64{}
	for _, ep := range targets {
		active[ep] = 1
	}
	suppressed := suppressionSet{put: func(k [40]byte) error {
		var old [40]byte
		if err := maps[5].Lookup(suppressionMapKey(k), &old); err != nil {
			return err
		}
		if !bytes.Equal(old[:36], k[:36]) {
			return errors.New("rejection admission identity mismatch")
		}
		v := k
		binary.LittleEndian.PutUint32(v[36:], 1)
		return maps[5].Update(suppressionMapKey(k), v, ebpf.UpdateExist)
	}, remove: func(k [40]byte) error { return removeAdmission(maps[5], k) }}

	for ctx.Err() == nil {
		// Kernel entry AND exit fence the observer incarnation on every syscall.
		// User-space proc/cgroup/netns checks are control-plane work, bounded to
		// once per 100ms; context and byte-loss checks still run per event.
		if !time.Now().Before(nextCheck) {
			nextCheck = time.Now().Add(100 * time.Millisecond)
			if c.Check != nil {
				if e := c.Check(); e != nil {
					return e
				}
			}
			st, x := discovery.StartTime("/proc", c.PID)
			if x != nil {
				if errors.Is(x, os.ErrNotExist) || errors.Is(x, discovery.ErrProcessEnded) {
					return ErrObserverEnded
				}
				return x
			}
			if st != c.StartTime {
				return ErrObserverEnded
			}
		}

		if c.Refresh != nil && !time.Now().Before(nextRefresh) {
			next, err := c.Refresh()
			if err != nil {
				return err
			}
			if len(next) > MaxTargets {
				return errors.New("target budget exhausted")
			}
			if len(next) > 0 {
				eps := make([]Endpoint, 0, len(next))
				for ep, g := range next {
					if g == 0 {
						return errors.New("zero target generation")
					}
					eps = append(eps, ep)
				}
				if _, err := (Config{Targets: eps}).Endpoints(); err != nil {
					return err
				}
			}
			// Revoke before adding. Readers match the generation captured at syscall entry.
			for ep, g := range active {
				if next[ep] != g {
					if err := maps[4].Delete(ep.Key()); err != nil {
						return err
					}
				}
			}
			if err := revokeAdmissions(maps[5], next); err != nil {
				return fmt.Errorf("admission revoke: %w", err)
			}
			if err := suppressed.reconcile(next); err != nil {
				return fmt.Errorf("suppression revoke: %w", err)
			}
			for ep, g := range next {
				if active[ep] != g {
					if err := maps[4].Put(ep.Key(), g); err != nil {
						return err
					}
				}
			}
			active = next
			nextRefresh = time.Now().Add(250 * time.Millisecond)
		}
		if c.Suppressions != nil {
			if err := suppressed.add(c.Suppressions(), active); err != nil {
				return fmt.Errorf("suppression install: %w", err)
			}
		}
		// Publish readiness only after the initial dynamic generations are installed.
		if !ready {
			ready = true
			if c.Ready != nil {
				c.Ready()
			}
		}
		reader.SetDeadline(time.Now().Add(100 * time.Millisecond))
		rec, e := reader.Read()
		var lost uint64
		if x := maps[3].Lookup(uint32(0), &lost); x != nil {
			return x
		}
		if lost != 0 {
			return captureFailure(lost)
		}
		if errors.Is(e, os.ErrDeadlineExceeded) {
			continue
		}
		if e != nil {
			return e
		}
		if err := budget.accept(time.Now(), len(rec.RawSample)); err != nil {
			return err
		}
		ev, e := decode(rec.RawSample)
		if e != nil {
			return e
		}
		if !ev.Closed && !(ev.Connected && ev.LocalPort == 0) {
			if err := suppressed.track(ev, active); err != nil {
				return fmt.Errorf("connection track: %w", err)
			}
		}
		if ev.Closed {
			if err := suppressed.close(ev); err != nil {
				return fmt.Errorf("suppression close: %w", err)
			}
		}
		if e = consume(ev); e != nil {
			return e
		}
	}
	return nil
}
func decode(b []byte) (Event, error) {
	if len(b) < payload {
		return Event{}, errors.New("short event")
	}
	n := binary.LittleEndian.Uint32(b[20:24])
	if n > maxData || len(b) != payload+int(n) {
		return Event{}, errors.New("invalid event length")
	}
	var a, z [4]byte
	copy(a[:], b[24:28])
	copy(z[:], b[28:32])
	ev := Event{Damaged: binary.LittleEndian.Uint32(b[36:40]) == 4, Connected: binary.LittleEndian.Uint32(b[36:40]) == 3, TimestampNS: binary.LittleEndian.Uint64(b[104:112]), Outbound: binary.LittleEndian.Uint32(b[96:100]) == 1, Closed: binary.LittleEndian.Uint32(b[36:40]) == 1, Generation: binary.LittleEndian.Uint64(b[40:48]), Inode: binary.LittleEndian.Uint64(b), NetNS: binary.LittleEndian.Uint32(b[8:]), FD: binary.LittleEndian.Uint32(b[12:]), Write: binary.LittleEndian.Uint32(b[16:]) == 1, Data: append([]byte(nil), b[payload:]...), LocalIP: netip.AddrFrom4(a), RemoteIP: netip.AddrFrom4(z), LocalPort: binary.LittleEndian.Uint16(b[32:]), RemotePort: binary.BigEndian.Uint16(b[34:])}
	kind := binary.LittleEndian.Uint32(b[36:40])
	if kind > 4 || (kind == 4 && n != 0) || (kind == 3 && (n != 0 || ev.TimestampNS == 0)) {
		return Event{}, errors.New("invalid event kind")
	}
	if kind == 2 {
		if !ev.Outbound || n != 16 || binary.LittleEndian.Uint16(ev.Data[:2]) != 2 {
			return Event{}, errors.New("invalid original destination")
		}
		ev.OriginalDestination = netip.AddrPortFrom(netip.AddrFrom4([4]byte(ev.Data[4:8])), binary.BigEndian.Uint16(ev.Data[2:4]))
		ev.Data = nil
	}
	return ev, nil
}

// Compare before deletion: queued old close/feedback must not erase a newer
// identity. No eviction, pinning or unbounded map enumeration.
func removeAdmission(m *ebpf.Map, k [40]byte) error {
	var old [40]byte
	if err := m.Lookup(suppressionMapKey(k), &old); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil
		}
		return err
	}
	if !bytes.Equal(old[:36], k[:36]) {
		return nil
	}
	err := m.Delete(suppressionMapKey(k))
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return nil
	}
	return err
}
func revokeAdmissions(m *ebpf.Map, active map[Endpoint]uint64) error {
	iter := m.Iterate()
	var id [16]byte
	var v [40]byte
	var stale [][40]byte
	count := 0
	for iter.Next(&id, &v) {
		count++
		if count > 128 {
			return errors.New("admission scan budget exhausted")
		}
		e := admissionEvent(v)
		if active[e.Target()] != e.Generation {
			stale = append(stale, v)
		}
	}
	if err := iter.Err(); err != nil {
		return err
	}
	for _, k := range stale {
		if err := removeAdmission(m, k); err != nil {
			return err
		}
	}
	return nil
}
func admissionEvent(v [40]byte) Event {
	var l, r [4]byte
	copy(l[:], v[20:24])
	copy(r[:], v[24:28])
	return Event{Inode: binary.LittleEndian.Uint64(v[:8]), Generation: binary.LittleEndian.Uint64(v[8:16]), NetNS: binary.LittleEndian.Uint32(v[16:20]), LocalIP: netip.AddrFrom4(l), RemoteIP: netip.AddrFrom4(r), LocalPort: binary.LittleEndian.Uint16(v[28:30]), RemotePort: binary.BigEndian.Uint16(v[30:32]), Outbound: binary.LittleEndian.Uint32(v[32:36]) == 1}
}

// Only a single failure has an unambiguous code; sums from concurrent failures
// are reported as multiple, never decoded as a different specific operation.
func captureFailure(word uint64) error {
	count := uint32(word)
	reason := "multiple"
	if count == 1 {
		reason = map[uint64]string{0: "unclassified", 1: "payload_limit", 2: "admission_identity", 3: "admission_update", 4: "ring_output", 5: "iovec_limit", 6: "user_read", 7: "unsupported_flags", 8: "admission_inode", 9: "admission_generation", 10: "admission_local", 11: "admission_peer", 12: "admission_direction"}[word>>32]
		if reason == "" {
			reason = "unknown"
		}
	}
	return fmt.Errorf("capture incomplete: %d lost or unsupported operations; reason=%s; stopped", count, reason)
}
