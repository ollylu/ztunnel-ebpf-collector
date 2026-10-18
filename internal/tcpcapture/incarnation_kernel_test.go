//go:build linux && amd64 && kernel

package tcpcapture

import (
	"encoding/binary"
	"errors"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
	"os"
	"runtime"
	"testing"
	"time"
	"ztunnel-ebpf-collector/internal/discovery"
)

// Seed a stale in-flight record for this TID, exactly the state a recycled
// PID/TID could encounter. The exit hook alone must reject a different leader
// start time. A matching-generation control proves the seeded record is usable.
func TestExitRejectsStaleProcessIncarnation(t *testing.T) {
	for _, wrong := range []bool{false, true} {
		name := "matching"
		if wrong {
			name = "stale"
		}
		t.Run(name, func(t *testing.T) {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			st, err := discovery.StartTime("/proc", os.Getpid())
			if err != nil {
				t.Fatal(err)
			}
			l, err := loadLayout()
			if err != nil {
				t.Fatal(err)
			}
			specs := []*ebpf.MapSpec{
				{Name: "zc_test_flight", Type: ebpf.Hash, KeySize: 8, ValueSize: valueSize, MaxEntries: 1},
				{Name: "zc_test_zero", Type: ebpf.Array, KeySize: 4, ValueSize: valueSize, MaxEntries: 1},
				{Name: "zc_test_events", Type: ebpf.RingBuf, MaxEntries: 16384},
				{Name: "zc_test_loss", Type: ebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: 1},
				{Name: "zc_test_targets", Type: ebpf.Hash, KeySize: 12, ValueSize: 8, MaxEntries: 1},
				{Name: "zc_test_admit", Type: ebpf.Hash, KeySize: 16, ValueSize: 40, MaxEntries: 1},
			}
			var maps []*ebpf.Map
			defer func() {
				for _, m := range maps {
					m.Close()
				}
			}()
			for _, s := range specs {
				m, e := ebpf.NewMap(s)
				if e != nil {
					t.Fatal(e)
				}
				maps = append(maps, m)
			}
			expected := st
			if wrong {
				expected++
			}
			_, ins := programs(Config{PID: os.Getpid(), StartTime: expected}, l, maps[0].FD(), maps[1].FD(), maps[2].FD(), maps[3].FD(), maps[4].FD(), maps[5].FD())
			p, err := ebpf.NewProgram(&ebpf.ProgramSpec{Name: "zc_test_exit", Type: ebpf.TracePoint, Instructions: ins, License: "GPL"})
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			reader, err := ringbuf.NewReader(maps[2])
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			hook, err := link.Tracepoint("raw_syscalls", "sys_exit", p, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer hook.Close()
			key := uint64(os.Getpid())<<32 | uint64(unix.Gettid())
			v := make([]byte, valueSize)
			binary.LittleEndian.PutUint32(v[36:], 1) // closed event
			// The BPF_MAP_UPDATE syscall returns zero; its exit encounters this record.
			if err = maps[0].Put(key, v); err != nil {
				t.Fatal(err)
			}
			reader.SetDeadline(time.Now().Add(200 * time.Millisecond))
			_, err = reader.Read()
			if wrong && !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("stale incarnation emitted an event: %v", err)
			}
			if !wrong && err != nil {
				t.Fatalf("matching control was not emitted: %v", err)
			}
		})
	}
}
