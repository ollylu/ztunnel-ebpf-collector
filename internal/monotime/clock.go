// Package monotime uses the clock shared by bpf_ktime_get_ns and the node agent.
package monotime

import "golang.org/x/sys/unix"

func Now() uint64 {
	var ts unix.Timespec
	if unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts) != nil {
		return 0
	}
	return uint64(ts.Sec)*1_000_000_000 + uint64(ts.Nsec)
}
