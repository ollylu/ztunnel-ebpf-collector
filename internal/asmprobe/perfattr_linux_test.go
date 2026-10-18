//go:build linux && amd64

package asmprobe

import (
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// 可移植常量与内核常量一致；映射字段正确。
func TestOpenSpecMatchesLinuxConstants(t *testing.T) {
	if PerfTypeSoftware != unix.PERF_TYPE_SOFTWARE {
		t.Errorf("PerfTypeSoftware=%d, want %d", PerfTypeSoftware, unix.PERF_TYPE_SOFTWARE)
	}
	if PerfCountSwCPUClock != unix.PERF_COUNT_SW_CPU_CLOCK {
		t.Errorf("PerfCountSwCPUClock=%d, want %d", PerfCountSwCPUClock, unix.PERF_COUNT_SW_CPU_CLOCK)
	}
	po := OpenSpec(SoftwareCPUClockSpec(777, 10*time.Millisecond))
	if po.PID != 777 || po.CPU != -1 {
		t.Errorf("pid/cpu=%d/%d, want 777/-1", po.PID, po.CPU)
	}
	if !po.AttrDisabled() || po.AttrInherit() {
		t.Error("attr must be disabled and non-inheriting")
	}
	if po.Flags&unix.PERF_FLAG_FD_CLOEXEC == 0 {
		t.Error("CLOEXEC flag missing")
	}
}
