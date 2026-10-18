package asmprobe

import "time"

// 本片候选（PL 安全修订）：BPF_PROG_TYPE_PERF_EVENT + PERF_TYPE_SOFTWARE/PERF_COUNT_SW_CPU_CLOCK。
//
// 依据（PL 提供的内核源，v6.8）：
//   - bpf_trace.c:2233 perf_event_attach_bpf_prog 对 **tracepoint** 会把程序放进
//     event->tp_event->prog_array；trace_syscalls.c:596/613 在 perf 过滤前执行 ⇒ pid 限定不保证线程隔离。
//   - perf_core.c: perf_event_set_bpf_prog(event,…) 只设置 event->prog（10490），
//     热路径 bpf_prog_run(event->prog)（10445/10448）仅在该 perf event 溢出时执行 ⇒ per-event 专用。
const (
	// PerfTypeSoftware 对应 Linux PERF_TYPE_SOFTWARE。
	PerfTypeSoftware = 1
	// PerfCountSwCPUClock 对应 Linux PERF_COUNT_SW_CPU_CLOCK。
	PerfCountSwCPUClock = 0
	// DefaultSamplePeriod 是保守的采样周期（可增大，不得小于 10ms）。
	DefaultSamplePeriod = 10 * time.Millisecond
)

// PerfSpec 是与平台无关的 perf_event_open 目标描述（便于在非 Linux 上做契约测试）。
type PerfSpec struct {
	Type         uint32
	Config       uint64
	SamplePeriod time.Duration
	PID          int // 显式锁定 TID（禁止 -1）
	CPU          int // -1：不限定 CPU
	Disabled     bool
	Inherit      bool
	CLOEXEC      bool
}

// SoftwareCPUClockSpec 构造 SW CPU_CLOCK 采样描述：pid=显式 TID、cpu=-1、disabled、inherit=false、CLOEXEC。
func SoftwareCPUClockSpec(tid int, samplePeriod time.Duration) PerfSpec {
	if samplePeriod < DefaultSamplePeriod {
		samplePeriod = DefaultSamplePeriod
	}
	return PerfSpec{
		Type: PerfTypeSoftware, Config: PerfCountSwCPUClock, SamplePeriod: samplePeriod,
		PID: tid, CPU: -1, Disabled: true, Inherit: false, CLOEXEC: true,
	}
}
