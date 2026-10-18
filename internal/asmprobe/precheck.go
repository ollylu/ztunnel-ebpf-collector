package asmprobe

import "fmt"

// Env 是预检所需的只读环境访问接口（便于测试注入）。
type Env interface {
	PerfEventParanoid() (int, error)
	SwCPUClockAvailable() (bool, error)
	KernelRelease() (string, error)
}

// Precheck 结果：与"行为红"严格分开，环境/权限不满足不得记作红。
type Precheck struct {
	Paranoid    int
	SwClockOK   bool
	Kernel      string
	Ready       bool
	Reason      string
	EventSource string
}

// PrecheckEnv 只做只读探测；任何缺失都返回 Ready=false 并说明原因（不自动提权/不换挂点）。
func PrecheckEnv(env Env, requiredParanoidMax int) Precheck {
	pc := Precheck{EventSource: "PERF_TYPE_SOFTWARE/PERF_COUNT_SW_CPU_CLOCK + BPF_PROG_TYPE_PERF_EVENT"}
	par, err := env.PerfEventParanoid()
	if err != nil {
		pc.Reason = fmt.Sprintf("perf_event_paranoid unreadable: %v", err)
		return pc
	}
	pc.Paranoid = par
	if par > requiredParanoidMax {
		pc.Reason = fmt.Sprintf("perf_event_paranoid=%d exceeds allowed %d (no sysctl change in this slice)", par, requiredParanoidMax)
		return pc
	}
	ok, err := env.SwCPUClockAvailable()
	if err != nil {
		pc.Reason = fmt.Sprintf("sw cpu-clock probe failed: %v", err)
		return pc
	}
	pc.SwClockOK = ok
	if !ok {
		pc.Reason = "PERF_COUNT_SW_CPU_CLOCK not available on this kernel"
		return pc
	}
	rel, err := env.KernelRelease()
	if err != nil {
		pc.Reason = fmt.Sprintf("kernel release unreadable: %v", err)
		return pc
	}
	pc.Kernel = rel
	pc.Ready = true
	return pc
}
