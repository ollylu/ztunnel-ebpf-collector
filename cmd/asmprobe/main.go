// Command asmprobe 是 I1-5 最小内核实验入口（纯 Go；无 C/cgo）。
//
// 退出码语义（前提与行为断言严格分开）：
//
//	0 = 达到真实目标事件数（Green，本片不实现事件输出）
//	1 = 行为红：前提与 attach 均成功，但零真实事件
//	2 = 用法/配置错误（含 TID 与当前锁定线程不一致）
//	3 = 前提失败（加载/挂载/权限/资源或平台不支持）——不得记作行为红
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"
	"time"

	"ztunnel-ebpf-collector/internal/asmprobe"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: asmprobe <precheck|experiment> [flags]")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "precheck":
		os.Exit(runPrecheck(os.Args[2:]))
	case "experiment":
		os.Exit(runExperiment(os.Args[2:]))
	default:
		fmt.Fprintf(os.Stderr, "asmprobe: unknown subcommand %q\n", os.Args[1])
		os.Exit(2)
	}
}

func runPrecheck(args []string) int {
	fs := flag.NewFlagSet("precheck", flag.ContinueOnError)
	paranoidMax := fs.Int("paranoid-max", 4, "maximum allowed perf_event_paranoid")
	asJSON := fs.Bool("json", false, "print result as JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	pc := asmprobe.PrecheckEnv(asmprobe.OSEnv{}, *paranoidMax)
	if *asJSON {
		b, _ := json.Marshal(pc)
		fmt.Println(string(b))
	} else {
		fmt.Printf("ready=%v sw_clock=%v paranoid=%d kernel=%s source=%s reason=%s\n",
			pc.Ready, pc.SwClockOK, pc.Paranoid, pc.Kernel, pc.EventSource, pc.Reason)
	}
	if !pc.Ready {
		return 3 // 环境未就绪：不是行为红
	}
	return 0
}

// runExperiment 只使用**自身锁定线程**：不允许外部任意 TID。
func runExperiment(args []string) int {
	fs := flag.NewFlagSet("experiment", flag.ContinueOnError)
	nonce := fs.Uint64("nonce", 1, "fixed experiment nonce")
	want := fs.Int("want-events", 1, "required number of real events")
	dur := fs.Duration("duration", 5*time.Second, "bounded case duration (<=10s)")
	sample := fs.Duration("sample-period", asmprobe.DefaultSamplePeriod, "perf sample period (>=10ms)")
	cpuBudget := fs.Duration("cpu-budget", asmprobe.MaxCPUBudget, "bounded CPU work on the locked thread (<=1s)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "asmprobe: unexpected argument %q (no external TID accepted)\n", fs.Arg(0))
		return 2
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	tid := asmprobe.CurrentTID()

	cfg := asmprobe.Config{
		TID: tid, Nonce: *nonce, MaxEvents: asmprobe.MaxEvents,
		Duration: *dur, SamplePeriod: *sample, CPUBudget: *cpuBudget,
		OnAttach: func(info asmprobe.AttachInfo) {
			fmt.Printf("attach_ok program_id=%d map_id=%d perf_fd=%d locked_tid=%d\n",
				info.ProgramID, info.MapID, info.PerfEventFD, info.LockedTID)
		},
	}
	if *want <= 0 || *want > asmprobe.MaxEvents {
		fmt.Fprintf(os.Stderr, "asmprobe: invalid want-events=%d (must be in (0,%d])\n", *want, asmprobe.MaxEvents)
		return 2
	}
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "asmprobe: invalid config: %v\n", err)
		return 2
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Duration)
	defer cancel()
	events, err := asmprobe.Run(ctx, cfg, asmprobe.NewKernelCollector())
	if err != nil {
		switch {
		case asmprobe.IsPrereq(err):
			fmt.Fprintf(os.Stderr, "asmprobe: prerequisite failure (NOT behavior red): %v\n", err)
			return 3
		case asmprobe.IsTIDMismatch(err):
			fmt.Fprintf(os.Stderr, "asmprobe: invalid target thread: %v\n", err)
			return 2
		default:
			fmt.Fprintf(os.Stderr, "asmprobe: %v\n", err)
			return 2
		}
	}
	fmt.Printf("events=%d want=%d nonce=%d locked_tid=%d\n", len(events), *want, *nonce, tid)
	if len(events) < *want {
		return 1 // 行为红：前提与 attach 成功但零真实事件
	}
	return 0
}
