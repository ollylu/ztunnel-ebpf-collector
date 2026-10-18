package asmprobe

import (
	"context"
	"time"
)

// burnCPU 在调用线程上做有界纯 CPU 工作（不产生 syscall），用于触发本 perf event 采样。
func burnCPU(ctx context.Context, d time.Duration) {
	if d <= 0 {
		return
	}
	deadline := time.Now().Add(d)
	x := uint64(1)
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return
		}
		for i := 0; i < 1<<16; i++ {
			x = x*6364136223846793005 + 1442695040888963407
		}
	}
	sink = x
}

// sink 防止编译器优化掉 CPU 工作。
var sink uint64
