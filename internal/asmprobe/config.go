package asmprobe

import (
	"errors"
	"fmt"
	"time"
)

const (
	// RingSize 是 ringbuf 容量（64KiB，非 per-CPU）。
	RingSize = 64 * 1024
	// MaxEvents 是每个 case 允许的最大事件数。
	MaxEvents = 16
	// MaxDuration 是每个 case 的硬时间上限。
	MaxDuration = 10 * time.Second
	// MaxCPUBudget 是事件产生线程的 CPU 负载上限（1 秒）。
	MaxCPUBudget = 1 * time.Second
)

// AttachInfo 暴露本次实验**自有**对象的身份，供外部核对回收（pid/map/program/perf fd）。
type AttachInfo struct {
	ProgramID   uint32
	MapID       uint32
	PerfEventFD int
	LockedTID   int
}

// OnAttach 在 load+attach 成功后回调（可为 nil）。
type OnAttach func(AttachInfo)

// ErrInvalidConfig 表示配置越界（拒绝执行，不放宽预算）。
var ErrInvalidConfig = errors.New("asmprobe: invalid config")

// Config 是一次有界实验的配置；TID 必须显式给出（禁止 pid=-1 全节点）。
type Config struct {
	TID          int
	Nonce        uint64
	MaxEvents    int
	Duration     time.Duration
	SamplePeriod time.Duration
	CPUBudget    time.Duration
	OnAttach     OnAttach
}

// ErrTIDMismatch 表示 cfg.TID 与当前锁定线程不一致（要求调用方 LockOSThread 并使用自身 TID）。
var ErrTIDMismatch = errors.New("asmprobe: cfg.TID must equal the current locked thread id")

// Validate 校验预算边界；越界一律拒绝。
func (c Config) Validate() error {
	switch {
	case c.TID <= 0:
		return fmt.Errorf("%w: TID must be an explicit positive thread id", ErrInvalidConfig)
	case c.Nonce == 0:
		return fmt.Errorf("%w: nonce must be non-zero", ErrInvalidConfig)
	case c.MaxEvents <= 0 || c.MaxEvents > MaxEvents:
		return fmt.Errorf("%w: MaxEvents must be in (0,%d]", ErrInvalidConfig, MaxEvents)
	case c.Duration <= 0 || c.Duration > MaxDuration:
		return fmt.Errorf("%w: Duration must be in (0,%s]", ErrInvalidConfig, MaxDuration)
	case c.SamplePeriod < DefaultSamplePeriod:
		return fmt.Errorf("%w: SamplePeriod must be >= %s (conservative)", ErrInvalidConfig, DefaultSamplePeriod)
	case c.CPUBudget <= 0 || c.CPUBudget > MaxCPUBudget:
		return fmt.Errorf("%w: CPUBudget must be in (0,%s]", ErrInvalidConfig, MaxCPUBudget)
	}
	return nil
}
