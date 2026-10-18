//go:build linux && amd64

package asmprobe

import "golang.org/x/sys/unix"

// Linux perf UAPI 常量（x/sys v0.31.0 未导出这些名字，按其值显式定义）。
const (
	perfAttrBitDisabled = 1 << 0 // struct perf_event_attr.disabled
	perfAttrBitInherit  = 1 << 1 // struct perf_event_attr.inherit
	perfAttrSizeV7      = 128    // PERF_ATTR_SIZE_VER7（本片只声明到 VER7 的字段）
)

// PerfOpen 是 Linux 上的实际 perf_event_open 参数。
type PerfOpen struct {
	Attr  unix.PerfEventAttr
	Flags int
	PID   int
	CPU   int
}

// OpenSpec 把可移植描述映射为 Linux perf_event_open 参数（software CPU clock, per-event 专用）。
func OpenSpec(s PerfSpec) PerfOpen {
	attr := unix.PerfEventAttr{
		Type:   s.Type,
		Size:   perfAttrSizeV7,
		Config: s.Config,
		Sample: uint64(s.SamplePeriod.Nanoseconds()),
	}
	if s.Disabled {
		attr.Bits |= perfAttrBitDisabled
	}
	if s.Inherit {
		attr.Bits |= perfAttrBitInherit
	}
	flags := 0
	if s.CLOEXEC {
		flags |= unix.PERF_FLAG_FD_CLOEXEC
	}
	return PerfOpen{Attr: attr, Flags: flags, PID: s.PID, CPU: s.CPU}
}

// AttrDisabled 报告 attr 是否以 disabled 起始（供 linux 侧测试核对）。
func (p PerfOpen) AttrDisabled() bool { return p.Attr.Bits&perfAttrBitDisabled != 0 }

// AttrInherit 报告 attr 是否继承。
func (p PerfOpen) AttrInherit() bool { return p.Attr.Bits&perfAttrBitInherit != 0 }
