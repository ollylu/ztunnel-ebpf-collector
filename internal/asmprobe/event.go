// Package asmprobe 是 I1-5 的最小内核实验薄片（Go/asm，无 C/cgo/clang）。
//
// 本片边界：
//   - 事件源：PERF_TYPE_SOFTWARE/PERF_COUNT_SW_CPU_CLOCK + BPF_PROG_TYPE_PERF_EVENT（pid=显式锁定 TID, cpu=-1, 初始 disabled, inherit=false, CLOEXEC）
//   - 事件：固定 32 字节，仅 pid/tid/ktime/nonce；每 case ≤16 次 syscall；≤10 秒
//   - 资源：1 program + 1 ring(64KiB, 非 per-CPU) + 1 perf attachment，单一 owner 逆序回滚
//   - 不做：pid=-1 全节点挂载、改 sysctl/rlimit、装模块、自动切 uprobe/tracefs、pin
package asmprobe

import (
	"encoding/binary"
	"errors"
)

// EventSize 是内核事件的固定 ABI 长度（字节）。
const EventSize = 32

// ErrShortEvent 表示读取到的字节数不足以构成一个完整事件。
var ErrShortEvent = errors.New("asmprobe: short event")

// Event 是固定 32 字节的事件 ABI：tid(4) + pid(4) + ktime(8) + nonce(8) + 保留(8)。
type Event struct {
	Tid   uint32
	Pid   uint32
	Ktime uint64
	Nonce uint64
	_     [8]byte // ABI 保留位，必须显式存在以固定长度
}

// ParseEvent 解析一条事件；长度不符立即拒绝（不做截断或补齐）。
func ParseEvent(b []byte) (Event, error) {
	if len(b) != EventSize {
		return Event{}, ErrShortEvent
	}
	return Event{
		Tid:   binary.LittleEndian.Uint32(b[0:4]),
		Pid:   binary.LittleEndian.Uint32(b[4:8]),
		Ktime: binary.LittleEndian.Uint64(b[8:16]),
		Nonce: binary.LittleEndian.Uint64(b[16:24]),
	}, nil
}
