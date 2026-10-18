//go:build linux && amd64

package asmprobe

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
)

// Linux perf ioctl（linux/perf_event.h 的 _IO/_IOW 编码值）。
const (
	perfEventIocEnable  = 0x2400
	perfEventIocDisable = 0x2401
	perfEventIocSetBPF  = 0x40042408
)

// programType 固定为 PERF_EVENT（不使用 tracepoint：其 prog_array 全局共享，pid 不保证线程隔离）。
const programType = ebpf.PerfEvent

// KernelCollector 是本片内核路径：本轮**仅支持 linux/amd64**。
type KernelCollector struct{}

// NewKernelCollector 返回内核事件来源。
func NewKernelCollector() Collector { return &KernelCollector{} }

// Collect 执行一次有界实验；前提失败返回 *PrereqError（不得算作行为红）。
// 目标刺激与读取都在**同一锁定线程**上，且 TID 必须与 cfg.TID 一致。
func (k *KernelCollector) Collect(ctx context.Context, cfg Config) ([]Event, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if got := CurrentTID(); got != cfg.TID {
		return nil, fmt.Errorf("%w: cfg.TID=%d current=%d", ErrTIDMismatch, cfg.TID, got)
	}
	entry := time.Now()
	src := newLinuxSource()
	return CollectBounded(ctx, cfg, src, entry)
}

// linuxSource 是 Linux 上的 EventSource：资源创建/持有/释放的单一 owner。
// 约定：perfFD 哨兵为 **-1**（合法 fd 0 不能被漏关）；Close/Disable 幂等（sync.Once），
// 部分初始化状态下也可安全回收；多次 Close 不重复关同一 FD。
type linuxSource struct {
	ring     *ebpf.Map
	prog     *ebpf.Program
	perfFD   int
	reader   *ringbuf.Reader
	readerMu sync.Mutex

	orderMu sync.Mutex
	order   []string

	disableOnce sync.Once
	disableErr  error

	readerOnce sync.Once
	readerErr  error

	closeOnce sync.Once
	closeErr  error
}

func newLinuxSource() *linuxSource { return &linuxSource{perfFD: -1} }

// Attach 创建 1 ring map + 1 program + 1 perf event 并挂载（失败即 *PrereqError，由主循环统一回收）。
func (s *linuxSource) Attach(cfg Config) error {
	m, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.RingBuf, MaxEntries: RingSize, Name: "i15_events"})
	if err != nil {
		return &PrereqError{Stage: "create_ringbuf", Err: err}
	}
	s.ring = m

	insns := eventInstructions(m.FD(), cfg.Nonce)
	prog, err := ebpf.NewProgramWithOptions(&ebpf.ProgramSpec{
		Type: programType, Instructions: insns, License: "GPL",
	}, ebpf.ProgramOptions{LogDisabled: true})
	if err != nil {
		return &PrereqError{Stage: "load_event_program", Err: err}
	}
	s.prog = prog

	po := OpenSpec(SoftwareCPUClockSpec(cfg.TID, cfg.SamplePeriod))
	fd, err := unix.PerfEventOpen(&po.Attr, po.PID, po.CPU, -1, po.Flags)
	if err != nil {
		return &PrereqError{Stage: "perf_event_open", Err: err}
	}
	s.perfFD = fd
	if err := unix.IoctlSetInt(fd, perfEventIocSetBPF, prog.FD()); err != nil {
		return &PrereqError{Stage: "perf_event_ioc_set_bpf", Err: err}
	}
	if err := unix.IoctlSetInt(fd, perfEventIocEnable, 0); err != nil {
		return &PrereqError{Stage: "perf_event_ioc_enable", Err: err}
	}
	rd, err := ringbuf.NewReader(m)
	if err != nil {
		return &PrereqError{Stage: "ringbuf_reader", Err: err}
	}
	s.reader = rd

	pi, err := prog.Info()
	if err != nil {
		return &PrereqError{Stage: "program_info_id", Err: err}
	}
	progID, ok := pi.ID()
	if !ok {
		return &PrereqError{Stage: "program_info_id", Err: errors.New("program id unavailable")}
	}
	mi, err := m.Info()
	if err != nil {
		return &PrereqError{Stage: "map_info_id", Err: err}
	}
	mapID, ok := mi.ID()
	if !ok {
		return &PrereqError{Stage: "map_info_id", Err: errors.New("map id unavailable")}
	}
	if cfg.OnAttach != nil {
		cfg.OnAttach(AttachInfo{ProgramID: uint32(progID), MapID: uint32(mapID), PerfEventFD: fd, LockedTID: cfg.TID})
	}
	return nil
}

// Read 读取一条事件；超时/关闭以 (ok=false, nil) 或 ErrSourceClosed 表达，未知错误原样返回。
func (s *linuxSource) Read(deadline time.Time) (Event, bool, error) {
	s.readerMu.Lock()
	rd := s.reader
	if rd != nil {
		rd.SetDeadline(deadline)
	}
	s.readerMu.Unlock()
	if rd == nil {
		return Event{}, false, ErrSourceClosed
	}
	rec, err := rd.Read()
	if err != nil {
		if errors.Is(err, ringbuf.ErrClosed) {
			return Event{}, false, ErrSourceClosed
		}
		if isTimeoutErr(err) {
			return Event{}, false, nil
		}
		return Event{}, false, err
	}
	ev, perr := ParseEvent(rec.RawSample)
	if perr != nil {
		return Event{}, false, nil // ABI 长度门禁：拒绝该条
	}
	return ev, true, nil
}

// Interrupt 是可选取消接缝：关闭 reader 使阻塞中的 Read 返回（cilium/ebpf 文档保证解阻塞）。
func (s *linuxSource) Interrupt() error {
	s.readerOnce.Do(func() {
		s.readerMu.Lock()
		defer s.readerMu.Unlock()
		if s.reader != nil {
			s.readerErr = s.reader.Close()
		}
	})
	return s.readerErr
}

// Disable 先解除挂载（幂等）。
func (s *linuxSource) Disable() error {
	s.disableOnce.Do(func() {
		s.record("perf_disable")
		if s.perfFD >= 0 {
			s.disableErr = unix.IoctlSetInt(s.perfFD, perfEventIocDisable, 0)
		}
	})
	return s.disableErr
}

// Close 逆序释放：perf fd → reader → program → map（幂等；错误聚合返回，不吞错）。
func (s *linuxSource) Close() error {
	s.closeOnce.Do(func() {
		var errs []error
		s.record("perf_close")
		if s.perfFD >= 0 {
			if err := unix.Close(s.perfFD); err != nil {
				errs = append(errs, err)
			}
			s.perfFD = -1
		}
		s.record("reader")
		s.readerMu.Lock()
		rd := s.reader
		if rd != nil {
			s.readerOnce.Do(func() { s.readerErr = rd.Close() })
			if s.readerErr != nil {
				errs = append(errs, s.readerErr)
			}
			s.reader = nil
		}
		s.readerMu.Unlock()
		s.record("program")
		if s.prog != nil {
			if err := s.prog.Close(); err != nil {
				errs = append(errs, err)
			}
			s.prog = nil
		}
		s.record("map")
		if s.ring != nil {
			if err := s.ring.Close(); err != nil {
				errs = append(errs, err)
			}
			s.ring = nil
		}
		s.closeErr = errors.Join(errs...)
	})
	return s.closeErr
}

func (s *linuxSource) record(name string) {
	s.orderMu.Lock()
	s.order = append(s.order, name)
	s.orderMu.Unlock()
}

// CloseOrder 返回实际释放顺序（证据用）。
func (s *linuxSource) CloseOrder() []string {
	s.orderMu.Lock()
	defer s.orderMu.Unlock()
	out := make([]string, len(s.order))
	copy(out, s.order)
	return out
}

// eventInstructions 构造 32 字节事件 ABI 的最小 asm：
// tid@0(u32) pid@4(u32) ktime@8(u64) nonce@16(u64) reserved@24(u64=0)。
// 无用户态伪造：pid/tid 与 ktime 均来自内核 helper。
func eventInstructions(ringFD int, nonce uint64) asm.Instructions {
	const labelExit = "exit"
	insns := asm.Instructions{
		asm.LoadMapPtr(asm.R1, ringFD),
		asm.Mov.Imm(asm.R2, EventSize),
		asm.Mov.Imm(asm.R3, 0),
		asm.FnRingbufReserve.Call(),
		asm.JEq.Imm(asm.R0, 0, labelExit), // reserve 失败 → 退出（有界，不等待）
		asm.Mov.Reg(asm.R6, asm.R0),       // r6 = 事件指针（callee-saved）
		asm.FnGetCurrentPidTgid.Call(),    // r0 = pid<<32 | tid
		asm.StoreMem(asm.R6, 0, asm.R0, asm.Word),
		asm.RSh.Imm(asm.R0, 32),
		asm.StoreMem(asm.R6, 4, asm.R0, asm.Word),
		asm.FnKtimeGetNs.Call(),
		asm.StoreMem(asm.R6, 8, asm.R0, asm.DWord),
		asm.LoadImm(asm.R1, int64(nonce), asm.DWord),
		asm.StoreMem(asm.R6, 16, asm.R1, asm.DWord),
		asm.Mov.Imm(asm.R1, 0),
		asm.StoreMem(asm.R6, 24, asm.R1, asm.DWord), // reserved = 0
		asm.Mov.Reg(asm.R1, asm.R6),
		asm.Mov.Imm(asm.R2, 0),
		asm.FnRingbufSubmit.Call(),
	}
	insns = append(insns,
		asm.Mov.Imm(asm.R0, 0).WithSymbol(labelExit),
		asm.Return(),
	)
	return insns
}
