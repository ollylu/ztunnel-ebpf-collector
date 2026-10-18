//go:build kernel

package tests

import (
	"context"
	"errors"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/cilium/ebpf"

	"ztunnel-ebpf-collector/internal/asmprobe"
)

// 预检与行为断言严格分开：环境未就绪只报告，不记作行为红。
func TestI15_PrecheckEnvironment(t *testing.T) {
	pc := asmprobe.PrecheckEnv(asmprobe.OSEnv{}, 4)
	t.Logf("precheck ready=%v sw_clock=%v paranoid=%d kernel=%s source=%s reason=%s", pc.Ready, pc.SwClockOK, pc.Paranoid, pc.Kernel, pc.EventSource, pc.Reason)
	if !pc.Ready {
		t.Skipf("environment not ready (NOT a behavior red): %s", pc.Reason)
	}
}

// 真实内核行为：在**同一锁定 TID** 上做有界 CPU 工作（hrtimer SW CPU_CLOCK 采样）后必须取得真实事件，
// 断言对象是"真实事件缺失"（attach 成功后零事件），不是桩的错误返回。
func TestI15_RealEventsForLockedTID(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	tid := asmprobe.CurrentTID()
	attached := false
	cfg := asmprobe.Config{
		TID: tid, Nonce: 0x5eed, MaxEvents: asmprobe.MaxEvents, Duration: 5 * time.Second,
		SamplePeriod: asmprobe.DefaultSamplePeriod, CPUBudget: asmprobe.MaxCPUBudget,
		OnAttach: func(asmprobe.AttachInfo) { attached = true },
	}
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Duration)
	defer cancel()
	events, err := asmprobe.Run(ctx, cfg, asmprobe.NewKernelCollector())
	if asmprobe.IsPrereq(err) {
		t.Skipf("prerequisite not ready (NOT a behavior red): %v", err)
	}
	if err != nil {
		t.Fatalf("collect failed on the locked thread (not a zero-event red): %v", err)
	}
	if !attached {
		t.Fatal("load+attach did not report success; zero events would be meaningless")
	}
	if len(events) == 0 {
		t.Fatalf("attach succeeded on locked tid %d but no real events were captured: event output missing (behavior red)", tid)
	}
	for _, e := range events {
		if e.Nonce != cfg.Nonce {
			t.Fatalf("event nonce=%d, want %d", e.Nonce, cfg.Nonce)
		}
		if e.Tid != uint32(tid) {
			t.Fatalf("event tid=%d, want locked tid %d", e.Tid, tid)
		}
	}
}

// 真实阻塞 Read 的产品取消：不预关 source，仅取消 ctx；必须 ≤2s 返回。
func TestI15_CancelUnblocksRealRead(t *testing.T) {
	runtime.LockOSThread()
	tid := asmprobe.CurrentTID()
	runtime.UnlockOSThread()
	attached := false
	cfg := asmprobe.Config{
		TID: tid, Nonce: 0x1234, MaxEvents: asmprobe.MaxEvents, Duration: 10 * time.Second,
		SamplePeriod: asmprobe.DefaultSamplePeriod, CPUBudget: asmprobe.MaxCPUBudget,
		OnAttach: func(asmprobe.AttachInfo) { attached = true },
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := asmprobe.Run(ctx, cfg, asmprobe.NewKernelCollector())
		done <- err
	}()
	time.Sleep(300 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if asmprobe.IsPrereq(err) {
			t.Skipf("prerequisite not ready (NOT a behavior red): %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("real blocked Read did not return within 2s of ctx cancel")
	}
	_ = attached
}

// 自有对象回收：ID 必须**曾存在**，随后在 ≤2s 有界轮询内消失（只认 ENOENT，其他错误不放过）。
func TestI15_ReclaimsOwnObjectsBounded(t *testing.T) {
	runtime.LockOSThread()
	tid := asmprobe.CurrentTID()
	runtime.UnlockOSThread()
	var progID, mapID uint32
	cfg := asmprobe.Config{
		TID: tid, Nonce: 0x4321, MaxEvents: asmprobe.MaxEvents, Duration: 3 * time.Second,
		SamplePeriod: asmprobe.DefaultSamplePeriod, CPUBudget: 200 * time.Millisecond,
		OnAttach: func(info asmprobe.AttachInfo) { progID, mapID = info.ProgramID, info.MapID },
	}
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Duration)
	defer cancel()
	if _, err := asmprobe.Run(ctx, cfg, asmprobe.NewKernelCollector()); asmprobe.IsPrereq(err) {
		t.Skipf("prerequisite not ready (NOT a behavior red): %v", err)
	}
	if progID == 0 || mapID == 0 {
		t.Fatal("own program/map id was never observed; reclamation cannot be asserted")
	}
	if err := waitProgramReclaimed(progID, 2*time.Second); err != nil {
		t.Fatalf("program id=%d not reclaimed within 2s: %v", progID, err)
	}
	if err := waitMapReclaimed(mapID, 2*time.Second); err != nil {
		t.Fatalf("map id=%d not reclaimed within 2s: %v", mapID, err)
	}
}

// 有界轮询：只把 ENOENT 视为已回收；其他错误原样返回；每次查询取得的 FD 立即关闭。
func waitMapReclaimed(id uint32, budget time.Duration) error {
	deadline := time.Now().Add(budget)
	var last error
	for {
		m, err := ebpf.NewMapFromID(ebpf.MapID(id))
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			return err
		}
		_ = m.Close()
		last = errors.New("map id still queryable")
		if time.Now().After(deadline) {
			return last
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func waitProgramReclaimed(id uint32, budget time.Duration) error {
	deadline := time.Now().Add(budget)
	var last error
	for {
		p, err := ebpf.NewProgramFromID(ebpf.ProgramID(id))
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			return err
		}
		_ = p.Close()
		last = errors.New("program id still queryable")
		if time.Now().After(deadline) {
			return last
		}
		time.Sleep(50 * time.Millisecond)
	}
}
