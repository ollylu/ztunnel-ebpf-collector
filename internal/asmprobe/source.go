package asmprobe

import (
	"context"
	"errors"
	"time"
)

// 单一读取 worker 的边界常量。
const (
	readSlice  = 100 * time.Millisecond // 分片读取上限（便于在总 deadline 与取消间有界响应）
	joinBudget = 1 * time.Second        // 返回前等待 worker 退出的上限
)

// ErrSourceClosed 表示事件来源已被关闭（正常收束，不算错误）。
var ErrSourceClosed = errors.New("asmprobe: source closed")

// errWorkerJoinTimeout 表示读取 worker 未能在有界时间内退出（Collect 仍会返回，不悬挂）。
var errWorkerJoinTimeout = errors.New("asmprobe: read worker did not exit within join budget")

// interruptor 是**可选的**取消接缝：实现方在被中断时须让阻塞中的 Read 返回。
// 它不是 EventSource 契约的一部分（4f 的接口面不受影响），只有本包的内核实现会实现它。
type interruptor interface{ Interrupt() error }

// EventSource 是可移植的事件来源接缝：内核实现与测试 fake 共享同一契约。
type EventSource interface {
	Attach(cfg Config) error
	Read(deadline time.Time) (Event, bool, error)
	Disable() error
	Close() error
	CloseOrder() []string
}

// CollectBounded 是本片唯一的采集主循环（可移植）。
//
// 读取所有权：**每次 Collect 只有一个 read worker**（不是每事件/每分片起 goroutine），
// 它是唯一调用 src.Read 的角色；主循环只消费行到 channel 的结果。
//
// 关闭顺序（取消与**总 deadline** 共用同一路径）：
//  1. src.Disable() —— 先停止事件生产者；
//  2. 关闭 stop 通道并（可选）调用 src.Interrupt()，使阻塞读返回；
//  3. 有界 join worker（返回前保证 worker 已退出；超时记为错误但不悬挂）；
//  4. src.Close() 释放其余资源。
//
// Attach 失败时同样回收（Disable+Close），清理错误与原错合并；所有错误不吞。
func CollectBounded(ctx context.Context, cfg Config, src EventSource, entry time.Time) (events []Event, err error) {
	plan, perr := PlanBudget(cfg, entry)
	if perr != nil {
		return nil, perr
	}
	if aerr := src.Attach(cfg); aerr != nil {
		e := aerr
		if derr := src.Disable(); derr != nil {
			e = errors.Join(e, derr)
		}
		if cerr := src.Close(); cerr != nil {
			e = errors.Join(e, cerr)
		}
		return nil, e
	}
	burnCPU(ctx, plan.Burn)

	type readMsg struct {
		ev  Event
		ok  bool
		err error
	}
	msgs := make(chan readMsg, 1)
	stop := make(chan struct{})
	returned := make(chan struct{})
	go func() { // 单一 read worker：唯一调用 src.Read 的角色
		defer close(returned)
		for {
			select {
			case <-stop:
				return
			default:
			}
			dl := time.Now().Add(readSlice)
			if plan.Deadline.Before(dl) {
				dl = plan.Deadline
			}
			ev, ok, rerr := src.Read(dl)
			select {
			case msgs <- readMsg{ev: ev, ok: ok, err: rerr}:
			case <-stop:
				return
			}
			if rerr != nil || !ok {
				return
			}
		}
	}()

	shutdown := func(e error) error {
		if derr := src.Disable(); derr != nil { // 先停事件生产者
			e = errors.Join(e, derr)
		}
		close(stop)
		if it, ok := src.(interruptor); ok {
			if ierr := it.Interrupt(); ierr != nil {
				e = errors.Join(e, ierr)
			}
		}
		select {
		case <-returned: // worker 已退出
		case <-time.After(joinBudget):
			e = errors.Join(e, errWorkerJoinTimeout)
		}
		if cerr := src.Close(); cerr != nil {
			e = errors.Join(e, cerr)
		}
		return e
	}

	events = make([]Event, 0, cfg.MaxEvents)
outer:
	for len(events) < cfg.MaxEvents {
		if ctx.Err() != nil || time.Now().After(plan.Deadline) {
			break
		}
		wait := time.Until(plan.Deadline)
		if wait > readSlice {
			wait = readSlice
		}
		if wait < 0 {
			wait = 0
		}
		select {
		case m := <-msgs:
			if m.err != nil {
				if errors.Is(m.err, ErrSourceClosed) || isTimeoutErr(m.err) {
					break outer
				}
				err = m.err
				break outer
			}
			if !m.ok {
				break outer
			}
			events = append(events, m.ev)
		case <-ctx.Done():
			break outer
		case <-time.After(wait):
			// 读分片或总 deadline 到点：回到循环头统一判断
		}
	}
	return events, shutdown(err)
}

func isTimeoutErr(err error) bool {
	var t interface{ Timeout() bool }
	return errors.As(err, &t) && t.Timeout()
}
