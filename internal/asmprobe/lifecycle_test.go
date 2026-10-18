package asmprobe

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
	"unsafe"
)

// fakeSource 是可控事件来源：脚本化 read 行为、阻塞读取、错误注入与关闭顺序记录。
type fakeSource struct {
	mu         sync.Mutex
	events     []Event
	attachErr  error
	readErr    error
	disableErr error
	closeErr   error
	block      bool
	closed     chan struct{}
	closeOnce  sync.Once
	closedFlag bool
	order      []string
}

func newFakeSource() *fakeSource { return &fakeSource{closed: make(chan struct{})} }

func (f *fakeSource) Attach(Config) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.attachErr
}

func (f *fakeSource) Read(deadline time.Time) (Event, bool, error) {
	if f.block {
		<-f.closed
		return Event{}, false, ErrSourceClosed
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.events) == 0 {
		return Event{}, false, f.readErr
	}
	ev := f.events[0]
	f.events = f.events[1:]
	return ev, true, nil
}

func (f *fakeSource) Disable() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.order = append(f.order, "perf_disable")
	return f.disableErr
}

func (f *fakeSource) Close() error {
	f.mu.Lock()
	f.order = append(f.order, "perf_close", "reader", "program", "map")
	f.mu.Unlock()
	f.closeOnce.Do(func() { f.closedFlag = true; close(f.closed) })
	return f.closeErr
}

func (f *fakeSource) isClosed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closedFlag
}

func (f *fakeSource) CloseOrder() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.order))
	copy(out, f.order)
	return out
}

func testCfg() Config {
	return Config{TID: 1, Nonce: 7, MaxEvents: MaxEvents, Duration: 4 * time.Second,
		SamplePeriod: DefaultSamplePeriod, CPUBudget: 1 * time.Second}
}

// deadline 必须从 Collect 入口一次计算，且 burn+read 不超总时长。
func TestPlanBudgetDeadlineFromEntryAndWithinDuration(t *testing.T) {
	entry := time.Now()
	plan, err := PlanBudget(testCfg(), entry)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Deadline.Equal(entry.Add(testCfg().Duration)) {
		t.Fatalf("deadline=%s, want entry+%s", plan.Deadline, testCfg().Duration)
	}
	if plan.Burn <= 0 || plan.Burn > testCfg().CPUBudget {
		t.Fatalf("burn=%s, want in (0,%s]", plan.Burn, testCfg().CPUBudget)
	}
	if plan.Burn+plan.Read > testCfg().Duration {
		t.Fatalf("burn+read=%s exceeds duration %s", plan.Burn+plan.Read, testCfg().Duration)
	}
	if _, err := PlanBudget(Config{}, entry); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("invalid cfg must be rejected, got %v", err)
	}
}

// 取消必须能真正打断阻塞读取：用可取消 ctx，且**不预关 src**。
func TestCollectBoundedCancelUnblocksBlockedRead(t *testing.T) {
	src := newFakeSource()
	src.block = true
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		_, _ = CollectBounded(ctx, testCfg(), src, time.Now())
		close(done)
	}()
	time.Sleep(100 * time.Millisecond)
	cancel() // 产品取消路径（真实 ctx），不预关 src
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("blocked Read did not return within 2s of ctx cancel")
	}
	if !src.isClosed() {
		t.Fatal("cancel path must still run Disable/Close cleanup")
	}
}

// 未知 Read 错误必须返回（不吞错）。
func TestCollectBoundedPropagatesUnknownReadError(t *testing.T) {
	src := newFakeSource()
	sentinel := errors.New("unknown read failure")
	src.readErr = sentinel
	_, err := CollectBounded(context.Background(), testCfg(), src, time.Now())
	if !errors.Is(err, sentinel) {
		t.Fatalf("unknown read error must propagate, got %v", err)
	}
}

// Disable/Close 错误必须经 CollectBounded 返回；Attach 失败也必须回收并合并错误。
func TestCollectBoundedPropagatesDisableAndCloseErrors(t *testing.T) {
	src := newFakeSource()
	src.disableErr = errors.New("disable failed")
	if _, err := CollectBounded(context.Background(), testCfg(), src, time.Now()); !errors.Is(err, src.disableErr) {
		t.Fatalf("disable error must propagate through CollectBounded, got %v", err)
	}
	src2 := newFakeSource()
	src2.closeErr = errors.New("close failed")
	if _, err := CollectBounded(context.Background(), testCfg(), src2, time.Now()); !errors.Is(err, src2.closeErr) {
		t.Fatalf("close error must propagate through CollectBounded, got %v", err)
	}
	src3 := newFakeSource()
	src3.attachErr = errors.New("attach failed")
	src3.disableErr = errors.New("disable after attach failure")
	_, err := CollectBounded(context.Background(), testCfg(), src3, time.Now())
	if !errors.Is(err, src3.attachErr) || !errors.Is(err, src3.disableErr) {
		t.Fatalf("attach failure must be cleaned up and errors merged, got %v", err)
	}
	if !src3.isClosed() {
		t.Fatal("attach failure must still close the source")
	}
}

// 关闭顺序：perf disable/close 必须先于 reader/program/map。
func TestCollectBoundedClosesPerfBeforeReaderProgramMap(t *testing.T) {
	src := newFakeSource()
	src.events = []Event{{Tid: 1, Pid: 2, Ktime: 3, Nonce: 7}}
	events, err := CollectBounded(context.Background(), testCfg(), src, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("want 1 event, got %d", len(events))
	}
	order := src.CloseOrder()
	want := []string{"perf_disable", "perf_close", "reader", "program", "map"}
	if len(order) != len(want) {
		t.Fatalf("close order=%v, want %v", order, want)
	}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("close order=%v, want %v", order, want)
		}
	}
}

// 事件 ABI：偏移与保留位必须精确。
func TestEventABIOffsetsAndReserved(t *testing.T) {
	var e Event
	if got := unsafe.Offsetof(e.Tid); got != 0 {
		t.Errorf("Tid offset=%d, want 0", got)
	}
	if got := unsafe.Offsetof(e.Pid); got != 4 {
		t.Errorf("Pid offset=%d, want 4", got)
	}
	if got := unsafe.Offsetof(e.Ktime); got != 8 {
		t.Errorf("Ktime offset=%d, want 8", got)
	}
	if got := unsafe.Offsetof(e.Nonce); got != 16 {
		t.Errorf("Nonce offset=%d, want 16", got)
	}
	b := make([]byte, EventSize)
	binaryLittleEndianPut(b)
	for i := 24; i < EventSize; i++ {
		if b[i] != 0 {
			t.Fatalf("reserved byte %d = %d, want 0", i, b[i])
		}
	}
}

// deadlineSource：Read 阻塞直到 Interrupt 释放；用于验证"总 deadline"与 ctx 共用关闭路径。
type deadlineSource struct {
	release     chan struct{}
	releaseOnce sync.Once
	mu          sync.Mutex
	log         []string
}

func newDeadlineSource() *deadlineSource {
	return &deadlineSource{release: make(chan struct{})}
}

func (f *deadlineSource) record(s string) { f.mu.Lock(); f.log = append(f.log, s); f.mu.Unlock() }
func (f *deadlineSource) snapshot() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.log...)
}

func (f *deadlineSource) Attach(Config) error { f.record("attach"); return nil }
func (f *deadlineSource) Read(time.Time) (Event, bool, error) {
	<-f.release
	return Event{}, false, ErrSourceClosed
}
func (f *deadlineSource) Disable() error       { f.record("disable"); return nil }
func (f *deadlineSource) Close() error         { f.record("close"); return nil }
func (f *deadlineSource) CloseOrder() []string { return f.snapshot() }
func (f *deadlineSource) Interrupt() error {
	f.record("interrupt")
	go func() {
		time.Sleep(10 * time.Millisecond)
		f.releaseOnce.Do(func() { close(f.release) })
	}()
	return nil
}

func TestCollectBoundedTotalDeadlineUsesSameShutdownPath(t *testing.T) {
	f := newDeadlineSource()
	cfg := testCfg()
	cfg.Duration = 300 * time.Millisecond
	start := time.Now()
	if _, err := CollectBounded(context.Background(), cfg, f, start); err != nil && !errors.Is(err, errWorkerJoinTimeout) {
		t.Fatalf("unexpected error on deadline path: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("deadline path took %s (must be bounded)", elapsed)
	}
	log := f.snapshot()
	di, ii, ci := -1, -1, -1
	for i, s := range log {
		switch s {
		case "disable":
			if di < 0 {
				di = i
			}
		case "interrupt":
			if ii < 0 {
				ii = i
			}
		case "close":
			if ci < 0 {
				ci = i
			}
		}
	}
	if di < 0 || ii < 0 || ci < 0 {
		t.Fatalf("deadline path must Disable, Interrupt and Close; log=%v", log)
	}
	if ii < di {
		t.Fatalf("deadline path must Disable before Interrupt; log=%v", log)
	}
	if ci < ii {
		t.Fatalf("deadline path must Interrupt before Close; log=%v", log)
	}
}
