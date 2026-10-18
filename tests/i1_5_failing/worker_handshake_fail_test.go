// 5c 独立失败件（修订版，非作者；确定性握手，不用 -race/cgo）。
// 夹具修订（PL 指正）：Interrupt 后**有界短延迟(50ms)释放 Read**（模拟真实 reader.Close 解阻塞），
// 用独立 readReturned 通道证明 worker 结束；不再循环等待。断言未弱化：
//
//	R1 Collect 返回时必须已收到 readReturned（即无未完成 worker）；
//	R3 取消路径 Disable 必须先于 Interrupt/最终 Close。
package i15failing

import (
	"context"
	"sync"
	"testing"
	"time"

	"ztunnel-ebpf-collector/internal/asmprobe"
)

type handshakeSource struct {
	started, release, returned chan struct{}
	releaseOnce                sync.Once
	mu                         sync.Mutex
	log                        []string
	closed                     bool
}

func (f *handshakeSource) record(s string) { f.mu.Lock(); f.log = append(f.log, s); f.mu.Unlock() }
func (f *handshakeSource) snapshot() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.log...)
}
func (f *handshakeSource) forceRelease() { f.releaseOnce.Do(func() { close(f.release) }) }

func (f *handshakeSource) Attach(asmprobe.Config) error { f.record("attach"); return nil }
func (f *handshakeSource) Read(time.Time) (asmprobe.Event, bool, error) {
	f.record("read")
	select {
	case f.started <- struct{}{}:
	default:
	}
	<-f.release
	f.mu.Lock()
	f.closed = true
	f.mu.Unlock()
	f.record("read-returned")
	close(f.returned)
	return asmprobe.Event{}, false, asmprobe.ErrSourceClosed
}
func (f *handshakeSource) Disable() error       { f.record("disable"); return nil }
func (f *handshakeSource) Close() error         { f.record("close"); return nil }
func (f *handshakeSource) CloseOrder() []string { return []string{"perf", "reader", "prog", "ring"} }

// Interrupt 模拟真实语义：关闭 reader 使阻塞读返回（有界短延迟，避免夹具循环等待）。
func (f *handshakeSource) Interrupt() error {
	f.record("interrupt")
	go func() { time.Sleep(50 * time.Millisecond); f.forceRelease() }()
	return nil
}

func newHandshake() *handshakeSource {
	return &handshakeSource{started: make(chan struct{}, 1), release: make(chan struct{}), returned: make(chan struct{})}
}

// runCancel 启动 Collect、确定性等 Read 已开始、cancel，并等待 Collect 返回；
// 返回的 cleanup 保证失败分支也释放并等待测试自身 worker（不留挂 goroutine）。
func runCancel(t *testing.T, f *handshakeSource) (cleanup func()) {
	t.Helper()
	cleanup = func() {
		f.forceRelease()
		select {
		case <-f.returned:
		case <-time.After(2 * time.Second):
			t.Errorf("测试自身 worker 未在有界时间内结束（夹具泄漏）")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _, _ = asmprobe.CollectBounded(ctx, cfg(5*time.Second), f, time.Now()); close(done) }()
	select {
	case <-f.started:
	case <-time.After(2 * time.Second):
		cancel()
		cleanup()
		t.Fatal("Read worker 未在 2s 内启动（前置失败）")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		cancel()
		cleanup()
		t.Fatal("取消后 Collect 未在 2s 内返回")
	}
	return cleanup
}

// R1：Collect 返回时必须已收到 readReturned（无未完成 worker）。
func TestCollectReturnLeavesNoRunningReadWorker(t *testing.T) {
	f := newHandshake()
	cleanup := runCancel(t, f)
	defer cleanup()
	select {
	case <-f.returned:
		// 正确 join：worker 已结束
	default:
		t.Fatalf("Collect 返回时 Read worker 未结束（无 join 握手）：log=%v", f.snapshot())
	}
}

// R3：取消路径 Disable 必须先于 Interrupt/最终 Close。
func TestCancelPathStopsProducerBeforeClosingReader(t *testing.T) {
	f := newHandshake()
	cleanup := runCancel(t, f)
	defer cleanup()
	di, ii := -1, -1
	for i, s := range f.snapshot() {
		if s == "disable" && di < 0 {
			di = i
		}
		if s == "interrupt" && ii < 0 {
			ii = i
		}
	}
	if di < 0 || ii < 0 {
		t.Fatalf("取消路径须同时出现 disable 与 interrupt；实际 log=%v", f.snapshot())
	}
	if ii < di {
		t.Fatalf("取消路径先关 reader 再 Disable（偏离先停事件生产者约定）：log=%v", f.snapshot())
	}
}
