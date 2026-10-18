// 5c 独立失败件（非作者）：复现 a8213570 生命周期阻断。
// 可移植：用假 EventSource 模拟"部分 Attach 已获取资源后失败"与"阻塞 Read 期间真实 ctx cancel"。
package i15failing

import (
	"context"
	"errors"
	"testing"
	"time"

	"ztunnel-ebpf-collector/internal/asmprobe"
)

func cfg(d time.Duration) asmprobe.Config {
	return asmprobe.Config{TID: 1, Nonce: 1, MaxEvents: 4, Duration: d, SamplePeriod: 10 * time.Millisecond, CPUBudget: 10 * time.Millisecond}
}

// partialAttach 记录 Attach 已获取资源后失败；回收必须发生（Disable/Close）。
type partialAttach struct{ disabled, closed bool }

func (f *partialAttach) Attach(asmprobe.Config) error {
	return errors.New("attach failed after partial acquisition (map/prog/perf held)")
}
func (f *partialAttach) Read(time.Time) (asmprobe.Event, bool, error) {
	return asmprobe.Event{}, false, asmprobe.ErrSourceClosed
}
func (f *partialAttach) Disable() error       { f.disabled = true; return nil }
func (f *partialAttach) Close() error         { f.closed = true; return nil }
func (f *partialAttach) CloseOrder() []string { return []string{"perf", "reader", "prog", "ring"} }

// blockingSource 的 Read 一直阻塞，直到 release；测试不预关 src。
type blockingSource struct {
	release chan struct{}
	closed  bool
}

func (f *blockingSource) Attach(asmprobe.Config) error { return nil }
func (f *blockingSource) Read(time.Time) (asmprobe.Event, bool, error) {
	<-f.release
	return asmprobe.Event{}, false, asmprobe.ErrSourceClosed
}
func (f *blockingSource) Disable() error       { return nil }
func (f *blockingSource) Close() error         { f.closed = true; return nil }
func (f *blockingSource) CloseOrder() []string { return []string{"perf", "reader", "prog", "ring"} }

// 阻断①：Attach 部分获取后失败 ⇒ 必须回收（当前直接 return，未 Disable/Close）。
func TestCollectBoundedCleansUpWhenAttachFailsAfterPartialAcquire(t *testing.T) {
	f := &partialAttach{}
	_, err := asmprobe.CollectBounded(context.Background(), cfg(time.Second), f, time.Now())
	if err == nil {
		t.Fatal("Attach 失败应返回错误")
	}
	if !f.disabled || !f.closed {
		t.Fatalf("Attach 部分获取后失败必须回收：期望 Disable/Close 均被调用，实际 disabled=%v closed=%v ⇒ map/prog/perf 泄漏", f.disabled, f.closed)
	}
}

// 阻断②：阻塞 Read 期间真实 ctx cancel 必须被打断（不预关 src、无测试侧 Close）。
func TestCollectBoundedCtxCancelInterruptsBlockingRead(t *testing.T) {
	f := &blockingSource{release: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := asmprobe.CollectBounded(ctx, cfg(10*time.Second), f, time.Now())
		done <- err
	}()
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case <-done:
		// 取消被及时响应 ⇒ 通过
	case <-time.After(2 * time.Second):
		close(f.release)
		t.Fatal("ctx 取消后 2s 内未返回 ⇒ 读取期间无 ctx watcher/短 deadline，产品取消不可打断 Read")
	}
}
