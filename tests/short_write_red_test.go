package tests

import (
	"strings"
	"testing"

	"ztunnel-ebpf-collector/internal/replay"
)

// shortWriter 模拟"短写"：只接收 limit 字节并返回 n<len(p) 且 **err==nil**。
// 契约：同步短程 replay writer，**写失败立即返回**；
// 因此 n<len(p) 必须作为写失败上报，不能被当成成功（否则 stdout 静默截断）。
type shortWriter struct{ limit int }

func (w *shortWriter) Write(p []byte) (int, error) {
	if w.limit <= 0 {
		return 0, nil
	}
	if len(p) > w.limit {
		return w.limit, nil // 短写：n < len(p)，err == nil
	}
	return len(p), nil
}

func TestReplaySurfacesShortWrite(t *testing.T) {
	const line = `{"request":"GET / HTTP/1.1\r\nx-trace: print\r\nHost: a\r\n\r\n","response":"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc"}` + "\n"
	err := replay.Run(strings.NewReader(line), &shortWriter{limit: 1})
	if err == nil {
		t.Fatalf("短写（n<len(p) 且 err==nil）必须作为写失败上报（例如 io.ErrShortWrite）；实际 err=nil ⇒ 记录被静默截断")
	}
}
