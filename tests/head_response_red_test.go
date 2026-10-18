package tests

import (
	"bytes"
	"strings"
	"testing"

	"ztunnel-ebpf-collector/internal/replay"
)

// 配对语义：响应解析必须使用**真实请求 method**（parseMessage 响应侧现硬编码 http.MethodGet）。
// HEAD 的合法响应按 RFC 9110 **无正文**，即使带 Content-Length>0 也不得因此判非法；
// 而同一形状的 **GET** 响应（声明 CL>0 却无正文）必须**继续 fail-closed 拒绝**。
func TestReplayHeadResponseWithoutBodyIsAccepted(t *testing.T) {
	head := `{"request":"HEAD / HTTP/1.1\r\nx-trace: print\r\nHost: a\r\n\r\n","response":"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n"}` + "\n"
	var out bytes.Buffer
	if err := replay.Run(strings.NewReader(head), &out); err != nil {
		t.Fatalf("染色 HEAD 配对不得使整条失败：%v", err)
	}
	lines := strings.Count(strings.TrimSpace(out.String()), "\n") + 1
	if strings.TrimSpace(out.String()) == "" {
		lines = 0
	}
	if lines != 2 {
		t.Fatalf("合法 HEAD(200/CL>0 无正文) 应产出请求+响应 2 条，实际 %d 条（响应被误拒）", lines)
	}
	var get bytes.Buffer
	getIn := `{"request":"GET / HTTP/1.1\r\nx-trace: print\r\nHost: a\r\n\r\n","response":"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n"}` + "\n"
	if err := replay.Run(strings.NewReader(getIn), &get); err != nil {
		t.Fatalf("GET 对照组不得使整条失败（应 fail-closed 不输出）：%v", err)
	}
	if strings.TrimSpace(get.String()) != "" {
		t.Fatalf("GET 声明 CL>0 却无正文必须继续拒绝；实际输出=%q", get.String())
	}
}
