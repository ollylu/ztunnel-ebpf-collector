package replay_test

import (
	"errors"
	"io"
	"strings"
	"testing"

	"ztunnel-ebpf-collector/internal/replay"
)

// errShortWriteWant 是契约要求的短写错误（io.ErrShortWrite）。
var errShortWriteWant = io.ErrShortWrite

// 以下用例逐条对应非作者行为报告 5d01291 的阻断项；先红后修，不修改需求期望。

// ①a 非 HTTP/1 版本必须拒绝（只允许 HTTP/1.0 与 HTTP/1.1）。
func TestBlocker_NonHTTP1VersionRejected(t *testing.T) {
	recs, out, err := run(t, fixture(t, "blocker_http99.jsonl"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(recs) != 0 || out != "" {
		t.Fatalf("HTTP/9.9 must produce no output, got %d records (%q)", len(recs), out)
	}
}

// ①b 字段名前导空白必须拒绝（标准库若兼容接受，也须显式校验）。
func TestBlocker_LeadingWhitespaceHeaderNameRejected(t *testing.T) {
	recs, out, err := run(t, fixture(t, "blocker_ws_header.jsonl"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(recs) != 0 || out != "" {
		t.Fatalf("' x-trace: print' must not colorize, got %d records (%q)", len(recs), out)
	}
}

// ①c-1 声明 Content-Length: 0 但头后仍有字节：不得当作正文输出。
func TestBlocker_ContentLengthZeroWithTrailingBytesRejected(t *testing.T) {
	recs, out, err := run(t, fixture(t, "blocker_cl0_trailing.jsonl"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(recs) != 0 || strings.Contains(out, "EXTRA") {
		t.Fatalf("trailing bytes after CL:0 must not be emitted, got %d records (%q)", len(recs), out)
	}
}

// ①c-2 声明长度小于实际字节（CL:3 实际 abcdef）：不得把多余字节当正文。
func TestBlocker_BodyLongerThanDeclaredRejected(t *testing.T) {
	recs, out, err := run(t, fixture(t, "blocker_cl_short_body.jsonl"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(recs) != 0 || strings.Contains(out, "abcdef") {
		t.Fatalf("body longer than declared must not be emitted, got %d records (%q)", len(recs), out)
	}
}

// ①c-3 不支持的传输编码（chunked）必须拒绝：允许编码必须显式。
func TestBlocker_TransferEncodingChunkedRejected(t *testing.T) {
	recs, out, err := run(t, fixture(t, "blocker_te_chunked.jsonl"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(recs) != 0 || out != "" {
		t.Fatalf("chunked transfer-encoding must be rejected, got %d records (%q)", len(recs), out)
	}
}

// ③ 恰好 64KiB 的**合法** JSONL 行必须被接受（内容 65536B，不含结尾换行）。
func TestBlocker_ValidJSONLAtExactly64KiBAccepted(t *testing.T) {
	if got := len(mkLine(replay.MaxInputLine)); got != replay.MaxInputLine {
		t.Fatalf("fixture construction: content = %d, want %d", got, replay.MaxInputLine)
	}
	recs, _, err := run(t, strings.NewReader(mkLine(replay.MaxInputLine)+"\n"))
	if err != nil {
		t.Fatalf("valid JSONL of exactly %d bytes must be accepted, got %v", replay.MaxInputLine, err)
	}
	if len(recs) != 2 {
		t.Fatalf("want 2 records, got %d", len(recs))
	}
}

// ③' 超过 64KiB 一个字节必须按"行过长"拒绝（区别于"JSON 非法"）。
func TestBlocker_ValidJSONLOver64KiBIsTooLong(t *testing.T) {
	_, _, err := run(t, strings.NewReader(mkLine(replay.MaxInputLine+1)+"\n"))
	if !errors.Is(err, replay.ErrInputTooLong) {
		t.Fatalf("want ErrInputTooLong, got %v", err)
	}
}

// ② short write（n<len, err=nil）必须被检出并返回 io.ErrShortWrite。
func TestBlocker_ShortWriteDetected(t *testing.T) {
	err := replay.Run(fixture(t, "colored_pair.jsonl"), shortWriter{})
	if !errors.Is(err, errShortWriteWant) {
		t.Fatalf("want io.ErrShortWrite, got %v", err)
	}
}

type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }
