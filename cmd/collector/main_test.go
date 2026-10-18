package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

func invoke(args []string, stdin string) (int, string, string) {
	var out, errBuf bytes.Buffer
	code := Main(args, strings.NewReader(stdin), &out, &errBuf)
	return code, out.String(), errBuf.String()
}

// version 必须暴露构建 revision/版本/来源模式，且工作树构建不得标为已发布。
func TestVersionReportsWorktreeSourceMode(t *testing.T) {
	code, out, errOut := invoke([]string{"version"}, "")
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr=%q)", code, errOut)
	}
	for _, needle := range []string{"revision=", "version=dev", "source_mode=worktree"} {
		if !strings.Contains(out, needle) {
			t.Errorf("version output missing %q: %q", needle, out)
		}
	}
	if strings.Contains(strings.ToLower(out), "released") {
		t.Errorf("worktree build must not be marked released: %q", out)
	}
}

// replay --input 只输出染色 pair 的两条 JSONL。
func TestReplayFromInputFile(t *testing.T) {
	code, out, errOut := invoke([]string{"replay", "--input", filepath.Join("..", "..", "internal", "replay", "testdata", "colored_pair.jsonl")}, "")
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr=%q)", code, errOut)
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 output lines, got %d: %q", len(lines), out)
	}
	if !strings.Contains(out, `"source_kind":"synthetic_replay"`) {
		t.Errorf("output must be marked synthetic_replay: %q", out)
	}
}

// replay 默认从 stdin 读取。
func TestReplayFromStdin(t *testing.T) {
	raw := `{"source_kind":"synthetic_replay","request":"GET /x HTTP/1.1\r\nx-trace: print\r\n\r\n","response":"HTTP/1.1 204 No Content\r\n\r\n"}` + "\n"
	code, out, errOut := invoke([]string{"replay"}, raw)
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr=%q)", code, errOut)
	}
	if got := strings.Count(out, "\n"); got != 2 {
		t.Fatalf("want 2 output lines, got %d: %q", got, out)
	}
}

// 输入错误必须非零退出，且 stderr 不得包含原始输入。
func TestReplayMalformedJSONLExitsNonZeroWithoutEchoingInput(t *testing.T) {
	raw := "{this-is-not-json}\n"
	code, out, errOut := invoke([]string{"replay"}, raw)
	if code == 0 {
		t.Fatalf("exit = 0, want non-zero for malformed input")
	}
	if out != "" {
		t.Errorf("stdout must stay empty on input error: %q", out)
	}
	for _, needle := range []string{"this-is-not-json", raw} {
		if strings.Contains(errOut, needle) {
			t.Errorf("stderr echoed raw input %q: %q", needle, errOut)
		}
	}
	if lower := strings.ToLower(errOut); !strings.Contains(lower, "invalid") && !strings.Contains(lower, "malformed") {
		t.Errorf("stderr must state the input is invalid: %q", errOut)
	}
}

// 外来来源标记必须被拒（replay 不冒充采集）。
func TestReplayRejectsForeignSourceKind(t *testing.T) {
	code, out, errOut := invoke([]string{"replay", "--input", filepath.Join("..", "..", "internal", "replay", "testdata", "wrong_source_kind.jsonl")}, "")
	if code == 0 {
		t.Fatalf("exit = 0, want non-zero for foreign source_kind")
	}
	if out != "" {
		t.Errorf("stdout must stay empty, got %q", out)
	}
	if !strings.Contains(strings.ToLower(errOut), "source_kind") {
		t.Errorf("stderr must name the rejected source_kind: %q", errOut)
	}
}

// capture 未实现必须明确失败，不得用 replay 冒充成功。
func TestCaptureUnsupportedFailsExplicitly(t *testing.T) {
	code, out, errOut := invoke([]string{"capture"}, "")
	if code == 0 {
		t.Fatal("capture must not exit 0 in this slice")
	}
	if out != "" {
		t.Errorf("capture must not print collector output: %q", out)
	}
	lower := strings.ToLower(errOut)
	if !strings.Contains(lower, "capture") {
		t.Errorf("stderr must name the capture subcommand: %q", errOut)
	}
	if !strings.Contains(lower, "unsupported") && !strings.Contains(lower, "not implemented") {
		t.Errorf("stderr must state capture is unsupported: %q", errOut)
	}
}

// 未知子命令必须失败。
func TestUnknownSubcommandFails(t *testing.T) {
	code, _, errOut := invoke([]string{"frobnicate"}, "")
	if code == 0 {
		t.Fatal("unknown subcommand must exit non-zero")
	}
	if !strings.Contains(errOut, "frobnicate") {
		t.Errorf("stderr must name the unknown subcommand: %q", errOut)
	}
}
