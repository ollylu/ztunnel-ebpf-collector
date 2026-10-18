package replay_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ztunnel-ebpf-collector/internal/replay"
)

// fixture 读取 testdata 下的 synthetic replay 输入（均为 source_kind=synthetic_replay，
// 唯一例外 wrong_source_kind.jsonl 用于验证外来来源被拒）。
func fixture(t *testing.T, name string) io.Reader {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return bytes.NewReader(b)
}

func decode(t *testing.T, buf *bytes.Buffer) []replay.Record {
	t.Helper()
	var recs []replay.Record
	for _, line := range strings.Split(strings.TrimRight(buf.String(), "\n"), "\n") {
		if line == "" {
			continue
		}
		var r replay.Record
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("output line is not valid JSON: %v (%q)", err, line)
		}
		recs = append(recs, r)
	}
	return recs
}

func run(t *testing.T, in io.Reader) ([]replay.Record, string, error) {
	t.Helper()
	var out bytes.Buffer
	err := replay.Run(in, &out)
	return decode(t, &out), out.String(), err
}

// 命中染色时，同一 pair 必须输出两条记录（request/response），共享 request_id。
func TestColoredPairEmitsRequestAndResponseRecords(t *testing.T) {
	recs, _, err := run(t, fixture(t, "colored_pair.jsonl"))
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if len(recs) != 2 {
		t.Fatalf("want 2 records (request+response), got %d", len(recs))
	}
	req, resp := recs[0], recs[1]
	if req.Direction != "request" || resp.Direction != "response" {
		t.Errorf("directions = %q/%q, want request/response", req.Direction, resp.Direction)
	}
	if req.RequestID == "" || req.RequestID != resp.RequestID {
		t.Errorf("request_id must be non-empty and shared: %q vs %q", req.RequestID, resp.RequestID)
	}
	if req.SchemaVersion != "1" || resp.SchemaVersion != "1" {
		t.Errorf("schema_version = %q/%q, want 1", req.SchemaVersion, resp.SchemaVersion)
	}
	if req.SourceKind != replay.SourceKindSyntheticReplay || resp.SourceKind != replay.SourceKindSyntheticReplay {
		t.Errorf("source_kind = %q/%q, want %q", req.SourceKind, resp.SourceKind, replay.SourceKindSyntheticReplay)
	}
	if req.Method != "POST" || req.Path != "/demo" {
		t.Errorf("request method/path = %q/%q, want POST//demo", req.Method, req.Path)
	}
	if resp.Status != 200 {
		t.Errorf("response status = %d, want 200", resp.Status)
	}
	if req.Body != "hello-world" || resp.Body != "resp-body" {
		t.Errorf("bodies = %q/%q, want hello-world/resp-body", req.Body, resp.Body)
	}
	// 本片未证实 Pod 元数据：一律 unknown，不得用 fixture 冒充。
	for _, r := range recs {
		for name, got := range map[string]string{
			"pod_ip": r.PodIP, "pod_name": r.PodName, "pod_namespace": r.PodNamespace, "pod_uid": r.PodUID,
		} {
			if got != replay.UnknownField {
				t.Errorf("%s = %q, want %q", name, got, replay.UnknownField)
			}
		}
	}
}

// 未染色（无 x-trace）不得输出。
func TestUncoloredPairEmitsNothing(t *testing.T) {
	recs, out, err := run(t, fixture(t, "uncolored_pair.jsonl"))
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if len(recs) != 0 || out != "" {
		t.Fatalf("want no output, got %d records (%q)", len(recs), out)
	}
}

// 重复 x-trace 视为冲突，不得输出。
func TestDuplicateMarkerEmitsNothing(t *testing.T) {
	recs, _, err := run(t, fixture(t, "duplicate_marker.jsonl"))
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if len(recs) != 0 {
		t.Fatalf("want no output for duplicate marker, got %d records", len(recs))
	}
}

// 响应单独带标记不能放行。
func TestResponseOnlyMarkerEmitsNothing(t *testing.T) {
	recs, _, err := run(t, fixture(t, "response_only_marker.jsonl"))
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if len(recs) != 0 {
		t.Fatalf("want no output when only the response carries the marker, got %d records", len(recs))
	}
}

// 标记值必须 OWS 后精确等于 print（大小写敏感）。
func TestMarkerValueMustBeExactPrint(t *testing.T) {
	recs, _, err := run(t, fixture(t, "not_print_value.jsonl"))
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if len(recs) != 0 {
		t.Fatalf("want no output for x-trace: Print, got %d records", len(recs))
	}
}

// 字段名大小写不敏感，值允许 OWS。
func TestMarkerNameCaseInsensitiveAndOWS(t *testing.T) {
	recs, _, err := run(t, fixture(t, "ows_colored.jsonl"))
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if len(recs) != 2 {
		t.Fatalf("want 2 records for X-Trace with OWS, got %d", len(recs))
	}
}

// 合法但超限的 body 必须截断并标记 truncated。
func TestOverlongBodyIsTruncatedToMaxBody(t *testing.T) {
	recs, _, err := run(t, fixture(t, "truncated_body.jsonl"))
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if len(recs) != 2 {
		t.Fatalf("want 2 records, got %d", len(recs))
	}
	for _, r := range recs {
		if !r.Truncated {
			t.Errorf("direction %s: truncated = false, want true", r.Direction)
		}
		if len(r.Body) != replay.MaxBody {
			t.Errorf("direction %s: body length = %d, want %d", r.Direction, len(r.Body), replay.MaxBody)
		}
	}
}

// header 无法完整可信解析时不输出。
func TestUnparseableHTTPIsSkippedWithoutOutput(t *testing.T) {
	recs, _, err := run(t, fixture(t, "bad_http.jsonl"))
	if err != nil {
		t.Fatalf("Run returned error for unparseable HTTP: %v", err)
	}
	if len(recs) != 0 {
		t.Fatalf("want no output for unparseable header, got %d records", len(recs))
	}
}

// 输入声明为在线采集来源时必须拒绝，禁止 replay 冒充采集。
func TestForeignSourceKindIsRejected(t *testing.T) {
	_, _, err := run(t, fixture(t, "wrong_source_kind.jsonl"))
	if !errors.Is(err, replay.ErrForeignSourceKind) {
		t.Fatalf("want ErrForeignSourceKind, got %v", err)
	}
}

// User explicitly requires complete headers, including credentials on marked pairs.
func TestCompleteHeadersAreEchoedOnlyForMarkedPairs(t *testing.T) {
	_, out, err := run(t, fixture(t, "secrets.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var records []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		var r map[string]any
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatal(err)
		}
		records = append(records, r)
	}
	if len(records) != 2 {
		t.Fatalf("missing marked pair: %s", out)
	}
	h, _ := records[0]["headers"].(map[string]any)
	if h == nil || h["authorization"] == nil || h["cookie"] == nil {
		t.Fatalf("marked request headers omitted: %s", out)
	}
	h, _ = records[1]["headers"].(map[string]any)
	if h == nil || h["set-cookie"] == nil {
		t.Fatalf("response headers omitted: %s", out)
	}
}

func TestHTTP1HeaderValuesHostAndDuplicatesPreserved(t *testing.T) {
	req := "POST /all HTTP/1.1\r\nHost: demo:8080\r\nX-Trace: print\r\nAuthorization: Bearer test-only\r\nX-Multi: one\r\nX-Multi: two\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n"
	rs := replay.DecodePair(req, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", replay.Marker{Header: "X-Trace", Value: "print"}, "headers")
	if len(rs) != 2 {
		t.Fatal("missing pair")
	}
	var out bytes.Buffer
	if err := replay.WriteRecord(&out, rs[0]); err != nil {
		t.Fatal(err)
	}
	var m struct {
		Headers map[string][]string `json:"headers"`
	}
	if err := json.Unmarshal(out.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	if strings.Join(m.Headers["x-multi"], ",") != "one,two" || strings.Join(m.Headers["content-length"], ",") != "0,0" || strings.Join(m.Headers["host"], ",") != "demo:8080" || strings.Join(m.Headers["authorization"], ",") != "Bearer test-only" {
		t.Fatalf("headers incomplete: %s", out.String())
	}
	plain := strings.Replace(req, "X-Trace: print\r\n", "", 1)
	if got := replay.DecodePair(plain, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", replay.Marker{Header: "X-Trace", Value: "print"}, "plain"); len(got) != 0 {
		t.Fatal("unmarked headers leaked")
	}
}

// Complete headers must still fit the explicit output budget.
func TestEveryOutputLineWithinMaxOutputLine(t *testing.T) {
	_, out, err := run(t, fixture(t, "truncated_body.jsonl"))
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	for _, line := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
		if len(line) > replay.MaxOutputLine {
			t.Errorf("output line length %d exceeds %d", len(line), replay.MaxOutputLine)
		}
	}
}

// 单行输入超过 64KiB 属于输入错误。
func TestOverlongInputLineIsRejected(t *testing.T) {
	pad := strings.Repeat("a", replay.MaxInputLine)
	line := `{"source_kind":"synthetic_replay","request":"GET / HTTP/1.1\r\nX-Pad: ` + pad + `\r\nX-Trace: print\r\n\r\n","response":"HTTP/1.1 200 OK\r\n\r\n"}`
	_, _, err := run(t, strings.NewReader(line+"\n"))
	if !errors.Is(err, replay.ErrInputTooLong) {
		t.Fatalf("want ErrInputTooLong, got %v", err)
	}
}

// 写失败必须立即返回错误，不做无界重试（本片同步短程语义）。
func TestWriterFailureReturnsErrorImmediately(t *testing.T) {
	err := replay.Run(fixture(t, "colored_pair.jsonl"), errWriter{})
	if !errors.Is(err, errWriteRefused) {
		t.Fatalf("want the writer error to surface immediately, got %v", err)
	}
}

// 空输入不得报错、不得输出。
func TestEmptyInputProducesNoOutputNoError(t *testing.T) {
	recs, out, err := run(t, strings.NewReader(""))
	if err != nil {
		t.Fatalf("Run returned error for empty input: %v", err)
	}
	if len(recs) != 0 || out != "" {
		t.Fatalf("want no output for empty input, got %d records (%q)", len(recs), out)
	}
}

var errWriteRefused = errors.New("writer refused")

type errWriter struct{}

func (errWriter) Write(p []byte) (int, error) { return 0, errWriteRefused }

// mkLine 构造一条内容长度（不含结尾换行）精确为 n 字节的 JSONL 行。
func mkLine(n int) string {
	pre := `{"source_kind":"synthetic_replay","request":"GET / HTTP/1.1\r\nX-Pad: `
	post := `\r\nX-Trace: print\r\n\r\n","response":"HTTP/1.1 200 OK\r\n\r\n"}`
	return pre + strings.Repeat("a", n-len(pre)-len(post)) + post
}

// 精确等于 64KiB 的单行输入必须被接受（PL 精确化：只有 >64KiB 才拒收）。
func TestInputLineAtExactlyMaxIsAccepted(t *testing.T) {
	recs, _, err := run(t, strings.NewReader(mkLine(replay.MaxInputLine)+"\n"))
	if err != nil {
		t.Fatalf("exactly %d-byte line must be accepted, got %v", replay.MaxInputLine, err)
	}
	if len(recs) != 2 {
		t.Fatalf("want 2 records for an exactly-max line, got %d", len(recs))
	}
}

// 超过 64KiB 一个字节就必须拒收，且不得截断后解析（无任何记录）。
func TestInputLineOneByteOverMaxIsRejected(t *testing.T) {
	recs, out, err := run(t, strings.NewReader(mkLine(replay.MaxInputLine+1)+"\n"))
	if !errors.Is(err, replay.ErrInputTooLong) {
		t.Fatalf("want ErrInputTooLong for %d-byte line, got %v", replay.MaxInputLine+1, err)
	}
	if len(recs) != 0 || out != "" {
		t.Fatalf("over-long line must not be parsed or emitted, got %d records (%q)", len(recs), out)
	}
}
