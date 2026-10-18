// Package replay 实现 I1-1 的显式 synthetic replay 薄片：读取 JSONL 输入，
// 仅对满足染色契约的 HTTP/1.x 请求-响应对输出两条 JSONL 记录。
//
// 本片边界：
//   - 只做同步短程 replay；常驻采集与有界异步 stdout 背压属于 I2，不在本片。
//   - 输入单行 ≤ MaxInputLine，单条输出 ≤ MaxOutputLine，body ≤ MaxBody。
//   - 只有完整初始请求头中存在单一 x-trace（OWS 后精确等于 "print"）才输出；
//     响应单独带标记不放行。
//   - Pod 元数据在本片一律 unknown，不用 fixture 冒充真实元数据。
package replay

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/textproto"
	"strings"
)

const (
	// SourceKindSyntheticReplay 是本片唯一的输出来源标记；replay 不冒充在线采集。
	SourceKindSyntheticReplay = "synthetic_replay"
	// SchemaVersion 是输出记录的模式版本。
	SchemaVersion = "1"
	// MaxInputLine 是单行输入上限（64KiB）。
	MaxInputLine = 64 * 1024
	// MaxOutputLine covers live retained 1MiB body + 512KiB headers under
	// worst-case JSON escaping. Replay input and replay body limits stay separate.
	MaxOutputLine = 10 * 1024 * 1024
	// MaxBody 是输出保留的 body 上限（4KiB）。
	MaxBody = 4 * 1024
	// maxPathBytes 约束路径等标量字段，保证单条输出不越 MaxOutputLine。
	maxPathBytes = 2048
	// UnknownField 是本片未证实字段的取值。
	UnknownField = "unknown"
)

// 输入错误哨兵：调用方据此区分"输入非法"与"该条不可信解析、跳过"。
var (
	// ErrNotImplemented 保留给尚未实现的路径（本片不再由 replay 返回）。
	ErrNotImplemented = errors.New("replay: not implemented")
	// ErrInputTooLong 表示单行输入超过 MaxInputLine。
	ErrInputTooLong = errors.New("replay: input line too long")
	// ErrInvalidInput 表示 JSONL 行非法。
	ErrInvalidInput = errors.New("replay: invalid input")
	// ErrForeignSourceKind 表示输入声明的来源不是 synthetic_replay。
	ErrForeignSourceKind = errors.New("replay: foreign source_kind")
)

// Pair 是一条 JSONL 输入：两个原始 HTTP/1.x 报文字符串。
// SourceKind 用于显式声明 fixture 来源；非 synthetic_replay 一律拒绝。
type Pair struct {
	SourceKind string `json:"source_kind"`
	Request    string `json:"request"`
	Response   string `json:"response"`
}

type PodIdentity struct {
	IP        string `json:"ip"`
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	UID       string `json:"uid"`
}

// Record 是一条输出记录的对外契约（最少字段集）。
type Record struct {
	ContentDecoding     string              `json:"content_decoding,omitempty"`
	PeerIdentitySource  string              `json:"peer_identity_source,omitempty"`
	ObservationSide     string              `json:"observation_side,omitempty"`
	Client              *PodIdentity        `json:"client,omitempty"`
	Server              *PodIdentity        `json:"server,omitempty"`
	OriginalDestination string              `json:"original_destination,omitempty"`
	SchemaVersion       string              `json:"schema_version"`
	StreamID            uint32              `json:"stream_id,omitempty"`
	BodyEncoding        string              `json:"body_encoding,omitempty"`
	GRPCMessages        []string            `json:"grpc_messages,omitempty"`
	GRPCStatus          *int                `json:"grpc_status,omitempty"`
	SourceKind          string              `json:"source_kind"`
	RequestID           string              `json:"request_id"`
	Direction           string              `json:"direction"`
	Protocol            string              `json:"protocol"`
	Method              string              `json:"method,omitempty"`
	Path                string              `json:"path,omitempty"`
	Status              int                 `json:"status,omitempty"`
	Headers             map[string][]string `json:"headers,omitempty"`
	Trailers            map[string][]string `json:"trailers,omitempty"`
	Body                string              `json:"body"`
	Truncated           bool                `json:"truncated"`
	PodIP               string              `json:"pod_ip"`
	PodName             string              `json:"pod_name"`
	PodNamespace        string              `json:"pod_namespace"`
	PodUID              string              `json:"pod_uid"`
}

// message 是一条已解析的 HTTP/1.x 报文；解析失败时不产出任何记录。
type message struct {
	protocol  string
	method    string
	target    string
	status    int
	headers   map[string][]string // 键为小写字段名
	body      string
	truncated bool
}

// Run 从 in 读取 JSONL 并向 out 写出染色 pair 的两条记录（request 优先）。
// 输入非法立即返回错误；写失败立即透传错误，不做重试。
func Run(in io.Reader, out io.Writer) error {
	return RunWithMarker(in, out, Marker{Header: "X-trace", Value: "print"})
}

// RunWithMarker applies an explicit request-only marker rule.
func RunWithMarker(in io.Reader, out io.Writer, marker Marker) error {
	if err := marker.Validate(); err != nil {
		return err
	}
	sc := bufio.NewScanner(in)
	// 上限取 MaxInputLine+1：Scanner 以 max 判定"超过"即报 ErrTooLong，
	// 故 max=MaxInputLine+1 恰好允许内容长度等于 MaxInputLine 的单行，
	// 而 >MaxInputLine 的行（含不得截断后解析的要求）直接拒收。
	sc.Buffer(make([]byte, 0, 4096), MaxInputLine+1)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var p Pair
		if err := json.Unmarshal(line, &p); err != nil {
			_ = err
			return fmt.Errorf("%w (line %d)", ErrInvalidInput, lineNo)
		}
		if p.SourceKind != "" && p.SourceKind != SourceKindSyntheticReplay {
			return fmt.Errorf("%w (line %d): %q", ErrForeignSourceKind, lineNo, p.SourceKind)
		}
		req, ok := parseMessage(p.Request, true, "")
		if !ok {
			continue // header 无法完整可信解析：不输出
		}
		resp, ok := parseMessage(p.Response, false, req.method)
		if !ok {
			continue
		}
		if !marker.Match(req.headers) {
			continue
		}
		reqID := fmt.Sprintf("replay-%06d", lineNo)
		if err := writeRecord(out, requestRecord(reqID, req)); err != nil {
			return err
		}
		if err := writeRecord(out, responseRecord(reqID, resp)); err != nil {
			return err
		}
	}
	if err := sc.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			return fmt.Errorf("%w (line %d)", ErrInputTooLong, lineNo+1)
		}
		return fmt.Errorf("%w: read error", ErrInvalidInput)
	}
	return nil
}

func requestRecord(id string, m *message) Record {
	path, pathCut := bound(m.target, maxPathBytes)
	return Record{
		SchemaVersion: SchemaVersion, SourceKind: SourceKindSyntheticReplay, RequestID: id,
		Direction: "request", Protocol: m.protocol, Method: m.method, Path: path,
		Headers: m.headers,
		Body:    m.body, Truncated: pathCut || m.truncated,
		PodIP: UnknownField, PodName: UnknownField, PodNamespace: UnknownField, PodUID: UnknownField,
	}
}

func responseRecord(id string, m *message) Record {
	return Record{
		SchemaVersion: SchemaVersion, SourceKind: SourceKindSyntheticReplay, RequestID: id,
		Direction: "response", Protocol: m.protocol, Status: m.status,
		Headers: m.headers,
		Body:    m.body, Truncated: m.truncated,
		PodIP: UnknownField, PodName: UnknownField, PodNamespace: UnknownField, PodUID: UnknownField,
	}
}

// writeRecord 同步写出一条 JSONL；写失败立即返回，不重试。
func writeRecord(out io.Writer, r Record) error {
	b, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("replay: encode record: %w", err)
	}
	if len(b) > MaxOutputLine {
		return fmt.Errorf("replay: record exceeds %d bytes", MaxOutputLine)
	}
	n, err := out.Write(append(b, '\n'))
	if err != nil {
		return err
	}
	if n != len(b)+1 {
		return io.ErrShortWrite
	}
	return nil
}

// bound 截断超长标量/正文并报告是否发生截断。
func bound(s string, max int) (string, bool) {
	if len(s) <= max {
		return s, false
	}
	return s[:max], true
}

// parseMessage 解析一条有限 HTTP/1.x 报文：
//   - 使用标准库 net/http（不手写切分）；
//   - 只接受 HTTP/1.0 与 HTTP/1.1；
//   - 拒绝 Transfer-Encoding（本片只允许 Content-Length 定界）；
//   - 拒绝字段名前导 SP/HTAB（obs-fold 或前导空白）；
//   - 头块之后必须被完整消费（无残余字节），正文读取有界且截断/读错误即拒绝。
func parseMessage(raw string, isRequest bool, requestMethod string) (*message, bool) {
	idx := strings.Index(raw, "\r\n\r\n")
	if idx < 0 {
		return nil, false
	}
	if hasLeadingWhitespaceHeaderLine(raw[:idx]) {
		return nil, false
	}
	br := bufio.NewReader(strings.NewReader(raw))
	m := &message{headers: make(map[string][]string)}
	var body io.Reader
	if isRequest {
		req, err := http.ReadRequest(br)
		if err != nil {
			return nil, false
		}
		defer req.Body.Close()
		if !validProtocol(req.Proto) || len(req.TransferEncoding) > 0 {
			return nil, false
		}
		m.protocol, m.method, m.target = req.Proto, req.Method, req.URL.RequestURI()
		body = req.Body
	} else {
		method := requestMethod
		if method == "" {
			method = http.MethodGet // 兜底：无已解析请求时按 GET 语义
		}
		resp, err := http.ReadResponse(br, &http.Request{Method: method})
		if err != nil {
			return nil, false
		}
		defer resp.Body.Close()
		if !validProtocol(resp.Proto) || len(resp.TransferEncoding) > 0 {
			return nil, false
		}
		m.protocol, m.status = resp.Proto, resp.StatusCode
		body = resp.Body
	}
	limited, err := io.ReadAll(io.LimitReader(body, MaxBody+1))
	if err != nil {
		return nil, false // 正文截断或读错误：不可信，拒绝
	}
	if len(limited) > MaxBody {
		m.truncated = true
		limited = limited[:MaxBody]
		// 排空"已声明"的剩余正文（有界：单行输入 ≤ MaxInputLine，且受 Content-Length 约束）；
		// 排空失败（声明长度与实际不符）同样拒绝，不把未声明字节当正文。
		if _, err := io.Copy(io.Discard, body); err != nil {
			return nil, false
		}
	}
	m.body = string(limited)
	// 定界校验：报文字节必须恰好被消费完（有界 1 字节探测残余）。
	if _, err := br.ReadByte(); !errors.Is(err, io.EOF) {
		return nil, false
	}
	// net/http moves Host out of Header and coalesces duplicate Content-Length.
	// Read the already validated initial block with the standard MIME reader so
	// every field and repeated value survives in the output and marker checks.
	head := textproto.NewReader(bufio.NewReader(strings.NewReader(raw[:idx+4])))
	if _, err := head.ReadLine(); err != nil {
		return nil, false
	}
	fields, err := head.ReadMIMEHeader()
	if err != nil {
		return nil, false
	}
	for k, values := range fields {
		m.headers[strings.ToLower(k)] = values
	}
	return m, true
}

// validProtocol 只允许 HTTP/1.0 与 HTTP/1.1。
func validProtocol(proto string) bool {
	return proto == "HTTP/1.0" || proto == "HTTP/1.1"
}

// hasLeadingWhitespaceHeaderLine 判定头块中是否存在以 SP/HTAB 起头的字段行
// （标准库可能把其当作上一字段的延续，故这里显式拒绝）。
func hasLeadingWhitespaceHeaderLine(head string) bool {
	lines := strings.Split(head, "\r\n")
	for _, l := range lines[1:] {
		if l == "" {
			continue
		}
		if l[0] == ' ' || l[0] == '\t' {
			return true
		}
	}
	return false
}
