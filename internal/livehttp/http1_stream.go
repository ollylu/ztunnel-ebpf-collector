package livehttp

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"net/http"
	"net/textproto"
	"sort"
	"strconv"
	"strings"

	"ztunnel-ebpf-collector/internal/replay"
)

// Cap decoded content, independently of wire framing. One extra byte is read
// during gzip decoding to distinguish an exact fit from a truncated prefix.
const bodyOutputLimit = 5 << 10
const headerOutputLimit = 512 << 10
const compressedInputLimit = 5_000_000
const headerParseLimit = 8 << 20

// Prefix retention is independent of framing. Unretained bytes are still drained.
type bodyPrefix struct {
	data       []byte
	total      int64
	compressed bool
	selected   bool
}

func (b *bodyPrefix) add(p []byte) {
	b.total += int64(len(p))
	if !b.selected {
		return
	}
	limit := bodyOutputLimit
	if b.compressed {
		limit = compressedInputLimit
	}
	n := min(len(p), limit-len(b.data))
	if n > 0 {
		b.data = append(b.data, p[:n]...)
	}
}
func (b *bodyPrefix) output() ([]byte, bool, error) {
	if !b.compressed {
		return b.data, b.total > int64(len(b.data)), nil
	}
	r, e := gzip.NewReader(bytes.NewReader(b.data))
	if e != nil {
		return nil, false, e
	}
	defer r.Close()
	out, e := io.ReadAll(io.LimitReader(r, bodyOutputLimit+1))
	if e != nil {
		return nil, false, e
	}
	cut := len(out) > bodyOutputLimit
	// A truncated compressed input may yield a valid bounded prefix; it cannot
	// claim a complete message. The wire framing is independently fully consumed.
	if b.total > int64(len(b.data)) && !cut {
		return nil, false, io.ErrUnexpectedEOF
	}
	return out[:min(len(out), bodyOutputLimit)], cut, nil
}
func boundedHeaders(h map[string][]string, priority ...string) (map[string][]string, bool) {
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		rank := func(k string) int {
			for _, p := range priority {
				if strings.EqualFold(k, p) {
					return 0
				}
			}
			if strings.HasPrefix(k, ":") || k == "content-length" || k == "content-type" || k == "grpc-status" || k == "grpc-encoding" || k == "content-encoding" {
				return 0
			}
			return 1
		}
		a, b := rank(keys[i]), rank(keys[j])
		if a != b {
			return a < b
		}
		return keys[i] < keys[j]
	})
	out := map[string][]string{}
	left := headerOutputLimit
	cut := false
	for _, k := range keys {
		for _, v := range h[k] {
			if len(k) >= left {
				cut = true
				continue
			}
			n := min(len(v), left-len(k))
			out[k] = append(out[k], strings.Clone(v[:n]))
			left -= len(k) + n
			if n < len(v) {
				cut = true
			}
		}
	}
	return out, cut
}

type h1message struct {
	head                      []byte
	record                    replay.Record
	body                      bodyPrefix
	parsed, done, cut, marked bool
	remaining                 int64
	chunked                   bool
	chunkState                int // 0=size, 1=data, 2=CRLF, 3=trailers
	line                      []byte
}
type h1pair struct{ request, response h1message }

func (h *h1message) push(p []byte, request bool, method string, marker replay.Marker, selected bool) error {
	if h.done && len(p) > 0 {
		return errors.New("HTTP pipelining unsupported")
	}
	if !h.parsed {
		// Search across event boundaries without buffering a body past its header.
		h.head = append(h.head, p...)
		at := bytes.Index(h.head, []byte("\r\n\r\n"))
		if at < 0 {
			if len(h.head) > headerParseLimit {
				return errors.New("header parse budget")
			}
			return nil
		}
		if at > headerParseLimit {
			return errors.New("header parse budget")
		}
		raw := h.head[:at+4]
		p = h.head[at+4:]
		for _, line := range bytes.Split(raw, []byte("\r\n"))[1:] {
			if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
				return errors.New("ambiguous folded header")
			}
		}
		br := bufio.NewReader(bytes.NewReader(raw))
		var proto string
		var transfer []string
		if request {
			r, e := http.ReadRequest(br)
			if e != nil {
				return e
			}
			proto = r.Proto
			h.record.Method = r.Method
			h.record.Path = r.URL.RequestURI()
			h.remaining = r.ContentLength
			transfer = r.TransferEncoding
			if r.Header.Get("Upgrade") != "" {
				return errors.New("upgrade unsupported")
			}
			if h.remaining < 0 {
				h.remaining = 0
			}
		} else {
			r, e := http.ReadResponse(br, &http.Request{Method: method})
			if e != nil {
				return e
			}
			proto = r.Proto
			h.record.Status = r.StatusCode
			h.remaining = r.ContentLength
			transfer = r.TransferEncoding
			if r.StatusCode < 200 {
				return errors.New("interim response unsupported")
			}
			if method == "HEAD" || r.StatusCode == 204 || r.StatusCode == 304 {
				h.remaining = 0
				transfer = nil
			}
		}
		if proto != "HTTP/1.1" && proto != "HTTP/1.0" {
			return errors.New("unsupported HTTP version")
		}
		hr := textproto.NewReader(bufio.NewReader(bytes.NewReader(raw)))
		_, _ = hr.ReadLine()
		fields, e := hr.ReadMIMEHeader()
		if e != nil {
			return e
		}
		full := map[string][]string{}
		for k, v := range fields {
			full[strings.ToLower(k)] = v
		}
		h.marked = selected
		if request {
			h.marked = marker.Match(full)
		}
		h.record.Headers, h.cut = boundedHeaders(full, marker.Header)
		h.record.Protocol = proto
		h.body.selected = h.marked
		if values := full["content-encoding"]; len(values) == 1 && strings.EqualFold(values[0], "gzip") {
			h.body.compressed = true
		}
		if len(transfer) > 0 {
			if len(transfer) != 1 || transfer[0] != "chunked" {
				return errors.New("unsupported transfer encoding")
			}
			h.chunked = true
		}
		if !h.chunked && h.remaining < 0 {
			return errors.New("close-delimited response unsupported")
		}
		h.parsed = true
	}
	if h.chunked {
		if e := h.chunks(p); e != nil {
			return e
		}
	} else {
		if int64(len(p)) > h.remaining {
			return errors.New("HTTP pipelining or length mismatch")
		}
		h.body.add(p)
		h.remaining -= int64(len(p))
		h.done = h.remaining == 0
	}
	h.head = nil
	return nil
}
func (h *h1message) chunks(p []byte) error {
	for len(p) > 0 {
		if h.done {
			return errors.New("bytes after chunk terminator")
		}
		if h.chunkState == 1 {
			n := int64(len(p))
			if n > h.remaining {
				n = h.remaining
			}
			h.body.add(p[:int(n)])
			p = p[int(n):]
			h.remaining -= n
			if h.remaining == 0 {
				h.chunkState = 2
			}
			continue
		}
		h.line = append(h.line, p[0])
		p = p[1:]
		if len(h.line) > 8192 {
			return errors.New("chunk line budget")
		}
		if !bytes.HasSuffix(h.line, []byte("\r\n")) {
			continue
		}
		line := string(h.line[:len(h.line)-2])
		h.line = nil
		switch h.chunkState {
		case 0:
			raw, _, _ := strings.Cut(line, ";")
			n, e := strconv.ParseUint(raw, 16, 63)
			if e != nil || raw == "" {
				return errors.New("invalid chunk size")
			}
			h.remaining = int64(n)
			h.chunkState = 1
			if n == 0 {
				h.chunkState = 3
			}
		case 2:
			if line != "" {
				return errors.New("missing chunk CRLF")
			}
			h.chunkState = 0
		case 3:
			if line == "" {
				h.done = true
			} else {
				if strings.HasPrefix(line, " ") || !strings.Contains(line, ":") {
					return errors.New("invalid trailer")
				}
			}
		}
	}
	return nil
}
func (h *h1pair) push(p []byte, write bool, marker replay.Marker, id string) ([]replay.Record, error) {
	var err error
	if write {
		err = h.request.push(p, true, "", marker, false)
	} else {
		if !h.request.parsed {
			return nil, errors.New("response before request headers")
		}
		err = h.response.push(p, false, h.request.record.Method, marker, h.request.marked)
	}
	if err != nil {
		return nil, err
	}
	if !h.request.done || !h.response.done {
		return nil, nil
	}
	defer func() { *h = h1pair{} }()
	if !h.request.marked {
		return nil, nil
	}
	rs := make([]replay.Record, 2)
	for i, m := range []*h1message{&h.request, &h.response} {
		body, cut, e := m.body.output()
		if e != nil {
			return nil, nil
		} // invalid representation; framing is still synchronized.
		r := m.record
		r.SchemaVersion = "1"
		r.SourceKind = "live_socket"
		r.RequestID = id
		r.Direction = []string{"request", "response"}[i]
		r.Body = string(body)
		r.Truncated = cut || m.cut
		if m.body.compressed {
			r.ContentDecoding = "gzip"
		}
		r.PodIP, r.PodName, r.PodNamespace, r.PodUID = "unknown", "unknown", "unknown", "unknown"
		rs[i] = r
	}
	return rs, nil
}
func (h *h1pair) retained() int {
	n := 0
	for _, m := range []*h1message{&h.request, &h.response} {
		n += cap(m.head) + cap(m.body.data) + cap(m.line)
		for k, vs := range m.record.Headers {
			for _, v := range vs {
				n += len(k) + len(v)
			}
		}
	}
	return n
}
