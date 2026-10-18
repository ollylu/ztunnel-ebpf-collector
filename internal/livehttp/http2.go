package livehttp

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
	"ztunnel-ebpf-collector/internal/replay"
)

const h2BodyLimit = bodyOutputLimit

var errH2 = errors.New("incomplete, invalid or over-budget HTTP2 connection")

type h2direction struct {
	input, block           []byte
	decoder                *hpack.Decoder
	settings               bool
	pending                uint32
	end                    bool
	dataID                 uint32
	dataRemaining, padding int
	dataEnd, padPending    bool
}
type h2stream struct {
	headers   [2]map[string][]string
	trailers  [2]map[string][]string
	body      [2]bodyPrefix
	grpc      [2]grpcPrefix
	wireBytes [2]int64
	marked    bool
	cut       [2]bool
	ended     [2]bool
	seen      time.Time
}
type h2connection struct {
	dir     [2]h2direction
	streams map[uint32]*h2stream
	last    uint32
	goaway  [2]bool
	ceiling [2]uint32
}

func newH2() *h2connection {
	c := &h2connection{streams: make(map[uint32]*h2stream)}
	for i := range c.dir {
		d := &c.dir[i]
		d.decoder = hpack.NewDecoder(4096, nil)
		d.decoder.SetMaxStringLength(headerParseLimit)
	}
	return c
}

// Both directional HPACK tables include unmarked streams. Selection happens only
// after decoding initial request headers; stream IDs, never timing, join pairs.
func (c *h2connection) push(b []byte, write bool, marker replay.Marker, prefix string) ([]replay.Record, error) {
	side := 1
	if write {
		side = 0
	}
	d := &c.dir[side]
	c.expire(time.Now())
	if len(d.input)+len(b) > headerParseLimit+16384+9 {
		return nil, errH2
	}
	d.input = append(d.input, b...)
	var records []replay.Record
	for {
		if d.dataID != 0 {
			if d.padPending {
				if len(d.input) == 0 {
					break
				}
				d.padding = int(d.input[0])
				d.input = d.input[1:]
				d.dataRemaining--
				d.padPending = false
				if d.padding > d.dataRemaining {
					return nil, errH2
				}
			}
			n := min(len(d.input), d.dataRemaining-d.padding)
			if n > 0 {
				c.acceptData(side, d.dataID, d.input[:n])
				d.input = d.input[n:]
				d.dataRemaining -= n
			}
			if d.dataRemaining == d.padding {
				n = min(len(d.input), d.padding)
				d.input = d.input[n:]
				d.padding -= n
				d.dataRemaining -= n
			}
			if d.dataRemaining > 0 {
				break
			}
			if stream := c.streams[d.dataID]; stream != nil {
				stream.ended[side] = d.dataEnd
				stream.seen = time.Now()
			}
			records = append(records, c.complete(d.dataID, marker, prefix)...)
			d.dataID = 0
			if c.retained() > 32<<20 {
				return nil, errH2
			}
			continue
		}
		if len(d.input) < 9 {
			break
		}
		n := int(d.input[0])<<16 | int(d.input[1])<<8 | int(d.input[2])
		if d.input[3] == 0 {
			id := binary.BigEndian.Uint32(d.input[5:9]) & 0x7fffffff
			if !d.settings || d.pending != 0 || id == 0 {
				return nil, errH2
			}
			flags := d.input[4]
			d.dataID = id
			d.dataRemaining = n
			d.padding = 0
			d.dataEnd = flags&1 != 0
			d.padPending = flags&8 != 0
			if d.padPending && n == 0 {
				return nil, errH2
			}
			d.input = d.input[9:]
			continue
		}
		if n > headerParseLimit {
			return nil, errH2
		}
		if len(d.input) < 9+n {
			break
		}
		fr := http2.NewFramer(nil, bytes.NewReader(d.input[:9+n]))
		// Frame order spans syscall fragments; pending below enforces CONTINUATION ordering.
		fr.AllowIllegalReads = true
		fr.SetMaxReadFrameSize(headerParseLimit)
		f, e := fr.ReadFrame()
		if e != nil {
			return nil, e
		}
		if !d.settings {
			if s, ok := f.(*http2.SettingsFrame); !ok || s.IsAck() {
				return nil, errH2
			}
			d.settings = true
		}
		if d.pending != 0 {
			if _, ok := f.(*http2.ContinuationFrame); !ok {
				return nil, errH2
			}
		}
		switch f := f.(type) {
		case *http2.SettingsFrame:
			if e := f.ForeachSetting(func(s http2.Setting) error {
				if s.ID == http2.SettingHeaderTableSize {
					if s.Val > 16384 {
						return errH2
					}
					c.dir[1-side].decoder.SetAllowedMaxDynamicTableSize(s.Val)
				}
				return nil
			}); e != nil {
				return nil, e
			}
		case *http2.HeadersFrame:
			d.pending = f.StreamID
			d.end = f.StreamEnded()
			d.block = append(d.block, f.HeaderBlockFragment()...)
			if f.HeadersEnded() {
				if e := c.headers(side, marker); e != nil {
					return nil, e
				}
			}
		case *http2.ContinuationFrame:
			if d.pending == 0 || d.pending != f.StreamID {
				return nil, errH2
			}
			if len(d.block)+len(f.HeaderBlockFragment()) > headerParseLimit {
				return nil, errH2
			}
			d.block = append(d.block, f.HeaderBlockFragment()...)
			if f.HeadersEnded() {
				if e := c.headers(side, marker); e != nil {
					return nil, e
				}
			}

		case *http2.RSTStreamFrame:
			delete(c.streams, f.StreamID)
		case *http2.GoAwayFrame:
			if f.ErrCode != http2.ErrCodeNo || (c.goaway[side] && f.LastStreamID > c.ceiling[side]) {
				return nil, errH2
			}
			c.goaway[side], c.ceiling[side] = true, f.LastStreamID
			// Only a server GOAWAY limits client-initiated (odd) streams.
			if side == 1 {
				for id := range c.streams {
					if id > f.LastStreamID {
						delete(c.streams, id)
					}
				}
			}
		case *http2.PushPromiseFrame:
			return nil, errH2
		}
		d.input = d.input[9+n:]
		records = append(records, c.complete(f.Header().StreamID, marker, prefix)...)
		if c.retained() > 32<<20 {
			return nil, errH2
		}
	}
	if len(d.input) == 0 {
		d.input = nil
	}
	return records, nil
}
func (c *h2connection) headers(side int, marker replay.Marker) error {
	d := &c.dir[side]
	if len(d.block) > headerParseLimit {
		return errH2
	}
	headers := map[string][]string{}
	size, count := 0, 0
	valid, regular := true, false
	defer d.decoder.SetEmitFunc(nil) // release the full decoded header map after bounded copies
	d.decoder.SetEmitEnabled(true)
	d.decoder.SetEmitFunc(func(f hpack.HeaderField) {
		size += len(f.Name) + len(f.Value)
		count++
		if size > headerParseLimit || count > 16384 || f.Name == "" || strings.ToLower(f.Name) != f.Name || strings.ContainsAny(f.Value, "\r\n\x00") {
			valid = false
			d.decoder.SetEmitEnabled(false)
			return
		}
		for _, ch := range f.Name {
			if ch <= 32 || ch >= 127 {
				valid = false
			}
		}
		if strings.HasPrefix(f.Name, ":") {
			if regular || len(headers[f.Name]) != 0 {
				valid = false
			}
		} else {
			regular = true
		}
		switch f.Name {
		case "connection", "upgrade", "transfer-encoding", "keep-alive", "proxy-connection":
			valid = false
		case "te":
			if f.Value != "trailers" {
				valid = false
			}
		}
		headers[f.Name] = append(headers[f.Name], f.Value)
	})
	if _, e := d.decoder.Write(d.block); e != nil {
		return e
	}
	if e := d.decoder.Close(); e != nil {
		return e
	}
	if !valid {
		return errH2
	}
	s := c.streams[d.pending]
	if side == 0 && s == nil {
		if d.pending%2 == 0 {
			return errH2
		}
		// A retired stream's late trailers still update HPACK, but cannot reopen it.
		if d.pending > c.last {
			c.last = d.pending
			if len(c.streams) < 64 && (!c.goaway[1] || d.pending <= c.ceiling[1]) {
				s = &h2stream{}
				c.streams[d.pending] = s
			}
		}
	}
	if s != nil {
		if s.ended[side] {
			return errH2
		}
		if s.headers[side] == nil {
			if side == 0 {
				if one(headers, ":method") == "" || len(one(headers, ":method")) > 64 || !strings.HasPrefix(one(headers, ":path"), "/") || len(one(headers, ":path")) > 2048 || one(headers, ":scheme") == "" {
					return errH2
				}
				for k := range headers {
					if strings.HasPrefix(k, ":") && k != ":method" && k != ":scheme" && k != ":authority" && k != ":path" {
						return errH2
					}
				}
			} else {
				code, e := strconv.Atoi(one(headers, ":status"))
				if e != nil || code < 100 || code > 599 {
					return errH2
				}
				for k := range headers {
					if strings.HasPrefix(k, ":") && k != ":status" {
						return errH2
					}
				}
				if code < 200 {
					if d.end || code == 101 {
						return errH2
					}
					d.pending = 0
					d.block = nil
					return nil
				}
			}
			if side == 0 {
				s.marked = marker.Match(headers)
			}
			s.headers[side], s.cut[side] = boundedHeaders(headers, marker.Header)
			s.body[side].selected = s.marked
			s.body[side].compressed = strings.EqualFold(one(headers, "content-encoding"), "gzip")
		} else {
			for k := range headers {
				if strings.HasPrefix(k, ":") {
					return errH2
				}
			}
			if !d.end || s.trailers[side] != nil {
				return errH2
			}
			var cut bool
			s.trailers[side], cut = boundedHeaders(headers)
			s.cut[side] = s.cut[side] || cut
		}
		s.ended[side] = d.end
		s.seen = time.Now()
	}
	d.pending = 0
	d.block = nil
	return nil
}
func one(h map[string][]string, k string) string {
	if len(h[k]) != 1 {
		return ""
	}
	return h[k][0]
}
func h2records(s *h2stream, marker replay.Marker, id string, stream uint32) ([]replay.Record, error) {
	if !s.marked {
		return nil, nil
	}
	for i := 0; i < 2; i++ {
		if vs, ok := s.headers[i]["content-length"]; ok {
			n, e := strconv.Atoi(one(s.headers[i], "content-length"))
			if len(vs) != 1 || e != nil || int64(n) != s.wireBytes[i] {
				return nil, errH2
			}
		}
	}
	status, _ := strconv.Atoi(one(s.headers[1], ":status"))
	rs := []replay.Record{{SchemaVersion: "1", SourceKind: "live_socket", RequestID: id, StreamID: stream, Direction: "request", Protocol: "HTTP/2", Method: one(s.headers[0], ":method"), Path: one(s.headers[0], ":path")}, {SchemaVersion: "1", SourceKind: "live_socket", RequestID: id, StreamID: stream, Direction: "response", Protocol: "HTTP/2", Status: status}}
	for i := range rs {
		rs[i].Headers = s.headers[i]
		rs[i].Trailers = s.trailers[i]
	}
	ct := one(s.headers[0], "content-type")
	if ct == "application/grpc" || strings.HasPrefix(ct, "application/grpc+") {
		if rs[0].Method != "POST" {
			return nil, errH2
		}
		rct := one(s.headers[1], "content-type")
		if rct != "application/grpc" && !strings.HasPrefix(rct, "application/grpc+") {
			return nil, errH2
		}
		values := append(append([]string{}, s.headers[1]["grpc-status"]...), s.trailers[1]["grpc-status"]...)
		if len(values) != 1 {
			return nil, errH2
		}
		gs, e := strconv.Atoi(values[0])
		if e != nil || gs < 0 || gs > 16 {
			return nil, errH2
		}
		for i := range rs {
			rs[i].Protocol = "gRPC"
			if !s.grpc[i].complete() {
				return nil, errH2
			}
			rs[i].GRPCMessages = s.grpc[i].messages
			rs[i].Truncated = s.grpc[i].cut || s.cut[i]
			if one(s.headers[i], "grpc-encoding") == "gzip" {
				rs[i].ContentDecoding = "gzip"
			}
			rs[i].BodyEncoding = "base64"
		}
		rs[1].GRPCStatus = &gs
	} else {
		for i := range rs {
			b, cut, e := s.body[i].output()
			if e != nil {
				return nil, e
			}
			rs[i].Body = base64.StdEncoding.EncodeToString(b)
			rs[i].Truncated = cut || s.cut[i]
			if s.body[i].compressed {
				rs[i].ContentDecoding = "gzip"
			}
			rs[i].BodyEncoding = "base64"
		}
	}
	return rs, nil
}
func grpcMessages(b []byte) ([]string, error) {
	messages := make([]string, 0)
	for len(b) > 0 {
		if len(b) < 5 || b[0] != 0 || len(messages) >= 32 {
			return nil, errH2
		}
		n := uint64(binary.BigEndian.Uint32(b[1:5]))
		if n > uint64(len(b)-5) {
			return nil, errH2
		}
		messages = append(messages, base64.StdEncoding.EncodeToString(b[5:5+int(n)]))
		b = b[5+int(n):]
	}
	return messages, nil
}

// Retirement is stream-local; HPACK and stream high-water marks survive it.
func (c *h2connection) expire(now time.Time) {
	for id, s := range c.streams {
		if now.Sub(s.seen) > 5*time.Second {
			delete(c.streams, id)
		}
	}
}

func (c *h2connection) retained() int {
	n := 0
	for _, d := range c.dir {
		n += cap(d.input) + cap(d.block)
	}
	for _, s := range c.streams {
		for i := 0; i < 2; i++ {
			n += cap(s.body[i].data) + s.grpc[i].retained()
			for k, vs := range s.headers[i] {
				for _, v := range vs {
					n += len(k) + len(v)
				}
			}
			for k, vs := range s.trailers[i] {
				for _, v := range vs {
					n += len(k) + len(v)
				}
			}
		}
	}
	return n
}

func (c *h2connection) acceptData(side int, id uint32, p []byte) {
	s := c.streams[id]
	if s == nil {
		return
	}
	if s.headers[side] == nil || s.ended[side] {
		delete(c.streams, id)
		return
	}
	s.wireBytes[side] += int64(len(p))
	ct := one(s.headers[0], "content-type")
	if ct == "application/grpc" || strings.HasPrefix(ct, "application/grpc+") {
		if err := s.grpc[side].add(p, s.marked, one(s.headers[side], "grpc-encoding")); err != nil {
			delete(c.streams, id)
			return
		}
	} else {
		s.body[side].add(p)
	}
	s.seen = time.Now()
}
func (c *h2connection) complete(id uint32, marker replay.Marker, prefix string) []replay.Record {
	s := c.streams[id]
	if s == nil || !s.ended[0] || !s.ended[1] {
		return nil
	}
	defer delete(c.streams, id)
	rs, err := h2records(s, marker, fmt.Sprintf("%s-%d", prefix, id), id)
	if err != nil {
		return nil
	}
	return rs
}
