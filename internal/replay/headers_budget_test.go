package replay_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"ztunnel-ebpf-collector/internal/replay"
)

func TestCompleteLargeHeadersFitBoundedEscapedOutput(t *testing.T) {
	value := strings.Repeat("<", 60*1024)
	req := "GET /headers HTTP/1.1\r\nHost: demo\r\nX-Trace: print\r\nX-Large: " + value + "\r\n\r\n"
	if len(req) >= 65536 {
		t.Fatal("fixture exceeds capture input bound")
	}
	rs := replay.DecodePair(req, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", replay.Marker{Header: "X-Trace", Value: "print"}, "headers")
	if len(rs) != 2 {
		t.Fatal("valid marked pair omitted")
	}
	var out bytes.Buffer
	if err := replay.WriteRecord(&out, rs[0]); err != nil {
		t.Fatal("complete headers must not exceed escaped output bound", err)
	}
	var record struct {
		Headers map[string][]string `json:"headers"`
	}
	if err := json.Unmarshal(out.Bytes(), &record); err != nil || strings.Join(record.Headers["x-large"], "") != value {
		t.Fatal("large header truncated or changed", err)
	}
	if out.Len() > replay.MaxOutputLine+1 {
		t.Fatal("output bound exceeded")
	}
	out.Reset()
	if err := replay.WriteRecord(&out, replay.Record{Body: strings.Repeat("X", replay.MaxOutputLine)}); err == nil || out.Len() != 0 {
		t.Fatal("oversize record must fail before any output")
	}
}
