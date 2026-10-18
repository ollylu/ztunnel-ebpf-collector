// ACK socket fixture: idle RPC expiry, RST isolation and graceful GOAWAY.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
	"io"
	"net"
	"os"
	"time"
)

type wire struct {
	f   *http2.Framer
	b   bytes.Buffer
	enc *hpack.Encoder
}

func newWire(c net.Conn) *wire {
	w := &wire{f: http2.NewFramer(c, c)}
	w.enc = hpack.NewEncoder(&w.b)
	return w
}
func (w *wire) headers(id uint32, end bool, kv ...string) error {
	w.b.Reset()
	for i := 0; i < len(kv); i += 2 {
		if err := w.enc.WriteField(hpack.HeaderField{Name: kv[i], Value: kv[i+1]}); err != nil {
			return err
		}
	}
	return w.f.WriteHeaders(http2.HeadersFrameParam{StreamID: id, EndStream: end, EndHeaders: true, BlockFragment: w.b.Bytes()})
}
func serveConn(c net.Conn) error {
	defer c.Close()
	c.SetDeadline(time.Now().Add(20 * time.Second))
	p := make([]byte, len(http2.ClientPreface))
	if _, e := io.ReadFull(c, p); e != nil {
		return e
	}
	if string(p) != http2.ClientPreface {
		return fmt.Errorf("bad preface")
	}
	w := newWire(c)
	if e := w.f.WriteSettings(); e != nil {
		return e
	}
	for {
		f, e := w.f.ReadFrame()
		if e != nil {
			return e
		}
		switch x := f.(type) {
		case *http2.SettingsFrame:
			if !x.IsAck() {
				if e = w.f.WriteSettingsAck(); e != nil {
					return e
				}
			}
		case *http2.HeadersFrame:
			id := x.StreamID
			if id == 1 || id == 5 {
				continue
			}
			if id != 3 && id != 7 {
				return fmt.Errorf("unexpected stream")
			}
			if id == 7 {
				if e = w.f.WriteGoAway(7, http2.ErrCodeNo, nil); e != nil {
					return e
				}
			}
			if e = w.headers(id, false, ":status", "200", "content-type", "application/grpc"); e != nil {
				return e
			}
			if e = w.f.WriteData(id, false, []byte{0, 0, 0, 0, 2, 'o', 'k'}); e != nil {
				return e
			}
			if e = w.headers(id, true, "grpc-status", "0"); e != nil {
				return e
			}
		}
	}
}
func request(w *wire, id uint32) error {
	return w.headers(id, true, ":method", "POST", ":scheme", "http", ":authority", "h2fault", ":path", "/test.Fault/Check", "content-type", "application/grpc", "debug-token", "yes", "x-test-id", fmt.Sprintf("i17-stream-%d", id))
}
func client(addr string) error {
	c, e := net.DialTimeout("tcp", addr, 3*time.Second)
	if e != nil {
		return e
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(20 * time.Second))
	if _, e = io.WriteString(c, http2.ClientPreface); e != nil {
		return e
	}
	w := newWire(c)
	if e = w.f.WriteSettings(); e != nil {
		return e
	}
	if e = request(w, 1); e != nil {
		return e
	}
	time.Sleep(6 * time.Second)
	if e = request(w, 3); e != nil {
		return e
	}
	decoder := hpack.NewDecoder(4096, nil)
	replies := map[uint32]bool{}
	goaway := false
	body := map[uint32]string{}
	for len(replies) < 2 {
		f, e := w.f.ReadFrame()
		if e != nil {
			return e
		}
		switch x := f.(type) {
		case *http2.SettingsFrame:
			if !x.IsAck() {
				if e = w.f.WriteSettingsAck(); e != nil {
					return e
				}
			}
		case *http2.GoAwayFrame:
			if x.ErrCode != http2.ErrCodeNo || x.LastStreamID != 7 {
				return fmt.Errorf("bad GOAWAY")
			}
			goaway = true
		case *http2.DataFrame:
			body[x.StreamID] += string(x.Data())
		case *http2.HeadersFrame:
			fs, e := decoder.DecodeFull(x.HeaderBlockFragment())
			if e != nil {
				return e
			}
			if x.StreamEnded() {
				ok := false
				for _, h := range fs {
					if h.Name == "grpc-status" && h.Value == "0" {
						ok = true
					}
				}
				if !ok || body[x.StreamID] != string([]byte{0, 0, 0, 0, 2, 'o', 'k'}) {
					return fmt.Errorf("bad response")
				}
				replies[x.StreamID] = true
				if x.StreamID == 3 {
					if e = request(w, 5); e != nil {
						return e
					}
					if e = w.f.WriteRSTStream(5, http2.ErrCodeCancel); e != nil {
						return e
					}
					if e = request(w, 7); e != nil {
						return e
					}
				}
			}
		}
	}
	if !replies[3] || !replies[7] || !goaway {
		return fmt.Errorf("missing healthy streams or GOAWAY")
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"success": true, "healthy_streams": []int{3, 7}, "idle_stream": 1, "reset_stream": 5, "goaway_last": 7})
}
func main() {
	var e error
	if len(os.Args) == 3 && os.Args[1] == "client" {
		e = client(os.Args[2])
	} else {
		var ln net.Listener
		ln, e = net.Listen("tcp4", ":8080")
		if e == nil {
			for {
				var c net.Conn
				c, e = ln.Accept()
				if e != nil {
					break
				}
				go func() { _ = serveConn(c) }()
			}
		}
	}
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
