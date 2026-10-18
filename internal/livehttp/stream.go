// Package livehttp joins bounded TCP syscall fragments. It deliberately rejects
// pipelining, upgrades, chunked bodies and ambiguous framing in this first slice.
package livehttp

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"golang.org/x/net/http2"
	"io"
	"net/http"
	"net/netip"
	"time"
	"ztunnel-ebpf-collector/internal/replay"
	"ztunnel-ebpf-collector/internal/tcpcapture"
)

type key struct {
	generation    uint64
	outbound      bool
	inode         uint64
	netns         uint32
	local, remote netip.AddrPort
}
type connection struct {
	identity          tcpcapture.Event
	reported          bool
	destination       netip.AddrPort
	request, response []byte
	method            string
	seen              time.Time
	poison            bool
	h2                *h2connection
	h1                *h1pair
	retained          int
}
type Analyzer struct {
	Marker   replay.Marker
	streams  map[key]*connection
	sequence uint64
}

func eventKey(e tcpcapture.Event) key {
	return key{generation: e.Generation, outbound: e.Outbound, inode: e.Inode, netns: e.NetNS, local: netip.AddrPortFrom(e.LocalIP, e.LocalPort), remote: netip.AddrPortFrom(e.RemoteIP, e.RemotePort)}
}
func (a *Analyzer) Push(e tcpcapture.Event) ([]replay.Record, error) {
	defer func() {
		c := a.streams[eventKey(e)]
		if c == nil {
			return
		}
		c.retained = cap(c.request) + cap(c.response)
		if c.h1 != nil {
			c.retained += c.h1.retained()
		}
		if c.h2 != nil {
			c.retained += c.h2.retained()
		}
		total := 0
		for _, other := range a.streams {
			total += other.retained
		}
		if total > 32<<20 {
			c.request = nil
			c.response = nil
			c.h1 = nil
			c.h2 = nil
			c.retained = 0
			c.poison = true
		}
	}()

	e.Write = e.Write != e.Outbound
	rs, err := a.push(e)
	if e.Outbound {
		destination := "unknown"
		if c := a.streams[eventKey(e)]; c != nil && c.destination.IsValid() {
			destination = c.destination.String()
		}
		for i := range rs {
			rs[i].OriginalDestination = destination
		}
	}
	return rs, err
}
func (a *Analyzer) push(e tcpcapture.Event) ([]replay.Record, error) {
	if a.Marker.Validate() != nil {
		return nil, errors.New("invalid marker")
	}
	if a.streams == nil {
		a.streams = make(map[key]*connection)
	}
	k := eventKey(e)
	if e.Closed {
		// TCP teardown can clear the tuple before close; match the socket identity.
		for old := range a.streams {
			if old.inode == e.Inode && old.netns == e.NetNS && old.generation == e.Generation && old.outbound == e.Outbound {
				delete(a.streams, old)
			}
		}
		return nil, nil
	}
	prefix := fmt.Sprintf("live-%d-%d-%s-%s", e.NetNS, e.Inode, k.local, k.remote)
	if e.Outbound {
		prefix += "-outbound"
	}
	c := a.streams[k]
	if c == nil {
		if len(a.streams) >= 64 {
			return nil, errors.New("connection budget exhausted")
		}
		identity := e
		identity.Data = nil
		c = &connection{seen: time.Now(), identity: identity}
		a.streams[k] = c
	}
	if e.Damaged {
		c.poison = true
		c.request = nil
		c.response = nil
		c.h2 = nil
		c.h1 = nil
		return nil, nil
	}
	if e.OriginalDestination.IsValid() {
		if !e.Outbound || (c.destination.IsValid() && c.destination != e.OriginalDestination) {
			c.poison = true
			c.request = nil
			c.response = nil
			c.h2 = nil
			return nil, nil
		}
		c.destination = e.OriginalDestination
		return nil, nil
	}
	if c.poison {
		return nil, nil
	}
	if c.h1 != nil {
		return a.pushH1(c, e.Data, e.Write, prefix)
	}
	if c.h2 != nil {
		c.seen = time.Now()
		rs, err := c.h2.push(e.Data, e.Write, a.Marker, prefix)
		if err != nil {
			c.h2 = nil
			c.poison = true
			return nil, nil
		}
		return rs, nil
	}
	if time.Since(c.seen) > 5*time.Second && (len(c.request) > 0 || len(c.response) > 0) {
		c.poison = true
		c.request = nil
		c.response = nil
		return nil, nil
	}
	if e.Write {
		c.request = append(c.request, e.Data...)
	} else {
		c.response = append(c.response, e.Data...)
	}
	if len(c.request) > 65536 || len(c.response) > 65536 {
		c.poison = true
		c.request = nil
		c.response = nil
		return nil, nil
	}
	if len(c.request) < len(http2.ClientPreface) && bytes.HasPrefix([]byte(http2.ClientPreface), c.request) {
		return nil, nil
	}
	if bytes.HasPrefix(c.request, []byte(http2.ClientPreface)) {
		c.h2 = newH2()
		rs, err := c.h2.push(c.request[len(http2.ClientPreface):], true, a.Marker, prefix)
		if err == nil {
			var next []replay.Record
			next, err = c.h2.push(c.response, false, a.Marker, prefix)
			rs = append(rs, next...)
		}
		c.request = nil
		c.response = nil
		if err != nil {
			c.h2 = nil
			c.poison = true
			return nil, nil
		}
		return rs, nil
	}
	if !possibleRequestMethod(c.request) {
		c.poison = true
		c.request = nil
		c.response = nil
		return nil, nil
	}
	c.h1 = &h1pair{}
	req, resp := c.request, c.response
	c.request = nil
	c.response = nil
	rs, err := a.pushH1(c, req, true, prefix)
	if err == nil && len(resp) > 0 {
		var next []replay.Record
		next, err = a.pushH1(c, resp, false, prefix)
		rs = append(rs, next...)
	}
	return rs, err
}
func (a *Analyzer) pushH1(c *connection, p []byte, write bool, prefix string) ([]replay.Record, error) {
	c.seen = time.Now()
	rs, err := c.h1.push(p, write, a.Marker, fmt.Sprintf("%s-%d", prefix, a.sequence+1))
	if err != nil {
		c.h1 = nil
		c.poison = true
		return nil, nil
	}
	if len(rs) > 0 {
		a.sequence++
	}
	return rs, nil
}

func frame(b []byte, request bool, method string) (int, string, error) {
	at := bytes.Index(b, []byte("\r\n\r\n"))
	if at < 0 {
		return 0, "", nil
	}
	br := bufio.NewReader(bytes.NewReader(b))
	var size int64
	var body io.ReadCloser
	if request {
		r, e := http.ReadRequest(br)
		if e != nil {
			return 0, "", e
		}
		body = r.Body
		method = r.Method
		size = r.ContentLength
		if len(r.TransferEncoding) > 0 || r.Header.Get("Upgrade") != "" {
			return 0, "", errors.New("unsupported framing")
		}
		if size < 0 {
			size = 0
		}
	} else {
		r, e := http.ReadResponse(br, &http.Request{Method: method})
		if e != nil {
			return 0, "", e
		}
		body = r.Body
		size = r.ContentLength
		if len(r.TransferEncoding) > 0 || r.StatusCode < 200 || r.StatusCode == 101 {
			return 0, "", errors.New("unsupported response")
		}
		if method == "HEAD" || r.StatusCode == 204 || r.StatusCode == 304 {
			size = 0
		}
	}
	if body != nil {
		defer body.Close()
	}
	if size < 0 || size > 65536 {
		return 0, "", errors.New("unbounded body")
	}
	n := at + 4 + int(size)
	if n > 65536 {
		return 0, "", errors.New("message too large")
	}
	if len(b) < n {
		return 0, method, nil
	}
	return n, method, nil
}

// Sweep releases incomplete bodies even when no further bytes arrive. A poisoned
// connection stays quarantined until close; its body cannot become a new request.
func (a *Analyzer) Sweep(now time.Time) {
	for _, c := range a.streams {
		expired := now.Sub(c.seen) > 5*time.Second && (len(c.request) > 0 || len(c.response) > 0)
		if c.h2 != nil {
			c.h2.expire(now)
			for _, d := range c.h2.dir {
				if (len(d.input) > 0 || len(d.block) > 0) && now.Sub(c.seen) > 5*time.Second {
					expired = true
				}
			}
		}
		if c.h1 != nil && (c.h1.request.parsed || len(c.h1.request.head) > 0) && now.Sub(c.seen) > 5*time.Second {
			expired = true
		}
		if expired {
			c.h1 = nil
			c.retained = 0
			c.request = nil
			c.response = nil
			c.h2 = nil
			c.poison = true
		}
		c.retained = cap(c.request) + cap(c.response)
		if c.h1 != nil {
			c.retained += c.h1.retained()
		}
		if c.h2 != nil {
			c.retained += c.h2.retained()
		}

	}
}

// Forget removes the old target generation after its kernel admission is revoked.
func (a *Analyzer) Forget(e tcpcapture.Endpoint) {
	for k := range a.streams {
		port := k.remote.Port()
		if k.outbound {
			port = k.local.Port()
		}
		if k.outbound == e.Outbound && k.netns == e.NetNS && netip.AddrPortFrom(k.remote.Addr(), port) == e.Server {
			delete(a.streams, k)
		}
	}
}

// DrainSuppressed reports newly rejected connections once. The caller installs
// a bounded kernel filter; failure must stop capture, never silently resume it.
// Called serially with Push/Sweep/Forget by the capture owner.
func (a *Analyzer) DrainSuppressed() []tcpcapture.Event {
	var result []tcpcapture.Event
	for _, c := range a.streams {
		if c.poison && !c.reported {
			result = append(result, c.identity)
			c.reported = true
		}
	}
	return result
}

// Only reject a definitely invalid HTTP method prefix. Partial methods and the
// HTTP/2 preface remain admissible; no port-based protocol assumption is made.
func possibleRequestMethod(b []byte) bool {
	for i, c := range b {
		if c == ' ' {
			return i > 0
		}
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || bytes.ContainsRune([]byte("!#$%&'*+-.^_`|~"), rune(c)) {
			continue
		}
		return false
	}
	return true
}

// Begin handles proven new socket incarnations, including inode/tuple reuse.
func (a *Analyzer) Begin(e tcpcapture.Event) {
	for k := range a.streams {
		if k.inode == e.Inode && k.netns == e.NetNS && k.generation == e.Generation && k.outbound == e.Outbound {
			delete(a.streams, k)
		}
	}
}
