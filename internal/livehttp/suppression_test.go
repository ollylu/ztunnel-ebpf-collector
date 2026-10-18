package livehttp

import (
	"testing"
	"time"
	"ztunnel-ebpf-collector/internal/replay"
	"ztunnel-ebpf-collector/internal/tcpcapture"
)

// Missing early rejection would keep copying binary/RESP traffic until timeout.
func TestRejectImpossibleRequestPrefix(t *testing.T) {
	for _, data := range []string{"\x16\x03\x03", "*2\r\n$3\r\nGET\r\n", "PING\r\n"} {
		a := Analyzer{Marker: replay.Marker{Header: "Debug-Token", Value: "yes"}}
		e := tcpcapture.Event{Inode: 1, NetNS: 2, Write: true, Data: []byte(data)}
		rs, err := a.Push(e)
		if err != nil || len(rs) != 0 || !a.streams[eventKey(e)].poison {
			t.Fatalf("unsupported prefix retained: %q records=%v err=%v", data, rs, err)
		}
	}
}

// Feedback must contain identities only, exactly once, including timer rejection.
func TestSuppressionFeedbackAndLifecycle(t *testing.T) {
	a := Analyzer{Marker: replay.Marker{Header: "Debug-Token", Value: "yes"}}
	feedback, ok := any(&a).(interface{ DrainSuppressed() []tcpcapture.Event })
	if !ok {
		t.Fatal("analyzer cannot tell kernel to suppress rejected connections")
	}
	e := tcpcapture.Event{Inode: 2, NetNS: 3, Generation: 7, Write: true, Data: []byte("bad\r\n\r\n")}
	a.Push(e)
	es := feedback.DrainSuppressed()
	if len(es) != 1 || es[0].Inode != 2 || es[0].Generation != 7 || len(es[0].Data) != 0 {
		t.Fatal("missing identity or retained payload", es)
	}
	if len(feedback.DrainSuppressed()) != 0 {
		t.Fatal("repeated feedback")
	}
	e.Closed = true
	a.Push(e)
	e.Closed = false
	e.Data = []byte("G")
	a.Push(e)
	if len(feedback.DrainSuppressed()) != 0 {
		t.Fatal("partial valid request prematurely rejected")
	}
	a.Sweep(time.Now().Add(6 * time.Second))
	if len(feedback.DrainSuppressed()) != 1 {
		t.Fatal("timeout not sent to kernel")
	}
	a.Forget(e.Target())
	if len(feedback.DrainSuppressed()) != 0 || len(a.streams) != 0 {
		t.Fatal("revoked state retained")
	}
}

func TestUnmarkedKeepAliveAndFragmentedHTTPAreNotSuppressed(t *testing.T) {
	a := Analyzer{Marker: replay.Marker{Header: "Debug-Token", Value: "yes"}}
	e := tcpcapture.Event{Inode: 22, NetNS: 3, Generation: 1, Write: true}
	for _, marked := range []bool{false, true} {
		req := "GET /later HTTP/1.1\r\nHost: demo\r\n"
		if marked {
			req += "Debug-Token: yes\r\n"
		}
		req += "\r\n"
		e.Write = true
		for _, c := range []byte(req) {
			e.Data = []byte{c}
			if rs, err := a.Push(e); err != nil || len(rs) != 0 {
				t.Fatal(rs, err)
			}
		}
		e.Write = false
		e.Data = []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
		rs, err := a.Push(e)
		want := 0
		if marked {
			want = 2
		}
		if err != nil || len(rs) != want || len(a.DrainSuppressed()) != 0 {
			t.Fatal("valid or unmarked connection rejected", rs, err)
		}
	}
}

func TestCloseClearedTupleReleasesRejectedState(t *testing.T) {
	a := Analyzer{Marker: replay.Marker{Header: "Debug-Token", Value: "yes"}}
	e := tcpcapture.Event{Inode: 3, Generation: 4, NetNS: 5, LocalPort: 40000, RemotePort: 8080, Write: true, Data: []byte("PING\r\n")}
	a.Push(e)
	e.Closed = true
	e.Data = nil
	e.LocalPort = 0
	if _, err := a.Push(e); err != nil || len(a.streams) != 0 {
		t.Fatal("closed rejected socket still uses budget", err)
	}
}
