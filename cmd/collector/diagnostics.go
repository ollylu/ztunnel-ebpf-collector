package main

import (
	"fmt"
	"io"
	"sync"
	"sync/atomic"
)

// One worker, at most 32 x 4KiB retained. out MUST have bounded Write latency
// (boundedOutput for the production stderr FD). Shutdown discards queued lines.
type diagnosticWriter struct {
	out     io.Writer
	queue   chan []byte
	stop    chan struct{}
	done    chan struct{}
	once    sync.Once
	dropped atomic.Uint64
}

func newDiagnosticWriter(out io.Writer) *diagnosticWriter {
	d := &diagnosticWriter{out: out, queue: make(chan []byte, 32), stop: make(chan struct{}), done: make(chan struct{})}
	go d.run()
	return d
}
func (d *diagnosticWriter) Write(p []byte) (int, error) {
	n := len(p)
	if n > 4096 {
		d.dropped.Add(1)
		return n, nil
	}
	select {
	case <-d.stop:
		return n, nil
	default:
	}
	b := append([]byte(nil), p...)
	select {
	case d.queue <- b:
	default:
		d.dropped.Add(1)
	}
	return n, nil
}
func (d *diagnosticWriter) run() {
	defer close(d.done)
	for {
		select {
		case <-d.stop:
			return
		default:
		}
		select {
		case <-d.stop:
			return
		case b := <-d.queue:
			if _, err := d.out.Write(b); err != nil {
				d.dropped.Add(1)
				continue
			}
			if n := d.dropped.Swap(0); n > 0 {
				_, _ = fmt.Fprintf(d.out, "node_diagnostics_dropped count=%d\n", n)
			}
		}
	}
}
func (d *diagnosticWriter) close() { d.once.Do(func() { close(d.stop) }); <-d.done }
