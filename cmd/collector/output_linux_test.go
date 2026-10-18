//go:build linux

package main

import (
	"bytes"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Regression for the existing bounded writer reused by the node daemon. A full
// stdout pipe must return an error without waiting for a consumer indefinitely.
func TestSlowStdoutStopsWithinBudget(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	fd := w.Fd()
	before, err := unix.FcntlInt(fd, unix.F_GETFL, 0)
	if err != nil {
		t.Fatal(err)
	}
	out, closeOutput, err := boundedOutput(w)
	if err != nil {
		t.Fatal(err)
	}
	closeOutput = closeOnce(closeOutput)
	defer closeOutput()
	payload := bytes.Repeat([]byte("x"), 16384)
	started := time.Now()
	for i := 0; i < 1024; i++ {
		_, err = out.Write(payload)
		if err != nil {
			break
		}
	}
	if err == nil || time.Since(started) > 3*time.Second {
		t.Fatal("stdout did not stop within budget", err, time.Since(started))
	}
	closeOutput()
	after, err := unix.FcntlInt(fd, unix.F_GETFL, 0)
	if err != nil || after != before {
		t.Fatal("stdout flags not restored", before, after, err)
	}
}
func closeOnce(f func()) func() {
	done := false
	return func() {
		if !done {
			done = true
			f()
		}
	}
}

// Actual full OS pipe, using precisely the production diagnostic worker and
// deadline writer. No pipe reader is started to hide the backpressure.
func TestSlowStderrDoesNotHoldCaptureOwnerOrShutdown(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	out, closeOutput, err := boundedOutput(w)
	if err != nil {
		t.Fatal(err)
	}
	defer closeOutput()
	d := newDiagnosticWriter(out)
	start := time.Now()
	for i := 0; i < 10000; i++ {
		_, _ = d.Write(bytes.Repeat([]byte("x"), 4096))
	}
	if time.Since(start) > time.Second {
		t.Error("producer blocked by stderr")
	}
	start = time.Now()
	d.close()
	if time.Since(start) > 2500*time.Millisecond {
		t.Fatal("diagnostic shutdown exceeded write budget")
	}
}
