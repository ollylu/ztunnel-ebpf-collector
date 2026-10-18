package main

import (
	"testing"
	"time"
)

type blockedDiagnostic struct {
	entered chan struct{}
	release chan struct{}
}

func (w *blockedDiagnostic) Write(p []byte) (int, error) {
	select {
	case w.entered <- struct{}{}:
	default:
	}
	<-w.release
	return len(p), nil
}
func TestDiagnosticsDoNotBlockCaptureOwner(t *testing.T) {
	w := &blockedDiagnostic{make(chan struct{}, 1), make(chan struct{})}
	d := newDiagnosticWriter(w)
	defer d.close()
	defer close(w.release)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 128; i++ {
			_, _ = d.Write([]byte("diagnostic\n"))
		}
	}()
	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("diagnostic blocked capture owner")
	}
}
