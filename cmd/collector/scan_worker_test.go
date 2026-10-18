package main

import (
	"context"
	"testing"
	"time"
)

func TestScanWorkerFencesOldGenerationAndCancels(t *testing.T) {
	w := newScanWorker(context.Background())
	defer w.close()
	entered, release := make(chan struct{}), make(chan struct{})
	job := scanWork{1, func(ctx context.Context) ([]captureTarget, error) {
		close(entered)
		select {
		case <-release:
		case <-ctx.Done():
		}
		return nil, nil
	}}
	deadline := time.Now().Add(time.Second)
	for !w.submit(job) {
		if time.Now().After(deadline) {
			t.Fatal("worker unavailable")
		}
		time.Sleep(time.Millisecond)
	}
	<-entered
	if w.submit(scanWork{}) {
		t.Fatal("overlapping scan admitted")
	}
	close(release)
	for len(w.results) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("no scan result")
		}
		time.Sleep(time.Millisecond)
	}
	if _, ok := w.poll(2); ok {
		t.Fatal("old Pod generation re-admitted")
	}
}
