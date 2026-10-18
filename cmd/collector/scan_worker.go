package main

import "context"

type scanResult struct {
	generation uint64
	targets    []captureTarget
	err        error
}
type scanWork struct {
	generation uint64
	run        func(context.Context) ([]captureTarget, error)
}
type scanWorker struct {
	work    chan scanWork
	results chan scanResult
	cancel  context.CancelFunc
	done    chan struct{}
}

// One worker and one result slot; no overlapping /proc scans or callback mutation.
func newScanWorker(parent context.Context) *scanWorker {
	ctx, cancel := context.WithCancel(parent)
	w := &scanWorker{make(chan scanWork), make(chan scanResult, 1), cancel, make(chan struct{})}
	go func() {
		defer close(w.done)
		for {
			select {
			case <-ctx.Done():
				return
			case job := <-w.work:
				targets, err := job.run(ctx)
				select {
				case w.results <- scanResult{job.generation, targets, err}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return w
}
func (w *scanWorker) submit(job scanWork) bool {
	select {
	case w.work <- job:
		return true
	default:
		return false
	}
}
func (w *scanWorker) poll(generation uint64) (scanResult, bool) {
	select {
	case r := <-w.results:
		return r, r.generation == generation
	default:
		return scanResult{}, false
	}
}
func (w *scanWorker) close() { w.cancel(); <-w.done }
