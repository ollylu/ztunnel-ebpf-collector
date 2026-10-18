package tcpcapture

import (
	"errors"
	"time"
)

// Owned by Run; finite capture retains a total-event budget.
type eventBudget struct {
	continuous    bool
	window        time.Time
	events, bytes int
}

func (b *eventBudget) accept(now time.Time, size int) error {
	if b.window.IsZero() || (b.continuous && now.Sub(b.window) >= time.Second) {
		b.window = now
		b.events = 0
		b.bytes = 0
	}
	b.events++
	b.bytes += size
	limit := 4096
	if b.continuous {
		limit = 16384
	}
	if b.events > limit {
		return errors.New("event budget exhausted")
	}
	if b.continuous && b.bytes > 64*1024*1024 {
		return errors.New("event byte budget exhausted")
	}
	return nil
}
