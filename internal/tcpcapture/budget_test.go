package tcpcapture

import (
	"testing"
	"time"
)

func TestContinuousBudgetSeparatesSmallEventsFromBytePressure(t *testing.T) {
	now := time.Unix(1, 0)
	b := eventBudget{continuous: true}
	for i := 0; i < 16384; i++ {
		if err := b.accept(now, 256); err != nil {
			t.Fatalf("small event %d: %v", i, err)
		}
	}
	if b.accept(now, 256) == nil {
		t.Fatal("event ceiling bypassed")
	}
	if err := b.accept(now.Add(time.Second), 256); err != nil {
		t.Fatal("new window", err)
	}
	b = eventBudget{continuous: true}
	for i := 0; i < 4096; i++ {
		if err := b.accept(now, 16384); err != nil {
			t.Fatal(err)
		}
	}
	if b.accept(now, 1) == nil {
		t.Fatal("64MiB byte ceiling bypassed")
	}
}
func TestContinuousByteBudgetStopsBeforeEventBudget(t *testing.T) {
	b := eventBudget{continuous: true}
	now := time.Unix(1, 0)
	for i := 0; i < 4000; i++ {
		if err := b.accept(now, 16384+128); err != nil {
			t.Fatal(err)
		}
	}
	if b.accept(now, 2*1024*1024) == nil {
		t.Fatal("byte pressure accepted below event ceiling")
	}
}
func TestFiniteEventBudgetDoesNotReset(t *testing.T) {
	b := eventBudget{}
	for i := 0; i < 4096; i++ {
		if e := b.accept(time.Unix(int64(i+1), 0), 1); e != nil {
			t.Fatal(e)
		}
	}
	if b.accept(time.Unix(9000, 0), 1) == nil {
		t.Fatal("finite capture budget reset")
	}
}
