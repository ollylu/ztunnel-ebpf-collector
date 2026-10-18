package asmprobe

import (
	"context"
	"encoding/binary"
	"errors"
	"testing"
	"time"
)

func TestEventABIIsExactly32Bytes(t *testing.T) {
	if EventSize != 32 {
		t.Fatalf("EventSize=%d, want 32", EventSize)
	}
	var e Event
	if got := int(unsafeSizeof(e)); got != EventSize {
		t.Fatalf("struct size=%d, want %d", got, EventSize)
	}
}

func TestParseEventRejectsWrongLength(t *testing.T) {
	for _, n := range []int{0, 31, 33} {
		if _, err := ParseEvent(make([]byte, n)); !errors.Is(err, ErrShortEvent) {
			t.Errorf("len=%d: want ErrShortEvent, got %v", n, err)
		}
	}
}

func TestParseEventFieldOffsets(t *testing.T) {
	b := make([]byte, EventSize)
	binary.LittleEndian.PutUint32(b[0:4], 111)
	binary.LittleEndian.PutUint32(b[4:8], 222)
	binary.LittleEndian.PutUint64(b[8:16], 333)
	binary.LittleEndian.PutUint64(b[16:24], 444)
	e, err := ParseEvent(b)
	if err != nil {
		t.Fatal(err)
	}
	if e.Tid != 111 || e.Pid != 222 || e.Ktime != 333 || e.Nonce != 444 {
		t.Fatalf("offsets wrong: %+v", e)
	}
}

func TestConfigBounds(t *testing.T) {
	ok := Config{TID: 123, Nonce: 1, MaxEvents: MaxEvents, Duration: MaxDuration, SamplePeriod: DefaultSamplePeriod, CPUBudget: MaxCPUBudget}
	if err := ok.Validate(); err != nil {
		t.Fatalf("in-bounds config rejected: %v", err)
	}
	bad := []Config{
		{TID: 0, Nonce: 1, MaxEvents: 1, Duration: time.Second, SamplePeriod: DefaultSamplePeriod, CPUBudget: MaxCPUBudget},
		{TID: -1, Nonce: 1, MaxEvents: 1, Duration: time.Second, SamplePeriod: DefaultSamplePeriod, CPUBudget: MaxCPUBudget},
		{TID: 1, Nonce: 0, MaxEvents: 1, Duration: time.Second, SamplePeriod: DefaultSamplePeriod, CPUBudget: MaxCPUBudget},
		{TID: 1, Nonce: 1, MaxEvents: 0, Duration: time.Second, SamplePeriod: DefaultSamplePeriod, CPUBudget: MaxCPUBudget},
		{TID: 1, Nonce: 1, MaxEvents: MaxEvents + 1, Duration: time.Second, SamplePeriod: DefaultSamplePeriod, CPUBudget: MaxCPUBudget},
		{TID: 1, Nonce: 1, MaxEvents: 1, Duration: 0, SamplePeriod: DefaultSamplePeriod, CPUBudget: MaxCPUBudget},
		{TID: 1, Nonce: 1, MaxEvents: 1, Duration: MaxDuration + time.Second, SamplePeriod: DefaultSamplePeriod, CPUBudget: MaxCPUBudget},
		{TID: 1, Nonce: 1, MaxEvents: 1, Duration: time.Second, SamplePeriod: time.Millisecond, CPUBudget: MaxCPUBudget},
		{TID: 1, Nonce: 1, MaxEvents: 1, Duration: time.Second, SamplePeriod: DefaultSamplePeriod, CPUBudget: MaxCPUBudget + time.Second},
		{TID: 1, Nonce: 1, MaxEvents: 1, Duration: time.Second, SamplePeriod: DefaultSamplePeriod, CPUBudget: 0},
	}
	for i, c := range bad {
		if err := c.Validate(); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("bad[%d]: want ErrInvalidConfig, got %v", i, err)
		}
	}
}

func TestSoftwareCPUClockSpecBounds(t *testing.T) {
	sp := SoftwareCPUClockSpec(4242, DefaultSamplePeriod)
	if sp.Type != PerfTypeSoftware || sp.Config != PerfCountSwCPUClock {
		t.Errorf("type/config = %d/%d, want software/CPU_CLOCK", sp.Type, sp.Config)
	}
	if sp.SamplePeriod != DefaultSamplePeriod {
		t.Errorf("sample period=%s, want %s", sp.SamplePeriod, DefaultSamplePeriod)
	}
	if sp.PID != 4242 || sp.CPU != -1 {
		t.Errorf("pid/cpu = %d/%d, want 4242/-1 (explicit TID, no CPU pinning)", sp.PID, sp.CPU)
	}
	if !sp.Disabled || sp.Inherit || !sp.CLOEXEC {
		t.Errorf("must be disabled, non-inheriting, CLOEXEC: %+v", sp)
	}
	if got := SoftwareCPUClockSpec(1, time.Millisecond).SamplePeriod; got != DefaultSamplePeriod {
		t.Errorf("sample period below conservative minimum must be raised, got %s", got)
	}
}

func TestOwnerClosesInReverseOrderAndAggregates(t *testing.T) {
	o := &Owner{}
	var order []string
	o.Acquire(&fakeRes{name: "program", order: &order})
	o.Acquire(&fakeRes{name: "ring", order: &order})
	o.Acquire(&fakeRes{name: "perf", order: &order, err: errors.New("perf close failed")})
	err := o.CloseAll()
	if err == nil {
		t.Fatal("expected aggregated close error")
	}
	want := []string{"perf", "ring", "program"}
	for i := range want {
		if i >= len(order) || order[i] != want[i] {
			t.Fatalf("close order=%v, want %v", order, want)
		}
	}
	if err := o.CloseAll(); err != nil {
		t.Fatalf("second CloseAll must be a no-op, got %v", err)
	}
}

func TestPrecheckSeparatesEnvironmentFromBehavior(t *testing.T) {
	env := fakeEnv{swOK: true, paranoid: 4, release: "6.8.0-test"}
	pc := PrecheckEnv(env, 4)
	if !pc.Ready || !pc.SwClockOK {
		t.Fatalf("ready env must pass precheck: %+v", pc)
	}
	pc = PrecheckEnv(fakeEnv{swOK: true, paranoid: 5, release: "6.8.0-test"}, 4)
	if pc.Ready || pc.Reason == "" {
		t.Fatalf("paranoid>max must be not-ready with a reason: %+v", pc)
	}
	pc = PrecheckEnv(fakeEnv{err: errors.New("no perf interface")}, 4)
	if pc.Ready || pc.Reason == "" {
		t.Fatalf("missing tracepoint must be not-ready with a reason: %+v", pc)
	}
}

func TestStubYieldsNoEventsAndRunValidates(t *testing.T) {
	cfg := Config{TID: 1, Nonce: 1, MaxEvents: 1, Duration: time.Second, SamplePeriod: DefaultSamplePeriod, CPUBudget: MaxCPUBudget}
	ev, err := Run(context.Background(), cfg, StubCollector{})
	if err != nil || len(ev) != 0 {
		t.Fatalf("stub must yield 0 events and no error, got %d/%v", len(ev), err)
	}
	if _, err := Run(context.Background(), Config{}, StubCollector{}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("invalid config must be rejected, got %v", err)
	}
	if _, err := Run(context.Background(), cfg, nil); !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("nil collector must report not-implemented, got %v", err)
	}
}

type fakeRes struct {
	name  string
	order *[]string
	err   error
}

func (f *fakeRes) Name() string { return f.name }
func (f *fakeRes) Close() error {
	*f.order = append(*f.order, f.name)
	return f.err
}

type fakeEnv struct {
	swOK     bool
	paranoid int
	release  string
	err      error
}

func (f fakeEnv) PerfEventParanoid() (int, error) {
	if f.err != nil {
		return 0, f.err
	}
	return f.paranoid, nil
}
func (f fakeEnv) SwCPUClockAvailable() (bool, error) {
	if f.err != nil {
		return false, f.err
	}
	return f.swOK, nil
}
func (f fakeEnv) KernelRelease() (string, error) { return f.release, nil }
