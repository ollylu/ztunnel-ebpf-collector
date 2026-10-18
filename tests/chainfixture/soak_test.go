package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
)

func TestSoakFaultsAreIndependentOfColor(t *testing.T) {
	kinds := map[string]int{}
	markedFaults := 0
	for seq := uint64(1); seq <= 20000; seq++ {
		f := soakFault(seq, 17)
		kinds[f]++
		if f != "" && seq%20 == 0 {
			markedFaults++
		}
	}
	for _, f := range []string{"http-timeout", "grpc-timeout", "grpc-unavailable", "connect-fail"} {
		if kinds[f] < 100 || kinds[f] > 350 {
			t.Fatalf("missing/unbounded fault %s: %v", f, kinds)
		}
	}
	if markedFaults < 20 || markedFaults > 80 {
		t.Fatal("fault/color selection coupled", markedFaults)
	}
}
func TestSoakCountsExpectedFaultsAndExactColor(t *testing.T) {
	var marked atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Debug-Token") == "yes" {
			marked.Add(1)
		}
		f := r.Header.Get("X-Test-Fault")
		w.Header().Set("X-Test-Outcome", f)
		switch f {
		case "http-timeout":
			time.Sleep(250 * time.Millisecond)
			return
		case "grpc-timeout":
			w.WriteHeader(504)
		case "grpc-unavailable", "connect-fail":
			w.WriteHeader(502)
		default:
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"mysql":1}`))
		}
	}))
	defer server.Close()
	st, e := runMixed(context.Background(), server.URL, 40, time.Second, 0, 17, nil)
	if e != nil || st.Sent != 40 || st.Marked != 2 || marked.Load() != 2 || st.Unexpected != 0 || st.Success+st.Expected != 40 {
		t.Fatal(st, e, marked.Load())
	}
}

func TestMaintenanceSchedulingLossIsExplicitAndBounded(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.Write([]byte(`{"mysql":1}`))
	}))
	defer s.Close()
	var maintenance atomic.Int64
	maintenance.Store(time.Now().Add(5 * time.Second).UnixNano())
	st, e := runMixed(context.Background(), s.URL, 1000, 200*time.Millisecond, 0, 17, &maintenance)
	if e != nil || st.Scheduled != 200 || st.Sent >= 200 || st.Skipped != 0 || st.MaintenanceSkipped == 0 {
		t.Fatal("planned restart backpressure must remain visible without ending soak", st, e)
	}
}

// Invalid load settings must fail before attempting cluster API access.
func TestSoakRejectsInvalidQPSBeforeCloudAccess(t *testing.T) {
	t.Setenv("SOAK_QPS", "1001")
	t.Setenv("CLOUD_GUARD", "false")
	if err := soak(); err == nil || err.Error() != "SOAK_QPS must be 1..1000" {
		t.Fatalf("expected bounded QPS validation, got %v", err)
	}
}

func TestSoakScheduleRespectsRequestedCeiling(t *testing.T) {
	for _, tc := range []struct {
		value string
		hold  int
		ramp  []int
	}{
		{"500", 500, []int{10, 50, 100, 200, 400}},
		{"", 1000, []int{10, 50, 100, 200, 400, 600, 800}},
		{"1", 1, nil},
	} {
		hold, ramp, err := soakSchedule(tc.value)
		if err != nil || hold != tc.hold || !reflect.DeepEqual(ramp, tc.ramp) {
			t.Fatalf("%q: %d %v %v", tc.value, hold, ramp, err)
		}
	}
	for _, value := range []string{"0", "-1", "1001", "500x"} {
		if _, _, err := soakSchedule(value); err == nil {
			t.Fatalf("accepted %q", value)
		}
	}
}
