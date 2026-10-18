package main

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"
)

// Explicit cloud-only bounded baseline; normal unit runs skip this entry.
func TestACKBoundedBaseline(t *testing.T) {
	url := os.Getenv("ACK_BASELINE_URL")
	if url == "" {
		t.Skip("ACK baseline not requested")
	}
	if os.Getenv("CLOUD_GUARD") != "true" {
		t.Fatal("cloud guard required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	guard := make(chan error, 1)
	go func() {
		e := cloudGuard(ctx)
		guard <- e
		if e != nil {
			cancel()
		}
	}()
	warm, err := runLoad(ctx, url, 10, 2*time.Second)
	if err != nil || warm.Success != 20 {
		t.Fatal("warmup failed", warm, err)
	}
	start := time.Now()
	st, e := runLoad(ctx, url, 400, 30*time.Second)
	json.NewEncoder(os.Stdout).Encode(map[string]any{"mode": "ack-baseline", "time": time.Now().UTC(), "stats": st, "seconds": time.Since(start).Seconds(), "error": e != nil})
	if e != nil {
		select {
		case g := <-guard:
			t.Log("guard", g)
		default:
		}
		t.Fatal(e)
	}
	if st.Sent != 12000 || st.Success != 12000 || st.Marked != 600 {
		t.Fatal("incomplete baseline", st)
	}
}
