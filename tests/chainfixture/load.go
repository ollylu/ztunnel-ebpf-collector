package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type loadStats struct {
	Scheduled, Sent, Marked, Success, Failed, Skipped int64
	P95Millis, P99Millis                              int
}

func runLoad(parent context.Context, url string, qps int, d time.Duration) (loadStats, error) {
	if qps < 1 || qps > 1000 || d <= 0 || d > time.Minute {
		return loadStats{}, errors.New("load exceeds bounded configuration")
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	tr := &http.Transport{MaxIdleConns: 8, MaxIdleConnsPerHost: 8, MaxConnsPerHost: 8, IdleConnTimeout: time.Minute}
	defer tr.CloseIdleConnections()
	client := http.Client{Transport: tr, Timeout: 2 * time.Second}
	var mu sync.Mutex
	var st loadStats
	var hist [2001]int64
	var wg sync.WaitGroup
	jobs := make(chan int64, 16)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for seq := range jobs {
				if ctx.Err() != nil {
					return
				}
				started := time.Now()
				req, _ := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader("{}"))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("X-Request-Id", fmt.Sprintf("zc-%d", seq))
				marked := seq%20 == 0
				if marked {
					req.Header.Set("Debug-Token", "yes")
				}
				r, e := client.Do(req)
				good := false
				if e == nil {
					var body struct {
						Mysql int `json:"mysql"`
					}
					e = json.NewDecoder(io.LimitReader(r.Body, 2048)).Decode(&body)
					r.Body.Close()
					good = e == nil && r.StatusCode == 200 && body.Mysql == 1
				}
				ms := min(int(time.Since(started).Milliseconds()), 2000)
				mu.Lock()
				st.Sent++
				if marked {
					st.Marked++
				}
				if good {
					st.Success++
				} else {
					st.Failed++
				}
				hist[ms]++
				trip := st.Sent >= 50 && st.Failed*100 > st.Sent
				mu.Unlock()
				if trip {
					cancel()
				}
			}
		}()
	}
	started := time.Now()
	total := int64(float64(qps) * d.Seconds())
loop:
	for seq := int64(1); seq <= total; seq++ {
		deadline := started.Add(time.Duration(seq) * time.Second / time.Duration(qps))
		timer := time.NewTimer(time.Until(deadline))
		select {
		case <-ctx.Done():
			timer.Stop()
			break loop
		case <-timer.C:
		}
		mu.Lock()
		st.Scheduled++
		mu.Unlock()
		select {
		case jobs <- seq:
		default:
			mu.Lock()
			st.Skipped++
			skipTrip := st.Skipped*100 > st.Scheduled
			mu.Unlock()
			if skipTrip {
				cancel()
				break loop
			}
		}
	}
	close(jobs)
	wg.Wait()
	for percentile, out := range map[int]*int{95: &st.P95Millis, 99: &st.P99Millis} {
		target := (st.Sent*int64(percentile) + 99) / 100
		var n int64
		for i, c := range hist {
			n += c
			if n >= target {
				*out = i
				break
			}
		}
	}
	if st.Failed > 0 || st.Skipped > 0 || ctx.Err() != nil {
		return st, errors.New("load stopped: errors, scheduling saturation, cancellation or health protection")
	}
	return st, nil
}
func load() error {
	url := os.Getenv("TARGET_URL")
	if url == "" {
		return errors.New("TARGET_URL required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()
	if os.Getenv("CLOUD_GUARD") == "true" {
		go func() {
			if err := cloudGuard(ctx); err != nil {
				fmt.Fprintln(os.Stderr, err)
				cancel()
			}
		}()
	}
	for _, qps := range []int{10, 50, 100, 200, 400, 600, 800, 1000} {
		started := time.Now()
		st, err := runLoad(ctx, url, qps, 30*time.Second)
		json.NewEncoder(os.Stdout).Encode(map[string]any{"target_qps": qps, "duration_seconds": time.Since(started).Seconds(), "stats": st, "protected": err != nil})
		if err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Second):
		}
	}
	return nil
}
