package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const maintenancePath = "/tmp/zc-soak-maintenance"

type mixedStats struct {
	Scheduled, Sent, Marked, Success, Expected, Unexpected, MaintenanceErrors, Skipped int64
	MaintenanceSkipped                                                                 int64
	P95Millis, P99Millis                                                               int
	Cases                                                                              map[string]int64
}

func soakFault(seq, seed uint64) string {
	z := seq + seed + 0x9e3779b97f4a7c15
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb
	z ^= z >> 31
	switch z % 100 {
	case 0:
		return "http-timeout"
	case 1:
		return "grpc-timeout"
	case 2:
		return "grpc-unavailable"
	case 3:
		return "connect-fail"
	}
	return ""
}
func runMixed(parent context.Context, url string, qps int, d time.Duration, first, seed uint64, maintenance *atomic.Int64) (mixedStats, error) {
	st := mixedStats{Cases: map[string]int64{}}
	if qps < 1 || qps > 1000 || d <= 0 || d > time.Minute {
		return st, errors.New("mixed load bounds")
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	tr := &http.Transport{MaxConnsPerHost: 16, MaxIdleConns: 16, MaxIdleConnsPerHost: 16, IdleConnTimeout: time.Minute, DialContext: (&net.Dialer{Timeout: time.Second}).DialContext}
	defer tr.CloseIdleConnections()
	client := http.Client{Transport: tr, Timeout: 2 * time.Second}
	var mu sync.Mutex
	var wg sync.WaitGroup
	var hist [2001]int64
	jobs := make(chan uint64, 32)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for seq := range jobs {
				if ctx.Err() != nil {
					return
				}
				started := time.Now()
				fault := soakFault(seq, seed)
				jobCtx := ctx
				jobCancel := func() {}
				if fault == "http-timeout" {
					jobCtx, jobCancel = context.WithTimeout(ctx, 150*time.Millisecond)
				}
				req, e := http.NewRequestWithContext(jobCtx, "POST", url, strings.NewReader("{}"))
				if e != nil {
					jobCancel()
					cancel()
					return
				}
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("X-Request-Id", fmt.Sprintf("soak-%d-%d", seed, seq))
				if fault != "" {
					req.Header.Set("X-Test-Fault", fault)
				}
				marked := seq%20 == 0
				if marked {
					req.Header.Set("Debug-Token", "yes")
				}
				planned := maintenance != nil && started.UnixNano() < maintenance.Load()
				r, e := client.Do(req)
				good, expected := false, false
				if e == nil {
					if fault == "" {
						var body struct {
							Mysql int `json:"mysql"`
						}
						readErr := json.NewDecoder(io.LimitReader(r.Body, 2048)).Decode(&body)
						good = readErr == nil && r.StatusCode == 200 && body.Mysql == 1
					} else {
						_, readErr := io.Copy(io.Discard, io.LimitReader(r.Body, 2048))
						expected = readErr == nil && r.Header.Get("X-Test-Outcome") == fault && ((fault == "grpc-timeout" && r.StatusCode == 504) || ((fault == "grpc-unavailable" || fault == "connect-fail") && r.StatusCode == 502))
					}
					r.Body.Close()
				} else if fault == "http-timeout" {
					expected = errors.Is(jobCtx.Err(), context.DeadlineExceeded)
				}
				jobCancel()
				ms := min(int(time.Since(started).Milliseconds()), 2000)
				mu.Lock()
				st.Sent++
				if marked {
					st.Marked++
				}
				label := fault
				if label == "" {
					label = "normal"
				}
				st.Cases[label]++
				if good {
					st.Success++
				} else if expected {
					st.Expected++
				} else if planned {
					st.MaintenanceErrors++
				} else {
					st.Unexpected++
				}
				hist[ms]++
				trip := st.Sent >= 100 && st.Unexpected >= 3 && st.Unexpected*100 > st.Sent
				mu.Unlock()
				if trip {
					cancel()
				}
			}
		}()
	}
	started := time.Now()
	total := uint64(float64(qps) * d.Seconds())
loop:
	for i := uint64(1); i <= total; i++ {
		deadline := started.Add(time.Duration(i) * time.Second / time.Duration(qps))
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
		case jobs <- first + i:
		default:
			mu.Lock()
			if maintenance != nil && time.Now().UnixNano() < maintenance.Load() {
				st.MaintenanceSkipped++
			} else {
				st.Skipped++
			}
			trip := st.Skipped*100 > st.Scheduled
			mu.Unlock()
			if trip {
				cancel()
				break loop
			}
		}
	}
	close(jobs)
	wg.Wait()
	for p, out := range map[int]*int{95: &st.P95Millis, 99: &st.P99Millis} {
		target := (st.Sent*int64(p) + 99) / 100
		var n int64
		for i, v := range hist {
			n += v
			if n >= target {
				*out = i
				break
			}
		}
	}
	if ctx.Err() != nil || st.Skipped*100 > max(int64(100), st.Scheduled) || st.Unexpected*100 > max(int64(100), st.Sent) {
		return st, errors.New("mixed load incomplete: unexpected errors, skipped load or protection")
	}
	return st, nil
}
func setMaintenance(v string) error {
	d, e := time.ParseDuration(v)
	if e != nil || d <= 0 || d > 45*time.Second {
		return errors.New("maintenance must be 0..45 seconds")
	}
	return os.WriteFile(maintenancePath, []byte(strconv.FormatInt(time.Now().Add(d).UnixNano(), 10)), 0600)
}
func soakSchedule(value string) (int, []int, error) {
	qps := 1000
	if value != "" {
		n, err := strconv.Atoi(value)
		if err != nil || n < 1 || n > 1000 {
			return 0, nil, errors.New("SOAK_QPS must be 1..1000")
		}
		qps = n
	}
	var ramp []int
	for _, n := range []int{10, 50, 100, 200, 400, 600, 800} {
		if n < qps {
			ramp = append(ramp, n)
		}
	}
	return qps, ramp, nil
}
func soak() error {
	holdQPS, ramp, err := soakSchedule(os.Getenv("SOAK_QPS"))
	if err != nil {
		return err
	}
	if os.Getenv("CLOUD_GUARD") != "true" || os.Getenv("TARGET_URL") == "" {
		return errors.New("soak requires cloud guard and target")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Minute)
	defer cancel()
	guardDone := make(chan error, 1)
	go func() {
		e := cloudGuard(ctx)
		guardDone <- e
		if e != nil {
			cancel()
		}
	}()
	var maintenance atomic.Int64
	go func() {
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				b, e := os.ReadFile(maintenancePath)
				if e == nil && len(b) < 32 {
					n, e := strconv.ParseInt(string(b), 10, 64)
					if e == nil {
						maintenance.Store(n)
					}
				}
			}
		}
	}()
	seed := uint64(time.Now().Unix())
	var first uint64
	run := func(qps int, phase string, window int) error {
		start := time.Now()
		st, e := runMixed(ctx, os.Getenv("TARGET_URL"), qps, 30*time.Second, first, seed, &maintenance)
		first += uint64(st.Scheduled)
		json.NewEncoder(os.Stdout).Encode(map[string]any{"time": time.Now().UTC().Format(time.RFC3339Nano), "phase": phase, "window": window, "target_qps": qps, "actual_qps": float64(st.Sent) / time.Since(start).Seconds(), "duration_seconds": time.Since(start).Seconds(), "seed": seed, "first_sequence": first - uint64(st.Scheduled) + 1, "stats": st, "protected": e != nil})
		if e != nil {
			select {
			case g := <-guardDone:
				if g != nil {
					fmt.Fprintln(os.Stderr, g)
				}
			default:
			}
			return e
		}
		return nil
	}
	for i, q := range ramp {
		if e := run(q, "ramp", i); e != nil {
			return e
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
	for i := 0; i < 80; i++ {
		if e := run(holdQPS, "hold", i); e != nil {
			return e
		}
	}
	return nil
}
