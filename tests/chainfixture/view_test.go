package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestViewKeepsLowLoadAndEndsAfterTwentyMinutes(t *testing.T) {
	var out bytes.Buffer
	calls := 0
	err := runView(context.Background(), "http://chain/api/query", &out, func(_ context.Context, url string, qps int, d time.Duration) (loadStats, error) {
		calls++
		if url != "http://chain/api/query" || qps != 10 || d != 30*time.Second {
			t.Fatalf("unexpected load: %s %d %s", url, qps, d)
		}
		return loadStats{Sent: 300, Success: 300, Marked: 15}, nil
	})
	if err != nil || calls != 40 || strings.Count(out.String(), "\n") != 40 {
		t.Fatalf("view must run exactly forty bounded stages: calls=%d err=%v", calls, err)
	}
}

func TestViewStopsOnProtectionAndOutputFailure(t *testing.T) {
	stop := errors.New("guard stopped")
	calls := 0
	runner := func(context.Context, string, int, time.Duration) (loadStats, error) {
		calls++
		return loadStats{Failed: 1}, stop
	}
	if err := runView(context.Background(), "http://chain", &bytes.Buffer{}, runner); !errors.Is(err, stop) || calls != 1 {
		t.Fatalf("protection did not stop view: calls=%d err=%v", calls, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls = 0
	if err := runView(ctx, "http://chain", &bytes.Buffer{}, runner); !errors.Is(err, context.Canceled) || calls != 0 {
		t.Fatalf("canceled view still generated traffic: calls=%d err=%v", calls, err)
	}
	if err := runView(context.Background(), "http://chain", brokenViewWriter{}, func(context.Context, string, int, time.Duration) (loadStats, error) {
		return loadStats{}, nil
	}); err == nil {
		t.Fatal("view continued without writable health output")
	}
}

type brokenViewWriter struct{}

func (brokenViewWriter) Write([]byte) (int, error) { return 0, errors.New("output closed") }
