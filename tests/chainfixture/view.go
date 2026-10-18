package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

// Forty low-load stages keep the live demonstration bounded to twenty minutes.
func runView(ctx context.Context, url string, out io.Writer, run func(context.Context, string, int, time.Duration) (loadStats, error)) error {
	for i := 0; i < 40; i++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		st, err := run(ctx, url, 10, 30*time.Second)
		if writeErr := json.NewEncoder(out).Encode(map[string]any{"mode": "view", "time": time.Now().UTC(), "target_qps": 10, "stats": st, "protected": err != nil}); writeErr != nil {
			return writeErr
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func view() error {
	url := os.Getenv("TARGET_URL")
	if url == "" || os.Getenv("SENSOR_NAMESPACE") == "" {
		return errors.New("view requires TARGET_URL and SENSOR_NAMESPACE for cloud protection")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute+5*time.Second)
	defer cancel()
	go func() {
		if err := cloudGuard(ctx); err != nil {
			fmt.Fprintln(os.Stderr, err)
			cancel()
		}
	}()
	return runView(ctx, url, os.Stdout, runLoad)
}
