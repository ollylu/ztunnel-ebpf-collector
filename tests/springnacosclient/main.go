// Bounded ACK functional client. It emits synthetic counters, never traffic storage.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

func validate(b []byte, greeting, id, body string) error {
	var r struct {
		Role, Greeting string
		Downstream     struct {
			Role, Greeting, Echo string
			ID                   string `json:"request_id"`
		}
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return err
	}
	if r.Role != "spring-a" || r.Greeting != greeting || r.Downstream.Role != "spring-b" || r.Downstream.Greeting != greeting || r.Downstream.ID != id || r.Downstream.Echo != body {
		return errors.New("wrong live config, role, request identity or echo")
	}
	return nil
}
func run() error {
	url, greeting, round := os.Getenv("TARGET_URL"), os.Getenv("EXPECTED_GREETING"), os.Getenv("ROUND")
	if url == "" || greeting == "" || round == "" {
		return errors.New("TARGET_URL, EXPECTED_GREETING and ROUND required")
	}
	tr := &http.Transport{MaxConnsPerHost: 1, MaxIdleConnsPerHost: 1}
	defer tr.CloseIdleConnections()
	client := http.Client{Transport: tr, Timeout: 4 * time.Second}
	start := time.Now()
	for i := 1; i <= 200; i++ {
		id := fmt.Sprintf("i20-%s-%d", round, i)
		body := "你好 Spring " + id
		req, err := http.NewRequest("POST", url, strings.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "text/plain; charset=utf-8")
		req.Header.Set("X-Request-ID", id)
		req.Header.Add("X-Demo-Header", "first")
		req.Header.Add("X-Demo-Header", "second")
		if i%20 == 0 {
			req.Header.Set("Debug-Token", "yes")
		}
		r, err := client.Do(req)
		if err != nil {
			return err
		}
		b, err := io.ReadAll(io.LimitReader(r.Body, 65537))
		r.Body.Close()
		if err != nil {
			return err
		}
		if r.StatusCode != 200 || len(b) > 65536 {
			return fmt.Errorf("unexpected HTTP status/size: %d/%d", r.StatusCode, len(b))
		}
		if err = validate(b, greeting, id, body); err != nil {
			return err
		}
		if os.Getenv("CHECK_NACOS") == "true" {
			if err = validateNacosReply(b, greeting); err != nil {
				return err
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"round": round, "sent": 200, "success": 200, "marked": 10, "greeting": greeting, "seconds": time.Since(start).Seconds()})
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func validateNacosReply(b []byte, greeting string) error {
	var r struct {
		Downstream struct {
			Content string `json:"nacos_content"`
		}
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return err
	}
	if r.Downstream.Content != "greeting="+greeting+"\n" {
		return errors.New("missing/stale Nacos reply")
	}
	return nil
}
