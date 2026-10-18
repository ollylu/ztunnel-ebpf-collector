package main

import (
	"strings"
	"testing"
)

func TestReplayConfigurableMarker(t *testing.T) {
	input := `{"request":"GET /chosen HTTP/1.1\r\nHost: demo\r\nX-Debug-Flag: yes\r\n\r\n","response":"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"}` + "\n"
	code, out, errOut := invoke([]string{"replay", "--marker-header", "x-debug-flag", "--marker-value", "yes"}, input)
	if code != 0 || strings.Count(out, "\n") != 2 {
		t.Fatalf("configured marker not honored: code=%d output=%q err=%q", code, out, errOut)
	}
	code, out, _ = invoke([]string{"replay", "--marker-header", "x-debug-flag", "--marker-value", "no"}, input)
	if code != 0 || out != "" {
		t.Fatalf("mismatched marker printed: %d %q", code, out)
	}
}
func TestReplayRejectsInvalidMarker(t *testing.T) {
	for _, header := range []string{"", "X Debug", "X-Debug\r\nInjected", "Content-Length", "Host"} {
		code, out, _ := invoke([]string{"replay", "--marker-header", header, "--marker-value", "yes"}, "")
		if code != exitUsage || out != "" {
			t.Fatalf("accepted invalid header %q: %d", header, code)
		}
	}
}
