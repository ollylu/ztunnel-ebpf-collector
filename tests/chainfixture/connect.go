package main

import (
	"context"
	"io"
	"net"
	"time"
)

func probeConnection(ctx context.Context, address string) error {
	c, e := (&net.Dialer{}).DialContext(ctx, "tcp", address)
	if e != nil {
		return e
	}
	defer c.Close()
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(100 * time.Millisecond)
	}
	if e = c.SetDeadline(deadline); e != nil {
		return e
	}
	// Ambient can accept the local TCP socket before connecting the target.
	// Only terminal I/O establishes failure; a successful Dial is insufficient.
	if _, e = io.WriteString(c, "GET /i12-unreachable HTTP/1.1\r\nHost: fixture\r\nConnection: close\r\n\r\n"); e != nil {
		return e
	}
	var b [1]byte
	_, e = c.Read(b[:])
	return e
}
