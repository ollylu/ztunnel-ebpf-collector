// Bounded real TCP traffic for rejection tests. No capture events are fabricated.
package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	if len(os.Args) > 1 && os.Args[1] == "idle" {
		time.Sleep(5 * time.Minute)
		return nil
	}
	if len(os.Args) > 2 && os.Args[1] == "client" {
		c, err := net.DialTimeout("tcp4", os.Args[2], 3*time.Second)
		if err != nil {
			return err
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(80 * time.Second))
		echo := func(s string) error {
			if _, err := io.WriteString(c, s); err != nil {
				return err
			}
			b := make([]byte, len(s))
			if _, err := io.ReadFull(c, b); err != nil {
				return err
			}
			if string(b) != s {
				return fmt.Errorf("echo mismatch")
			}
			return nil
		}
		if err := echo("PING\r\n"); err != nil {
			return err
		}
		time.Sleep(2 * time.Second) // allow parser feedback before deliberately large I/O
		for i := 0; i < 80; i++ {
			if err := echo(strings.Repeat("u", 8192)); err != nil {
				return err
			}
			time.Sleep(750 * time.Millisecond)
		}
		fmt.Println("unknown protocol: 655360 payload bytes echoed successfully after prefix")
		return nil
	}
	l, err := net.Listen("tcp4", ":9099")
	if err != nil {
		return err
	}
	defer l.Close()
	l.(*net.TCPListener).SetDeadline(time.Now().Add(3 * time.Minute))
	c, err := l.Accept()
	if err != nil {
		return err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(90 * time.Second))
	_, err = io.Copy(c, c)
	if err != nil {
		return err
	}
	if err := c.Close(); err != nil {
		return err
	}
	// Keep Pod alive for post-close filter inspection; test deletes its namespace.
	time.Sleep(time.Minute)
	return nil
}
