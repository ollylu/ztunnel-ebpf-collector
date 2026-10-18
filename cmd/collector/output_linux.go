//go:build linux

package main

import (
	"errors"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"time"
)

type captureWriter struct{ fd int }

func (w captureWriter) Write(b []byte) (int, error) {
	deadline := time.Now().Add(time.Second)
	written := 0
	for len(b) > 0 {
		ms := time.Until(deadline).Milliseconds()
		if ms <= 0 {
			return written, errors.New("stdout backpressure timeout")
		}
		fds := []unix.PollFd{{Fd: int32(w.fd), Events: unix.POLLOUT}}
		n, e := unix.Poll(fds, int(ms))
		if e == unix.EINTR {
			continue
		}
		if e != nil {
			return written, e
		}
		if n == 0 {
			return written, errors.New("stdout backpressure timeout")
		}
		n, e = unix.Write(w.fd, b)
		if e == unix.EAGAIN || e == unix.EINTR {
			continue
		}
		if e != nil {
			return written, e
		}
		if n == 0 {
			return written, io.ErrShortWrite
		}
		written += n
		b = b[n:]
	}
	return written, nil
}
func boundedOutput(out io.Writer) (io.Writer, func(), error) {
	f, ok := out.(*os.File)
	if !ok {
		return out, func() {}, nil
	}
	fd, e := unix.FcntlInt(f.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if e != nil {
		return nil, nil, e
	}
	flags, e := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if e != nil {
		unix.Close(fd)
		return nil, nil, e
	}
	if e = unix.SetNonblock(fd, true); e != nil {
		unix.Close(fd)
		return nil, nil, e
	}
	return captureWriter{fd}, func() { _, _ = unix.FcntlInt(uintptr(fd), unix.F_SETFL, flags); _ = unix.Close(fd) }, nil
}
