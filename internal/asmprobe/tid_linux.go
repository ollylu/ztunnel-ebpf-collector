//go:build linux

package asmprobe

import "golang.org/x/sys/unix"

// CurrentTID 返回当前线程 id（Linux：真实 TID；须在 LockOSThread 后读取）。
func CurrentTID() int { return int(unix.Gettid()) }
