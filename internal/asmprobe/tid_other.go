//go:build !linux

package asmprobe

import "os"

// CurrentTID 在非 Linux 平台退化为进程 id（仅用于契约测试；真实线程隔离须在 Linux VM 验证）。
func CurrentTID() int { return os.Getpid() }
