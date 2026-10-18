package asmprobe

import (
	"os"
	"strconv"
	"strings"
)

// OSEnv 是本机只读环境实现（不写 sysctl、不提权）。
type OSEnv struct{}

// SwCPUClockAvailable 只读探测本机是否具备 software CPU clock 事件源。
// 说明：SW 事件不需要 tracefs/tracepoint id；此处仅确认平台与 perf 接口可读，
// 真实可用性仍须在专用 VM 内核上验证（预检不等于行为证据）。
func (OSEnv) SwCPUClockAvailable() (bool, error) {
	if _, err := os.Stat("/proc/sys/kernel/perf_event_paranoid"); err != nil {
		return false, err
	}
	return true, nil
}

// PerfEventParanoid 读取 /proc/sys/kernel/perf_event_paranoid（只读）。
func (OSEnv) PerfEventParanoid() (int, error) {
	b, err := os.ReadFile("/proc/sys/kernel/perf_event_paranoid")
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(b)))
}

// KernelRelease 读取内核版本（只读）。
func (OSEnv) KernelRelease() (string, error) {
	b, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}
