//go:build !linux || !amd64

package asmprobe

import "context"

// notImplementedCollector 代表**本片不支持**的平台/架构（非 linux，或 linux 非 amd64）：
// 明确 unsupported（前提失败单列），不做任何兼容兜底。
type notImplementedCollector struct{}

func (notImplementedCollector) Collect(context.Context, Config) ([]Event, error) {
	return nil, &PrereqError{Stage: "platform", Err: ErrNotImplemented}
}

// NewKernelCollector 在非 Linux 平台返回未实现来源（行为断言仍按"真实事件缺失"失败）。
func NewKernelCollector() Collector { return notImplementedCollector{} }
