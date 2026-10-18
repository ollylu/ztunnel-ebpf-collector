package asmprobe

import (
	"context"
	"errors"
)

// ErrNotImplemented 表示内核路径尚未实现（本片先交桩与红测试）。
var ErrNotImplemented = errors.New("asmprobe: kernel event path not implemented")

// Collector 是事件来源；内核实现与桩实现共享同一契约。
type Collector interface {
	Collect(ctx context.Context, cfg Config) ([]Event, error)
}

// StubCollector 是可编译桩：**不产生任何事件**且不报错，用于让内核行为测试真实失败。
type StubCollector struct{}

// Collect 返回空事件集。
func (StubCollector) Collect(context.Context, Config) ([]Event, error) { return nil, nil }

// Run 校验配置并取事件；事件数不足由调用方按真实目标断言（桩下必然失败）。
func Run(ctx context.Context, cfg Config, c Collector) ([]Event, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if c == nil {
		return nil, ErrNotImplemented
	}
	return c.Collect(ctx, cfg)
}
