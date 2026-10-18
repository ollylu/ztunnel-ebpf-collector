package asmprobe

import "errors"

// Resource 是被唯一 owner 持有的可回收对象（map/program/perf FD/reader 等）。
type Resource interface {
	Name() string
	Close() error
}

// Owner 按获取顺序登记资源，并按**逆序**回滚；单项关闭失败不阻断其余关闭。
type Owner struct {
	res     []Resource
	closed  bool
	errSeen []error
}

// Acquire 登记一项资源（调用方保证已成功获取）。
func (o *Owner) Acquire(r Resource) {
	if o.closed {
		return
	}
	o.res = append(o.res, r)
}

// CloseAll 逆序关闭并聚合错误；可重复调用（第二次为空操作）。
func (o *Owner) CloseAll() error {
	if o.closed {
		return nil
	}
	o.closed = true
	for i := len(o.res) - 1; i >= 0; i-- {
		if err := o.res[i].Close(); err != nil {
			o.errSeen = append(o.errSeen, err)
		}
	}
	o.res = nil
	if len(o.errSeen) == 0 {
		return nil
	}
	return errors.Join(o.errSeen...)
}

// CloseOrder 返回本次实际关闭顺序（供测试与证据使用）。
func (o *Owner) CloseOrder() []string {
	out := make([]string, 0, len(o.res))
	for i := len(o.res) - 1; i >= 0; i-- {
		out = append(out, o.res[i].Name())
	}
	return out
}
