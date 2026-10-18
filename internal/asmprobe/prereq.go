package asmprobe

import (
	"errors"
	"fmt"
)

// PrereqError 表示**前提失败**（加载/挂载/权限/资源获取），必须与行为红严格区分。
type PrereqError struct {
	Stage string
	Err   error
}

func (e *PrereqError) Error() string {
	return fmt.Sprintf("prerequisite failed at %s: %v", e.Stage, e.Err)
}

func (e *PrereqError) Unwrap() error { return e.Err }

// IsPrereq 判定错误是否为前提失败（CLI/测试据此不得记作行为红）。
func IsPrereq(err error) bool {
	var p *PrereqError
	return errors.As(err, &p)
}

// IsTIDMismatch 判定错误是否为"目标线程与当前锁定线程不一致"（配置/用法错误）。
func IsTIDMismatch(err error) bool { return errors.Is(err, ErrTIDMismatch) }
