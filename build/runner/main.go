// Command runner 是本任务自有的有界子进程执行器（非框架）。
// 语义：
//   - 子进程独立进程组；
//   - **超时**与**父进程收到 SIGINT/SIGTERM**都走同一清理路径：先向整组转发同信号，
//     有界等待后升级 SIGKILL，并轮询确认进程组已空；
//   - 退出码：子进程码 / 124=超时 / 130=SIGINT / 143=SIGTERM（以上均已确认组已清空）；
//     **125=清理无法确认**（调用方必须保留锁并人工核验）。
//
// 注意：runner 自身被 SIGKILL 时无法执行任何清理，**不承诺自动回收**，需人工核验。
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"
)

const (
	exitTimeout     = 124
	exitCleanupFail = 125
)

func main() {
	timeout := flag.Duration("timeout", 600*time.Second, "hard timeout for the whole process group")
	flag.Parse()
	args := flag.Args()
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "runner: missing command")
		os.Exit(2)
	}
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdout, cmd.Stderr, cmd.Stdin = os.Stdout, os.Stderr, os.Stdin
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "runner: start: %v\n", err)
		os.Exit(1)
	}
	pgid := cmd.Process.Pid
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-done:
		os.Exit(childCode(err))
	case <-time.After(*timeout):
		fmt.Fprintf(os.Stderr, "runner: timeout after %s; cleaning process group %d\n", *timeout, pgid)
		os.Exit(cleanup(pgid, syscall.SIGKILL, done, exitTimeout))
	case s := <-sigs:
		sig, ok := s.(syscall.Signal)
		if !ok {
			os.Exit(exitCleanupFail)
		}
		fmt.Fprintf(os.Stderr, "runner: received %s; cleaning process group %d\n", sig, pgid)
		os.Exit(cleanup(pgid, sig, done, 128+int(sig)))
	}
}

// childCode 把子进程结果映射为退出码。
func childCode(err error) int {
	if err == nil {
		return 0
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode()
	}
	fmt.Fprintf(os.Stderr, "runner: %v\n", err)
	return 1
}

// cleanup 向整组转发信号，有界等待后升级 SIGKILL，并确认组已空。
// 关键：done（cmd.Wait 结果）**只消费一次**；成功条件是「子进程已回收 且 进程组已空」
// 两个条件在同一有界循环内同时判定，避免在已耗尽的 channel 上二次阻塞。
// 确认成功返回 wantCode；无法确认返回 125（调用方须保留锁并人工核验）。
func cleanup(pgid int, sig syscall.Signal, done <-chan error, wantCode int) int {
	reaped := false
	var childErr error
	consume := func(wait time.Duration) {
		if reaped {
			return
		}
		select {
		case childErr = <-done:
			reaped = true
		case <-time.After(wait):
		}
	}
	_ = childErr
	groupEmpty := func() bool { return syscall.Kill(-pgid, 0) != nil }
	waitConfirmed := func(d time.Duration) bool {
		deadline := time.Now().Add(d)
		for time.Now().Before(deadline) {
			consume(100 * time.Millisecond)
			if reaped && groupEmpty() {
				return true
			}
			time.Sleep(100 * time.Millisecond)
		}
		return false
	}
	_ = syscall.Kill(-pgid, sig)
	if waitConfirmed(10 * time.Second) {
		return wantCode
	}
	_ = syscall.Kill(-pgid, syscall.SIGKILL)
	if waitConfirmed(10 * time.Second) {
		return wantCode
	}
	fmt.Fprintf(os.Stderr, "runner: process group %d still present: cleanup unconfirmed (keep lock; verify manually)\n", pgid)
	return exitCleanupFail
}
