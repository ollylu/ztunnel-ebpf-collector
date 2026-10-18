// Command collector 是 ztunnel-ebpf-collector 的 CLI 入口。
//
// 首片（I1-1）只提供 version / replay / capture 三个子命令的契约：
//   - version：输出构建 revision、版本与 source mode；工作树构建不得标为已发布。
//   - replay：同步短程回放 JSONL（默认 stdin），只输出染色 pair。
//   - capture：尚未实现，必须明确失败，不得用 replay 冒充成功。
package main

import (
	"errors"
	"fmt"
	"io"
	"os"

	"ztunnel-ebpf-collector/internal/replay"
)

// 构建期注入；默认值表示这是工作树构建，不是已发布制品。
var (
	revision   = "unknown"
	version    = "dev"
	sourceMode = "worktree"
)

const (
	exitOK          = 0
	exitUsage       = 2
	exitUnsupported = 3
	exitInputError  = 1
)

const usage = `usage: collector <version|replay|discover|capture|node|health> [--input PATH] [--marker-header NAME --marker-value VALUE]

  version   print build revision, version and source mode
  replay    replay explicit synthetic HTTP/1.x pairs from JSONL (stdin by default)
  capture   bounded live capture
  node      continuous node-local capture (in-cluster credentials required)
`

// Main 是真实 CLI 入口（main 直接调用它，保证测试覆盖的就是实际路径）。
func Main(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return exitUsage
	}
	switch args[0] {
	case "node":
		return runNode(args[1:], stdout, stderr)
	case "health":
		if len(args) != 1 {
			return exitUsage
		}
		if _, err := os.Stat(readyPath); err != nil {
			return exitInputError
		}
		return exitOK
	case "version":
		fmt.Fprintf(stdout, "revision=%s\nversion=%s\nsource_mode=%s\n", revision, version, sourceMode)
		return exitOK
	case "replay":
		return runReplay(args[1:], stdin, stdout, stderr)
	case "discover":
		return runDiscover(args[1:], stdout, stderr)
	case "capture":
		if len(args) > 1 {
			return runCapture(args[1:], stdout, stderr)
		}
		fmt.Fprintln(stderr, "collector: capture: unsupported in this slice; replay does not substitute for capture")
		return exitUnsupported
	default:
		fmt.Fprintf(stderr, "collector: unknown subcommand %q\n%s", args[0], usage)
		return exitUsage
	}
}

// runReplay 解析 --input 并执行同步回放；输入错误非零退出且不回显原始输入。
func runReplay(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	in := stdin
	marker := replay.Marker{Header: "X-trace", Value: "print"}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--marker-header", "--marker-value":
			if i+1 >= len(args) {
				fmt.Fprintln(stderr, "collector: marker flag requires a value")
				return exitUsage
			}
			if args[i] == "--marker-header" {
				marker.Header = args[i+1]
			} else {
				marker.Value = args[i+1]
			}
			i++
		case "--input":
			if i+1 >= len(args) {
				fmt.Fprintln(stderr, "collector: replay: --input requires a path")
				return exitUsage
			}
			f, err := os.Open(args[i+1])
			if err != nil {
				fmt.Fprintln(stderr, "collector: replay: cannot open input file")
				return exitInputError
			}
			defer f.Close()
			in = f
			i++
		default:
			fmt.Fprintf(stderr, "collector: replay: unknown flag %q\n", args[i])
			return exitUsage
		}
	}
	if err := marker.Validate(); err != nil {
		fmt.Fprintln(stderr, "collector: invalid marker configuration")
		return exitUsage
	}
	if err := replay.RunWithMarker(in, stdout, marker); err != nil {
		switch {
		case errors.Is(err, replay.ErrForeignSourceKind):
			fmt.Fprintln(stderr, "collector: replay: invalid source_kind (only synthetic_replay is accepted)")
		case errors.Is(err, replay.ErrInputTooLong):
			fmt.Fprintln(stderr, "collector: replay: input line exceeds the 64KiB limit")
		case errors.Is(err, replay.ErrInvalidInput):
			fmt.Fprintln(stderr, "collector: replay: invalid input")
		default:
			fmt.Fprintf(stderr, "collector: replay: %v\n", err)
		}
		return exitInputError
	}
	return exitOK
}

func main() { os.Exit(Main(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)) }
