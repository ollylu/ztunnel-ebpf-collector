package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"
	"ztunnel-ebpf-collector/internal/discovery"
)

func runDiscover(args []string, out, errOut io.Writer) int {
	fs := flag.NewFlagSet("discover", flag.ContinueOnError)
	fs.SetOutput(errOut)
	podsFile := fs.String("pods", "", "Kubernetes PodList JSON path")
	node := fs.String("node", "", "explicit target node")
	proc := fs.String("proc", "/proc", "host proc filesystem")
	if fs.Parse(args) != nil || fs.NArg() != 0 || *podsFile == "" || *node == "" {
		fmt.Fprintln(errOut, "discover requires --pods and --node")
		return exitUsage
	}
	f, e := os.Open(*podsFile)
	if e != nil {
		fmt.Fprintln(errOut, "cannot open pod metadata")
		return exitInputError
	}
	defer f.Close()
	pods, e := discovery.ReadPods(f)
	if e != nil {
		fmt.Fprintln(errOut, e)
		return exitInputError
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ps, e := discovery.Find(ctx, *proc, pods, *node)
	if e != nil {
		fmt.Fprintln(errOut, e)
		return exitInputError
	}
	if len(ps) != 1 {
		fmt.Fprintf(errOut, "expected one verified ztunnel process; found %d\n", len(ps))
		return exitInputError
	}
	if e = json.NewEncoder(out).Encode(ps[0]); e != nil {
		return exitInputError
	}
	return exitOK
}
