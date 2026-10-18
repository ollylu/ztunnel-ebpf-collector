package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
	"ztunnel-ebpf-collector/internal/discovery"
	"ztunnel-ebpf-collector/internal/livehttp"
	"ztunnel-ebpf-collector/internal/replay"
	"ztunnel-ebpf-collector/internal/tcpcapture"
)

func runCapture(args []string, out, errOut io.Writer) int {
	fs := flag.NewFlagSet("capture", flag.ContinueOnError)
	fs.SetOutput(errOut)
	var requested targetArgs
	fs.Var(&requested, "target", "repeatable namespace/pod:port; protocol detected automatically; ztunnel only")
	podsPath := fs.String("pods", "", "bounded Kubernetes PodList snapshot")
	source := fs.String("source", "ztunnel", "ztunnel or daprd (same-Pod plaintext app channel)")
	node := fs.String("node", "", "target node")
	server := fs.String("server", "", "business Pod namespace/name")
	port := fs.Uint("port", 8080, "business TCP port")
	header := fs.String("marker-header", "", "required request header name")
	value := fs.String("marker-value", "", "required exact header value")
	duration := fs.Duration("duration", 15*time.Second, "capture duration, 1s..30s")
	if fs.Parse(args) != nil || fs.NArg() != 0 {
		return exitUsage
	}
	marker := replay.Marker{Header: *header, Value: *value}
	ns, name, ok := strings.Cut(*server, "/")
	if (*source != "ztunnel" && *source != "daprd") || (len(requested) == 0 && (!ok || ns == "" || name == "")) || (len(requested) > 0 && (*server != "" || *source != "ztunnel")) || *node == "" || *podsPath == "" || *port == 0 || *port > 65535 || *duration < time.Second || *duration > 30*time.Second || marker.Validate() != nil {
		fmt.Fprintln(errOut, "capture requires --pods, --node, --server namespace/name or --target namespace/name:port, --marker-header and --marker-value; duration 1s..30s")
		return exitUsage
	}
	f, e := os.Open(*podsPath)
	if e != nil {
		fmt.Fprintln(errOut, "cannot open pod metadata")
		return exitInputError
	}
	pods, e := discovery.ReadPods(f)
	f.Close()
	if e != nil {
		fmt.Fprintln(errOut, e)
		return exitInputError
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	scan, stop := context.WithTimeout(ctx, 3*time.Second)
	var target discovery.Process
	var targets []captureTarget
	if len(requested) > 0 {
		target, targets, e = resolveCaptureTargets(scan, "/proc", pods, *node, requested)
	} else {
		var workload discovery.Process
		target, workload, e = discovery.ResolveCapture(scan, "/proc", pods, *node, ns, name, *source)
		if e == nil {
			targets, e = bindCaptureTargets(targetArgs{*server + ":" + strconv.FormatUint(uint64(*port), 10)}, []discovery.Process{workload})
		}
		if e == nil && *source == "daprd" {
			targets[0].Endpoint.Server = netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(*port))
		}
	}
	stop()
	if e != nil {
		fmt.Fprintln(errOut, e)
		return exitInputError
	}
	byEndpoint := make(map[tcpcapture.Endpoint]discovery.Process, len(targets))
	endpoints := make([]tcpcapture.Endpoint, 0, len(targets))
	anchors := make(map[int]discovery.Process, len(targets))
	for _, t := range targets {
		byEndpoint[t.Endpoint] = t.Process
		endpoints = append(endpoints, t.Endpoint)
		anchors[t.Process.PID] = t.Process
	}
	analyzer := livehttp.Analyzer{Marker: marker}
	bounded, closeOutput, e := boundedOutput(out)
	if e != nil {
		fmt.Fprintln(errOut, "stdout unavailable")
		return exitInputError
	}
	defer closeOutput()
	records := 0
	events := 0
	var nextCheck time.Time
	cfg := tcpcapture.Config{Suppressions: analyzer.DrainSuppressed, PID: target.PID, StartTime: target.StartTime, Targets: endpoints, Duration: *duration,
		Check: func() error {
			if time.Now().Before(nextCheck) {
				return nil
			}
			analyzer.Sweep(time.Now())
			nextCheck = time.Now().Add(250 * time.Millisecond)
			if e := target.Validate("/proc"); e != nil {
				return e
			}
			for _, p := range anchors {
				if e := p.Validate("/proc"); e != nil {
					return e
				}
			}
			return nil
		},
		Ready: func() {
			for _, t := range targets {
				p := t.Process.Pod
				fmt.Fprintf(errOut, "capture_target server=%s/%s ip=%s netns=%d endpoint=%s\n", p.Namespace, p.Name, p.IP, t.Endpoint.NetNS, t.Endpoint.Server)
			}
			fmt.Fprintf(errOut, "capture_ready pid=%d source=%s targets=%d\n", target.PID, *source, len(targets))
		},
	}
	e = tcpcapture.Run(ctx, cfg, func(ev tcpcapture.Event) error {
		events++
		if os.Getenv("ZC_EVENT_DIAGNOSTIC") == "1" {
			fmt.Fprintf(errOut, "event inode=%d ns=%d write=%v bytes=%d local=%s:%d remote=%s:%d\n", ev.Inode, ev.NetNS, ev.Write, len(ev.Data), ev.LocalIP, ev.LocalPort, ev.RemoteIP, ev.RemotePort)
		}
		workload, ok := byEndpoint[tcpcapture.Endpoint{NetNS: ev.NetNS, Server: netip.AddrPortFrom(ev.RemoteIP, ev.RemotePort)}]
		if !ok {
			return errors.New("event outside verified target set")
		}
		rs, e := analyzer.Push(ev)
		if e != nil {
			return e
		}
		for _, r := range rs {
			r.PodIP = workload.Pod.IP
			r.PodName = workload.Pod.Name
			r.PodNamespace = workload.Pod.Namespace
			r.PodUID = workload.Pod.UID
			if e := replay.WriteRecord(bounded, r); e != nil {
				return e
			}
			records++
		}
		return nil
	})
	if e != nil {
		fmt.Fprintln(errOut, "capture stopped:", e)
		return exitInputError
	}
	fmt.Fprintf(errOut, "capture_done events=%d records=%d\n", events, records)
	return exitOK
}
