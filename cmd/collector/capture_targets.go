package main

import (
	"context"
	"errors"
	"net/netip"
	"strconv"
	"strings"
	"ztunnel-ebpf-collector/internal/discovery"
	"ztunnel-ebpf-collector/internal/tcpcapture"
)

type targetArgs []string

func (a *targetArgs) String() string { return strings.Join(*a, ",") }
func splitTarget(s string) (ns, name string, port uint16, err error) {
	pair, p, ok := strings.Cut(s, ":")
	ns, name, slash := strings.Cut(pair, "/")
	n, e := strconv.ParseUint(p, 10, 16)
	if !ok || !slash || ns == "" || name == "" || strings.ContainsAny(pair, " \t\r\n") || strings.Contains(name, "/") || e != nil || n == 0 || strconv.FormatUint(n, 10) != p {
		return "", "", 0, errors.New("target must be namespace/pod:port")
	}
	return ns, name, uint16(n), nil
}
func (a *targetArgs) Set(s string) error {
	if _, _, _, err := splitTarget(s); err != nil {
		return err
	}
	if len(*a) >= tcpcapture.MaxTargets {
		return errors.New("target budget exhausted (maximum 32)")
	}
	for _, old := range *a {
		if old == s {
			return errors.New("duplicate target")
		}
	}
	*a = append(*a, s)
	return nil
}

type captureTarget struct {
	Discovered bool // admitted by owned-listener discovery when YAML has no TCP ports
	Endpoint   tcpcapture.Endpoint
	Process    discovery.Process
}

func resolveCaptureTargets(ctx context.Context, root string, pods []discovery.Pod, node string, args targetArgs) (discovery.Process, []captureTarget, error) {
	observers, err := discovery.Find(ctx, root, pods, node)
	if err != nil || len(observers) != 1 {
		return discovery.Process{}, nil, errors.New("no unique verified ztunnel")
	}
	selected := []discovery.Pod{}
	for _, p := range pods {
		for _, arg := range args {
			ns, name, _, err := splitTarget(arg)
			if err != nil {
				return discovery.Process{}, nil, err
			}
			if p.Namespace == ns && p.Name == name && p.Node == node {
				selected = append(selected, p)
				break
			}
		}
	}
	workers, err := discovery.FindWorkload(ctx, root, selected, node)
	if err != nil {
		return discovery.Process{}, nil, err
	}
	targets, err := bindCaptureTargets(args, workers)
	return observers[0], targets, err
}
func bindCaptureTargets(args targetArgs, workers []discovery.Process) ([]captureTarget, error) {
	if len(args) == 0 || len(args) > tcpcapture.MaxTargets {
		return nil, errors.New("invalid target count")
	}
	var out []captureTarget
	var endpoints []tcpcapture.Endpoint
	for _, arg := range args {
		ns, name, port, err := splitTarget(arg)
		if err != nil {
			return nil, err
		}
		var anchor *discovery.Process
		for _, w := range workers {
			if w.Pod.Namespace != ns || w.Pod.Name != name {
				continue
			}
			if anchor == nil {
				copy := w
				anchor = &copy
			} else if anchor.Pod.UID != w.Pod.UID || anchor.Pod.IP != w.Pod.IP || anchor.NetNS != w.NetNS {
				return nil, errors.New("ambiguous target Pod identity")
			}
		}
		if anchor == nil {
			return nil, errors.New("target Pod has no verified local process")
		}
		ip, err := netip.ParseAddr(anchor.Pod.IP)
		if err != nil || !ip.Is4() {
			return nil, errors.New("target requires IPv4 Pod address")
		}
		nsText, ok := strings.CutPrefix(anchor.NetNS, "net:[")
		if !ok || !strings.HasSuffix(nsText, "]") {
			return nil, errors.New("invalid target network namespace")
		}
		n, err := strconv.ParseUint(strings.TrimSuffix(nsText, "]"), 10, 32)
		if err != nil || n == 0 {
			return nil, errors.New("invalid target network namespace")
		}
		ep := tcpcapture.Endpoint{NetNS: uint32(n), Server: netip.AddrPortFrom(ip, port)}
		out = append(out, captureTarget{Endpoint: ep, Process: *anchor})
		endpoints = append(endpoints, ep)
	}
	if _, err := (tcpcapture.Config{Targets: endpoints}).Endpoints(); err != nil {
		return nil, err
	}
	return out, nil
}
