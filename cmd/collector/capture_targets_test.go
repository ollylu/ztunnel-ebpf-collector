package main

import (
	"fmt"
	"testing"
	"ztunnel-ebpf-collector/internal/discovery"
)

func TestCaptureTargetArgumentsAndPodBinding(t *testing.T) {
	var args targetArgs
	for _, s := range []string{"lab/a:8080", "lab/a:8081", "lab/b:50002"} {
		if err := args.Set(s); err != nil {
			t.Fatal(err)
		}
	}
	a := discovery.Process{PID: 10, StartTime: 1, NetNS: "net:[100]", Pod: discovery.Pod{UID: "uid-a", Name: "a", Namespace: "lab", Node: "n", IP: "10.0.0.1"}}
	b := discovery.Process{PID: 20, StartTime: 2, NetNS: "net:[200]", Pod: discovery.Pod{UID: "uid-b", Name: "b", Namespace: "lab", Node: "n", IP: "10.0.0.2"}}
	got, err := bindCaptureTargets(args, []discovery.Process{a, b})
	if err != nil || len(got) != 3 {
		t.Fatalf("binding failed: %+v %v", got, err)
	}
	if got[0].Process.Pod.UID != "uid-a" || got[1].Endpoint.Server.String() != "10.0.0.1:8081" || got[2].Process.Pod.UID != "uid-b" || got[2].Endpoint.NetNS != 200 {
		t.Fatal("wrong Pod mapping", got)
	}
	if _, err = bindCaptureTargets(args, []discovery.Process{a}); err == nil {
		t.Fatal("missing target silently omitted")
	}
	conflict := a
	conflict.NetNS = "net:[999]"
	if _, err = bindCaptureTargets(args, []discovery.Process{a, b, conflict}); err == nil {
		t.Fatal("ambiguous namespace accepted")
	}
	for _, s := range []string{"lab/a:8080", "lab/a:08080", "bad", "lab/a:0", "lab/a:65536", "lab/a:http", "/a:80", "lab/:80", "lab/a/b:80"} {
		if err := args.Set(s); err == nil {
			t.Fatalf("accepted invalid or duplicate: %s", s)
		}
	}
	args = nil
	for i := 0; i < 32; i++ {
		if err := args.Set(fmt.Sprintf("lab/a:%d", 8000+i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := args.Set("lab/b:80"); err == nil {
		t.Fatal("target bound bypassed")
	}
}
