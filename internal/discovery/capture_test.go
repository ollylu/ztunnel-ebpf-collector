package discovery

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestZtunnelCaptureResolvesSharedPodNamespace(t *testing.T) {
	for _, conflict := range []string{"none", "netns", "uid", "ip"} {
		t.Run(conflict, func(t *testing.T) {
			root := t.TempDir()
			uid := "12345678-1111-2222-3333-123456789abc"
			pods := []Pod{}
			for i, exe := range []string{"/app", "/daprd", "/ztunnel"} {
				id := strings.Repeat(string(rune('a'+i)), 64)
				p := Pod{UID: uid, Name: "server", Namespace: "lab", Node: "n", IP: "10.0.0.1", ContainerID: "containerd://" + id}
				if i == 1 && conflict == "uid" {
					p.UID = "different-generation"
				}
				if i == 1 && conflict == "ip" {
					p.IP = "10.0.0.2"
				}
				if i == 2 {
					p.UID, p.Name, p.Namespace = "ztunnel-uid", "ztunnel", "istio-system"
				}
				fixture(t, root, 101+i, id, p.UID, exe)
				pods = append(pods, p)
			}
			if conflict == "netns" {
				path := filepath.Join(root, "102/ns/net")
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("net:[999]", path); err != nil {
					t.Fatal(err)
				}
			}
			observer, workload, err := ResolveCapture(context.Background(), root, pods, "n", "lab", "server", "ztunnel")
			if conflict != "none" {
				if err == nil {
					t.Fatalf("accepted ambiguous Pod identity: %s", conflict)
				}
				return
			}
			if err != nil || observer.PID != 103 || workload.Pod.UID != uid || workload.NetNS != "net:[4026532222]" {
				t.Fatalf("multi-container Pod rejected: observer=%+v workload=%+v err=%v", observer, workload, err)
			}
		})
	}
}

func TestDaprdCaptureSelectsOnlyVerifiedServerPod(t *testing.T) {
	root := t.TempDir()
	id := strings.Repeat("a", 64)
	other := strings.Repeat("b", 64)
	uid := "12345678-1111-2222-3333-123456789abc"
	fixture(t, root, 101, id, uid, "/daprd")
	fixture(t, root, 102, other, uid, "/app")
	fixture(t, root, 103, strings.Repeat("c", 64), "foreign", "/daprd")
	pods := []Pod{{UID: uid, Name: "server", Namespace: "lab", Node: "n", IP: "10.0.0.1", ContainerID: "containerd://" + id}, {UID: uid, Name: "server", Namespace: "lab", Node: "n", IP: "10.0.0.1", ContainerID: "containerd://" + other}, {UID: "foreign", Name: "other", Namespace: "lab", Node: "n", ContainerID: "containerd://" + strings.Repeat("c", 64)}}
	target, server, e := ResolveCapture(context.Background(), root, pods, "n", "lab", "server", "daprd")
	if e != nil || target.PID != 101 || server.Pod.UID != uid || server.NetNS != target.NetNS {
		t.Fatalf("daprd source not scoped: %+v %+v %v", target, server, e)
	}
	if _, _, e := ResolveCapture(context.Background(), root, pods, "n", "lab", "missing", "daprd"); e == nil {
		t.Fatal("missing pod selected")
	}
	if _, _, e := ResolveCapture(context.Background(), root, pods, "n", "lab", "server", "any"); e == nil {
		t.Fatal("arbitrary process source allowed")
	}
}
