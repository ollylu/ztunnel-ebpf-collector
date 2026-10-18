package discovery

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fixture(t *testing.T, root string, pid int, id, uid, exe string) {
	t.Helper()
	p := filepath.Join(root, fmt.Sprint(pid))
	if err := os.MkdirAll(p+"/ns", 0700); err != nil {
		t.Fatal(err)
	}
	stat := fmt.Sprintf("%d (z tunnel) S ", pid) + strings.Repeat("0 ", 18) + "12345 0\n"
	for name, value := range map[string]string{"stat": stat, "cgroup": "0::/kubepods.slice/kubepods-burstable-pod" + strings.ReplaceAll(uid, "-", "_") + ".slice/cri-containerd-" + id + ".scope\n"} {
		if err := os.WriteFile(p+"/"+name, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(exe, p+"/exe"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("net:[4026532222]", p+"/ns/net"); err != nil {
		t.Fatal(err)
	}
}
func TestFindRequiresFullContainerAndPodIdentity(t *testing.T) {
	root := t.TempDir()
	id := strings.Repeat("a", 64)
	uid := "12345678-1111-2222-3333-123456789abc"
	fixture(t, root, 101, id, uid, "/usr/local/bin/ztunnel")
	fixture(t, root, 102, strings.Repeat("b", 64), uid, "/usr/local/bin/ztunnel")
	fixture(t, root, 103, id, "different-pod", "/usr/local/bin/ztunnel")
	fixture(t, root, 104, id, uid, "/usr/bin/not-ztunnel")
	got, err := Find(context.Background(), root, []Pod{{UID: uid, Name: "ztunnel-real", Namespace: "istio-system", Node: "node1", ContainerID: "containerd://" + id}}, "node1")
	if err != nil || len(got) != 1 || got[0].PID != 101 || got[0].StartTime != 12345 {
		t.Fatalf("got %+v err %v", got, err)
	}
	got, err = Find(context.Background(), root, []Pod{{UID: uid, Node: "other", ContainerID: "containerd://" + id}}, "node1")
	if err != nil || len(got) != 0 {
		t.Fatalf("foreign node matched: %+v %v", got, err)
	}
}
func TestFindCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Find(ctx, t.TempDir(), nil, "n"); err == nil {
		t.Fatal("cancel ignored")
	}
}

func TestValidateRejectsChangedNetworkNamespace(t *testing.T) {
	root := t.TempDir()
	id := strings.Repeat("a", 64)
	fixture(t, root, 101, id, "uid", "/app")
	p := Process{PID: 101, StartTime: 12345, NetNS: "net:[999]", Pod: Pod{UID: "uid", ContainerID: "containerd://" + id}}
	if p.Validate(root) == nil {
		t.Fatal("changed netns accepted")
	}
}
func TestValidatePreservesMissingProcessCause(t *testing.T) {
	p := Process{PID: 101, StartTime: 12345}
	if err := p.Validate(t.TempDir()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing process indistinguishable from I/O failure: %v", err)
	}
}
