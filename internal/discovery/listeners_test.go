package discovery

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func listenerFixture(t *testing.T) (string, Process) {
	t.Helper()
	root := t.TempDir()
	id := strings.Repeat("a", 64)
	uid := "12345678-1111-2222-3333-123456789abc"
	fixture(t, root, 101, id, uid, "/app")
	base := filepath.Join(root, "101")
	for _, dir := range []string{"fdinfo", "net"} {
		if err := os.MkdirAll(base+"/"+dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	tcp := "header\n 0: 00000000:1F90 00000000:0000 0A 0:0 0:0 0 0 0 111\n 1: 0100007F:2328 00000000:0000 0A 0:0 0:0 0 0 0 112\n 2: 00000000:3AA0 00000000:0000 0A 0:0 0:0 0 0 0 113\n 3: 0200000A:1F91 00000000:0000 01 0:0 0:0 0 0 0 114\n"
	tcp6 := "header\n 0: 00000000000000000000000000000000:2382 00000000000000000000000000000000:0000 0A 0:0 0:0 0 0 0 115\n"
	for name, text := range map[string]string{"tcp": tcp, "tcp6": tcp6} {
		if err := os.WriteFile(base+"/net/"+name, []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for fd, inode := range map[string]string{"3": "111", "4": "112", "5": "114", "6": "115"} {
		if err := os.WriteFile(base+"/fdinfo/"+fd, []byte("pos:\t0\nflags:\t02\nino:\t"+inode+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return root, Process{PID: 101, StartTime: 12345, NetNS: "net:[4026532222]", Pod: Pod{UID: uid, IP: "10.0.0.2", ContainerID: "containerd://" + id}}
}
func TestListeningPortsRequiresOwnedListener(t *testing.T) {
	root, p := listenerFixture(t)
	ports, err := ListeningPorts(context.Background(), root, []Process{p})
	if err != nil || !reflect.DeepEqual(ports, []uint16{8080, 9090}) {
		t.Fatal("owned IPv4/dual-stack listener discovery", ports, err)
	}
	if err := os.Remove(filepath.Join(root, "101/fdinfo/3")); err != nil {
		t.Fatal(err)
	}
	ports, err = ListeningPorts(context.Background(), root, []Process{p})
	if err != nil || !reflect.DeepEqual(ports, []uint16{9090}) {
		t.Fatal("closed listener retained", ports, err)
	}
	p.StartTime++
	if _, err = ListeningPorts(context.Background(), root, []Process{p}); err == nil {
		t.Fatal("stale process trusted")
	}
}
func TestListenerCancellationAndIdentity(t *testing.T) {
	root, p := listenerFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ListeningPorts(ctx, root, []Process{p}); err == nil {
		t.Fatal("cancellation ignored")
	}
	other := p
	other.NetNS = "net:[99]"
	if _, err := ListeningPorts(context.Background(), root, []Process{p, other}); err == nil {
		t.Fatal("mixed netns trusted")
	}
}
