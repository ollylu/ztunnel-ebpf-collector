package discovery

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestOutboundListenerOwnedByObserver(t *testing.T) {
	root, worker := listenerFixture(t)
	id := strings.Repeat("b", 64)
	uid := "ztunnel-pod"
	fixture(t, root, 102, id, uid, "/usr/local/bin/ztunnel")
	observer := Process{PID: 102, StartTime: 12345, NetNS: "net:[4026532222]", Pod: Pod{UID: uid, ContainerID: "containerd://" + id}}
	dir := filepath.Join(root, "102/fdinfo")
	os.MkdirAll(dir, 0700)
	fd := dir + "/8"
	os.WriteFile(fd, []byte("ino:\t116\n"), 0600)
	table := filepath.Join(root, "101/net/tcp")
	os.WriteFile(table, []byte("header\n 0: 00000000:3A99 00000000:0000 0A 0:0 0:0 0 0 0 116\n"), 0600)
	got, err := OutboundListeners(context.Background(), root, observer, []Process{worker})
	if err != nil || !got[worker.Pod.UID] {
		t.Fatal("verified observer listener missing", got, err)
	}
	// Same port owned by another process cannot authorize capture.
	os.Remove(fd)
	got, err = OutboundListeners(context.Background(), root, observer, []Process{worker})
	if err != nil || got[worker.Pod.UID] {
		t.Fatal("foreign listener accepted", got, err)
	}
	observer.StartTime++
	if _, err = OutboundListeners(context.Background(), root, observer, []Process{worker}); err == nil {
		t.Fatal("stale observer accepted")
	}
}

func TestMissingPodTCPTableDoesNotStopOtherPods(t *testing.T) {
	root, w := listenerFixture(t)
	id := strings.Repeat("b", 64)
	fixture(t, root, 102, id, "observer", "/usr/local/bin/ztunnel")
	observer := Process{PID: 102, StartTime: 12345, NetNS: w.NetNS, Pod: Pod{UID: "observer", ContainerID: "containerd://" + id}}
	os.MkdirAll(filepath.Join(root, "102/fdinfo"), 0700)
	os.WriteFile(filepath.Join(root, "102/fdinfo/8"), []byte("ino:\t116\n"), 0600)
	fixture(t, root, 103, id, "healthy", "/app")
	os.MkdirAll(filepath.Join(root, "103/net"), 0700)
	os.WriteFile(filepath.Join(root, "103/net/tcp"), []byte("header\n 0: 00000000:3A99 00000000:0000 0A 0:0 0:0 0 0 0 116\n"), 0600)
	healthy := Process{PID: 103, StartTime: 12345, NetNS: w.NetNS, Pod: Pod{UID: "healthy", ContainerID: "containerd://" + id}}
	os.Remove(filepath.Join(root, "101/net/tcp"))
	got, err := OutboundListeners(context.Background(), root, observer, []Process{w, healthy})
	if err != nil || got[w.Pod.UID] || !got["healthy"] {
		t.Fatalf("one disappearing pod poisoned healthy pod discovery: %v %v", got, err)
	}
}

func TestManyObserverFDsDoNotStopNode(t *testing.T) {
	root, w := listenerFixture(t)
	observer := w
	base := filepath.Join(root, strconv.Itoa(observer.PID), "fdinfo")
	for i := 0; i < 4100; i++ {
		if err := os.WriteFile(filepath.Join(base, strconv.Itoa(i+10000)), []byte("ino:\t999999\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := OutboundListeners(context.Background(), root, observer, []Process{w}); err != nil {
		t.Fatalf("bounded scan stopped entire node: %v", err)
	}
}
