package ambient

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOutboundSocketLayout(t *testing.T) {
	if os.Getenv("ZC_OUTBOUND_LAYOUT") != "1" {
		t.Skip("explicit local read-only socket diagnosis")
	}
	root, _ := filepath.Abs("../..")
	l := lab{t: t, root: root, kube: filepath.Join(root, ".local/k3s-kubeconfig"), ns: "collector-out-layout", evidence: filepath.Join(root, ".local/outbound-layout")}
	os.MkdirAll(l.evidence, 0700)
	if l.must(l.k("config", "view", "--minify", "-o", "jsonpath={.clusters[0].cluster.server}")) != "https://127.0.0.1:16443" {
		t.Fatal("refuse non-local")
	}
	if _, err := l.k("get", "ns", l.ns); err == nil {
		t.Fatal("refuse existing namespace")
	}
	l.must(l.k("create", "ns", l.ns))
	defer func() { l.must(l.k("delete", "ns", l.ns, "--wait=true", "--timeout=50s")) }()
	l.must(l.k("label", "ns", l.ns, "istio.io/dataplane-mode=ambient"))
	l.pod("caller", []any{container("app", "ztunnel-collector-traffic:i2", "idle")}, nil)
	l.pod("server", []any{container("app", "ztunnel-collector-traffic:i2")}, nil)
	ip := l.must(l.k("-n", l.ns, "get", "pod/server", "-o", "jsonpath={.status.podIP}"))
	l.must(l.exec("caller", "client", "http://"+ip+":8080"))
	id := l.must(l.k("-n", l.ns, "get", "pod/caller", "-o", "jsonpath={.status.containerStatuses[0].containerID}"))
	id = strings.TrimPrefix(id, "containerd://")
	raw := l.must(l.run("", "limactl", "shell", "ztunnel-ebpf-amd64", "sudo", "k3s", "crictl", "inspect", id))
	var c struct{ Info struct{ Pid json.Number } }
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
		t.Fatal(err)
	}
	if c.Info.Pid == "" {
		t.Fatal("missing caller pid")
	}
	for _, table := range []string{"tcp", "tcp6"} {
		s := l.must(l.run("", "limactl", "shell", "ztunnel-ebpf-amd64", "sudo", "cat", "/proc/"+string(c.Info.Pid)+"/net/"+table))
		l.save(table+".txt", s)
		t.Log(table, s)
	}
}
