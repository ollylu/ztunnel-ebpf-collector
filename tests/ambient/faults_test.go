package ambient

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Catches stale observer generations and orphaned BPF links after process loss.
// Explicitly limited to this project's disposable single-node Lima cluster.
// This proves post-fault recovery, not cross-node HBONE or in-flight completion.
func TestLocalProcessFaultRecovery(t *testing.T) { runLocalFaultRecovery(t) }

func runLocalFaultRecovery(t *testing.T) {
	if os.Getenv("ZC_FAULT_LOCAL") != "1" {
		t.Skip("explicit isolated VM fault test only")
	}
	root, _ := filepath.Abs("../..")
	l := lab{t: t, root: root, kube: filepath.Join(root, ".local/k3s-kubeconfig"), source: os.Getenv("ZC_SOURCE_SHA"), ns: "collector-i14", evidence: filepath.Join(root, ".local/i14/process")}
	if len(l.source) != 40 {
		t.Fatal("fixed product SHA required")
	}
	os.MkdirAll(l.evidence, 0700)
	if l.must(l.k("config", "view", "--minify", "-o", "jsonpath={.clusters[0].cluster.server}")) != "https://127.0.0.1:16443" {
		t.Fatal("refuse non-local cluster")
	}
	if _, e := l.k("get", "ns", l.ns); e == nil {
		t.Fatal("refuse existing test namespace")
	}
	if b := nodeBPF(l); len(b) != 0 {
		t.Fatal("other capture active", b)
	}
	l.must(l.k("create", "ns", l.ns))
	defer func() { l.k("delete", "ns", l.ns, "--wait=false") }()
	l.must(l.k("label", "ns", l.ns, "istio.io/dataplane-mode=ambient"))
	for _, name := range []string{"server", "client"} {
		c := container("app", "ztunnel-collector-traffic:i2")
		if name == "client" {
			c["args"] = []string{"idle"}
		}
		p := l.obj("Pod", name)
		p["metadata"].(map[string]any)["labels"] = map[string]string{"observe": "yes"}
		p["spec"] = map[string]any{"nodeName": "collector-local", "restartPolicy": "Always", "automountServiceAccountToken": false, "terminationGracePeriodSeconds": 2, "containers": []any{c}}
		l.apply(p)
	}
	l.must(l.k("-n", l.ns, "wait", "pods", "--all", "--for=condition=Ready", "--timeout=60s"))
	values := map[string]any{"syntheticReplay": false, "daemon": map[string]any{"enabled": true, "namespace": l.ns, "selector": "observe=yes", "direction": "both", "nodeSelector": map[string]string{"kubernetes.io/hostname": "collector-local"}}, "image": map[string]string{"repository": "ztunnel-ebpf-collector", "tag": l.source + "-amd64", "pullPolicy": "Never"}, "captureConfig": map[string]string{"markerHeader": "Debug-Token", "markerValue": "yes"}}
	vp := filepath.Join(l.evidence, "values.json")
	os.WriteFile(vp, []byte(jsonText(values)), 0600)
	l.must(l.run("", "helm", "install", "i14", filepath.Join(root, "dist", l.source, "ztunnel-ebpf-collector-0.1.0.tgz"), "--kubeconfig", l.kube, "-n", l.ns, "-f", vp))
	defer func() {
		l.run("", "helm", "uninstall", "i14", "--kubeconfig", l.kube, "-n", l.ns, "--wait", "--timeout", "30s")
		if b := nodeBPF(l); len(b) != 0 {
			t.Error("leaked BPF", b)
		}
	}()
	logs := func() string {
		s, _ := l.k("-n", l.ns, "logs", "ds/i14-node", "--tail=300", "--limit-bytes=250000")
		return s
	}
	wait := func(label string, check func() bool) {
		t.Helper()
		deadline := time.Now().Add(80 * time.Second)
		for !check() {
			if time.Now().After(deadline) {
				l.save(label+"-failed.log", logs())
				t.Fatal(label, "not recovered")
			}
			time.Sleep(time.Second)
		}
	}
	wait("initial", func() bool { return strings.Contains(logs(), "node_targets count=3 ") })
	records := func(s string) []map[string]any {
		var rs []map[string]any
		for _, line := range strings.Split(s, "\n") {
			if strings.HasPrefix(line, "{") {
				var r map[string]any
				if json.Unmarshal([]byte(line), &r) == nil {
					rs = append(rs, r)
				}
			}
		}
		return rs
	}
	traffic := func(label string) {
		t.Helper()
		before := len(records(logs()))
		ip := l.must(l.k("-n", l.ns, "get", "pod/server", "-o", "jsonpath={.status.podIP}"))
		uid := l.must(l.k("-n", l.ns, "get", "pod/server", "-o", "jsonpath={.metadata.uid}"))
		body := l.must(l.exec("client", "client", "http://"+ip+":8080"))
		l.save(label+"-business.txt", body)
		if body != "/marked 200\n/unmarked 200\n" {
			t.Fatal(body)
		}
		wait(label, func() bool { return len(records(logs())) >= before+4 })
		raw := logs()
		l.save(label+"-capture.log", raw)
		if strings.Contains(raw, "node_stopped") {
			t.Fatal("protection", raw)
		}
		rs := records(raw)[before:]
		if len(rs) != 4 {
			t.Fatal("missing/extra observation", len(rs))
		}
		pairs := map[string][]map[string]any{}
		for _, r := range rs {
			pairs[r["request_id"].(string)] = append(pairs[r["request_id"].(string)], r)
			if r["direction"] == "request" && r["path"] != "/marked" {
				t.Fatal("unmarked leak", r)
			}
			if r["observation_side"] == "inbound" && (r["pod_uid"] != uid || r["pod_ip"] != ip) {
				t.Fatal("stale Pod", r)
			}
		}
		for _, p := range pairs {
			if len(p) != 2 || p[0]["direction"] != "request" || p[1]["direction"] != "response" || p[0]["pod_uid"] != p[1]["pod_uid"] {
				t.Fatal("mismatched pair", p)
			}
		}
	}
	traffic("before")
	// Process signals are directed at a container ID verified through CRI, never
	// an arbitrary PID from a stale log or a shared ACK node.
	signalPod := func(ns, pod, containerName, signal string) {
		raw := l.must(l.k("-n", ns, "get", "pod", pod, "-o", "json"))
		var p struct {
			Status struct {
				ContainerStatuses []struct{ Name, ContainerID string }
			}
		}
		json.Unmarshal([]byte(raw), &p)
		id := ""
		for _, c := range p.Status.ContainerStatuses {
			if c.Name == containerName {
				id = strings.TrimPrefix(c.ContainerID, "containerd://")
			}
		}
		if len(id) != 64 {
			t.Fatal("invalid container ID")
		}
		raw = l.must(l.run("", "limactl", "shell", "ztunnel-ebpf-amd64", "sudo", "k3s", "crictl", "inspect", id))
		var c struct {
			Status struct {
				ID string `json:"id"`
			}
			Info struct {
				PID int `json:"pid"`
			}
		}
		if json.Unmarshal([]byte(raw), &c) != nil || c.Status.ID != id || c.Info.PID <= 1 {
			t.Fatal("CRI identity invalid")
		}
		l.save(fmt.Sprintf("%s-%s-process.json", containerName, signal), jsonText(map[string]any{"container_id": id, "pid": c.Info.PID, "signal": signal, "time": time.Now().UTC()}))
		l.must(l.run("", "limactl", "shell", "ztunnel-ebpf-amd64", "sudo", "kill", "-"+signal, fmt.Sprint(c.Info.PID)))
	}
	signals := []string{"TERM", "KILL"}
	if os.Getenv("ZC_FAULT_CASE") == "collector" {
		signals = nil
	}
	for _, signal := range signals {
		old := nodeBPF(l)
		oldLog := logs()
		count := strings.Count(oldLog, "node_capture_ready pid=")
		z := l.must(l.k("-n", "istio-system", "get", "pods", "-l", "app=ztunnel", "-o", "jsonpath={.items[0].metadata.name}"))
		signalPod("istio-system", z, "istio-proxy", signal)
		wait("ztunnel-"+signal, func() bool {
			s := logs()
			return strings.Count(s, "node_capture_ready pid=") > count && strings.Contains(s, "observer generation ended")
		})
		time.Sleep(6 * time.Second)
		current := nodeBPF(l)
		l.save("ztunnel-"+signal+"-bpf.json", jsonText(map[string]any{"old": old, "current": current}))
		if len(current) != 10 {
			t.Fatal("BPF count", current)
		}
		for _, a := range old {
			for _, b := range current {
				if a == b {
					t.Fatal("old resource retained", a)
				}
			}
		}
		traffic("ztunnel-" + signal)
	}
	for _, signal := range []string{"TERM", "KILL"} {
		old := nodeBPF(l)
		pod := l.must(l.k("-n", l.ns, "get", "pod", "-l", "app.kubernetes.io/instance=i14-node", "-o", "jsonpath={.items[0].metadata.name}"))
		signalPod(l.ns, pod, "collector", signal)
		wait("collector-"+signal, func() bool {
			s := logs()
			return strings.Contains(s, "node_targets count=3 ") && len(nodeBPF(l)) == 10 && !strings.Contains(s, "node_stopped")
		})
		// CRI restarts can be delayed; require the old IDs to disappear, not only Ready.
		wait("collector-resources-"+signal, func() bool {
			current := nodeBPF(l)
			for _, a := range old {
				for _, b := range current {
					if a == b {
						return false
					}
				}
			}
			return true
		})
		traffic("collector-" + signal)
	}

	l.save("final-pods.json", l.must(l.k("-n", l.ns, "get", "pods", "-o", "json")))
	t.Log("selected process fault cases completed: fresh capture, old objects released, marked pairs correct")
}
