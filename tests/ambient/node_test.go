package ambient

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNodeDaemonLifecycle(t *testing.T) {
	if os.Getenv("ZC_NODE_LOCAL") != "1" {
		t.Skip("explicit isolated local DaemonSet test only")
	}
	root, _ := filepath.Abs("../..")
	l := lab{t: t, root: root, kube: filepath.Join(root, ".local/k3s-kubeconfig"), source: os.Getenv("ZC_SOURCE_SHA"), ns: "collector-node", evidence: filepath.Join(root, ".local/ports-e2e")}
	if len(l.source) != 40 {
		t.Fatal("fixed SHA required")
	}
	if err := os.MkdirAll(l.evidence, 0700); err != nil {
		t.Fatal(err)
	}
	if l.must(l.k("config", "view", "--minify", "-o", "jsonpath={.clusters[0].cluster.server}")) != "https://127.0.0.1:16443" {
		t.Fatal("refuse non-local cluster")
	}
	if _, err := l.k("get", "ns", l.ns); err == nil {
		t.Fatal("refuse existing namespace")
	}
	before := nodeBPF(l)
	if len(before) != 0 {
		t.Fatal("another collector probe already active")
	}
	l.save("baseline-pods.txt", l.must(l.k("get", "pods", "-A", "-o", "wide")))
	l.must(l.k("create", "ns", l.ns))
	t.Cleanup(func() {
		out, err := l.k("delete", "ns", l.ns, "--wait=true", "--timeout=50s")
		if err != nil {
			t.Error(out, err)
		}
	})
	l.must(l.k("label", "ns", l.ns, "istio.io/dataplane-mode=ambient"))
	policy := l.obj("PeerAuthentication", "permissive")
	policy["apiVersion"] = "security.istio.io/v1"
	policy["spec"] = map[string]any{"mtls": map[string]string{"mode": "PERMISSIVE"}}
	l.apply(policy)
	setupPlaintextDapr(l)
	l.must(l.k("-n", l.ns, "annotate", "pod/target", "collector.ztunnel.io/ports=50002"))
	l.must(l.k("-n", l.ns, "label", "pod/target", "observe=yes"))
	makeServer := func(name string, port int) {
		image := "ztunnel-collector-h2:dapr-zt-native"
		if name == "http1" || name == "portless" {
			image = "ztunnel-collector-traffic:i2"
		}
		c := container("app", image)
		if name == "portless" {
			c["securityContext"] = map[string]any{"runAsUser": 65532, "runAsNonRoot": true}
		}
		if port > 0 {
			c["ports"] = []any{map[string]any{"containerPort": port, "protocol": "TCP"}}
		}
		l.pod(name, []any{c}, nil)
	}
	makeServer("http1", 8080)
	makeServer("ignored", 8081)
	makeServer("portless", 0)
	l.must(l.k("-n", l.ns, "label", "pod/http1", "pod/portless", "observe=yes"))
	l.save("undeclared-port-pod.json", l.must(l.k("-n", l.ns, "get", "pod/portless", "-o", "json")))
	l.pod("h1-client", []any{container("app", "ztunnel-collector-traffic:i2", "idle")}, nil)
	extraTarget := 0
	unknownEnabled := os.Getenv("ZC_UNKNOWN_LOCAL") == "1"
	unknownAddr := ""
	if unknownEnabled {
		c := container("app", "ztunnel-collector-unknown:"+l.source)
		c["ports"] = []any{map[string]any{"containerPort": 9099, "protocol": "TCP"}}
		l.pod("unknown", []any{c}, nil)
		l.must(l.k("-n", l.ns, "label", "pod/unknown", "observe=yes"))
		l.pod("unknown-client", []any{container("app", "ztunnel-collector-unknown:"+l.source, "idle")}, nil)
		unknownAddr = l.must(l.k("-n", l.ns, "get", "pod/unknown", "-o", "jsonpath={.status.podIP}")) + ":9099"
		extraTarget = 1
	}
	values := map[string]any{"syntheticReplay": false, "daemon": map[string]any{"enabled": true, "namespace": l.ns, "selector": "observe=yes", "nodeSelector": map[string]string{"kubernetes.io/hostname": "collector-local"}}, "image": map[string]string{"repository": "ztunnel-ebpf-collector", "tag": l.source + "-amd64", "pullPolicy": "Never"}, "captureConfig": map[string]string{"markerHeader": "Debug-Token", "markerValue": "yes"}}
	b, _ := json.Marshal(values)
	vp := filepath.Join(t.TempDir(), "values.json")
	os.WriteFile(vp, b, 0600)
	release := "i5-node"
	l.must(l.run("", "helm", "install", release, filepath.Join(root, "dist", l.source, "ztunnel-ebpf-collector-0.1.0.tgz"), "--kubeconfig", l.kube, "-n", l.ns, "-f", vp))
	installed := true
	defer func() {
		if installed {
			out, err := l.run("", "helm", "uninstall", release, "--kubeconfig", l.kube, "-n", l.ns, "--wait", "--timeout", "30s")
			if err != nil {
				t.Error(out, err)
			}
		}
	}()
	logs := func() string { s, _ := l.k("-n", l.ns, "logs", "ds/"+release+"-node"); return s }
	waitTargets := func(count int) {
		t.Helper()
		count += extraTarget
		deadline := time.Now().Add(40 * time.Second)
		for {
			body := logs()
			at := strings.LastIndex(body, "node_targets count=")
			if at >= 0 && strings.HasPrefix(body[at:], fmt.Sprintf("node_targets count=%d ", count)) {
				return
			}
			if strings.Contains(body, "node_stopped") || time.Now().After(deadline) {
				l.save("capture.log", body)
				t.Fatal("target reconcile failed", count, body)
			}
			time.Sleep(time.Second)
		}
	}
	waitTargets(3)
	l.must(l.k("-n", l.ns, "rollout", "status", "ds/"+release+"-node", "--timeout=40s"))
	started := time.Now()
	initial := nodeBPF(l)
	l.save("objects-running.json", jsonText(initial))
	if len(initial) != 10 {
		t.Fatal("expected 2 programs, 6 maps, 2 links", initial)
	}
	var unknownDone chan error
	if unknownEnabled {
		unknownDone = make(chan error, 1)
		go func() {
			body, err := l.exec("unknown-client", "client", unknownAddr)
			l.save("unknown-client.txt", body)
			unknownDone <- err
		}()
		deadline := time.Now().Add(10 * time.Second)
		for !strings.Contains(logs(), "node_connections_rejected count=") {
			if time.Now().After(deadline) {
				t.Fatal("unknown rejection feedback missing", logs())
			}
			time.Sleep(100 * time.Millisecond)
		}
		time.Sleep(200 * time.Millisecond)
		raw := l.must(l.run("", "limactl", "shell", "ztunnel-ebpf-amd64", "sudo", "bpftool", "-j", "map", "dump", "name", "zc_suppressed"))
		l.save("suppressed-active.json", raw)
		var entries []any
		if err := json.Unmarshal([]byte(raw), &entries); err != nil || len(entries) != 1 {
			t.Fatal("kernel filter not installed", raw, err)
		}
		l.save("suppressed-map-info.json", l.must(l.run("", "limactl", "shell", "ztunnel-ebpf-amd64", "sudo", "bpftool", "-j", "map", "show", "name", "zc_suppressed")))
	}
	makeServer("http2", 8081)
	l.must(l.k("-n", l.ns, "label", "pod/http2", "observe=yes"))
	waitTargets(4)
	identities := map[string]map[string]string{}
	podIdentity := func(name string) (string, string) {
		raw := l.must(l.k("-n", l.ns, "get", "pod", name, "-o", "json"))
		var p struct {
			Metadata struct{ UID string }
			Status   struct{ PodIP string }
		}
		if err := json.Unmarshal([]byte(raw), &p); err != nil {
			t.Fatal(err)
		}
		if identities[name] == nil {
			identities[name] = map[string]string{}
		}
		identities[name][p.Metadata.UID] = p.Status.PodIP
		return p.Status.PodIP, p.Metadata.UID
	}
	ips := map[string]string{}
	for _, n := range []string{"http1", "http2", "target", "ignored", "portless"} {
		ips[n], _ = podIdentity(n)
	}
	round := func(n int) {
		for _, call := range []struct {
			name, pod string
			args      []string
		}{
			{"http1", "h1-client", []string{"client", "http://" + ips["http1"] + ":8080"}},
			{"portless", "h1-client", []string{"client", "http://" + ips["portless"] + ":8080"}},
			{"http2", "caller", []string{"http2-client", "http://" + ips["http2"] + ":8081"}},
			{"grpc", "caller", []string{"grpc-client-native", "127.0.0.1:50001", "target"}},
			{"ignored", "caller", []string{"http2-client", "http://" + ips["ignored"] + ":8081"}},
		} {
			out, err := l.exec(call.pod, call.args...)
			l.save(fmt.Sprintf("round%d-%s.txt", n, call.name), out)
			if err != nil {
				t.Fatal(out, err)
			}
		}
	}
	round(1)
	// Same agent and same inter-daprd connection survive several reconciliation
	// cycles and the old 30-second ceiling; no intentional connection reset.
	if remaining := 35*time.Second - time.Since(started); remaining > 0 {
		time.Sleep(remaining)
	}
	round(2)
	l.must(l.k("-n", l.ns, "label", "pod/http1", "observe-"))
	waitTargets(3)
	l.must(l.exec("h1-client", "client", "http://"+ips["http1"]+":8080"))
	l.must(l.k("-n", l.ns, "delete", "pod/http2", "--wait=true", "--timeout=30s"))
	waitTargets(2)
	makeServer("http2", 8081)
	l.must(l.k("-n", l.ns, "label", "pod/http2", "observe=yes"))
	ips["http2"], _ = podIdentity("http2")
	waitTargets(3)
	l.must(l.k("-n", l.ns, "label", "pod/http1", "observe=yes"))
	waitTargets(4)
	round(3)
	if unknownEnabled {
		if err := <-unknownDone; err != nil {
			t.Fatal("unknown business failed", err)
		}
		deadline := time.Now().Add(5 * time.Second)
		for {
			raw := l.must(l.run("", "limactl", "shell", "ztunnel-ebpf-amd64", "sudo", "bpftool", "-j", "map", "dump", "name", "zc_suppressed"))
			var entries []any
			if err := json.Unmarshal([]byte(raw), &entries); err != nil {
				t.Fatal(err)
			}
			if len(entries) == 0 {
				l.save("suppressed-after-close.json", raw)
				break
			}
			if time.Now().After(deadline) {
				l.save("capture.log", logs())
				t.Fatal("filter not reclaimed on close", raw)
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	time.Sleep(time.Second)
	body := logs()
	l.save("capture.log", body)
	if strings.Contains(body, "node_stopped") || !strings.Contains(body, "node_ports_discovered pod=collector-node/portless ports=[8080]") {
		t.Fatal("protection trip or missing listener discovery diagnostic", body)
	}
	counts := map[string]int{}
	pairs := map[string]int{}
	for _, line := range strings.Split(body, "\n") {
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var r map[string]any
		if json.Unmarshal([]byte(line), &r) != nil {
			t.Fatal("invalid record")
		}
		name, _ := r["pod_name"].(string)
		uid, _ := r["pod_uid"].(string)
		want := map[string]string{"http1": "HTTP/1.1", "portless": "HTTP/1.1", "http2": "HTTP/2", "target": "gRPC"}[name]
		if want == "" || r["protocol"] != want || r["pod_namespace"] != l.ns || r["pod_ip"] != identities[name][uid] {
			t.Fatal("unknown, excluded or stale Pod identity", r)
		}
		if name != "target" && r["direction"] == "request" && r["path"] != "/marked" {
			t.Fatal("unmarked HTTP output", r)
		}
		if name == "target" && r["direction"] == "request" {
			msgs, _ := r["grpc_messages"].([]any)
			if len(msgs) != 1 || (msgs[0] != "CgZtYXJrZWQ=" && msgs[0] != "CgVlcnJvcg==" && msgs[0] != "CgZzdHJlYW0=") {
				t.Fatal("unmarked or corrupt RPC", r)
			}
		}
		if name != "target" && r["direction"] == "response" {
			wantBody := "reply:/marked"
			if name == "http2" {
				wantBody = base64.StdEncoding.EncodeToString([]byte(wantBody))
			}
			if r["body"] != wantBody || r["status"] != float64(200) {
				t.Fatal("corrupt HTTP response", r)
			}
		}
		if name == "target" && r["direction"] == "response" {
			status, ok := r["grpc_status"].(float64)
			if !ok || (status != 0 && status != 5) {
				t.Fatal("corrupt RPC status", r)
			}
		}
		counts[name]++
		pairs[fmt.Sprint(r["request_id"])]++
	}
	if counts["portless"] != 6 || counts["http1"] != 6 || counts["http2"] != 6 || counts["target"] != 18 || len(pairs) != 18 {
		t.Fatal("missing, leaked or duplicate records", counts, len(pairs), body)
	}
	for id, n := range pairs {
		if n != 2 {
			t.Fatal("cross-pair", id, n)
		}
	}
	if len(identities["http2"]) != 2 {
		t.Fatal("Pod replacement not exercised")
	}
	after := nodeBPF(l)
	l.save("objects-after-lifecycle.json", jsonText(after))
	if jsonText(initial) != jsonText(after) {
		t.Fatal("probe resources changed across target updates")
	}
	podState := l.must(l.k("-n", l.ns, "get", "pods", "-l", "app.kubernetes.io/instance="+release+"-node", "-o", "json"))
	l.save("daemon-pod.json", podState)
	var dsPods struct {
		Items []struct {
			Status struct {
				ContainerStatuses []struct {
					RestartCount int
					ImageID      string
				}
			}
		}
	}
	json.Unmarshal([]byte(podState), &dsPods)
	if len(dsPods.Items) != 1 || len(dsPods.Items[0].Status.ContainerStatuses) != 1 || dsPods.Items[0].Status.ContainerStatuses[0].RestartCount != 0 {
		t.Fatal("agent restarted or duplicated")
	}
	l.must(l.run("", "helm", "uninstall", release, "--kubeconfig", l.kube, "-n", l.ns, "--wait", "--timeout", "30s"))
	installed = false
	l.must(l.k("-n", l.ns, "wait", "--for=delete", "pod", "-l", "app.kubernetes.io/instance="+release+"-node", "--timeout=30s"))
	remaining := nodeBPF(l)
	l.save("objects-after-stop.json", jsonText(remaining))
	if len(remaining) != 0 {
		t.Fatal("BPF resources leaked", remaining)
	}
	t.Logf("one DaemonSet agent, duration=%s, 3 rounds/18 pairs: %v; dynamic add/delete/recreate/relabel; 10 stable BPF objects then zero", time.Since(started).Round(time.Second), counts)
}

func jsonText(v any) string { b, _ := json.MarshalIndent(v, "", "  "); return string(b) }
func nodeBPF(l lab) []string {
	var result []string
	progs := map[float64]bool{}
	for _, kind := range []string{"prog", "map", "link"} {
		raw := l.must(l.run("", "limactl", "shell", "ztunnel-ebpf-amd64", "sudo", "bpftool", "-j", kind, "show"))
		var objs []map[string]any
		if err := json.Unmarshal([]byte(raw), &objs); err != nil {
			l.t.Fatal(err)
		}
		for _, o := range objs {
			name, _ := o["name"].(string)
			selected := strings.HasPrefix(name, "zc_")
			if kind == "link" {
				id, _ := o["prog_id"].(float64)
				selected = progs[id]
			}
			if selected {
				result = append(result, fmt.Sprintf("%s:%v", kind, o["id"]))
				if kind == "prog" {
					id, _ := o["id"].(float64)
					progs[id] = true
				}
			}
		}
	}
	return result
}
