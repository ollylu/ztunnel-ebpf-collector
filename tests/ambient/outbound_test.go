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

func TestNodeOutboundCaller(t *testing.T) {
	if os.Getenv("ZC_OUTBOUND_LOCAL") != "1" {
		t.Skip("explicit isolated local outbound test only")
	}
	root, _ := filepath.Abs("../..")
	l := lab{t: t, root: root, kube: filepath.Join(root, ".local/k3s-kubeconfig"), source: os.Getenv("ZC_SOURCE_SHA"), ns: "collector-out-a", evidence: filepath.Join(root, ".local/outbound-e2e")}
	if len(l.source) != 40 {
		t.Fatal("fixed SHA required")
	}
	if err := os.MkdirAll(l.evidence, 0700); err != nil {
		t.Fatal(err)
	}
	if l.must(l.k("config", "view", "--minify", "-o", "jsonpath={.clusters[0].cluster.server}")) != "https://127.0.0.1:16443" {
		t.Fatal("refuse non-local cluster")
	}
	if len(nodeBPF(l)) != 0 {
		t.Fatal("another collector already active")
	}
	namespaces := []string{l.ns, "collector-out-b", "collector-out-c"}
	for _, ns := range namespaces {
		if _, err := l.k("get", "ns", ns); err == nil {
			t.Fatal("refuse existing namespace", ns)
		}
	}
	l.save("baseline-pods.txt", l.must(l.k("get", "pods", "-A", "-o", "wide")))
	identities := map[string]struct{ IP, UID string }{}
	for _, ns := range namespaces {
		n := l
		n.ns = ns
		n.must(n.k("create", "ns", ns))
		t.Cleanup(func() {
			out, err := n.k("delete", "ns", n.ns, "--wait=true", "--timeout=50s")
			if err != nil {
				t.Error(out, err)
			}
		})
		n.must(n.k("label", "ns", ns, "istio.io/dataplane-mode=ambient"))
		policy := n.obj("PeerAuthentication", "permissive")
		policy["apiVersion"] = "security.istio.io/v1"
		policy["spec"] = map[string]any{"mtls": map[string]string{"mode": "PERMISSIVE"}}
		n.apply(policy)
		c := container("app", "ztunnel-collector-traffic:i2", "idle")
		if ns == namespaces[1] {
			c = container("app", "ztunnel-collector-traffic:i2")
			c["ports"] = []any{map[string]any{"containerPort": 8080}}
		}
		n.pod("same-name", []any{c}, nil)
		n.must(n.k("-n", ns, "label", "pod/same-name", "observe=yes"))
		var p struct {
			Metadata struct{ UID string }
			Status   struct{ PodIP string }
		}
		if err := json.Unmarshal([]byte(n.must(n.k("-n", ns, "get", "pod/same-name", "-o", "json"))), &p); err != nil {
			t.Fatal(err)
		}
		identities[ns] = struct{ IP, UID string }{p.Status.PodIP, p.Metadata.UID}
	}
	// A and C are clients with no declared ports and no listening sockets.
	l.save("caller-pod.json", l.must(l.k("-n", l.ns, "get", "pod/same-name", "-o", "json")))
	l.pod("unselected", []any{container("app", "ztunnel-collector-traffic:i2", "idle")}, nil)
	bLab := l
	bLab.ns = namespaces[1]
	bLab.service("backend", "same-name", 8080)
	vip := bLab.must(bLab.k("-n", bLab.ns, "get", "svc/backend", "-o", "jsonpath={.spec.clusterIP}"))
	destinations := []string{identities[namespaces[1]].IP + ":8080", vip + ":8080"}
	values := map[string]any{"syntheticReplay": false, "daemon": map[string]any{"enabled": true, "namespaces": namespaces[:1], "direction": "outbound", "selector": "observe=yes", "nodeSelector": map[string]string{"kubernetes.io/hostname": "collector-local"}}, "image": map[string]string{"repository": "ztunnel-ebpf-collector", "tag": l.source + "-amd64", "pullPolicy": "Never"}, "captureConfig": map[string]string{"markerHeader": "Debug-Token", "markerValue": "yes"}}
	vp := filepath.Join(t.TempDir(), "values.json")
	b, _ := json.Marshal(values)
	if err := os.WriteFile(vp, b, 0600); err != nil {
		t.Fatal(err)
	}
	release := "i6-outbound"
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
	deadline := time.Now().Add(45 * time.Second)
	for {
		body := logs()
		at := strings.LastIndex(body, "node_targets count=")
		if at >= 0 && strings.HasPrefix(body[at:], "node_targets count=1 ") {
			break
		}
		if strings.Contains(body, "node_stopped") || time.Now().After(deadline) {
			l.save("capture.log", body)
			t.Fatal("expected one outbound caller target", body)
		}
		time.Sleep(time.Second)
	}
	l.must(l.k("-n", l.ns, "rollout", "status", "ds/"+release+"-node", "--timeout=40s"))
	initial := nodeBPF(l)
	if len(initial) != 10 {
		t.Fatal("unexpected probe count", initial)
	}
	for round := 0; round < 2; round++ {
		for _, dest := range destinations {
			out := l.must(l.exec("same-name", "client", "http://"+dest))
			l.save(fmt.Sprintf("round%d-%s.txt", round, strings.ReplaceAll(dest, ":", "-")), out)
		}
		cLab := l
		cLab.ns = namespaces[2]
		l.save(fmt.Sprintf("round%d-excluded-caller.txt", round), cLab.must(cLab.exec("same-name", "client", "http://"+destinations[0])))
		l.save(fmt.Sprintf("round%d-unselected.txt", round), l.must(l.exec("unselected", "client", "http://"+destinations[0])))
	}
	time.Sleep(time.Second)
	body := logs()
	l.save("capture.log", body)
	if strings.Contains(body, "node_stopped") {
		t.Fatal("protection trip", body)
	}
	counts := map[string]int{}
	pairs := map[string]int{}
	for _, line := range strings.Split(body, "\n") {
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var r map[string]any
		if json.Unmarshal([]byte(line), &r) != nil {
			t.Fatal("invalid output")
		}
		ns, _ := r["pod_namespace"].(string)
		id, ok := identities[ns]
		if !ok || ns != namespaces[0] || r["pod_name"] != "same-name" || r["pod_ip"] != id.IP || r["pod_uid"] != id.UID || r["protocol"] != "HTTP/1.1" {
			t.Fatal("excluded or mixed identity", r)
		}
		client, _ := r["client"].(map[string]any)
		server, _ := r["server"].(map[string]any)
		if r["observation_side"] != "outbound" || client["uid"] != id.UID || client["ip"] != id.IP || client["namespace"] != ns || server["uid"] != "unknown" {
			t.Fatal("wrong endpoint role", r)
		}
		dest, _ := r["original_destination"].(string)
		if dest != destinations[0] && dest != destinations[1] {
			t.Fatal("missing or fabricated original destination", r)
		}
		counts[dest]++
		switch r["direction"] {
		case "request":
			if r["path"] != "/marked" {
				t.Fatal("unmarked output", r)
			}
		case "response":
			if r["body"] != "reply:/marked" || r["status"] != float64(200) {
				t.Fatal("bad response", r)
			}
		default:
			t.Fatal("unknown direction", r)
		}
		counts[ns]++
		pairs[fmt.Sprint(r["request_id"])]++
	}
	if counts[namespaces[0]] != 8 || counts[destinations[0]] != 4 || counts[destinations[1]] != 4 || len(pairs) != 4 {
		t.Fatal("missing or duplicate records", counts, pairs, body)
	}
	for _, n := range pairs {
		if n != 2 {
			t.Fatal("incorrect pairing", pairs)
		}
	}
	if jsonText(initial) != jsonText(nodeBPF(l)) {
		t.Fatal("probe resources changed")
	}
	raw := l.must(l.k("-n", l.ns, "get", "pods", "-l", "app.kubernetes.io/instance="+release+"-node", "-o", "json"))
	l.save("daemon-pod.json", raw)
	var pods struct {
		Items []struct {
			Status struct{ ContainerStatuses []struct{ RestartCount int } }
		}
	}
	if err := json.Unmarshal([]byte(raw), &pods); err != nil {
		t.Fatal(err)
	}
	if len(pods.Items) != 1 || len(pods.Items[0].Status.ContainerStatuses) != 1 || pods.Items[0].Status.ContainerStatuses[0].RestartCount != 0 {
		t.Fatal("agent duplicated or restarted")
	}
	l.must(l.run("", "helm", "uninstall", release, "--kubeconfig", l.kube, "-n", l.ns, "--wait", "--timeout", "30s"))
	installed = false
	l.must(l.k("-n", l.ns, "wait", "--for=delete", "pod", "-l", "app.kubernetes.io/instance="+release+"-node", "--timeout=30s"))
	remaining := nodeBPF(l)
	l.save("objects-after-stop.json", jsonText(remaining))
	if len(remaining) != 0 {
		t.Fatal("leaked objects", remaining)
	}
	l.save("result.json", jsonText(map[string]any{"source": l.source, "counts": counts, "pairs": len(pairs), "identities": identities, "bpf_running": initial, "bpf_after_stop": remaining}))
	t.Logf("one agent, caller A only/no listener, B excluded, PodIP + Service VIP, 4 marked pairs; excluded caller/unselected Pod/unmarked requests: zero; 10 BPF objects then zero")
}
