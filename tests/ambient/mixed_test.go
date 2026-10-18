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

// One packaged collector, one ztunnel, multiple real Pod endpoints; no protocol
// hints. Unexpected protocol, identity, duplicate, hidden or excluded output fails.
func TestMixedPodProtocols(t *testing.T) {
	if os.Getenv("ZC_MIXED_LOCAL") != "1" {
		t.Skip("explicit isolated local mixed-protocol test only")
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	l := lab{t: t, root: root, kube: filepath.Join(root, ".local/k3s-kubeconfig"), source: os.Getenv("ZC_SOURCE_SHA"), ns: "collector-mixed", evidence: filepath.Join(root, ".local/mixed-e2e")}
	if len(l.source) != 40 {
		t.Fatal("fixed collector SHA required")
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
	l.must(l.k("create", "ns", l.ns))
	t.Cleanup(func() {
		out, err := l.k("delete", "ns", l.ns, "--wait=true", "--timeout=50s")
		if err != nil {
			t.Errorf("cleanup: %v %s", err, out)
		}
	})
	l.must(l.k("label", "ns", l.ns, "istio.io/dataplane-mode=ambient"))
	policy := l.obj("PeerAuthentication", "permissive")
	policy["apiVersion"] = "security.istio.io/v1"
	policy["spec"] = map[string]any{"mtls": map[string]string{"mode": "PERMISSIVE"}}
	l.apply(policy)
	setupPlaintextDapr(l)
	for _, name := range []string{"http1", "http2", "ignored"} {
		image := "ztunnel-collector-h2:dapr-zt-native"
		if name == "http1" {
			image = "ztunnel-collector-traffic:i2"
		}
		l.pod(name, []any{container("app", image)}, nil)
	}
	l.pod("h1-client", []any{container("app", "ztunnel-collector-traffic:i2", "idle")}, nil)
	snapshot := l.must(l.k("get", "pods", "-A", "-o", "json"))
	l.save("pods.json", snapshot)
	var list struct {
		Items []struct {
			Metadata struct{ Name, Namespace, UID string }
			Status   struct{ PodIP string }
		}
	}
	if err := json.Unmarshal([]byte(snapshot), &list); err != nil {
		t.Fatal(err)
	}
	ips, uids := map[string]string{}, map[string]string{}
	for _, p := range list.Items {
		if p.Metadata.Namespace == l.ns {
			ips[p.Metadata.Name] = p.Status.PodIP
			uids[p.Metadata.Name] = p.Metadata.UID
		}
	}
	values := map[string]any{"capture": true, "syntheticReplay": false, "image": map[string]string{"repository": "ztunnel-ebpf-collector", "tag": l.source + "-amd64", "pullPolicy": "Never"}, "captureConfig": map[string]any{"source": "ztunnel", "node": "collector-local", "targets": []string{l.ns + "/http1:8080", l.ns + "/http2:8081", l.ns + "/target:50002"}, "markerHeader": "Debug-Token", "markerValue": "yes", "duration": "30s", "podList": snapshot}}
	b, _ := json.Marshal(values)
	vp := filepath.Join(t.TempDir(), "values.json")
	if err := os.WriteFile(vp, b, 0600); err != nil {
		t.Fatal(err)
	}
	release := "i4-mixed"
	l.must(l.run("", "helm", "install", release, filepath.Join(root, "dist", l.source, "ztunnel-ebpf-collector-0.1.0.tgz"), "--kubeconfig", l.kube, "-n", l.ns, "-f", vp))
	defer func() {
		out, err := l.run("", "helm", "uninstall", release, "--kubeconfig", l.kube, "-n", l.ns, "--wait", "--timeout", "30s")
		if err != nil {
			t.Errorf("uninstall: %v %s", err, out)
		}
	}()
	job := "job/" + release + "-capture"
	deadline := time.Now().Add(25 * time.Second)
	for {
		logs, _ := l.k("-n", l.ns, "logs", job)
		if strings.Contains(logs, "capture_ready") {
			if !strings.Contains(logs, "source=ztunnel targets=3") {
				t.Fatal("wrong capture scope", logs)
			}
			break
		}
		if time.Now().After(deadline) {
			l.save("capture.log", logs)
			t.Fatal("probe not ready", logs)
		}
		time.Sleep(time.Second)
	}
	type result struct {
		name, out string
		err       error
	}
	results := make(chan result, 4)
	for _, call := range []struct {
		name, pod string
		args      []string
	}{
		{"http1", "h1-client", []string{"client", "http://" + ips["http1"] + ":8080"}},
		{"http2", "caller", []string{"http2-client", "http://" + ips["http2"] + ":8081"}},
		{"grpc", "caller", []string{"grpc-client-native", "127.0.0.1:50001", "target"}},
		{"ignored", "caller", []string{"http2-client", "http://" + ips["ignored"] + ":8081"}},
	} {
		go func() { out, err := l.exec(call.pod, call.args...); results <- result{call.name, out, err} }()
	}
	for i := 0; i < 4; i++ {
		r := <-results
		l.save(r.name+"-client.txt", r.out)
		if r.err != nil {
			t.Errorf("%s traffic: %v %s", r.name, r.err, r.out)
		}
	}
	out, err := l.k("-n", l.ns, "wait", job, "--for=condition=Complete", "--timeout=40s")
	logs := l.must(l.k("-n", l.ns, "logs", job))
	l.save("capture.log", logs)
	l.save("capture-pod.json", l.must(l.k("-n", l.ns, "get", "pods", "-l", "job-name="+release+"-capture", "-o", "json")))
	if err != nil {
		t.Fatalf("capture failed: %v %s\n%s", err, out, logs)
	}
	counts := map[string]int{}
	pairs := map[string][]map[string]any{}
	for _, line := range strings.Split(logs, "\n") {
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var r map[string]any
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatal(err)
		}
		pod, _ := r["pod_name"].(string)
		want := map[string]string{"http1": "HTTP/1.1", "http2": "HTTP/2", "target": "gRPC"}[pod]
		if want == "" || r["protocol"] != want || r["pod_namespace"] != l.ns || r["pod_ip"] != ips[pod] || r["pod_uid"] != uids[pod] {
			t.Fatalf("wrong protocol/Pod or excluded leakage: %v", r)
		}
		id, ok := r["request_id"].(string)
		if !ok {
			t.Fatal("missing identity")
		}
		pairs[id] = append(pairs[id], r)
		counts[pod]++
	}
	if counts["http1"] != 2 || counts["http2"] != 2 || counts["target"] != 6 || len(pairs) != 5 {
		t.Fatal("missing/duplicate pairs", counts, len(pairs))
	}
	grpcSeen := map[string]bool{}
	for id, pair := range pairs {
		if len(pair) != 2 || pair[0]["direction"] != "request" || pair[1]["direction"] != "response" || pair[0]["pod_uid"] != pair[1]["pod_uid"] || pair[0]["protocol"] != pair[1]["protocol"] || pair[0]["stream_id"] != pair[1]["stream_id"] {
			t.Fatalf("cross-pair %s: %v", id, pair)
		}
		req, resp := pair[0], pair[1]
		if req["protocol"] != "gRPC" {
			want := "reply:/marked"
			if req["protocol"] == "HTTP/2" {
				want = base64.StdEncoding.EncodeToString([]byte(want))
			}
			if req["path"] != "/marked" || resp["body"] != want {
				t.Fatalf("hidden or corrupt HTTP pair: %v", pair)
			}
			continue
		}
		msgs, ok := req["grpc_messages"].([]any)
		if !ok || len(msgs) != 1 {
			t.Fatal("missing RPC request")
		}
		raw, err := base64.StdEncoding.DecodeString(fmt.Sprint(msgs[0]))
		if err != nil || len(raw) < 2 || raw[0] != 10 || int(raw[1]) != len(raw)-2 {
			t.Fatal("invalid RPC bytes")
		}
		name := string(raw[2:])
		status, path := float64(0), "/grpc.health.v1.Health/Check"
		expected := []string{"CAE="}
		switch name {
		case "marked":
		case "error":
			status = 5
			expected = nil
		case "stream":
			path = "/grpc.health.v1.Health/Watch"
			expected = []string{"CAE=", "CAI="}
		default:
			t.Fatal("hidden RPC leaked", name)
		}
		if grpcSeen[name] || resp["grpc_status"] != status || req["path"] != path {
			t.Fatal("RPC cross-pair", pair)
		}
		grpcSeen[name] = true
		actual, _ := resp["grpc_messages"].([]any)
		if len(actual) != len(expected) {
			t.Fatal("missing RPC response")
		}
		for i, want := range expected {
			if actual[i] != want {
				t.Fatal("wrong RPC response", pair)
			}
		}
	}
	t.Logf("one collector, 3 targets: HTTP1=%d HTTP2=%d gRPC=%d records; 5 correct pairs; hidden/excluded=0", counts["http1"], counts["http2"], counts["target"])
}
