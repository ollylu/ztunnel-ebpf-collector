package ambient

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
	"ztunnel-ebpf-collector/internal/replay"
)

// The test fails on reversed direction, missing/duplicated streams, taint
// crossing streams, payload/status mismatch, or attributing B's identity to A.
func TestNodeOutboundHTTP2Dapr(t *testing.T) {
	if os.Getenv("ZC_OUTBOUND_H2_LOCAL") != "1" {
		t.Skip("explicit isolated local HTTP2/Dapr outbound test")
	}
	for _, version := range []string{"1.14.5", "1.16.0"} {
		t.Run(version, func(t *testing.T) { testOutboundH2Dapr(t, version) })
	}
}
func testOutboundH2Dapr(t *testing.T, version string) {
	root, _ := filepath.Abs("../..")
	l := lab{t: t, root: root, kube: filepath.Join(root, ".local/k3s-kubeconfig"), source: os.Getenv("ZC_SOURCE_SHA"), ns: "collector-out-h2-" + strings.ReplaceAll(version, ".", "-")}
	if len(l.source) != 40 {
		t.Fatal("fixed SHA required")
	}
	// Unique evidence directory: failed runs must not be mixed into a later pass.
	parent := filepath.Join(root, ".local/outbound-h2", l.source)
	if err := os.MkdirAll(parent, 0700); err != nil {
		t.Fatal(err)
	}
	var err error
	l.evidence, err = os.MkdirTemp(parent, version+"-")
	if err != nil {
		t.Fatal(err)
	}
	t.Log("evidence", l.evidence)
	if l.must(l.k("config", "view", "--minify", "-o", "jsonpath={.clusters[0].cluster.server}")) != "https://127.0.0.1:16443" {
		t.Fatal("refuse non-local cluster")
	}
	if _, err := l.k("get", "ns", l.ns); err == nil {
		t.Fatal("refuse existing namespace")
	}
	if len(nodeBPF(l)) != 0 {
		t.Fatal("another probe active")
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
	setupPlaintextDaprVersion(l, version)
	l.must(l.k("-n", l.ns, "label", "pod/caller", "observe=yes"))
	l.pod("unselected", []any{container("app", "ztunnel-collector-h2:dapr-zt-native", "idle")}, nil)
	l.service("target-h2", "target", 8081)
	l.service("target-app", "target", 8082)
	h2VIP := l.must(l.k("-n", l.ns, "get", "svc/target-h2", "-o", "jsonpath={.spec.clusterIP}"))
	daprVIP := l.must(l.k("-n", l.ns, "get", "svc/target-dapr", "-o", "jsonpath={.spec.clusterIP}"))
	var caller struct {
		Metadata struct{ UID string }
		Status   struct{ PodIP string }
	}
	if err := json.Unmarshal([]byte(l.must(l.k("-n", l.ns, "get", "pod/caller", "-o", "json"))), &caller); err != nil {
		t.Fatal(err)
	}
	values := map[string]any{"syntheticReplay": false, "daemon": map[string]any{"enabled": true, "namespace": l.ns, "direction": "outbound", "selector": "observe=yes", "nodeSelector": map[string]string{"kubernetes.io/hostname": "collector-local"}}, "image": map[string]string{"repository": "ztunnel-ebpf-collector", "tag": l.source + "-amd64", "pullPolicy": "Never"}, "captureConfig": map[string]string{"markerHeader": "Debug-Token", "markerValue": "yes"}}
	b, _ := json.Marshal(values)
	vp := filepath.Join(t.TempDir(), "values.json")
	if err := os.WriteFile(vp, b, 0600); err != nil {
		t.Fatal(err)
	}
	release := "i6-h2"
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
			t.Fatal("caller target missing", body)
		}
		time.Sleep(time.Second)
	}
	l.must(l.k("-n", l.ns, "rollout", "status", "ds/"+release+"-node", "--timeout=40s"))
	initial := nodeBPF(l)
	if len(initial) != 10 {
		t.Fatal("unexpected probe count", initial)
	}
	started := time.Now()
	type call struct {
		name, pod string
		args      []string
	}
	calls := []call{
		{"h2-dns", "caller", []string{"http2-client", "http://target-h2." + l.ns + ".svc.cluster.local:8081"}},
		{"dapr-native", "caller", []string{"grpc-client-native", "127.0.0.1:50001", "target"}},
		{"unselected-h2", "unselected", []string{"http2-client", "http://target-h2." + l.ns + ".svc.cluster.local:8081"}},
		{"unselected-grpc", "unselected", []string{"grpc-client-native", "target-app." + l.ns + ".svc.cluster.local:8082"}},
	}
	type result struct {
		name, body string
		err        error
	}
	for round := 1; round <= 2; round++ {
		results := make(chan result, len(calls))
		for _, c := range calls {
			go func() { body, err := l.exec(c.pod, c.args...); results <- result{c.name, body, err} }()
		}
		for range calls {
			r := <-results
			l.save(fmt.Sprintf("round%d-%s.txt", round, r.name), r.body)
			if r.err != nil {
				l.save("capture.log", logs())
				t.Fatal(r.name, r.err, r.body)
			}
		}
		l.save(fmt.Sprintf("round%d-capture.log", round), logs())
		// Exercise retained inter-daprd HPACK state across refresh/watch rotations.
		if round == 1 {
			if remaining := 35*time.Second - time.Since(started); remaining > 0 {
				time.Sleep(remaining)
			}
		}
	}
	time.Sleep(time.Second)
	body := logs()
	l.save("capture.log", body)
	if strings.Contains(body, "node_stopped") {
		t.Fatal("protection trip", body)
	}
	pairs := map[string]map[string]replay.Record{}
	counts := map[string]int{}
	rpcConnections := map[string]bool{}
	for _, line := range strings.Split(body, "\n") {
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var r replay.Record
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatal(err)
		}
		if r.ObservationSide != "outbound" || r.PodName != "caller" || r.PodNamespace != l.ns || r.PodUID != caller.Metadata.UID || r.PodIP != caller.Status.PodIP || r.Client == nil || r.Client.UID != caller.Metadata.UID || r.Client.IP != caller.Status.PodIP || r.Client.Namespace != l.ns || r.Server == nil || r.Server.UID != "unknown" {
			t.Fatal("wrong caller identity or excluded Pod", r)
		}
		wantDest := h2VIP + ":8081"
		if r.Protocol == "gRPC" {
			wantDest = daprVIP + ":50002"
			rpcConnections[strings.TrimSuffix(r.RequestID, "-"+strconv.Itoa(int(r.StreamID)))] = true
		} else if r.Protocol != "HTTP/2" {
			t.Fatal("wrong protocol", r)
		}
		if r.OriginalDestination != wantDest || r.StreamID == 0 {
			t.Fatal("wrong service/stream", r)
		}
		if r.Direction != "request" && r.Direction != "response" {
			t.Fatal("wrong direction", r)
		}
		if pairs[r.RequestID] == nil {
			pairs[r.RequestID] = map[string]replay.Record{}
		}
		if _, exists := pairs[r.RequestID][r.Direction]; exists {
			t.Fatal("duplicate record", r)
		}
		pairs[r.RequestID][r.Direction] = r
		counts[r.Protocol]++
	}
	seen := map[string]int{}
	for _, pair := range pairs {
		req, ok := pair["request"]
		resp, okResp := pair["response"]
		if !ok || !okResp || req.StreamID != resp.StreamID || req.Protocol != resp.Protocol {
			t.Fatal("missing/cross-stream pair", pair)
		}
		if req.Protocol == "HTTP/2" {
			if req.Path != "/marked" || req.Method != "GET" || resp.Status != 200 || resp.Body != "cmVwbHk6L21hcmtlZA==" || resp.BodyEncoding != "base64" {
				t.Fatal("unmarked or wrong HTTP2 response", pair)
			}
			seen["h2"]++
			continue
		}
		if len(req.GRPCMessages) != 1 || req.Method != "POST" || resp.GRPCStatus == nil {
			t.Fatal("missing RPC metadata", pair)
		}
		name := ""
		path := "/grpc.health.v1.Health/Check"
		status := 0
		messages := []string{"CAE="}
		switch req.GRPCMessages[0] {
		case "CgZtYXJrZWQ=":
			name = "marked"
		case "CgVlcnJvcg==":
			name = "error"
			status = 5
			messages = nil
		case "CgZzdHJlYW0=":
			name = "stream"
			path = "/grpc.health.v1.Health/Watch"
			messages = []string{"CAE=", "CAI="}
		default:
			t.Fatal("unmarked or wrong protobuf request", pair)
		}
		if req.Path != path || *resp.GRPCStatus != status || !reflect.DeepEqual(resp.GRPCMessages, messages) {
			t.Fatal("incorrect RPC response pairing", pair)
		}
		seen[name]++
	}
	if counts["HTTP/2"] != 4 || counts["gRPC"] != 12 || len(pairs) != 8 || !reflect.DeepEqual(seen, map[string]int{"h2": 2, "marked": 2, "error": 2, "stream": 2}) {
		t.Fatal("missing/leaked records", counts, seen, len(pairs), body)
	}
	if len(rpcConnections) != 1 {
		t.Fatal("inter-daprd connection reuse not established", rpcConnections)
	}
	if jsonText(initial) != jsonText(nodeBPF(l)) {
		t.Fatal("probe resources changed")
	}
	raw := l.must(l.k("-n", l.ns, "get", "pods", "-l", "app.kubernetes.io/instance="+release+"-node", "-o", "json"))
	l.save("daemon-pod.json", raw)
	var pods struct {
		Items []struct {
			Status struct {
				ContainerStatuses []struct {
					RestartCount int
					ImageID      string
				}
			}
		}
	}
	if err := json.Unmarshal([]byte(raw), &pods); err != nil {
		t.Fatal(err)
	}
	expected, err := os.ReadFile(filepath.Join(root, "dist", l.source, "image-id.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if len(pods.Items) != 1 || len(pods.Items[0].Status.ContainerStatuses) != 1 || pods.Items[0].Status.ContainerStatuses[0].RestartCount != 0 || !strings.HasSuffix(pods.Items[0].Status.ContainerStatuses[0].ImageID, strings.TrimSpace(string(expected))) {
		t.Fatal("agent restart/duplication or wrong image", pods)
	}
	for _, role := range []string{"caller", "target"} {
		l.save(role+"-final-pod.json", l.must(l.k("-n", l.ns, "get", "pod", role, "-o", "json")))
		l.save(role+"-final-daprd.log", l.must(l.k("-n", l.ns, "logs", role, "-c", "daprd", "--tail=100")))
	}
	l.must(l.run("", "helm", "uninstall", release, "--kubeconfig", l.kube, "-n", l.ns, "--wait", "--timeout", "30s"))
	installed = false
	l.must(l.k("-n", l.ns, "wait", "--for=delete", "pod", "-l", "app.kubernetes.io/instance="+release+"-node", "--timeout=30s"))
	remaining := nodeBPF(l)
	l.save("objects-after-stop.json", jsonText(remaining))
	if len(remaining) != 0 {
		t.Fatal("leaked objects", remaining)
	}
	l.save("result.json", jsonText(map[string]any{"source": l.source, "dapr_version": version, "counts": counts, "pairs": len(pairs), "seen": seen, "rpc_connections": rpcConnections, "caller": caller, "h2_vip": h2VIP, "dapr_vip": daprVIP, "bpf_running": initial, "bpf_after_stop": remaining}))
	t.Logf("Dapr %s: 2 rounds, 8 pairs, HTTP2 Service DNS + native gRPC, retained inter-daprd connection; negatives silent; 10 BPF objects then zero", version)
}
