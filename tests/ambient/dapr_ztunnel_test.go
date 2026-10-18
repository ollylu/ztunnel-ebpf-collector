package ambient

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDaprPlaintextViaZtunnel rejects missing records, hidden-request leakage,
// cross-stream responses and incorrect Pod attribution on the real proxy path.
// Standalone daprd in Kubernetes Pods exercises the data plane without adding
// a Dapr control plane. This is not a production Kubernetes-mode acceptance.
func TestDaprPlaintextViaZtunnel(t *testing.T) {
	if os.Getenv("ZC_DAPR_ZTUNNEL_LOCAL") != "1" {
		t.Skip("explicit isolated local Dapr/ztunnel test only")
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	l := lab{t: t, root: root, kube: filepath.Join(root, ".local/k3s-kubeconfig"), source: os.Getenv("ZC_SOURCE_SHA"), ns: "collector-dapr-zt", evidence: filepath.Join(root, ".local/dapr-ztunnel")}
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
			t.Errorf("cleanup failed: %v %s", err, out)
		}
	})
	l.must(l.k("label", "ns", l.ns, "istio.io/dataplane-mode=ambient"))
	policy := l.obj("PeerAuthentication", "permissive")
	policy["apiVersion"] = "security.istio.io/v1"
	policy["spec"] = map[string]any{"mtls": map[string]string{"mode": "PERMISSIVE"}}
	l.apply(policy)
	l.save("policy.json", l.must(l.k("-n", l.ns, "get", "peerauthentication", "permissive", "-o", "json")))
	setupPlaintextDapr(l)
	// No warm-up calls: capture must precede the first inter-daprd HTTP/2
	// connection. The existing collector cannot reconstruct midstream HPACK.
	l.capture("dapr-zt", "target", "ztunnel", 50002, func() string {
		return l.must(l.exec("caller", "grpc-client-native", "127.0.0.1:50001", "target"))
	}, 6)
	data, err := os.ReadFile(filepath.Join(l.evidence, "dapr-zt-capture.log"))
	if err != nil {
		t.Fatal(err)
	}
	var records []map[string]any
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "{") {
			var r map[string]any
			if err := json.Unmarshal([]byte(line), &r); err != nil {
				t.Fatal(err)
			}
			records = append(records, r)
		}
	}
	seen := map[string]bool{}
	for i := 0; i < len(records); i += 2 {
		req, resp := records[i], records[i+1]
		msgs, ok := req["grpc_messages"].([]any)
		if !ok || len(msgs) != 1 {
			t.Fatalf("missing request message: %v", req)
		}
		payload, err := base64.StdEncoding.DecodeString(msgs[0].(string))
		if err != nil || len(payload) < 2 || payload[0] != 10 || int(payload[1]) != len(payload)-2 {
			t.Fatalf("invalid health request: %x %v", payload, err)
		}
		name := string(payload[2:])
		wantPath, wantStatus := "/grpc.health.v1.Health/Check", float64(0)
		wantMessages := []string{"CAE="} // HealthCheckResponse{SERVING}
		switch name {
		case "marked":
		case "error":
			wantStatus, wantMessages = 5, nil
		case "stream":
			wantPath, wantMessages = "/grpc.health.v1.Health/Watch", []string{"CAE=", "CAI="}
		default:
			t.Fatalf("unexpected or unmarked request: %q", name)
		}
		if seen[name] || req["path"] != wantPath || resp["grpc_status"] != wantStatus || req["stream_id"] != resp["stream_id"] {
			t.Fatalf("duplicate or cross-stream response for %s: %v %v", name, req, resp)
		}
		seen[name] = true
		actual, _ := resp["grpc_messages"].([]any)
		if len(actual) != len(wantMessages) {
			t.Fatalf("%s response messages: %v", name, actual)
		}
		for j, want := range wantMessages {
			if actual[j] != want {
				t.Fatalf("%s response bytes: %v", name, actual)
			}
		}
	}
	if len(seen) != 3 {
		t.Fatalf("missing marked RPCs: %v", seen)
	}
}

func setupPlaintextDapr(l lab) { setupPlaintextDaprVersion(l, "1.14.5") }

func setupPlaintextDaprVersion(l lab, version string) {
	cm := l.obj("ConfigMap", "config")
	cm["data"] = map[string]string{"config.yaml": "apiVersion: dapr.io/v1alpha1\nkind: Configuration\nmetadata:\n  name: test\nspec:\n  mtls:\n    enabled: false\n  nameResolution:\n    component: kubernetes\n    version: v1\n  tracing:\n    samplingRate: '0'\n"}
	l.apply(cm)
	for _, role := range []string{"target", "caller"} {
		args := []string{"--mode", "standalone", "--app-id", role, "--dapr-grpc-port", "50001", "--dapr-internal-grpc-port", "50002", "--config", "/config/config.yaml", "--enable-mtls=false", "--placement-host-address", "", "--scheduler-host-address", ""}
		if role == "target" {
			args = append(args, "--app-port", "8082", "--app-protocol", "grpc")
		}
		dp := container("daprd", "daprio/daprd:"+version, args...)
		dp["command"] = []string{"/daprd"}
		dp["env"] = []any{map[string]string{"name": "NAMESPACE", "value": l.ns}}
		dp["volumeMounts"] = []any{map[string]any{"name": "config", "mountPath": "/config"}}
		dp["readinessProbe"] = map[string]any{"httpGet": map[string]any{"path": "/v1.0/healthz/outbound", "port": 3500}, "periodSeconds": 2}
		app := container("app", "ztunnel-collector-h2:dapr-zt-native")
		if role == "caller" {
			app["args"] = []string{"idle"}
		}
		l.pod(role, []any{app, dp}, []any{map[string]any{"name": "config", "configMap": map[string]string{"name": "config"}}})
		l.save(role+"-pod.json", l.must(l.k("-n", l.ns, "get", "pod", role, "-o", "json")))
		l.save(role+"-daprd.log", l.must(l.k("-n", l.ns, "logs", role, "-c", "daprd", "--tail=100")))
	}
	l.service("target-dapr", "target", 50002)
}
