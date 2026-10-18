package ambient

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Explicit opt-in: only the project's disposable localhost cluster, never ACK/EKS.
// A regression that drops plaintext ztunnel IO, leaks unmarked pairs, or loses
// server identity must fail this test against real sockets and a packaged Chart.
func TestPermissiveInbound(t *testing.T) {
	if os.Getenv("ZC_AMBIENT_LOCAL") != "1" {
		t.Skip("requires dedicated local Ambient cluster")
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	kube := filepath.Join(root, ".local/k3s-kubeconfig")
	source := "b014cb32ef78af3af80ac9d246612b602cb73ffc"
	chart := filepath.Join(root, "dist", source, "ztunnel-ebpf-collector-0.1.0.tgz")
	evidence := filepath.Join(root, ".local/permissive")
	if err := os.MkdirAll(evidence, 0700); err != nil {
		t.Fatal(err)
	}
	run := func(input string, name string, args ...string) (string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, name, args...)
		if input != "" {
			cmd.Stdin = strings.NewReader(input)
		}
		b, e := cmd.CombinedOutput()
		return string(b), e
	}
	k := func(args ...string) (string, error) {
		return run("", "kubectl", append([]string{"--kubeconfig", kube, "--request-timeout=10s"}, args...)...)
	}
	must := func(out string, e error) string {
		t.Helper()
		if e != nil {
			t.Fatalf("command: %v: %s", e, out)
		}
		return out
	}
	save := func(name, text string) {
		t.Helper()
		if e := os.WriteFile(filepath.Join(evidence, name), []byte(text), 0600); e != nil {
			t.Fatal(e)
		}
	}
	endpoint := must(k("config", "view", "--minify", "-o", "jsonpath={.clusters[0].cluster.server}"))
	if endpoint != "https://127.0.0.1:16443" {
		t.Fatalf("refuse non-local cluster %q", endpoint)
	}
	must(k("get", "node", "collector-local"))
	oldMode := must(k("-n", "collector-lab", "get", "peerauthentication", "collector-strict", "-o", "jsonpath={.spec.mtls.mode}"))
	if oldMode != "STRICT" {
		t.Fatalf("expected isolated STRICT baseline, found %q", oldMode)
	}
	serverJSON := must(k("-n", "collector-lab", "get", "pod", "server", "-o", "json"))
	var server struct {
		Metadata struct{ UID string }
		Status   struct{ PodIP string }
	}
	if e := json.Unmarshal([]byte(serverJSON), &server); e != nil {
		t.Fatal(e)
	}
	if server.Status.PodIP == "" || server.Metadata.UID == "" {
		t.Fatal("server identity missing")
	}
	const plainNS = "collector-permissive-client"
	if _, e := k("get", "namespace", plainNS); e == nil {
		t.Fatal("test namespace already exists; refusing reuse")
	}
	must(k("create", "namespace", plainNS))
	t.Cleanup(func() {
		out, e := k("delete", "namespace", plainNS, "--wait=false")
		if e != nil {
			t.Errorf("cleanup namespace: %v %s", e, out)
		}
	})
	fixture := `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"client","namespace":"collector-permissive-client"},"spec":{"nodeName":"collector-local","automountServiceAccountToken":false,"restartPolicy":"Never","containers":[{"name":"client","image":"ztunnel-collector-traffic:i2","imagePullPolicy":"Never","args":["idle"],"resources":{"requests":{"cpu":"10m","memory":"16Mi"},"limits":{"cpu":"200m","memory":"64Mi"}}}]}}`
	must(run(fixture, "kubectl", "--kubeconfig", kube, "apply", "-f", "-"))
	must(k("-n", plainNS, "wait", "pod/client", "--for=condition=Ready", "--timeout=60s"))
	save("plaintext-client.json", must(k("-n", plainNS, "get", "pod", "client", "-o", "json")))
	// Negative control proves the source does not get mesh mTLS automatically.
	traffic := func(ns string) (string, error) {
		return k("-n", ns, "exec", "client", "--", "/traffic", "client", "http://"+server.Status.PodIP+":8080")
	}
	rejected, e := traffic(plainNS)
	save("strict-plaintext-negative.txt", rejected)
	if e == nil || (!strings.Contains(rejected, "EOF") && !strings.Contains(rejected, "reset by peer")) {
		t.Fatalf("STRICT plaintext negative not established: %v %s", e, rejected)
	}
	t.Cleanup(func() {
		out, e := k("-n", "collector-lab", "patch", "peerauthentication", "collector-strict", "--type=merge", "-p", `{"spec":{"mtls":{"mode":"STRICT"}}}`)
		if e != nil {
			t.Errorf("restore STRICT: %v %s", e, out)
		}
	})
	must(k("-n", "collector-lab", "patch", "peerauthentication", "collector-strict", "--type=merge", "-p", `{"spec":{"mtls":{"mode":"PERMISSIVE"}}}`))
	save("policy.json", must(k("-n", "collector-lab", "get", "peerauthentication", "collector-strict", "-o", "json")))
	// Wait for actual policy propagation; finite, tiny fixture load, no probe yet.
	deadline := time.Now().Add(15 * time.Second)
	for {
		out, e := traffic(plainNS)
		if e == nil && strings.Contains(out, "/unmarked 200") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("PERMISSIVE not effective: %v %s", e, out)
		}
		time.Sleep(time.Second)
	}
	for _, tc := range []struct{ name, ns string }{{"mesh-mtls", "collector-lab"}, {"plaintext", plainNS}} {
		t.Run(tc.name, func(t *testing.T) {
			start := time.Now().UTC().Format(time.RFC3339)
			release := "collector-perm-" + tc.name
			pods := must(k("get", "pods", "-A", "-o", "json"))
			values := map[string]any{"capture": true, "syntheticReplay": false, "image": map[string]any{"repository": "ztunnel-ebpf-collector", "tag": source + "-amd64", "pullPolicy": "Never"}, "captureConfig": map[string]any{"node": "collector-local", "server": "collector-lab/server", "port": 8080, "markerHeader": "Debug-Token", "markerValue": "yes", "duration": "30s", "podList": pods}}
			vb, e := json.Marshal(values)
			if e != nil {
				t.Fatal(e)
			}
			path := filepath.Join(t.TempDir(), "values.json")
			if e := os.WriteFile(path, vb, 0600); e != nil {
				t.Fatal(e)
			}
			must(run("", "helm", "install", release, chart, "--kubeconfig", kube, "-n", "collector-i2", "-f", path))
			t.Cleanup(func() {
				out, e := run("", "helm", "uninstall", release, "--kubeconfig", kube, "-n", "collector-i2", "--wait", "--timeout", "30s")
				if e != nil {
					t.Errorf("cleanup Helm: %v %s", e, out)
				}
			})
			job := "job/" + release + "-capture"
			readyBy := time.Now().Add(25 * time.Second)
			for {
				out, _ := k("-n", "collector-i2", "logs", job)
				if strings.Contains(out, "capture_ready") {
					break
				}
				if time.Now().After(readyBy) {
					t.Fatalf("capture not ready: %s", out)
				}
				time.Sleep(time.Second)
			}
			client := must(traffic(tc.ns))
			save(tc.name+"-client.txt", client)
			if client != "/marked 200\n/unmarked 200\n" {
				t.Fatalf("business requests failed: %q", client)
			}
			out, e := k("-n", "collector-i2", "wait", job, "--for=condition=Complete", "--timeout=40s")
			logs := must(k("-n", "collector-i2", "logs", job))
			save(tc.name+"-capture.log", logs)
			if e != nil {
				t.Fatalf("capture job did not complete: %v %s\n%s", e, out, logs)
			}
			save(tc.name+"-job.json", must(k("-n", "collector-i2", "get", job, "-o", "json")))
			save(tc.name+"-pod.json", must(k("-n", "collector-i2", "get", "pods", "-l", "job-name="+release+"-capture", "-o", "json")))
			zlog := must(k("-n", "istio-system", "logs", "ztunnel-zdltm", "--since-time="+start, "--tail=100"))
			save(tc.name+"-ztunnel.log", zlog)
			var records []map[string]any
			for _, line := range strings.Split(logs, "\n") {
				if strings.HasPrefix(line, "{") {
					var r map[string]any
					if e := json.Unmarshal([]byte(line), &r); e != nil {
						t.Fatal(e)
					}
					records = append(records, r)
				}
			}
			if len(records) != 2 {
				t.Fatalf("want marked pair only, got %d: %s", len(records), logs)
			}
			if records[0]["direction"] != "request" || records[0]["path"] != "/marked" || records[1]["direction"] != "response" || records[1]["body"] != "reply:/marked" || records[1]["status"] != float64(200) || records[0]["request_id"] != records[1]["request_id"] {
				t.Fatalf("incorrect pair: %v", records)
			}
			for _, r := range records {
				if r["source_kind"] != "live_socket" || r["pod_ip"] != server.Status.PodIP || r["pod_uid"] != server.Metadata.UID || r["pod_name"] != "server" || r["pod_namespace"] != "collector-lab" {
					t.Fatalf("incorrect identity: %v", r)
				}
			}
			t.Logf("PASS %s: two business 200s, exactly one marked request/response pair with verified Pod identity", tc.name)
		})
	}
	fmt.Fprintln(os.Stdout, "PERMISSIVE test evidence:", evidence)
}
