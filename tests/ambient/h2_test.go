package ambient

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type lab struct {
	t                                *testing.T
	root, kube, source, ns, evidence string
}

func (l lab) run(input, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = strings.NewReader(input)
	b, e := cmd.CombinedOutput()
	return string(b), e
}
func (l lab) k(args ...string) (string, error) {
	return l.run("", "kubectl", append([]string{"--kubeconfig", l.kube, "--request-timeout=10s"}, args...)...)
}
func (l lab) must(s string, e error) string {
	l.t.Helper()
	if e != nil {
		l.t.Fatalf("command failed: %v\n%s", e, s)
	}
	return s
}
func (l lab) save(name, s string) {
	l.t.Helper()
	if e := os.WriteFile(filepath.Join(l.evidence, name), []byte(s), 0600); e != nil {
		l.t.Fatal(e)
	}
}
func (l lab) apply(v any) {
	l.t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		l.t.Fatal(e)
	}
	l.must(l.run(string(b), "kubectl", "--kubeconfig", l.kube, "apply", "-f", "-"))
}
func (l lab) obj(kind, name string) map[string]any {
	return map[string]any{"apiVersion": "v1", "kind": kind, "metadata": map[string]any{"name": name, "namespace": l.ns}}
}
func (l lab) pod(name string, containers []any, volumes []any) {
	p := l.obj("Pod", name)
	p["metadata"].(map[string]any)["labels"] = map[string]string{"app": name}
	p["spec"] = map[string]any{"nodeName": "collector-local", "restartPolicy": "Never", "automountServiceAccountToken": false, "terminationGracePeriodSeconds": 2, "containers": containers, "volumes": volumes}
	l.apply(p)
	l.must(l.k("-n", l.ns, "wait", "pod/"+name, "--for=condition=Ready", "--timeout=70s"))
}
func container(name, image string, args ...string) map[string]any {
	return map[string]any{"name": name, "image": image, "imagePullPolicy": "Never", "args": args, "resources": map[string]any{"requests": map[string]string{"cpu": "10m", "memory": "32Mi"}, "limits": map[string]string{"cpu": "500m", "memory": "256Mi"}}}
}
func (l lab) exec(pod string, args ...string) (string, error) {
	return l.k(append([]string{"-n", l.ns, "exec", pod, "-c", "app", "--", "/traffic"}, args...)...)
}
func (l lab) service(name, app string, port int) {
	s := l.obj("Service", name)
	s["spec"] = map[string]any{"selector": map[string]string{"app": app}, "ports": []any{map[string]any{"port": port, "targetPort": port}}}
	l.apply(s)
}
func (l lab) capture(name, server, source string, port int, traffic func() string, want int) {
	l.t.Helper()
	podJSON := l.must(l.k("-n", l.ns, "get", "pod", server, "-o", "json"))
	var pod struct {
		Metadata struct{ UID string }
		Status   struct{ PodIP string }
	}
	if e := json.Unmarshal([]byte(podJSON), &pod); e != nil {
		l.t.Fatal(e)
	}
	pods := l.must(l.k("get", "pods", "-A", "-o", "json"))
	values := map[string]any{"capture": true, "syntheticReplay": false, "image": map[string]string{"repository": "ztunnel-ebpf-collector", "tag": l.source + "-amd64", "pullPolicy": "Never"}, "captureConfig": map[string]any{"source": source, "node": "collector-local", "server": l.ns + "/" + server, "port": port, "markerHeader": "Debug-Token", "markerValue": "yes", "duration": "30s", "podList": pods}}
	b, _ := json.Marshal(values)
	vp := filepath.Join(l.t.TempDir(), "values.json")
	if e := os.WriteFile(vp, b, 0600); e != nil {
		l.t.Fatal(e)
	}
	release := "i3-" + name
	chart := filepath.Join(l.root, "dist", l.source, "ztunnel-ebpf-collector-0.1.0.tgz")
	l.must(l.run("", "helm", "install", release, chart, "--kubeconfig", l.kube, "-n", l.ns, "-f", vp))
	defer func() {
		out, e := l.run("", "helm", "uninstall", release, "--kubeconfig", l.kube, "-n", l.ns, "--wait", "--timeout", "30s")
		if e != nil {
			l.t.Errorf("cleanup: %v %s", e, out)
		}
	}()
	job := "job/" + release + "-capture"
	deadline := time.Now().Add(25 * time.Second)
	for {
		out, _ := l.k("-n", l.ns, "logs", job)
		if strings.Contains(out, "capture_ready") {
			break
		}
		if time.Now().After(deadline) {
			l.save(name+"-capture.log", out)
			l.t.Fatalf("probe not ready: %s", out)
		}
		time.Sleep(time.Second)
	}
	if source == "daprd" {
		time.Sleep(7 * time.Second)
	} // fixture-only MaxConnectionAge: fresh HPACK; never closes real app connections
	l.save(name+"-client.txt", traffic())
	out, e := l.k("-n", l.ns, "wait", job, "--for=condition=Complete", "--timeout=40s")
	logs := l.must(l.k("-n", l.ns, "logs", job))
	l.save(name+"-capture.log", logs)
	if e != nil {
		l.t.Fatalf("capture incomplete: %v %s\n%s", e, out, logs)
	}
	l.save(name+"-pod.json", l.must(l.k("-n", l.ns, "get", "pods", "-l", "job-name="+release+"-capture", "-o", "json")))
	var rs []map[string]any
	for _, line := range strings.Split(logs, "\n") {
		if strings.HasPrefix(line, "{") {
			var r map[string]any
			if e := json.Unmarshal([]byte(line), &r); e != nil {
				l.t.Fatal(e)
			}
			rs = append(rs, r)
		}
	}
	if len(rs) != want {
		l.t.Fatalf("want %d marked records got %d\n%s", want, len(rs), logs)
	}
	statusCount := map[float64]int{}
	messageCount := 0
	for i, r := range rs {
		if r["pod_ip"] != pod.Status.PodIP || r["pod_uid"] != pod.Metadata.UID || r["pod_name"] != server || r["pod_namespace"] != l.ns || r["source_kind"] != "live_socket" {
			l.t.Fatalf("incorrect Pod identity: %v", r)
		}
		if i%2 == 0 && r["request_id"] != rs[i+1]["request_id"] {
			l.t.Fatal("cross-stream pair")
		}
		if want == 2 {
			if r["protocol"] != "HTTP/2" {
				l.t.Fatal(r)
			}
			if i == 0 && r["path"] != "/marked" {
				l.t.Fatal("unmarked HTTP2 leak")
			}
			if i == 1 && r["body"] != base64.StdEncoding.EncodeToString([]byte("reply:/marked")) {
				l.t.Fatal("HTTP2 bytes changed")
			}
		}
		if want == 6 {
			if r["protocol"] != "gRPC" {
				l.t.Fatal(r)
			}
			if i%2 == 1 {
				v, ok := r["grpc_status"].(float64)
				if !ok {
					l.t.Fatal("missing grpc-status")
				}
				statusCount[v]++
			}
			if msgs, ok := r["grpc_messages"].([]any); ok {
				for _, m := range msgs {
					p, e := base64.StdEncoding.DecodeString(m.(string))
					if e != nil {
						l.t.Fatal(e)
					}
					if strings.Contains(string(p), "hidden") {
						l.t.Fatal("unmarked RPC leaked")
					}
					messageCount++
				}
			}
		}
	}
	if want == 6 && (statusCount[0] != 2 || statusCount[5] != 1 || messageCount != 6) {
		l.t.Fatalf("RPC status/message loss: %v messages=%d", statusCount, messageCount)
	}
	l.t.Logf("%s PASS: %d marked records, verified stream/Pod identity", name, want)
}

// Runs only on the existing disposable local VM. Never installs a control plane
// in ACK/EKS. Images must be preloaded, and the collector must be a fixed build.
func TestHTTP2GRPCAndDapr(t *testing.T) {
	if os.Getenv("ZC_H2_LOCAL") != "1" {
		t.Skip("explicit local H2 lab only")
	}
	source := os.Getenv("ZC_SOURCE_SHA")
	if len(source) != 40 {
		t.Fatal("ZC_SOURCE_SHA must identify a fixed build")
	}
	root, e := filepath.Abs("../..")
	if e != nil {
		t.Fatal(e)
	}
	l := lab{t: t, root: root, kube: filepath.Join(root, ".local/k3s-kubeconfig"), source: source, ns: "collector-h2", evidence: filepath.Join(root, ".local/h2-e2e")}
	if e := os.MkdirAll(l.evidence, 0700); e != nil {
		t.Fatal(e)
	}
	if l.must(l.k("config", "view", "--minify", "-o", "jsonpath={.clusters[0].cluster.server}")) != "https://127.0.0.1:16443" {
		t.Fatal("refuse non-local cluster")
	}
	if _, e := l.k("get", "ns", l.ns); e == nil {
		t.Fatal("lab namespace already exists; refusing reuse")
	}
	l.must(l.k("create", "ns", l.ns))
	t.Cleanup(func() {
		out, e := l.k("delete", "ns", l.ns, "--wait=false")
		if e != nil {
			t.Errorf("cleanup: %v %s", e, out)
		}
	})
	// Explicit mesh enrollment for the direct ztunnel cases.
	l.must(l.k("label", "ns", l.ns, "istio.io/dataplane-mode=ambient"))
	l.pod("direct", []any{container("app", "ztunnel-collector-h2:i3")}, nil)
	l.pod("client", []any{container("app", "ztunnel-collector-h2:i3", "idle")}, nil)
	ip := l.must(l.k("-n", l.ns, "get", "pod", "direct", "-o", "jsonpath={.status.podIP}"))
	for _, tc := range []struct {
		name, mode string
		port, want int
	}{{"http2", "http2-client", 8081, 2}, {"grpc", "grpc-client", 8082, 6}} {
		t.Run(tc.name, func(t *testing.T) {
			ll := l
			ll.t = t
			addr := fmt.Sprintf("%s:%d", ip, tc.port)
			if tc.port == 8081 {
				addr = "http://" + addr
			}
			ll.capture(tc.name, "direct", "ztunnel", tc.port, func() string { return ll.must(ll.exec("client", tc.mode, addr)) }, tc.want)
		})
	}
	// Sentry issues real Dapr certificates. Standalone mode avoids installing
	// unrelated placement/scheduler/operator components for this bounded test.
	cm := l.obj("ConfigMap", "config")
	cm["data"] = map[string]string{"config.yaml": "apiVersion: dapr.io/v1alpha1\nkind: Configuration\nmetadata:\n  name: test\nspec:\n  nameResolution:\n    component: kubernetes\n    version: v1\n  tracing:\n    samplingRate: '0'\n"}
	l.apply(cm)
	sentry := container("sentry", "daprio/sentry:1.16.0", "--mode", "standalone", "--config", "/config/config.yaml", "--issuer-credentials", "/certs", "--trust-domain", "public", "--port", "50001")
	sentry["command"] = []string{"/sentry"}
	sentry["env"] = []any{map[string]string{"name": "NAMESPACE", "value": l.ns}}
	sentry["securityContext"] = map[string]any{"runAsUser": 0}
	sentry["volumeMounts"] = []any{map[string]any{"name": "certs", "mountPath": "/certs"}, map[string]any{"name": "config", "mountPath": "/config"}}
	l.pod("sentry", []any{sentry}, []any{map[string]any{"name": "certs", "emptyDir": map[string]any{}}, map[string]any{"name": "config", "configMap": map[string]string{"name": "config"}}})
	l.service("sentry", "sentry", 50001)
	uid := l.must(l.k("-n", l.ns, "get", "pod", "sentry", "-o", "jsonpath={.metadata.uid}"))
	rootpath := "/var/lib/kubelet/pods/" + uid + "/volumes/kubernetes.io~empty-dir/certs/ca.crt"
	var ca string
	deadline := time.Now().Add(20 * time.Second)
	for {
		out, e := l.run("", "limactl", "shell", "ztunnel-ebpf-amd64", "sudo", "cat", rootpath)
		if e == nil && strings.HasPrefix(out, "-----BEGIN CERTIFICATE-----") {
			ca = out
			break
		}
		if time.Now().After(deadline) {
			l.t.Fatalf("Sentry CA unavailable: %v %s", e, out)
		}
		time.Sleep(time.Second)
	}
	roots := l.obj("ConfigMap", "roots")
	roots["data"] = map[string]string{"ca.crt": ca}
	l.apply(roots)
	for _, version := range []string{"1.14.0", "1.16.0"} {
		for _, mtls := range []bool{false, true} {
			name := strings.ReplaceAll(version, ".", "-") + fmt.Sprintf("-%t", mtls)
			t.Run(name, func(t *testing.T) {
				ll := l
				ll.t = t
				for _, role := range []string{"target", "caller"} {
					args := []string{"--mode", "standalone", "--app-id", role, "--dapr-grpc-port", "50001", "--dapr-internal-grpc-port", "50002", "--config", "/config/config.yaml", "--enable-mtls=" + fmt.Sprint(mtls), "--sentry-address", "sentry." + l.ns + ".svc.cluster.local:50001", "--control-plane-trust-domain", "public", "--control-plane-namespace", l.ns, "--placement-host-address", "", "--scheduler-host-address", ""}
					if role == "target" {
						args = append(args, "--app-port", "8082", "--app-protocol", "grpc")
					}
					dp := container("daprd", "daprio/daprd:"+version, args...)
					dp["command"] = []string{"/daprd"}
					dp["env"] = []any{map[string]string{"name": "NAMESPACE", "value": l.ns}, map[string]any{"name": "DAPR_TRUST_ANCHORS", "valueFrom": map[string]any{"configMapKeyRef": map[string]string{"name": "roots", "key": "ca.crt"}}}}
					dp["volumeMounts"] = []any{map[string]any{"name": "config", "mountPath": "/config"}}
					dp["readinessProbe"] = map[string]any{"httpGet": map[string]any{"path": "/v1.0/healthz/outbound", "port": 3500}, "initialDelaySeconds": 2, "periodSeconds": 2, "timeoutSeconds": 2}
					app := container("app", "ztunnel-collector-h2:i3")
					if role == "caller" {
						app["args"] = []string{"idle"}
					}
					ll.pod(role, []any{app, dp}, []any{map[string]any{"name": "config", "configMap": map[string]string{"name": "config"}}})
				}
				defer func() { ll.must(ll.k("-n", l.ns, "delete", "pod", "target", "caller", "--wait=true", "--timeout=30s")) }()
				ll.service("target-dapr", "target", 50002)
				targetIP := ll.must(ll.k("-n", l.ns, "get", "pod", "target", "-o", "jsonpath={.status.podIP}"))
				// Direct plaintext against Dapr's internal port is rejected only with mTLS.
				plain, e := ll.exec("caller", "grpc-client", targetIP+":50002", "target")
				ll.save(name+"-internal-plaintext.txt", plain)
				if mtls && e == nil {
					t.Fatal("mTLS internal port accepted plaintext")
				}
				if !mtls && e != nil {
					t.Fatalf("plaintext Dapr invocation failed: %v %s", e, plain)
				}
				ll.capture("dapr-"+name, "target", "daprd", 8082, func() string { return ll.must(ll.exec("caller", "grpc-client", "127.0.0.1:50001", "target")) }, 6)
				for _, role := range []string{"target", "caller"} {
					ll.save(name+"-"+role+".log", ll.must(ll.k("-n", l.ns, "logs", role, "-c", "daprd", "--tail=100")))
				}
			})
			if t.Failed() {
				return
			}
		}
	}
	l.save("sentry.log", l.must(l.k("-n", l.ns, "logs", "sentry", "--tail=100")))
}
