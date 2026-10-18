package ambient

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
	"ztunnel-ebpf-collector/internal/replay"
)

// Verify real both-side observations independently: same-name Pods in different
// namespaces, service destinations, stream/message pairs, and negative scopes.
func TestNodeBothNamespaces(t *testing.T) {
	if os.Getenv("ZC_BOTH_LOCAL") != "1" {
		t.Skip("explicit isolated local both-side test")
	}
	root, _ := filepath.Abs("../..")
	l := lab{t: t, root: root, kube: filepath.Join(root, ".local/k3s-kubeconfig"), source: os.Getenv("ZC_SOURCE_SHA"), ns: "collector-both-a"}
	if len(l.source) != 40 {
		t.Fatal("fixed artifact SHA required")
	}
	parent := filepath.Join(root, ".local/both", l.source)
	if err := os.MkdirAll(parent, 0700); err != nil {
		t.Fatal(err)
	}
	var err error
	l.evidence, err = os.MkdirTemp(parent, "run-")
	if err != nil {
		t.Fatal(err)
	}
	t.Log("evidence", l.evidence)
	if l.must(l.k("config", "view", "--minify", "-o", "jsonpath={.clusters[0].cluster.server}")) != "https://127.0.0.1:16443" {
		t.Fatal("refuse non-local cluster")
	}
	if len(nodeBPF(l)) != 0 {
		t.Fatal("another probe active")
	}
	l.save("before-pods.txt", l.must(l.k("get", "pods", "-A", "-o", "wide")))
	ns := []string{l.ns, "collector-both-b", "collector-both-excluded"}
	labs := make([]lab, 3)
	for i, name := range ns {
		n := l
		n.ns = name
		labs[i] = n
		if _, err := n.k("get", "ns", name); err == nil {
			t.Fatal("existing namespace", name)
		}
		n.must(n.k("create", "ns", name))
		t.Cleanup(func() {
			s, e := n.k("delete", "ns", n.ns, "--wait=true", "--timeout=50s")
			if e != nil {
				t.Error(s, e)
			}
		})
		n.must(n.k("label", "ns", name, "istio.io/dataplane-mode=ambient"))
		p := n.obj("PeerAuthentication", "permissive")
		p["apiVersion"] = "security.istio.io/v1"
		p["spec"] = map[string]any{"mtls": map[string]string{"mode": "PERMISSIVE"}}
		n.apply(p)
	}
	ids := map[string]replay.PodIdentity{}
	vips := map[string]string{}
	identify := func(n lab, name string) {
		raw := n.must(n.k("-n", n.ns, "get", "pod", name, "-o", "json"))
		n.save(strings.TrimPrefix(n.ns, "collector-both-")+"-"+name+".json", raw)
		var p struct {
			Metadata struct{ UID string }
			Status   struct{ PodIP string }
		}
		if err := json.Unmarshal([]byte(raw), &p); err != nil {
			t.Fatal(err)
		}
		ids[n.ns+"/"+name] = replay.PodIdentity{IP: p.Status.PodIP, Name: name, Namespace: n.ns, UID: p.Metadata.UID}
	}
	h1 := func(n lab, name string) {
		c := container("app", "ztunnel-collector-traffic:i2")
		c["ports"] = []any{map[string]any{"containerPort": 8080}}
		n.pod(name, []any{c}, nil)
	}
	for _, n := range labs[:2] {
		setupPlaintextDapr(n)
		for _, name := range []string{"target", "caller"} {
			ports := "50002"
			if name == "target" {
				ports = "8081,50002"
			}
			n.must(n.k("-n", n.ns, "annotate", "pod/"+name, "collector.ztunnel.io/ports="+ports))
			n.must(n.k("-n", n.ns, "label", "pod/"+name, "observe=yes"))
			identify(n, name)
		}
		h1(n, "h1")
		n.must(n.k("-n", n.ns, "label", "pod/h1", "observe=yes"))
		identify(n, "h1")
		n.service("h1", "h1", 8080)
		n.service("h2", "target", 8081)
		for _, svc := range []string{"h1", "h2", "target-dapr"} {
			vips[n.ns+"/"+svc] = n.must(n.k("-n", n.ns, "get", "svc", svc, "-o", "jsonpath={.spec.clusterIP}"))
		}
	}
	// Same-label Pods outside the allowlist, and unlabeled Pods inside it.
	h1(labs[2], "h1")
	labs[2].must(labs[2].k("-n", ns[2], "label", "pod/h1", "observe=yes"))
	labs[2].pod("client", []any{container("app", "ztunnel-collector-traffic:i2", "idle")}, nil)
	h1(l, "unselected")
	l.pod("unselected-client", []any{container("app", "ztunnel-collector-traffic:i2", "idle")}, nil)
	excludedIP := labs[2].must(labs[2].k("-n", ns[2], "get", "pod/h1", "-o", "jsonpath={.status.podIP}"))
	unselectedIP := l.must(l.k("-n", l.ns, "get", "pod/unselected", "-o", "jsonpath={.status.podIP}"))
	// Existing fixed Go fixture; a single connection is observed on both sides.
	fixture := "ztunnel-collector-unknown:4629ad4fea58a8c7ed57b448d65cda733f633c3d"
	uc := container("app", fixture)
	uc["ports"] = []any{map[string]any{"containerPort": 9099}}
	labs[1].pod("unknown", []any{uc}, nil)
	labs[1].must(labs[1].k("-n", ns[1], "label", "pod/unknown", "observe=yes"))
	labs[1].service("unknown", "unknown", 9099)
	l.pod("unknown-client", []any{container("app", fixture, "idle")}, nil)
	l.must(l.k("-n", l.ns, "label", "pod/unknown-client", "observe=yes"))
	values := map[string]any{"syntheticReplay": false, "daemon": map[string]any{"enabled": true, "namespaces": ns[:2], "selector": "observe=yes", "direction": "both", "nodeSelector": map[string]string{"kubernetes.io/hostname": "collector-local"}}, "image": map[string]string{"repository": "ztunnel-ebpf-collector", "tag": l.source + "-amd64", "pullPolicy": "Never"}, "captureConfig": map[string]string{"markerHeader": "Debug-Token", "markerValue": "yes"}}
	b, _ := json.Marshal(values)
	vp := filepath.Join(t.TempDir(), "values.json")
	if err := os.WriteFile(vp, b, 0600); err != nil {
		t.Fatal(err)
	}
	release := "both-check"
	l.must(l.run("", "helm", "install", release, filepath.Join(root, "dist", l.source, "ztunnel-ebpf-collector-0.1.0.tgz"), "--kubeconfig", l.kube, "-n", l.ns, "-f", vp))
	installed := true
	defer func() {
		if installed {
			s, e := l.run("", "helm", "uninstall", release, "--kubeconfig", l.kube, "-n", l.ns, "--wait", "--timeout", "30s")
			if e != nil {
				t.Error(s, e)
			}
		}
	}()
	logs := func() string { s, _ := l.k("-n", l.ns, "logs", "ds/"+release+"-node"); return s }
	deadline := time.Now().Add(50 * time.Second)
	for {
		s := logs()
		at := strings.LastIndex(s, "node_targets count=")
		if at >= 0 && strings.HasPrefix(s[at:], "node_targets count=17 ") {
			break
		}
		if strings.Contains(s, "node_stopped") || time.Now().After(deadline) {
			l.save("capture.log", s)
			t.Fatal("expected 17 targets", s)
		}
		time.Sleep(time.Second)
	}
	l.must(l.k("-n", l.ns, "rollout", "status", "ds/"+release+"-node", "--timeout=40s"))
	initial := nodeBPF(l)
	if len(initial) != 10 {
		t.Fatal(initial)
	}
	unknownDone := make(chan struct {
		body string
		err  error
	}, 1)
	go func() {
		s, e := l.exec("unknown-client", "client", "unknown."+ns[1]+".svc.cluster.local:9099")
		unknownDone <- struct {
			body string
			err  error
		}{s, e}
	}()
	dump := func() string {
		return l.must(l.run("", "limactl", "shell", "ztunnel-ebpf-amd64", "sudo", "bpftool", "-j", "map", "dump", "name", "zc_suppressed"))
	}
	deadline = time.Now().Add(12 * time.Second)
	for {
		raw := dump()
		var entries []any
		if err := json.Unmarshal([]byte(raw), &entries); err != nil {
			t.Fatal(err)
		}
		if len(entries) == 2 {
			l.save("suppressed-active.json", raw)
			break
		}
		if strings.Contains(logs(), "node_stopped") || time.Now().After(deadline) {
			l.save("capture.log", logs())
			t.Fatal("expected both unknown socket filters", raw)
		}
		time.Sleep(200 * time.Millisecond)
	}
	type call struct {
		n    lab
		pod  string
		args []string
	}
	calls := []call{}
	for i, n := range labs[:2] {
		other := ns[1-i]
		calls = append(calls, call{n, "h1", []string{"client", "http://h1." + other + ".svc.cluster.local:8080"}}, call{n, "caller", []string{"http2-client", "http://h2." + other + ".svc.cluster.local:8081"}}, call{n, "caller", []string{"grpc-client-native", "127.0.0.1:50001", "target"}})
	}
	calls = append(calls, call{l, "unselected-client", []string{"client", "http://" + unselectedIP + ":8080"}}, call{labs[2], "client", []string{"client", "http://" + excludedIP + ":8080"}})
	started := time.Now()
	for round := 1; round <= 2; round++ {
		type result struct {
			i int
			s string
			e error
		}
		done := make(chan result, len(calls))
		for i, c := range calls {
			go func() { s, e := c.n.exec(c.pod, c.args...); done <- result{i, s, e} }()
		}
		for range calls {
			r := <-done
			l.save(fmt.Sprintf("round%d-call%d.txt", round, r.i), r.s)
			if r.e != nil {
				l.save("capture.log", logs())
				t.Fatal(r.i, r.e, r.s)
			}
		}
		if round == 1 {
			if d := 35*time.Second - time.Since(started); d > 0 {
				time.Sleep(d)
			}
		}
	}
	u := <-unknownDone
	l.save("unknown-client.txt", u.body)
	if u.err != nil {
		t.Fatal(u.err, u.body)
	}
	deadline = time.Now().Add(8 * time.Second)
	for {
		raw := dump()
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
			t.Fatal("filters not reclaimed", raw)
		}
		time.Sleep(200 * time.Millisecond)
	}
	body := logs()
	l.save("capture.log", body)
	if strings.Contains(body, "node_stopped") {
		t.Fatal(body)
	}
	pairs := map[string]map[string]replay.Record{}
	counts := map[string]int{}
	for _, line := range strings.Split(body, "\n") {
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var r replay.Record
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatal(err)
		}
		identity, ok := ids[r.PodNamespace+"/"+r.PodName]
		if !ok || r.PodIP != identity.IP || r.PodUID != identity.UID {
			t.Fatal("wrong/excluded Pod", r)
		}
		inbound := r.ObservationSide == "inbound"
		if !inbound && r.ObservationSide != "outbound" {
			t.Fatal("side", r)
		}
		known, unknown := r.Client, r.Server
		if inbound {
			known, unknown = r.Server, r.Client
		}
		if known == nil || *known != identity || unknown == nil || unknown.UID != "unknown" {
			t.Fatal("wrong side identity", r)
		}
		wantPod := "h1"
		svc := "h1"
		port := "8080"
		if r.Protocol == "HTTP/2" {
			wantPod = "caller"
			if inbound {
				wantPod = "target"
			}
			svc = "h2"
			port = "8081"
		} else if r.Protocol == "gRPC" {
			wantPod = "caller"
			if inbound {
				wantPod = "target"
			}
			svc = "target-dapr"
			port = "50002"
		} else if r.Protocol != "HTTP/1.1" {
			t.Fatal("protocol", r)
		}
		if r.PodName != wantPod {
			t.Fatal("wrong role", r)
		}
		if !inbound {
			destNS := ns[0]
			if r.PodNamespace == ns[0] {
				destNS = ns[1]
			}
			if r.Protocol == "gRPC" {
				destNS = r.PodNamespace
			}
			if r.OriginalDestination != vips[destNS+"/"+svc]+":"+port {
				t.Fatal("wrong service destination", r)
			}
		}
		if r.Direction != "request" && r.Direction != "response" {
			t.Fatal(r)
		}
		if pairs[r.RequestID] == nil {
			pairs[r.RequestID] = map[string]replay.Record{}
		}
		if _, ok := pairs[r.RequestID][r.Direction]; ok {
			t.Fatal("duplicate", r)
		}
		pairs[r.RequestID][r.Direction] = r
		counts[r.PodNamespace+"/"+r.ObservationSide+"/"+r.Protocol]++
	}
	for _, pair := range pairs {
		q, ok := pair["request"]
		r, ok2 := pair["response"]
		if !ok || !ok2 || q.StreamID != r.StreamID || q.PodUID != r.PodUID || q.ObservationSide != r.ObservationSide {
			t.Fatal("crossed pair", pair)
		}
		if q.Protocol != "gRPC" {
			wantBody := "reply:/marked"
			if q.Protocol == "HTTP/2" {
				wantBody = "cmVwbHk6L21hcmtlZA=="
				if r.BodyEncoding != "base64" || q.StreamID == 0 {
					t.Fatal(pair)
				}
			}
			if q.Path != "/marked" || q.Method != "GET" || r.Status != 200 || r.Body != wantBody {
				t.Fatal("bad HTTP pair", pair)
			}
			continue
		}
		if len(q.GRPCMessages) != 1 || r.GRPCStatus == nil || q.StreamID == 0 {
			t.Fatal(pair)
		}
		status := 0
		path := "/grpc.health.v1.Health/Check"
		messages := []string{"CAE="}
		switch q.GRPCMessages[0] {
		case "CgZtYXJrZWQ=":
		case "CgVlcnJvcg==":
			status = 5
			messages = nil
		case "CgZzdHJlYW0=":
			path = "/grpc.health.v1.Health/Watch"
			messages = []string{"CAE=", "CAI="}
		default:
			t.Fatal("unmarked RPC", pair)
		}
		if q.Path != path || *r.GRPCStatus != status || !reflect.DeepEqual(r.GRPCMessages, messages) {
			t.Fatal("bad RPC pair", pair)
		}
	}
	want := map[string]int{}
	for _, name := range ns[:2] {
		for _, side := range []string{"inbound", "outbound"} {
			for p, c := range map[string]int{"HTTP/1.1": 4, "HTTP/2": 4, "gRPC": 12} {
				want[name+"/"+side+"/"+p] = c
			}
		}
	}
	if !reflect.DeepEqual(counts, want) || len(pairs) != 40 {
		t.Fatal("missing/leaked observations", counts, len(pairs))
	}
	if !reflect.DeepEqual(initial, nodeBPF(l)) {
		t.Fatal("BPF resources changed")
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
		t.Fatal("wrong agent/image", pods)
	}
	l.must(l.run("", "helm", "uninstall", release, "--kubeconfig", l.kube, "-n", l.ns, "--wait", "--timeout", "30s"))
	installed = false
	l.must(l.k("-n", l.ns, "wait", "--for=delete", "pod", "-l", "app.kubernetes.io/instance="+release+"-node", "--timeout=30s"))
	after := nodeBPF(l)
	if len(after) != 0 {
		t.Fatal("leaked BPF objects", after)
	}
	l.save("result.json", jsonText(map[string]any{"source": l.source, "counts": counts, "pairs": len(pairs), "identities": ids, "vips": vips, "objects_running": initial, "objects_after_stop": after, "unknown_echo_bytes": 655360}))
	t.Log("two namespaces, both directions, 80 records/40 observation pairs; unknown and out-of-scope bodies silent; filters and 10 BPF objects reclaimed")
}
