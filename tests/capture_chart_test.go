package tests

import (
	"os/exec"
	"strings"
	"testing"
)

func TestCaptureChartExplicitConfiguration(t *testing.T) {
	cmd := exec.Command("helm", "template", "live", "../charts/ztunnel-ebpf-collector", "--set", "capture=true,syntheticReplay=false,captureConfig.node=collector-local,captureConfig.server=collector-lab/server,captureConfig.markerHeader=Debug-Token,captureConfig.markerValue=yes", "--set-string", "captureConfig.podList={}")
	b, e := cmd.CombinedOutput()
	if e != nil {
		t.Fatalf("configured capture chart failed: %s", b)
	}
	s := string(b)
	for _, want := range []string{"hostPID: true", "nodeName: collector-local"} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %s", want)
		}
	}
	if strings.Contains(s, "privileged: true") || strings.Contains(s, "SYS_ADMIN") || strings.Contains(s, "NET_ADMIN") {
		t.Fatal("unneeded privileges")
	}
	for _, want := range []string{"PERFMON", "BPF", "--marker-header", "Debug-Token", "collector-lab/server"} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %s", want)
		}
	}
}

func TestCaptureChartMultipleTargets(t *testing.T) {
	args := []string{"template", "mixed", "../charts/ztunnel-ebpf-collector", "--set", "capture=true,syntheticReplay=false,captureConfig.node=collector-local,captureConfig.markerHeader=Debug-Token,captureConfig.markerValue=yes", "--set-string", "captureConfig.podList={}", "--set", "captureConfig.targets[0]=lab/a:8080,captureConfig.targets[1]=lab/b:50002"}
	b, err := exec.Command("helm", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("multi-target deployment rejected: %v %s", err, b)
	}
	s := string(b)
	if strings.Count(s, "- --target\n") != 2 || strings.Contains(s, "- --server") || !strings.Contains(s, "lab/b:50002") {
		t.Fatal("incorrect rendered target arguments", s)
	}
	for _, extra := range []string{"captureConfig.server=lab/a", "captureConfig.source=daprd"} {
		b, err = exec.Command("helm", append(args, "--set", extra)...).CombinedOutput()
		if err == nil {
			t.Fatalf("ambiguous target selection allowed: %s %s", extra, b)
		}
	}
}

func TestDaemonSetChartScopeAndPrivileges(t *testing.T) {
	args := []string{"template", "node", "../charts/ztunnel-ebpf-collector", "--set", "daemon.enabled=true,syntheticReplay=false,daemon.namespace=demo,daemon.selector=observe=yes,captureConfig.markerHeader=Debug-Token,captureConfig.markerValue=yes"}
	b, err := exec.Command("helm", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("daemon chart rejected: %s", b)
	}
	s := string(b)
	for _, want := range []string{"kind: DaemonSet", "fieldPath: spec.nodeName", "verbs: [get, list, watch]", "--namespace", "--selector", "readOnlyRootFilesystem: true", "hostPID: true", "terminationGracePeriodSeconds: 10", "readinessProbe:"} {
		if !strings.Contains(s, want) {
			t.Fatal("missing daemon contract", want)
		}
	}
	for _, bad := range []string{"kind: Job", "activeDeadlineSeconds", "SYS_ADMIN", "NET_ADMIN", "privileged: true"} {
		if strings.Contains(s, bad) {
			t.Fatal("unsafe daemon contract", bad)
		}
	}
	if _, err := exec.Command("helm", append(args, "--set", "capture=true")...).CombinedOutput(); err == nil {
		t.Fatal("ambiguous capture modes accepted")
	}
}

func TestDaemonSetChartMultipleNamespaces(t *testing.T) {
	base := []string{"template", "multi", "../charts/ztunnel-ebpf-collector", "--set", "daemon.enabled=true,syntheticReplay=false,daemon.selector=observe=yes,captureConfig.markerHeader=Debug-Token,captureConfig.markerValue=yes"}
	args := append(append([]string{}, base...), "--set", "daemon.namespaces[0]=orders,daemon.namespaces[1]=payments")
	b, err := exec.Command("helm", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("multiple namespaces rejected: %s", b)
	}
	s := string(b)
	if strings.Count(s, "kind: DaemonSet") != 1 || strings.Count(s, "- --namespace\n") != 2 || !strings.Contains(s, `- "orders"`) || !strings.Contains(s, `- "payments"`) {
		t.Fatal("incorrect scope", s)
	}
	for _, extra := range []string{"daemon.namespace=other", "daemon.namespaces[1]=orders", "daemon.namespaces[1]=*", "daemon.namespaces[1]="} {
		if b, err := exec.Command("helm", append(append([]string{}, args...), "--set", extra)...).CombinedOutput(); err == nil {
			t.Fatalf("invalid scope accepted: %s %s", extra, b)
		}
	}
	if b, err := exec.Command("helm", base...).CombinedOutput(); err == nil {
		t.Fatal("empty scope accepted", string(b))
	}
}

func TestDaemonSetOutboundDirection(t *testing.T) {
	args := []string{"template", "out", "../charts/ztunnel-ebpf-collector", "--set", "daemon.enabled=true,syntheticReplay=false,daemon.namespace=demo,daemon.selector=observe=yes,daemon.direction=outbound,captureConfig.markerHeader=Debug-Token,captureConfig.markerValue=yes"}
	b, err := exec.Command("helm", args...).CombinedOutput()
	if err != nil || !strings.Contains(string(b), "- --direction\n        - \"outbound\"") {
		t.Fatal("outbound mode not deployed", string(b), err)
	}
	if b, err := exec.Command("helm", append(args, "--set", "daemon.direction=invalid")...).CombinedOutput(); err == nil {
		t.Fatal("invalid direction accepted", string(b))
	}
}
