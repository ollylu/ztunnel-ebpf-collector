package tests

import (
	"os/exec"
	"strings"
	"testing"
)

func TestDeliveryPrivateRegistryAcrossModes(t *testing.T) {
	for _, mode := range []string{
		"syntheticReplay=true",
		"syntheticReplay=false,daemon.enabled=true,daemon.namespace=orders,daemon.selector=observe=yes,captureConfig.markerHeader=Debug-Token,captureConfig.markerValue=yes",
		"syntheticReplay=false,capture=true,captureConfig.node=test,captureConfig.server=orders/api,captureConfig.markerHeader=Debug-Token,captureConfig.markerValue=yes,captureConfig.podList={}",
	} {
		b, err := exec.Command("helm", "template", "internal", "../charts/ztunnel-ebpf-collector", "--set", mode, "--set", "image.repository=registry.example/team/collector,image.tag=ignored,image.digest=sha256:"+strings.Repeat("a", 64)+",imagePullSecrets[0].name=registry-auth").CombinedOutput()
		if err != nil {
			t.Fatal(string(b), err)
		}
		for _, want := range []string{"registry.example/team/collector@sha256:" + strings.Repeat("a", 64), "imagePullSecrets:", "name: registry-auth"} {
			if !strings.Contains(string(b), want) {
				t.Errorf("mode %s missing %s", mode, want)
			}
		}
		if strings.Contains(string(b), ":ignored") {
			t.Error("tag used instead of pinned digest")
		}
	}
}

func TestDeliveryDaemonSchedulingAndResources(t *testing.T) {
	b, err := exec.Command("helm", "template", "internal", "../charts/ztunnel-ebpf-collector", "--set", "syntheticReplay=false,daemon.enabled=true,daemon.namespace=orders,daemon.selector=observe=yes,captureConfig.markerHeader=Debug-Token,captureConfig.markerValue=yes,daemon.resources.limits.cpu=750m,daemon.tolerations[0].key=dedicated,daemon.tolerations[0].operator=Exists,daemon.priorityClassName=collector-test,daemon.nodeSelector.pool=test").CombinedOutput()
	if err != nil {
		t.Fatal(string(b), err)
	}
	for _, want := range []string{"cpu: 750m", "tolerations:", "key: dedicated", `priorityClassName: "collector-test"`, "pool: test", "kubernetes.io/arch: amd64"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("missing %s", want)
		}
	}
}

func TestDeliveryRejectsInvalidDigest(t *testing.T) {
	b, err := exec.Command("helm", "template", "internal", "../charts/ztunnel-ebpf-collector", "--set", "image.digest=sha256:bad").CombinedOutput()
	if err == nil {
		t.Fatal("invalid digest accepted", string(b))
	}
}

func TestDeliveryRejectsUnsupportedNodeArchitecture(t *testing.T) {
	b, err := exec.Command("helm", "template", "internal", "../charts/ztunnel-ebpf-collector", "--set", "syntheticReplay=false,daemon.enabled=true,daemon.namespace=orders,daemon.selector=observe=yes,captureConfig.markerHeader=Debug-Token,captureConfig.markerValue=yes", "--set-string", "daemon.nodeSelector.kubernetes\\.io/arch=arm64").CombinedOutput()
	if err == nil {
		t.Fatal("unsupported node architecture accepted", string(b))
	}
}

func TestDeliveryDefaultImageMatchesDaemonArchitecture(t *testing.T) {
	b, err := exec.Command("make", "-n", "-C", "..", "image").CombinedOutput()
	if err != nil {
		t.Fatal(string(b), err)
	}
	if !strings.Contains(string(b), "--platform linux/amd64") {
		t.Fatal("default image cannot run on default DaemonSet nodes")
	}
}
