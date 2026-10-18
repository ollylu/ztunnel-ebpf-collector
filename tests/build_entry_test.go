//go:build integration

package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// 防重入：这些用例会调用 make，而 make check 会跑 go test；
// 一旦在 make check 内再次进入就会递归，故显式拒绝在门禁内运行。
func guardReentry(t *testing.T) {
	t.Helper()
	if os.Getenv("ZTUNNEL_CHECK_ACTIVE") == "1" {
		t.Skip("integration entry must not run inside make check (re-entrancy guard)")
	}
}

// 子进程超时：默认 120s，可用 ZTUNNEL_ITIMEOUT 覆盖；超时后杀掉整个进程组。
func timeout() time.Duration {
	if v := os.Getenv("ZTUNNEL_ITIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return 120 * time.Second
}

// repoRoot 返回被测仓库根（本测试位于 tests/ 下）。
func repoRoot(t *testing.T) string {
	t.Helper()
	abs, err := filepath.Abs("..")
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	return abs
}

// copyTree 把工作树（排除 .git/dist）复制到临时目录，供负控与脏树用例使用。
func copyTree(t *testing.T) string {
	t.Helper()
	dst := t.TempDir()
	src := repoRoot(t)
	err := filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		if rel == ".git" || strings.HasPrefix(rel, ".git"+string(filepath.Separator)) || rel == "dist" {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, b, info.Mode().Perm())
	})
	if err != nil {
		t.Fatalf("copy tree: %v", err)
	}
	return dst
}

// copyTreeAsRepo 复制工作树并建立**真实提交**，使入口能看到 40 位 revision。
func copyTreeAsRepo(t *testing.T) (string, string) {
	t.Helper()
	dir := copyTree(t)
	if _, errOut, code := run(t, dir, nil, "git", "init", "-q"); code != 0 {
		t.Fatalf("git init: %s", errOut)
	}
	if _, errOut, code := run(t, dir, nil, "git", "-c", "user.name=t", "-c", "user.email=t@t", "add", "-A"); code != 0 {
		t.Fatalf("git add: %s", errOut)
	}
	if _, errOut, code := run(t, dir, nil, "git", "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "init"); code != 0 {
		t.Fatalf("git commit: %s", errOut)
	}
	sha, _, code := run(t, dir, nil, "git", "rev-parse", "HEAD")
	if code != 0 {
		t.Fatal("rev-parse failed")
	}
	return dir, strings.TrimSpace(sha)
}

func run(t *testing.T, dir string, env []string, name string, args ...string) (string, string, int) {
	t.Helper()
	guardReentry(t)
	ctx, cancel := context.WithTimeout(context.Background(), timeout())
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process != nil {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		return nil
	}
	cmd.WaitDelay = 5 * time.Second
	var out, errBuf strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	err := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		t.Fatalf("%s %v timed out after %s (process group killed)", name, args, timeout())
	}
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			t.Fatalf("%s %v: %v", name, args, err)
		}
	}
	return out.String(), errBuf.String(), code
}

// B1 `make check` 必须真实跑通（CGO=0）。
func TestBuildEntry_CheckPasses(t *testing.T) {
	dir := copyTree(t)
	out, errOut, code := run(t, dir, []string{"CGO_ENABLED=0"}, "make", "check")
	if code != 0 {
		t.Fatalf("make check exit=%d, want 0\nstdout=%s\nstderr=%s", code, out, errOut)
	}
	for _, needle := range []string{"go test", "go vet"} {
		if !strings.Contains(out+errOut, needle) {
			t.Errorf("make check must actually run %q; output=%q", needle, out+errOut)
		}
	}
}

// B2 负控：注入失败测试后 `make check` 必须非零退出（防止空转通过）。
func TestBuildEntry_CheckFailsOnBrokenTest(t *testing.T) {
	dir := copyTree(t)
	bad := filepath.Join(dir, "internal", "replay", "zz_broken_test.go")
	if err := os.WriteFile(bad, []byte("package replay_test\n\nimport \"testing\"\n\nfunc TestZZBroken(t *testing.T) { t.Fatal(\"injected\") }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, code := run(t, dir, []string{"CGO_ENABLED=0"}, "make", "check"); code == 0 {
		t.Fatal("make check must fail when a test fails (no no-op gate)")
	}
}

// B3 `make build` 产出绑定 revision 的制品与回执，回执 sha256 与文件一致。
func TestBuildEntry_BuildProducesReceiptBoundArtifacts(t *testing.T) {
	dir, sha := copyTreeAsRepo(t)
	out, errOut, code := run(t, dir, []string{"CGO_ENABLED=0"}, "make", "build")
	if code != 0 {
		t.Fatalf("make build exit=%d\nstdout=%s\nstderr=%s", code, out, errOut)
	}
	receipts, _ := filepath.Glob(filepath.Join(dir, "dist", "*", "build-receipt.json"))
	if len(receipts) != 1 {
		t.Fatalf("want exactly one build receipt, got %v", receipts)
	}
	b, err := os.ReadFile(receipts[0])
	if err != nil {
		t.Fatal(err)
	}
	var r struct {
		Revision   string            `json:"revision"`
		Dirty      bool              `json:"dirty"`
		CGOEnabled bool              `json:"cgo_enabled"`
		Trimpath   bool              `json:"trimpath"`
		BuildVCS   bool              `json:"buildvcs"`
		Artifacts  map[string]string `json:"artifacts_sha256"`
	}
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatalf("receipt is not valid JSON: %v", err)
	}
	if r.Revision != sha {
		t.Errorf("receipt revision = %q, want %q", r.Revision, sha)
	}
	if r.CGOEnabled {
		t.Error("receipt must record cgo_enabled=false")
	}
	if !r.Trimpath || r.BuildVCS {
		t.Errorf("receipt must record trimpath=true and buildvcs=false, got %v/%v", r.Trimpath, r.BuildVCS)
	}
	if len(r.Artifacts) == 0 {
		t.Fatal("receipt must bind artifact hashes")
	}
	for rel, want := range r.Artifacts {
		p := filepath.Join(filepath.Dir(receipts[0]), rel)
		if _, err := os.Stat(p); err != nil {
			t.Errorf("artifact %s missing: %v", rel, err)
			continue
		}
		got, _, _ := run(t, filepath.Dir(p), nil, "shasum", "-a", "256", filepath.Base(p))
		if !strings.HasPrefix(got, want) {
			t.Errorf("artifact %s sha256=%s, receipt=%s", rel, strings.TrimSpace(got), want)
		}
	}
}

// B4 脏树必须记录 dirty=true（不标 release）。
func TestBuildEntry_DirtyTreeRecorded(t *testing.T) {
	dir, sha := copyTreeAsRepo(t)
	if err := os.WriteFile(filepath.Join(dir, "internal", "replay", "zz_dirty_marker.go"), []byte("package replay\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, errOut, code := run(t, dir, []string{"CGO_ENABLED=0"}, "make", "build"); code != 0 {
		t.Fatalf("make build on dirty tree must still produce artifacts: exit=%d\n%s\n%s", code, out, errOut)
	}
	if _, err := os.Stat(filepath.Join(dir, "dist", sha)); err == nil {
		t.Fatalf("dirty build must not write into the clean fixed-SHA dir dist/%s", sha)
	}
	receipts, _ := filepath.Glob(filepath.Join(dir, "dist", ".dirty", "*", "build-receipt.json"))
	if len(receipts) == 0 {
		t.Fatal("dirty build must produce a receipt under dist/.dirty/<rev>/")
	}
	b, _ := os.ReadFile(receipts[0])
	if !strings.Contains(string(b), `"dirty": true`) {
		t.Errorf("dirty tree must be recorded as dirty: %s", b)
	}
	if strings.Contains(string(b), `"release"`) {
		t.Errorf("unreviewed candidate must not be labeled release: %s", b)
	}
}

// B5 构建失败不得覆盖上一成功制品。
func TestBuildEntry_FailedBuildKeepsPreviousArtifacts(t *testing.T) {
	dir, _ := copyTreeAsRepo(t)
	if _, _, code := run(t, dir, []string{"CGO_ENABLED=0"}, "make", "build"); code != 0 {
		t.Fatal("baseline build failed")
	}
	receipts, _ := filepath.Glob(filepath.Join(dir, "dist", "*", "build-receipt.json"))
	before, _ := os.ReadFile(receipts[0])
	if err := os.WriteFile(filepath.Join(dir, "cmd", "collector", "zz_break.go"), []byte("package main\n\nfunc broken( {\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, code := run(t, dir, []string{"CGO_ENABLED=0"}, "make", "build"); code == 0 {
		t.Fatal("build must fail on injected compile error")
	}
	after, err := os.ReadFile(receipts[0])
	if err != nil {
		t.Fatalf("previous receipt was removed by failed build: %v", err)
	}
	if string(before) != string(after) {
		t.Error("failed build must not overwrite the previous receipt/artifacts")
	}
}

// B6 无 C 机器门禁：产物为静态 ELF（无 PT_INTERP）；import "C" 必须使 check 失败。
func TestBuildEntry_NoCMachineGate(t *testing.T) {
	dir, _ := copyTreeAsRepo(t)
	if _, _, code := run(t, dir, []string{"CGO_ENABLED=0"}, "make", "build"); code != 0 {
		t.Fatal("build failed")
	}
	bins, _ := filepath.Glob(filepath.Join(dir, "dist", "*", "collector-linux-*"))
	if len(bins) == 0 {
		t.Fatal("no linux artifact produced")
	}
	for _, bin := range bins {
		out, _, _ := run(t, filepath.Dir(bin), nil, "go", "version", "-m", filepath.Base(bin))
		if strings.Contains(out, "cgo") {
			t.Errorf("%s records cgo in build info: %s", bin, out)
		}
	}
	bad := copyTree(t)
	if err := os.WriteFile(filepath.Join(bad, "internal", "replay", "zz_cgo.go"), []byte("package replay\n\n/*\n#include <stdlib.h>\n*/\nimport \"C\"\n\nfunc zzC() { _ = C.malloc }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, code := run(t, bad, []string{"CGO_ENABLED=0"}, "make", "check"); code == 0 {
		t.Fatal("a file importing C must make make check fail")
	}
}

// B7 Chart 渲染必须满足安全与资源契约；capture=true 必须拒绝渲染。
func TestBuildEntry_ChartSafetyAndCaptureRejection(t *testing.T) {
	dir := copyTree(t)
	if _, errOut, code := run(t, dir, nil, "make", "chart"); code != 0 {
		t.Fatalf("make chart failed: %s", errOut)
	}
	tgz, _ := filepath.Glob(filepath.Join(dir, "dist", "*", "*.tgz"))
	if len(tgz) != 1 {
		t.Fatalf("want one chart tgz, got %v", tgz)
	}
	out, errOut, code := run(t, dir, nil, "helm", "template", "rel", tgz[0])
	if code != 0 {
		t.Fatalf("helm template failed: %s", errOut)
	}
	for _, needle := range []string{"activeDeadlineSeconds: 60", "backoffLimit: 0", "runAsNonRoot: true", "readOnlyRootFilesystem: true", "drop:", "RuntimeDefault", "memory: 16Mi", "memory: 64Mi", "cpu: 10m", "cpu: 100m"} {
		if !strings.Contains(out, needle) {
			t.Errorf("rendered chart missing %q", needle)
		}
	}
	for _, bad := range []string{"hostPID: true", "hostNetwork: true", "hostPath", "privileged: true", "automountServiceAccountToken: true", "persistentVolumeClaim"} {
		if strings.Contains(out, bad) {
			t.Errorf("rendered chart must not contain %q", bad)
		}
	}
	if _, _, code := run(t, dir, nil, "helm", "template", "rel", tgz[0], "--set", "capture=true"); code == 0 {
		t.Fatal("capture=true must be rejected at render time (no silent replay)")
	}
}

// B8 hooks-enable 只改本仓库配置，且安装本地 post-commit hook。
func TestBuildEntry_HooksAreLocalOnly(t *testing.T) {
	dir := copyTree(t)
	if _, _, code := run(t, dir, nil, "git", "init", "-q"); code != 0 {
		t.Fatal("git init failed")
	}
	globalBefore, _, _ := run(t, dir, nil, "git", "config", "--global", "--list")
	if _, errOut, code := run(t, dir, nil, "make", "hooks-enable"); code != 0 {
		t.Fatalf("make hooks-enable failed: %s", errOut)
	}
	got, _, _ := run(t, dir, nil, "git", "config", "--local", "core.hooksPath")
	if strings.TrimSpace(got) != ".githooks" {
		t.Errorf("core.hooksPath=%q, want .githooks (repo-local)", got)
	}
	if _, err := os.Stat(filepath.Join(dir, ".githooks", "post-commit")); err != nil {
		t.Errorf("post-commit hook missing: %v", err)
	}
	globalAfter, _, _ := run(t, dir, nil, "git", "config", "--global", "--list")
	if globalBefore != globalAfter {
		t.Error("hooks-enable must not modify global git config")
	}
}

// B9 回执必须保留 image 绑定（chart 重生成回执不得丢失 image 标签/id）。
func TestBuildEntry_ReceiptKeepsImageBinding(t *testing.T) {
	dir, sha := copyTreeAsRepo(t)
	if _, errOut, code := run(t, dir, []string{"CGO_ENABLED=0"}, "make", "build"); code != 0 {
		t.Fatalf("make build failed: %s", errOut)
	}
	dist := filepath.Join(dir, "dist", sha)
	if err := os.WriteFile(filepath.Join(dist, "image-id.txt"), []byte("sha256:deadbeef\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	receipt := filepath.Join(dist, "build-receipt.json")
	b, _ := os.ReadFile(receipt)
	var before struct {
		Image   string `json:"image"`
		ImageID string `json:"image_id"`
	}
	_ = json.Unmarshal(b, &before)
	if err := os.WriteFile(receipt, []byte(strings.Replace(string(b), `"image_id": "`+before.ImageID+`"`, `"image_id": "sha256:deadbeef"`, 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, errOut, code := run(t, dir, nil, "make", "chart"); code != 0 {
		t.Fatalf("make chart failed: %s", errOut)
	}
	b, _ = os.ReadFile(receipt)
	var r struct {
		Image    string            `json:"image"`
		ImageID  string            `json:"image_id"`
		Artifact map[string]string `json:"artifacts_sha256"`
	}
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatalf("receipt invalid: %v", err)
	}
	if r.ImageID != "sha256:deadbeef" {
		t.Errorf("chart must preserve the image id binding, got image_id=%q", r.ImageID)
	}
	if !strings.HasSuffix(r.Image, "-amd64") {
		t.Errorf("chart must preserve the local image tag, got image=%q", r.Image)
	}
	if len(r.Artifact) == 0 {
		t.Error("receipt must keep artifact hashes")
	}
}

// B10 构建期间锁必须由**存活进程**持有（acquire/hold/release 同一长寿命进程）。
func TestBuildEntry_BuildLockHeldByLiveProcess(t *testing.T) {
	dir, _ := copyTreeAsRepo(t)
	cmd := exec.Command("make", "build")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start make build: %v", err)
	}
	deadline := time.Now().Add(30 * time.Second)
	lock := filepath.Join(dir, "dist", ".build.lock", "owner.pid")
	sawLive := false
	for time.Now().Before(deadline) {
		b, err := os.ReadFile(lock)
		if err == nil {
			pid := 0
			if _, err := fmt.Sscanf(strings.TrimSpace(string(b)), "%d", &pid); err == nil && pid > 0 {
				if err := syscall.Kill(pid, 0); err == nil {
					sawLive = true
					break
				}
			}
		}
		if cmd.ProcessState != nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	_ = cmd.Wait()
	if !sawLive {
		t.Fatalf("build lock owner must be a live process while the build runs (owner pid not alive / lock not held)")
	}
}

// B11 最终回执必须同时含二进制与 chart tgz 哈希以及 image 绑定。
func TestBuildEntry_FinalReceiptHasBinariesChartAndImage(t *testing.T) {
	dir, sha := copyTreeAsRepo(t)
	if _, errOut, code := run(t, dir, []string{"CGO_ENABLED=0"}, "make", "build"); code != 0 {
		t.Fatalf("make build: %s", errOut)
	}
	dist := filepath.Join(dir, "dist", sha)
	if err := os.WriteFile(filepath.Join(dist, "image-id.txt"), []byte("sha256:cafebabe\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, errOut, code := run(t, dir, nil, "make", "chart"); code != 0 {
		t.Fatalf("make chart: %s", errOut)
	}
	b, err := os.ReadFile(filepath.Join(dist, "build-receipt.json"))
	if err != nil {
		t.Fatal(err)
	}
	var r struct {
		Image    string            `json:"image"`
		ImageID  string            `json:"image_id"`
		Artifact map[string]string `json:"artifacts_sha256"`
	}
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatalf("receipt: %v", err)
	}
	var hasLinux, hasChart bool
	for k := range r.Artifact {
		if k == "collector-linux-arm64" || k == "collector-linux-amd64" {
			hasLinux = true
		}
		if strings.HasSuffix(k, ".tgz") {
			hasChart = true
		}
	}
	if !hasLinux || !hasChart {
		t.Errorf("receipt must bind binaries and chart: %v", r.Artifact)
	}
	if r.ImageID != "sha256:cafebabe" || !strings.HasSuffix(r.Image, "-amd64") {
		t.Errorf("receipt must keep image binding: image=%q id=%q", r.Image, r.ImageID)
	}
}

// B12 make check 必须执行 tests/ 中未打 integration tag 的回归（HEAD/short-write 等）。
func TestBuildEntry_CheckRunsUntaggedTestsInTestsDir(t *testing.T) {
	dir, _ := copyTreeAsRepo(t)
	bad := filepath.Join(dir, "tests", "zz_untagged_fail_test.go")
	if err := os.WriteFile(bad, []byte("package tests\n\nimport \"testing\"\n\nfunc TestZZUntaggedFail(t *testing.T) { t.Fatal(\"injected untagged failure\") }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, code := run(t, dir, []string{"CGO_ENABLED=0"}, "make", "check"); code == 0 {
		t.Fatal("make check must run untagged tests under ./tests/ (HEAD/short-write regressions must not be lost)")
	}
}

// B13 采纳 PL 选项：已有成功目录**不覆盖**（幂等保留），首次发布仍是整组一次 rename。
func TestBuildEntry_PublishKeepsExistingSuccess(t *testing.T) {
	dir, sha := copyTreeAsRepo(t)
	if _, errOut, code := run(t, dir, []string{"CGO_ENABLED=0"}, "make", "build"); code != 0 {
		t.Fatalf("first build: %s", errOut)
	}
	dist := filepath.Join(dir, "dist", sha)
	receipt := filepath.Join(dist, "build-receipt.json")
	before, err := os.ReadFile(receipt)
	if err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(dist, "sentinel-of-existing-success.txt")
	if err := os.WriteFile(sentinel, []byte("keep\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, errOut, code := run(t, dir, []string{"CGO_ENABLED=0"}, "make", "build"); code != 0 {
		t.Fatalf("second build: %s", errOut)
	}
	if _, err := os.Stat(sentinel); err != nil {
		t.Fatal("existing successful directory must not be overwritten/removed by a later build")
	}
	after, err := os.ReadFile(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Error("existing successful receipt must stay unchanged when the directory is kept")
	}
}

// B14 锁必须 fail-closed 且**不得自动回收**：锁目录存在但 owner.pid 缺失（mkdir→写 owner 的空隙）
// 时必须拒绝构建且保留锁文件，交由人工核验清理。
func TestBuildEntry_LockFailsClosedWithoutAutoReclaim(t *testing.T) {
	dir, _ := copyTreeAsRepo(t)
	lock := filepath.Join(dir, "dist", ".build.lock")
	if err := os.MkdirAll(lock, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, errOut, code := run(t, dir, []string{"CGO_ENABLED=0"}, "make", "build"); code == 0 {
		t.Fatalf("lock present (even without owner.pid) must fail closed; stderr=%s", errOut)
	}
	if _, err := os.Stat(lock); err != nil {
		t.Fatal("lock must not be auto-removed (no automatic stale reclaim)")
	}
	if err := os.RemoveAll(lock); err != nil {
		t.Fatal(err)
	}
	if _, errOut, code := run(t, dir, []string{"CGO_ENABLED=0"}, "make", "build"); code != 0 {
		t.Fatalf("after manual lock removal the build must proceed: %s", errOut)
	}
}

// B15 有界执行器必须在超时后终止**整个进程组**（含孙进程），并等待回收。
func TestBuildEntry_RunnerKillsGrandchildrenOnTimeout(t *testing.T) {
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "grandchild.pid")
	script := "sleep 60 & echo $! > " + pidFile + "; wait"
	bin := filepath.Join(t.TempDir(), "runner")
	if _, errOut, code := run(t, repoRoot(t), nil, "go", "build", "-o", bin, "./build/runner"); code != 0 {
		t.Fatalf("build runner: %s", errOut)
	}
	_, errOut, code := run(t, repoRoot(t), nil, bin, "-timeout", "2s", "--", "sh", "-c", script)
	if code != 124 {
		t.Fatalf("runner must exit 124 on timeout, got %d (%s)", code, errOut)
	}
	b, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatalf("grandchild pid file: %v", err)
	}
	var pid int
	if _, err := fmt.Sscanf(strings.TrimSpace(string(b)), "%d", &pid); err != nil {
		t.Fatalf("parse pid: %v", err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if err := syscall.Kill(pid, 0); err != nil {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	_ = syscall.Kill(pid, syscall.SIGKILL)
	t.Fatalf("grandchild pid %d survived the runner timeout: process group was not killed", pid)
}

// B16 ci 某个阶段超时后：整条 ci 非零、**.ci.lock 必须释放**、失败回执落盘。
// 说明：本守卫与可配置超时同一批落地（无更早的有效红），如实标注，不冒充红绿历史。
func TestBuildEntry_CIReleasesLockAfterStageTimeout(t *testing.T) {
	dir, _ := copyTreeAsRepo(t)
	out, errOut, code := run(t, dir, []string{"CGO_ENABLED=0", "CI_TIMEOUT_CHECK=1s"}, "make", "ci")
	if code == 0 {
		t.Fatalf("ci must fail when a stage times out; stdout=%s stderr=%s", out, errOut)
	}
	if _, err := os.Stat(filepath.Join(dir, "dist", ".ci.lock")); err == nil {
		t.Fatal("ci lock must be released after the runner kills the stage process group")
	}
	matches, _ := filepath.Glob(filepath.Join(dir, "dist", ".failures", "*.txt"))
	if len(matches) == 0 {
		t.Error("failure receipt must be written when a ci stage fails")
	}
}

// B17 SIGTERM 必须走与超时相同的进程组清理路径（子进程独立 pgid 不随父进程收信号）。
func TestBuildEntry_RunnerCleansGroupOnSIGTERM(t *testing.T) {
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "grandchild.pid")
	bin := filepath.Join(t.TempDir(), "runner")
	if _, errOut, code := run(t, repoRoot(t), nil, "go", "build", "-o", bin, "./build/runner"); code != 0 {
		t.Fatalf("build runner: %s", errOut)
	}
	script := "sleep 60 & echo $! > " + pidFile + "; wait"
	cmd := exec.Command(bin, "-timeout", "60s", "--", "sh", "-c", script)
	cmd.Dir = repoRoot(t)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start runner: %v", err)
	}
	// 等孙进程 PID 落盘后再发 SIGTERM
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(pidFile); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("signal runner: %v", err)
	}
	_ = cmd.Wait()
	b, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatalf("grandchild pid file: %v", err)
	}
	var pid int
	if _, err := fmt.Sscanf(strings.TrimSpace(string(b)), "%d", &pid); err != nil {
		t.Fatalf("parse pid: %v", err)
	}
	deadline = time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if err := syscall.Kill(pid, 0); err != nil {
			return // 进程组已清理
		}
		time.Sleep(200 * time.Millisecond)
	}
	_ = syscall.Kill(pid, syscall.SIGKILL)
	t.Fatalf("SIGTERM must clean the whole process group; grandchild %d survived", pid)
}

// B18 清理无法确认（runner 退出 125）时：ci 必须**保留** .ci.lock（fail-closed），不得一律 rm。
func TestBuildEntry_CIKeepsLockWhenCleanupUnconfirmed(t *testing.T) {
	dir, _ := copyTreeAsRepo(t)
	fake := filepath.Join(t.TempDir(), "fake-runner-125.sh")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\nexit 125\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	out, errOut, code := run(t, dir, []string{"CGO_ENABLED=0", "CI_RUNNER=" + fake}, "make", "ci")
	if code == 0 {
		t.Fatalf("ci must fail when cleanup is unconfirmed; stdout=%s stderr=%s", out, errOut)
	}
	if _, err := os.Stat(filepath.Join(dir, "dist", ".ci.lock")); err != nil {
		t.Fatal("ci must keep .ci.lock (fail-closed) when cleanup cannot be confirmed (runner exit 125)")
	}
}

// B19 **真实默认入口**必须保留子进程真实退出码：检查阶段退出 125 时
// ci 必须看到 125 并**保留** .ci.lock（旧默认 go run 会把 125 映射成 1，从而误删锁）。
func TestBuildEntry_RealRunnerPreserves125AndKeepsLock(t *testing.T) {
	dir, _ := copyTreeAsRepo(t)
	out, errOut, code := run(t, dir, []string{"CGO_ENABLED=0", "CI_CHECK_CMD=sh -c 'exit 125'"}, "make", "ci")
	if code == 0 {
		t.Fatalf("ci must fail when the check stage exits 125; stdout=%s stderr=%s", out, errOut)
	}
	if _, err := os.Stat(filepath.Join(dir, "dist", ".ci.lock")); err != nil {
		t.Fatalf("real default entry must see 125 and keep .ci.lock; stderr=%s", errOut)
	}
	matches, _ := filepath.Glob(filepath.Join(dir, "dist", ".failures", "*.txt"))
	if len(matches) == 0 {
		t.Error("failure receipt must be written")
	}
}
