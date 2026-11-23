// 이 파일: builder 패키지의 TestSystemSandboxArtifact, TestSystemTCPMappedChildAdaptation, TestSystemKVMMMUAdaptation 회귀 시험.
package builder

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"kpctl/internal/model"
)

// Offline, opt-in real compilation for either tool. The config must contain
// exactly one target and an explicitly enabled disposable environment.
func TestSystemSandboxArtifact(t *testing.T) {
	path := os.Getenv("KPCTL_TEST_SANDBOX_CONFIG")
	if path == "" {
		t.Skip("set KPCTL_TEST_SANDBOX_CONFIG and KPCTL_TEST_SANDBOX_PATCHES on an idle builder")
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Sandbox == nil || len(cfg.Kernels) != 1 {
		t.Fatal("real isolated test requires sandbox and exactly one target")
	}
	if cfg.Sandbox.WorkerBinary == "" {
		t.Fatal("test runner requires sandbox.worker_binary pointing to the actual kpctl-builder executable")
	}
	var files []string
	if err := json.Unmarshal([]byte(os.Getenv("KPCTL_TEST_SANDBOX_PATCHES")), &files); err != nil || len(files) == 0 {
		t.Fatal("patch inputs must be a nonempty JSON path array", err)
	}
	dir := filepath.Join(cfg.WorkDir, "isolated-acceptance")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	b := &Builder{cfg: cfg}
	out, buildErr := b.runBuild(cfg.Kernels[0], "kpctl_isolated_acceptance", filepath.Join(dir, "out"), files)
	if err := os.WriteFile(filepath.Join(dir, "build.log"), []byte(out.Log), 0o640); err != nil {
		t.Fatal(err)
	}
	if buildErr != nil {
		t.Fatalf("%v; log: %s", buildErr, filepath.Join(dir, "build.log"))
	}
	t.Logf("verified artifact: %s\n%s", out.ModulePath, lastLines(out.Log, 4))
}

// Opt-in compilation on an isolated/idle builder. Never registers, approves,
// loads, or reboots anything. The usual work-dir lock and ABI checks apply.
func TestSystemTCPMappedChildAdaptation(t *testing.T) {
	testReviewedAdaptation(t, "KPCTL_TEST_TCP_ADAPT_CONFIG", "25e02a1564bb0cd0cb9fc926e9ddde4ece8ce800", "review-cve-2026-43198-abi", "kpctl_adapt_cve43198")
}

func TestSystemKVMMMUAdaptation(t *testing.T) {
	testReviewedAdaptation(t, "KPCTL_TEST_KVM_ADAPT_CONFIG", "8c3fb26c9d258976db78d7fe1e4a996e22770373", "review-cve-2026-53359-locations", "kpctl_adapt_cve53359")
}

func testReviewedAdaptation(t *testing.T, configEnv, commit, reviewDir, name string) {
	t.Helper()
	path := os.Getenv(configEnv)
	if path == "" {
		t.Skip("set " + configEnv + " on an idle Ubuntu 24 builder")
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Sandbox != nil && cfg.Sandbox.WorkerBinary == "" {
		t.Fatal("test runner requires sandbox.worker_binary pointing to the actual kpctl-builder executable")
	}
	k := KernelConfig{Kernel: "6.8.0-136-generic", BaseTag: "Ubuntu-6.8.0-136.136",
		GitDir: filepath.Join(cfg.GitRoot, "ubuntu-noble"), Vmlinux: filepath.Join(cfg.DebugDir, "vmlinux-6.8.0-136-generic")}
	a := selectAdaptation(k, commit)
	if a == nil {
		t.Fatal("this architecture has no reviewed adaptation")
	}
	content, err := a.verifiedContent(k)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(cfg.WorkDir, reviewDir)
	cumulative := os.Getenv("KPCTL_TEST_TCP_ADAPT_CUMULATIVE") == "1"
	if cumulative {
		dir = filepath.Join(dir, "cumulative")
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	var files []string
	b := &Builder{cfg: cfg}
	if cumulative {
		b, err = New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		var known model.KnownCommitsResponse
		if err := b.c.Do("GET", "/api/builder/kernels/"+k.Kernel+"/known", nil, &known); err != nil {
			t.Fatal(err)
		}
		for i, p := range known.ActivePatches {
			if p.Commit == a.commit {
				continue
			}
			file := filepath.Join(dir, fmt.Sprintf("%04d-prerequisite.patch", i))
			if err := os.WriteFile(file, []byte(p.Content), 0o640); err != nil {
				t.Fatal(err)
			}
			files = append(files, file)
		}
		if len(files) == 0 {
			t.Fatal("cumulative verification requires existing active patches")
		}
	}
	patch := filepath.Join(dir, "adapted.patch")
	if err := os.WriteFile(patch, []byte(content), 0o640); err != nil {
		t.Fatal(err)
	}
	files = append(files, patch)
	if cumulative {
		name += "_cumulative"
	}
	t.Logf("source patches: %d, cumulative=%v", len(files), cumulative)
	out, buildErr := b.runBuild(k, name, filepath.Join(dir, "out"), files)
	if err := os.WriteFile(filepath.Join(dir, "build.log"), []byte(out.Log), 0o640); err != nil {
		t.Fatal(err)
	}
	if buildErr != nil {
		t.Fatalf("%v; full log: %s", buildErr, filepath.Join(dir, "build.log"))
	}
	t.Logf("verified artifact: %s\n%s", out.ModulePath, lastLines(out.Log, 8))
}

// Opt-in normal queue workflow: claims and submits ONE build result, then
// exits without discovery or auto-update. Inspect the controller job/log for
// success; this runner never approves a module or touches a host.
func TestSystemProcessOneQueuedJob(t *testing.T) {
	path := os.Getenv("KPCTL_TEST_ONE_JOB_CONFIG")
	if path == "" {
		t.Skip("set KPCTL_TEST_ONE_JOB_CONFIG on an idle builder with one intended queued job")
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	b, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !b.BuildNext() {
		t.Fatal("no matching queued job processed")
	}
	t.Log("one queued request processed; inspect the controller job result")
}
