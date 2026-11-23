// 이 파일: builder 패키지의 TestSourceCheckPreservesRepositoryIndexAndFindsLeftovers, TestDirtyBuildNeedsReviewAndNextAttemptReextracts, TestBuildLockRejectsConcurrentCacheUse 회귀 시험.
package builder

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func sourceIntegrityFixture(t *testing.T) (*Builder, KernelConfig, string) {
	t.Helper()
	root := t.TempDir()
	repo := filepath.Join(root, "repo")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"file.c": "int original;\n", ".gitignore": "*.o\n"} {
		if err := os.WriteFile(filepath.Join(repo, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	run(t, repo, "init", "-q")
	run(t, repo, "add", ".")
	run(t, repo, "commit", "-qm", "base")
	run(t, repo, "tag", "Ubuntu-6.8.0-85.85")
	if err := os.WriteFile(filepath.Join(root, "config-6.8.0-85-generic"), []byte("CONFIG_LIVEPATCH=y\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	b := &Builder{cfg: &Config{KernelCleanupFreeGiB: -1, WorkDir: filepath.Join(root, "work"), BootDir: root}}
	k := KernelConfig{Kernel: "6.8.0-85-generic", GitDir: repo, BaseTag: "Ubuntu-6.8.0-85.85"}
	src, log, err := b.kernelSource(context.Background(), k)
	if err != nil {
		t.Fatalf("source: %v %s", err, log)
	}
	return b, k, src
}

func TestSourceCheckPreservesRepositoryIndexAndFindsLeftovers(t *testing.T) {
	b, k, src := sourceIntegrityFixture(t)
	indexPath := filepath.Join(k.GitDir, ".git/index")
	before, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatal(err)
	}
	// The repository's current checkout is independent of the extracted base source.
	if err := os.WriteFile(filepath.Join(k.GitDir, "file.c"), []byte("int caller_change;\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "build.o"), []byte("generated"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := b.verifySourceTree(context.Background(), k, src); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "leftover.c"), []byte("int leftover;\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := b.verifySourceTree(context.Background(), k, src); !errors.Is(err, errSourceDirty) {
		t.Fatalf("new source left behind by a patch must be detected: %v", err)
	}
	after, err := os.ReadFile(indexPath)
	if err != nil || string(before) != string(after) {
		t.Fatal("source verification must not change the caller's repository index")
	}
}

func TestDirtyBuildNeedsReviewAndNextAttemptReextracts(t *testing.T) {
	b, k, src := sourceIntegrityFixture(t)
	helper := filepath.Join(b.cfg.WorkDir, "bad-build")
	script := `#!/bin/sh
while [ "$#" -gt 0 ]; do
 case "$1" in
  -s) source="$2"; shift 2 ;;
  *) shift ;;
 esac
done
printf 'int poisoned;\n' > "$source/file.c"
echo 'ERROR: changed data section'
exit 1
`
	if err := os.WriteFile(helper, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	b.cfg.KpatchBuild, b.cfg.BuildTool, b.cfg.BuildTimeoutMinutes = helper, BuildToolKpatch, 1
	reason, err := b.trialBuild(k, "0123456789abcdef", "--- a/file.c\n+++ b/file.c\n")
	if reason != "" || err == nil || !strings.Contains(err.Error(), "소스 복구") {
		t.Fatalf("dirty cleanup overrides even an explicit constraint diagnostic: %q %v", reason, err)
	}
	if _, err := os.Stat(filepath.Join(src, sourceBuildMarker)); err != nil {
		t.Fatal("failed cleanup must preserve the interrupted marker", err)
	}
	if _, _, err := b.kernelSource(context.Background(), k); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(filepath.Join(src, "file.c"))
	if string(data) != "int original;\n" {
		t.Fatal("the next attempt must re-extract the original source")
	}
	// A process that dies before finish() leaves a marker even when source bytes look clean.
	if _, err := b.trackSourceBuild(context.Background(), k, src); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "marker-survivor"), []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.kernelSource(context.Background(), k); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(src, "marker-survivor")); !os.IsNotExist(err) {
		t.Fatal("an interrupted source tree must be replaced, not reused")
	}
}

func TestBuildLockRejectsConcurrentCacheUse(t *testing.T) {
	b, _, _ := sourceIntegrityFixture(t)
	first, err := b.lockBuild()
	if err != nil {
		t.Fatal(err)
	}
	if second, err := b.lockBuild(); err == nil {
		second.Close()
		t.Fatal("concurrent builder must not enter source preparation")
	}
	first.Close()
	second, err := b.lockBuild()
	if err != nil {
		t.Fatal("lock must be released when its process/file closes", err)
	}
	second.Close()
}

func TestCanceledBuildKillsCompilerChildren(t *testing.T) {
	root := t.TempDir()
	ready, leaked := filepath.Join(root, "ready"), filepath.Join(root, "leaked")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := exec.CommandContext(ctx, "sh", "-c", `(sleep 1; echo leaked > "$2") &
echo ready > "$1"
wait`, "build", ready, leaked)
	killProcessGroup(cmd)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if cmd.ProcessState == nil {
			cancel()
			cmd.Wait()
		}
	}()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("test build did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := cmd.Wait(); err == nil {
		t.Fatal("canceled build must fail")
	}
	time.Sleep(1200 * time.Millisecond)
	if _, err := os.Stat(leaked); !os.IsNotExist(err) {
		t.Fatal("compiler child survived cancellation and wrote into the source tree")
	}
}

func TestSystemSourceTree(t *testing.T) {
	src := os.Getenv("KPCTL_TEST_SOURCE")
	if src == "" {
		t.Skip("set KPCTL_TEST_SOURCE, KPCTL_TEST_GIT and KPCTL_TEST_BASE_TAG on the builder")
	}
	b := &Builder{cfg: &Config{KernelCleanupFreeGiB: -1, WorkDir: t.TempDir()}}
	if err := b.verifySourceTree(context.Background(), KernelConfig{GitDir: os.Getenv("KPCTL_TEST_GIT"), BaseTag: os.Getenv("KPCTL_TEST_BASE_TAG")}, src); err != nil {
		t.Fatal(err)
	}
}
