// 이 파일: builder 패키지의 TestSandboxConfigRequiresExplicitAbsoluteProfile, TestSandboxCannotBypassHostArtifactValidation, TestStoppedBuilderNeverClaimsMoreWork 회귀 시험.
package builder

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"kpctl/internal/model"
)

func TestSandboxConfigRequiresExplicitAbsoluteProfile(t *testing.T) {
	for _, entry := range []struct {
		extra string
		valid bool
	}{
		{``, true},
		{`,"sandbox":{"profile":"/profile.json","retry_clean":true}`, true},
		{`,"sandbox":{"profile":"relative"}`, false},
		{`,"sandbox":{"profile":"/profile.json","helper":"relative"}`, false},
		{`,"sandbox":{"profile":"/profile.json","worker_binary":"relative"}`, false},
	} {
		cfg, err := LoadConfig(writeConfig(t, `{"controller_url":"https://controller","token":"secret","series":"noble","work_dir":"`+t.TempDir()+`"`+entry.extra+`}`))
		if (err == nil) != entry.valid {
			t.Fatalf("%s: %v", entry.extra, err)
		}
		if err == nil && cfg.Sandbox != nil && cfg.Sandbox.Helper != "/usr/local/libexec/kpctl-build-environment" {
			t.Fatal("helper default missing")
		}
	}
}

func TestSandboxCannotBypassHostArtifactValidation(t *testing.T) {
	root := t.TempDir()
	profile := sandboxProfileFixture(t, root, "6.8.0-136-generic", "(Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0")
	repo := filepath.Join(root, "repo")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	run(t, repo, "init", "-q")
	run(t, repo, "commit", "--allow-empty", "-qm", "base")
	run(t, repo, "tag", "Ubuntu-6.8.0-136.136")
	helper := filepath.Join(root, "helper")
	// Simulate an otherwise successful container exporting a corrupt module.
	script := `#!/usr/bin/env python3
import json,sys,pathlib
r=json.loads(pathlib.Path(sys.argv[sys.argv.index('--request')+1]).read_text())
o=pathlib.Path(r['out_dir'])
assert not (o/'environment-result.json').exists()
assert not (o/(r['name']+'.ko')).exists()
(o/'environment-result.json').write_text(json.dumps({'success':True,'log':'container verified'}))
(o/(r['name']+'.ko')).write_bytes(b'not ELF')
`
	if err := os.WriteFile(helper, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(root, "out")
	os.MkdirAll(outDir, 0o755)
	os.WriteFile(filepath.Join(outDir, "environment-result.json"), []byte(`{"success":true}`), 0o600)
	os.WriteFile(filepath.Join(outDir, "isolated_test.ko"), []byte("old"), 0o600)
	b := &Builder{headersRoot: root, cfg: &Config{KernelCleanupFreeGiB: -1, WorkDir: root, BootDir: root, BuildTimeoutMinutes: 1, BuildTool: BuildToolKpatch, Token: "do-not-export-this", ControllerURL: "https://private-controller", Sandbox: &SandboxConfig{Profile: profile, Helper: helper}}}
	k := KernelConfig{Kernel: "6.8.0-136-generic", GitDir: repo, BaseTag: "Ubuntu-6.8.0-136.136"}
	out, err := b.runBuild(k, "isolated_test", outDir, nil)
	if !errors.Is(err, errBuildArtifact) || failureKind(err, "") != model.FailureArtifact || !strings.Contains(err.Error(), "결과물 검증 실패") {
		t.Fatalf("invalid module passed: %v (%s)", err, out.Log)
	}
	data, err := os.ReadFile(filepath.Join(outDir, "environment-request.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "do-not-export-this") || strings.Contains(string(data), "private-controller") {
		t.Fatal("credentials exported to worker")
	}
	var req BuildRequest
	if err := json.Unmarshal(data, &req); err != nil || !fullCommit.MatchString(req.BaseCommit) {
		t.Fatalf("not a pinned build request: %s %v", data, err)
	}
	// A missing runtime must fail closed, without invoking the host compiler.
	b.cfg.Sandbox.Helper = filepath.Join(root, "unavailable")
	if _, err := b.runBuild(k, "isolated_test", outDir, nil); !errors.Is(err, errBuildEnv) {
		t.Fatalf("no runtime: %v", err)
	}
}

func TestStoppedBuilderNeverClaimsMoreWork(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	selfUpdate := false
	b := &Builder{cfg: &Config{DiscoverMinutes: intp(60), UpdateCheckMinutes: intp(5), SelfUpdate: &selfUpdate}}
	// A nil client would panic if Run claims work or checks for an update.
	b.Run(ctx)
	if !b.stopping() {
		t.Fatal("cancellation was lost")
	}
}

func TestQueuedBuildDefersOnProfileLock(t *testing.T) {
	b, k, _ := automaticProfileFixture(t)
	b.cfg.Kernels = []KernelConfig{k}
	b.cfg.KernelCleanupFreeGiB = -1
	if err := os.WriteFile(b.cfg.Sandbox.Helper, []byte("#!/bin/sh\nexit 75\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	result := b.build(model.BuildTask{Job: model.Job{ID: 1, Version: 1, Kernel: k.Kernel}})
	if result.Success || !result.Deferred || !strings.Contains(result.Error, errBuildBusy.Error()) {
		t.Fatalf("profile lock did not defer the queued build: %+v", result)
	}
	if len(b.nextRequest(time.Now()).DeferredJobIDs) != 0 {
		t.Fatal("build lock contention inherited the APT cooldown")
	}
}

func TestSandboxDiskPressureDefersBuild(t *testing.T) {
	b, k, outDir := sandboxExecutionFixture(t)
	script := `#!/usr/bin/env python3
import json, pathlib, sys
request = json.loads(pathlib.Path(sys.argv[sys.argv.index('--request') + 1]).read_text())
result = {'success': False, 'kind': 'disk_space', 'error': '4 GiB free; need 5 GiB'}
(pathlib.Path(request['out_dir']) / 'environment-result.json').write_text(json.dumps(result))
sys.exit(1)
`
	if err := os.WriteFile(b.cfg.Sandbox.Helper, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := b.runBuild(k, "isolated_test", outDir, nil)
	if !errors.Is(err, errDiskSpace) || failureKind(err, "") != model.FailureBusy || !strings.Contains(err.Error(), "4 GiB free") {
		t.Fatalf("disk shortage was not preserved: %v", err)
	}
	if err := os.WriteFile(b.cfg.Sandbox.Helper, []byte("#!/bin/sh\necho 'No space left saving result' >&2\nexit 73\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	_, err = b.runBuild(k, "isolated_test", outDir, nil)
	if !errors.Is(err, errDiskSpace) || !strings.Contains(err.Error(), "No space left saving result") {
		t.Fatalf("lost disk deferral when helper could not write its result: %v", err)
	}
}

func TestSandboxMissingResponsePreservesProcessFailureBeforeWarningTail(t *testing.T) {
	const warning = "warning: the frame size of 1040 bytes is larger than 1024 bytes"
	for _, kind := range []string{"exit", "signal", "success without result", "invalid response"} {
		t.Run(kind, func(t *testing.T) {
			b, k, outDir := sandboxExecutionFixture(t)
			script := `#!/usr/bin/env python3
import json,os,pathlib,signal,sys
print('warning: the frame size of 1040 bytes is larger than 1024 bytes',flush=True)
`
			switch kind {
			case "exit":
				script += "sys.exit(42)\n"
			case "signal":
				script += "os.kill(os.getpid(),signal.SIGKILL)\n"
			case "invalid response":
				script += "r=json.loads(pathlib.Path(sys.argv[sys.argv.index('--request')+1]).read_text())\n(pathlib.Path(r['out_dir'])/'environment-result.json').write_text('invalid json')\nsys.exit(42)\n"
			}
			if err := os.WriteFile(b.cfg.Sandbox.Helper, []byte(script), 0755); err != nil {
				t.Fatal(err)
			}
			out, err := b.runSandboxBuild(k, "isolated_test", outDir, nil)
			if !errors.Is(err, errBuildEnv) || failureKind(err, out.Log) != model.FailureEnvironment {
				t.Fatalf("missing result must remain an environment failure: %v", err)
			}
			message := err.Error()
			contextAt := strings.Index(message, "도우미 로그 끝부분 (참고)")
			warningAt := strings.Index(message, warning)
			if contextAt < 0 || warningAt <= contextAt || !strings.Contains(out.Log, warning) {
				t.Fatalf("warning was not preserved as log context: %v (%s)", err, out.Log)
			}
			if kind == "success without result" {
				if !strings.Contains(message[:contextAt], "도우미 정상 종료") {
					t.Fatalf("missing result looked like a warning failure: %v", err)
				}
			} else {
				var exitErr *exec.ExitError
				if !errors.As(err, &exitErr) {
					t.Fatalf("actual helper exit error was discarded: %v", err)
				}
				if kind == "signal" {
					status, ok := exitErr.Sys().(syscall.WaitStatus)
					if !ok || status.Signal() != syscall.SIGKILL || !strings.Contains(message[:contextAt], "signal: killed") {
						t.Fatalf("helper signal hidden by warning tail: %v", err)
					}
					// The actual incident hit the deadline and then killed the
					// helper after its grace period. Preserve both causes.
					timeoutErr := sandboxResponseFailure(exitErr, context.DeadlineExceeded, "격리 결과 읽기 실패", os.ErrNotExist, out.Log)
					var stopped *exec.ExitError
					if !errors.Is(timeoutErr, context.DeadlineExceeded) || !errors.As(timeoutErr, &stopped) || stopped != exitErr || !strings.Contains(timeoutErr.Error(), "context deadline exceeded") || !strings.Contains(timeoutErr.Error(), "signal: killed") {
						t.Fatalf("timeout must retain its helper termination signal: %v", timeoutErr)
					}
				} else if exitErr.ExitCode() != 42 || !strings.Contains(message[:contextAt], "exit status 42") {
					t.Fatalf("helper exit code hidden by warning tail: %v", err)
				}
			}
			if kind == "invalid response" && !strings.Contains(message[:contextAt], "응답 해석 실패") {
				t.Fatalf("invalid response detail lost: %v", err)
			}
			if strings.Contains(strings.ToLower(message[:contextAt]), "oom") {
				t.Fatal("a signal must not be guessed to mean OOM")
			}
		})
	}
}

func TestSandboxMissingResponsePreservesDeadline(t *testing.T) {
	b, k, outDir := sandboxExecutionFixture(t)
	// An expired deadline exercises the real exec path without waiting minutes.
	b.cfg.BuildTimeoutMinutes = 0
	if err := os.WriteFile(b.cfg.Sandbox.Helper, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}
	_, err := b.runSandboxBuild(k, "isolated_test", outDir, nil)
	if !errors.Is(err, errBuildEnv) || !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "제한 시간/취소") {
		t.Fatalf("deadline was concealed by missing response: %v", err)
	}
}

func sandboxExecutionFixture(t *testing.T) (*Builder, KernelConfig, string) {
	t.Helper()
	root := t.TempDir()
	kernel := "6.8.0-136-generic"
	profile := sandboxProfileFixture(t, root, kernel, "(Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0")
	repo := filepath.Join(root, "repo")
	if err := os.MkdirAll(repo, 0755); err != nil {
		t.Fatal(err)
	}
	run(t, repo, "init", "-q")
	run(t, repo, "commit", "--allow-empty", "-qm", "base")
	run(t, repo, "tag", "Ubuntu-6.8.0-136.136")
	b := &Builder{headersRoot: root, cfg: &Config{KernelCleanupFreeGiB: -1, WorkDir: root, BootDir: root, BuildTimeoutMinutes: 1, BuildTool: BuildToolKpatch, Sandbox: &SandboxConfig{Profile: profile, Helper: filepath.Join(root, "helper")}}}
	k := KernelConfig{Kernel: kernel, GitDir: repo, BaseTag: "Ubuntu-6.8.0-136.136"}
	return b, k, filepath.Join(root, "out")
}

func TestOfflineWorkerRefusesHostExecution(t *testing.T) {
	t.Setenv("KPCTL_ISOLATED_WORKER", "")
	if err := RunBuildRequest("/nonexistent"); err == nil || !strings.Contains(err.Error(), "비특권") {
		t.Fatalf("worker ran outside a container: %v", err)
	}
}

func TestBuildAccountLockIsIndependentOfWorkDirectory(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	first, err := lockUserBuild()
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if second, err := lockUserBuild(); err == nil {
		second.Close()
		t.Fatal("same account admitted another build")
	}
	first.Close()
	last, err := lockUserBuild()
	if err != nil {
		t.Fatal("account lock was not released", err)
	}
	last.Close()
}

func TestGracefulStopPublishesFinishedTrialWithoutClaimingWholeTag(t *testing.T) {
	b, k, calls, first, _ := dependencyFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	posted := make(chan model.DiscoveredRequest, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/cancel-during-build":
			cancel()
		case strings.HasSuffix(r.URL.Path, "/known"):
			json.NewEncoder(w).Encode(model.KnownCommitsResponse{})
			return
		case strings.HasSuffix(r.URL.Path, "/discovered"):
			var req model.DiscoveredRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Error(err)
			}
			posted <- req
		default:
			if strings.HasSuffix(r.URL.Path, "/next") {
				t.Error("stopped builder requested another job")
			}
		}
		w.Write([]byte(`{}`))
	}))
	defer server.Close()
	t.Setenv("KPCTL_TEST_CANCEL_URL", server.URL+"/cancel-during-build")
	t.Setenv("KPCTL_TEST_FIRST_HELPER", b.cfg.KpatchBuild)
	wrapper := filepath.Join(t.TempDir(), "cancel-while-compiling")
	script := "#!/bin/sh\nset -eu\npython3 -c 'import os,urllib.request;urllib.request.urlopen(os.environ[\"KPCTL_TEST_CANCEL_URL\"], timeout=5).read()'\nexec \"$KPCTL_TEST_FIRST_HELPER\" \"$@\"\n"
	if err := os.WriteFile(wrapper, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	b.cfg.KpatchBuild = wrapper
	b.cfg.ControllerURL = server.URL
	b, err := New(b.cfg)
	if err != nil {
		t.Fatal(err)
	}
	b.runContext = ctx
	more, err := b.discover(k)
	if err != nil || !more || !b.stopping() {
		t.Fatalf("finished trial should survive cancellation: more=%v err=%v", more, err)
	}
	select {
	case req := <-posted:
		if len(req.Patches) != 1 || req.Patches[0].Commit != first.Commit || req.LatestTag != "" || len(req.Unpatchable) != 0 {
			t.Fatalf("incorrect partial progress after stop: %+v", req)
		}
	default:
		t.Fatal("finished trial was not published")
	}
	data, err := os.ReadFile(calls)
	if err != nil || strings.TrimSpace(string(data)) != "1" {
		t.Fatalf("a second trial started after cancellation: %q %v", data, err)
	}
	if b.BuildNext() {
		t.Fatal("stopped builder claimed another job")
	}
}

// 기준 빌드와 실제 빌드가 각각 제한 시간을 쓰므로, 바깥 안전장치가 그 전에 도우미를 끊으면 안 됩니다.
func TestSandboxTimeoutCoversBaselineAndBuild(t *testing.T) {
	if got := sandboxTimeout(180); got < 2*180*time.Minute {
		t.Fatalf("sandboxTimeout(180) = %v", got)
	}
}
