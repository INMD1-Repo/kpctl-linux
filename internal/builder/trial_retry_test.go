// 이 파일: builder 패키지의 TestFailedTrialPersistsUntilInputsChangeOrAdminRetries, TestTrialFailureBackoffAndBusyDoNotCreatePermanentDecision, TestTrialFingerprintTracksSandboxInputsAndPatchChanges 회귀 시험.
package builder

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"kpctl/internal/client"
	"kpctl/internal/model"
)

func TestFailedTrialPersistsUntilInputsChangeOrAdminRetries(t *testing.T) {
	b, k, calls, _, _ := dependencyFixture(t)
	b.cfg.Kernels = []KernelConfig{k}
	script := "#!/bin/sh\necho attempt >> \"$KPCTL_TEST_DEPENDENCY_CALLS\"\necho 'ERROR: changed data section'\nexit 1\n"
	if err := os.WriteFile(b.cfg.KpatchBuild, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	var posted int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/discovered") {
			posted++
		}
		w.Write([]byte(`{}`))
	}))
	defer server.Close()
	b.cfg.ControllerURL, b.cfg.Token = server.URL, "builder"
	b.c, _ = client.New(server.URL, "builder", "")
	check := func(want int) {
		t.Helper()
		data, err := os.ReadFile(calls)
		if err != nil || len(strings.Fields(string(data))) != want || posted != 0 {
			t.Fatalf("attempts=%q want=%d posted=%d err=%v", data, want, posted, err)
		}
	}
	for i := 0; i < 2; i++ {
		if more, err := b.discover(k); err == nil || more {
			t.Fatalf("미해결 시험은 수집 완료가 아님: more=%v err=%v", more, err)
		}
		check(1)
	}
	restarted, err := New(b.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.discover(k); err == nil {
		t.Fatal("재시작 뒤에도 검토 필요 상태를 보존해야 함")
	}
	check(1)
	restarted.DiscoverKernels([]string{k.Kernel})
	check(2)
	// Fixing/replacing a tool retries automatically even at the same pathname.
	if err := os.WriteFile(b.cfg.KpatchBuild, []byte(script+"# new tool revision\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.discover(k); err == nil {
		t.Fatal("바뀐 입력의 실패도 검토 상태여야 함")
	}
	check(3)
}

func TestTrialFailureBackoffAndBusyDoNotCreatePermanentDecision(t *testing.T) {
	b := &Builder{cfg: &Config{WorkDir: t.TempDir()}}
	kernel := "6.8.0-85-generic"
	if err := b.saveTrialFailure(kernel, "commit", "input", errBuildBusy); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(b.trialFailurePath(kernel)); !os.IsNotExist(err) {
		t.Fatalf("busy는 실패 기록을 남기면 안 됨: %v", err)
	}
	for _, kind := range []string{model.FailureEnvironment, model.FailureUnsupported, model.FailureArtifact, model.FailureUnknown} {
		if err := b.saveTrialFailure(kernel, "commit", "input", &buildFailure{kind, errors.New("test failure")}); err != nil {
			t.Fatal(err)
		}
		if err := b.previousTrialFailure(kernel, "commit", "input"); failureKind(err, "") != kind {
			t.Fatalf("저장한 유형 보존: kind=%s err=%v", kind, err)
		}
		if err := b.previousTrialFailure(kernel, "commit", "changed"); err != nil {
			t.Fatal("새 입력은 재시험해야 함", err)
		}
		data, _ := os.ReadFile(b.trialFailurePath(kernel))
		var record trialFailureRecord
		json.Unmarshal(data, &record)
		record.At = time.Now().Add(-7 * time.Hour)
		data, _ = json.Marshal(record)
		os.WriteFile(b.trialFailurePath(kernel), data, 0o600)
		if err := b.previousTrialFailure(kernel, "commit", "input"); (err == nil) != (kind == model.FailureEnvironment) {
			t.Fatalf("6시간 뒤에는 환경 실패만 재시도: kind=%s err=%v", kind, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	b.runContext = ctx
	b.clearTrialFailure(kernel)
	if err := b.saveTrialFailure(kernel, "commit", "input", errors.New("cancelled")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(b.trialFailurePath(kernel)); !os.IsNotExist(err) {
		t.Fatalf("종료 중에는 실패 기록을 남기면 안 됨: %v", err)
	}
}

func TestTrialFingerprintTracksSandboxInputsAndPatchChanges(t *testing.T) {
	b, k, _, first, _ := dependencyFixture(t)
	root := t.TempDir()
	profile := sandboxProfileFixture(t, root, k.Kernel, "(Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0")
	symvers := filepath.Join(root, "linux-headers-"+k.Kernel, "Module.symvers")
	os.WriteFile(symvers, []byte("0x12345678 module_layout vmlinux EXPORT_SYMBOL\n"), 0o600)
	helper := filepath.Join(root, "helper")
	worker := filepath.Join(root, "worker")
	os.WriteFile(helper, []byte("helper1"), 0o700)
	os.WriteFile(worker, []byte("worker1"), 0o700)
	b.headersRoot = root
	b.cfg.Sandbox = &SandboxConfig{Profile: profile, Helper: helper, WorkerBinary: worker}
	before, err := b.trialEnvironmentFingerprint(k, "Ubuntu-6.8.0-90.90")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{helper, worker, profile, symvers, filepath.Join(b.cfg.BootDir, "config-"+k.Kernel), k.Vmlinux} {
		original, _ := os.ReadFile(path)
		changed := append(append([]byte(nil), original...), '\n')
		if path == symvers {
			changed = []byte(strings.Replace(string(original), "0x12345678", "0x87654321", 1))
		}
		if path == profile {
			var p map[string]any
			json.Unmarshal(original, &p)
			p["image"] = "sha256:" + strings.Repeat("b", 64)
			changed, _ = json.Marshal(p)
		}
		os.WriteFile(path, changed, 0o600)
		after, err := b.trialEnvironmentFingerprint(k, "Ubuntu-6.8.0-90.90")
		if err != nil || after == before {
			t.Fatalf("입력이 바뀌면 식별값도 바뀌어야 함: %s %v", path, err)
		}
		os.WriteFile(path, original, 0o600)
	}
	original := trialFingerprint(before, first.Content, []model.DiscoveredPatch{first}, []string{"b", "a"})
	if reordered := trialFingerprint(before, first.Content, []model.DiscoveredPatch{first}, []string{"a", "b"}); reordered != original {
		t.Fatal("같은 관리자 판단 목록은 순서만 바뀌어도 같은 입력이어야 함")
	}
	if trialFingerprint(before, first.Content+"changed", []model.DiscoveredPatch{first}, []string{"a", "b"}) == original ||
		trialFingerprint(before, first.Content, nil, []string{"a", "b"}) == original ||
		trialFingerprint(before, first.Content, []model.DiscoveredPatch{first}, nil) == original {
		t.Fatal("후보·활성 패치·관리자 판단이 바뀌면 재시험해야 함")
	}
}

func TestTrialInputRejectsFIFOAndPurgeRemovesFailureRecord(t *testing.T) {
	root := t.TempDir()
	fifo := filepath.Join(root, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := retryFileIdentity(fifo); err == nil {
		t.Fatal("FIFO 입력은 대기 없이 거부해야 함")
	}
	b := &Builder{cfg: &Config{WorkDir: root}}
	kernel := "6.8.0-85-generic"
	if err := b.saveTrialFailure(kernel, "c", "f", errors.New("failure")); err != nil {
		t.Fatal(err)
	}
	if n, err := b.purgeKernelWorkDir(kernel); err != nil || n != 1 {
		t.Fatalf("시험 자료 삭제에 재시험 보류 기록 포함: %d %v", n, err)
	}
	if _, err := os.Stat(b.trialFailurePath(kernel)); !os.IsNotExist(err) {
		t.Fatalf("실패 기록을 지워야 함: %v", err)
	}
}
