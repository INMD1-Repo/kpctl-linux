// 이 파일: agent 패키지의 TestAutomaticKernelPrepareReportsWhileInstallingWithoutReboot, TestInterruptedRefreshRequiresReviewWhenGRUBChanged, TestConfirmedJumpAllowsNextAutomaticPreparation 회귀 시험.
package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"kpctl/internal/client"
	"kpctl/internal/model"
)

func collectKernelPrepare(t *testing.T, a *Agent) {
	t.Helper()
	select {
	case result := <-a.prepareDone:
		a.finishKernelPrepare(result)
	case <-time.After(3 * time.Second):
		t.Fatal("preparation did not finish")
	}
}

func TestAutomaticKernelPrepareReportsWhileInstallingWithoutReboot(t *testing.T) {
	a, _, root, claims := rebootAgentFixture(t)
	record, err := os.ReadFile(a.cfg.BootTargetPath)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(a.cfg.BootTargetPath); err != nil {
		t.Fatal(err)
	}
	a.st.HostID, a.st.HostToken = "test-host", "token"
	started, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	a.prepareRun = func(ctx context.Context, stateDir string) error {
		calls.Add(1)
		if stateDir != a.cfg.StateDir {
			return fmt.Errorf("wrong state dir: %s", stateDir)
		}
		close(started)
		select {
		case <-release:
			return os.WriteFile(a.cfg.BootTargetPath, record, 0600)
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	var reports []model.ReportRequest
	var reportsMu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/agent/report" {
			t.Errorf("unexpected request: %s", r.URL.Path)
			return
		}
		var req model.ReportRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
		}
		reportsMu.Lock()
		reports = append(reports, req)
		reportsMu.Unlock()
		_ = json.NewEncoder(w).Encode(model.ReportResponse{PrepareKernel: true})
	}))
	defer srv.Close()
	a.c, _ = client.New(srv.URL, "token", "")
	a.Cycle()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("helper never started")
	}
	a.Cycle()
	reportsMu.Lock()
	if calls.Load() != 1 || len(reports) != 3 || reports[1].Status.KernelPrepare == nil || reports[1].Status.KernelPrepare.State != "preparing" || reports[2].Status.KernelPrepare.State != "preparing" {
		t.Fatalf("preparation must report and avoid duplicate execution: calls=%d reports=%+v", calls.Load(), reports)
	}
	reportsMu.Unlock()
	close(release)
	collectKernelPrepare(t, a)
	a.Cycle()
	reportsMu.Lock()
	defer reportsMu.Unlock()
	if a.st.KernelPrepare.State != "prepared" || a.st.KernelPrepare.Error != "" || calls.Load() != 1 || reports[len(reports)-1].Status.BootTarget == nil {
		t.Fatalf("prepared target was not verified and reported: %+v", a.st.KernelPrepare)
	}
	if _, err := os.Stat(filepath.Join(root, "rebooted")); !os.IsNotExist(err) || *claims != 0 || a.st.LastRebootID != 0 {
		t.Fatal("installation must never authorize or execute a reboot")
	}
}

func TestInterruptedRefreshRequiresReviewWhenGRUBChanged(t *testing.T) {
	a, approval, _, _ := rebootAgentFixture(t)
	a.prepareRun = func(context.Context, string) error {
		if err := os.WriteFile(a.cfg.GrubConfig, []byte("partially regenerated GRUB"), 0600); err != nil {
			return err
		}
		return errors.New("package hook failed")
	}
	if !a.maybePrepareKernel(model.ReportResponse{PrepareKernel: true, PrepareKernelTargetID: approval.Target.ID}) {
		t.Fatal("refresh did not start")
	}
	collectKernelPrepare(t, a)
	if p := a.st.KernelPrepare; p.State != "failed" || !p.NextAttemptAt.IsZero() || !strings.Contains(p.Error, "자동 갱신 중지") || !strings.Contains(p.Error, "package hook failed") {
		t.Fatalf("invalid preparation did not request review: %+v", p)
	}
	if _, err := os.Stat(a.cfg.BootTargetPath); err != nil {
		t.Fatal("failed refresh removed evidence", err)
	}
	restarted, err := New(a.cfg)
	if err != nil || restarted.st.KernelPrepare == nil || !strings.Contains(restarted.st.KernelPrepare.Error, "자동 갱신 중지") {
		t.Fatalf("review state was not preserved: %v", err)
	}
	if restarted.maybePrepareKernel(model.ReportResponse{PrepareKernel: true, PrepareKernelTargetID: approval.Target.ID}) {
		t.Fatal("invalid target was automatically overwritten")
	}
}

func TestConfirmedJumpAllowsNextAutomaticPreparation(t *testing.T) {
	a, approval, _, _ := rebootAgentFixture(t)
	a.st.PendingReboot = approval
	a.cfg.SignaturePath = filepath.Join(a.cfg.StateDir, "signature")
	writeTestFile(t, a.cfg.OSReleasePath, approval.Target.Kernel)
	writeTestFile(t, a.cfg.BootIDPath, "boot-after")
	writeTestFile(t, a.cfg.SignaturePath, "Ubuntu 6.8.0-86.86-generic 6.8.12")
	if err := a.reconcileBootChoice(model.ReportResponse{RebootResult: &model.RebootResult{ID: approval.ID, Status: "booted"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(a.cfg.BootTargetPath); !os.IsNotExist(err) {
		t.Fatal("confirmed record blocks the next jump")
	}
	a.prepareRun = func(context.Context, string) error { return errors.New("next archive probe") }
	if !a.maybePrepareKernel(model.ReportResponse{PrepareKernel: true}) {
		t.Fatal("next official jump was not started")
	}
	collectKernelPrepare(t, a)
	if a.st.KernelPrepare.Kernel != approval.Target.Kernel {
		t.Fatal("next jump did not use the running kernel")
	}
}

func TestKernelPreparationRefreshPreservesOldTargetUntilAtomicReplacement(t *testing.T) {
	a, approval, root, claims := rebootAgentFixture(t)
	original, err := os.ReadFile(a.cfg.BootTargetPath)
	if err != nil {
		t.Fatal(err)
	}
	newTarget := approval.Target
	newTarget.Kernel, newTarget.PackageVersion = "6.8.0-87-generic", "6.8.0-87.87"
	newTarget.Entry = strings.Replace(newTarget.Entry, approval.Target.Kernel, newTarget.Kernel, 1)
	for _, prefix := range []string{"vmlinuz-", "initrd.img-", "config-"} {
		writeTestFile(t, filepath.Join(a.cfg.BootDir, prefix+newTarget.Kernel), "new-"+prefix)
	}
	newTarget.ImageSHA256, _ = fileSHA256(filepath.Join(a.cfg.BootDir, "vmlinuz-"+newTarget.Kernel))
	newTarget.InitrdSHA256, _ = fileSHA256(filepath.Join(a.cfg.BootDir, "initrd.img-"+newTarget.Kernel))
	newTarget.ConfigSHA256, _ = fileSHA256(filepath.Join(a.cfg.BootDir, "config-"+newTarget.Kernel))
	oldGrub, err := os.ReadFile(a.cfg.GrubConfig)
	if err != nil {
		t.Fatal(err)
	}
	newGrub := append(oldGrub, []byte(" 'gnulinux-6.8.0-87-generic-advanced-abc'")...)
	started, release := make(chan struct{}), make(chan struct{})
	a.prepareRun = func(ctx context.Context, stateDir string) error {
		data, err := os.ReadFile(a.cfg.BootTargetPath)
		if err != nil || string(data) != string(original) {
			return errors.New("old target was removed before helper started")
		}
		close(started)
		select {
		case <-release:
		case <-ctx.Done():
			return ctx.Err()
		}
		if err := os.WriteFile(a.cfg.GrubConfig, newGrub, 0600); err != nil {
			return err
		}
		newTarget.GrubSHA256, err = fileSHA256(a.cfg.GrubConfig)
		if err != nil {
			return err
		}
		newTarget.ID = model.BootTargetID(newTarget)
		data, err = json.Marshal(newTarget)
		if err != nil {
			return err
		}
		temp := filepath.Join(stateDir, "boot-target.json.tmp")
		if err := os.WriteFile(temp, data, 0600); err != nil {
			return err
		}
		return os.Rename(temp, a.cfg.BootTargetPath)
	}
	resp := model.ReportResponse{PrepareKernel: true, PrepareKernelTargetID: approval.Target.ID}
	if !a.maybePrepareKernel(resp) {
		t.Fatal("current validated target was not allowed to refresh")
	}
	<-started
	if target, problem := a.bootTarget(); target == nil || target.ID != approval.Target.ID {
		t.Fatalf("old target was not preserved while installing: %+v %s", target, problem)
	}
	if a.maybePrepareKernel(resp) {
		t.Fatal("duplicate refresh started while installing")
	}
	close(release)
	collectKernelPrepare(t, a)
	if target, problem := a.bootTarget(); target == nil || target.Kernel != newTarget.Kernel || target.ID != newTarget.ID || a.st.KernelPrepare.State != "prepared" {
		t.Fatalf("replacement was not fully validated: %+v %s %+v", target, problem, a.st.KernelPrepare)
	}
	if _, err := os.Stat(filepath.Join(root, "rebooted")); !os.IsNotExist(err) || *claims != 0 || a.st.LastRebootID != 0 {
		t.Fatal("refresh authorized or executed a reboot")
	}
}

func TestKernelPreparationRefreshRejectsChangedUnsafeOrApprovedTarget(t *testing.T) {
	for _, kind := range []string{"changed ID", "corrupt record", "changed image", "writable record", "symlink", "dangling symlink", "missing record", "approval", "legacy approval", "pending", "armed", "foreign next entry", "GRUB unavailable", "not requested"} {
		t.Run(kind, func(t *testing.T) {
			a, approval, root, _ := rebootAgentFixture(t)
			resp := model.ReportResponse{PrepareKernel: true, PrepareKernelTargetID: approval.Target.ID}
			switch kind {
			case "changed ID":
				resp.PrepareKernelTargetID = strings.Repeat("a", 64)
			case "corrupt record":
				writeTestFile(t, a.cfg.BootTargetPath, "not json")
			case "changed image":
				writeTestFile(t, filepath.Join(a.cfg.BootDir, "vmlinuz-"+approval.Target.Kernel), "changed")
			case "writable record":
				_ = os.Chmod(a.cfg.BootTargetPath, 0666)
			case "symlink", "dangling symlink":
				other := filepath.Join(root, "other-target.json")
				if kind == "symlink" {
					data, _ := os.ReadFile(a.cfg.BootTargetPath)
					writeTestFile(t, other, string(data))
				}
				_ = os.Remove(a.cfg.BootTargetPath)
				if err := os.Symlink(other, a.cfg.BootTargetPath); err != nil {
					t.Fatal(err)
				}
			case "missing record":
				_ = os.Remove(a.cfg.BootTargetPath)
			case "approval":
				resp.Reboot = approval
			case "legacy approval":
				resp.RebootID = approval.ID
			case "pending":
				a.st.PendingReboot = approval
			case "armed":
				a.st.BootChoiceArmed = true
			case "foreign next entry":
				writeTestFile(t, a.cfg.GrubEnv, "another-entry")
			case "GRUB unavailable":
				a.cfg.GrubEditenvBin = filepath.Join(root, "missing")
			case "not requested":
				resp.PrepareKernel = false
			}
			a.prepareRun = func(context.Context, string) error {
				t.Error("unsafe refresh launched")
				return nil
			}
			if a.maybePrepareKernel(resp) || a.prepareDone != nil || a.st.KernelPrepare != nil {
				t.Fatal("unsafe refresh changed preparation state")
			}
		})
	}
}

func TestKernelPreparationRefreshFailureKeepsRecordAndPersistedBackoff(t *testing.T) {
	a, approval, _, _ := rebootAgentFixture(t)
	original, err := os.ReadFile(a.cfg.BootTargetPath)
	if err != nil {
		t.Fatal(err)
	}
	resp := model.ReportResponse{PrepareKernel: true, PrepareKernelTargetID: approval.Target.ID}
	a.prepareRun = func(context.Context, string) error { return errors.New("archive unavailable") }
	if !a.maybePrepareKernel(resp) {
		t.Fatal("refresh was not started")
	}
	collectKernelPrepare(t, a)
	data, err := os.ReadFile(a.cfg.BootTargetPath)
	if err != nil || string(data) != string(original) {
		t.Fatal("failed refresh removed or changed existing target")
	}
	if a.st.KernelPrepare.State != "failed" || !strings.Contains(a.st.KernelPrepare.Error, "archive unavailable") || time.Until(a.st.KernelPrepare.NextAttemptAt) < kernelPrepareRetry-time.Minute {
		t.Fatalf("refresh failure did not preserve six-hour backoff: %+v", a.st.KernelPrepare)
	}
	restarted, err := New(a.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if restarted.maybePrepareKernel(resp) {
		t.Fatal("restart bypassed refresh backoff")
	}
	if target, problem := restarted.bootTarget(); target == nil || target.ID != approval.Target.ID {
		t.Fatalf("failed refresh lost previous valid target: %+v %s", target, problem)
	}
}

func TestConfirmedJumpPreservesDifferentPreparationRecord(t *testing.T) {
	a, approval, _, _ := rebootAgentFixture(t)
	newRecord := `{"kernel":"6.8.0-87-generic"}`
	writeTestFile(t, a.cfg.BootTargetPath, newRecord)
	if err := a.retireBootTarget(approval.Target); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(a.cfg.BootTargetPath)
	if err != nil || string(data) != newRecord {
		t.Fatal("confirmation removed a different prepared target")
	}
}

func TestConfirmedJumpWaitsForManualPreparationLock(t *testing.T) {
	a, approval, _, _ := rebootAgentFixture(t)
	a.st.PendingReboot = approval
	a.cfg.SignaturePath = filepath.Join(a.cfg.StateDir, "signature")
	writeTestFile(t, a.cfg.OSReleasePath, approval.Target.Kernel)
	writeTestFile(t, a.cfg.BootIDPath, "boot-after")
	writeTestFile(t, a.cfg.SignaturePath, "Ubuntu 6.8.0-86.86-generic 6.8.12")
	lock, err := os.OpenFile(a.cfg.KernelPrepareLock, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	response := model.ReportResponse{RebootResult: &model.RebootResult{ID: approval.ID, Status: "booted"}}
	if err := a.reconcileBootChoice(response); err == nil || !strings.Contains(err.Error(), "커널 준비 중") {
		t.Fatalf("confirmation bypassed preparation lock: %v", err)
	}
	if a.st.PendingReboot == nil {
		t.Fatal("busy confirmation lost pending approval")
	}
	if saved, err := a.grubField("saved_entry"); err != nil || saved != approval.Target.FallbackEntry {
		t.Fatal("busy confirmation changed the saved default", saved, err)
	}
	if _, err := os.Stat(a.cfg.BootTargetPath); err != nil {
		t.Fatal("busy confirmation retired prepared target", err)
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	if err := a.reconcileBootChoice(response); err != nil {
		t.Fatal(err)
	}
	if a.st.PendingReboot != nil {
		t.Fatal("confirmation did not recover after preparation finished")
	}
	if _, err := os.Stat(a.cfg.BootTargetPath); !os.IsNotExist(err) {
		t.Fatal("confirmed record was not retired")
	}
}

func TestKernelPrepareFailureBackoffSurvivesRestartAndPatchSuccess(t *testing.T) {
	a, _ := newTestAgent(t)
	a.cfg.BootTargetPath = filepath.Join(a.cfg.StateDir, "boot-target.json")
	a.prepareRun = func(context.Context, string) error { return errors.New("archive unavailable") }
	if !a.maybePrepareKernel(model.ReportResponse{PrepareKernel: true}) {
		t.Fatal("not started")
	}
	collectKernelPrepare(t, a)
	p := *a.st.KernelPrepare
	if p.State != "failed" || !strings.Contains(p.Error, "archive unavailable") || time.Until(p.NextAttemptAt) < kernelPrepareRetry-time.Minute {
		t.Fatalf("missing bounded backoff: %+v", p)
	}
	// Unrelated livepatch success must not erase the installation failure.
	a.st.FailedAt = time.Now()
	a.apply(model.DesiredPatch{})
	if a.st.KernelPrepare.Error != p.Error {
		t.Fatal("patch result erased preparation error")
	}
	restarted, err := New(a.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if restarted.st.KernelPrepare == nil || !restarted.st.KernelPrepare.NextAttemptAt.Equal(p.NextAttemptAt) || restarted.maybePrepareKernel(model.ReportResponse{PrepareKernel: true}) {
		t.Fatal("restart bypassed persisted retry delay")
	}
	restarted.st.KernelPrepare.NextAttemptAt = time.Now().Add(-time.Second)
	restarted.prepareRun = func(context.Context, string) error { return nil }
	if !restarted.maybePrepareKernel(model.ReportResponse{PrepareKernel: true}) {
		t.Fatal("elapsed backoff did not retry")
	}
	collectKernelPrepare(t, restarted)
	if restarted.st.KernelPrepare.State != "failed" || !strings.Contains(restarted.st.KernelPrepare.Error, "검증 실패") {
		t.Fatal("helper exit success must require an actually valid prepared target")
	}
}

// 원인을 고친 관리자가 다시 요청하면 6시간을 기다리지 않고 한 번만 바로 재시도합니다.
func TestNewAdminRequestSkipsRetryDelayOnce(t *testing.T) {
	a, _ := newTestAgent(t)
	a.cfg.BootTargetPath = filepath.Join(a.cfg.StateDir, "boot-target.json")
	a.prepareRun = func(context.Context, string) error { return errors.New("helper missing") }
	first := time.Now().Add(-time.Hour)
	if !a.maybePrepareKernel(model.ReportResponse{PrepareKernel: true, PrepareKernelRequest: &first}) {
		t.Fatal("not started")
	}
	collectKernelPrepare(t, a)
	if a.maybePrepareKernel(model.ReportResponse{PrepareKernel: true}) {
		t.Fatal("automatic request bypassed retry delay")
	}
	if a.maybePrepareKernel(model.ReportResponse{PrepareKernel: true, PrepareKernelRequest: &first}) {
		t.Fatal("same admin request retried again")
	}
	second := first.Add(time.Second)
	// 컨트롤러 시계가 뒤처져도(요청 시각이 과거) 새 요청이면 재시도
	if !a.maybePrepareKernel(model.ReportResponse{PrepareKernel: true, PrepareKernelRequest: &second}) {
		t.Fatal("new admin request waited for retry delay")
	}
	collectKernelPrepare(t, a)
}

func TestKernelPrepareRejectsIncompatibleTargetPath(t *testing.T) {
	a, root := newTestAgent(t)
	a.cfg.BootTargetPath = filepath.Join(root, "custom-target.json")
	a.prepareRun = func(context.Context, string) error {
		t.Error("helper must not write a different target path")
		return nil
	}
	if !a.maybePrepareKernel(model.ReportResponse{PrepareKernel: true}) || a.prepareDone != nil || a.st.KernelPrepare.State != "failed" || !strings.Contains(a.st.KernelPrepare.Error, "boot_target_path") {
		t.Fatalf("incompatible configured path must fail before execution: %+v", a.st.KernelPrepare)
	}
	restarted, err := New(a.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if restarted.st.KernelPrepare == nil || restarted.st.KernelPrepare.State != "failed" {
		t.Fatal("configuration failure was not persisted")
	}
}

func TestKernelPrepareRefusesExistingRecordsAndPendingReboot(t *testing.T) {
	for _, kind := range []string{"valid record", "invalid record", "dangling symlink", "record permission", "approval", "pending", "armed", "HWE", "unsupported", "not requested"} {
		t.Run(kind, func(t *testing.T) {
			a, approval, root, _ := rebootAgentFixture(t)
			resp := model.ReportResponse{PrepareKernel: true}
			if kind != "valid record" && kind != "invalid record" && kind != "dangling symlink" && kind != "record permission" {
				_ = os.Remove(a.cfg.BootTargetPath)
			}
			switch kind {
			case "invalid record":
				writeTestFile(t, a.cfg.BootTargetPath, "not json")
			case "dangling symlink":
				_ = os.Remove(a.cfg.BootTargetPath)
				if err := os.Symlink(filepath.Join(root, "absent"), a.cfg.BootTargetPath); err != nil {
					t.Fatal(err)
				}
			case "record permission":
				_ = os.Chmod(a.cfg.BootTargetPath, 0666)
			case "approval":
				resp.Reboot = approval
			case "pending":
				a.st.PendingReboot = approval
			case "armed":
				a.st.BootChoiceArmed = true
			case "HWE":
				a.cfg.SignaturePath = filepath.Join(root, "signature")
				writeTestFile(t, a.cfg.SignaturePath, "Ubuntu 6.8.0-85.85~22.04.1-generic 6.8.12")
			case "unsupported":
				writeTestFile(t, a.cfg.OSReleasePath, "6.8.0-85-aws")
			case "not requested":
				resp.PrepareKernel = false
			}
			if a.maybePrepareKernel(resp) || a.prepareDone != nil || a.st.KernelPrepare != nil {
				t.Fatal("unsafe preparation launched")
			}
		})
	}
}

func TestRestartRecoversInterruptedKernelPreparation(t *testing.T) {
	for _, prepared := range []bool{false, true} {
		t.Run(strconv.FormatBool(prepared), func(t *testing.T) {
			a, _, _, _ := rebootAgentFixture(t)
			if !prepared {
				_ = os.Remove(a.cfg.BootTargetPath)
			}
			a.st.KernelPrepare = &model.KernelPrepareStatus{Kernel: testKernel, State: "preparing", AttemptedAt: time.Now().Add(-time.Minute)}
			if err := a.saveState(); err != nil {
				t.Fatal(err)
			}
			restarted, err := New(a.cfg)
			if err != nil {
				t.Fatal(err)
			}
			p := restarted.st.KernelPrepare
			if prepared && (p.State != "prepared" || !p.NextAttemptAt.IsZero()) || !prepared && (p.State != "failed" || p.Error == "" || time.Until(p.NextAttemptAt) < kernelPrepareRetry-time.Minute) {
				t.Fatalf("incorrect restart reconciliation: %+v", p)
			}
		})
	}
}

func TestPreparingKernelDefersApprovedRebootAndCancelsWorker(t *testing.T) {
	a, approval, root, claims := rebootAgentFixture(t)
	_ = os.Remove(a.cfg.BootTargetPath)
	started := make(chan struct{})
	a.prepareRun = func(ctx context.Context, _ string) error { close(started); <-ctx.Done(); return ctx.Err() }
	if !a.maybePrepareKernel(model.ReportResponse{PrepareKernel: true}) {
		t.Fatal("not started")
	}
	<-started
	a.maybeReboot(approval)
	if a.st.LastRebootID != 0 || a.st.PendingReboot != nil || *claims != 0 {
		t.Fatal("reboot attempted during installation")
	}
	a.stopKernelPrepare()
	if a.prepareDone != nil || a.st.KernelPrepare.State != "failed" || a.st.KernelPrepare.Error == "" {
		t.Fatal("shutdown did not persist cancellation")
	}
	if _, err := os.Stat(filepath.Join(root, "rebooted")); !os.IsNotExist(err) {
		t.Fatal("reboot hook ran")
	}
}

func TestKernelPrepareCommandCancellationStopsChildren(t *testing.T) {
	root := t.TempDir()
	pidFile := filepath.Join(root, "child.pid")
	script := filepath.Join(root, "prepare")
	writeTestFile(t, script, "#!/bin/sh\ntrap '' TERM\nsleep 60 &\nprintf '%s' \"$!\" > \"$1\"\nwait\n")
	if err := os.Chmod(script, 0700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- runKernelPrepareCommand(ctx, 50*time.Millisecond, script, pidFile) }()
	deadline := time.Now().Add(2 * time.Second)
	var child int
	for time.Now().Before(deadline) {
		data, _ := os.ReadFile(pidFile)
		child, _ = strconv.Atoi(string(data))
		if child > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if child <= 0 {
		cancel()
		t.Fatal("child did not start")
	}
	defer syscall.Kill(child, syscall.SIGKILL)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("wrong cancellation error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("preparation or descendants outlived cancellation")
	}
	deadline = time.Now().Add(time.Second)
	for {
		data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", child))
		parts := strings.Fields(string(data))
		if os.IsNotExist(err) || err == nil && len(parts) >= 3 && parts[2] == "Z" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("child still running after group cancellation: %s (%v)", data, err)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestRestartKeepsPatchFailureVisibleAndBlocksRebootDuringCooldown(t *testing.T) {
	a, approval, root, _ := rebootAgentFixture(t)
	a.st.FailedAt, a.st.FailedVersion = time.Now(), 2
	if err := a.saveState(); err != nil {
		t.Fatal(err)
	}
	restarted, err := New(a.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if restarted.lastErr == "" || restarted.apply(model.DesiredPatch{Version: 2}) {
		t.Fatal("restart lost the remembered patch failure or bypassed retry delay")
	}
	reportError := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/agent/report" {
			t.Errorf("unexpected reboot claim: %s", r.URL.Path)
			http.Error(w, "unexpected", 500)
			return
		}
		var req model.ReportRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
		}
		reportError <- req.Status.Error
		_ = json.NewEncoder(w).Encode(model.ReportResponse{})
	}))
	defer srv.Close()
	restarted.c, _ = client.New(srv.URL, "token", "")
	if _, err := restarted.report(); err != nil {
		t.Fatal(err)
	}
	if <-reportError == "" {
		t.Fatal("remembered patch failure was not reported")
	}
	restarted.maybeReboot(approval)
	if restarted.st.RebootError == "" {
		t.Fatal("remembered patch failure did not prevent reboot")
	}
	if _, err := os.Stat(filepath.Join(root, "rebooted")); !os.IsNotExist(err) {
		t.Fatal("reboot ran during patch failure cooldown")
	}
	if !restarted.apply(model.DesiredPatch{}) || restarted.lastErr != "" {
		t.Fatal("successful patch reconciliation did not clear remembered failure")
	}
}

func TestRunOnceReportsWithoutLaunchingBackgroundPreparation(t *testing.T) {
	a, _ := newTestAgent(t)
	a.cfg.BootTargetPath = filepath.Join(a.cfg.StateDir, "boot-target.json")
	a.st.HostID, a.st.HostToken = "test-host", "token"
	var calls atomic.Int32
	a.prepareRun = func(context.Context, string) error { calls.Add(1); return nil }
	reports := make(chan model.ReportRequest, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/agent/report" {
			t.Errorf("unexpected request %s", r.URL.Path)
			http.Error(w, "unexpected", 500)
			return
		}
		var req model.ReportRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
		}
		reports <- req
		_ = json.NewEncoder(w).Encode(model.ReportResponse{PrepareKernel: true})
	}))
	defer srv.Close()
	a.c, _ = client.New(srv.URL, "token", "")
	if err := a.RunOnce(); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 0 || a.prepareDone != nil || a.st.KernelPrepare != nil {
		t.Fatal("one-shot agent launched an orphan package operation")
	}
	select {
	case req := <-reports:
		if req.Status.Kernel != testKernel {
			t.Fatal("one-shot did not report kernel status")
		}
	default:
		t.Fatal("one-shot did not report")
	}
}
