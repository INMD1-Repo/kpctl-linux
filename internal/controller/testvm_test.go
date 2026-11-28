// 이 파일: controller 패키지의 TestVMApprovalTestsAndReleasesExactSignedArtifact, TestVMFailureBlocksApprovalAndRetrySignsFreshCandidate, TestVMApprovalRechecksFleetBeforeRelease 회귀 시험.
package controller

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"kpctl/internal/model"
	"kpctl/internal/testvm"
)

type approvalVMRunner struct {
	onTest func() error
	copied []byte
	mu     sync.Mutex
	copies [][]byte
}

func (r *approvalVMRunner) Run(ctx context.Context, e testvm.Endpoint, cmd, stdin string) (string, error) {
	if strings.Contains(stdin, "kpatch load") {
		if r.onTest != nil {
			if err := r.onTest(); err != nil {
				return "KPCTL_STEP\tload_new\tfailed\tmodule rejected\n", err
			}
		}
		return "KPCTL_STEP\tload_new\tpassed\tmodule test passed\nKPCTL_STEP\tcleanup\tpassed\tmodule removed\n", nil
	}
	if strings.Contains(stdin, "/proc/sys/kernel/random/boot_id") {
		return "fixture-boot\n", nil
	}
	if strings.Contains(cmd, "uname -r") {
		return testKernel + "\nbios\noff\nnone\noff\n", nil
	}
	return "", nil
}

func (r *approvalVMRunner) Copy(ctx context.Context, e testvm.Endpoint, path, dir string) error {
	data, err := os.ReadFile(path)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.copied = data
	r.copies = append(r.copies, data)
	return err
}

func (r *approvalVMRunner) sawCopy(want []byte) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, data := range r.copies {
		if string(data) == string(want) {
			return true
		}
	}
	return false
}

func vmScript(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\nset -eu\n"+body+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func enableApprovalVM(t *testing.T, s *Server, r testvm.Runner) {
	t.Helper()
	dir := t.TempDir()
	disk, key := filepath.Join(dir, "bios.qcow2"), filepath.Join(dir, "key")
	for _, path := range []string{disk, key} {
		if err := os.WriteFile(path, []byte("fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	s.cfg.TestVM = testvm.Config{
		Enabled: true, Modes: testvm.Modes{"bios"},
		Images: map[string]map[string]testvm.Image{testKernel: {"bios": {Disk: disk}}}, SSHKey: key,
		CreateCmd:     []string{vmScript(t, dir, "create.sh", `printf '{"host":"127.0.0.1","port":2255,"id":"%s"}\n' "$1"`), "{{.Name}}"},
		DeleteCmd:     []string{vmScript(t, dir, "delete.sh", `printf '%s\n' "$1" >> "$0.calls"`), "{{.ID}}"},
		ConsoleLogCmd: []string{vmScript(t, dir, "console.sh", `echo 'serial console OK'`), "{{.ID}}"},
		ListCmd:       []string{vmScript(t, dir, "list.sh", `true`)},
	}
	m, err := testvm.New(s.cfg.TestVM, testVMRegistry{s.store}, r, filepath.Join(s.cfg.DataDir, "testlogs"))
	if err != nil {
		t.Fatal(err)
	}
	s.testVM = m
	t.Cleanup(s.testVMCancel)
	addHost(t, s, "gpu-test", 1)
	if err := s.store.Update(func(st *State) error { st.Hosts["gpu-test"].Status.Firmware = "bios"; return nil }); err != nil {
		t.Fatal(err)
	}
	s.cfg.SignCommand = testSigningKey(t, "default", true).SignCommand
}

func TestVMApprovalTestsAndReleasesExactSignedArtifact(t *testing.T) {
	s := newAutoServer(t, AutoRollout{})
	r := &approvalVMRunner{}
	enableApprovalVM(t, s, r)
	id := addBuilt(t, s, "manual")
	if _, _, _, err := s.approveJob(id, "tester"); err != nil {
		t.Fatal(err)
	}
	s.store.View(func(st *State) {
		j := st.job(id)
		if j.Status != model.JobReleased || j.VMTest == nil || j.VMTest.Status != "passed" || j.VMTest.SHA256 != j.SHA256 {
			t.Errorf("release bypassed VM evidence: %+v", j)
		}
		if len(st.TestVMs) != 0 {
			t.Errorf("VMs survived successful test: %+v", st.TestVMs)
		}
		actual, err := os.ReadFile(s.artifactFile(j.Kernel, j.ModuleName))
		if err != nil || string(actual) != expectedPayload(t, s, "module", "default") || !r.sawCopy(actual) {
			t.Errorf("tested artifact differs from release: %q / %q (%v)", r.copied, actual, err)
		}
	})
	if ringVersion(s, 1) != 1 {
		t.Fatal("tested artifact was not released")
	}
}

func TestVMFailureBlocksApprovalAndRetrySignsFreshCandidate(t *testing.T) {
	s := newAutoServer(t, AutoRollout{})
	r := &approvalVMRunner{onTest: func() error { return fmt.Errorf("module rejected") }}
	enableApprovalVM(t, s, r)
	id := addBuilt(t, s, "manual")
	if _, _, _, err := s.approveJob(id, "tester"); err == nil {
		t.Fatal("failed VM test released")
	}
	if ringVersion(s, 1) != 0 {
		t.Fatal("failed VM test changed rollout")
	}
	s.store.View(func(st *State) {
		j := st.job(id)
		if j.Status != model.JobBuilt || j.VMTest == nil || j.VMTest.Status != "failed" {
			t.Errorf("failure not retained: %+v", j)
		}
		data, err := os.ReadFile(s.artifactFile(j.Kernel, j.ModuleName))
		if err != nil || string(data) != "module" {
			t.Errorf("failed attempt modified original artifact: %q %v", data, err)
		}
		if len(st.TestVMs) != 0 {
			t.Errorf("failed VM not cleaned: %+v", st.TestVMs)
		}
	})
	if holdReason(s) == "" {
		t.Fatal("VM failure must stop repeated automatic approval attempts")
	}
	logs, err := filepath.Glob(filepath.Join(s.cfg.DataDir, "testlogs", fmt.Sprintf("kpctl-test-%d-bios*.console.log", id)))
	if err != nil || len(logs) != 1 {
		t.Fatalf("missing keyed console evidence: %v (%v)", logs, err)
	}
	log, err := os.ReadFile(logs[0])
	if err != nil || !strings.Contains(string(log), "serial console OK") {
		t.Fatalf("missing console evidence: %q %v", log, err)
	}
	r.onTest = nil
	if _, _, _, err := s.approveJob(id, "tester"); err != nil {
		t.Fatal(err)
	}
	if !r.sawCopy([]byte(expectedPayload(t, s, "module", "default"))) {
		t.Fatalf("retry appended duplicate signatures: %q", r.copied)
	}
}

func TestVMApprovalRechecksFleetBeforeRelease(t *testing.T) {
	s := newAutoServer(t, AutoRollout{})
	r := &approvalVMRunner{}
	enableApprovalVM(t, s, r)
	s.cfg.TestVM.Modes = nil // auto initially selects BIOS only
	r.onTest = func() error {
		return s.store.Update(func(st *State) error {
			st.Hosts["new-uefi"] = &model.Host{ID: "new-uefi", Status: model.HostStatus{Kernel: testKernel, Firmware: "uefi", SecureBoot: "on"}}
			return nil
		})
	}
	id := addBuilt(t, s, "manual")
	if _, _, _, err := s.approveJob(id, "tester"); err == nil || !strings.Contains(err.Error(), "sb_on") {
		t.Fatalf("new firmware mode was released without test: %v", err)
	}
	if ringVersion(s, 1) != 0 {
		t.Fatal("fleet change bypassed gate")
	}
}

func TestVMBIOSSignatureEnforcementRequiresSigner(t *testing.T) {
	s := newAutoServer(t, AutoRollout{})
	r := &approvalVMRunner{}
	enableApprovalVM(t, s, r)
	s.cfg.SignCommand = nil
	if err := s.store.Update(func(st *State) error { st.Hosts["gpu-test"].Status.SigEnforce = "on"; return nil }); err != nil {
		t.Fatal(err)
	}
	id := addBuilt(t, s, "manual")
	if _, _, _, err := s.approveJob(id, "tester"); err == nil || !strings.Contains(err.Error(), "sign_command") {
		t.Fatalf("BIOS sig_enforce bypassed signing: %v", err)
	}
}

func TestVMStartupCleansRecordedAndUnrecordedOrphans(t *testing.T) {
	s := newAutoServer(t, AutoRollout{})
	enableApprovalVM(t, s, &approvalVMRunner{})
	r := testVMRegistry{s.store}
	if err := r.Remember(testvm.Instance{ID: "kpctl-test-recorded", Name: "kpctl-test-recorded", JobID: 1, Firmware: "bios"}); err != nil {
		t.Fatal(err)
	}
	id := addBuilt(t, s, "manual")
	if err := s.store.Update(func(st *State) error { st.job(id).VMTest = &model.VMTestResult{Status: "running"}; return nil }); err != nil {
		t.Fatal(err)
	}
	listPath := s.cfg.TestVM.ListCmd[0]
	if err := os.WriteFile(listPath, []byte("#!/bin/sh\necho kpctl-test-unrecorded\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewServer(s.cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restarted.testVMCancel)
	data, err := os.ReadFile(s.cfg.TestVM.DeleteCmd[0] + ".calls")
	if err != nil || !strings.Contains(string(data), "kpctl-test-recorded\n") || !strings.Contains(string(data), "kpctl-test-unrecorded\n") {
		t.Fatalf("startup failed orphan union cleanup: %q %v", data, err)
	}
	restarted.store.View(func(st *State) {
		if len(st.TestVMs) != 0 {
			t.Errorf("orphan state not cleared: %+v", st.TestVMs)
		}
		if j := st.job(id); j.VMTest.Status != "failed" || j.VMTest.FinishedAt.IsZero() {
			t.Errorf("interrupted VM test still running: %+v", j.VMTest)
		}
	})
}

func TestVMAutomaticApprovalUsesSameGateAndHoldsOnFailure(t *testing.T) {
	s := newAutoServer(t, AutoRollout{Enabled: true})
	r := &approvalVMRunner{onTest: func() error { return fmt.Errorf("test failed") }}
	enableApprovalVM(t, s, r)
	id := addBuilt(t, s, "ubuntu")
	s.autoTick()
	if ringVersion(s, 1) != 0 || holdReason(s) == "" {
		t.Fatal("automatic approval bypassed failed VM gate")
	}
	s.store.View(func(st *State) {
		if j := st.job(id); j.VMTest == nil || j.VMTest.Status != "failed" || j.Status != model.JobBuilt {
			t.Errorf("automatic approval evidence missing: %+v", j)
		}
	})
}

func TestVMShutdownWaitsForDestruction(t *testing.T) {
	s := newAutoServer(t, AutoRollout{CheckSeconds: 60})
	r := &approvalVMRunner{}
	enableApprovalVM(t, s, r)
	id := addBuilt(t, s, "manual")
	deletePath := s.cfg.TestVM.DeleteCmd[0]
	// Manager owns a copy of the command config, so replace the script in place.
	deleteScript := "#!/bin/sh\nset -eu\ntouch \"$0.started\"\nwhile [ ! -e \"$0.release\" ]; do sleep 0.01; done\n"
	if err := os.WriteFile(deletePath, []byte(deleteScript), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.WriteFile(deletePath+".release", nil, 0o600) })
	entered := make(chan struct{})
	r.onTest = func() error { close(entered); <-s.testVMCtx.Done(); return s.testVMCtx.Err() }
	approved := make(chan error, 1)
	go func() { _, _, _, err := s.approveJob(id, "tester"); approved <- err }()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("test VM did not enter module test")
	}
	s.cfg.Listen = "127.0.0.1:0"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stopped := make(chan error, 1)
	go func() { stopped <- s.Run(ctx) }()
	cancel()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(deletePath + ".started"); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("canceled VM did not reach destruction")
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case err := <-stopped:
		t.Fatalf("controller exited before destruction: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	if err := os.WriteFile(deletePath+".release", nil, 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-approved:
		if err == nil {
			t.Fatal("canceled approval succeeded")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("approval stuck after cleanup")
	}
	select {
	case err := <-stopped:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("controller stuck after cleanup")
	}
}
