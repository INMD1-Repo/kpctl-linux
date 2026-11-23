// 이 파일: agent 패키지의 TestApprovedRebootSelectsPinnedKernelOnlyOnce, TestExpiredChangedOrBusyKernelNeverReboots, TestFailedRebootHookClearsOnlyItsGRUBSelection 회귀 시험.
package agent

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kpctl/internal/client"
	"kpctl/internal/model"
)

func rebootAgentFixture(t *testing.T) (*Agent, *model.RebootApproval, string, *int) {
	t.Helper()
	a, root := newTestAgent(t)
	a.cfg.BootDir = filepath.Join(root, "boot")
	a.cfg.BootTargetPath = filepath.Join(a.cfg.StateDir, "boot-target.json")
	a.cfg.BootIDPath = filepath.Join(root, "boot-id")
	a.cfg.ProcDir = filepath.Join(root, "proc")
	a.cfg.KernelPrepareLock = filepath.Join(root, "prepare.lock")
	a.cfg.GrubConfig = filepath.Join(a.cfg.BootDir, "grub.cfg")
	a.cfg.GrubEnv = filepath.Join(root, "grubenv")
	a.cfg.GrubRebootBin = filepath.Join(root, "grub-reboot")
	a.cfg.GrubSetDefaultBin = filepath.Join(root, "grub-set-default")
	a.cfg.GrubEditenvBin = filepath.Join(root, "grub-editenv")
	a.cfg.RebootHook = filepath.Join(root, "reboot-hook")
	writeTestFile(t, a.cfg.BootIDPath, "boot-before")
	target := model.BootTarget{Kernel: "6.8.0-86-generic", PackageVersion: "6.8.0-86.86", Entry: "gnulinux-advanced-abc>gnulinux-6.8.0-86-generic-advanced-abc"}
	target.FallbackEntry = "gnulinux-advanced-abc>gnulinux-6.8.0-85-generic-advanced-abc"
	for path, value := range map[string]string{filepath.Join(a.cfg.BootDir, "vmlinuz-"+target.Kernel): "new-image", filepath.Join(a.cfg.BootDir, "initrd.img-"+target.Kernel): "new-initrd", filepath.Join(a.cfg.BootDir, "config-"+target.Kernel): "config", a.cfg.GrubConfig: `set default="${saved_entry}" ${next_entry} 'gnulinux-advanced-abc' 'gnulinux-6.8.0-86-generic-advanced-abc'`} {
		writeTestFile(t, path, value)
	}
	target.ImageSHA256, _ = fileSHA256(filepath.Join(a.cfg.BootDir, "vmlinuz-"+target.Kernel))
	target.InitrdSHA256, _ = fileSHA256(filepath.Join(a.cfg.BootDir, "initrd.img-"+target.Kernel))
	target.ConfigSHA256, _ = fileSHA256(filepath.Join(a.cfg.BootDir, "config-"+target.Kernel))
	target.GrubSHA256, _ = fileSHA256(a.cfg.GrubConfig)
	target.ID = model.BootTargetID(target)
	data, _ := json.Marshal(target)
	writeTestFile(t, a.cfg.BootTargetPath, string(data))
	writeTestFile(t, a.cfg.GrubEnv, "")
	writeTestFile(t, a.cfg.GrubRebootBin, "#!/bin/sh\nprintf '%s' \"$2\" > '"+a.cfg.GrubEnv+"'\n")
	writeTestFile(t, filepath.Join(root, "saved"), target.FallbackEntry)
	writeTestFile(t, a.cfg.GrubSetDefaultBin, "#!/bin/sh\nprintf '%s' \"$2\" > '"+filepath.Join(root, "saved")+"'\n")
	_ = os.Chmod(a.cfg.GrubSetDefaultBin, 0700)
	writeTestFile(t, a.cfg.GrubEditenvBin, "#!/bin/sh\nif [ \"$2\" = list ]; then printf 'saved_entry='; cat '"+filepath.Join(root, "saved")+"'; printf '\\nnext_entry='; cat \"$1\"; else : > \"$1\"; fi\n")
	writeTestFile(t, a.cfg.RebootHook, "#!/bin/sh\nprintf '%s' \"$KPCTL_TARGET_KERNEL\" >> '"+filepath.Join(root, "rebooted")+"'\n")
	_ = os.Chmod(a.cfg.GrubRebootBin, 0700)
	_ = os.Chmod(a.cfg.GrubEditenvBin, 0700)
	claims := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/agent/reboot/claim" {
			t.Error(r.URL.Path)
		}
		claims++
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"result":"claimed"}`))
	}))
	t.Cleanup(srv.Close)
	a.c, _ = client.New(srv.URL, "agent-token", "")
	return a, &model.RebootApproval{ID: 7, FromBootID: "boot-before", FromKernel: testKernel, Target: target, ExpiresAt: time.Now().Add(time.Minute)}, root, &claims
}

func TestApprovedRebootSelectsPinnedKernelOnlyOnce(t *testing.T) {
	a, approval, root, claims := rebootAgentFixture(t)
	a.maybeReboot(nil)
	if *claims != 0 {
		t.Fatal("unapproved claim")
	}
	a.maybeReboot(approval)
	a.maybeReboot(approval)
	data, err := os.ReadFile(filepath.Join(root, "rebooted"))
	if err != nil || string(data) != approval.Target.Kernel || *claims != 1 {
		t.Fatalf("claims=%d marker=%q err=%v error=%s", *claims, data, err, a.st.RebootError)
	}
	if next, err := a.grubEnv(); err != nil || next != approval.Target.Entry {
		t.Fatal(next, err)
	}
}

func TestExpiredChangedOrBusyKernelNeverReboots(t *testing.T) {
	for _, kind := range []string{"expired", "other boot", "changed image", "guest", "foreign GRUB", "controller cancelled"} {
		t.Run(kind, func(t *testing.T) {
			a, approval, root, claims := rebootAgentFixture(t)
			switch kind {
			case "expired":
				approval.ExpiresAt = time.Now().Add(-time.Second)
			case "other boot":
				writeTestFile(t, a.cfg.BootIDPath, "other")
			case "changed image":
				writeTestFile(t, filepath.Join(a.cfg.BootDir, "vmlinuz-"+approval.Target.Kernel), "changed")
			case "guest":
				writeTestFile(t, filepath.Join(a.cfg.ProcDir, "123", "cmdline"), "/usr/bin/qemu-system-x86_64\x00-name\x00guest")
			case "foreign GRUB":
				writeTestFile(t, a.cfg.GrubEnv, "another-entry")
			case "controller cancelled":
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "cancelled", http.StatusConflict) }))
				defer srv.Close()
				a.c, _ = client.New(srv.URL, "agent-token", "")
			}
			a.maybeReboot(approval)
			if _, err := os.Stat(filepath.Join(root, "rebooted")); !os.IsNotExist(err) {
				t.Fatal("unexpected reboot hook")
			}
			if *claims != 0 || a.st.RebootError == "" {
				t.Fatalf("claims=%d error=%s", *claims, a.st.RebootError)
			}
		})
	}
}

func TestFailedRebootHookClearsOnlyItsGRUBSelection(t *testing.T) {
	a, approval, _, _ := rebootAgentFixture(t)
	writeTestFile(t, a.cfg.RebootHook, "exit 1\n")
	a.maybeReboot(approval)
	if next, _ := a.grubEnv(); next != "" || !strings.Contains(a.st.RebootError, "훅 실패") {
		t.Fatal(next, a.st.RebootError)
	}
}

func TestExpiredBootChoiceIsClearedAfterAgentRestartWithoutController(t *testing.T) {
	a, approval, _, _ := rebootAgentFixture(t)
	a.maybeReboot(approval)
	a.st.PendingReboot.ExpiresAt = time.Now().Add(-time.Second)
	if err := a.saveState(); err != nil {
		t.Fatal(err)
	}
	restarted, err := New(a.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err = restarted.expireBootChoice(); err != nil {
		t.Fatal(err)
	}
	if next, _ := restarted.grubEnv(); next != "" || restarted.st.PendingReboot != nil {
		t.Fatal("expired next-entry survived restart", next)
	}
	if saved, _ := restarted.grubField("saved_entry"); saved != approval.Target.FallbackEntry {
		t.Fatal("fallback changed without a real boot", saved)
	}
}

func TestNewDefaultRequiresConfirmedRealBoot(t *testing.T) {
	a, approval, root, _ := rebootAgentFixture(t)
	a.maybeReboot(approval)
	if err := a.reconcileBootChoice(model.ReportResponse{Reboot: approval}); err != nil {
		t.Fatal(err)
	}
	if saved, _ := a.grubField("saved_entry"); saved != approval.Target.FallbackEntry {
		t.Fatal("changed default before boot", saved)
	}
	writeTestFile(t, a.cfg.BootIDPath, "boot-after")
	writeTestFile(t, a.cfg.OSReleasePath, approval.Target.Kernel)
	a.cfg.SignaturePath = filepath.Join(root, "signature")
	writeTestFile(t, a.cfg.SignaturePath, "Ubuntu 6.8.0-86.86-generic 6.8.12")
	if err := a.reconcileBootChoice(model.ReportResponse{}); err != nil {
		t.Fatal(err)
	}
	if saved, _ := a.grubField("saved_entry"); saved != approval.Target.FallbackEntry {
		t.Fatal("changed default without controller confirmation", saved)
	}
	if a.st.BootConfirmedID != 0 {
		t.Fatal("reported GRUB confirmation before committing the new default")
	}
	if err := a.reconcileBootChoice(model.ReportResponse{RebootResult: &model.RebootResult{ID: approval.ID, Status: "booted"}}); err != nil {
		t.Fatal(err)
	}
	if saved, _ := a.grubField("saved_entry"); saved != approval.Target.Entry || a.st.PendingReboot != nil {
		t.Fatal("new default not committed", saved)
	}
	restarted, err := New(a.cfg)
	if err != nil || restarted.st.BootConfirmedID != approval.ID {
		t.Fatalf("boot confirmation was not persisted: %v", err)
	}
}

func TestBootConfirmationReportRequiresDiskFinalization(t *testing.T) {
	for _, failed := range []bool{false, true} {
		t.Run(map[bool]string{false: "confirmed", true: "GRUB failure"}[failed], func(t *testing.T) {
			a, approval, root, _ := rebootAgentFixture(t)
			a.st.PendingReboot = approval
			writeTestFile(t, a.cfg.BootIDPath, "boot-after")
			writeTestFile(t, a.cfg.OSReleasePath, approval.Target.Kernel)
			a.cfg.SignaturePath = filepath.Join(root, "signature")
			writeTestFile(t, a.cfg.SignaturePath, "Ubuntu 6.8.0-86.86-generic 6.8.12")
			if target, _ := a.bootTarget(); target != nil {
				t.Fatal("fixture must reproduce nil target before disk finalization")
			}
			var reported int
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var req model.ReportRequest
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					t.Error(err)
				}
				reported = req.Status.BootConfirmedID
				_ = json.NewEncoder(w).Encode(model.ReportResponse{})
			}))
			defer srv.Close()
			a.c, _ = client.New(srv.URL, "agent-token", "")
			if _, err := a.report(); err != nil || reported != 0 {
				t.Fatalf("new boot report prematurely confirmed the disk: %d, %v", reported, err)
			}
			if failed {
				writeTestFile(t, a.cfg.GrubSetDefaultBin, "#!/bin/sh\nexit 1\n")
			}
			err := a.reconcileBootChoice(model.ReportResponse{RebootResult: &model.RebootResult{ID: approval.ID, Status: "booted"}})
			if (err != nil) != failed {
				t.Fatalf("finalization error = %v, want failure %v", err, failed)
			}
			want := approval.ID
			if failed {
				want = 0
			}
			if _, err := a.report(); err != nil || reported != want {
				t.Fatalf("disk finalization report = %d, want %d: %v", reported, want, err)
			}
		})
	}
}

func TestKernelChangePreservesOldABIRecoveryFiles(t *testing.T) {
	a, _, root, _ := rebootAgentFixture(t)
	old := filepath.Join(a.cfg.KpatchInstallDir, testKernel, "kpctl_old.ko")
	writeTestFile(t, old, "old-ABI-recovery-module")
	a.st.Kernel = testKernel
	a.st.Version = 2
	a.st.ModuleName = "kpctl_old"
	a.st.Installed = []string{"kpctl_old"}
	a.st.LastRebootID = 7
	if err := a.saveState(); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, a.cfg.OSReleasePath, "6.8.0-86-generic")
	next, err := New(a.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if next.st.Version != 0 || len(next.st.Installed) != 0 || next.st.LastRebootID != 7 {
		t.Fatalf("stale or lost reboot state %+v", next.st)
	}
	if data, err := os.ReadFile(old); err != nil || string(data) != "old-ABI-recovery-module" {
		t.Fatalf("recovery files removed: %s %v (%s)", data, err, root)
	}
}
