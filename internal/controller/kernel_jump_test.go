// 이 파일: controller 패키지의 TestAutoKernelJumpRequiresExplicitHostAndEveryRebootGuard, TestAutoKernelJumpCreatesExistingScopedApprovalAndClaimsOnce, TestAutoKernelJumpDoesNotRetryUnsuccessfulAttemptAfterRestart 회귀 시험.
package controller

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"kpctl/internal/model"
)

func kernelJumpFixture(t *testing.T) (*Server, model.BootTarget) {
	t.Helper()
	s, target := rebootFixture(t)
	s.cfg.AutoPrepareKernel = true
	s.cfg.AutoJumpKernelHosts = []string{"node"}
	if err := s.store.Update(func(st *State) error {
		st.Hosts["node"].Status.KernelPrepare = &model.KernelPrepareStatus{Kernel: testKernel, State: "prepared", AttemptedAt: time.Now()}
		st.upstream(testKernel).Outside = "최근 3개 ABI 밖"
		st.upstream(testKernel).LatestTag = "Ubuntu-" + target.PackageVersion
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return s, target
}

func kernelJumpReport(t *testing.T, s *Server, lastID int, rebootError string) model.ReportResponse {
	t.Helper()
	var status model.HostStatus
	s.store.View(func(st *State) { status = st.Hosts["node"].Status })
	body := agentRebootAPI(t, s, "/api/agent/report", model.ReportRequest{Status: status, LastRebootID: lastID, RebootError: rebootError}, http.StatusOK)
	var response model.ReportResponse
	if err := json.Unmarshal([]byte(body), &response); err != nil {
		t.Fatal(err)
	}
	return response
}

func TestAutoKernelJumpRequiresExplicitHostAndEveryRebootGuard(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*Server, *State, *model.Host)
	}{
		{"no opt in", func(s *Server, _ *State, _ *model.Host) { s.cfg.AutoJumpKernelHosts = nil }},
		{"hostname is not ID", func(s *Server, _ *State, h *model.Host) {
			h.Hostname = "allowed"
			s.cfg.AutoJumpKernelHosts = []string{"allowed"}
		}},
		{"preparation disabled", func(s *Server, _ *State, _ *model.Host) { s.cfg.AutoPrepareKernel = false }},
		{"paused", func(_ *Server, st *State, _ *model.Host) { st.AutoPaused = true }},
		{"not cordoned", func(_ *Server, _ *State, h *model.Host) { h.Cordoned = false }},
		{"unknown VM count", func(_ *Server, _ *State, h *model.Host) { h.Status.LocalVMCount = nil }},
		{"VM present", func(_ *Server, _ *State, h *model.Host) { n := 1; h.Status.LocalVMCount = &n }},
		{"never reboot", func(_ *Server, _ *State, h *model.Host) { h.RebootPolicy = model.RebootNever }},
		{"no boot ID", func(_ *Server, _ *State, h *model.Host) { h.Status.BootID = "" }},
		{"host error", func(_ *Server, _ *State, h *model.Host) { h.Status.Error = "transition failed" }},
		{"HWE", func(_ *Server, _ *State, h *model.Host) {
			h.Status.KernelSignature = "Ubuntu 6.8.0-85.85~22.04.1-generic 6.8.12"
		}},
		{"no signature", func(_ *Server, _ *State, h *model.Host) { h.Status.KernelSignature = "" }},
		{"inconsistent signature", func(_ *Server, _ *State, h *model.Host) {
			h.Status.KernelSignature = "Ubuntu 6.8.0-84.84-generic 6.8.12"
		}},
		{"no preparation status", func(_ *Server, _ *State, h *model.Host) { h.Status.KernelPrepare = nil }},
		{"still preparing", func(_ *Server, _ *State, h *model.Host) { h.Status.KernelPrepare.State = "preparing" }},
		{"failed preparation", func(_ *Server, _ *State, h *model.Host) { h.Status.KernelPrepare.State = "failed" }},
		{"preparation error", func(_ *Server, _ *State, h *model.Host) { h.Status.KernelPrepare.Error = "package lock" }},
		{"different baseline", func(_ *Server, _ *State, h *model.Host) { h.Status.KernelPrepare.Kernel = "6.8.0-84-generic" }},
		{"no target", func(_ *Server, _ *State, h *model.Host) { h.Status.BootTarget = nil }},
		{"invalid target", func(_ *Server, _ *State, h *model.Host) { h.Status.BootTarget.ID = "invalid" }},
		{"no upstream", func(_ *Server, st *State, _ *model.Host) { st.Upstream = nil }},
		{"inside range", func(_ *Server, st *State, _ *model.Host) { st.Upstream[testKernel].Outside = "" }},
		{"no official latest", func(_ *Server, st *State, _ *model.Host) { st.Upstream[testKernel].LatestTag = "" }},
		{"stale prepared target", func(_ *Server, st *State, _ *model.Host) { st.Upstream[testKernel].LatestTag = "Ubuntu-6.8.0-87.87" }},
		{"package differs", func(_ *Server, st *State, _ *model.Host) { st.Upstream[testKernel].LatestTag = "Ubuntu-6.8.0-86.87" }},
		{"another pending request", func(_ *Server, st *State, _ *model.Host) {
			st.Hosts["other"] = &model.Host{ID: "other", RebootRequestID: 2}
		}},
		{"another pending approval", func(_ *Server, st *State, _ *model.Host) {
			st.Hosts["other"] = &model.Host{ID: "other", RebootApproval: &model.RebootApproval{ID: 2}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := kernelJumpFixture(t)
			if err := s.store.Update(func(st *State) error { tc.edit(s, st, st.Hosts["node"]); return nil }); err != nil {
				t.Fatal(err)
			}
			response := kernelJumpReport(t, s, 0, "")
			if response.Reboot != nil || response.RebootID != 0 {
				t.Fatalf("automatic approval bypassed guard: %+v", response)
			}
			s.store.View(func(st *State) {
				if st.NextRebootID != 0 || st.Hosts["node"].AutoKernelJump != nil {
					t.Fatal("refused automatic approval changed attempt history")
				}
			})
		})
	}
}

func TestAutoKernelJumpCreatesExistingScopedApprovalAndClaimsOnce(t *testing.T) {
	s, target := kernelJumpFixture(t)
	response := kernelJumpReport(t, s, 0, "")
	a := response.Reboot
	if a == nil || a.ID != 1 || a.Target != target || a.FromBootID != "boot-before" || a.FromKernel != testKernel || a.ApprovedBy != "auto-kernel-jump" || response.RebootID != 0 || a.ExpiresAt.Sub(a.ApprovedAt) != rebootApprovalTTL {
		t.Fatalf("incorrect automatic approval: %+v", response)
	}
	for i := 0; i < 2; i++ {
		if got := kernelJumpReport(t, s, 0, "").Reboot; got == nil || got.ID != a.ID {
			t.Fatalf("repeated report replaced pending approval: %+v", got)
		}
	}
	claim := model.RebootClaim{ID: a.ID, BootID: a.FromBootID, TargetID: a.Target.ID}
	agentRebootAPI(t, s, "/api/agent/reboot/claim", claim, http.StatusOK)
	agentRebootAPI(t, s, "/api/agent/reboot/claim", claim, http.StatusConflict)
	s.store.View(func(st *State) {
		if st.Hosts["node"].AutoKernelJump.DispatchedAt != nil {
			t.Fatal("saved attempt aliases mutable dispatched approval")
		}
	})
}

func TestAutoKernelJumpDoesNotRetryUnsuccessfulAttemptAfterRestart(t *testing.T) {
	for _, kind := range []string{"cancelled", "expired", "failed"} {
		t.Run(kind, func(t *testing.T) {
			s, target := kernelJumpFixture(t)
			if kernelJumpReport(t, s, 0, "").Reboot == nil {
				t.Fatal("expected initial automatic approval")
			}
			switch kind {
			case "cancelled":
				callAPI(t, s, "POST", "/api/hosts/node/reboot", `{"cancel":true}`, http.StatusOK)
			case "expired":
				if err := s.store.Update(func(st *State) error {
					st.Hosts["node"].RebootApproval.ExpiresAt = time.Now().Add(-time.Second)
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			case "failed":
				kernelJumpReport(t, s, 1, "reboot hook failed")
			}
			response := kernelJumpReport(t, s, 1, "")
			if response.Reboot != nil || response.RebootResult == nil || response.RebootResult.Status != kind || response.RebootResult.FromBootID != "boot-before" || response.RebootResult.TargetID != target.ID {
				t.Fatalf("unexpected terminal result: %+v", response)
			}
			var err error
			s.store, err = OpenStore(filepath.Join(s.cfg.DataDir, "state.json"))
			if err != nil {
				t.Fatal(err)
			}
			// Rebuilt initrd metadata alone must not bypass the attempt record.
			if err := s.store.Update(func(st *State) error {
				h := st.Hosts["node"]
				h.Status.BootTarget.InitrdSHA256 = strings.Repeat("e", 64)
				h.Status.BootTarget.ID = model.BootTargetID(*h.Status.BootTarget)
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if kernelJumpReport(t, s, 1, "").Reboot != nil {
				t.Fatal("restarted controller automatically retried terminal attempt")
			}
			// Explicit manual retry remains available after reviewing the failure.
			s.store.View(func(st *State) { target = *st.Hosts["node"].Status.BootTarget })
			approveReboot(t, s, target)
		})
	}
}

func TestAutoKernelJumpHonorsPreviousManualCancellation(t *testing.T) {
	s, target := kernelJumpFixture(t)
	approveReboot(t, s, target)
	callAPI(t, s, "POST", "/api/hosts/node/reboot", `{"cancel":true}`, http.StatusOK)
	if kernelJumpReport(t, s, 0, "").Reboot != nil {
		t.Fatal("automatic approval reversed a manual cancellation")
	}
}

func TestAutoKernelJumpRefreshesSchedulerAndPreservesLocalCountGuard(t *testing.T) {
	for _, count := range []string{"0", "1", "unknown"} {
		t.Run(count, func(t *testing.T) {
			s, _ := kernelJumpFixture(t)
			s.cfg.Scheduler.VMCountCommand = []string{"/bin/echo", count}
			response := kernelJumpReport(t, s, 0, "")
			if (response.Reboot != nil) != (count == "0") {
				t.Fatalf("scheduler evidence ignored: %+v", response)
			}
		})
	}
}

func TestAutoKernelJumpRefreshesOnlyExactPreparedTargetForNewerOfficialPackage(t *testing.T) {
	for _, tc := range []struct {
		name, latest string
		edit         func(*Server, *model.Host)
		refresh      bool
	}{
		{"newer ABI", "Ubuntu-6.8.0-87.87", nil, true},
		{"numeric ABI comparison", "Ubuntu-6.8.0-100.100", nil, true},
		{"already latest", "Ubuntu-6.8.0-86.86", nil, false},
		{"older ABI", "Ubuntu-6.8.0-85.85", nil, false},
		{"same ABI newer revision", "Ubuntu-6.8.0-86.87", nil, true},
		{"same ABI numeric revision", "Ubuntu-6.8.0-86.100", nil, true},
		{"same ABI older revision", "Ubuntu-6.8.0-86.9", nil, false},
		{"same ABI overflowing revision", "Ubuntu-6.8.0-86.18446744073709551616", nil, false},
		{"different branch", "Ubuntu-7.0.0-87.87", nil, false},
		{"invalid tag", "Ubuntu-6.8.0-87.87-proposed", nil, false},
		{"not allowlisted", "Ubuntu-6.8.0-87.87", func(s *Server, _ *model.Host) { s.cfg.AutoJumpKernelHosts = nil }, false},
		{"preparation disabled", "Ubuntu-6.8.0-87.87", func(s *Server, _ *model.Host) { s.cfg.AutoPrepareKernel = false }, false},
		{"never reboot", "Ubuntu-6.8.0-87.87", func(_ *Server, h *model.Host) { h.RebootPolicy = model.RebootNever }, false},
		{"HWE", "Ubuntu-6.8.0-87.87", func(_ *Server, h *model.Host) { h.Status.KernelSignature = "Ubuntu 6.8.0-85.85~22.04.1-generic 6.8.12" }, false},
		{"invalid prepared record", "Ubuntu-6.8.0-87.87", func(_ *Server, h *model.Host) { h.Status.BootTarget.ID = "invalid" }, false},
		{"pending approval", "Ubuntu-6.8.0-87.87", func(_ *Server, h *model.Host) {
			h.RebootRequestID = 2
			h.RebootApproval = &model.RebootApproval{ID: 2, FromBootID: h.Status.BootID, ExpiresAt: time.Now().Add(time.Minute)}
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, target := kernelJumpFixture(t)
			if err := s.store.Update(func(st *State) error {
				st.Upstream[testKernel].LatestTag = tc.latest
				if tc.edit != nil {
					tc.edit(s, st.Hosts["node"])
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			response := kernelJumpReport(t, s, 0, "")
			if (response.PrepareKernelTargetID != "") != tc.refresh || tc.refresh && (!response.PrepareKernel || response.PrepareKernelTargetID != target.ID || response.Reboot != nil) {
				t.Fatalf("incorrect exact-target refresh authorization: %+v", response)
			}
		})
	}
}

func TestAutoKernelJumpWaitsForOtherHostBootConfirmation(t *testing.T) {
	for _, state := range []string{"unknown", "failed", "expired", "cancelled", "unconfirmed", "next target prepared", "stale", "error", "same boot", "wrong kernel", "wrong package", "ready", "manual recovery"} {
		t.Run(state, func(t *testing.T) {
			s, target := kernelJumpFixture(t)
			if err := s.store.Update(func(st *State) error {
				last := &model.RebootApproval{ID: 2, FromBootID: "other-before", Target: target}
				other := &model.Host{ID: "other", AutoKernelJump: last, LastSeen: time.Now(), RebootResult: &model.RebootResult{ID: 2, Status: "booted", FromBootID: "other-before", TargetKernel: target.Kernel, TargetPackageVersion: target.PackageVersion}, Status: model.HostStatus{Kernel: target.Kernel, KernelSignature: "Ubuntu " + target.PackageVersion + "-generic 6.8.12", BootID: "other-after", BootConfirmedID: 2}}
				switch state {
				case "unknown":
					other.RebootResult = nil
				case "failed", "expired", "cancelled":
					other.RebootResult.Status = state
				case "unconfirmed":
					other.Status.BootConfirmedID = 0
				case "manual recovery":
					other.RebootResult.ID, other.Status.BootConfirmedID = 3, 3
				case "next target prepared":
					next := target
					next.Kernel, next.PackageVersion = "6.8.0-87-generic", "6.8.0-87.87"
					next.Entry = strings.ReplaceAll(next.Entry, target.Kernel, next.Kernel)
					next.FallbackEntry = target.Entry
					next.ID = model.BootTargetID(next)
					other.Status.BootTarget = &next
				case "stale":
					other.LastSeen = time.Now().Add(-3 * time.Minute)
				case "error":
					other.Status.Error = "default boot confirmation failed"
				case "same boot":
					other.Status.BootID = "other-before"
				case "wrong kernel":
					other.Status.Kernel = testKernel
				case "wrong package":
					other.Status.KernelSignature = "Ubuntu 6.8.0-86.87-generic 6.8.12"
				}
				st.Hosts[other.ID] = other
				st.NextRebootID = 2
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			response := kernelJumpReport(t, s, 0, "")
			if (response.Reboot != nil) != (state == "ready" || state == "manual recovery" || state == "next target prepared") {
				t.Fatalf("prior host confirmation guard ignored: %+v", response)
			}
		})
	}
}

func TestConfirmedHostsWithNextTargetsJumpOneAtATime(t *testing.T) {
	s, previousTarget := kernelJumpFixture(t)
	s.cfg.AutoJumpKernelHosts = []string{"node", "other"}
	nextTarget := previousTarget
	nextTarget.Kernel, nextTarget.PackageVersion = "6.8.0-87-generic", "6.8.0-87.87"
	nextTarget.Entry = strings.ReplaceAll(previousTarget.Entry, previousTarget.Kernel, nextTarget.Kernel)
	nextTarget.FallbackEntry = previousTarget.Entry
	nextTarget.ID = model.BootTargetID(nextTarget)
	if err := s.store.Update(func(st *State) error {
		for i, id := range []string{"node", "other"} {
			copy := *st.Hosts["node"]
			copy.ID, copy.Hostname = id, id
			copy.Status.Kernel = previousTarget.Kernel
			copy.Status.KernelSignature = "Ubuntu " + previousTarget.PackageVersion + "-generic 6.8.12"
			copy.Status.BootID = id + "-confirmed"
			copy.Status.BootConfirmedID = i + 1
			copy.Status.KernelPrepare = &model.KernelPrepareStatus{Kernel: previousTarget.Kernel, State: "prepared"}
			copy.Status.BootTarget = &nextTarget
			copy.AutoKernelJump = &model.RebootApproval{ID: i + 1, FromBootID: id + "-before", Target: previousTarget}
			copy.RebootResult = &model.RebootResult{ID: i + 1, Status: "booted", FromBootID: id + "-before", TargetKernel: previousTarget.Kernel, TargetPackageVersion: previousTarget.PackageVersion}
			st.Hosts[id] = &copy
		}
		st.NextRebootID = 2
		st.upstream(previousTarget.Kernel).LatestTag = "Ubuntu-" + nextTarget.PackageVersion
		st.upstream(previousTarget.Kernel).Outside = "최근 1개 ABI 밖"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for _, id := range []string{"node", "other"} {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			s.rebootMu.Lock()
			defer s.rebootMu.Unlock()
			_ = s.store.Update(func(st *State) error { s.maybeApproveKernelJump(st, st.Hosts[id], time.Now()); return nil })
		}(id)
	}
	wg.Wait()
	s.rebootMu.Lock()
	defer s.rebootMu.Unlock()
	if err := s.store.Update(func(st *State) error {
		var first, waiting *model.Host
		for _, h := range st.Hosts {
			if h.RebootApproval != nil {
				if first != nil {
					t.Fatal("both confirmed hosts were approved at once")
				}
				first = h
			} else {
				waiting = h
			}
		}
		if first == nil || waiting == nil || st.NextRebootID != 3 {
			t.Fatal("confirmed hosts with new prepared targets failed to select one jump")
		}
		if s.maybeApproveKernelJump(st, waiting, time.Now()) != nil {
			t.Fatal("second host jumped while first approval was pending")
		}
		approval := first.RebootApproval
		now := time.Now()
		approval.DispatchedAt = &now
		first.Status.Kernel, first.Status.KernelSignature = nextTarget.Kernel, "Ubuntu "+nextTarget.PackageVersion+"-generic 6.8.12"
		first.Status.BootID = first.ID + "-next"
		first.Status.BootTarget, first.Status.KernelPrepare = nil, nil
		reconcileReboot(first, model.ReportRequest{Status: first.Status, LastRebootID: approval.ID})
		if first.RebootResult == nil || first.RebootResult.Status != "booted" {
			t.Fatal("first jump did not record real boot")
		}
		if s.maybeApproveKernelJump(st, waiting, time.Now()) != nil {
			t.Fatal("second host jumped before first GRUB confirmation")
		}
		first.Status.BootConfirmedID = approval.ID
		if a := s.maybeApproveKernelJump(st, waiting, time.Now()); a == nil || a.ID != 4 {
			t.Fatal("second host did not progress after first GRUB confirmation")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentAutoKernelJumpsApproveOnlyOneHost(t *testing.T) {
	s, _ := kernelJumpFixture(t)
	s.cfg.AutoJumpKernelHosts = []string{"node", "other"}
	if err := s.store.Update(func(st *State) error {
		copy := *st.Hosts["node"]
		copy.ID = "other"
		copy.Hostname = "other"
		st.Hosts["other"] = &copy
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for _, id := range []string{"node", "other"} {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			s.rebootMu.Lock()
			defer s.rebootMu.Unlock()
			_ = s.store.Update(func(st *State) error { s.maybeApproveKernelJump(st, st.Hosts[id], time.Now()); return nil })
		}(id)
	}
	wg.Wait()
	s.store.View(func(st *State) {
		n := 0
		for _, h := range st.Hosts {
			if h.RebootApproval != nil {
				n++
			}
		}
		if n != 1 || st.NextRebootID != 1 {
			t.Fatalf("concurrent jump approvals=%d nextID=%d", n, st.NextRebootID)
		}
	})
}

func TestAutoJumpKernelHostsConfigRequiresExactUniqueIDs(t *testing.T) {
	for _, tc := range []struct {
		value string
		valid bool
	}{
		{`[]`, true}, {`["h-0123abcd"]`, true}, {`["h-0123abcd","h-4567abcd"]`, true},
		{`[""]`, false}, {`[" h-0123abcd"]`, false}, {`["*"]`, false}, {`["h-0123abcd","h-0123abcd"]`, false}, {`true`, false},
	} {
		t.Run(tc.value, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "controller.json")
			data := `{"admin_tokens":{"ops":"admin-token-0123456789"},"builder_token":"builder-token-0123456789","auto_jump_kernel_hosts":` + tc.value + `}`
			if err := os.WriteFile(path, []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
			_, err := LoadConfig(path)
			if (err == nil) != tc.valid {
				t.Fatalf("config valid=%v, err=%v", tc.valid, err)
			}
		})
	}
}
