// 이 파일: controller 패키지의 TestAgentReportRequestsOnlyEligibleKernelPreparation, TestKernelPreparationReportPersistsWithoutAffectingLegacyAgents, TestRebootApprovalWaitsForKernelPreparationToFinish 회귀 시험.
package controller

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kpctl/internal/model"
)

func TestAgentReportRequestsOnlyEligibleKernelPreparation(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*Server, *State, *model.Host)
		want bool
	}{
		{"outside GA", nil, true},
		{"disabled", func(s *Server, _ *State, _ *model.Host) { s.cfg.AutoPrepareKernel = false }, false},
		{"policy never", func(_ *Server, _ *State, h *model.Host) { h.RebootPolicy = model.RebootNever }, false},
		{"policy unknown", func(_ *Server, _ *State, h *model.Host) { h.RebootPolicy = "" }, false},
		{"no range report", func(_ *Server, st *State, _ *model.Host) { st.Upstream = nil }, false},
		{"inside range", func(_ *Server, st *State, h *model.Host) { st.Upstream[h.Status.Kernel].Outside = "" }, false},
		{"empty range reason", func(_ *Server, st *State, h *model.Host) { st.Upstream[h.Status.Kernel].Outside = "  " }, false},
		{"already prepared", func(_ *Server, _ *State, h *model.Host) {
			h.Status.BootTarget = &model.BootTarget{Kernel: "6.8.0-86-generic"}
		}, false},
		{"reboot pending", func(_ *Server, _ *State, h *model.Host) {
			h.RebootRequestID = 1
			h.RebootApproval = &model.RebootApproval{ID: 1, FromBootID: h.Status.BootID, ExpiresAt: time.Now().Add(time.Minute)}
		}, false},
		{"HWE", func(_ *Server, _ *State, h *model.Host) {
			h.Status.KernelSignature = "Ubuntu 6.8.0-85.85~22.04.1-generic 6.8.12"
		}, false},
		{"invalid kernel", func(_ *Server, st *State, h *model.Host) {
			h.Status.Kernel = "../../6.8.0-85-generic"
			st.Upstream[h.Status.Kernel] = &model.Upstream{Outside: "outside"}
		}, false},
		{"unsupported flavor", func(_ *Server, st *State, h *model.Host) {
			h.Status.Kernel = "6.8.0-85-aws"
			st.Upstream[h.Status.Kernel] = &model.Upstream{Outside: "outside"}
		}, false},
		{"changed kernel", func(_ *Server, _ *State, h *model.Host) { h.Status.Kernel = "6.8.0-86-generic" }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := rebootFixture(t)
			s.cfg.AutoPrepareKernel = true
			var status model.HostStatus
			if err := s.store.Update(func(st *State) error {
				h := st.Hosts["node"]
				h.Status.BootTarget = nil
				h.Status.BootProblem = "다음 GA 커널 준비 필요 (kpctl-prepare-kernel)"
				// Installing beside the current kernel does not require a drain.
				h.Cordoned, h.VMCount = false, 5
				st.upstream(h.Status.Kernel).Outside = "최근 3개 ABI 밖"
				if tc.edit != nil {
					tc.edit(s, st, h)
				}
				status = h.Status
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			body := agentRebootAPI(t, s, "/api/agent/report", model.ReportRequest{Status: status}, http.StatusOK)
			var got model.ReportResponse
			if err := json.Unmarshal([]byte(body), &got); err != nil {
				t.Fatal(err)
			}
			if got.PrepareKernel != tc.want {
				t.Fatalf("prepare_kernel = %v, want %v: %s", got.PrepareKernel, tc.want, body)
			}
			if tc.want && (got.Reboot != nil || got.RebootID != 0) {
				t.Fatalf("preparation authorized a reboot: %+v", got)
			}
		})
	}
}

func TestKernelPreparationReportPersistsWithoutAffectingLegacyAgents(t *testing.T) {
	s, _ := rebootFixture(t)
	now := time.Now().UTC().Truncate(time.Second)
	status := model.HostStatus{Kernel: testKernel, KernelPrepare: &model.KernelPrepareStatus{
		Kernel: testKernel, State: "failed", Error: "APT lock busy", AttemptedAt: now, NextAttemptAt: now.Add(6 * time.Hour),
	}}
	body := agentRebootAPI(t, s, "/api/agent/report", model.ReportRequest{Status: status}, http.StatusOK)
	if strings.Contains(body, "prepare_kernel") {
		t.Fatalf("disabled preparation changed legacy response: %s", body)
	}
	// A legacy response decoder still reads the original fields.
	var legacy struct {
		Desired  model.DesiredPatch `json:"desired"`
		RebootID int                `json:"reboot_id"`
	}
	if err := json.Unmarshal([]byte(body), &legacy); err != nil || legacy.RebootID != 0 {
		t.Fatalf("legacy response decode: %+v, %v", legacy, err)
	}
	s.store.View(func(st *State) {
		got := st.Hosts["node"].Status.KernelPrepare
		if got == nil || *got != *status.KernelPrepare {
			t.Fatalf("preparation failure not persisted: %+v", got)
		}
	})
	restarted, err := NewServer(s.cfg)
	if err != nil {
		t.Fatal(err)
	}
	restarted.store.View(func(st *State) {
		got := st.Hosts["node"].Status.KernelPrepare
		if got == nil || *got != *status.KernelPrepare {
			t.Fatalf("preparation failure lost after restart: %+v", got)
		}
	})
	// An older agent without the new status remains compatible.
	agentRebootAPI(t, s, "/api/agent/report", model.ReportRequest{Status: model.HostStatus{Kernel: testKernel}}, http.StatusOK)
}

func TestRebootApprovalWaitsForKernelPreparationToFinish(t *testing.T) {
	s, target := rebootFixture(t)
	if err := s.store.Update(func(st *State) error {
		// The helper can publish its target just before the agent observes exit.
		st.Hosts["node"].Status.KernelPrepare = &model.KernelPrepareStatus{Kernel: testKernel, State: "preparing", AttemptedAt: time.Now()}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	callAPI(t, s, "POST", "/api/hosts/node/reboot", `{"target_id":"`+target.ID+`"}`, http.StatusConflict)
	if err := s.store.Update(func(st *State) error {
		st.Hosts["node"].Status.KernelPrepare.State = "prepared"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	approveReboot(t, s, target)
	// A prepare operation discovered after approval also blocks final dispatch.
	if err := s.store.Update(func(st *State) error {
		st.Hosts["node"].Status.KernelPrepare.State = "preparing"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	claim := model.RebootClaim{ID: 1, BootID: "boot-before", TargetID: target.ID}
	agentRebootAPI(t, s, "/api/agent/reboot/claim", claim, http.StatusConflict)
	if err := s.store.Update(func(st *State) error {
		st.Hosts["node"].Status.KernelPrepare.State = "prepared"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	agentRebootAPI(t, s, "/api/agent/reboot/claim", claim, http.StatusOK)
}

func TestKernelPreparationDoesNotBypassPatchFailureRebootGuard(t *testing.T) {
	s, target := rebootFixture(t)
	s.cfg.AutoPrepareKernel = true
	var status model.HostStatus
	if err := s.store.Update(func(st *State) error {
		status = st.Hosts["node"].Status
		status.BootTarget = nil
		status.Error = "livepatch transition failed"
		st.upstream(testKernel).Outside = "최근 3개 ABI 밖"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	body := agentRebootAPI(t, s, "/api/agent/report", model.ReportRequest{Status: status}, http.StatusOK)
	var response model.ReportResponse
	if err := json.Unmarshal([]byte(body), &response); err != nil {
		t.Fatal(err)
	}
	if !response.PrepareKernel || response.Reboot != nil || response.RebootID != 0 {
		t.Fatalf("disk preparation must remain separate from reboot: %+v", response)
	}
	status.BootTarget = &target
	status.KernelPrepare = &model.KernelPrepareStatus{Kernel: testKernel, State: "prepared", AttemptedAt: time.Now()}
	agentRebootAPI(t, s, "/api/agent/report", model.ReportRequest{Status: status}, http.StatusOK)
	callAPI(t, s, "POST", "/api/hosts/node/reboot", `{"target_id":"`+target.ID+`"}`, http.StatusConflict)
	status.Error = ""
	agentRebootAPI(t, s, "/api/agent/report", model.ReportRequest{Status: status}, http.StatusOK)
	approveReboot(t, s, target)
}

func TestAutoPrepareKernelConfigIsExplicitOptIn(t *testing.T) {
	for _, tc := range []struct {
		field string
		want  bool
		valid bool
	}{
		{"", false, true},
		{`,"auto_prepare_kernel":false`, false, true},
		{`,"auto_prepare_kernel":true`, true, true},
		{`,"auto_prepare_kernel":"true"`, false, false},
	} {
		t.Run(tc.field, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "controller.json")
			data := `{"admin_tokens":{"ops":"admin-token-0123456789"},"builder_token":"builder-token-0123456789"` + tc.field + `}`
			if err := os.WriteFile(path, []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
			cfg, err := LoadConfig(path)
			if !tc.valid {
				if err == nil {
					t.Fatal("invalid auto_prepare_kernel accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if cfg.AutoPrepareKernel != tc.want {
				t.Fatalf("AutoPrepareKernel=%v, want %v", cfg.AutoPrepareKernel, tc.want)
			}
		})
	}
}

// 관리자 요청(웹의 "새 커널 준비")은 auto_prepare_kernel 과 빌더 범위 없이 그 호스트·그 커널에만 준비를 요청합니다.
func TestManualKernelPrepareRequest(t *testing.T) {
	s, _ := rebootFixture(t)
	s.cfg.AutoPrepareKernel = false
	report := func() model.ReportResponse {
		t.Helper()
		var status model.HostStatus
		s.store.View(func(st *State) { status = st.Hosts["node"].Status })
		var got model.ReportResponse
		if err := json.Unmarshal([]byte(agentRebootAPI(t, s, "/api/agent/report", model.ReportRequest{Status: status}, http.StatusOK)), &got); err != nil {
			t.Fatal(err)
		}
		return got
	}
	_ = s.store.Update(func(st *State) error {
		h := st.Hosts["node"]
		h.Status.BootTarget = nil
		h.Cordoned, h.VMCount = false, 5 // 설치는 드레인과 무관
		st.upstream(testKernel).LatestTag = "Ubuntu-6.8.0-85.85"
		return nil
	})
	path := "/api/hosts/node/prepare-kernel"
	// 이미 최신 ABI 면 점프할 커널이 없음
	callAPI(t, s, "POST", path, "", http.StatusConflict)
	_ = s.store.Update(func(st *State) error { st.upstream(testKernel).LatestTag = "Ubuntu-6.8.0-90.90"; return nil })
	callAPI(t, s, "POST", path, `{"kernel":"6.8.0-99-generic"}`, http.StatusConflict) // 화면의 커널이 낡음
	if report().PrepareKernel {
		t.Fatal("요청 전에는 준비하면 안 됨")
	}
	body := callAPI(t, s, "POST", path, `{"kernel":"`+testKernel+`"}`, http.StatusOK)
	if !strings.Contains(body, "6.8.0-90-generic") {
		t.Fatalf("응답에 대상 커널이 없음: %s", body)
	}
	if got := report(); !got.PrepareKernel || got.Reboot != nil {
		t.Fatalf("요청 뒤 준비만 요청해야 함: %+v", got)
	}
	callAPI(t, s, "POST", path, `{"cancel":true}`, http.StatusOK)
	if report().PrepareKernel {
		t.Fatal("취소 뒤에는 준비하면 안 됨")
	}

	// 준비 기록이 생기면 요청은 지워짐
	callAPI(t, s, "POST", path, "", http.StatusOK)
	_ = s.store.Update(func(st *State) error {
		st.Hosts["node"].Status.BootTarget = &model.BootTarget{Kernel: "6.8.0-90-generic"}
		return nil
	})
	report()
	s.store.View(func(st *State) {
		if st.Hosts["node"].KernelPrepareRequest != nil {
			t.Fatal("준비 기록이 생겼는데 요청이 남음")
		}
	})
	callAPI(t, s, "POST", path, "", http.StatusConflict) // 이미 준비됨 → 점프(재부팅 승인)로

	// drain 정책이 아니면 거부
	_ = s.store.Update(func(st *State) error {
		h := st.Hosts["node"]
		h.Status.BootTarget, h.RebootPolicy = nil, model.RebootNever
		return nil
	})
	callAPI(t, s, "POST", path, "", http.StatusConflict)
}
