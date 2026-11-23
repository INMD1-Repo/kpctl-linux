// 이 파일: controller 패키지의 finishReboot, rebootProblem, refreshRebootDrain 구현·자료형.
package controller

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"kpctl/internal/model"
)

const rebootApprovalTTL = 5 * time.Minute

func finishReboot(h *model.Host, status, detail string) {
	if h.RebootRequestID != 0 {
		target, packageVersion, fromBootID, targetID := "", "", "", ""
		if h.RebootApproval != nil {
			target = h.RebootApproval.Target.Kernel
			packageVersion = h.RebootApproval.Target.PackageVersion
			fromBootID = h.RebootApproval.FromBootID
			targetID = h.RebootApproval.Target.ID
		}
		h.RebootResult = &model.RebootResult{ID: h.RebootRequestID, TargetKernel: target, TargetPackageVersion: packageVersion, FromBootID: fromBootID, TargetID: targetID, Status: status, Detail: detail, At: time.Now()}
	}
	h.RebootRequestID = 0
	h.RebootApproval = nil
}

func rebootProblem(h *model.Host, now time.Time) error {
	switch {
	case h.RebootPolicy != model.RebootDrain:
		return fmt.Errorf("%s 은 재부팅 정책이 drain 이 아닙니다", h.Hostname)
	case !h.Cordoned:
		return fmt.Errorf("%s 은 cordon 상태가 아닙니다. 먼저 kpctl host cordon", h.Hostname)
	case h.VMCount < 0:
		return fmt.Errorf("%s 의 VM 수를 아직 모릅니다", h.Hostname)
	case h.VMCount > 0:
		return fmt.Errorf("%s 에 VM 이 %d 대 남아 있습니다", h.Hostname, h.VMCount)
	case now.Sub(h.VMCountCheckedAt) > 120*time.Second:
		return fmt.Errorf("VM 수 확인이 오래됐습니다")
	case now.Sub(h.LastSeen) > 120*time.Second || h.LastSeen.After(now.Add(30*time.Second)):
		return fmt.Errorf("호스트 보고가 오래됐거나 시각이 잘못됐습니다")
	case h.Status.Error != "":
		return fmt.Errorf("호스트 오류를 먼저 확인하세요: %s", h.Status.Error)
	case h.Status.KernelPrepare != nil && h.Status.KernelPrepare.State == "preparing":
		return fmt.Errorf("디스크 커널 준비가 진행 중입니다")
	case h.Status.BootID == "":
		return fmt.Errorf("부팅 ID를 보고하는 새 에이전트가 필요합니다")
	}
	return nil
}

// Fresh scheduler evidence for both approval and dispatch. A missing scheduler
// uses the authenticated agent's explicit local count; it never invents zero.
func (s *Server) refreshRebootDrain(id string) {
	if len(s.cfg.Scheduler.VMCountCommand) == 0 {
		return
	}
	var name string
	s.store.View(func(st *State) {
		if h := st.Hosts[id]; h != nil {
			name = h.Hostname
		}
	})
	if name == "" {
		return
	}
	count := -1
	out, err := runCommand(s.cfg.Scheduler.VMCountCommand, map[string]string{"host": name}, time.Minute)
	if err == nil {
		if n, e := strconv.Atoi(strings.TrimSpace(out)); e == nil && n >= 0 {
			count = n
		}
	}
	_ = s.store.Update(func(st *State) error {
		if h := st.Hosts[id]; h != nil {
			h.VMCount = count
			h.VMCountCheckedAt = time.Now()
		}
		return nil
	})
}

func (s *Server) handleHostReboot(w http.ResponseWriter, r *http.Request, who string) {
	s.rebootMu.Lock()
	defer s.rebootMu.Unlock()
	var req model.RebootRequest
	if err := readJSON(r, &req); err != nil {
		writeErr(w, err)
		return
	}
	id := r.PathValue("id")
	if !req.Cancel {
		s.refreshRebootDrain(id)
	}
	var approval *model.RebootApproval
	err := s.store.UpdateAtomic(func(st *State) error {
		h := st.Hosts[id]
		if h == nil {
			return fail(http.StatusNotFound, "호스트가 없습니다")
		}
		if req.Cancel {
			if h.RebootApproval != nil && h.RebootApproval.DispatchedAt != nil {
				return fail(http.StatusConflict, "이미 실행을 전달했습니다. 실제 부팅 결과를 확인하세요")
			}
			finishReboot(h, "cancelled", "관리자가 재부팅 승인을 취소했습니다")
			return nil
		}
		if err := rebootProblem(h, time.Now()); err != nil {
			return fail(http.StatusConflict, "%v", err)
		}
		if h.RebootRequestID != 0 {
			return fail(http.StatusConflict, "이미 재부팅 승인됨 (요청 #%d)", h.RebootRequestID)
		}
		if !model.ValidBootTarget(h.Status.Kernel, h.Status.BootTarget) || model.IsHWESignature(h.Status.KernelSignature) {
			return fail(http.StatusConflict, "새 GA 디스크 커널 준비가 필요합니다: %s", h.Status.BootProblem)
		}
		if req.TargetID == "" || req.TargetID != h.Status.BootTarget.ID {
			return fail(http.StatusConflict, "승인 화면의 커널 정보가 바뀌었습니다. 준비된 커널을 다시 확인하세요")
		}
		st.NextRebootID++
		now := time.Now()
		approval = &model.RebootApproval{ID: st.NextRebootID, Target: *h.Status.BootTarget, FromBootID: h.Status.BootID, FromKernel: h.Status.Kernel, ApprovedBy: who, ApprovedAt: now, ExpiresAt: now.Add(rebootApprovalTTL)}
		h.RebootApproval = approval
		h.RebootRequestID = approval.ID
		return nil
	})
	if err != nil {
		writeErr(w, err)
		return
	}
	if req.Cancel {
		s.audit(who, "재부팅 승인 취소 host=%s", id)
		writeJSON(w, http.StatusOK, map[string]string{"result": "cancelled"})
		return
	}
	s.audit(who, "재부팅 승인 host=%s 요청 #%d %s → %s target=%s expires=%s", id, approval.ID, approval.FromKernel, approval.Target.Kernel, approval.Target.ID, approval.ExpiresAt.Format(time.RFC3339))
	writeJSON(w, http.StatusOK, map[string]any{"reboot_id": approval.ID, "approval": approval})
}

func (s *Server) handleRebootClaim(w http.ResponseWriter, r *http.Request, id string) {
	s.rebootMu.Lock()
	defer s.rebootMu.Unlock()
	var req model.RebootClaim
	if err := readJSON(r, &req); err != nil {
		writeErr(w, err)
		return
	}
	s.refreshRebootDrain(id)
	err := s.store.UpdateAtomic(func(st *State) error {
		h := st.Hosts[id]
		if h == nil {
			return fail(http.StatusNotFound, "호스트가 없습니다")
		}
		a := h.RebootApproval
		if a == nil || a.ID != req.ID || a.DispatchedAt != nil || !time.Now().Before(a.ExpiresAt) {
			return fail(http.StatusConflict, "활성 상태의 미사용 관리자 승인이 없습니다")
		}
		if err := rebootProblem(h, time.Now()); err != nil {
			return fail(http.StatusConflict, "%v", err)
		}
		if req.BootID != a.FromBootID || h.Status.BootID != a.FromBootID || h.Status.Kernel != a.FromKernel || req.TargetID != a.Target.ID || h.Status.BootTarget == nil || *h.Status.BootTarget != a.Target {
			return fail(http.StatusConflict, "승인한 부팅·커널 정보와 다릅니다")
		}
		now := time.Now()
		a.DispatchedAt = &now
		return nil
	})
	if err != nil {
		writeErr(w, err)
		return
	}
	s.audit("agent", "관리자 승인 재부팅 실행 전달 host=%s 요청 #%d", id, req.ID)
	writeJSON(w, http.StatusOK, map[string]string{"result": "claimed"})
}

func reconcileReboot(h *model.Host, req model.ReportRequest) {
	a := h.RebootApproval
	if h.RebootRequestID == 0 {
		return
	}
	if a == nil {
		finishReboot(h, "cancelled", "대상 커널이 고정되지 않은 이전 승인은 취소됐습니다")
		return
	}
	if req.Status.BootID != "" && req.Status.BootID != a.FromBootID {
		if a.DispatchedAt != nil && req.LastRebootID == a.ID && req.Status.Kernel == a.Target.Kernel && model.SignatureVersion(req.Status.KernelSignature) == a.Target.PackageVersion {
			finishReboot(h, "booted", "관리자 승인 대상 커널로 실제 부팅 확인")
		} else {
			finishReboot(h, "failed", "부팅은 바뀌었으나 승인 대상 커널·실행 기록이 일치하지 않습니다")
		}
		return
	}
	if req.LastRebootID == a.ID && req.RebootError != "" {
		finishReboot(h, "failed", req.RebootError)
		return
	}
	if !time.Now().Before(a.ExpiresAt) {
		finishReboot(h, "expired", "승인 시간 내 대상 커널 부팅을 확인하지 못했습니다")
	}
}
