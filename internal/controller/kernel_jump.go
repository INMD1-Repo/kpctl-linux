// 이 파일: controller 패키지의 kernelRefreshTargetID, autoJumpKernelHost, maybeApproveKernelJump, handleHostPrepareKernel 구현·자료형.
package controller

import (
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"kpctl/internal/model"
)

var officialGAJumpTag = regexp.MustCompile(`^Ubuntu-((?:5\.15\.0|6\.8\.0|7\.0\.0)-[0-9]+)\.([0-9]+)$`)

// kernelRefreshTargetID authorizes replacing only the exact, verified prepared
// target when a newer published ABI or package revision overtakes it. The agent revalidates the
// record and its files and keeps that record unless preparation succeeds.
func (s *Server) kernelRefreshTargetID(st *State, h *model.Host) string {
	if !s.cfg.AutoPrepareKernel || !s.autoJumpKernelHost(h.ID) || h.RebootPolicy != model.RebootDrain ||
		h.RebootApproval != nil || h.RebootRequestID != 0 || model.IsHWESignature(h.Status.KernelSignature) ||
		!model.ValidBootTarget(h.Status.Kernel, h.Status.BootTarget) {
		return ""
	}
	u := st.Upstream[h.Status.Kernel]
	if u == nil || strings.TrimSpace(u.Outside) == "" {
		return ""
	}
	latest := officialGAJumpTag.FindStringSubmatch(u.LatestTag)
	prepared := officialGAJumpTag.FindStringSubmatch("Ubuntu-" + h.Status.BootTarget.PackageVersion)
	if latest == nil || prepared == nil {
		return ""
	}
	if !model.NewerGAKernel(h.Status.BootTarget.Kernel, latest[1]+"-generic") {
		// Ubuntu can republish a prepared ABI with a higher package revision.
		// Compare revisions numerically: .100 is newer than .86, while .9 is not.
		if latest[1] != prepared[1] {
			return ""
		}
		latestRevision, latestErr := strconv.ParseUint(latest[2], 10, 64)
		preparedRevision, preparedErr := strconv.ParseUint(prepared[2], 10, 64)
		if latestErr != nil || preparedErr != nil || latestRevision <= preparedRevision {
			return ""
		}
	}
	return h.Status.BootTarget.ID
}

func (s *Server) autoJumpKernelHost(id string) bool {
	for _, allowed := range s.cfg.AutoJumpKernelHosts {
		if id == allowed {
			return true
		}
	}
	return false
}

// maybeApproveKernelJump grants the existing, one-shot scoped approval only to
// explicitly designated, already cordoned hosts. It never drains or uncordons a
// host. The caller holds rebootMu and the state lock through the persisted grant.
func (s *Server) maybeApproveKernelJump(st *State, h *model.Host, now time.Time) *model.RebootApproval {
	if !s.cfg.AutoPrepareKernel || !s.autoJumpKernelHost(h.ID) || st.AutoPaused ||
		h.RebootApproval != nil || h.RebootRequestID != 0 || rebootProblem(h, now) != nil ||
		model.LTSForKernel(h.Status.Kernel) == nil || model.IsHWESignature(h.Status.KernelSignature) ||
		!model.ValidBootTarget(h.Status.Kernel, h.Status.BootTarget) {
		return nil
	}
	p := h.Status.KernelPrepare
	u := st.Upstream[h.Status.Kernel]
	target := h.Status.BootTarget
	if p == nil || p.State != "prepared" || p.Error != "" || p.Kernel != h.Status.Kernel ||
		u == nil || strings.TrimSpace(u.Outside) == "" || !officialGAJumpTag.MatchString(u.LatestTag) || u.LatestTag != "Ubuntu-"+target.PackageVersion ||
		!strings.HasPrefix(model.SignatureVersion(h.Status.KernelSignature), model.KernelABI(h.Status.Kernel)+".") {
		return nil
	}
	// Changing initrd/GRUB hashes must not silently retry a failed or cancelled
	// attempt at the same package from the same boot. A new baseline or official
	// target package can progress; an operator can always retry manually.
	if last := h.AutoKernelJump; last != nil && last.FromBootID == h.Status.BootID &&
		last.Target.Kernel == target.Kernel && last.Target.PackageVersion == target.PackageVersion {
		return nil
	}
	if last := h.RebootResult; last != nil && last.Status != "booted" &&
		last.TargetKernel == target.Kernel && (last.FromBootID == "" || last.FromBootID == h.Status.BootID) {
		return nil
	}
	// Serialize both automatic jumps and existing manual maintenance: an offline
	// or expired-but-unconfirmed host must be reconciled before another jump.
	for _, other := range st.Hosts {
		if other.RebootRequestID != 0 || other.RebootApproval != nil {
			return nil
		}
		if last := other.AutoKernelJump; last != nil {
			result := other.RebootResult
			// A later explicit manual retry can recover a stopped rollout, but it
			// must also finish GRUB confirmation before automatic work resumes.
			if result == nil || result.ID < last.ID || result.Status != "booted" ||
				other.Status.BootConfirmedID != result.ID ||
				other.Status.BootID == "" || result.FromBootID == "" || other.Status.BootID == result.FromBootID ||
				other.Status.Kernel != result.TargetKernel || model.SignatureVersion(other.Status.KernelSignature) != result.TargetPackageVersion ||
				now.Sub(other.LastSeen) > 120*time.Second || other.LastSeen.After(now.Add(30*time.Second)) ||
				other.Status.Error != "" {
				return nil
			}
		}
	}
	st.NextRebootID++
	a := &model.RebootApproval{ID: st.NextRebootID, Target: *target, FromBootID: h.Status.BootID,
		FromKernel: h.Status.Kernel, ApprovedBy: "auto-kernel-jump", ApprovedAt: now, ExpiresAt: now.Add(rebootApprovalTTL)}
	h.RebootRequestID, h.RebootApproval = a.ID, a
	last := *a
	h.AutoKernelJump = &last
	return a
}

// handleHostPrepareKernel 은 POST /api/hosts/{id}/prepare-kernel — 관리자가 커널 점프 1단계
// (다음 공식 GA 커널 디스크 설치)를 이 호스트에만 요청합니다. auto_prepare_kernel 과 빌더 범위와
// 상관없이 동작하지만, 재부팅은 하지 않으며 준비가 끝나면 별도의 재부팅 승인이 필요합니다.
func (s *Server) handleHostPrepareKernel(w http.ResponseWriter, r *http.Request, who string) {
	id := r.PathValue("id")
	var req model.PrepareKernelBody
	if r.ContentLength != 0 {
		if err := readJSON(r, &req); err != nil {
			writeErr(w, err)
			return
		}
	}
	var name, kernel, latest, msg string
	err := s.store.Update(func(st *State) error {
		h := st.Hosts[id]
		if h == nil {
			return fail(http.StatusNotFound, "호스트 %s 가 없습니다", id)
		}
		name, kernel = h.Hostname, h.Status.Kernel
		if req.Cancel {
			h.KernelPrepareRequest = nil
			msg = name + ": 커널 준비 요청을 취소했습니다. 이미 시작한 설치는 끝까지 진행됩니다."
			return nil
		}
		if req.Kernel != "" && req.Kernel != kernel {
			return fail(http.StatusConflict, "호스트 커널이 바뀌었습니다. 현재 커널 %s 를 다시 확인하세요", kernel)
		}
		switch {
		case h.RebootPolicy != model.RebootDrain:
			return fail(http.StatusConflict, "%s 은 재부팅 정책이 drain 이 아닙니다 (kpctl host set %s -policy drain)", name, name)
		case model.LTSForKernel(kernel) == nil || model.IsHWESignature(h.Status.KernelSignature):
			return fail(http.StatusBadRequest, "%s 은 지원하는 LTS GA generic 커널이 아니라 자동 준비할 수 없습니다", name)
		case h.Status.BootTarget != nil:
			return fail(http.StatusConflict, "%s 에 이미 준비된 커널(%s)이 있습니다. 커널 점프(재부팅 승인)를 진행하세요", name, h.Status.BootTarget.Kernel)
		case h.RebootApproval != nil || h.RebootRequestID != 0:
			return fail(http.StatusConflict, "%s 은 재부팅 승인이 진행 중입니다", name)
		case h.Status.KernelPrepare != nil && h.Status.KernelPrepare.State == "preparing":
			return fail(http.StatusConflict, "%s 은 이미 커널을 준비하고 있습니다", name)
		}
		u := st.Upstream[kernel]
		if u != nil {
			if m := officialGAJumpTag.FindStringSubmatch(u.LatestTag); m != nil {
				latest = m[1] + "-generic"
			}
		}
		if latest == "" {
			return fail(http.StatusConflict, "%s 커널의 최신 공식 GA 버전을 아직 모릅니다. 빌드 서버의 최신 확인을 기다리세요", kernel)
		}
		if !model.NewerGAKernel(kernel, latest) {
			return fail(http.StatusConflict, "%s 은 이미 최신 GA ABI(%s)입니다. 점프할 새 커널이 없습니다", name, latest)
		}
		h.KernelPrepareRequest = &model.KernelPrepareRequest{Kernel: kernel, RequestedBy: who, RequestedAt: time.Now()}
		msg = fmt.Sprintf("%s: %s → %s 커널 설치를 요청했습니다. 에이전트 다음 보고 때 시작하며 재부팅하지 않습니다. 준비되면 커널 점프를 승인하세요.", name, kernel, latest)
		return nil
	})
	if err != nil {
		writeErr(w, err)
		return
	}
	if req.Cancel {
		s.audit(who, "호스트 %s(%s) 커널 준비 요청 취소", name, id)
	} else {
		s.audit(who, "호스트 %s(%s) 커널 준비 요청 %s → %s", name, id, kernel, latest)
	}
	writeJSON(w, http.StatusOK, map[string]any{"result": "ok", "message": msg, "target": latest})
}
