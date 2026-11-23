// 이 파일: 보류·호스트 건강·출시 전 목표를 존중하는 자동 승인과 승급.
package controller

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strconv"
	"time"

	"kpctl/internal/model"
)

// 이 파일: 자동 배포 (설정 auto_rollout.enabled 를 켜야 동작)
//
// 빌드된 작업을 사람 대신 승인하고, 관찰 시간이 지나면 다음 링으로 넘깁니다.
// 실제 배포는 관리자 명령과 같은 approveJob, promoteKernel 을 거칩니다.
//
// 자동으로 승인하지 않는 것:
//   - 수동 제출 패치가 새로 들어간 작업, 새 패치가 없는 재빌드 (사람이 요청한 변경)
//   - 첫 번째 링에 그 커널 호스트가 없을 때 (카나리 없이 배포하지 않음)
//   - 첫 번째 링이 건강하지 않을 때 (promoteProblems 와 같은 검사)
//
// 자동으로 멈추는 경우 (kpctl auto clear 또는 웹에서 풀 때까지):
//   - 패치가 배포된 호스트가 오류를 보고했을 때
//   - 롤백했을 때 (롤백한 패치가 다음 누적 빌드에 다시 들어가므로)
//   - 자동 승인 중 서명에 실패했을 때
//   - 누적 빌드 실패 또는 수집·시험 빌드의 검토가 필요할 때
//
// 자동으로 롤백하지는 않습니다. 멈춘 뒤의 판단은 사람이 합니다.

const autoWho = "auto" // 감사 로그와 승인자에 남는 이름

// autoAction 은 지금 실행할 일 하나입니다. jobID 가 있으면 승인, 없으면 ring 으로 승급입니다.
type autoAction struct {
	kernel string
	jobID  int
	ring   int
}

type autoPlan struct {
	actions []autoAction
	holds   map[string]autoHoldCause // 이번에 새로 멈출 커널 → 원인
	notes   map[string][]string      // 커널 → 진행하지 않는 이유
}

type autoHoldCause struct{ reason, kind, ref string }

const (
	holdUpstream = "upstream_problem"
	holdHost     = "host_error"
	holdBuild    = "build_failed"
	holdManual   = "manual"
)

func setAutoHold(t *model.Track, reason, kind, ref string) {
	t.AutoHold, t.AutoHoldKind, t.AutoHoldRef = reason, kind, ref
	t.AutoHoldAt, t.AutoHoldResolved = time.Now(), ""
}

func upstreamHold(t *model.Track, u *model.Upstream) {
	if u.ProblemKind == model.FailureBusy {
		return
	}
	ref := u.ProblemAt.UTC().Format(time.RFC3339Nano)
	if t.AutoHold == "" || t.AutoHoldKind == holdUpstream && t.AutoHoldRef != ref {
		setAutoHold(t, "수집·빌드 검토 필요: "+u.Problem, holdUpstream, ref)
	}
}

// planAuto 는 상태를 보고 할 일을 정합니다. 상태를 바꾸지 않습니다.
// 반드시 store.View/Update 안에서 불러야 합니다.
func (s *Server) planAuto(st *State) autoPlan {
	plan := autoPlan{holds: map[string]autoHoldCause{}, notes: map[string][]string{}}

	kernels := make([]string, 0, len(st.Tracks))
	for k := range st.Tracks {
		kernels = append(kernels, k)
	}
	sort.Strings(kernels)

	for _, k := range kernels {
		t := st.Tracks[k]
		if t.HasPrerelease() {
			plan.notes[k] = append(plan.notes[k], "출시 전 누적본 배포 중: 자동 승인·승급 보류, 관리자의 명시적 조작 필요")
			continue
		}
		if t.AutoHold != "" {
			plan.notes[k] = append(plan.notes[k], "자동 배포 멈춤: "+t.AutoHold)
			continue
		}
		if u := st.Upstream[k]; u != nil && u.Problem != "" {
			plan.notes[k] = append(plan.notes[k], "수집·빌드 검토 필요: "+u.Problem)
			continue
		}
		if cause := s.hostFailure(st, k, t); cause.reason != "" {
			plan.holds[k] = cause
			plan.notes[k] = append(plan.notes[k], "자동 배포 멈춤: "+cause.reason)
			continue
		}
		if s.planApprove(st, k, t, &plan) {
			continue
		}
		s.planPromote(st, k, t, &plan)
	}
	return plan
}

// hostFailure 는 패치가 배포된 호스트 중 오류를 보고한 호스트가 있으면 그 내용을 돌려줍니다.
func (s *Server) hostFailure(st *State, kernel string, t *model.Track) autoHoldCause {
	var ids []string
	for id, h := range st.Hosts {
		if h.Status.Kernel == kernel && !model.HWEWithGAName(h.Status) && h.Status.Error != "" && t.RingVersions[h.Ring] > 0 && s.rolloutEligibility(h, st.releasedJob(kernel, t.RingVersions[h.Ring])).Status == "eligible" {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return autoHoldCause{}
	}
	sort.Strings(ids)
	h := st.Hosts[ids[0]]
	return autoHoldCause{"호스트 오류 — " + h.Hostname + ": " + firstLine(h.Status.Error), holdHost, ids[0]}
}

// planApprove 는 승인할 작업이 있으면 계획에 넣고 true 를 돌려줍니다.
func (s *Server) planApprove(st *State, kernel string, t *model.Track, plan *autoPlan) bool {
	var job *model.Job
	for _, j := range st.Jobs {
		if j.Kernel == kernel && !j.Prerelease && j.Status == model.JobBuilt {
			job = j
		}
	}
	if job == nil {
		return false
	}
	if reason := autoIneligible(st, job); reason != "" {
		plan.notes[kernel] = append(plan.notes[kernel], fmt.Sprintf("작업 %d 은 직접 승인해야 합니다: %s", job.ID, reason))
		return false
	}
	first := s.cfg.Rings[0]
	problems := s.promoteProblems(st, kernel, first, t.RingVersions[first], t.RingSetAt[first], first)
	if len(problems) > 0 {
		for _, p := range problems {
			plan.notes[kernel] = append(plan.notes[kernel], fmt.Sprintf("작업 %d 승인 대기: %s", job.ID, p))
		}
		return false
	}
	plan.actions = append(plan.actions, autoAction{kernel: kernel, jobID: job.ID})
	return true
}

// autoIneligible 은 사람이 승인해야 하는 작업이면 이유를 돌려줍니다.
func autoIneligible(st *State, j *model.Job) string {
	if j.Prerelease {
		return "출시 전 작업은 명시적 승인과 VM 시험 필요"
	}
	if len(j.NewPatchIDs) == 0 {
		return "새 패치가 없는 재빌드"
	}
	for _, id := range j.NewPatchIDs {
		if p := st.patch(id); p == nil || p.Source != "ubuntu" {
			return "수동 제출 패치 포함 (" + id + ")"
		}
	}
	return ""
}

// planPromote 는 다음 링으로 넘길 수 있으면 계획에 넣습니다. 한 번에 한 링만 넘깁니다.
func (s *Server) planPromote(st *State, kernel string, t *model.Track, plan *autoPlan) {
	for i := 1; i < len(s.cfg.Rings); i++ {
		prev, ring := s.cfg.Rings[i-1], s.cfg.Rings[i]
		version := t.RingVersions[prev]
		if version == 0 {
			return
		}
		if t.RingVersions[ring] >= version {
			continue
		}
		problems := s.autoPromoteProblems(st, kernel, prev, version, t.RingSetAt[prev], ring)
		if len(problems) > 0 {
			for _, p := range problems {
				plan.notes[kernel] = append(plan.notes[kernel], fmt.Sprintf("링 %d 승급 대기: %s", ring, p))
			}
			return
		}
		plan.actions = append(plan.actions, autoAction{kernel: kernel, ring: ring})
		return
	}
}

func (s *Server) autoPromoteProblems(st *State, kernel string, prevRing, version int, prevSetAt time.Time, ring int) []string {
	set := s.settings()
	if set.AutoApproveOnly {
		return []string{"승급은 직접 해야 합니다 (approve_only)"}
	}
	problems := s.promoteProblems(st, kernel, prevRing, version, prevSetAt, ring)
	// 링별 최소 관찰 시간보다 자동 배포의 관찰 시간이 길면 그만큼 더 기다립니다.
	need := time.Duration(set.AutoSoakMinutes) * time.Minute
	if since := time.Since(prevSetAt); since < need && set.MinSoakMinutes[ring] < set.AutoSoakMinutes {
		problems = append(problems, fmt.Sprintf("링 %d 관찰 시간 부족: %s 지남 / 최소 %s", prevRing, since.Round(time.Minute), need))
	}
	return problems
}

// autoStatus 는 /api/status 에 넣을 자동 배포 현황입니다. store.View 안에서 부릅니다.
func (s *Server) autoStatus(st *State) *model.AutoStatus {
	a := s.settings()
	out := &model.AutoStatus{
		Enabled: a.AutoEnabled, ApproveOnly: a.AutoApproveOnly, SoakMinutes: a.AutoSoakMinutes,
		Paused: st.AutoPaused, PausedBy: st.AutoPausedBy,
	}
	if a.AutoEnabled {
		out.Notes = s.planAuto(st).notes
	}
	return out
}

// ── 실행 ──

// 자동 배포는 웹 설정에서 켜고 끌 수 있으므로 루프는 항상 돌고, 꺼져 있으면 autoTick 이 바로 돌아갑니다.
func (s *Server) autoLoop(ctx context.Context) {
	set := s.settings()
	log.Printf("자동 배포 확인 루프 (%d초마다, 지금 켜짐=%v, 관찰 %d분, approve_only=%v)",
		s.cfg.AutoRollout.CheckSeconds, set.AutoEnabled, set.AutoSoakMinutes, set.AutoApproveOnly)
	ticker := time.NewTicker(time.Duration(s.cfg.AutoRollout.CheckSeconds) * time.Second)
	defer ticker.Stop()
	for {
		s.auditSigningWarnings(s.signingStatus())
		s.autoTick()
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// autoTick 은 한 번 확인하고 할 일을 실행합니다.
func (s *Server) autoTick() {
	s.markResolvedHolds()
	if !s.settings().AutoEnabled {
		return
	}
	var plan autoPlan
	paused := false
	s.store.View(func(st *State) {
		if paused = st.AutoPaused; !paused {
			plan = s.planAuto(st)
		}
	})
	if paused {
		return
	}
	for k, cause := range plan.holds {
		s.autoHold(k, cause)
	}
	for _, a := range plan.actions {
		if !s.autoAllowed(a.kernel) { // 계획을 세운 뒤 관리자가 멈췄을 수 있음
			continue
		}
		if a.jobID != 0 {
			if _, _, _, err := s.approveJobWithPrerelease(a.jobID, autoWho, false, true); err != nil {
				s.autoFailed(a, fmt.Sprintf("작업 %d 자동 승인 실패: %s", a.jobID, firstLine(err.Error())), err)
			}
			continue
		}
		if _, err := s.promoteKernel(a.kernel, autoWho, model.PromoteRequest{Ring: a.ring}, true); err != nil {
			s.autoFailed(a, fmt.Sprintf("링 %d 자동 승급 실패: %s", a.ring, firstLine(err.Error())), err)
		}
	}
}

func (s *Server) autoAllowed(kernel string) bool {
	ok := false
	s.store.View(func(st *State) {
		ok = s.autoRolloutProblem(st, kernel) == nil
	})
	return ok
}

// autoRolloutProblem은 상태 잠금 안에서 자동 배포의 공통 조건을 다시 확인합니다.
func (s *Server) autoRolloutProblem(st *State, kernel string) error {
	t := st.Tracks[kernel]
	switch {
	case !s.settings().AutoEnabled || st.AutoPaused:
		return fail(http.StatusConflict, "자동 배포가 꺼져 있거나 일시 중지됐습니다")
	case t == nil || t.AutoHold != "" || t.HasPrerelease():
		return fail(http.StatusConflict, "%s 커널의 자동 배포가 보류됐습니다", kernel)
	}
	if u := st.Upstream[kernel]; u != nil && u.Problem != "" {
		return fail(http.StatusConflict, "수집·빌드 검토 필요: %s", u.Problem)
	}
	if cause := s.hostFailure(st, kernel, t); cause.reason != "" {
		return fail(http.StatusConflict, "%s", cause.reason)
	}
	return nil
}

func (s *Server) autoApprovalProblem(st *State, j *model.Job) error {
	if err := s.autoRolloutProblem(st, j.Kernel); err != nil {
		return err
	}
	plan := autoPlan{notes: map[string][]string{}}
	if !s.planApprove(st, j.Kernel, st.Tracks[j.Kernel], &plan) || plan.actions[0].jobID != j.ID {
		return fail(http.StatusConflict, "%s 커널의 자동 승인 대상 또는 카나리 상태가 바뀌었습니다", j.Kernel)
	}
	return nil
}

// 웹 설정과 상태가 자동 승인·승급의 확인부터 디스크 커밋까지 유지되도록 합니다.
func (s *Server) updateRollout(automated bool, update func(*State) error) error {
	if automated {
		s.rolloutSettingsMu.Lock()
		defer s.rolloutSettingsMu.Unlock()
	}
	return s.store.UpdateAtomic(update)
}

// autoFailed 는 실패를 처리합니다. 상태가 그 사이 바뀐 충돌(409)은 다음 확인에 맡기고, 나머지는 멈춥니다.
func (s *Server) autoFailed(a autoAction, reason string, err error) {
	var he *httpError
	if errors.As(err, &he) && he.code == http.StatusConflict {
		log.Printf("자동 배포 %s: %s", a.kernel, reason)
		return
	}
	s.autoHold(a.kernel, autoHoldCause{reason, holdManual, ""})
}

func (s *Server) autoHold(kernel string, cause autoHoldCause) {
	err := s.store.Update(func(st *State) error {
		if t := st.Tracks[kernel]; t != nil {
			if t.AutoHold == "" {
				setAutoHold(t, cause.reason, cause.kind, cause.ref)
			}
		}
		return nil
	})
	if err != nil {
		log.Printf("자동 배포 멈춤 저장 실패: %v", err)
	}
	s.audit(autoWho, "자동 배포 멈춤 kernel=%s: %s", kernel, cause.reason)
}

// ── API ──

// POST /api/auto — 자동 배포 전체 일시 중지/재개
func (s *Server) handleAutoPause(w http.ResponseWriter, r *http.Request, who string) {
	var req model.AutoPauseRequest
	if err := readJSON(r, &req); err != nil {
		writeErr(w, err)
		return
	}
	err := s.store.UpdateAtomic(func(st *State) error {
		st.AutoPaused = req.Paused
		st.AutoPausedBy = ""
		if req.Paused {
			st.AutoPausedBy = who
		}
		return nil
	})
	if err != nil {
		writeErr(w, err)
		return
	}
	s.audit(who, "자동 배포 일시 중지=%v", req.Paused)
	writeJSON(w, http.StatusOK, map[string]string{"result": "ok"})
}

// POST /api/kernels/{kernel}/auto — 커널 하나의 자동 배포 멈춤/재개
func (s *Server) handleAutoHold(w http.ResponseWriter, r *http.Request, who string) {
	kernel := r.PathValue("kernel")
	var req model.AutoHoldRequest
	if err := readJSON(r, &req); err != nil {
		writeErr(w, err)
		return
	}
	err := s.store.UpdateAtomic(func(st *State) error {
		t := st.Tracks[kernel]
		if t == nil {
			return fail(http.StatusNotFound, "%s 커널의 배포 기록이 없습니다", kernel)
		}
		t.AutoHold, t.AutoHoldKind, t.AutoHoldRef, t.AutoHoldResolved = "", "", "", ""
		t.AutoHoldAt = time.Time{}
		if req.Hold {
			setAutoHold(t, who+" 가 멈춤", holdManual, "")
		}
		return nil
	})
	if err != nil {
		writeErr(w, err)
		return
	}
	s.audit(who, "자동 배포 kernel=%s 멈춤=%v", kernel, req.Hold)
	writeJSON(w, http.StatusOK, map[string]string{"result": "ok"})
}

// holdResolved 는 시스템이 자동으로 건 멈춤의 원인이 사라졌는지 봅니다.
// 관리자가 건 멈춤·롤백·자동 승인 실패처럼 사람이 판단할 멈춤은 false 입니다.
func (s *Server) holdResolved(st *State, kernel string, t *model.Track) (bool, string) {
	u := st.Upstream[kernel]
	if u != nil && (u.Problem != "" || u.Outside != "") {
		return false, ""
	}
	switch t.AutoHoldKind {
	case holdUpstream:
		if u != nil && u.Problem == "" && u.Outside == "" && t.AutoHoldRef != "" && u.ProblemResolvedRef == t.AutoHoldRef {
			if u.ProblemResolution == "admin_exclusion" {
				return true, "관리자 제외로 수집 계속 · CVE 미해결"
			}
			return true, "수집 문제 해결"
		}
	case holdHost:
		h := st.Hosts[t.AutoHoldRef]
		if h != nil && h.Status.Kernel == kernel && !model.HWEWithGAName(h.Status) && h.Status.Error == "" &&
			!t.AutoHoldAt.IsZero() && h.LastSeen.After(t.AutoHoldAt) &&
			time.Since(h.LastSeen) < time.Duration(s.settings().HostStaleMinutes)*time.Minute && s.hostFailure(st, kernel, t).reason == "" {
			return true, "호스트 오류 해결"
		}
	case holdBuild:
		id, _ := strconv.Atoi(t.AutoHoldRef)
		if failed := st.job(id); failed != nil && failed.Kernel == kernel && failed.Status == model.JobFailed {
			var latest *model.Job
			for _, j := range st.Jobs {
				if j.Kernel == kernel && j.Prerelease == failed.Prerelease && j.ID > id && (latest == nil || j.ID > latest.ID) {
					latest = j
				}
			}
			if latest != nil && (latest.Status == model.JobBuilt || latest.Status == model.JobReleased) && includesPatches(latest.PatchIDs, failed.PatchIDs) {
				return true, fmt.Sprintf("이후 job %d 빌드 성공", latest.ID)
			}
		}
	}
	return false, ""
}

func includesPatches(have, need []string) bool {
	if len(need) == 0 {
		return false // 원래 빌드 입력을 확인할 수 없음
	}
	for _, id := range need {
		found := false
		for _, got := range have {
			found = found || got == id
		}
		if !found {
			return false
		}
	}
	return true
}

// markResolvedHolds 는 자동으로 건 멈춤의 원인이 사라졌는지 표시만 합니다 (웹에서 오류 대신 "원인 해결됨"으로 보임).
// 멈춤 자체는 풀지 않습니다. 원인이 사라져도 그 사이 만든 모듈이 안전한지는 사람이 확인해야 합니다.
// (예: 적용 실패 호스트가 재부팅으로 오류가 사라져도, 실패한 버전이 다음 링으로 자동 승급되면 안 됨)
func (s *Server) markResolvedHolds() {
	type change struct{ kernel, why string }
	var changed []change
	unchanged := errors.New("자동 멈춤 표시 변경 없음")
	err := s.store.Update(func(st *State) error {
		dirty := false
		for k, t := range st.Tracks {
			why := ""
			if t.AutoHold != "" {
				_, why = s.holdResolved(st, k, t)
			}
			if why != t.AutoHoldResolved {
				dirty = true
				t.AutoHoldResolved = why
				if why != "" {
					changed = append(changed, change{k, why})
				}
			}
		}
		if !dirty {
			return unchanged
		} // Store.Update 는 오류이면 저장하지 않습니다.
		return nil
	})
	if errors.Is(err, unchanged) {
		return
	}
	if err != nil {
		log.Printf("자동 배포 멈춤 원인 확인 저장 실패: %v", err)
		return
	}
	for _, c := range changed {
		s.audit(autoWho, "자동 배포 멈춤 원인 해결 kernel=%s (%s) — 검토 후 자동 재개 필요", c.kernel, c.why)
	}
}
