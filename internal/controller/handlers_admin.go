// 이 파일: 관리자 패치·빌드·승인·승급·롤백·호스트 API.
package controller

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"kpctl/internal/model"
)

// 이 파일: kpctl(관리자)이 부르는 API

// GET /api/status — 전체 현황
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request, who string) {
	var body []byte
	validation := s.validationStatus()
	s.store.View(func(st *State) {
		resp := model.StatusResponse{
			Now: time.Now(), Who: who, Rings: s.cfg.Rings, HostStaleMinutes: s.settings().HostStaleMinutes,
			Auto: s.autoStatus(st), Unpatchable: st.Unpatchable,
			Validation: validation,
		}
		for _, t := range st.Tracks {
			resp.Tracks = append(resp.Tracks, t)
		}
		resp.Upstream = st.Upstream
		resp.Builders = st.Builders
		resp.LatestReleased = map[string]int{}
		resp.ReleasedTags = map[string]map[int]string{}
		for _, j := range st.Jobs {
			if j.Status != model.JobReleased || j.Prerelease {
				continue
			}
			if j.Version > resp.LatestReleased[j.Kernel] {
				resp.LatestReleased[j.Kernel] = j.Version
			}
			if j.UpToTag != "" {
				if resp.ReleasedTags[j.Kernel] == nil {
					resp.ReleasedTags[j.Kernel] = map[int]string{}
				}
				resp.ReleasedTags[j.Kernel][j.Version] = j.UpToTag
			}
		}
		sort.Slice(resp.Tracks, func(i, j int) bool { return resp.Tracks[i].Kernel < resp.Tracks[j].Kernel })

		// 최근 작업 30개 (최신이 위)
		for i := len(st.Jobs) - 1; i >= 0 && len(resp.Jobs) < 30; i-- {
			resp.Jobs = append(resp.Jobs, st.Jobs[i])
		}

		for _, h := range st.Hosts {
			cp := *h
			cp.TokenHash = "" // 토큰 해시는 내보내지 않음
			if e := st.MOKRequests[h.ID]; e != nil {
				cp.MOKRequest = &model.MOKImportResult{ID: e.Request.ID, KeyID: e.Request.KeyID, Status: "awaiting_agent"}
				if e.Result != nil {
					cp.MOKRequest.Status = e.Result.Status
				}
			}
			cp.Status.SignatureRequired, cp.Status.SecurityWarning = hostSecurityPolicy(cp.Status)
			cp.Status.SecurityWarning = joinSecurityWarnings(cp.Status.SecurityWarning, h.Status.SecurityWarning)
			if t := st.Tracks[h.Status.Kernel]; t != nil {
				j := st.releasedJob(h.Status.Kernel, t.TargetVersion(h.Ring))
				eligibility := s.rolloutEligibility(h, j)
				cp.RolloutEligibility = &eligibility
			}
			resp.Hosts = append(resp.Hosts, &cp)
		}
		sort.Slice(resp.Hosts, func(i, j int) bool { return resp.Hosts[i].Hostname < resp.Hosts[j].Hostname })

		body = mustJSON(resp) // 잠금 안에서 직렬화해야 안전함
	})
	writeRaw(w, http.StatusOK, body)
}

// GET /api/kernels/{kernel}/patches — 커널의 패치 목록
func (s *Server) handleListPatches(w http.ResponseWriter, r *http.Request, who string) {
	kernel := r.PathValue("kernel")
	var body []byte
	s.store.View(func(st *State) {
		out := []*model.Patch{}
		for _, p := range st.Patches {
			if p.Kernel == kernel {
				out = append(out, p)
			}
		}
		body = mustJSON(out)
	})
	writeRaw(w, http.StatusOK, body)
}

// POST /api/kernels/{kernel}/patches — 수동 패치 제출 (kpctl submit)
// 패치를 활성 목록에 넣고 곧바로 새 누적 빌드 작업을 만듭니다.
func (s *Server) handleSubmitPatch(w http.ResponseWriter, r *http.Request, who string) {
	kernel := r.PathValue("kernel")
	if !validKernel(kernel) {
		writeErr(w, fail(http.StatusBadRequest, "커널 이름이 잘못됐습니다: %q", kernel))
		return
	}
	var req model.SubmitPatchRequest
	if err := readJSON(r, &req); err != nil {
		writeErr(w, err)
		return
	}
	if !looksLikePatch(req.Content) {
		writeErr(w, fail(http.StatusBadRequest, "패치 내용이 diff 형식이 아닙니다"))
		return
	}

	var resp model.SubmitPatchResponse
	err := s.store.Update(func(st *State) error {
		id := "p" + leftPad(st.NextPatchID+1)
		if err := os.WriteFile(s.patchFile(id), []byte(req.Content), 0o640); err != nil {
			return err
		}
		st.NextPatchID++
		title := strings.TrimSpace(req.Title)
		if title == "" {
			title = "(제목 없음)"
		}
		st.Patches = append(st.Patches, &model.Patch{
			ID: id, Kernel: kernel, Source: "manual", CVEs: normalizeCVEs(req.CVEs),
			Title: title, State: model.PatchActive, AddedBy: who, AddedAt: time.Now(),
		})
		job, err := s.createJob(st, kernel, who, req.Urgent)
		if err != nil {
			return err
		}
		resp = model.SubmitPatchResponse{PatchID: id, JobID: job.ID, Version: job.Version}
		return nil
	})
	if err != nil {
		writeErr(w, err)
		return
	}
	s.audit(who, "패치 제출 %s kernel=%s urgent=%v → job %d (v%d)", resp.PatchID, kernel, req.Urgent, resp.JobID, resp.Version)
	writeJSON(w, http.StatusOK, resp)
}

// POST /api/kernels/{kernel}/build — 현재 활성 패치로 다시 빌드 (패치 enable/disable 후 사용)
func (s *Server) handleBuild(w http.ResponseWriter, r *http.Request, who string) {
	kernel := r.PathValue("kernel")
	var req model.BuildRequest
	if err := readJSON(r, &req); err != nil {
		writeErr(w, err)
		return
	}
	var job *model.Job
	err := s.store.Update(func(st *State) error {
		var err error
		job, err = s.createJobChannel(st, kernel, who, req.Urgent, req.Prerelease)
		return err
	})
	if err != nil {
		writeErr(w, err)
		return
	}
	s.audit(who, "빌드 요청 kernel=%s → job %d (v%d)", kernel, job.ID, job.Version)
	writeJSON(w, http.StatusOK, job)
}

// POST /api/patches/{id}/state — 패치를 다시 켜거나(active) 끔(disabled)
// 바꾼 뒤에는 kpctl build 로 새 버전을 만들어야 반영됩니다.
func (s *Server) handlePatchState(w http.ResponseWriter, r *http.Request, who string) {
	id := r.PathValue("id")
	var req model.PatchStateRequest
	if err := readJSON(r, &req); err != nil {
		writeErr(w, err)
		return
	}
	if req.State != model.PatchActive && req.State != model.PatchDisabled {
		writeErr(w, fail(http.StatusBadRequest, "state 는 active 또는 disabled 만 됩니다"))
		return
	}
	err := s.store.Update(func(st *State) error {
		p := st.patch(id)
		if p == nil {
			return fail(http.StatusNotFound, "패치 %s 가 없습니다", id)
		}
		p.State = req.State
		p.Reason = ""
		if req.State == model.PatchDisabled {
			p.Reason = who + " 가 비활성화"
		}
		return nil
	})
	if err != nil {
		writeErr(w, err)
		return
	}
	s.audit(who, "패치 %s 상태 → %s", id, req.State)
	writeJSON(w, http.StatusOK, map[string]string{"result": "ok"})
}

// POST /api/jobs/{id}/approve — 빌드된 작업을 승인: 서명 후 첫 번째 링에 배포
func (s *Server) handleApprove(w http.ResponseWriter, r *http.Request, who string) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		writeErr(w, fail(http.StatusBadRequest, "작업 번호가 잘못됐습니다"))
		return
	}

	var req model.ApproveRequest
	if r.ContentLength != 0 {
		if err := readJSON(r, &req); err != nil {
			writeErr(w, err)
			return
		}
	}
	kernel, version, ring, err := s.approveJobWithPrerelease(id, who, req.Prerelease, false)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"result": "released", "kernel": kernel, "version": version, "ring": ring, "prerelease": version < 0, "prerelease_version": max(0, -version)})
}

// approveJob 은 정식 작업을 수동 승인합니다.
func (s *Server) approveJob(id int, who string) (kernel string, version, firstRing int, err error) {
	return s.approveJobWithPrerelease(id, who, false, false)
}

func (s *Server) approveJobWithPrerelease(id int, who string, allowPrerelease, automated bool) (kernel string, version, firstRing int, err error) {
	s.approveMu.Lock() // 같은 모듈을 두 번 서명하지 않도록
	defer s.approveMu.Unlock()
	if s.cfg.TestVM.Enabled && s.testVMCtx.Err() != nil {
		return "", 0, 0, fail(http.StatusServiceUnavailable, "컨트롤러 종료 중에는 VM 시험을 시작할 수 없습니다")
	}

	// 1) 상태 확인
	var module string
	var checkErr error
	s.store.View(func(st *State) {
		j := st.job(id)
		switch {
		case j == nil:
			checkErr = fail(http.StatusNotFound, "작업 %d 이 없습니다", id)
		case j.Status != model.JobBuilt:
			checkErr = fail(http.StatusConflict, "작업 %d 은 %s 상태라 승인할 수 없습니다 (built 만 가능)", id, j.Status)
		default:
			checkErr = s.prereleaseApprovalProblem(st, j, allowPrerelease, automated)
			if checkErr == nil && automated {
				checkErr = s.autoApprovalProblem(st, j)
			}
			if checkErr == nil {
				kernel, module = j.Kernel, j.ModuleName
			}
		}
	})
	if checkErr != nil {
		return "", 0, 0, checkErr
	}

	// 2) 원본을 보존하고 키별 서명 바이트를 모두 시험합니다.
	artifacts, activeKey, rotations, err := s.prepareSigningArtifactsWithRotations(id, kernel, module)
	if err != nil {
		return "", 0, 0, err
	}
	active := artifacts[activeKey]
	sum := active.SHA256

	// 3) 배포 (첫 번째 링)
	firstRing = s.cfg.Rings[0]
	err = s.updateRollout(automated, func(st *State) error {
		j := st.job(id)
		if j == nil || j.Status != model.JobBuilt || j.Kernel != kernel || j.ModuleName != module {
			return fail(http.StatusConflict, "작업 %d 의 상태가 그 사이에 바뀌었습니다", id)
		}
		if err := s.prereleaseApprovalProblem(st, j, allowPrerelease, automated); err != nil {
			return err
		}
		if automated {
			if err := s.autoApprovalProblem(st, j); err != nil {
				return err
			}
		}
		if s.cfg.TestVM.Enabled {
			requiredModes, signatureRequired := s.testVMRequirementsLocked(st, kernel)
			for _, mode := range requiredModes {
				covered := false
				if active.VMTest != nil {
					for _, tested := range active.VMTest.Modes {
						covered = covered || tested == mode
					}
				}
				if !covered {
					return fail(http.StatusConflict, "시험 중 fleet 펌웨어가 바뀌었습니다. %s 모드 시험을 다시 실행하세요", mode)
				}
			}
			if signatureRequired && !active.Signed {
				return fail(http.StatusConflict, "시험 중 호스트 서명 정책이 바뀌었습니다. sign_command 또는 signing 을 설정하세요")
			}
		}
		for key, artifact := range artifacts {
			actual, err := fileSHA256(s.signingArtifactFile(kernel, module, key))
			if err != nil || actual != artifact.SHA256 {
				return fail(http.StatusConflict, "시험한 키 %s 사본의 SHA256이 게시 전에 바뀌었습니다", key)
			}
		}
		// 예전 에이전트의 URL도 active 서명 사본과 같은 바이트를 제공합니다.
		data, readErr := os.ReadFile(s.signingArtifactFile(kernel, module, activeKey))
		if readErr != nil {
			return readErr
		}
		if signingBytesSHA256(data) != sum {
			return fail(http.StatusConflict, "시험한 active 서명 사본의 SHA256이 게시 전에 바뀌었습니다")
		}
		tmp, writeErr := os.CreateTemp(filepath.Dir(s.artifactFile(kernel, module)), ".active-")
		if writeErr != nil {
			return writeErr
		}
		defer os.Remove(tmp.Name())
		if _, writeErr = tmp.Write(data); writeErr != nil {
			tmp.Close()
			return writeErr
		}
		if writeErr = tmp.Close(); writeErr != nil {
			return writeErr
		}
		commitRotations, rotationErr := s.publishSigningRotationsLocked(st, id, rotations)
		if rotationErr != nil {
			return rotationErr
		}
		if writeErr = os.Rename(tmp.Name(), s.artifactFile(kernel, module)); writeErr != nil {
			return writeErr
		}
		commitRotations()
		j.SigningArtifacts, j.ActiveSigningKey, j.VMTest = artifacts, activeKey, combinedVMResult(active, artifacts)

		now := time.Now()
		j.Status = model.JobReleased
		j.SHA256 = sum
		j.ApprovedBy = who
		j.ReleasedAt = now
		t := st.track(j.Kernel)
		setRingTarget(t, firstRing, j.Version, now)
		version = j.Version
		return nil
	})
	if err != nil {
		return "", 0, 0, err
	}
	s.audit(who, "승인 job %d kernel=%s v%d → 링 %d 배포 (sha256 %s)", id, kernel, version, firstRing, sum[:12])
	return kernel, version, firstRing, nil
}

// GET /api/jobs/{id}/log — 빌드 로그
func (s *Server) handleJobLog(w http.ResponseWriter, r *http.Request, who string) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		writeErr(w, fail(http.StatusBadRequest, "작업 번호가 잘못됐습니다"))
		return
	}
	var data []byte
	var readErr error
	s.store.View(func(st *State) {
		j := st.job(id)
		if j == nil {
			readErr = fail(http.StatusNotFound, "작업 %d 이 없습니다", id)
			return
		}
		path := s.logFile(id)
		if j.Status == model.JobRunning {
			path = s.liveLogFile(id)
		}
		data, readErr = os.ReadFile(path)
		if os.IsNotExist(readErr) && j.Status == model.JobRunning {
			data, readErr = []byte("실행 중인 빌더의 첫 로그 보고를 기다리고 있습니다.\n"), nil
		}
	})
	if readErr != nil {
		writeErr(w, fail(http.StatusNotFound, "작업 %d 의 로그가 없습니다: %v", id, readErr))
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(data)
}

// POST /api/kernels/{kernel}/promote — 이전 링의 버전을 다음 링으로
func (s *Server) handlePromote(w http.ResponseWriter, r *http.Request, who string) {
	kernel := r.PathValue("kernel")
	var req model.PromoteRequest
	if err := readJSON(r, &req); err != nil {
		writeErr(w, err)
		return
	}

	version, err := s.promoteKernel(kernel, who, req, false)
	if err != nil {
		writeErr(w, err)
		return
	}
	excluded := s.excludedHosts(kernel)
	writeJSON(w, http.StatusOK, map[string]any{"result": "ok", "ring": req.Ring, "version": version, "excluded_count": len(excluded), "excluded_hosts": excluded})
}

// promoteKernel 은 이전 링의 버전을 다음 링에 배포합니다.
func (s *Server) promoteKernel(kernel, who string, req model.PromoteRequest, automated bool) (version int, err error) {
	ring := req.Ring
	idx := -1
	for i, r := range s.cfg.Rings {
		if r == ring {
			idx = i
		}
	}
	if idx < 0 {
		return 0, fail(http.StatusBadRequest, "링 %d 은 설정에 없습니다 (rings: %v)", ring, s.cfg.Rings)
	}
	if idx == 0 {
		return 0, fail(http.StatusBadRequest, "첫 번째 링(%d)은 approve 로 배포됩니다", ring)
	}
	prevRing := s.cfg.Rings[idx-1]

	err = s.updateRollout(automated, func(st *State) error {
		t := st.Tracks[kernel]
		if t == nil {
			return fail(http.StatusNotFound, "%s 커널의 배포 기록이 없습니다", kernel)
		}
		if automated {
			if err := s.autoRolloutProblem(st, kernel); err != nil {
				return err
			}
		}
		version = t.TargetVersion(prevRing)
		if req.ExpectedVersion != nil && *req.ExpectedVersion != version {
			return fail(http.StatusPreconditionFailed, "링 %d 의 목표 버전이 %s 로 바뀌었습니다. 현재 버전을 확인하고 다시 승급하세요", prevRing, model.VersionLabel(version))
		}
		if version == 0 {
			return fail(http.StatusConflict, "링 %d 에 배포된 버전이 없습니다", prevRing)
		}
		if version < 0 {
			job := st.releasedJob(kernel, version)
			if job == nil || !job.Prerelease {
				return fail(http.StatusConflict, "출시 전 배포 작업을 확인하지 못했습니다")
			}
			if err := s.prereleaseApprovalProblem(st, job, req.Prerelease, automated); err != nil {
				return err
			}
		}
		target := t.TargetVersion(ring)
		if automated && target > version {
			return fail(http.StatusConflict, "링 %d 의 현재 목표 버전이 이전 링보다 높아 자동 승급을 보류합니다", ring)
		}
		if target == version {
			return fail(http.StatusConflict, "링 %d 은 이미 v%d 입니다", ring, version)
		}
		if !req.Force {
			setAt := t.TargetSetAt(prevRing)
			var problems []string
			if automated {
				problems = s.autoPromoteProblems(st, kernel, prevRing, version, setAt, ring)
			} else {
				problems = s.promoteProblems(st, kernel, prevRing, version, setAt, ring)
			}
			if len(problems) > 0 {
				return fail(http.StatusConflict, "promote 를 막았습니다:\n  - %s\n(확인 후에도 진행하려면 --force)", strings.Join(problems, "\n  - "))
			}
		}
		setRingTarget(t, ring, version, time.Now())
		return nil
	})
	if err != nil {
		return 0, err
	}
	s.audit(who, "promote kernel=%s v%d 링 %d → 링 %d force=%v", kernel, version, prevRing, ring, req.Force)
	return version, nil
}

// GET /api/patches/{id}/diff — 패치 본문 (승인 전 검토용)
func (s *Server) handlePatchDiff(w http.ResponseWriter, r *http.Request, who string) {
	id := r.PathValue("id")
	found := false
	s.store.View(func(st *State) { found = st.patch(id) != nil }) // 목록에 있는 ID 만 파일 경로로 씁니다
	if !found {
		writeErr(w, fail(http.StatusNotFound, "패치 %s 가 없습니다", id))
		return
	}
	data, err := os.ReadFile(s.patchFile(id))
	if err != nil {
		writeErr(w, err)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write(data)
}

// GET /api/audit — 감사 로그 최근 줄 (최신이 아래)
func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request, who string) {
	data, err := os.ReadFile(filepath.Join(s.cfg.DataDir, "audit.log"))
	if err != nil && !os.IsNotExist(err) {
		writeErr(w, err)
		return
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) > 500 {
		lines = lines[len(lines)-500:]
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(strings.Join(lines, "\n")))
}

// POST /api/kernels/{kernel}/rollback — 모든 링을 지정한 버전으로 되돌림 (0 = 패치 전부 내림)
func (s *Server) handleRollback(w http.ResponseWriter, r *http.Request, who string) {
	kernel := r.PathValue("kernel")
	var req model.RollbackRequest
	if err := readJSON(r, &req); err != nil {
		writeErr(w, err)
		return
	}
	err := s.store.UpdateAtomic(func(st *State) error {
		t := st.Tracks[kernel]
		if t == nil {
			return fail(http.StatusNotFound, "%s 커널의 배포 기록이 없습니다", kernel)
		}
		if req.Version != 0 && st.releasedJob(kernel, req.Version) == nil {
			return fail(http.StatusBadRequest, "v%d 은 배포된 적이 없는 버전입니다", req.Version)
		}
		if req.Version < 0 && !req.Prerelease {
			return fail(http.StatusConflict, "출시 전 롤백은 --prerelease를 명시해야 합니다")
		}
		now := time.Now()
		for _, ring := range s.cfg.Rings {
			setRingTarget(t, ring, req.Version, now)
		}
		// 롤백하면 호스트별 "즉시 업데이트"도 풀어서 모든 호스트가 롤백한 버전을 따르게 합니다.
		for _, h := range st.Hosts {
			if h.UpdateNowKernel == kernel {
				h.UpdateNowKernel, h.UpdateNowVersion = "", 0
			}
		}
		// 롤백한 패치도 활성 상태라 다음 누적 빌드에 다시 들어갑니다. 사람이 풀 때까지 자동 배포를 멈춥니다.
		setAutoHold(t, fmt.Sprintf("%s 가 v%d 로 롤백", who, req.Version), holdManual, "")
		return nil
	})
	if err != nil {
		writeErr(w, err)
		return
	}
	s.audit(who, "롤백 kernel=%s → 모든 링 v%d", kernel, req.Version)
	writeJSON(w, http.StatusOK, map[string]any{"result": "ok", "version": req.Version})
}

// ── 호스트 관리 ──

// POST /api/hosts/{id} — 링, 재부팅 정책 변경
func (s *Server) handleHostUpdate(w http.ResponseWriter, r *http.Request, who string) {
	s.rebootMu.Lock()
	defer s.rebootMu.Unlock()
	id := r.PathValue("id")
	var req model.HostUpdateRequest
	if err := readJSON(r, &req); err != nil {
		writeErr(w, err)
		return
	}
	if req.Ring != nil && !s.cfg.hasRing(*req.Ring) {
		writeErr(w, fail(http.StatusBadRequest, "링 %d 은 설정에 없습니다 (rings: %v)", *req.Ring, s.cfg.Rings))
		return
	}
	if req.RebootPolicy != nil && !validRebootPolicy(*req.RebootPolicy) {
		writeErr(w, fail(http.StatusBadRequest, "reboot_policy 는 drain 또는 never 입니다"))
		return
	}
	var name string
	err := s.store.Update(func(st *State) error {
		h := st.Hosts[id]
		if h == nil {
			return fail(http.StatusNotFound, "호스트 %s 가 없습니다", id)
		}
		name = h.Hostname
		if req.Ring != nil {
			h.Ring = *req.Ring
		}
		if req.RebootPolicy != nil {
			h.RebootPolicy = *req.RebootPolicy
			if *req.RebootPolicy == model.RebootNever && h.RebootApproval != nil && h.RebootApproval.DispatchedAt == nil {
				finishReboot(h, "cancelled", "관리자가 재부팅 정책을 never로 변경했습니다")
			}
		}
		return nil
	})
	if err != nil {
		writeErr(w, err)
		return
	}
	s.audit(who, "호스트 %s(%s) 설정 변경 ring=%v policy=%v", name, id, deref(req.Ring), derefS(req.RebootPolicy))
	writeJSON(w, http.StatusOK, map[string]string{"result": "ok"})
}

// POST /api/kernels/{kernel}/refresh — Ubuntu 최신 CVE 수정을 바로 수집해서 빌드하도록 빌드 서버에 요청
// 빌드 서버가 다음 작업 확인(기본 30초) 때 가져가서 수집하고, 새 패치가 있으면 컨트롤러가 빌드 작업을 만듭니다.
// 아직 빌드하지 않은 활성 패치가 있으면 수집을 기다리지 않고 바로 빌드 작업도 만듭니다.
func (s *Server) handleKernelRefresh(w http.ResponseWriter, r *http.Request, who string) {
	kernel := r.PathValue("kernel")
	if !validKernel(kernel) {
		writeErr(w, fail(http.StatusBadRequest, "커널 이름이 잘못됐습니다: %q", kernel))
		return
	}
	var jobID, version int
	err := s.store.Update(func(st *State) error {
		u := st.upstream(kernel)
		u.RefreshRequestedAt, u.RefreshRequestedBy = time.Now(), who
		if unbuiltPatches(st, kernel) {
			j, err := s.createJob(st, kernel, who, false)
			if err == nil {
				jobID, version = j.ID, j.Version
			}
		}
		return nil
	})
	if err != nil {
		writeErr(w, err)
		return
	}
	msg := kernel + ": 빌드 서버에 바로 수집·빌드를 요청했습니다. 새 수정이 있으면 빌드 작업이 생깁니다."
	if jobID != 0 {
		msg = fmt.Sprintf("%s: 아직 빌드하지 않은 패치로 빌드 작업 %d (v%d) 을 만들고, 최신 수정 수집도 요청했습니다.", kernel, jobID, version)
		s.audit(who, "빌드 요청 kernel=%s → job %d (v%d) + 수집 요청", kernel, jobID, version)
	} else {
		s.audit(who, "수집·빌드 요청 kernel=%s", kernel)
	}
	writeJSON(w, http.StatusOK, map[string]any{"result": "ok", "message": msg, "job_id": jobID})
}

// POST /api/kernels/{kernel}/purge — 최근 커널 범위 밖 커널의 빌드 서버 자료(캐시·디버그 심볼·시험 기록) 삭제 요청
// 컨트롤러 기록과 호스트의 라이브패치는 그대로 둡니다. 빌드 서버가 다음 작업 확인 때 가져가서 다시 범위를 확인한 뒤 지웁니다.
// body {"cancel": true} 면 아직 가져가지 않은 요청을 취소합니다.
func (s *Server) handleKernelPurge(w http.ResponseWriter, r *http.Request, who string) {
	kernel := r.PathValue("kernel")
	if !validKernel(kernel) {
		writeErr(w, fail(http.StatusBadRequest, "커널 이름이 잘못됐습니다: %q", kernel))
		return
	}
	var req struct {
		Cancel bool `json:"cancel"`
	}
	if r.ContentLength != 0 {
		if err := readJSON(r, &req); err != nil {
			writeErr(w, err)
			return
		}
	}
	err := s.store.Update(func(st *State) error {
		u := st.Upstream[kernel]
		if req.Cancel {
			if u != nil {
				u.PurgeRequestedAt, u.PurgeRequestedBy = time.Time{}, ""
			}
			return nil
		}
		if u == nil || u.Outside == "" {
			return fail(http.StatusConflict, "%s 은 빌드 서버의 최근 커널 범위 안이라 자료를 지울 수 없습니다", kernel)
		}
		u.PurgeRequestedAt, u.PurgeRequestedBy = time.Now(), who
		return nil
	})
	if err != nil {
		writeErr(w, err)
		return
	}
	if req.Cancel {
		s.audit(who, "빌드 서버 자료 삭제 요청 취소 kernel=%s", kernel)
		writeJSON(w, http.StatusOK, map[string]string{"result": "ok", "message": kernel + ": 빌드 서버 자료 삭제 요청을 취소했습니다."})
		return
	}
	s.audit(who, "빌드 서버 자료 삭제 요청 kernel=%s", kernel)
	writeJSON(w, http.StatusOK, map[string]string{"result": "ok",
		"message": kernel + ": 빌드 서버 자료 삭제를 요청했습니다. 빌드 서버가 다음 작업 확인 때 처리합니다."})
}

// unbuiltPatches 는 마지막 작업(대기·빌드중·승인대기·배포됨) 이후 추가된 활성 패치가 있는지 봅니다.
func unbuiltPatches(st *State, kernel string) bool {
	inJob := map[string]bool{}
	var last *model.Job
	for _, j := range st.Jobs {
		if j.Kernel == kernel && j.Status != model.JobFailed && j.Status != model.JobSuperseded && (last == nil || j.ID > last.ID) {
			last = j
		}
	}
	if last != nil {
		for _, p := range last.PatchIDs {
			inJob[p] = true
		}
	}
	for _, p := range st.activePatches(kernel) {
		if !inJob[p.ID] {
			return true
		}
	}
	return false
}

// POST /api/hosts/{id}/update-now — 이 호스트에만 지금 배포된 가장 새 패치를 바로 적용
// 링 순서(카나리 → 일반)를 건너뜁니다. 에이전트는 다음 보고(기본 1분 안)에 받아 적용합니다.
// 본문 {"cancel": true} 이면 취소하고 다시 링 목표를 따릅니다.
func (s *Server) handleHostUpdateNow(w http.ResponseWriter, r *http.Request, who string) {
	id := r.PathValue("id")
	var req model.UpdateNowRequest
	if r.ContentLength != 0 {
		if err := readJSON(r, &req); err != nil {
			writeErr(w, err)
			return
		}
	}
	var name, kernel, msg string
	var version int
	err := s.store.Update(func(st *State) error {
		h := st.Hosts[id]
		if h == nil {
			return fail(http.StatusNotFound, "호스트 %s 가 없습니다", id)
		}
		name, kernel = h.Hostname, h.Status.Kernel
		if req.Cancel {
			h.UpdateNowKernel, h.UpdateNowVersion = "", 0
			msg = name + ": 즉시 업데이트를 취소했습니다. 다시 링 목표를 따릅니다."
			return nil
		}
		if model.HWEWithGAName(h.Status) {
			return fail(http.StatusBadRequest, "%s 는 HWE 커널이라 패치를 줄 수 없습니다", name)
		}
		if req.Version < 0 {
			return fail(http.StatusBadRequest, "버전은 0 이상이어야 합니다")
		}
		if t := st.Tracks[kernel]; t != nil && t.PrereleaseRingVersions[h.Ring] != 0 {
			return fail(http.StatusConflict, "이 호스트는 출시 전 누적본 배포 중입니다. 정식 승인·링 승급 또는 명시적 롤백으로 전환하세요")
		}
		if req.Kernel != "" && req.Kernel != kernel {
			return fail(http.StatusConflict, "호스트 커널이 바뀌었습니다. 현재 커널 %s 를 다시 확인하세요", kernel)
		}
		j := st.latestReleased(kernel)
		if j == nil {
			return fail(http.StatusBadRequest, "%s 커널(%s)에 배포된 패치가 아직 없습니다. 빌드를 승인하면 생깁니다", name, kernel)
		}
		version = j.Version
		if req.Version > 0 && req.Version != version {
			return fail(http.StatusConflict, "최신 승인 버전이 v%d 로 바뀌었습니다. 누적본을 다시 확인하세요", version)
		}
		if version < h.Status.Version {
			return fail(http.StatusConflict, "현재 v%d 보다 낮은 버전으로는 업데이트할 수 없습니다. 롤백 기능을 사용하세요", h.Status.Version)
		}
		ringV := 0
		if t := st.Tracks[kernel]; t != nil {
			ringV = t.RingVersions[h.Ring]
		}
		if ringV >= version {
			h.UpdateNowKernel, h.UpdateNowVersion = "", 0
			msg = fmt.Sprintf("%s: 링 %d 목표가 이미 최신(v%d)입니다. 다음 보고 때 적용됩니다.", name, h.Ring, version)
			return nil
		}
		h.UpdateNowKernel, h.UpdateNowVersion = kernel, version
		msg = fmt.Sprintf("%s: v%d → 최신 누적 v%d 를 중간 버전 설치 없이 바로 적용합니다 (링 %d 목표 v%d 보다 앞섬). 에이전트 다음 보고 때 적용됩니다.", name, h.Status.Version, version, h.Ring, ringV)
		return nil
	})
	if err != nil {
		writeErr(w, err)
		return
	}
	if req.Cancel {
		s.audit(who, "호스트 %s(%s) 즉시 업데이트 취소", name, id)
	} else {
		s.audit(who, "호스트 %s(%s) 즉시 업데이트 kernel=%s → v%d", name, id, kernel, version)
	}
	writeJSON(w, http.StatusOK, map[string]any{"result": "ok", "message": msg, "version": version})
}

// DELETE /api/hosts/{id} — 호스트 등록 삭제 (서버 폐기 시)
func (s *Server) handleHostDelete(w http.ResponseWriter, r *http.Request, who string) {
	id := r.PathValue("id")
	var name string
	err := s.store.Update(func(st *State) error {
		h := st.Hosts[id]
		if h == nil {
			return fail(http.StatusNotFound, "호스트 %s 가 없습니다", id)
		}
		name = h.Hostname
		delete(st.Hosts, id)
		return nil
	})
	if err != nil {
		writeErr(w, err)
		return
	}
	s.audit(who, "호스트 삭제 %s(%s)", name, id)
	writeJSON(w, http.StatusOK, map[string]string{"result": "ok"})
}

// POST /api/hosts/{id}/cordon — 신규 VM 배치 차단/해제 (스케줄러 명령 실행)
func (s *Server) handleHostCordon(w http.ResponseWriter, r *http.Request, who string) {
	s.rebootMu.Lock()
	defer s.rebootMu.Unlock()
	id := r.PathValue("id")
	var req model.CordonRequest
	if err := readJSON(r, &req); err != nil {
		writeErr(w, err)
		return
	}
	var hostname string
	var dispatched bool
	s.store.View(func(st *State) {
		if h := st.Hosts[id]; h != nil {
			hostname = h.Hostname
			dispatched = h.RebootApproval != nil && h.RebootApproval.DispatchedAt != nil
		}
	})
	if hostname == "" {
		writeErr(w, fail(http.StatusNotFound, "호스트 %s 가 없습니다", id))
		return
	}

	if !req.On && dispatched {
		writeErr(w, fail(http.StatusConflict, "재부팅 실행 전달 후에는 부팅 결과를 먼저 확인하세요"))
		return
	}
	cmd := s.cfg.Scheduler.UncordonCommand
	if req.On {
		cmd = s.cfg.Scheduler.CordonCommand
	}
	if len(cmd) > 0 {
		if out, err := runCommand(cmd, map[string]string{"host": hostname}, time.Minute); err != nil {
			writeErr(w, fail(http.StatusBadGateway, "스케줄러 명령 실패: %v\n%s", err, out))
			return
		}
	}

	err := s.store.Update(func(st *State) error {
		h := st.Hosts[id]
		if h == nil {
			return fail(http.StatusNotFound, "호스트 %s 가 없습니다", id)
		}
		if !req.On && h.RebootApproval != nil && h.RebootApproval.DispatchedAt != nil {
			return fail(http.StatusConflict, "재부팅 실행을 전달한 상태입니다. 실제 부팅 결과 확인 후 uncordon 하세요")
		}
		h.Cordoned = req.On
		h.VMCount = -1 // 드레인 검사가 다시 셀 때까지 모름
		if len(s.cfg.Scheduler.VMCountCommand) == 0 {
			if h.Status.LocalVMCount != nil {
				h.VMCount = *h.Status.LocalVMCount
				h.VMCountCheckedAt = h.LastSeen
			}
		}
		if !req.On {
			finishReboot(h, "cancelled", "관리자가 cordon을 해제했습니다")
		}
		return nil
	})
	if err != nil {
		writeErr(w, err)
		return
	}
	s.background.Add(1)
	go func() { // VM 수를 바로 한 번 확인
		defer s.background.Done()
		s.checkDrain()
	}()
	s.audit(who, "호스트 %s(%s) cordon=%v", hostname, id, req.On)
	writeJSON(w, http.StatusOK, map[string]string{"result": "ok"})
}

// ── 작은 도우미 ──

func leftPad(n int) string {
	s := strconv.Itoa(n)
	for len(s) < 4 {
		s = "0" + s
	}
	return s
}

func deref(p *int) any {
	if p == nil {
		return "-"
	}
	return *p
}

func derefS(p *string) string {
	if p == nil {
		return "-"
	}
	return *p
}
