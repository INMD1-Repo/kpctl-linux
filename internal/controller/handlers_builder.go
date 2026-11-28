// 이 파일: 빌더 작업·결과·정식/출시 전 수집 API.
package controller

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"kpctl/internal/buildlog"
	"kpctl/internal/klpcheck"
	"kpctl/internal/model"
)

// 이 파일: 빌드 서버가 부르는 API

// POST /api/builder/next — 빌드할 작업 하나를 가져감 (없으면 204)
func (s *Server) handleBuilderNext(w http.ResponseWriter, r *http.Request) {
	var req model.NextJobRequest
	if err := readJSON(r, &req); err != nil {
		writeErr(w, err)
		return
	}

	if reason := model.KernelBuildBlock(req.NativeTrack); reason != "" {
		writeErr(w, fail(http.StatusConflict, "%s", reason))
		return
	}

	var task *model.BuildTask
	err := s.store.Update(func(st *State) error {
		if req.Builder != "" {
			s.recordBuilder(st, req, r.RemoteAddr).LastPolledAt = time.Now()
		}
		// 너무 오래 걸리는 빌드는 빌드 서버가 죽은 것으로 보고 다시 대기열로
		timeout := time.Duration(s.settings().JobTimeoutMinutes) * time.Minute
		for _, j := range st.Jobs {
			last := j.StartedAt
			if j.HeartbeatAt.After(last) {
				last = j.HeartbeatAt
			}
			if j.Status == model.JobRunning && time.Since(last) > timeout {
				j.Status = model.JobQueued
				j.Error = fmt.Sprintf("%s 에서 %s 넘게 응답이 없어 다시 대기열로", j.Builder, timeout)
			}
		}

		j := nextQueuedJob(st, req)
		if j == nil {
			if req.CanCollectReviewed {
				if k, ok := model.DistributionTrack(req.NativeTrack); ok {
					candidates, err := s.reviewedCandidates(st, k)
					if err != nil {
						return err
					}
					if len(candidates) > 0 {
						task = &model.BuildTask{ReviewedCandidates: candidates}
						return nil
					}
				}
			}
			if req.CanAutoDiscover && s.settings().NativeAutoPin {
				if k, ok := model.DistributionTrack(req.NativeTrack); ok && k.BuildBlock() == "" {
					if _, hasBase := s.hasValidBaseProof(req.NativeTrack); hasBase {
						u := st.upstream(req.NativeTrack)
						if u.CheckedAt.IsZero() || time.Since(u.CheckedAt) >= 30*time.Minute || !u.RefreshRequestedAt.IsZero() {
							now := time.Now()
							u.CheckedAt = now
							if !u.RefreshRequestedAt.IsZero() {
								u.RefreshRequestedAt, u.RefreshTakenBy, u.RefreshTakenAt = time.Time{}, req.Builder, now
							}
							task = &model.BuildTask{AutoDiscover: true}
							return nil
						}
					}
				}
			}
			// 빌드할 작업이 없으면, 관리자가 바로 수집을 요청한 커널을 넘김
			var refresh []string
			for kernel, u := range st.Upstream {
				if req.CanRefresh && !u.RefreshRequestedAt.IsZero() && builderCanBuild(req, kernel) {
					refresh = append(refresh, kernel)
					u.RefreshRequestedAt, u.RefreshTakenBy, u.RefreshTakenAt = time.Time{}, req.Builder, time.Now()
				}
			}
			// 범위 밖 커널의 빌드 서버 자료 삭제 요청
			var purge []string
			for kernel, u := range st.Upstream {
				if req.CanPurge && !u.PurgeRequestedAt.IsZero() && builderCanBuild(req, kernel) {
					purge = append(purge, kernel)
					u.PurgeRequestedAt, u.PurgeTakenBy = time.Time{}, req.Builder
				}
			}
			if len(refresh) > 0 || len(purge) > 0 {
				sort.Strings(refresh)
				sort.Strings(purge)
				task = &model.BuildTask{Refresh: refresh, Purge: purge}
			}
			return nil
		}

		// 패치 본문을 순서대로 모음
		t := &model.BuildTask{KernelInfo: buildKernelInfo(st, j.Kernel)}
		for _, pid := range j.PatchIDs {
			content, err := os.ReadFile(s.patchFile(pid))
			if err != nil {
				return fmt.Errorf("패치 파일 %s 읽기 실패: %w", pid, err)
			}
			if _, native := model.DistributionTrack(j.Kernel); native {
				if _, err := verifiedCandidatePaths(st.patch(pid), content); err != nil {
					return fail(409, "%v", err)
				}
			}
			patch := model.NewTaskPatch(pid, content)
			if err := patch.Validate(); err != nil {
				return err
			}
			t.Patches = append(t.Patches, patch)
		}

		if err := os.Remove(s.liveLogFile(j.ID)); err != nil && !os.IsNotExist(err) {
			return err
		}
		j.Status = model.JobRunning
		j.Builder = req.Builder
		j.StartedAt = time.Now()
		j.HeartbeatAt = j.StartedAt
		j.Error = ""
		t.Job = *j
		task = t
		return nil
	})
	if err != nil {
		writeErr(w, err)
		return
	}
	if task == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	writeJSON(w, http.StatusOK, task)
}

// 같은 ABI를 보고한 GA 호스트 중 가장 최근의 유효한 보고를 작업에 고정합니다.
// 서명이 없는 예전 에이전트·HWE 호스트는 기존 빌더의 입력 선택을 유지합니다.
func buildKernelInfo(st *State, kernel string) *model.BuildKernelInfo {
	var selected *model.Host
	var info *model.BuildKernelInfo
	for _, h := range st.Hosts {
		if h.Status.Kernel != kernel {
			continue
		}
		version := model.SignatureVersion(h.Status.KernelSignature)
		candidate := &model.BuildKernelInfo{
			Kernel: kernel, Signature: h.Status.KernelSignature,
			PackageVersion: version, BaseTag: "Ubuntu-" + version,
		}
		if candidate.Validate(kernel) != nil {
			continue
		}
		if selected == nil || h.LastSeen.After(selected.LastSeen) || h.LastSeen.Equal(selected.LastSeen) && h.ID < selected.ID {
			selected, info = h, candidate
		}
	}
	return info
}

var errBuildResultIgnored = errors.New("빌드 결과 무시")

// POST /api/builder/jobs/{id}/result — 빌드 결과 업로드
func (s *Server) handleBuilderResult(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		writeErr(w, fail(http.StatusBadRequest, "작업 번호가 잘못됐습니다"))
		return
	}
	var res model.BuildResult
	if err := readJSON(r, &res); err != nil {
		writeErr(w, err)
		return
	}

	if res.Deferred && (res.Success || res.ModuleName != "" || res.ModuleBase64 != "") {
		writeErr(w, fail(http.StatusBadRequest, "빌드 대기 응답에는 결과 모듈을 넣을 수 없습니다"))
		return
	}

	var kernel, ignoredReason string
	err = s.store.UpdateAtomic(func(st *State) error {
		j := st.job(id)
		if j == nil {
			return fail(http.StatusNotFound, "작업 %d 이 없습니다", id)
		}
		if j.Status != model.JobRunning {
			ignoredReason = "작업 상태가 " + j.Status
			return errBuildResultIgnored
		}
		if res.Builder == "" || res.JobStartedAt == nil || res.JobStartedAt.IsZero() {
			return fail(http.StatusBadRequest, "빌드 결과에는 배정받은 빌더·시작 시각이 필요합니다")
		}
		if j.Builder != res.Builder || !j.StartedAt.Equal(*res.JobStartedAt) {
			ignoredReason = "현재 빌드 시도가 아님"
			return errBuildResultIgnored
		}
		kernel = j.Kernel

		// 재배정과 로그 갱신도 같은 잠금을 사용합니다. 현재 시도만 파일을 바꿀 수 있습니다.
		_ = saveLiveLog(s.logFile(id), res.Log)
		_ = os.Remove(s.liveLogFile(id))
		if res.Deferred {
			j.Status = model.JobQueued
			j.StartedAt, j.HeartbeatAt, j.FinishedAt = time.Time{}, time.Time{}, time.Time{}
			j.Builder, j.Error = "", ""
			return nil
		}

		j.FinishedAt = time.Now()
		if reason := model.KernelBuildBlock(kernel); res.Success && reason != "" {
			res.Success = false
			res.Error = reason
		}
		if res.Success && strings.HasPrefix(kernel, "native__") && (!res.DistributionProof.Valid(kernel) || res.ModuleName != model.NativeModuleName(kernel, j.Version)) {
			res.Success = false
			res.Error = "공식 배포판 서명 패키지·Git revision·대상 모듈 일치 증거 필요"
		}
		if res.Success {
			checksum, moduleErr := s.saveArtifact(kernel, res.ModuleName, res.ModuleBase64)
			if moduleErr == nil {
				j.Status = model.JobBuilt
				j.ModuleName = res.ModuleName
				j.UnsignedSHA256 = checksum
				j.DistributionProof = res.DistributionProof
				return nil
			}
			res.Success = false
			res.Error = moduleErr.Error()
		}
		j.Status = model.JobFailed
		j.Error = res.Error
		// 누적 빌드 실패만으로 어느 패치가 원인인지 확정할 수 없습니다.
		// 패치는 보존하고, 관리자가 로그를 검토할 때까지 해당 커널의 자동 배포를 멈춥니다.
		if t := st.track(j.Kernel); t.AutoHold == "" || t.AutoHoldKind == holdBuild {
			setAutoHold(t, fmt.Sprintf("job %d 누적 빌드 실패 — 패치 보존, 로그 검토 필요", j.ID), holdBuild, strconv.Itoa(j.ID))
		}
		return nil
	})
	if errors.Is(err, errBuildResultIgnored) {
		writeJSON(w, http.StatusOK, map[string]string{"result": "ignored", "reason": ignoredReason})
		return
	}
	if err != nil {
		writeErr(w, err)
		return
	}
	if res.Deferred {
		s.audit("builder", "빌드 대기 job %d kernel=%s · 빌드 자원 확보 후 재시도", id, kernel)
		writeJSON(w, http.StatusOK, map[string]string{"result": "deferred"})
		return
	}
	if res.Success {
		s.audit("builder", "빌드 성공 job %d kernel=%s module=%s — 승인 대기", id, kernel, res.ModuleName)
	} else {
		s.audit("builder", "빌드 실패 job %d kernel=%s: %s", id, kernel, firstLine(res.Error))
	}
	writeJSON(w, http.StatusOK, map[string]string{"result": "ok"})
}

func (s *Server) saveArtifact(kernel, module, b64 string) (string, error) {
	if !validModule(module) {
		return "", fmt.Errorf("모듈 이름이 잘못됐습니다: %q", module)
	}
	data, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", fmt.Errorf("모듈 저장 실패: %w", err)
	}
	if len(data) == 0 {
		return "", fmt.Errorf("모듈 저장 실패: 모듈 파일이 비어 있습니다")
	}
	path := s.artifactFile(kernel, module)
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return "", fmt.Errorf("모듈 저장 실패: %w", err)
	}
	tmp := path + ".tmp"
	defer os.Remove(tmp)
	if err := os.WriteFile(tmp, data, 0o640); err != nil {
		return "", fmt.Errorf("모듈 저장 실패: %w", err)
	}
	checksum, err := fileSHA256(tmp)
	if err != nil {
		return "", fmt.Errorf("서명 전 모듈 SHA256 확인 실패: %w", err)
	}
	if k, ok := model.DistributionTrack(kernel); ok {
		if err := klpcheck.CheckTarget(tmp, k.ABI, module); err != nil {
			return "", err
		}
	}
	if err := os.Rename(tmp, path); err != nil {
		return "", fmt.Errorf("모듈 저장 실패: %w", err)
	}
	return checksum, nil
}

// GET /api/builder/kernels — 등록된 호스트들이 지금 쓰는 커널 목록
// 빌드 서버가 설정에 kernels 를 적지 않았으면 이 목록에서 자기 시리즈의 커널을 골라 자동 수집합니다.
func (s *Server) handleHostKernels(w http.ResponseWriter, r *http.Request) {
	var body []byte
	s.store.View(func(st *State) {
		body = mustJSON(model.HostKernelsResponse{Kernels: st.hostKernels()})
	})
	writeRaw(w, http.StatusOK, body)
}

// GET /api/builder/kernels/{kernel}/known — 이미 처리한 Ubuntu 커밋 목록
func (s *Server) handleKnownCommits(w http.ResponseWriter, r *http.Request) {
	kernel := r.PathValue("kernel")
	var body []byte
	var readErr error
	s.store.View(func(st *State) {
		resp := model.KnownCommitsResponse{Commits: st.knownCommits(kernel)}
		active := st.activePatches(kernel)
		if r.URL.Query().Get("prerelease") == "true" {
			resp.Commits = st.knownPrereleaseCommits(kernel)
			active = st.activePrereleasePatches(kernel)
		}
		for _, p := range active {
			content, err := os.ReadFile(s.patchFile(p.ID))
			if err != nil {
				readErr = fmt.Errorf("선행 패치 %s 읽기 실패: %w", p.ID, err)
				return
			}
			resp.ActivePatches = append(resp.ActivePatches, model.DiscoveredPatch{CandidateID: p.CandidateID, ParentCandidate: p.ParentCandidate, FixedRelease: p.FixedRelease, Commit: p.Commit, CVEs: p.CVEs, Title: p.Title, Content: string(content)})
		}
		body = mustJSON(resp)
	})
	if readErr != nil {
		writeErr(w, readErr)
		return
	}
	writeRaw(w, http.StatusOK, body)
}

// POST /api/builder/kernels/{kernel}/upstream — 빌드 서버가 확인한 Ubuntu 최신 태그와 수집 기준 태그
func (s *Server) handleUpstream(w http.ResponseWriter, r *http.Request) {
	kernel := r.PathValue("kernel")
	if _, native := model.DistributionTrack(kernel); native {
		writeErr(w, fail(http.StatusBadRequest, "배포판 패키징 변경에는 공식 서명 패키지의 fixed_release 증거가 필요합니다"))
		return
	}
	if !validKernel(kernel) {
		writeErr(w, fail(http.StatusBadRequest, "커널 이름이 잘못됐습니다: %q", kernel))
		return
	}
	var req model.UpstreamReport
	if err := readJSON(r, &req); err != nil {
		writeErr(w, err)
		return
	}
	if req.Problem != nil && len(*req.Problem) > 1000 {
		writeErr(w, fail(http.StatusBadRequest, "problem 이 너무 깁니다"))
		return
	}
	if len(req.ProblemKind) > 64 {
		writeErr(w, fail(http.StatusBadRequest, "problem_kind 가 너무 깁니다"))
		return
	}
	if f := req.ProblemFailure; f != nil {
		if req.Problem == nil || *req.Problem == "" || !commitSHA.MatchString(f.Commit) || len(f.Title) > 1000 || len(f.CVEs) > 100 ||
			len(f.Input.Profile) > 1024 || len(f.Input.Image) > 128 || f.Input.BaseTag != "" && !validTag(f.Input.BaseTag) ||
			(f.Input.BuildTool != "kpatch" && f.Input.BuildTool != "klp") {
			writeErr(w, fail(http.StatusBadRequest, "시험 실패 입력이 잘못됐습니다"))
			return
		}
		f.CVEs = normalizeCVEs(f.CVEs)
	}
	if req.Outside != nil && len(*req.Outside) > 1000 || req.Purged != nil && len(*req.Purged) > 4000 {
		writeErr(w, fail(http.StatusBadRequest, "outside·purged 가 너무 깁니다"))
		return
	}
	for _, t := range []string{req.LatestTag, req.CollectedTag} {
		if t != "" && !validTag(t) {
			writeErr(w, fail(http.StatusBadRequest, "태그 이름이 잘못됐습니다: %q", t))
			return
		}
	}
	err := s.store.Update(func(st *State) error {
		u := st.upstream(kernel)
		u.CheckedAt = time.Now()
		if req.LatestTag != "" {
			u.LatestTag = req.LatestTag
		}
		if req.Outside != nil {
			u.Outside = *req.Outside
		}
		if req.Problem != nil {
			// 종류가 있는 해제는 같은 종류만 지웁니다. 태그 경고는 기존 빌드 문제를 덮지 않습니다.
			clearOther := *req.Problem == "" && req.ProblemKind != "" && req.ProblemKind != u.ProblemKind
			tagOverOther := *req.Problem != "" && req.ProblemKind == "tag_fetch" && u.Problem != "" && u.ProblemKind != "tag_fetch"
			excluded := req.ProblemFailure != nil && st.excludedCommit(kernel, req.ProblemFailure.Commit) != nil
			if !clearOther && !tagOverOther && !excluded {
				if *req.Problem == "" {
					if u.Problem != "" {
						u.ProblemResolvedRef, u.ProblemResolution = "", ""
						if req.Recovered && u.Outside == "" && !u.ProblemAt.IsZero() {
							u.ProblemResolvedRef = u.ProblemAt.UTC().Format(time.RFC3339Nano)
						}
					}
					u.Problem, u.ProblemKind, u.ProblemFailure = "", "", nil
				} else if *req.Problem != u.Problem || req.ProblemKind != u.ProblemKind || !reflect.DeepEqual(req.ProblemFailure, u.ProblemFailure) {
					if u.Problem == "" || req.ProblemKind != u.ProblemKind || !reflect.DeepEqual(req.ProblemFailure, u.ProblemFailure) {
						u.ProblemAt = time.Now()
					}
					u.Problem, u.ProblemKind = *req.Problem, req.ProblemKind
					u.ProblemFailure = req.ProblemFailure
					u.ProblemResolvedRef, u.ProblemResolution = "", ""
				}
			}
		}
		if req.Purged != nil {
			u.PurgedAt, u.PurgeResult = time.Now(), *req.Purged
		}
		// 예전 빌드 서버가 미확인 "불가" 보고 뒤 수집 완료 태그를 보내도 진행시키지 않습니다.
		if req.CollectedTag != "" && u.Problem == "" {
			u.CollectedTag = req.CollectedTag
		}
		if req.Problem != nil && *req.Problem != "" && u.Problem != "" {
			upstreamHold(st.track(kernel), u)
		}
		return nil
	})
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"result": "ok"})
}

// validTag 는 Ubuntu 커널 태그 모양인지 봅니다. 예: Ubuntu-6.8.0-90.90
func validTag(t string) bool {
	if len(t) > 100 || !strings.HasPrefix(t, "Ubuntu-") {
		return false
	}
	for _, c := range t {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '.' || c == '-' || c == '_' || c == '~' || c == '+') {
			return false
		}
	}
	return true
}

// POST /api/builder/kernels/{kernel}/discovered — 빌드 서버가 Ubuntu git 에서 찾은 CVE 패치 등록
// 새 패치가 하나라도 있으면 누적 빌드 작업을 자동으로 만듭니다.
func (s *Server) handleDiscovered(w http.ResponseWriter, r *http.Request) {
	kernel := r.PathValue("kernel")
	if !validKernel(kernel) {
		writeErr(w, fail(http.StatusBadRequest, "커널 이름이 잘못됐습니다: %q", kernel))
		return
	}
	if reason := model.KernelBuildBlock(kernel); reason != "" {
		writeErr(w, fail(http.StatusConflict, "%s", reason))
		return
	}
	var req model.DiscoveredRequest
	if err := readJSON(r, &req); err != nil {
		writeErr(w, err)
		return
	}

	var resp model.DiscoveredResponse
	var ignoredReview int
	update := s.store.Update
	_, native := model.DistributionTrack(kernel)
	if native {
		update = s.store.UpdateAtomic
	}
	err := update(func(st *State) error {
		known := map[string]bool{}
		commits := st.knownCommits(kernel)
		if req.Prerelease {
			commits = st.knownPrereleaseCommits(kernel)
		}
		for _, c := range commits {
			known[c] = true
		}
		now := time.Now()

		latest := map[string]string{}
		var activeIDs []string
		if native {
			if len(req.Patches) != 1 || len(req.Unpatchable) != 0 {
				return fail(400, "submit one reviewed native candidate")
			}
			for _, p := range st.activePatches(kernel) {
				activeIDs = append(activeIDs, p.CandidateID)
				body, err := os.ReadFile(s.patchFile(p.ID))
				if err != nil {
					return err
				}
				paths, err := verifiedCandidatePaths(p, body)
				if err != nil {
					return fail(409, "%v", err)
				}
				for _, path := range paths {
					latest[path] = p.CandidateID
				}
			}
		}
		for _, dp := range req.Patches {
			if dp.Commit == "" || !looksLikePatch(dp.Content) {
				if native {
					return fail(400, "invalid native candidate")
				}
				continue
			}
			source := "ubuntu"
			identity := dp.Commit
			candidateID := ""
			if k, ok := model.DistributionTrack(kernel); ok {
				if req.Prerelease || !dp.FixedRelease.ValidFor(k, dp.Commit) {
					return fail(http.StatusBadRequest, "공식 수정 릴리스의 버전·Git·서명 증거가 필요합니다")
				}
				source = k.Distro
				candidateID = fmt.Sprintf("%s/%x", dp.Commit, sha256.Sum256([]byte(dp.Content)))
				identity = candidateID
			}
			var paths []string
			if known[identity] || known[dp.Commit] {
				continue
			}
			if native {
				if req.ExpectedActive == nil || !slices.Equal(req.ExpectedActive, activeIDs) {
					return fail(409, "active candidates changed; repeat collect")
				}
				var err error
				paths, err = candidatePaths([]byte(dp.Content))
				if err != nil {
					return fail(400, "%v", err)
				}
				if err = checkParent(latest, paths, dp.ParentCandidate); err != nil {
					return fail(409, "%v", err)
				}
				if req.AutoPin {
					if !s.settings().NativeAutoPin {
						return fail(http.StatusForbidden, "네이티브 자동 승인 핀 등록이 비활성화되어 있습니다")
					}
					if req.ReviewedBase == nil {
						return fail(http.StatusBadRequest, "자동 승인 핀 등록에는 기준 영수증(reviewed_base)이 필요합니다")
					}
					_, sum, _ := strings.Cut(candidateID, "/")
					if err := s.installAutoCandidatePins(*req.ReviewedBase, *dp.FixedRelease, paths, normalizeCVEs(dp.CVEs), dp.ParentCandidate, dp.Title, sum); err != nil {
						return err
					}
				}
				if req.ReviewedBase != nil {
					k, _ := model.DistributionTrack(kernel)
					pending, err := s.reviewedCandidates(st, k)
					if err != nil {
						return err
					}
					if !slices.ContainsFunc(pending, func(item model.ReviewedCandidate) bool {
						p := item.Pin
						return p.CandidateID == candidateID && p.Base == *req.ReviewedBase && p.Fixed == *dp.FixedRelease &&
							p.Parent == dp.ParentCandidate && slices.Equal(p.Paths, paths) && slices.Equal(p.CVEs, dp.CVEs) &&
							(p.Title == "" || p.Title == dp.Title)
					}) {
						return fail(409, "candidate review changed during trial: %s", candidateID)
					}
				}
			}
			id := "p" + leftPad(st.NextPatchID+1)
			if err := os.WriteFile(s.patchFile(id), []byte(dp.Content), 0o640); err != nil {
				return err
			}
			st.NextPatchID++
			st.Patches = append(st.Patches, &model.Patch{
				ID: id, Paths: paths, ParentCandidate: dp.ParentCandidate, Kernel: kernel, Source: source, Commit: dp.Commit, CandidateID: candidateID, FixedRelease: dp.FixedRelease,
				Prerelease: req.Prerelease,
				CVEs:       normalizeCVEs(dp.CVEs), Title: dp.Title, State: model.PatchActive,
				AddedBy: "builder", AddedAt: now,
			})
			known[identity] = true
			resp.AddedPatches++
		}

		for _, u := range req.Unpatchable {
			if u.Commit == "" || known[u.Commit] {
				continue
			}
			// 예전 빌더의 명시적 도구 제약도 새 영구 판정으로 받지 않습니다.
			ignoredReview++
		}

		if ignoredReview > 0 {
			u := st.upstream(kernel)
			u.Problem = fmt.Sprintf("시험 빌드 %d건의 실패 원인 검토 필요 — 라이브패치 불가로 확정하지 않았습니다", ignoredReview)
			u.ProblemAt = now
			u.ProblemKind, u.ProblemResolvedRef = "", ""
			u.ProblemFailure, u.ProblemResolution = nil, ""
			upstreamHold(st.track(kernel), u)
		}
		if !strings.HasPrefix(kernel, "native__") && !req.Prerelease && ignoredReview == 0 && req.LatestTag != "" && validTag(req.LatestTag) {
			st.upstream(kernel).CollectedTag = req.LatestTag
		}
		if resp.AddedPatches > 0 {
			job, err := s.createJobChannel(st, kernel, "builder", false, req.Prerelease)
			if err != nil {
				return err
			}
			resp.JobID = job.ID
		}
		return nil
	})
	if err != nil {
		writeErr(w, err)
		return
	}
	if ignoredReview > 0 {
		s.audit("builder", "패키징 Git 수집 kernel=%s: 원인 검토가 필요한 시험 빌드 %d건은 '불가'로 기록하지 않음", kernel, ignoredReview)
	}
	if resp.AddedPatches > 0 {
		s.audit("builder", "패키징 Git 수집 kernel=%s: 패치 %d건 추가, 라이브패치 불가 %d건, job %d",
			kernel, resp.AddedPatches, 0, resp.JobID)
	}
	writeJSON(w, http.StatusOK, resp)
}

// reviewUnpatchable 은 근거가 없는 과거 "불가" 판정을 원본 로그와 함께 보관하고
// 다시 시험할 수 있게 합니다. 자동 배포는 관리자가 검토할 때까지 멈춥니다.
// 시작할 때만 호출하며, 기록을 보관하지 못하면 상태를 바꾸지 않습니다.
func (s *Server) reviewUnpatchable() error {
	var review []*model.Unpatchable
	s.store.View(func(st *State) {
		for _, u := range st.Unpatchable {
			if u.Decision == nil && !buildlog.Unpatchable(u.Reason) {
				review = append(review, u)
			}
		}
	})
	if len(review) == 0 {
		return nil
	}
	f, err := os.CreateTemp(s.cfg.DataDir, "unpatchable-review-*.json")
	if err != nil {
		return err
	}
	encodeErr := json.NewEncoder(f).Encode(review)
	syncErr := f.Sync()
	closeErr := f.Close()
	if encodeErr != nil || syncErr != nil || closeErr != nil {
		_ = os.Remove(f.Name())
		return fmt.Errorf("기존 판정 기록 보관 실패: 인코딩=%v 동기화=%v 닫기=%v", encodeErr, syncErr, closeErr)
	}
	dir, err := os.Open(s.cfg.DataDir)
	if err != nil {
		return err
	}
	err = dir.Sync()
	_ = dir.Close()
	if err != nil {
		return fmt.Errorf("기존 판정 보관 디렉터리 동기화 실패: %w", err)
	}
	removed := map[string]int{}
	err = s.store.Update(func(st *State) error {
		var kept []*model.Unpatchable
		for _, u := range st.Unpatchable {
			if u.Decision == nil && !buildlog.Unpatchable(u.Reason) {
				removed[u.Kernel]++
				continue
			}
			kept = append(kept, u)
		}
		st.Unpatchable = kept
		for kernel, count := range removed {
			problem := fmt.Sprintf("과거 시험 빌드 %d건의 불가 판정 재검토 필요 (기록: %s)", count, filepath.Base(f.Name()))
			u := st.upstream(kernel)
			u.Problem, u.ProblemAt, u.CollectedTag = problem, time.Now(), ""
			u.ProblemKind, u.ProblemResolvedRef = "", ""
			u.ProblemFailure, u.ProblemResolution = nil, ""
			upstreamHold(st.track(kernel), u)
		}
		return nil
	})
	if err != nil {
		return err
	}
	for k, n := range removed {
		s.audit("controller", "미확인 '라이브패치 불가' %d건을 재검토로 전환 kernel=%s 기록=%s (재시험 가능, 자동 배포 멈춤)", n, k, f.Name())
	}
	return nil
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
