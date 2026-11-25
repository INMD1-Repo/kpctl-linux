// 이 파일: controller 패키지의 handleExcludeCommit, handleCancelExcludeCommit 구현·자료형.
package controller

import (
	"net/http"
	"regexp"
	"strings"
	"time"

	"kpctl/internal/model"
)

var commitSHA = regexp.MustCompile(`^[0-9a-f]{40}$`)

// 관리자 결정은 현재 보고된 실패만 대상으로 합니다. 클라이언트가 CVE나 입력을 정하지 않습니다.
func (s *Server) handleExcludeCommit(w http.ResponseWriter, r *http.Request, who string) {
	kernel, commit := r.PathValue("kernel"), r.PathValue("commit")
	if !validKernel(kernel) || !commitSHA.MatchString(commit) {
		writeErr(w, fail(http.StatusBadRequest, "커널·커밋이 잘못됐습니다"))
		return
	}
	var req model.ExcludeCommitRequest
	if err := readJSON(r, &req); err != nil {
		writeErr(w, err)
		return
	}
	req.Reason = strings.TrimSpace(req.Reason)
	if req.Reason == "" || len(req.Reason) > 1000 || len(req.ProblemRef) > 64 {
		writeErr(w, fail(http.StatusBadRequest, "제외 사유는 1~1000바이트로 입력하세요"))
		return
	}
	reportedAt, parseErr := time.Parse(time.RFC3339Nano, req.ProblemRef)
	err := s.store.Update(func(st *State) error {
		u := st.Upstream[kernel]
		if u == nil || u.Problem == "" || u.ProblemKind == model.FailureBusy || u.ProblemFailure == nil || u.ProblemFailure.Commit != commit ||
			parseErr != nil || u.ProblemAt.IsZero() || !reportedAt.Equal(u.ProblemAt) {
			return fail(http.StatusConflict, "수집 문제가 바뀌었습니다. 새로 확인하세요")
		}
		for _, known := range st.knownCommits(kernel) {
			if known == commit {
				return fail(http.StatusConflict, "이미 처리한 커밋입니다")
			}
		}
		f := u.ProblemFailure
		now := time.Now()
		st.Unpatchable = append(st.Unpatchable, &model.Unpatchable{
			Kernel: kernel, Commit: commit, CVEs: append([]string(nil), f.CVEs...), Title: f.Title,
			Reason: req.Reason, FoundAt: now, Decision: &model.CommitDecision{By: who, At: now, Input: f.Input},
		})
		u.ProblemResolvedRef, u.ProblemResolution = u.ProblemAt.UTC().Format(time.RFC3339Nano), "admin_exclusion"
		u.Problem, u.ProblemKind, u.ProblemFailure = "", "", nil
		u.RefreshRequestedAt, u.RefreshRequestedBy = now, who
		return nil
	})
	if err != nil {
		writeErr(w, err)
		return
	}
	s.audit(who, "관리자 커밋 제외 kernel=%s commit=%s 사유=%q (미해결 유지, 자동 배포 재개 안 함)", kernel, commit, req.Reason)
	s.markResolvedHolds()
	writeJSON(w, http.StatusOK, map[string]string{"result": "ok"})
}

func (s *Server) handleCancelExcludeCommit(w http.ResponseWriter, r *http.Request, who string) {
	kernel, commit := r.PathValue("kernel"), r.PathValue("commit")
	if !validKernel(kernel) || !commitSHA.MatchString(commit) {
		writeErr(w, fail(http.StatusBadRequest, "커널·커밋이 잘못됐습니다"))
		return
	}
	err := s.store.Update(func(st *State) error {
		d := st.excludedCommit(kernel, commit)
		if d == nil {
			return fail(http.StatusNotFound, "관리자 제외 결정을 찾을 수 없습니다")
		}
		for i, u := range st.Unpatchable {
			if u == d {
				st.Unpatchable = append(st.Unpatchable[:i], st.Unpatchable[i+1:]...)
				break
			}
		}
		u := st.upstream(kernel)
		u.CollectedTag = "" // 태그가 같아도 다음 수집에서 다시 시험합니다.
		u.RefreshRequestedAt, u.RefreshRequestedBy = time.Now(), who
		// 다른 커밋·환경 문제를 덮지 않습니다.
		if u.Problem == "" {
			u.Problem, u.ProblemKind, u.ProblemAt = "관리자 제외 취소 · 해당 커밋 재시험 대기", model.FailureUnknown, time.Now()
			u.ProblemFailure = &model.TrialFailure{Commit: commit, CVEs: append([]string(nil), d.CVEs...), Title: d.Title, Input: d.Decision.Input}
			u.ProblemResolvedRef, u.ProblemResolution = "", ""
			upstreamHold(st.track(kernel), u)
		}
		return nil
	})
	if err != nil {
		writeErr(w, err)
		return
	}
	s.audit(who, "관리자 커밋 제외 취소 kernel=%s commit=%s (다음 수집에서 재시험)", kernel, commit)
	writeJSON(w, http.StatusOK, map[string]string{"result": "ok"})
}
