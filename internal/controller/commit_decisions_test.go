// 이 파일: controller 패키지의 TestCommitDecisionPersistsAndIsNotRecovery, TestCommitDecisionDoesNotResolveManualHoldOrOtherProblem, TestAdminExcludedCVEsStayUnresolvedEvenWithIncludedOtherFix 회귀 시험.
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

func reportedCommitFailure(t *testing.T, s *Server) (string, string, string) {
	t.Helper()
	commit := strings.Repeat("a", 40)
	problem := "도구가 지원하지 않는 변경"
	input := model.BuildInput{BaseTag: "Ubuntu-6.8.0-85.85", BuildTool: "klp", Profile: "/profile.json", Image: "sha256:" + strings.Repeat("b", 64)}
	report := model.UpstreamReport{Problem: &problem, ProblemKind: model.FailureUnsupported, ProblemFailure: &model.TrialFailure{
		Commit: commit, CVEs: []string{"CVE-2026-1000", "CVE-2026-9999"}, Title: "cross-module change", Input: input,
	}}
	data, _ := json.Marshal(report)
	callBuilderAPI(t, s, "POST", "/api/builder/kernels/"+testKernel+"/upstream", string(data), http.StatusOK)
	ref := ""
	s.store.View(func(st *State) { ref = st.upstream(testKernel).ProblemAt.UTC().Format(time.RFC3339Nano) })
	return "/api/kernels/" + testKernel + "/commits/" + commit + "/exclude", ref, string(data)
}

func TestCommitDecisionPersistsAndIsNotRecovery(t *testing.T) {
	s := newAutoServer(t, AutoRollout{Enabled: true})
	path, ref, report := reportedCommitFailure(t, s)
	for _, body := range []string{`{}`, `{"reason":"   "}`, `{"reason":"` + strings.Repeat("x", 1001) + `"}`} {
		callAPI(t, s, "POST", path, body, http.StatusBadRequest)
	}
	callAPI(t, s, "POST", path, `{"reason":"별도 완화", "problem_ref":"stale"}`, http.StatusConflict)
	callAPI(t, s, "POST", path, `{"reason":"별도 완화", "problem_ref":"`+ref+`"}`, http.StatusOK)
	s.store.View(func(st *State) {
		u, track := st.upstream(testKernel), st.track(testKernel)
		if u.Problem != "" || track.AutoHold == "" || track.AutoHoldResolved != "관리자 제외로 수집 계속 · CVE 미해결" {
			t.Fatalf("실제 복구·자동 재개로 오인: u=%+v track=%+v", u, track)
		}
		d := st.Unpatchable[0]
		if d.Decision == nil || d.Decision.By != "tester" || d.Decision.At.IsZero() || d.Reason != "별도 완화" || d.Decision.Input.Image == "" || d.Decision.Input.BaseTag == "" {
			t.Fatalf("결정 증거 누락: %+v", d)
		}
	})
	// 결정 직전 시작했던 시험이 같은 실패를 늦게 보내도 다시 문제를 만들지 않습니다.
	callBuilderAPI(t, s, "POST", "/api/builder/kernels/"+testKernel+"/upstream", report, http.StatusOK)
	s.store.View(func(st *State) {
		if st.upstream(testKernel).Problem != "" {
			t.Fatal("제외된 실패의 늦은 보고가 문제를 다시 만듦")
		}
	})
	restarted, err := NewServer(s.cfg)
	if err != nil {
		t.Fatal(err)
	}
	restarted.store.View(func(st *State) {
		if len(st.Unpatchable) != 1 || len(st.knownCommits(testKernel)) != 1 {
			t.Fatal("재시작의 과거 자동 판정 정리가 관리자 결정을 지움")
		}
	})
	callAPI(t, restarted, "DELETE", path, "", http.StatusOK)
	restarted.store.View(func(st *State) {
		if len(st.knownCommits(testKernel)) != 0 || st.upstream(testKernel).CollectedTag != "" || st.track(testKernel).AutoHold == "" || st.track(testKernel).AutoHoldResolved != "" {
			t.Fatal("취소 후 재시험·멈춤 유지 실패")
		}
	})
	callAPI(t, restarted, "DELETE", path, "", http.StatusNotFound)
	data, _ := os.ReadFile(filepath.Join(s.cfg.DataDir, "audit.log"))
	if !strings.Contains(string(data), "관리자 커밋 제외 kernel=") || !strings.Contains(string(data), "관리자 커밋 제외 취소") || !strings.Contains(string(data), "별도 완화") {
		t.Fatalf("감사 기록 누락: %s", data)
	}
}

func TestCommitDecisionDoesNotResolveManualHoldOrOtherProblem(t *testing.T) {
	s := newAutoServer(t, AutoRollout{})
	path, ref, _ := reportedCommitFailure(t, s)
	_ = s.store.Update(func(st *State) error {
		setAutoHold(st.track(testKernel), "관리자 멈춤", holdManual, "")
		return nil
	})
	callAPI(t, s, "POST", path, `{"reason":"검토 완료, 미해결 유지", "problem_ref":"`+ref+`"}`, http.StatusOK)
	s.store.View(func(st *State) {
		if st.track(testKernel).AutoHoldResolved != "" {
			t.Fatal("관리자 멈춤을 해결로 표시하면 안 됨")
		}
	})
	callBuilderAPI(t, s, "POST", "/api/builder/kernels/"+testKernel+"/upstream", `{"problem":"실제 환경 오류", "problem_kind":"environment"}`, http.StatusOK)
	callAPI(t, s, "DELETE", path, "", http.StatusOK)
	s.store.View(func(st *State) {
		if st.upstream(testKernel).Problem != "실제 환경 오류" {
			t.Fatal("결정 취소가 다른 문제를 지움")
		}
	})
}

func TestAdminExcludedCVEsStayUnresolvedEvenWithIncludedOtherFix(t *testing.T) {
	s := newAutoServer(t, AutoRollout{})
	addHost(t, s, "canary", 1)
	coverageFixture(t, s)
	_ = s.store.Update(func(st *State) error {
		h := st.Hosts["canary"]
		h.Status.KernelSignature = "Ubuntu 6.8.0-85.85-generic 6.8.12"
		h.Status.Version = 1
		h.Status.Loaded = []model.LoadedPatch{{Name: "module", Enabled: true}}
		st.Patches = append(st.Patches, &model.Patch{ID: "p1", Kernel: testKernel, Commit: "another-fix", CVEs: []string{"CVE-2026-1000"}, State: model.PatchActive})
		st.Jobs = append(st.Jobs, &model.Job{ID: 1, Kernel: testKernel, Version: 1, Status: model.JobReleased, ModuleName: "module", PatchIDs: []string{"p1"}})
		return nil
	})
	path, ref, _ := reportedCommitFailure(t, s)
	callAPI(t, s, "POST", path, `{"reason":"커널 업데이트 대기", "problem_ref":"`+ref+`"}`, http.StatusOK)
	body := callAPI(t, s, "GET", "/api/coverage?host=canary&state=admin_excluded", "", http.StatusOK)
	var coverage struct {
		Rows []coverageRow `json:"rows"`
	}
	if json.Unmarshal([]byte(body), &coverage) != nil || len(coverage.Rows) != 2 {
		t.Fatalf("벤더 목록에 없는 CVE도 관리자 제외로 표시: %s", body)
	}
	for _, row := range coverage.Rows {
		if row.Status != "admin_excluded" || !strings.Contains(strings.Join(row.Details, " "), "미해결 · 관리자 제외") {
			t.Fatalf("관리자 제외가 포함으로 보임: %+v", row)
		}
	}
}

func TestBusyReportDoesNotCreateHold(t *testing.T) {
	s := newAutoServer(t, AutoRollout{Enabled: true})
	callBuilderAPI(t, s, "POST", "/api/builder/kernels/"+testKernel+"/upstream", `{"problem":"잠금 사용 중", "problem_kind":"busy"}`, http.StatusOK)
	s.store.View(func(st *State) {
		if st.track(testKernel).AutoHold != "" {
			t.Fatal("일시 busy가 영구 멈춤으로 남음")
		}
	})
}

func TestLegacyReviewCannotReuseStaleFailedCommit(t *testing.T) {
	s := newAutoServer(t, AutoRollout{})
	path, ref, _ := reportedCommitFailure(t, s)
	callBuilderAPI(t, s, "POST", "/api/builder/kernels/"+testKernel+"/discovered", `{"unpatchable":[{"commit":"old-builder", "reason":"ERROR: changed data section"}]}`, http.StatusOK)
	callAPI(t, s, "POST", path, `{"reason":"별도 완화", "problem_ref":"`+ref+`"}`, http.StatusConflict)
	s.store.View(func(st *State) {
		if st.upstream(testKernel).ProblemFailure != nil {
			t.Fatal("다른 문제에 이전 실패 커밋을 붙이면 안 됨")
		}
	})
}
