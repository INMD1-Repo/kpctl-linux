// 이 파일: controller 패키지의 TestHistoricalUnverifiedFailuresAreArchivedForReview, TestHistoricalFailureArchiveErrorPreservesOriginalState, TestKnownCommitsIncludesOnlyActivePrerequisitesInBuildOrder 회귀 시험.
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

func TestHistoricalUnverifiedFailuresAreArchivedForReview(t *testing.T) {
	s := newAutoServer(t, AutoRollout{})
	if err := s.store.Update(func(st *State) error {
		st.Unpatchable = []*model.Unpatchable{
			{Kernel: testKernel, Commit: "cert", Reason: "No rule to make target 'debian/canonical-certs.pem'"},
			{Kernel: testKernel, Commit: "dependency", Reason: "patch does not apply"},
			{Kernel: testKernel, Commit: "confirmed", Reason: "ERROR: changed data section"},
		}
		st.upstream(testKernel).CollectedTag = "Ubuntu-6.8.0-90.90"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewServer(s.cfg)
	if err != nil {
		t.Fatal(err)
	}
	restarted.store.View(func(st *State) {
		if len(st.Unpatchable) != 1 || st.Unpatchable[0].Commit != "confirmed" || len(st.knownCommits(testKernel)) != 1 {
			t.Fatal("미확인 판정은 재시험할 수 있고 명시적 제약은 보존해야 함")
		}
		if st.upstream(testKernel).Problem == "" || st.upstream(testKernel).CollectedTag != "" || st.track(testKernel).AutoHold == "" {
			t.Fatal("과거 미확인 판정은 수집 완료를 무효화하고 자동 배포를 멈춰야 함")
		}
	})
	files, err := filepath.Glob(filepath.Join(s.cfg.DataDir, "unpatchable-review-*.json"))
	if err != nil || len(files) != 1 {
		t.Fatalf("원본 판정 보관 파일 필요: %v %v", files, err)
	}
	data, err := os.ReadFile(files[0])
	var archived []*model.Unpatchable
	if err != nil || json.Unmarshal(data, &archived) != nil || len(archived) != 2 || archived[0].Reason != "No rule to make target 'debian/canonical-certs.pem'" {
		t.Fatalf("기존 로그가 그대로 남아야 함: %s %v", data, err)
	}
	if _, err := NewServer(s.cfg); err != nil {
		t.Fatal(err)
	}
	files, _ = filepath.Glob(filepath.Join(s.cfg.DataDir, "unpatchable-review-*.json"))
	if len(files) != 1 {
		t.Fatal("재시작마다 같은 기록을 다시 보관하면 안 됨")
	}
}

func TestHistoricalFailureArchiveErrorPreservesOriginalState(t *testing.T) {
	s := newAutoServer(t, AutoRollout{})
	if err := s.store.Update(func(st *State) error {
		st.Unpatchable = []*model.Unpatchable{{Kernel: testKernel, Commit: "original", Reason: "patch does not apply"}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	s.cfg.DataDir = file
	if err := s.reviewUnpatchable(); err == nil {
		t.Fatal("보관할 수 없으면 재검토 전환에 실패해야 함")
	}
	s.store.View(func(st *State) {
		if len(st.Unpatchable) != 1 || st.Unpatchable[0].Commit != "original" || len(st.Tracks) != 0 {
			t.Fatal("원본 판정과 상태를 그대로 유지해야 함")
		}
	})
}

func TestKnownCommitsIncludesOnlyActivePrerequisitesInBuildOrder(t *testing.T) {
	s := newAutoServer(t, AutoRollout{})
	if err := s.store.Update(func(st *State) error {
		st.Patches = []*model.Patch{
			{ID: "p1", Kernel: testKernel, Commit: "first", State: model.PatchActive},
			{ID: "p2", Kernel: testKernel, Commit: "disabled", State: model.PatchDisabled},
			{ID: "p3", Kernel: testKernel, Commit: "second", State: model.PatchActive},
			{ID: "p4", Kernel: "7.0.0-28-generic", Commit: "other", State: model.PatchActive},
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"p1", "p3"} {
		if err := os.WriteFile(s.patchFile(id), []byte(id+" content"), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	path := "/api/builder/kernels/" + testKernel + "/known"
	body := callBuilderAPI(t, s, "GET", path, "", http.StatusOK)
	var got model.KnownCommitsResponse
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Commits) != 3 || len(got.ActivePatches) != 2 || got.ActivePatches[0].Content != "p1 content" || got.ActivePatches[1].Content != "p3 content" {
		t.Fatalf("같은 커널의 활성 패치만 최종 빌드와 같은 순서로 필요: %+v", got)
	}
	if err := os.Remove(s.patchFile("p1")); err != nil {
		t.Fatal(err)
	}
	callBuilderAPI(t, s, "GET", path, "", http.StatusInternalServerError)
}

func TestFailedBuildPreservesPatchesAndHoldsRollout(t *testing.T) {
	for _, reason := range []string{"ERROR: changed data section", "make: *** [certs] Error 2", "unexpected failure"} {
		t.Run(reason, func(t *testing.T) {
			s := newAutoServer(t, AutoRollout{Enabled: true})
			addHost(t, s, "canary", 1)
			id := addBuilt(t, s, "ubuntu")
			started := time.Now()
			if err := s.store.Update(func(st *State) error {
				job := st.job(id)
				job.Status, job.Builder, job.StartedAt = model.JobRunning, "builder", started
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			postBuildResult(t, s, id, model.BuildResult{Builder: "builder", JobStartedAt: &started, Error: "빌드 실패", Log: reason}, http.StatusOK)
			s.store.View(func(st *State) {
				if st.job(id).Status != model.JobFailed || st.Patches[0].State != model.PatchActive {
					t.Fatal("실패 결과만으로 보안 패치를 제외하면 안 됨")
				}
			})
			if !strings.Contains(holdReason(s), "누적 빌드 실패") {
				t.Fatal("관리자 검토까지 자동 배포를 멈춰야 함")
			}
			addBuilt(t, s, "ubuntu")
			s.autoTick()
			if ringVersion(s, 1) != 0 {
				t.Fatal("나중 빌드가 성공해도 검토 없이 자동 배포하면 안 됨")
			}
			restarted, err := NewServer(s.cfg)
			if err != nil {
				t.Fatal(err)
			}
			if holdReason(restarted) == "" {
				t.Fatal("재시작 뒤에도 검토 대기를 유지해야 함")
			}
		})
	}
}

func TestUncertainFailureDoesNotAdvanceCollection(t *testing.T) {
	for _, tc := range []struct {
		name, reason string
	}{
		{"인증서", "make[2]: *** [scripts/Makefile.build:548: certs] Error 2"},
		{"패치 의존성", "patch does not apply"},
		{"미분류", "unexpected failure"},
		{"명시적 패치 제약", "ERROR: changed data section"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newAutoServer(t, AutoRollout{})
			oldTag, newTag := "Ubuntu-6.8.0-85.85", "Ubuntu-6.8.0-90.90"
			if err := s.store.Update(func(st *State) error {
				st.upstream(testKernel).CollectedTag = oldTag
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			body := `{"latest_tag":"` + newTag + `","unpatchable":[{"commit":"c1","reason":` + strconvQuote(tc.reason) + `}]}`
			callBuilderAPI(t, s, "POST", "/api/builder/kernels/"+testKernel+"/discovered", body, http.StatusOK)
			// 예전 빌드 서버는 별도 upstream 보고로 수집 완료 태그를 다시 보냅니다.
			callBuilderAPI(t, s, "POST", "/api/builder/kernels/"+testKernel+"/upstream", `{"collected_tag":"`+newTag+`"}`, http.StatusOK)
			s.store.View(func(st *State) {
				if len(st.Unpatchable) != 0 || len(st.knownCommits(testKernel)) != 0 || st.upstream(testKernel).CollectedTag != oldTag || st.upstream(testKernel).Problem == "" || st.track(testKernel).AutoHold == "" {
					t.Fatal("원인 미확인 실패는 처리 완료로 간주하지 않고 검토를 기다려야 함")
				}
			})
		})
	}
}

func TestResolvedBuildProblemStillRequiresReview(t *testing.T) {
	s := newAutoServer(t, AutoRollout{Enabled: true})
	addHost(t, s, "canary", 1)
	addBuilt(t, s, "ubuntu")
	path := "/api/builder/kernels/" + testKernel + "/upstream"
	callBuilderAPI(t, s, "POST", path, `{"problem":"인증서 빌드 실패"}`, http.StatusOK)
	callBuilderAPI(t, s, "POST", path, `{"problem":"","recovered":true}`, http.StatusOK)
	s.autoTick()
	if holdReason(s) == "" || ringVersion(s, 1) != 0 {
		t.Fatal("환경 오류가 사라져도 관리자가 확인하기 전에 자동 배포를 재개하면 안 됨")
	}
	// 대신 웹이 오류 대신 "원인 해결됨"을 보여 줄 수 있게 표시합니다.
	s.store.View(func(st *State) {
		if st.track(testKernel).AutoHoldResolved != "수집 문제 해결" {
			t.Fatalf("원인 해결 표시: %q", st.track(testKernel).AutoHoldResolved)
		}
	})
	callAPI(t, s, "POST", "/api/kernels/"+testKernel+"/auto", `{"hold":false}`, http.StatusOK)
	s.store.View(func(st *State) {
		if t2 := st.track(testKernel); t2.AutoHold != "" || t2.AutoHoldResolved != "" {
			t.Fatalf("재개하면 표시도 지움: %+v", t2)
		}
	})
}

func TestManualHoldNeverMarkedResolved(t *testing.T) {
	s := newAutoServer(t, AutoRollout{Enabled: true})
	addHost(t, s, "canary", 1)
	addBuilt(t, s, "ubuntu")
	callAPI(t, s, "POST", "/api/kernels/"+testKernel+"/auto", `{"hold":true}`, http.StatusOK)
	s.autoTick()
	s.store.View(func(st *State) {
		if st.track(testKernel).AutoHoldResolved != "" {
			t.Fatal("관리자가 건 멈춤은 원인 해결로 표시하지 않음")
		}
	})
}

func TestUpstreamRecoveryRequiresEvidenceAndSameProblem(t *testing.T) {
	for _, tc := range []struct {
		name, clear string
		resolved    bool
	}{
		{"단순 표시 삭제", `{"problem":""}`, false},
		{"범위 밖", `{"problem":"","outside":"지원 범위 밖","recovered":true}`, false},
		{"다른 종류 해제", `{"problem":"","problem_kind":"tag_fetch","recovered":true}`, false},
		{"확인한 복구", `{"problem":"","problem_kind":"disk_space","recovered":true}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newAutoServer(t, AutoRollout{})
			path := "/api/builder/kernels/" + testKernel + "/upstream"
			callBuilderAPI(t, s, "POST", path, `{"problem":"디스크 부족","problem_kind":"disk_space"}`, http.StatusOK)
			callBuilderAPI(t, s, "POST", path, tc.clear, http.StatusOK)
			s.markResolvedHolds()
			before, err := os.Stat(s.store.path)
			if err != nil {
				t.Fatal(err)
			}
			s.markResolvedHolds()
			after, err := os.Stat(s.store.path)
			if err != nil {
				t.Fatal(err)
			}
			if !os.SameFile(before, after) || !before.ModTime().Equal(after.ModTime()) {
				t.Fatal("해결 표시가 같으면 다시 저장하지 않음")
			}
			s.store.View(func(st *State) {
				track := st.track(testKernel)
				if track.AutoHoldKind != holdUpstream || track.AutoHoldRef == "" {
					t.Fatalf("구조화 원인: %+v", track)
				}
				if (track.AutoHoldResolved != "") != tc.resolved || track.AutoHold == "" {
					t.Fatalf("해결 표시/멈춤 유지: %+v", track)
				}
			})
		})
	}
}

func TestUpstreamProblemRefStaysStableAcrossRepeatedTagFailures(t *testing.T) {
	s := newAutoServer(t, AutoRollout{})
	path := "/api/builder/kernels/" + testKernel + "/upstream"
	callBuilderAPI(t, s, "POST", path, `{"problem":"3회 실패","problem_kind":"tag_fetch"}`, http.StatusOK)
	callBuilderAPI(t, s, "POST", path, `{"problem":"4회 실패","problem_kind":"tag_fetch"}`, http.StatusOK)
	callBuilderAPI(t, s, "POST", path, `{"problem":"","problem_kind":"tag_fetch","recovered":true}`, http.StatusOK)
	s.markResolvedHolds()
	s.store.View(func(st *State) {
		if st.track(testKernel).AutoHoldResolved == "" {
			t.Fatal("실패 횟수가 늘어도 같은 원인의 복구를 확인")
		}
	})
	// 복구 후 새 문제가 발생하면 새 원인을 추적하며 수동 멈춤·옛 문구는 바꾸지 않습니다.
	callBuilderAPI(t, s, "POST", path, `{"problem":"새 태그 장애","problem_kind":"tag_fetch"}`, http.StatusOK)
	s.markResolvedHolds()
	s.store.View(func(st *State) {
		if st.track(testKernel).AutoHoldResolved != "" {
			t.Fatal("새 문제가 생기면 해결 표시 해제")
		}
	})
	callBuilderAPI(t, s, "POST", path, `{"problem":"","problem_kind":"tag_fetch","recovered":true}`, http.StatusOK)
	s.markResolvedHolds()
	s.store.View(func(st *State) {
		if st.track(testKernel).AutoHoldResolved == "" {
			t.Fatal("새 원인도 명시적 복구 뒤 표시")
		}
	})
}

func TestTagReportsCannotOverwriteOrClearBuildProblem(t *testing.T) {
	s := newAutoServer(t, AutoRollout{})
	path := "/api/builder/kernels/" + testKernel + "/upstream"
	callBuilderAPI(t, s, "POST", path, `{"problem":"시험 빌드 검토 필요"}`, http.StatusOK)
	callBuilderAPI(t, s, "POST", path, `{"problem":"3회 실패","problem_kind":"tag_fetch"}`, http.StatusOK)
	callBuilderAPI(t, s, "POST", path, `{"problem":"","problem_kind":"tag_fetch","recovered":true}`, http.StatusOK)
	s.markResolvedHolds()
	s.store.View(func(st *State) {
		if st.upstream(testKernel).Problem != "시험 빌드 검토 필요" || st.track(testKernel).AutoHoldResolved != "" {
			t.Fatal("태그 성공은 시험 빌드 복구가 아님")
		}
	})
}
