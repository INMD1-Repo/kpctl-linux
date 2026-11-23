// 이 파일: 출시 전 작업의 API 격리·명시 승인·정식 이관과 보호 유지 회귀 시험.
package controller

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"kpctl/internal/model"
)

const prereleaseAPIPatch = "diff --git a/kernel/test.c b/kernel/test.c\n--- a/kernel/test.c\n+++ b/kernel/test.c\n@@ -1 +1 @@\n-int base;\n+int fixed;\n"

func prereleaseAPIDiscover(t *testing.T, s *Server, pre bool, commit string) model.DiscoveredResponse {
	t.Helper()
	req := map[string]any{"prerelease": pre, "latest_tag": "Ubuntu-6.8.0-90.90", "patches": []map[string]any{{"commit": commit, "cves": []string{"CVE-2099-1234"}, "title": "candidate " + commit[:8], "content": prereleaseAPIPatch}}}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	body := callBuilderAPI(t, s, "POST", "/api/builder/kernels/"+testKernel+"/discovered", string(data), http.StatusOK)
	var response model.DiscoveredResponse
	if err := json.Unmarshal([]byte(body), &response); err != nil {
		t.Fatal(err)
	}
	return response
}
func prereleaseAPIBuilt(t *testing.T, s *Server, id int) {
	t.Helper()
	if err := s.store.Update(func(st *State) error {
		j := st.job(id)
		if j == nil {
			return fmt.Errorf("job %d missing", id)
		}
		j.Status = model.JobBuilt
		j.ModuleName = fmt.Sprintf("kpctl_candidate_%d", id)
		path := s.artifactFile(j.Kernel, j.ModuleName)
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			return err
		}
		return os.WriteFile(path, []byte("unsigned module fixture"), 0o640)
	}); err != nil {
		t.Fatal(err)
	}
}
func prereleaseAPIKnown(t *testing.T, s *Server, pre bool) model.KnownCommitsResponse {
	t.Helper()
	path := "/api/builder/kernels/" + testKernel + "/known"
	if pre {
		path += "?prerelease=true"
	}
	body := callBuilderAPI(t, s, "GET", path, "", http.StatusOK)
	var got model.KnownCommitsResponse
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatal(err)
	}
	return got
}
func containsPrereleaseID(ids []string, want string) bool {
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}

func TestPrereleaseAPIKeepsOfficialCountersPatchesAndQueuedJobsIndependent(t *testing.T) {
	s := newAutoServer(t, AutoRollout{})
	formal := prereleaseAPIDiscover(t, s, false, strings.Repeat("a", 40))
	pre := prereleaseAPIDiscover(t, s, true, strings.Repeat("b", 40))
	pre2 := prereleaseAPIDiscover(t, s, true, strings.Repeat("c", 40))
	s.store.View(func(st *State) {
		official, first, second := st.job(formal.JobID), st.job(pre.JobID), st.job(pre2.JobID)
		track := st.track(testKernel)
		if official.Status != model.JobQueued || official.Version != 1 || track.NextVersion != 1 {
			t.Fatalf("출시 전 작업이 정식 대기 작업/번호를 오염함: %+v %+v", official, track)
		}
		if !first.Prerelease || first.Version != -1 || first.PrereleaseVersion != 1 || first.Status != model.JobSuperseded {
			t.Fatalf("출시 전 번호/폐기 규칙: %+v", first)
		}
		if !second.Prerelease || second.Version != -2 || second.PrereleaseVersion != 2 || track.NextPrereleaseVersion != 2 {
			t.Fatalf("출시 전 별도 카운터: %+v %+v", second, track)
		}
		if len(official.PatchIDs) != 1 || len(st.activePatches(testKernel)) != 1 || len(second.PatchIDs) != 3 {
			t.Fatalf("정식/출시 전 누적 입력이 섞임: official=%+v pre=%+v", official, second)
		}
		for _, id := range official.PatchIDs {
			if st.patch(id).Prerelease {
				t.Fatalf("정식 누적본에 출시 전 패치 %s 포함", id)
			}
		}
		if !containsPrereleaseID(second.PatchIDs, official.PatchIDs[0]) {
			t.Fatal("출시 전 누적본에서 현재 정식 보호가 누락됨")
		}
		if st.upstream(testKernel).CollectedTag != "Ubuntu-6.8.0-90.90" {
			t.Fatal("정식 수집 태그가 변경됨")
		}
	})
	// 더 새 정식 패치는 정식 대기 작업만 대체합니다.
	formal2 := prereleaseAPIDiscover(t, s, false, strings.Repeat("d", 40))
	s.store.View(func(st *State) {
		if st.job(formal.JobID).Status != model.JobSuperseded || st.job(pre2.JobID).Status != model.JobQueued {
			t.Fatal("정식/출시 전 작업 폐기 범위가 섞임")
		}
		if st.job(formal2.JobID).Version != 2 || len(st.job(formal2.JobID).PatchIDs) != 2 {
			t.Fatalf("정식 버전 계열/누적 입력 오염: %+v", st.job(formal2.JobID))
		}
	})
}

func TestPrereleaseAPICannotAdvanceOfficialCollectionOrReachOldBuilder(t *testing.T) {
	s := newAutoServer(t, AutoRollout{})
	if err := s.store.Update(func(st *State) error { st.upstream(testKernel).CollectedTag = "Ubuntu-6.8.0-85.85"; return nil }); err != nil {
		t.Fatal(err)
	}
	pre := prereleaseAPIDiscover(t, s, true, strings.Repeat("a", 40))
	s.store.View(func(st *State) {
		if st.upstream(testKernel).CollectedTag != "Ubuntu-6.8.0-85.85" || st.track(testKernel).NextVersion != 0 {
			t.Fatal("출시 전 수집이 정식 태그/버전 카운터를 진행시킴")
		}
	})
	callBuilderAPI(t, s, "POST", "/api/builder/next", `{"builder":"legacy","series":"noble"}`, http.StatusNoContent)
	s.store.View(func(st *State) {
		if st.job(pre.JobID).Status != model.JobQueued {
			t.Fatal("음수 버전을 모르는 이전 빌더에 작업이 배정됨")
		}
	})
	body := callBuilderAPI(t, s, "POST", "/api/builder/next", `{"builder":"new","series":"noble","can_prerelease":true}`, http.StatusOK)
	var task model.BuildTask
	if err := json.Unmarshal([]byte(body), &task); err != nil {
		t.Fatal(err)
	}
	if task.Job.ID != pre.JobID || !task.Job.Prerelease || task.Job.Version != -1 || len(task.Patches) != 1 {
		t.Fatalf("능력 확인된 빌더의 별도 출시 전 작업 배정 실패: %+v", task)
	}
}

func TestPrereleaseAPIApprovalRequiresOptInAndVMAndNeverAutomatesPromotion(t *testing.T) {
	s := newAutoServer(t, AutoRollout{Enabled: true, SoakMinutes: minutes(0)})
	pre := prereleaseAPIDiscover(t, s, true, strings.Repeat("a", 40))
	prereleaseAPIBuilt(t, s, pre.JobID)
	path := fmt.Sprintf("/api/jobs/%d/approve", pre.JobID)
	callAPI(t, s, "POST", path, `{}`, http.StatusConflict)
	callAPI(t, s, "POST", path, `{"prerelease":true}`, http.StatusConflict)
	s.autoTick()
	s.store.View(func(st *State) {
		if st.job(pre.JobID).Status != model.JobBuilt || st.track(testKernel).RingVersions[1] != 0 {
			t.Fatal("출시 전 후보가 명시 승인/VM 없이 배포됨")
		}
	})
	runner := &approvalVMRunner{}
	enableApprovalVM(t, s, runner)
	callAPI(t, s, "POST", path, `{"prerelease":true}`, http.StatusOK)
	s.store.View(func(st *State) {
		j, track := st.job(pre.JobID), st.track(testKernel)
		if j.Status != model.JobReleased || j.VMTest == nil || j.VMTest.Status != "passed" || track.PrereleaseRingVersions[1] != -1 || track.RingVersions[1] != 0 || st.latestReleased(testKernel) != nil {
			t.Fatalf("VM 증거/배포 계열 분리 실패: %+v %+v", j, track)
		}
		if got := s.desired(st, st.Hosts["gpu-test"]); got.Version != -1 || got.ModuleName != j.ModuleName || got.SHA256 != j.SHA256 {
			t.Fatalf("카나리가 승인한 출시 전 사본을 받지 못함: %+v", got)
		}
	})
	s.autoTick()
	s.store.View(func(st *State) {
		if st.track(testKernel).PrereleaseRingVersions[2] != 0 || st.track(testKernel).RingVersions[2] != 0 {
			t.Fatal("출시 전 누적본이 자동 승급됨")
		}
	})
	callAPI(t, s, "POST", "/api/hosts/gpu-test/update-now", `{"version":-1}`, http.StatusBadRequest)
	callAPI(t, s, "POST", "/api/hosts/gpu-test/update-now", `{}`, http.StatusConflict)
	promote := "/api/kernels/" + testKernel + "/promote"
	callAPI(t, s, "POST", promote, `{"ring":2,"force":true}`, http.StatusConflict)
	// 명시 승급도 실제 모듈 적용을 확인해야 합니다.
	callAPI(t, s, "POST", promote, `{"ring":2,"prerelease":true}`, http.StatusConflict)
	if err := s.store.Update(func(st *State) error {
		j := st.job(pre.JobID)
		h := st.Hosts["gpu-test"]
		h.Status.Version = -1
		h.Status.Loaded = []model.LoadedPatch{{Name: j.ModuleName, Enabled: true}}
		st.track(testKernel).PrereleaseRingSetAt[1] = time.Now().Add(-48 * time.Hour)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	callAPI(t, s, "POST", promote, `{"ring":2,"prerelease":true,"expected_version":-1}`, http.StatusOK)
	s.store.View(func(st *State) {
		if st.track(testKernel).PrereleaseRingVersions[2] != -1 || st.track(testKernel).RingVersions[2] != 0 {
			t.Fatal("명시 출시 전 승급이 정식 목표를 오염함")
		}
	})
}

func TestPrereleaseAPIFormalMigrationPreservesOriginalProvenance(t *testing.T) {
	s := newAutoServer(t, AutoRollout{})
	sha := strings.Repeat("b", 40)
	pre := prereleaseAPIDiscover(t, s, true, sha)
	var originalPatch *model.Patch
	var originalJSON []byte
	s.store.View(func(st *State) {
		p := st.patch(st.job(pre.JobID).PatchIDs[0])
		copy := *p
		originalPatch = &copy
		originalJSON, _ = json.Marshal(p)
	})
	if known := prereleaseAPIKnown(t, s, false); len(known.Commits) != 0 || len(known.ActivePatches) != 0 {
		t.Fatalf("정식 known에 출시 전 후보가 섞임: %+v", known)
	}
	formal := prereleaseAPIDiscover(t, s, false, sha)
	if formal.AddedPatches != 1 || formal.JobID == 0 {
		t.Fatalf("정식 배포로 넘어온 같은 커밋이 수집되지 않음: %+v", formal)
	}
	s.store.View(func(st *State) {
		p := st.patch(originalPatch.ID)
		currentJSON, _ := json.Marshal(p)
		if !reflect.DeepEqual(originalJSON, currentJSON) || !p.Prerelease {
			t.Fatalf("기존 출시 전 이력의 출처를 변경함: before=%s after=%s", originalJSON, currentJSON)
		}
		job := st.job(formal.JobID)
		if job.Prerelease || job.Version != 1 || len(job.PatchIDs) != 1 || job.PatchIDs[0] == originalPatch.ID || st.patch(job.PatchIDs[0]).Prerelease {
			t.Fatalf("정식 patch/job가 별도 출처를 보존하지 않음: %+v", job)
		}
	})
	for _, preQuery := range []bool{false, true} {
		known := prereleaseAPIKnown(t, s, preQuery)
		if len(known.Commits) != 1 || known.Commits[0] != sha || len(known.ActivePatches) != 1 || known.ActivePatches[0].Commit != sha {
			t.Fatalf("정식 이관 뒤 중복 입력/재수집 위험: pre=%v %+v", preQuery, known)
		}
	}
	again := prereleaseAPIDiscover(t, s, true, sha)
	if again.AddedPatches != 0 || again.JobID != 0 {
		t.Fatalf("정식 배포된 커밋을 출시 전 후보로 다시 만듦: %+v", again)
	}
}

func TestPrereleaseAPIRejectsCandidateMissingNewOfficialProtection(t *testing.T) {
	s := newAutoServer(t, AutoRollout{})
	prereleaseAPIDiscover(t, s, false, strings.Repeat("a", 40))
	pre := prereleaseAPIDiscover(t, s, true, strings.Repeat("b", 40))
	prereleaseAPIBuilt(t, s, pre.JobID)
	// 후보가 빌드된 뒤 정식 경로에 새 보안 패치가 추가되었습니다.
	formal := prereleaseAPIDiscover(t, s, false, strings.Repeat("c", 40))
	runner := &approvalVMRunner{}
	enableApprovalVM(t, s, runner)
	path := fmt.Sprintf("/api/jobs/%d/approve", pre.JobID)
	callAPI(t, s, "POST", path, `{"prerelease":true}`, http.StatusConflict)
	s.store.View(func(st *State) {
		if st.job(pre.JobID).Status == model.JobReleased || st.track(testKernel).PrereleaseRingVersions[1] != 0 || st.job(formal.JobID).Status != model.JobQueued {
			t.Fatal("최신 정식 보호가 빠진 출시 전 후보가 승인되거나 정식 대기 작업을 훼손함")
		}
	})
}

func TestPrereleaseAPIRechecksOfficialProtectionAfterVMTest(t *testing.T) {
	s := newAutoServer(t, AutoRollout{})
	prereleaseAPIDiscover(t, s, false, strings.Repeat("a", 40))
	pre := prereleaseAPIDiscover(t, s, true, strings.Repeat("b", 40))
	prereleaseAPIBuilt(t, s, pre.JobID)
	var changed atomic.Bool
	data, err := json.Marshal(map[string]any{"patches": []map[string]any{{"commit": strings.Repeat("c", 40), "cves": []string{"CVE-2099-1235"}, "title": "new official protection", "content": prereleaseAPIPatch}}})
	if err != nil {
		t.Fatal(err)
	}
	runner := &approvalVMRunner{onTest: func() error {
		if changed.Swap(true) {
			return nil
		}
		request := httptest.NewRequest(http.MethodPost, "/api/builder/kernels/"+testKernel+"/discovered", strings.NewReader(string(data)))
		request.Header.Set("Authorization", "Bearer builder-token-0123456789")
		recorder := httptest.NewRecorder()
		s.Handler().ServeHTTP(recorder, request)
		if recorder.Code != http.StatusOK {
			return fmt.Errorf("concurrent official discovery failed: %s", recorder.Body)
		}
		return nil
	}}
	enableApprovalVM(t, s, runner)
	callAPI(t, s, "POST", fmt.Sprintf("/api/jobs/%d/approve", pre.JobID), `{"prerelease":true}`, http.StatusConflict)
	if !changed.Load() || len(runner.copied) == 0 {
		t.Fatal("VM 시험 동안 정식 수집이 바뀌는 경합을 재현하지 못함")
	}
	s.store.View(func(st *State) {
		if st.job(pre.JobID).Status == model.JobReleased || st.track(testKernel).PrereleaseRingVersions[1] != 0 {
			t.Fatal("VM 통과 뒤 새 정식 보호가 누락된 출시 전 후보가 배포됨")
		}
	})
}

func TestPrereleaseAPINegativeCurrentVersionKeepsProtectionWhenBlocked(t *testing.T) {
	s := newAutoServer(t, AutoRollout{})
	fixture, current := signingFixture()
	s.cfg.Signing = fixture.cfg.Signing
	s.cfg.Signing.Mode = "never"
	current.Version, current.Prerelease, current.PrereleaseVersion = -1, true, 1
	current.ModuleName, current.SHA256 = "kpctl_current_prerelease", "pre-sha"
	target := *current
	target.ID, target.Version, target.Prerelease, target.PrereleaseVersion = 2, 2, false, 0
	target.ModuleName, target.SHA256 = "kpctl_official_target", "formal-sha"
	h := &model.Host{ID: "node", Hostname: "node", Ring: 1, TokenHash: hashToken("node-token"), LastSeen: time.Now(), Status: model.HostStatus{Kernel: testKernel, Version: -1, Loaded: []model.LoadedPatch{{Name: current.ModuleName, Enabled: true}}}}
	if err := s.store.Update(func(st *State) error {
		st.Jobs = []*model.Job{current, &target}
		st.Hosts[h.ID] = h
		st.track(testKernel).RingVersions[1] = 2
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	s.store.View(func(st *State) {
		got := s.desired(st, h)
		if !got.Blocked || got.Version != -1 || got.ModuleName != current.ModuleName {
			t.Fatalf("제외 응답이 이미 적용한 출시 전 보호를 v0로 내릴 위험: %+v", got)
		}
	})
	body := agentRebootAPI(t, s, "/api/agent/report", model.ReportRequest{Status: h.Status}, http.StatusOK)
	var response model.ReportResponse
	if err := json.Unmarshal([]byte(body), &response); err != nil {
		t.Fatal(err)
	}
	if !response.Desired.Blocked || response.Desired.Version != -1 || response.Desired.ModuleName != current.ModuleName {
		t.Fatalf("이전 에이전트의 음수 버전 보호가 유지되지 않음: %+v", response.Desired)
	}
}
