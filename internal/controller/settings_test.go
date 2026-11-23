// 이 파일: controller 패키지의 TestUpdateNow, TestSettings, TestKernelRefresh 회귀 시험.
package controller

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"kpctl/internal/model"
)

func desiredFor(s *Server, id string) (v int) {
	s.store.View(func(st *State) { v = s.desired(st, st.Hosts[id]).Version })
	return v
}

func TestUpdateNow(t *testing.T) {
	s := newAutoServer(t, AutoRollout{Enabled: true})
	addHost(t, s, "gpu-01", 1)
	addHost(t, s, "gpu-02", 2)

	// 배포된 패치가 없으면 거부
	callAPI(t, s, "POST", "/api/hosts/gpu-02/update-now", "", http.StatusBadRequest)

	addBuilt(t, s, "ubuntu")
	s.autoTick() // 링 1 에만 v1
	if v := desiredFor(s, "gpu-02"); v != 0 {
		t.Fatalf("링 2 는 아직 v0 이어야 함: v%d", v)
	}
	callAPI(t, s, "POST", "/api/hosts/gpu-02/update-now", "", http.StatusOK)
	if v := desiredFor(s, "gpu-02"); v != 1 {
		t.Fatalf("즉시 업데이트 뒤 v1 이어야 함: v%d", v)
	}

	// 커널이 바뀌면 적용하지 않음
	_ = s.store.Update(func(st *State) error { st.Hosts["gpu-02"].Status.Kernel = "6.8.0-90-generic"; return nil })
	if v := desiredFor(s, "gpu-02"); v != 0 {
		t.Fatalf("다른 커널에는 주면 안 됨: v%d", v)
	}
	_ = s.store.Update(func(st *State) error { st.Hosts["gpu-02"].Status.Kernel = testKernel; return nil })

	// 취소
	callAPI(t, s, "POST", "/api/hosts/gpu-02/update-now", `{"cancel":true}`, http.StatusOK)
	if v := desiredFor(s, "gpu-02"); v != 0 {
		t.Fatalf("취소 뒤 v0 이어야 함: v%d", v)
	}

	// 롤백하면 풀림
	callAPI(t, s, "POST", "/api/hosts/gpu-02/update-now", "", http.StatusOK)
	callAPI(t, s, "POST", "/api/kernels/"+testKernel+"/rollback", `{"version":0}`, http.StatusOK)
	s.store.View(func(st *State) {
		if h := st.Hosts["gpu-02"]; h.UpdateNowVersion != 0 {
			t.Fatalf("롤백 뒤 즉시 업데이트가 남음: %+v", h)
		}
	})
}

func TestSettings(t *testing.T) {
	s := newAutoServer(t, AutoRollout{})
	addHost(t, s, "gpu-01", 1)
	addBuilt(t, s, "ubuntu")

	body := callAPI(t, s, "GET", "/api/settings", "", http.StatusOK)
	if !strings.Contains(body, `"auto_enabled":false`) {
		t.Fatalf("설정 응답: %s", body)
	}
	callAPI(t, s, "POST", "/api/settings", `{"host_stale_minutes":0}`, http.StatusBadRequest)
	callAPI(t, s, "POST", "/api/settings", `{"min_soak_minutes":{"9":10}}`, http.StatusBadRequest)

	// 웹에서 자동 배포를 켜면 재시작 없이 바로 동작
	callAPI(t, s, "POST", "/api/settings", `{"auto_enabled":true,"min_soak_minutes":{"2":30},"host_stale_minutes":15}`, http.StatusOK)
	s.autoTick()
	if v := ringVersion(s, 1); v != 1 {
		t.Fatalf("설정으로 켠 자동 배포가 동작해야 함: 링 1 v%d", v)
	}
	if got := s.settings(); got.MinSoakMinutes[2] != 30 || got.HostStaleMinutes != 15 {
		t.Fatalf("설정 = %+v", got)
	}

	// 다시 시작해도 유지 (settings.json)
	s2, err := NewServer(s.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if got := s2.settings(); !got.AutoEnabled || got.MinSoakMinutes[2] != 30 {
		t.Fatalf("재시작 뒤 설정 = %+v", got)
	}
}

func callBuilderAPI(t *testing.T, s *Server, method, path, body string, want int) string {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer builder-token-0123456789")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != want {
		t.Fatalf("%s %s = %d, want %d: %s", method, path, rec.Code, want, rec.Body)
	}
	return rec.Body.String()
}

func TestKernelRefresh(t *testing.T) {
	s := newAutoServer(t, AutoRollout{})
	addHost(t, s, "gpu-01", 1)
	k := "/api/kernels/" + testKernel

	// 빌드 서버가 Ubuntu 최신 태그를 알림
	callBuilderAPI(t, s, "POST", "/api/builder/kernels/"+testKernel+"/upstream", `{"latest_tag":"Ubuntu-6.8.0-90.90"}`, http.StatusOK)
	callBuilderAPI(t, s, "POST", "/api/builder/kernels/"+testKernel+"/upstream", `{"latest_tag":"bad tag;rm"}`, http.StatusBadRequest)
	if body := callAPI(t, s, "GET", "/api/status", "", http.StatusOK); !strings.Contains(body, `"latest_tag":"Ubuntu-6.8.0-90.90"`) {
		t.Fatalf("상태에 최신 태그가 없음: %s", body)
	}

	// 관리자가 "빌드" → 빌드할 작업이 없으면 수집 요청이 빌드 서버로
	callAPI(t, s, "POST", k+"/refresh", "", http.StatusOK)
	next := `{"builder":"b1","series":"noble"`
	// 예전 빌드 서버(can_refresh 없음)에는 주지 않음
	callBuilderAPI(t, s, "POST", "/api/builder/next", next+`}`, http.StatusNoContent)
	// 다른 시리즈 빌드 서버에도 주지 않음
	callBuilderAPI(t, s, "POST", "/api/builder/next", `{"builder":"b2","series":"jammy","can_refresh":true}`, http.StatusNoContent)
	body := callBuilderAPI(t, s, "POST", "/api/builder/next", next+`,"can_refresh":true}`, http.StatusOK)
	if !strings.Contains(body, `"refresh":["`+testKernel+`"]`) {
		t.Fatalf("수집 요청이 없음: %s", body)
	}
	// 한 번 넘기면 지워짐
	callBuilderAPI(t, s, "POST", "/api/builder/next", next+`,"can_refresh":true}`, http.StatusNoContent)

	// 아직 빌드하지 않은 활성 패치가 있으면 바로 빌드 작업도 만듦
	addBuilt(t, s, "ubuntu") // job 1 (승인대기)
	_ = s.store.Update(func(st *State) error {
		st.NextPatchID++
		st.Patches = append(st.Patches, &model.Patch{ID: "p" + leftPad(st.NextPatchID), Kernel: testKernel, Source: "ubuntu", State: model.PatchActive})
		return nil
	})
	if body := callAPI(t, s, "POST", k+"/refresh", "", http.StatusOK); !strings.Contains(body, `"job_id":2`) {
		t.Fatalf("빌드 작업을 만들어야 함: %s", body)
	}
}

func TestBuilderUpdateAPI(t *testing.T) {
	s := newAutoServer(t, AutoRollout{})
	s.cfg.BuilderBinary = filepath.Join(t.TempDir(), "kpctl-builder")
	// 파일이 없으면 업데이트 없음
	if body := callBuilderAPI(t, s, "POST", "/api/builder/update", `{"sha256":"aaa"}`, http.StatusOK); !strings.Contains(body, `"update":false`) {
		t.Fatalf("파일이 없으면 update=false: %s", body)
	}
	os.WriteFile(s.cfg.BuilderBinary, []byte("new-builder"), 0o644)
	body := callBuilderAPI(t, s, "POST", "/api/builder/update", `{"sha256":"aaa"}`, http.StatusOK)
	if !strings.Contains(body, `"update":true`) {
		t.Fatalf("다른 버전이면 update=true: %s", body)
	}
	sum, _ := s.builderBinarySHA()
	if b := callBuilderAPI(t, s, "POST", "/api/builder/update", `{"sha256":"`+sum+`"}`, http.StatusOK); !strings.Contains(b, `"update":false`) {
		t.Fatalf("같은 버전이면 update=false: %s", b)
	}
	if b := callBuilderAPI(t, s, "GET", "/api/builder/binary", "", http.StatusOK); b != "new-builder" {
		t.Fatalf("실행 파일 내용: %q", b)
	}
	// 관리자 토큰으로는 받을 수 없음 (빌드 서버 전용)
	callAPI(t, s, "GET", "/api/builder/binary", "", http.StatusUnauthorized)

	// 작업 확인 때 버전 기록 → 웹 표시
	callBuilderAPI(t, s, "POST", "/api/builder/next", `{"builder":"b1","series":"noble","can_refresh":true,"binary_sha256":"old"}`, http.StatusNoContent)
	s.store.View(func(st *State) {
		if b := st.Builders["b1"]; b == nil || b.UpToDate {
			t.Fatalf("예전 버전으로 표시돼야 함: %+v", b)
		}
	})
}

func TestUpToTagAndProblem(t *testing.T) {
	s := newAutoServer(t, AutoRollout{Enabled: true})
	addHost(t, s, "gpu-01", 1)
	k := "/api/builder/kernels/" + testKernel

	// 빌드 서버: 수집할 수 없음 → 해결
	callBuilderAPI(t, s, "POST", k+"/upstream", `{"problem":"디버그 심볼 없음"}`, http.StatusOK)
	if body := callAPI(t, s, "GET", "/api/status", "", http.StatusOK); !strings.Contains(body, `"problem":"디버그 심볼 없음"`) {
		t.Fatalf("문제가 상태에 없음: %s", body)
	}
	callBuilderAPI(t, s, "POST", k+"/upstream", `{"problem":""}`, http.StatusOK)
	callBuilderAPI(t, s, "POST", k+"/upstream", `{"latest_tag":"Ubuntu-6.8.0-90.90"}`, http.StatusOK) // problem 없으면 그대로
	s.store.View(func(st *State) {
		if u := st.Upstream[testKernel]; u.Problem != "" || u.LatestTag != "Ubuntu-6.8.0-90.90" {
			t.Fatalf("upstream = %+v", u)
		}
	})

	// 수집 결과 → 새 작업이 "어디까지 반영" 을 기록 → 배포되면 상태에 나옴
	patch := "--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n+b\n"
	body := callBuilderAPI(t, s, "POST", k+"/discovered",
		`{"latest_tag":"Ubuntu-6.8.0-90.90","patches":[{"commit":"c1","cves":["CVE-2026-1"],"title":"t","content":`+strconvQuote(patch)+`}]}`, http.StatusOK)
	if !strings.Contains(body, `"job_id":1`) {
		t.Fatalf("작업이 생겨야 함: %s", body)
	}
	s.store.View(func(st *State) {
		if j := st.job(1); j.UpToTag != "Ubuntu-6.8.0-90.90" {
			t.Fatalf("작업 반영 태그 = %q", j.UpToTag)
		}
	})
	_ = s.store.Update(func(st *State) error {
		j := st.job(1)
		j.Status, j.ModuleName = model.JobReleased, "kpctl_x"
		return nil
	})
	if body := callAPI(t, s, "GET", "/api/status", "", http.StatusOK); !strings.Contains(body, `"released_tags":{"`+testKernel+`":{"1":"Ubuntu-6.8.0-90.90"}}`) {
		t.Fatalf("released_tags 가 없음: %s", body)
	}
}

func strconvQuote(s string) string { return strconv.Quote(s) }

func TestDropEnvUnpatchable(t *testing.T) {
	s := newAutoServer(t, AutoRollout{})
	_ = s.store.Update(func(st *State) error {
		st.Unpatchable = append(st.Unpatchable,
			&model.Unpatchable{Kernel: testKernel, Commit: "a", Reason: "kpatch-build 실패\ncurl: (22) The requested URL returned error: 404"},
			&model.Unpatchable{Kernel: testKernel, Commit: "b", Reason: "ERROR: changed data section"})
		return nil
	})
	s2, err := NewServer(s.cfg)
	if err != nil {
		t.Fatal(err)
	}
	s2.store.View(func(st *State) {
		if len(st.Unpatchable) != 1 || st.Unpatchable[0].Commit != "b" {
			t.Fatalf("환경 오류 항목만 지워야 함: %+v", st.Unpatchable)
		}
	})
	// 환경 오류로 올라온 "불가" 는 받지 않음
	body := callBuilderAPI(t, s2, "POST", "/api/builder/kernels/"+testKernel+"/discovered",
		`{"unpatchable":[{"commit":"c","reason":"커널 소스 준비 실패: exit status 1"}]}`, http.StatusOK)
	_ = body
	s2.store.View(func(st *State) {
		if len(st.Unpatchable) != 1 {
			t.Fatalf("환경 오류는 기록하면 안 됨: %d건", len(st.Unpatchable))
		}
	})
}
