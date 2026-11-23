// 이 파일: controller 패키지의 TestAutoDisabledDoesNothing, TestAutoFullFlow, TestAutoSkipsWhatHumansMustApprove 회귀 시험.
package controller

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kpctl/internal/model"
)

const (
	testKernel = "6.8.0-85-generic"
	testAdmin  = "admin-token-0123456789"
)

func newAutoServer(t *testing.T, auto AutoRollout) *Server {
	t.Helper()
	s, err := NewServer(&Config{
		DataDir:          t.TempDir(),
		AdminTokens:      map[string]string{"tester": testAdmin},
		BuilderToken:     "builder-token-0123456789",
		Rings:            []int{1, 2},
		HostStaleMinutes: 10,
		AutoRollout:      auto,
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func minutes(n int) *int { return &n }

// addBuilt 는 빌드가 끝난 작업을 만듭니다. source 는 새 패치의 출처입니다.
func addBuilt(t *testing.T, s *Server, source string) int {
	t.Helper()
	var id int
	err := s.store.Update(func(st *State) error {
		st.NextPatchID++
		pid := "p" + leftPad(st.NextPatchID)
		st.Patches = append(st.Patches, &model.Patch{ID: pid, Kernel: testKernel, Source: source, State: model.PatchActive})
		if err := os.WriteFile(s.patchFile(pid), []byte("--- a\n+++ b\n@@\n"), 0o640); err != nil {
			return err
		}
		j, err := s.createJob(st, testKernel, "builder", false)
		if err != nil {
			return err
		}
		j.Status = model.JobBuilt
		j.ModuleName = "kpctl_test_v" + leftPad(j.Version)
		id = j.ID
		path := s.artifactFile(testKernel, j.ModuleName)
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			return err
		}
		return os.WriteFile(path, []byte("module"), 0o640)
	})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func addHost(t *testing.T, s *Server, name string, ring int) {
	t.Helper()
	_ = s.store.Update(func(st *State) error {
		st.Hosts[name] = &model.Host{ID: name, Hostname: name, Ring: ring, LastSeen: time.Now(),
			Status: model.HostStatus{Kernel: testKernel}}
		return nil
	})
}

// setHosts 는 모든 호스트가 지금 목표 버전을 적용했다고 보고한 것처럼 만듭니다.
func setHosts(s *Server) {
	_ = s.store.Update(func(st *State) error {
		for _, h := range st.Hosts {
			h.LastSeen = time.Now()
			h.Status.Version = st.Tracks[testKernel].RingVersions[h.Ring]
			h.Status.Loaded = nil
			if j := st.releasedJob(testKernel, h.Status.Version); j != nil {
				h.Status.Loaded = []model.LoadedPatch{{Name: j.ModuleName, Enabled: true}}
			}
		}
		return nil
	})
}

func ringVersion(s *Server, ring int) (v int) {
	s.store.View(func(st *State) {
		if t := st.Tracks[testKernel]; t != nil {
			v = t.RingVersions[ring]
		}
	})
	return v
}

func holdReason(s *Server) (r string) {
	s.store.View(func(st *State) {
		if t := st.Tracks[testKernel]; t != nil {
			r = t.AutoHold
		}
	})
	return r
}

// soakPassed 는 첫 번째 링의 관찰 시간이 다 지난 것처럼 만듭니다.
func soakPassed(s *Server) {
	_ = s.store.Update(func(st *State) error {
		st.Tracks[testKernel].RingSetAt[1] = time.Now().Add(-48 * time.Hour)
		return nil
	})
}

func TestAutoDisabledDoesNothing(t *testing.T) {
	s := newAutoServer(t, AutoRollout{})
	addHost(t, s, "gpu-01", 1)
	addBuilt(t, s, "ubuntu")
	s.autoTick()
	if v := ringVersion(s, 1); v != 0 {
		t.Fatalf("꺼져 있으면 배포하면 안 됨: 링 1 v%d", v)
	}
}

func TestAutoFullFlow(t *testing.T) {
	s := newAutoServer(t, AutoRollout{Enabled: true})
	addHost(t, s, "gpu-01", 1)
	addHost(t, s, "gpu-02", 2)
	id := addBuilt(t, s, "ubuntu")

	s.autoTick()
	if v := ringVersion(s, 1); v != 1 {
		t.Fatalf("링 1 에 자동 승인돼야 함: v%d", v)
	}
	s.store.View(func(st *State) {
		if j := st.job(id); j.ApprovedBy != autoWho || j.Status != model.JobReleased {
			t.Fatalf("승인 기록: %+v", j)
		}
	})

	s.autoTick()
	if v := ringVersion(s, 2); v != 0 {
		t.Fatalf("카나리 적용 전에는 승급하면 안 됨: 링 2 v%d", v)
	}

	setHosts(s)
	s.autoTick()
	if v := ringVersion(s, 2); v != 0 {
		t.Fatalf("관찰 시간 전에는 승급하면 안 됨: 링 2 v%d", v)
	}

	soakPassed(s)
	s.autoTick()
	if v := ringVersion(s, 2); v != 1 {
		t.Fatalf("관찰 시간 뒤에는 승급돼야 함: 링 2 v%d", v)
	}
}

func TestAutoSkipsWhatHumansMustApprove(t *testing.T) {
	cases := []struct {
		name   string
		source string
		ring   int
	}{
		{"수동 제출 패치", "manual", 1},
		{"첫 번째 링에 호스트 없음", "ubuntu", 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := newAutoServer(t, AutoRollout{Enabled: true})
			addHost(t, s, "gpu-01", c.ring)
			addBuilt(t, s, c.source)
			s.autoTick()
			if v := ringVersion(s, 1); v != 0 {
				t.Fatalf("자동 승인되면 안 됨: 링 1 v%d", v)
			}
		})
	}
}

func TestAutoSkipsRebuildWithoutNewPatches(t *testing.T) {
	s := newAutoServer(t, AutoRollout{Enabled: true})
	addHost(t, s, "gpu-01", 1)
	addBuilt(t, s, "ubuntu")
	s.autoTick()
	setHosts(s)
	var rebuilt int
	_ = s.store.Update(func(st *State) error {
		j, err := s.createJob(st, testKernel, "tester", false)
		if err != nil {
			return err
		}
		j.Status, j.ModuleName, rebuilt = model.JobBuilt, "kpctl_rebuild", j.ID
		return nil
	})
	s.autoTick()
	s.store.View(func(st *State) {
		if st.job(rebuilt).Status != model.JobBuilt {
			t.Fatal("새 패치 없는 재빌드는 자동 승인되면 안 됨")
		}
	})
}

func TestAutoHoldsOnHostError(t *testing.T) {
	s := newAutoServer(t, AutoRollout{Enabled: true, SoakMinutes: minutes(0)})
	addHost(t, s, "gpu-01", 1)
	addHost(t, s, "gpu-02", 2)
	addBuilt(t, s, "ubuntu")
	s.autoTick()
	setHosts(s)
	_ = s.store.Update(func(st *State) error {
		st.Hosts["gpu-01"].Status.Error = "kpatch load 실패"
		return nil
	})

	s.autoTick()
	if r := holdReason(s); !strings.Contains(r, "kpatch load 실패") {
		t.Fatalf("호스트 오류로 멈춰야 함: %q", r)
	}

	// 오류가 사라져도 사람이 풀 때까지 멈춰 있어야 함
	_ = s.store.Update(func(st *State) error {
		st.Hosts["gpu-01"].Status.Error = ""
		st.Hosts["gpu-01"].LastSeen = time.Now()
		return nil
	})
	addBuilt(t, s, "ubuntu")
	s.autoTick()
	s.store.View(func(st *State) {
		if st.track(testKernel).AutoHoldResolved != "호스트 오류 해결" {
			t.Fatalf("호스트 오류 해결 표시: %q", st.track(testKernel).AutoHoldResolved)
		}
	})
	if v1, v2 := ringVersion(s, 1), ringVersion(s, 2); v1 != 1 || v2 != 0 {
		t.Fatalf("멈춘 동안 배포되면 안 됨: 링 1 v%d, 링 2 v%d", v1, v2)
	}

	callAPI(t, s, "POST", "/api/kernels/"+testKernel+"/auto", `{"hold":false}`, http.StatusOK)
	s.autoTick()
	if v := ringVersion(s, 1); v != 2 {
		t.Fatalf("재개 후 새 작업이 승인돼야 함: 링 1 v%d", v)
	}
}

func TestLegacyAndUnknownHoldsNeverResolveAndUnchangedTicksDoNotSave(t *testing.T) {
	s := newAutoServer(t, AutoRollout{})
	for _, reason := range []string{"수집·빌드 검토 필요: 과거 문제", "시험 빌드 1건의 실패 원인 검토 필요", "과거 시험 빌드 1건의 불가 판정 재검토 필요", "호스트 오류 — 옛 호스트", "job 1 누적 빌드 실패"} {
		if err := s.store.Update(func(st *State) error {
			st.track(testKernel).AutoHold = reason
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		before, err := os.Stat(s.store.path)
		if err != nil {
			t.Fatal(err)
		}
		s.markResolvedHolds()
		s.markResolvedHolds()
		after, err := os.Stat(s.store.path)
		if err != nil {
			t.Fatal(err)
		}
		if !os.SameFile(before, after) || !before.ModTime().Equal(after.ModTime()) {
			t.Fatal("변경 없는 주기에는 state.json을 쓰지 않아야 함")
		}
		s.store.View(func(st *State) {
			if st.track(testKernel).AutoHoldResolved != "" {
				t.Fatalf("기존 문구를 해석하면 안 됨: %s", reason)
			}
		})
	}
	// 구조화된 원인도 확인 불가이면 해결로 표시하지 않습니다.
	if err := s.store.Update(func(st *State) error {
		setAutoHold(st.track(testKernel), "아무 표시 문구", holdUpstream, "missing")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	s.markResolvedHolds()
	s.store.View(func(st *State) {
		if st.track(testKernel).AutoHoldResolved != "" {
			t.Fatal("Upstream 부재는 복구가 아님")
		}
	})
}

func TestHostHoldRequiresFreshSameKernelReport(t *testing.T) {
	s := newAutoServer(t, AutoRollout{})
	now := time.Now()
	track := &model.Track{AutoHold: "임의 문구", AutoHoldKind: holdHost, AutoHoldRef: "node", AutoHoldAt: now.Add(-time.Minute)}
	for _, tc := range []struct {
		name, kernel     string
		seen             time.Time
		exists, resolved bool
	}{
		{"없음", testKernel, now, false, false},
		{"다른 커널로 이동", "6.8.0-147-generic", now, true, false},
		{"연락 끊김", testKernel, now.Add(-time.Hour), true, false},
		{"멈춤 이전 보고", testKernel, now.Add(-2 * time.Minute), true, false},
		{"확인된 정상 보고", testKernel, now, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := &State{Hosts: map[string]*model.Host{}}
			if tc.exists {
				st.Hosts["node"] = &model.Host{Status: model.HostStatus{Kernel: tc.kernel}, LastSeen: tc.seen}
			}
			if got, _ := s.holdResolved(st, testKernel, track); got != tc.resolved {
				t.Fatalf("resolved=%v", got)
			}
		})
	}
}

func TestBuildHoldDoesNotResolveWhenFailedInputsAreMissing(t *testing.T) {
	s := newAutoServer(t, AutoRollout{})
	track := &model.Track{AutoHold: "번역 가능 문구", AutoHoldKind: holdBuild, AutoHoldRef: "1"}
	st := &State{Jobs: []*model.Job{{ID: 1, Kernel: testKernel, Status: model.JobFailed, PatchIDs: []string{"p1", "p2"}},
		{ID: 2, Kernel: testKernel, Status: model.JobBuilt, PatchIDs: []string{"p1"}}}}
	if got, _ := s.holdResolved(st, testKernel, track); got {
		t.Fatal("실패한 패치를 빼고 성공한 빌드는 복구 증거가 아님")
	}
	st.Jobs[1].PatchIDs = append(st.Jobs[1].PatchIDs, "p2", "p3")
	if got, _ := s.holdResolved(st, testKernel, track); !got {
		t.Fatal("기존 입력을 포함한 후속 빌드 성공")
	}
	st.Jobs = append(st.Jobs, &model.Job{ID: 3, Kernel: testKernel, Status: model.JobFailed, PatchIDs: []string{"p1", "p2", "p3"}})
	if got, _ := s.holdResolved(st, testKernel, track); got {
		t.Fatal("더 최신 빌드가 실패하면 이전 성공으로 해결 표시하지 않음")
	}
}

func TestRollbackHoldsAuto(t *testing.T) {
	s := newAutoServer(t, AutoRollout{Enabled: true})
	addHost(t, s, "gpu-01", 1)
	addBuilt(t, s, "ubuntu")
	s.autoTick()
	setHosts(s)

	callAPI(t, s, "POST", "/api/kernels/"+testKernel+"/rollback", `{"version":0}`, http.StatusOK)
	setHosts(s)
	addBuilt(t, s, "ubuntu") // 롤백한 패치를 포함한 새 누적 빌드
	s.autoTick()
	if v := ringVersion(s, 1); v != 0 {
		t.Fatalf("롤백 뒤 자동 재배포되면 안 됨: 링 1 v%d", v)
	}
	if r := holdReason(s); !strings.Contains(r, "롤백") {
		t.Fatalf("멈춤 이유: %q", r)
	}
}

func TestAutoPause(t *testing.T) {
	s := newAutoServer(t, AutoRollout{Enabled: true})
	addHost(t, s, "gpu-01", 1)
	addBuilt(t, s, "ubuntu")

	callAPI(t, s, "POST", "/api/auto", `{"paused":true}`, http.StatusOK)
	s.autoTick()
	if v := ringVersion(s, 1); v != 0 {
		t.Fatalf("일시 중지 중 배포: 링 1 v%d", v)
	}

	callAPI(t, s, "POST", "/api/auto", `{"paused":false}`, http.StatusOK)
	s.autoTick()
	if v := ringVersion(s, 1); v != 1 {
		t.Fatalf("재개 후 배포돼야 함: 링 1 v%d", v)
	}
}

func TestAutoApprovalRechecksOperatorStopAfterVMTest(t *testing.T) {
	for _, tc := range []struct{ name, path, body string }{
		{"pause", "/api/auto", `{"paused":true}`},
		{"disable", "/api/settings", `{"auto_enabled":false}`},
		{"hold", "/api/kernels/" + testKernel + "/auto", `{"hold":true}`},
		{"rollback", "/api/kernels/" + testKernel + "/rollback", `{"version":0}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newAutoServer(t, AutoRollout{Enabled: true})
			stopped := false
			runner := &approvalVMRunner{onTest: func() error {
				req := httptest.NewRequest("POST", tc.path, strings.NewReader(tc.body))
				req.Header.Set("Authorization", "Bearer "+testAdmin)
				rec := httptest.NewRecorder()
				s.Handler().ServeHTTP(rec, req)
				if rec.Code != http.StatusOK {
					return fmt.Errorf("operator stop failed: %d %s", rec.Code, rec.Body)
				}
				stopped = true
				return nil
			}}
			enableApprovalVM(t, s, runner)
			id := addBuilt(t, s, "ubuntu")

			_, _, _, err := s.approveJobWithPrerelease(id, autoWho, false, true)
			if conflict, ok := err.(*httpError); !stopped || !ok || conflict.code != http.StatusConflict {
				t.Fatalf("stop during VM did not prevent approval: stopped=%v err=%v", stopped, err)
			}
			s.store.View(func(st *State) {
				if j := st.job(id); j.Status != model.JobBuilt || j.ApprovedBy != "" || st.track(testKernel).TargetVersion(1) != 0 {
					t.Fatalf("stopped rollout was published: %+v", j)
				}
			})
		})
	}
}

func TestAutoApproveOnly(t *testing.T) {
	s := newAutoServer(t, AutoRollout{Enabled: true, ApproveOnly: true, SoakMinutes: minutes(0)})
	addHost(t, s, "gpu-01", 1)
	addBuilt(t, s, "ubuntu")
	s.autoTick()
	setHosts(s)
	s.autoTick()
	if v1, v2 := ringVersion(s, 1), ringVersion(s, 2); v1 != 1 || v2 != 0 {
		t.Fatalf("approve_only: 링 1 v%d, 링 2 v%d", v1, v2)
	}
}

func TestSignFailureHoldsAuto(t *testing.T) {
	s := newAutoServer(t, AutoRollout{Enabled: true})
	s.cfg.SignCommand = []string{"/nonexistent/sign-file", "{module}"}
	addHost(t, s, "gpu-01", 1)
	addBuilt(t, s, "ubuntu")
	s.autoTick()
	if r := holdReason(s); !strings.Contains(r, "자동 승인 실패") {
		t.Fatalf("서명 실패로 멈춰야 함: %q", r)
	}
	if v := ringVersion(s, 1); v != 0 {
		t.Fatalf("서명 실패 시 배포되면 안 됨: 링 1 v%d", v)
	}
}

// ── 관리자 웹, 추가 API ──

func callAPI(t *testing.T, s *Server, method, path, body string, want int) string {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testAdmin)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != want {
		t.Fatalf("%s %s = %d, want %d: %s", method, path, rec.Code, want, rec.Body)
	}
	return rec.Body.String()
}

func TestWebFiles(t *testing.T) {
	s := newAutoServer(t, AutoRollout{})
	for path, ctype := range map[string]string{
		"/":             "text/html",
		"/ui/app.js":    "text/javascript",
		"/ui/style.css": "text/css",
	} {
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Header().Get("Content-Type"), ctype) {
			t.Errorf("%s: %d %s", path, rec.Code, rec.Header().Get("Content-Type"))
		}
		if !strings.Contains(rec.Header().Get("Content-Security-Policy"), "script-src 'self'") {
			t.Errorf("%s: CSP 없음", path)
		}
		if rec.Body.Len() == 0 {
			t.Errorf("%s: 내용 없음", path)
		}
		if path == "/" && (!strings.Contains(rec.Body.String(), `id="root"`) || !strings.Contains(rec.Body.String(), `type="module"`)) {
			t.Errorf("React 루트 또는 Vite 모듈 진입점 없음")
		}
	}
	for _, path := range []string{"/ui/nope.js", "/nope", "/ui/..%2fweb.go", "/ui/package.json", "/ui/app.js.map", "/ui/src/main.jsx"} {
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s = %d, want 404", path, rec.Code)
		}
	}
}

func TestAdminAPIsNeedToken(t *testing.T) {
	s := newAutoServer(t, AutoRollout{})
	for _, r := range [][2]string{
		{"GET", "/api/status"},
		{"GET", "/api/audit"},
		{"GET", "/api/patches/p0001/diff"},
		{"POST", "/api/auto"},
		{"POST", "/api/kernels/" + testKernel + "/auto"},
	} {
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, httptest.NewRequest(r[0], r[1], strings.NewReader("{}")))
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s = %d, want 401", r[0], r[1], rec.Code)
		}
	}
}

func TestPatchDiff(t *testing.T) {
	s := newAutoServer(t, AutoRollout{})
	addBuilt(t, s, "ubuntu")
	if body := callAPI(t, s, "GET", "/api/patches/p0001/diff", "", http.StatusOK); !strings.Contains(body, "+++ b") {
		t.Fatalf("diff 내용: %q", body)
	}
	callAPI(t, s, "GET", "/api/patches/..%2f..%2fstate/diff", "", http.StatusNotFound)
}

// ── 자동 등록 묶음 ──

func TestBootstrapBundle(t *testing.T) {
	s := newAutoServer(t, AutoRollout{})
	dir := t.TempDir()
	s.cfg.AgentBundleDir = dir
	s.cfg.EnrollTokens = []EnrollToken{{Name: "gpu", Token: "enroll-gpu-0123456789", Ring: 2, RebootPolicy: model.RebootDrain}}

	get := func(token string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "/api/bootstrap/agent.tar.gz", nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, req)
		return rec
	}

	for _, tok := range []string{"", "wrong-token", testAdmin} {
		if rec := get(tok); rec.Code != http.StatusUnauthorized {
			t.Errorf("토큰 %q: %d, want 401", tok, rec.Code)
		}
	}
	if rec := get("enroll-gpu-0123456789"); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("묶음 없을 때: %d, want 503", rec.Code)
	}

	for _, f := range []string{"kpctl-agent", "install-agent.sh"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte(f), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	secret := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secret, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(dir, "leak")); err != nil {
		t.Fatal(err)
	}

	rec := get("enroll-gpu-0123456789")
	if rec.Code != http.StatusOK {
		t.Fatalf("묶음 받기: %d %s", rec.Code, rec.Body)
	}
	gz, err := gzip.NewReader(rec.Body)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]int64{}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		names[h.Name] = h.Mode
	}
	if names["agent/kpctl-agent"] != 0o755 || names["agent/install-agent.sh"] != 0o755 {
		t.Errorf("묶음 내용: %v", names)
	}
	if _, ok := names["agent/leak"]; ok {
		t.Error("심볼릭 링크가 묶음에 들어감")
	}
}

// ── 컨트롤러 제외, VM 없는 서버 ──

func TestRegisterRejectsController(t *testing.T) {
	s := newAutoServer(t, AutoRollout{})
	s.cfg.EnrollTokens = []EnrollToken{{Name: "server", Token: "enroll-server-0123456", Ring: 2, RebootPolicy: model.RebootDrain}}
	self, err := os.Hostname()
	if err != nil {
		t.Fatal(err)
	}
	register := func(name string) int {
		body := `{"enroll_token":"enroll-server-0123456","hostname":"` + name + `","kernel":"` + testKernel + `"}`
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, httptest.NewRequest("POST", "/api/agent/register", strings.NewReader(body)))
		return rec.Code
	}
	for _, name := range []string{self, strings.ToUpper(self), self + ".mgmt.internal"} {
		if code := register(name); code != http.StatusForbidden {
			t.Errorf("%s = %d, want 403", name, code)
		}
	}
	s.store.View(func(st *State) {
		if len(st.Hosts) != 0 {
			t.Errorf("컨트롤러가 등록됨: %d대", len(st.Hosts))
		}
	})
	if code := register("cpu-01"); code != http.StatusOK {
		t.Errorf("일반 호스트 = %d", code)
	}
	s.cfg.AllowSelfEnroll = true
	if code := register(self); code != http.StatusOK {
		t.Errorf("allow_self_enroll = %d", code)
	}
}

func TestRebootWithoutScheduler(t *testing.T) {
	s := newAutoServer(t, AutoRollout{})
	addHost(t, s, "cpu-01", 2)
	callAPI(t, s, "POST", "/api/hosts/cpu-01/reboot", `{}`, http.StatusConflict)
	callAPI(t, s, "POST", "/api/hosts/cpu-01/cordon", `{"on":true}`, http.StatusOK)
	callAPI(t, s, "POST", "/api/hosts/cpu-01/reboot", `{}`, http.StatusConflict) // VM 수를 모르면 0으로 간주하지 않음
}

func TestRebootWaitsForSchedulerCount(t *testing.T) {
	s := newAutoServer(t, AutoRollout{})
	s.cfg.Scheduler.VMCountCommand = []string{"/nonexistent/vm-count", "{host}"}
	addHost(t, s, "cpu-01", 2)
	callAPI(t, s, "POST", "/api/hosts/cpu-01/cordon", `{"on":true}`, http.StatusOK)
	callAPI(t, s, "POST", "/api/hosts/cpu-01/reboot", `{}`, http.StatusConflict)
	// cordon 은 VM 수 확인을 따로 시작합니다. reboot 요청도 VM 수를 바로 기록하므로
	// 기록 시각만 보면 따로 도는 확인이 TempDir 정리 중에 state.json 을 쓸 수 있습니다.
	s.background.Wait()
}
