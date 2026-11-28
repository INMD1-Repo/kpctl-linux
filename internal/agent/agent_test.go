// 이 파일: agent 패키지의 TestApplyLatestCumulativeWithoutIntermediateDownloads, TestCycleChecksModuleBeforeLoadAndReportsFailure, TestLoadRefusesConflictingPatches 회귀 시험.
package agent

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"kpctl/internal/client"
	"kpctl/internal/klpcheck/klptest"
	"kpctl/internal/model"
)

const testKernel = "6.8.0-85-generic"

func TestRunOnceRequiresRegistrationAndFirstReport(t *testing.T) {
	for _, tc := range []struct {
		name           string
		registerStatus int
		reportStatus   int
		wantStep       string
		wantStatus     int
		wantToken      string
	}{
		{"registration rejected", http.StatusForbidden, http.StatusOK, "등록 실패", http.StatusForbidden, ""},
		{"new token rejected", http.StatusOK, http.StatusUnauthorized, "보고 실패", http.StatusUnauthorized, ""},
		{"report unavailable", http.StatusOK, http.StatusServiceUnavailable, "보고 실패", http.StatusServiceUnavailable, "test-token"},
		{"registration and report accepted", http.StatusOK, http.StatusOK, "", 0, "test-token"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, _ := newTestAgent(t)
			a.cfg.EnrollToken = "test-enroll-token"
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/api/agent/register":
					if tc.registerStatus != http.StatusOK {
						http.Error(w, "registration rejected", tc.registerStatus)
						return
					}
					_ = json.NewEncoder(w).Encode(model.RegisterResponse{HostID: "test-host", HostToken: "test-token"})
				case "/api/agent/report":
					if tc.registerStatus != http.StatusOK || r.Header.Get("Authorization") != "Bearer test-token" {
						t.Error("report sent without accepted registration")
					}
					if tc.reportStatus != http.StatusOK {
						http.Error(w, "report rejected", tc.reportStatus)
						return
					}
					_ = json.NewEncoder(w).Encode(model.ReportResponse{})
				default:
					t.Errorf("unexpected request %s", r.URL.Path)
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			c, err := client.New(server.URL, "", "")
			if err != nil {
				t.Fatal(err)
			}
			a.c = c
			err = a.RunOnce()
			var httpErr *client.HTTPError
			if tc.wantStatus == 0 {
				if err != nil {
					t.Fatalf("successful one-shot: %v", err)
				}
			} else if !errors.As(err, &httpErr) || httpErr.Status != tc.wantStatus || !strings.Contains(err.Error(), tc.wantStep) {
				t.Fatalf("incorrect one-shot error: %v", err)
			}
			if a.st.HostToken != tc.wantToken {
				t.Fatal("one-shot kept the wrong enrollment state")
			}
		})
	}
}

func TestApplyLatestCumulativeWithoutIntermediateDownloads(t *testing.T) {
	a, _ := newTestAgent(t)
	old := previousVersion(t, a)
	content := klptest.Module(klptest.Options{})
	var mu sync.Mutex
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		if r.URL.Path != "/artifacts/latest-v7.ko" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(content)
	}))
	defer server.Close()
	c, err := client.New(server.URL, "test-host-token", "")
	if err != nil {
		t.Fatal(err)
	}
	a.c = c
	d := model.DesiredPatch{Version: 7, ModuleName: "kpctl_test_v7", URL: "/artifacts/latest-v7.ko", SHA256: fmt.Sprintf("%x", sha256.Sum256(content))}
	if !a.apply(d) || a.lastErr != "" || a.st.Version != 7 {
		t.Fatalf("direct update failed: %s", a.lastErr)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(paths) != 1 || paths[0] != d.URL {
		t.Fatalf("unexpected intermediate downloads: %v", paths)
	}
	if a.moduleLoaded(old) || len(a.st.Installed) != 1 || a.st.Installed[0] != d.ModuleName {
		t.Fatal("must leave only the verified cumulative module installed")
	}
}

func TestCycleChecksModuleBeforeLoadAndReportsFailure(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts klptest.Options
		bad  bool
	}{
		{"valid", klptest.Options{}, false},
		{"mcount livepatch reference", klptest.Options{Ftrace: "__mcount_loc"}, true},
		{"path object", klptest.Options{Object: "net/rxrpc/rxrpc"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, root := newTestAgent(t)
			old := previousVersion(t, a)
			a.st.HostID, a.st.HostToken = "test-host", "test-token"
			// Record every kpatch command, including an attempted load/install
			// that fails. Existing module state alone cannot prove no call occurred.
			script, err := os.ReadFile(a.cfg.KpatchBin)
			if err != nil {
				t.Fatal(err)
			}
			bin := filepath.Join(root, "kpatch")
			writeTestFile(t, bin, strings.Replace(string(script), "#!/bin/bash\n", "#!/bin/bash\nprintf '%s\\n' \"$*\" >> \"$FAKE_ROOT/kpatch.calls\"\n", 1))
			if err := os.Chmod(bin, 0o700); err != nil {
				t.Fatal(err)
			}
			a.cfg.KpatchBin = bin
			content := klptest.Module(tc.opts)
			d := model.DesiredPatch{Version: 2, ModuleName: "kpctl_test_v2", URL: "/module.ko", SHA256: fmt.Sprintf("%x", sha256.Sum256(content))}
			var mu sync.Mutex
			var reports []model.ReportRequest
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case d.URL:
					_, _ = w.Write(content)
				case "/api/agent/report":
					var report model.ReportRequest
					if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
						t.Error(err)
					}
					mu.Lock()
					reports = append(reports, report)
					mu.Unlock()
					_ = json.NewEncoder(w).Encode(model.ReportResponse{Desired: d})
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			a.c, err = client.New(server.URL, a.st.HostToken, "")
			if err != nil {
				t.Fatal(err)
			}
			a.Cycle()
			mu.Lock()
			defer mu.Unlock()
			if len(reports) != 2 {
				t.Fatalf("expected before/after reports: %+v", reports)
			}
			calls, err := os.ReadFile(filepath.Join(root, "kpatch.calls"))
			if tc.bad {
				if !os.IsNotExist(err) || len(calls) != 0 {
					t.Fatalf("rejected module must never invoke kpatch: %q, %v", calls, err)
				}
				if !strings.Contains(reports[1].Status.Error, "라이브패치 모듈 ELF 검사 실패") || a.st.FailedVersion != d.Version || a.st.Version != 1 {
					t.Fatalf("ELF failure must use existing host error reporting: %+v, %+v", reports[1], a.st)
				}
				if !a.patchEnabled(old) || len(a.st.Installed) != 1 || a.st.Installed[0] != old {
					t.Fatal("must preserve already-loaded module and boot installation")
				}
				if _, err := os.Stat(filepath.Join(a.cfg.StateDir, "modules", d.ModuleName+".ko.part")); !os.IsNotExist(err) {
					t.Fatal("rejected download must be removed")
				}
			} else if err != nil || !strings.Contains(string(calls), "load ") || !strings.Contains(string(calls), "install ") || reports[1].Status.Error != "" || a.st.Version != d.Version {
				t.Fatalf("valid module must load, install and report success: %q, %v, %+v", calls, err, reports[1])
			}
		})
	}
}

func writeTestFile(t *testing.T, path, value string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
}

func newTestAgent(t *testing.T) (*Agent, string) {
	t.Helper()
	root := t.TempDir()
	fake, err := filepath.Abs("../../test/fake/kpatch")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("FAKE_ROOT", root)
	cfg := &Config{
		ControllerURL:     "http://127.0.0.1:1",
		StateDir:          filepath.Join(root, "state"),
		KpatchBin:         fake,
		KpatchInstallDir:  filepath.Join(root, "installed"),
		ModulePrefix:      "kpctl_",
		LivepatchSysfs:    filepath.Join(root, "sys/livepatch"),
		ModuleSysfs:       filepath.Join(root, "sys/module"),
		SysfsRoot:         filepath.Join(root, "sys"),
		DistroReleasePath: filepath.Join(root, "etc/os-release"),
		OSReleasePath:     filepath.Join(root, "proc/osrelease"),
	}
	for _, dir := range []string{cfg.StateDir, cfg.LivepatchSysfs, cfg.ModuleSysfs} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	writeTestFile(t, cfg.DistroReleasePath, "ID=ubuntu\n")
	writeTestFile(t, cfg.OSReleasePath, testKernel)
	a, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return a, root
}

func setTestPatch(t *testing.T, a *Agent, name, enabled, transition string) {
	t.Helper()
	dir := filepath.Join(a.cfg.LivepatchSysfs, name)
	writeTestFile(t, filepath.Join(dir, "enabled"), enabled)
	writeTestFile(t, filepath.Join(dir, "transition"), transition)
	if err := os.MkdirAll(filepath.Join(a.cfg.ModuleSysfs, name), 0o700); err != nil {
		t.Fatal(err)
	}
}

func testCandidate(t *testing.T, a *Agent) (model.DesiredPatch, string) {
	t.Helper()
	content := "signed cumulative module v2"
	d := model.DesiredPatch{Version: 2, ModuleName: "kpctl_test_v2", SHA256: fmt.Sprintf("%x", sha256.Sum256([]byte(content)))}
	path := filepath.Join(a.cfg.StateDir, "modules", d.ModuleName+".ko")
	writeTestFile(t, path, content)
	return d, path
}

func previousVersion(t *testing.T, a *Agent) string {
	t.Helper()
	name := "kpctl_test_v1"
	setTestPatch(t, a, name, "1", "0")
	a.st.Version, a.st.ModuleName = 1, name
	a.st.Installed = []string{name}
	writeTestFile(t, filepath.Join(a.cfg.KpatchInstallDir, testKernel, name+".ko"), "previous module")
	writeTestFile(t, filepath.Join(a.cfg.StateDir, "modules", name+".ko"), "previous module")
	return name
}

func TestLoadRefusesConflictingPatches(t *testing.T) {
	for _, tc := range []struct{ name, enabled, transition, want string }{
		{"canonical_livepatch", "1", "0", "외부 라이브패치"},
		{"canonical_livepatch", "0", "1", "외부 라이브패치"},
		{"canonical_livepatch", "invalid", "0", "올바르지"},
		{"kpctl_other", "1", "1", "전환이 끝나지"},
	} {
		t.Run(tc.name+tc.enabled+tc.transition, func(t *testing.T) {
			a, _ := newTestAgent(t)
			previousVersion(t, a)
			setTestPatch(t, a, tc.name, tc.enabled, tc.transition)
			d, _ := testCandidate(t, a)
			// URL 도 주지 않습니다. 상태 충돌은 다운로드와 kpatch 실행 전에 거부해야 합니다.
			err := a.loadVersion(d)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("충돌을 먼저 거부해야 함: %v", err)
			}
			if a.st.Version != 1 || readTrim(filepath.Join(a.cfg.LivepatchSysfs, tc.name, "enabled")) != tc.enabled {
				t.Fatal("거부할 때 기존 보호와 버전을 바꾸면 안 됨")
			}
		})
	}
}

func TestLoadRefusesUnreadablePatchState(t *testing.T) {
	a, _ := newTestAgent(t)
	setTestPatch(t, a, "canonical_livepatch", "1", "0")
	if err := os.Remove(filepath.Join(a.cfg.LivepatchSysfs, "canonical_livepatch", "transition")); err != nil {
		t.Fatal(err)
	}
	if err := a.checkCanLoad("kpctl_test_v2"); err == nil {
		t.Fatal("상태를 확인할 수 없으면 새 패치를 올리면 안 됨")
	}
	if loaded := a.loadedPatches(); len(loaded) != 1 || !loaded[0].Transition {
		t.Fatalf("상태를 읽지 못한 패치를 전환 완료로 보고하면 안 됨: %+v", loaded)
	}
}

func TestTransitionRequiresActiveStablePatch(t *testing.T) {
	for _, tc := range []struct {
		enabled, transition string
		want                bool
	}{
		{"1", "0", true}, {"1", "1", false}, {"0", "0", false}, {"1", "", false},
	} {
		t.Run(tc.enabled+tc.transition, func(t *testing.T) {
			a, _ := newTestAgent(t)
			setTestPatch(t, a, "kpctl_test", tc.enabled, tc.transition)
			if got := a.waitTransition("kpctl_test", 0); got != tc.want {
				t.Fatalf("완료 확인 = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestIncompleteTransitionPreservesPreviousBootPatch(t *testing.T) {
	a, _ := newTestAgent(t)
	old := previousVersion(t, a)
	d, path := testCandidate(t, a)
	setTestPatch(t, a, d.ModuleName, "1", "1")
	if err := a.activateVersion(d, path, 0); err == nil {
		t.Fatal("전환 중이면 성공 처리하면 안 됨")
	}
	if a.st.Version != 1 || !a.patchEnabled(old) {
		t.Fatal("전환 중 이전 버전을 정리하면 안 됨")
	}
	if _, err := os.Stat(filepath.Join(a.cfg.KpatchInstallDir, testKernel, old+".ko")); err != nil {
		t.Fatal("이전 부팅용 패치를 보존해야 함", err)
	}
	if _, err := os.Stat(filepath.Join(a.cfg.KpatchInstallDir, testKernel, d.ModuleName+".ko")); !os.IsNotExist(err) {
		t.Fatal("전환을 확인하지 못한 후보는 부팅용으로 설치하면 안 됨")
	}
}

func TestRetryAfterLoadFailure(t *testing.T) {
	a, root := newTestAgent(t)
	previousVersion(t, a)
	d, path := testCandidate(t, a)
	fail := filepath.Join(root, "fail-load")
	writeTestFile(t, fail, "1")
	if err := a.activateVersion(d, path, 0); err == nil {
		t.Fatal("load 실패를 보고해야 함")
	}
	if a.st.Version != 1 || len(a.st.Installed) != 1 {
		t.Fatal("실패한 후보는 설치하거나 성공으로 기록하면 안 됨")
	}
	if err := os.Remove(fail); err != nil {
		t.Fatal(err)
	}
	if err := a.activateVersion(d, path, 0); err != nil {
		t.Fatal("재시도는 성공해야 함", err)
	}
	if a.st.Version != 2 || a.moduleLoaded("kpctl_test_v1") {
		t.Fatal("전환 완료 뒤 이전 모듈을 정리해야 함")
	}
}

func TestResumeAlreadyInstalledModule(t *testing.T) {
	a, _ := newTestAgent(t)
	previousVersion(t, a)
	d, path := testCandidate(t, a)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// install 직후 상태 저장 전에 프로세스가 중단된 경우를 흉내 냅니다.
	writeTestFile(t, filepath.Join(a.cfg.KpatchInstallDir, testKernel, d.ModuleName+".ko"), string(data))
	if err := a.activateVersion(d, path, 0); err != nil {
		t.Fatal("동일 파일은 재설치 없이 이어가야 함", err)
	}
	if a.st.Version != d.Version || len(a.st.Installed) != 1 || a.st.Installed[0] != d.ModuleName {
		t.Fatalf("복구 후 상태가 올바르지 않음: %+v", a.st)
	}
}

func TestInstalledModuleHashMismatch(t *testing.T) {
	a, _ := newTestAgent(t)
	old := previousVersion(t, a)
	d, path := testCandidate(t, a)
	writeTestFile(t, filepath.Join(a.cfg.KpatchInstallDir, testKernel, d.ModuleName+".ko"), "different module")
	if err := a.activateVersion(d, path, 0); err == nil || !strings.Contains(err.Error(), "해시") {
		t.Fatalf("다른 설치 파일을 재사용하면 안 됨: %v", err)
	}
	if a.st.Version != 1 || readTrim(filepath.Join(a.cfg.KpatchInstallDir, testKernel, old+".ko")) != "previous module" {
		t.Fatal("해시 충돌 시 이전 설치본을 정리하면 안 됨")
	}
}

func TestFailedUnloadPreservesInstalledModule(t *testing.T) {
	a, root := newTestAgent(t)
	old := previousVersion(t, a)
	writeTestFile(t, filepath.Join(root, "fail-unload"), "1")
	bin := filepath.Join(root, "bin")
	rmmod := filepath.Join(bin, "rmmod")
	writeTestFile(t, rmmod, "#!/bin/sh\nexit 1\n")
	if err := os.Chmod(rmmod, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	if err := a.removeOurModules(""); err == nil {
		t.Fatal("unload 실패를 보고해야 함")
	}
	if len(a.st.Installed) != 1 || !a.moduleLoaded(old) {
		t.Fatal("실패한 모듈의 추적 정보를 보존해야 함")
	}
	for _, path := range []string{filepath.Join(a.cfg.KpatchInstallDir, testKernel, old+".ko"), filepath.Join(a.cfg.StateDir, "modules", old+".ko")} {
		if _, err := os.Stat(path); err != nil {
			t.Fatal("unload 실패한 모듈 파일을 보존해야 함", err)
		}
	}
}

func TestRecoveredPatchClearsFailure(t *testing.T) {
	a, _ := newTestAgent(t)
	name := previousVersion(t, a)
	a.lastErr = "전환 지연"
	a.st.FailedVersion, a.st.FailedAt = 1, time.Now()
	d := model.DesiredPatch{Version: 1, ModuleName: name, SHA256: fmt.Sprintf("%x", sha256.Sum256([]byte("previous module")))}
	if !a.apply(d) || a.lastErr != "" || !a.st.FailedAt.IsZero() {
		t.Fatal("실제 정상 상태로 복구되면 예전 오류도 지워야 함")
	}
}

func TestActivateChecksForeignPatchAgain(t *testing.T) {
	a, _ := newTestAgent(t)
	previousVersion(t, a)
	d, path := testCandidate(t, a)
	if err := a.checkCanLoad(d.ModuleName); err != nil {
		t.Fatal(err)
	}
	// 모듈 다운로드 도중 다른 공급자가 패치를 올린 상황입니다.
	setTestPatch(t, a, "canonical_livepatch", "1", "0")
	if err := a.activateVersion(d, path, 0); err == nil {
		t.Fatal("load 직전에도 외부 패치를 확인해야 함")
	}
	if !a.patchEnabled("canonical_livepatch") || a.st.Version != 1 {
		t.Fatal("외부 패치의 보호를 유지해야 함")
	}
}

func TestDisabledForeignPatchDoesNotBlock(t *testing.T) {
	a, _ := newTestAgent(t)
	setTestPatch(t, a, "canonical_livepatch", "0", "0")
	d, path := testCandidate(t, a)
	if err := a.activateVersion(d, path, 0); err != nil {
		t.Fatal("비활성이고 전환도 끝난 외부 패치는 차단하지 않음", err)
	}
}

func TestCleanupRetryAfterInterruptedUninstall(t *testing.T) {
	a, root := newTestAgent(t)
	old := previousVersion(t, a)
	d, path := testCandidate(t, a)
	fail := filepath.Join(root, "fail-uninstall")
	writeTestFile(t, fail, "1")
	if err := a.activateVersion(d, path, 0); err == nil || !strings.Contains(err.Error(), "정리 실패") {
		t.Fatalf("이전 부팅용 설치본 정리 실패를 보고해야 함: %v", err)
	}
	if len(a.st.Installed) != 2 {
		t.Fatal("정리 실패한 설치본의 추적 정보를 보존해야 함")
	}
	a.lastErr = "이전 설치본 정리 실패"
	a.st.FailedVersion, a.st.FailedAt = d.Version, time.Now()
	if err := os.Remove(fail); err != nil {
		t.Fatal(err)
	}
	// uninstall 이 끝난 뒤 상태 저장 전에 중단된 경우입니다.
	if err := os.Remove(a.installedModulePath(old)); err != nil {
		t.Fatal(err)
	}
	// URL 없이도 실패 쿨다운을 건너뛰고 정리만 바로 재시도해야 합니다.
	if !a.apply(d) || a.lastErr != "" || !a.st.FailedAt.IsZero() {
		t.Fatalf("다운로드 없이 정리만 재시도해야 함: %s", a.lastErr)
	}
	if len(a.st.Installed) != 1 || a.st.Installed[0] != d.ModuleName {
		t.Fatalf("부팅용 설치본은 목표 버전 하나여야 함: %v", a.st.Installed)
	}
}
