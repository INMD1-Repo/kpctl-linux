// 이 파일: builder 패키지의 TestDiskCleanupRemovesOnlyUnusedKernelData, TestDiskCleanupProtectsLatestRunningAndRegistered, TestDiskLowKeepsAllHostKernelsAndDefersBuildUntilRecovery 회귀 시험.
package builder

import (
	"bytes"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"kpctl/internal/model"
)

const diskOld = "6.8.0-987636-generic"
const diskMid = "6.8.0-987642-generic"
const diskLatest = "6.8.0-987647-generic"

type diskFixture struct {
	b              *Builder
	hosts          []model.HostKernel
	free           uint64
	mu             sync.Mutex
	reports        map[string]model.UpstreamReport
	hostRequests   int
	problemReports int
	nextRequests   int
}

func newDiskFixture(t *testing.T, kernels ...string) *diskFixture {
	t.Helper()
	fakePublishedAPT(t, "noble", "6.8.0-987647.987647")
	root := t.TempDir()
	t.Setenv("HOME", t.TempDir())
	repo := filepath.Join(root, "ubuntu-noble")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	run(t, repo, "init", "-q")
	run(t, repo, "commit", "-q", "--allow-empty", "-m", "base")
	for _, tag := range []string{"Ubuntu-6.8.0-987636.987636", "Ubuntu-6.8.0-987642.987642", "Ubuntu-6.8.0-987647.987647"} {
		run(t, repo, "tag", tag)
	}
	f := &diskFixture{free: 500 << 30, reports: map[string]model.UpstreamReport{}}
	for _, kernel := range kernels {
		abi := strings.TrimSuffix(strings.TrimPrefix(kernel, "6.8.0-"), "-generic")
		f.hosts = append(f.hosts, model.HostKernel{Kernel: kernel, Signature: "Ubuntu 6.8.0-" + abi + "." + abi + "-generic 6.8.12", Hosts: 1})
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.URL.Path == "/api/builder/kernels" {
			f.hostRequests++
			json.NewEncoder(w).Encode(model.HostKernelsResponse{Kernels: f.hosts})
			return
		}
		if r.URL.Path == "/api/builder/next" {
			f.nextRequests++
			w.WriteHeader(http.StatusNoContent)
			return
		}
		var req model.UpstreamReport
		if json.NewDecoder(r.Body).Decode(&req) == nil {
			kernel := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/builder/kernels/"), "/upstream")
			old := f.reports[kernel]
			if req.Problem != nil {
				f.problemReports++
				old.Problem, old.ProblemKind, old.Recovered = req.Problem, req.ProblemKind, req.Recovered
			}
			if req.Outside != nil {
				old.Outside = req.Outside
			}
			if req.Purged != nil {
				old.Purged = req.Purged
			}
			f.reports[kernel] = old
		}
		w.Write([]byte(`{}`))
	}))
	t.Cleanup(server.Close)
	no := false
	var err error
	f.b, err = New(&Config{ControllerURL: server.URL, Series: "noble", GitRoot: root, DebugDir: filepath.Join(root, "debug"), WorkDir: filepath.Join(root, "work"),
		DebugHelper: filepath.Join(root, "no-helper"), AutoDebugSymbols: &no, KernelCleanupFreeGiB: 100, MaxKernels: -1})
	if err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{f.b.cfg.DebugDir, f.b.cfg.WorkDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	f.b.headersRoot = filepath.Join(root, "headers")
	old := diskFreeBytes
	t.Cleanup(func() { diskFreeBytes = old })
	diskFreeBytes = func(string) (uint64, error) { return f.free, nil }
	return f
}

func (f *diskFixture) debug(t *testing.T, kernel string) string {
	t.Helper()
	path := filepath.Join(f.b.cfg.DebugDir, "vmlinux-"+kernel)
	if err := os.WriteFile(path, []byte("debug"), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDiskCleanupRemovesOnlyUnusedKernelData(t *testing.T) {
	f := newDiskFixture(t, diskMid, diskLatest)
	old := f.debug(t, diskOld)
	mid, latest := f.debug(t, diskMid), f.debug(t, diskLatest)
	f.free = 50 << 30
	diskFreeBytes = func(string) (uint64, error) {
		if _, err := os.Stat(old); errors.Is(err, os.ErrNotExist) {
			return 500 << 30, nil
		}
		return f.free, nil
	}
	if got := f.b.kernels(); len(got) != 2 {
		t.Fatalf("정리 후 두 호스트 커널 수집: %+v", got)
	}
	if _, err := os.Stat(old); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("떠난 커널 자료를 지워야 함: %v", err)
	}
	for _, path := range []string{mid, latest} {
		if _, err := os.Stat(path); err != nil {
			t.Fatal(err)
		}
	}
	if req := f.reports[diskOld]; req.Purged == nil || strings.Contains(*req.Purged, "실패") {
		t.Fatalf("정리 결과 보고: %+v", req)
	}
}

func TestDiskCleanupProtectsLatestRunningAndRegistered(t *testing.T) {
	window := kernelRange{latest: 147}
	for _, tc := range []struct {
		kernel, running string
		hosts           []model.HostKernel
		protected       bool
	}{
		{"6.8.0-136-generic", "", nil, false},
		{"6.8.0-147-generic", "", nil, true},
		{"6.8.0-148-generic", "", nil, true},
		{"6.8.0-136-generic", "6.8.0-136-generic", nil, true},
		{"6.8.0-142-generic", "", []model.HostKernel{{Kernel: "6.8.0-142-generic"}}, true},
	} {
		if got := purgeKernelProtection(tc.kernel, tc.hosts, window, tc.running); (got != nil) != tc.protected {
			t.Errorf("%+v: %v", tc, got)
		}
	}
}

func TestDiskLowKeepsAllHostKernelsAndDefersBuildUntilRecovery(t *testing.T) {
	f := newDiskFixture(t, diskOld, diskMid, diskLatest)
	for _, kernel := range []string{diskOld, diskMid, diskLatest} {
		f.debug(t, kernel)
	}
	if err := os.WriteFile(filepath.Join(f.b.cfg.WorkDir, "kernel-retention.json"), []byte(`{"series":"noble","min_abi":999999}`), 0o640); err != nil {
		t.Fatal(err)
	}
	f.free = 50 << 30
	if got := f.b.kernels(); len(got) != 0 {
		t.Fatalf("시험 빌드 준비 보류: %+v", got)
	}
	if !reflect.DeepEqual(f.b.activeKernels, []string{diskOld, diskMid, diskLatest}) {
		t.Fatalf("136·142·147 모두 범위 유지: %v", f.b.activeKernels)
	}
	window, err := f.b.kernelWindow()
	if err != nil || window.floor != 0 {
		t.Fatalf("디스크 경계 없음: %+v %v", window, err)
	}
	for _, kernel := range f.b.activeKernels {
		req := f.reports[kernel]
		if req.Problem == nil || *req.Problem != "디스크 부족 · 빌드 보류 (여유 50.0 GiB < 필요 60 GiB)" || req.ProblemKind != problemDiskSpace || req.Outside != nil && *req.Outside != "" {
			t.Fatalf("디스크 문제만 보고: %+v", req)
		}
		if _, err := os.Stat(filepath.Join(f.b.cfg.DebugDir, "vmlinux-"+kernel)); err != nil {
			t.Fatal(err)
		}
	}
	if f.b.BuildNext() || f.nextRequests != 0 {
		t.Fatal("새 작업을 가져오면 안 됨")
	}
	if _, err := f.b.runBuild(KernelConfig{Kernel: diskOld}, "unused", t.TempDir(), nil); !errors.Is(err, errBuildBusy) {
		t.Fatalf("시험도 보류: %v", err)
	}
	f.free = 500 << 30
	if got := f.b.kernels(); len(got) != 3 || f.b.diskBlocked {
		t.Fatalf("여유 회복 후 재개: %+v", got)
	}
	for _, kernel := range f.b.activeKernels {
		req := f.reports[kernel]
		if req.Problem == nil || *req.Problem != "" || !req.Recovered {
			t.Fatalf("복구 보고: %+v", req)
		}
	}
	f.b.BuildNext()
	if f.nextRequests != 1 {
		t.Fatal("공간 회복 후 작업 요청 재개")
	}
}

func TestDiskCleanupRetriesFailedDeletion(t *testing.T) {
	f := newDiskFixture(t, diskLatest)
	f.debug(t, diskLatest)
	old := filepath.Join(f.b.cfg.DebugDir, "vmlinux-"+diskOld)
	if err := os.MkdirAll(old, 0o755); err != nil {
		t.Fatal(err)
	}
	child := filepath.Join(old, "busy")
	if err := os.WriteFile(child, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	f.free = 50 << 30
	diskFreeBytes = func(string) (uint64, error) {
		if _, err := os.Stat(old); errors.Is(err, os.ErrNotExist) {
			return 500 << 30, nil
		}
		return f.free, nil
	}
	f.b.kernels()
	if !f.b.purgePending[diskOld] || !f.b.diskBlocked {
		t.Fatal("삭제 실패를 남기고 빌드 보류")
	}
	if req := f.reports[diskOld]; req.Purged == nil || !strings.Contains(*req.Purged, "중단") {
		t.Fatalf("실패 보고: %+v", req)
	}
	if err := os.Remove(child); err != nil {
		t.Fatal(err)
	}
	f.b.kernels()
	if f.b.purgePending[diskOld] || f.b.diskBlocked {
		t.Fatal("다음 주기에 다시 지우고 복구")
	}
}

func TestDiskCleanupRechecksHostsBeforeDeletion(t *testing.T) {
	f := newDiskFixture(t, diskOld, diskLatest)
	old := f.debug(t, diskOld)
	f.free = 50 << 30
	f.b.cleanupForDisk(nil, kernelRange{latest: 987647})
	if _, err := os.Stat(old); err != nil {
		t.Fatalf("새로 확인한 사용 커널 보호: %v", err)
	}
}

func TestDiskCleanupRunsCachePolicyAfterUnusedKernelPurge(t *testing.T) {
	f := newDiskFixture(t, diskLatest)
	old := f.debug(t, diskOld)
	marker := filepath.Join(t.TempDir(), "cache-freed")
	calls := filepath.Join(t.TempDir(), "calls")
	t.Setenv("KPCTL_DISK_OLD", old)
	t.Setenv("KPCTL_DISK_FREED", marker)
	t.Setenv("KPCTL_DISK_CALLS", calls)
	helper := filepath.Join(t.TempDir(), "helper")
	script := `#!/bin/sh
set -eu
echo "$1" >> "$KPCTL_DISK_CALLS"
case "$1" in
 kernel-inventory) echo '{"kernels":[]}' ;;
 purge-kernel) echo '{"removed":0,"bytes":0}' ;;
 gc) test ! -e "$KPCTL_DISK_OLD"; touch "$KPCTL_DISK_FREED" ;;
 *) exit 1 ;;
esac
`
	if err := os.WriteFile(helper, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	f.b.cfg.Sandbox = &SandboxConfig{Helper: helper, ProfilesDir: t.TempDir(), RetentionDays: 14}
	diskFreeBytes = func(string) (uint64, error) {
		if _, err := os.Stat(marker); err == nil {
			return 500 << 30, nil
		}
		return 50 << 30, nil
	}
	if !f.b.cleanupForDisk(f.hosts, kernelRange{latest: 987647}) {
		t.Fatal("재생성 가능한 캐시 정리 뒤 공간 회복")
	}
	data, err := os.ReadFile(calls)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "kernel-inventory\npurge-kernel\ngc\n" {
		t.Fatalf("미사용 자료 다음에 캐시 정책 적용: %s", data)
	}
}

func TestDiskRecoveryIsReportedAfterRestartWithDiscoveryDisabled(t *testing.T) {
	f := newDiskFixture(t, diskLatest)
	f.free = 50 << 30
	f.b.cleanupForDisk(f.hosts, kernelRange{latest: 987647})
	f.free = 500 << 30
	cfg := *f.b.cfg
	cfg.Kernels = []KernelConfig{{Kernel: diskLatest}}
	cfg.DiscoverMinutes = intp(0)
	restarted, err := New(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	restarted.BuildNext()
	req := f.reports[diskLatest]
	if req.Problem == nil || *req.Problem != "" || !req.Recovered || !restarted.diskChecked {
		t.Fatalf("첫 작업 확인 때 이전 디스크 문제 복구 보고: %+v", req)
	}
}

func TestUnknownFreeSpaceDoesNotDeleteData(t *testing.T) {
	f := newDiskFixture(t, diskLatest)
	old := f.debug(t, diskOld)
	diskFreeBytes = func(string) (uint64, error) { return 0, errors.New("statfs failed") }
	if f.b.cleanupForDisk(f.hosts, kernelRange{latest: 987647}) {
		t.Fatal("여유 확인 불가이면 보류")
	}
	if _, err := os.Stat(old); err != nil {
		t.Fatalf("확인 불가이면 자동 삭제하지 않음: %v", err)
	}
}

func (f *diskFixture) profile(t *testing.T, minimumMiB int) string {
	t.Helper()
	path := sandboxProfileFixture(t, f.b.headersRoot, diskLatest, "(Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var profile map[string]any
	if err := json.Unmarshal(data, &profile); err != nil {
		t.Fatal(err)
	}
	profile["limits"] = map[string]int{"disk_free_mib": minimumMiB}
	data, err = json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(filepath.Dir(path), "helper")
	script := `#!/bin/sh
set -eu
printf '%s\n' "$*" >> "$0.calls"
case "$1" in
 kernel-inventory) echo '{"kernels":[]}' ;;
 purge-kernel) echo '{"removed":0,"bytes":0}' ;;
 gc) echo '{}' ;;
 *) exit 1 ;;
esac
`
	if err := os.WriteFile(helper, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	f.b.cfg.Sandbox = &SandboxConfig{Profile: path, Helper: helper, RetentionDays: 14}
	f.b.cfg.KernelCleanupFreeGiB = 0
	return path
}

func TestDiskPreventiveCleanupDoesNotBlockBuild(t *testing.T) {
	f := newDiskFixture(t, diskLatest)
	path := f.profile(t, 40960)
	// 준비 설정이나 디스크 전체 크기 대신 실제 프로파일의 빌드 기준(40 GiB)을 씁니다.
	f.b.cfg.Sandbox.Prepare = &SandboxPreparation{MinFreeGiB: 60}
	f.b.cfg.Sandbox.ProfilesDir = filepath.Dir(filepath.Dir(path))
	f.b.cfg.Sandbox.Profile = ""
	old := f.debug(t, diskOld)
	f.free = 51 << 30 // 전체 79 GB인 디스크에서도 가능한 여유. 전체 용량은 판단에 쓰지 않습니다.
	f.b.BuildNext()
	if f.nextRequests != 1 || f.b.diskBlocked {
		t.Fatal("51 GiB는 프로파일의 40 GiB 이상이므로 작업을 받아야 함")
	}
	if _, err := os.Stat(old); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("60 GiB 정리 기준 미만이므로 떠난 커널 정리는 시도: %v", err)
	}
	calls, err := os.ReadFile(f.b.cfg.Sandbox.Helper + ".calls")
	if err != nil || !strings.Contains(string(calls), "kernel-inventory ") || strings.Contains(string(calls), "gc ") {
		t.Fatalf("예방 정리에서는 미사용 커널만 정리하고 캐시 LRU를 호출하지 않음: %s %v", calls, err)
	}
	hostRequests := f.hostRequests
	f.b.BuildNext()
	f.b.cleanupForDisk(f.hosts, kernelRange{latest: 987647}) // 정기 수집 경로도 같은 시간 제한 적용.
	after, err := os.ReadFile(f.b.cfg.Sandbox.Helper + ".calls")
	if err != nil || string(after) != string(calls) || f.hostRequests != hostRequests || f.nextRequests != 2 {
		t.Fatalf("한 시간 안에는 호스트 조회·정리 없이 빌드 진행: %s %v hosts=%d/%d next=%d", after, err, f.hostRequests, hostRequests, f.nextRequests)
	}
	old = f.debug(t, diskOld)
	f.b.diskCleanupAt = time.Now().Add(-time.Hour)
	f.b.BuildNext()
	if _, err := os.Stat(old); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("한 시간이 지나면 새 미사용 커널 정리를 다시 시도: %v", err)
	}
	old = f.debug(t, diskOld)
	restarted, err := New(f.b.cfg)
	if err != nil {
		t.Fatal(err)
	}
	restarted.headersRoot = f.b.headersRoot
	restarted.activeKernels = f.b.activeKernels
	restarted.BuildNext()
	if _, err := os.Stat(old); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("재시작 뒤 첫 예방 정리 허용: %v", err)
	}
	for _, req := range f.reports {
		if req.Problem != nil && *req.Problem != "" {
			t.Fatalf("예방 정리만으로 웹 문제를 보고하면 안 됨: %+v", req)
		}
	}
	space, err := f.b.diskSpace(diskLatest)
	if err != nil || space.minimum != 40<<30 || space.cleanup != 60<<30 {
		t.Fatalf("프로파일 우선, 정리·보류 기준 분리: %+v %v", space, err)
	}
	if _, err := f.b.runBuild(KernelConfig{Kernel: diskLatest}, "unused", t.TempDir(), nil); errors.Is(err, errDiskSpace) {
		t.Fatalf("실제 빌드 진입도 60 GiB 예방 정리 기준으로 막지 않음: %v", err)
	}
}

func TestDiskShortageRetriesCacheOnlyToBuildMinimumAndDeduplicatesLogs(t *testing.T) {
	f := newDiskFixture(t, diskLatest)
	path := f.profile(t, 61440)
	f.b.cfg.Sandbox.ProfilesDir = filepath.Dir(filepath.Dir(path))
	f.b.cfg.Sandbox.Profile = ""
	f.free = 48 << 30
	var logs bytes.Buffer
	oldWriter := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(oldWriter) })
	for i := 0; i < 2; i++ {
		f.b.BuildNext()
	}
	calls, err := os.ReadFile(f.b.cfg.Sandbox.Helper + ".calls")
	if err != nil || strings.Count(string(calls), "kernel-inventory ") != 2 || strings.Count(string(calls), "gc ") != 2 {
		t.Fatalf("부족 구간은 매번 커널 자료 확인 후 캐시 정리: %s %v", calls, err)
	}
	for _, call := range strings.Split(string(calls), "\n") {
		if strings.HasPrefix(call, "gc ") && !strings.Contains(call, "--min-free-gib 60 ") {
			t.Fatalf("캐시 정리 목표는 정리 기준 80이 아닌 빌드 최소 60 GiB: %s", call)
		}
	}
	if f.nextRequests != 0 || !f.b.diskBlocked || f.problemReports != 1 || strings.Count(logs.String(), "디스크 부족 · 빌드 보류") != 1 || strings.Contains(logs.String(), "디스크 정리 시도") {
		t.Fatalf("같은 부족 수치의 로그·문제 보고는 한 번: reports=%d next=%d logs=%s", f.problemReports, f.nextRequests, logs.String())
	}
	f.free = 49 << 30
	f.b.BuildNext()
	if f.problemReports != 2 || strings.Count(logs.String(), "디스크 부족 · 빌드 보류") != 2 || !strings.Contains(logs.String(), "여유 49.0 GiB") {
		t.Fatalf("부족 수치가 바뀌면 로그·보고 갱신: reports=%d logs=%s", f.problemReports, logs.String())
	}
}

func TestDiskProfileMinimumControlsHoldAndRecovery(t *testing.T) {
	for _, recoverAfterPurge := range []bool{false, true} {
		t.Run(map[bool]string{false: "still-low", true: "recovered-by-purge"}[recoverAfterPurge], func(t *testing.T) {
			f := newDiskFixture(t, diskLatest)
			f.profile(t, 61440)
			old := f.debug(t, diskOld)
			f.free = 48 << 30
			diskFreeBytes = func(string) (uint64, error) {
				if _, err := os.Stat(old); recoverAfterPurge && errors.Is(err, os.ErrNotExist) {
					return 61 << 30, nil // 정리 목표 80 GiB까지 회복할 필요는 없습니다.
				}
				return f.free, nil
			}
			f.b.BuildNext()
			if _, err := os.Stat(old); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("먼저 떠난 커널을 정리: %v", err)
			}
			if recoverAfterPurge {
				if f.b.diskBlocked || f.nextRequests != 1 {
					t.Fatal("정리로 60 GiB 이상 회복하면 진행")
				}
			} else {
				req := f.reports[diskLatest]
				if !f.b.diskBlocked || f.nextRequests != 0 || req.Problem == nil || *req.Problem != "디스크 부족 · 빌드 보류 (여유 48.0 GiB < 필요 60 GiB)" || req.ProblemKind != problemDiskSpace {
					t.Fatalf("60 GiB 미만에서만 수치 포함 디스크 문제·보류: %+v", req)
				}
				f.free = 60 << 30 // 정확히 최소 여유이면 충분합니다.
				f.b.BuildNext()
				if f.b.diskBlocked || f.nextRequests != 1 {
					t.Fatal("80 GiB 미만이어도 60 GiB 회복 시 진행")
				}
			}
			req := f.reports[diskLatest]
			if req.Problem == nil || *req.Problem != "" || !req.Recovered || req.ProblemKind != problemDiskSpace {
				t.Fatalf("disk_space 종류를 유지하며 회복 표시: %+v", req)
			}
		})
	}
}

func TestDiskCleanupSettingDoesNotChangeBuildMinimum(t *testing.T) {
	f := newDiskFixture(t, diskLatest)
	f.profile(t, 40960)
	f.b.cfg.KernelCleanupFreeGiB = 70
	f.free = 51 << 30
	if !f.b.cleanupForDisk(f.hosts, kernelRange{latest: 987647}) || f.b.diskBlocked {
		t.Fatal("명시 정리 기준 70 GiB는 보류 기준이 아님")
	}
	if req := f.reports[diskLatest]; req.Problem != nil && *req.Problem != "" {
		t.Fatalf("40 GiB 이상이면 문제 없음: %+v", req)
	}
	f.free = 39 << 30
	if f.b.cleanupForDisk(f.hosts, kernelRange{latest: 987647}) {
		t.Fatal("프로파일의 40 GiB 미만일 때 보류")
	}
	f.free = 40 << 30
	if !f.b.cleanupForDisk(f.hosts, kernelRange{latest: 987647}) {
		t.Fatal("정리 기준 미만이어도 빌드 최소 여유 회복 시 진행")
	}
}

func TestDiskMinimumFallbackAndMiBPrecision(t *testing.T) {
	f := newDiskFixture(t, diskLatest)
	path := f.profile(t, 40961)
	space, err := f.b.diskSpace(diskLatest)
	if err != nil || space.minimum != 40961<<20 || space.cleanup != (40961<<20)+(20<<30) {
		t.Fatalf("프로파일 MiB를 GiB로 반올림하지 않음: %+v %v", space, err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	f.b.cfg.Sandbox.Prepare = &SandboxPreparation{MinFreeGiB: 45}
	space, err = f.b.diskSpace(diskLatest)
	if err != nil || space.minimum != 45<<30 {
		t.Fatalf("프로파일이 없으면 기존 준비 설정 적용: %+v %v", space, err)
	}
	f.b.cfg.Sandbox.Prepare = nil
	space, err = f.b.diskSpace(diskLatest)
	if err != nil || space.minimum != 60<<30 {
		t.Fatalf("기본 빌드 최소 여유는 60 GiB: %+v %v", space, err)
	}
}
