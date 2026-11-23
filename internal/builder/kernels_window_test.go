// 이 파일: builder 패키지의 TestRecentABIsKeepsLatestFour, TestOutsideReportTracksLatestOfficialPackageAndRetriesFailures, TestKernelsSkipsOutsideRecentWindowBeforePreparation 회귀 시험.
package builder

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"kpctl/internal/model"
)

func TestRecentABIsKeepsLatestFour(t *testing.T) {
	tags := []string{"Ubuntu-6.8.0-136.136", "Ubuntu-6.8.0-140.140", "Ubuntu-6.8.0-141.141", "Ubuntu-6.8.0-142.142",
		"Ubuntu-6.8.0-145.145", "Ubuntu-6.8.0-146.146", "Ubuntu-6.8.0-146.147", "Ubuntu-6.8.0-147.147",
		"Ubuntu-6.8.0-148.148", "Ubuntu-6.8.0-149.149", "Ubuntu-hwe-6.8.0-147.147", "Ubuntu-6.8.0-147.147_foo"}
	r, err := recentABIs("6.8.0", "Ubuntu-6.8.0-147.147", tags, 4)
	if err != nil {
		t.Fatal(err)
	}
	// 정식 배포(147)보다 새 제안 태그는 세지 않고, 같은 ABI 재배포 태그는 하나로 셉니다.
	if !reflect.DeepEqual(r.kept, []int{147, 146, 145, 142}) || r.floor != 142 || r.latest != 147 || r.latestTag != "Ubuntu-6.8.0-147.147" {
		t.Fatalf("범위 %+v", r)
	}
	for kernel, want := range map[string]bool{"6.8.0-136-generic": false, "6.8.0-141-generic": false,
		"6.8.0-142-generic": true, "6.8.0-147-generic": true, "6.8.0-149-generic": true} {
		if got := r.contains(kernel); got != want {
			t.Errorf("%s contains=%v, want %v", kernel, got, want)
		}
	}
	if (kernelRange{}).contains("6.8.0-1-generic") != true {
		t.Fatal("범위를 모르면 제한하지 않아야 함")
	}
}

func TestOutsideReportTracksLatestOfficialPackageAndRetriesFailures(t *testing.T) {
	const kernel = "6.8.0-136-generic"
	const reason = "최근 2개 ABI(147·146) 밖 · 자동 수집하지 않음"
	var mu sync.Mutex
	var reports []model.UpstreamReport
	failNext := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req model.UpstreamReport
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
		}
		mu.Lock()
		reports = append(reports, req)
		failed := failNext
		failNext = false
		mu.Unlock()
		if failed {
			http.Error(w, "try again", http.StatusServiceUnavailable)
			return
		}
		w.Write([]byte(`{}`))
	}))
	defer server.Close()
	b, err := New(&Config{ControllerURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	b.reportOutside(kernel, reason, "Ubuntu-6.8.0-147.147")
	b.reportOutside(kernel, reason, "Ubuntu-6.8.0-147.147") // Same report is suppressed.
	// A reissued package has the same ABI window, but must replace the old tag.
	b.reportOutside(kernel, reason, "Ubuntu-6.8.0-147.148")
	mu.Lock()
	failNext = true
	mu.Unlock()
	b.reportOutside(kernel, reason, "Ubuntu-6.8.0-147.149")
	b.reportOutside(kernel, reason, "Ubuntu-6.8.0-147.149") // Failed report is retried.
	b.reportOutside(kernel, "", "Ubuntu-6.8.0-147.149")     // Range transitions still report.
	mu.Lock()
	defer mu.Unlock()
	if len(reports) != 5 {
		t.Fatalf("reports = %d, want 5", len(reports))
	}
	for i, tag := range []string{"Ubuntu-6.8.0-147.147", "Ubuntu-6.8.0-147.148", "Ubuntu-6.8.0-147.149", "Ubuntu-6.8.0-147.149", "Ubuntu-6.8.0-147.149"} {
		if reports[i].LatestTag != tag || reports[i].Outside == nil {
			t.Fatalf("report %d lost official tag or range: %+v", i, reports[i])
		}
		if i < 4 && (*reports[i].Outside != reason || reports[i].Problem == nil || *reports[i].Problem != "") {
			t.Fatalf("outside report %d did not clear old problem: %+v", i, reports[i])
		}
	}
	if *reports[4].Outside != "" || reports[4].Problem != nil {
		t.Fatalf("inside report must preserve unresolved discovery problems: %+v", reports[4])
	}
}

func TestKernelsSkipsOutsideRecentWindowBeforePreparation(t *testing.T) {
	const old, cur = "6.8.0-987650-generic", "6.8.0-987654-generic"
	fakePublishedAPT(t, "noble", "6.8.0-987654.987654")
	root := t.TempDir()
	repo := filepath.Join(root, "ubuntu-noble")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	run(t, repo, "init", "-q")
	run(t, repo, "commit", "-q", "--allow-empty", "-m", "base")
	for _, tag := range []string{"Ubuntu-6.8.0-987650.987650", "Ubuntu-6.8.0-987652.987652", "Ubuntu-6.8.0-987653.987653", "Ubuntu-6.8.0-987654.987654"} {
		run(t, repo, "tag", tag)
	}
	// 범위 밖 커널은 vmlinux 가 없어도 디버그 심볼 설치를 시도하지 않아야 합니다.
	if err := os.WriteFile(filepath.Join(root, "vmlinux-"+cur), []byte("debug"), 0o644); err != nil {
		t.Fatal(err)
	}
	retired := false
	problems, outside, latest := map[string]string{}, map[string]string{}, map[string]string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/builder/kernels" {
			ks := []model.HostKernel{{Kernel: cur, Signature: "Ubuntu 6.8.0-987654.987654-generic 6.8.12", Hosts: 1}}
			if !retired {
				ks = append(ks, model.HostKernel{Kernel: old, Signature: "Ubuntu 6.8.0-987650.987650-generic 6.8.12", Hosts: 1})
			}
			json.NewEncoder(w).Encode(model.HostKernelsResponse{Kernels: ks})
			return
		}
		var req model.UpstreamReport
		name := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/builder/kernels/"), "/upstream")
		if err := json.NewDecoder(r.Body).Decode(&req); err == nil {
			if req.LatestTag != "" {
				latest[name] = req.LatestTag
			}
			if req.Problem != nil {
				problems[name] = *req.Problem
			}
			if req.Outside != nil {
				outside[name] = *req.Outside
			}
		}
		w.Write([]byte(`{}`))
	}))
	defer server.Close()
	no := false
	b, err := New(&Config{ControllerURL: server.URL, Series: "noble", GitRoot: root, DebugDir: root, MaxKernels: 3,
		AutoDebugSymbols: &no})
	if err != nil {
		t.Fatal(err)
	}
	kernels := b.kernels()
	if len(kernels) != 1 || kernels[0].Kernel != cur {
		t.Fatalf("최근 범위 커널만 수집해야 함: %+v", kernels)
	}
	if !reflect.DeepEqual(b.activeKernels, []string{cur}) {
		t.Fatalf("범위 밖 커널은 정리 보호 대상에서 빠져야 함: %v", b.activeKernels)
	}
	if !strings.Contains(outside[old], "987654·987653·987652") || problems[old] != "" {
		t.Fatalf("범위 밖은 수집 문제가 아닌 별도 상태로 보고하고 이전 문제는 지워야 함: %q %q", outside[old], problems[old])
	}
	if v, ok := outside[cur]; !ok || v != "" {
		t.Fatalf("범위 안 커널은 범위 밖 표시를 지워야 함: %q %v", v, ok)
	}
	for _, kernel := range []string{old, cur} {
		if latest[kernel] != "Ubuntu-6.8.0-987654.987654" {
			t.Fatalf("%s 범위 보고에 공식 최신 태그가 없음: %q", kernel, latest[kernel])
		}
	}

	// 범위 확인이 잠시 실패해도 마지막으로 확인한 범위를 써서 범위 밖 커널을 다시 수집하지 않습니다.
	if err := os.Rename(repo, repo+".off"); err != nil {
		t.Fatal(err)
	}
	if _, err := b.kernelWindow(); err == nil {
		t.Fatal("Git 저장소가 없으면 범위 확인이 실패해야 함")
	}
	b.kernels()
	if !reflect.DeepEqual(b.activeKernels, []string{cur}) {
		t.Fatalf("범위 확인 실패 때 마지막 범위를 써서 범위 밖 커널을 빼야 함: %v", b.activeKernels)
	}
	if err := os.Rename(repo+".off", repo); err != nil {
		t.Fatal(err)
	}

	// 범위 안 커널·직접 지정 모드는 자료 삭제를 거부하고, 범위 밖 커널은 그 커널의 기록만 지웁니다.
	if _, err := b.purgeKernel(cur); err == nil || !strings.Contains(err.Error(), "등록 호스트") {
		t.Fatalf("범위 안 커널 삭제 거부: %v", err)
	}
	if _, err := b.purgeKernel(old); err == nil {
		t.Fatal("범위 밖이어도 사용 중이면 삭제 거부")
	}
	retired = true
	b.cfg.KernelCleanupFreeGiB = -1
	t.Setenv("HOME", t.TempDir())
	b.cfg.WorkDir, b.cfg.DebugHelper = t.TempDir(), filepath.Join(root, "no-helper")
	trial := func(name, kernel string) string {
		dir := filepath.Join(b.cfg.WorkDir, name, "out")
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatal(err)
		}
		os.WriteFile(filepath.Join(dir, "environment-request.json"), []byte(`{"kernel":{"kernel":"`+kernel+`"}}`), 0o640)
		return filepath.Dir(dir)
	}
	oldTrial, curTrial := trial("trial-aaaaaaaaaaaa", old), trial("trial-bbbbbbbbbbbb", cur)
	unknown := filepath.Join(b.cfg.WorkDir, "trial-cccccccccccc")
	os.MkdirAll(unknown, 0o750)
	os.MkdirAll(filepath.Join(b.cfg.WorkDir, "src", old), 0o750)
	vmlinux := filepath.Join(root, "vmlinux-"+old)
	os.WriteFile(vmlinux, []byte("debug"), 0o644)
	summary, err := b.purgeKernel(old)
	if err != nil {
		t.Fatal(err)
	}
	for path, gone := range map[string]bool{oldTrial: true, filepath.Join(b.cfg.WorkDir, "src", old): true, vmlinux: true,
		curTrial: false, unknown: false, filepath.Join(root, "vmlinux-"+cur): false} {
		if _, err := os.Stat(path); os.IsNotExist(err) != gone {
			t.Errorf("%s 삭제=%v 이어야 함", path, gone)
		}
	}
	if !strings.Contains(summary, "기록 2개") {
		t.Fatalf("요약: %q", summary)
	}
	b.cfg.Kernels = []KernelConfig{{Kernel: cur}}
	if _, err := b.purgeKernel(old); err == nil {
		t.Fatal("직접 지정 모드는 삭제를 거부해야 함")
	}
}
