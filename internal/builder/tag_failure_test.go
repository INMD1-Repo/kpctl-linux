// 이 파일: builder 패키지의 TestTransientTagCheckFailureDoesNotRaiseProblemImmediately 회귀 시험.
package builder

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"kpctl/internal/model"
)

// 원격 태그 확인이 일시적으로 실패해도 바로 수집 문제(→ 자동 배포 멈춤)를 올리지 않습니다.
func TestTransientTagCheckFailureDoesNotRaiseProblemImmediately(t *testing.T) {
	const cur = "6.8.0-987654-generic"
	fakePublishedAPT(t, "noble", "6.8.0-987654.987654")
	root := t.TempDir()
	repo := filepath.Join(root, "ubuntu-noble")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	run(t, repo, "init", "-q")
	run(t, repo, "commit", "-q", "--allow-empty", "-m", "base")
	run(t, repo, "tag", "Ubuntu-6.8.0-987654.987654")
	// 없는 원격 경로라 ls-remote 와 정기 fetch 가 모두 실패합니다.
	run(t, repo, "remote", "add", "origin", filepath.Join(root, "missing-remote"))
	os.WriteFile(filepath.Join(root, "vmlinux-"+cur), []byte("debug"), 0o644)
	var mu sync.Mutex
	var problems []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/builder/kernels" {
			json.NewEncoder(w).Encode(model.HostKernelsResponse{Kernels: []model.HostKernel{
				{Kernel: cur, Signature: "Ubuntu 6.8.0-987654.987654-generic 6.8.12", Hosts: 1}}})
			return
		}
		var req model.UpstreamReport
		if json.NewDecoder(r.Body).Decode(&req) == nil && req.Problem != nil && *req.Problem != "" {
			mu.Lock()
			problems = append(problems, *req.Problem)
			mu.Unlock()
		}
		w.Write([]byte(`{}`))
	}))
	defer server.Close()
	no := false
	b, err := New(&Config{ControllerURL: server.URL, Series: "noble", GitRoot: root, DebugDir: root, AutoDebugSymbols: &no})
	if err != nil {
		t.Fatal(err)
	}
	b.UpdatesAvailable() // 1: 원격 확인
	k := b.kernels()[0]
	if _, err := b.discover(k); err == nil {
		t.Fatal("정기 fetch 실패가 필요")
	} // 2: 정기 수집
	if len(problems) != 0 {
		t.Fatalf("일시 실패로 수집 문제를 올리면 안 됨: %v", problems)
	}
	b.UpdatesAvailable()
	if len(problems) != 1 || !strings.Contains(problems[0], "연속 실패") {
		t.Fatalf("연속 실패는 알려야 함: %v", problems)
	}
	// 원격 확인이 다시 되면 문제 표시를 지웁니다.
	remote := t.TempDir()
	run(t, remote, "init", "-q", "--bare")
	run(t, repo, "remote", "set-url", "origin", remote)
	run(t, repo, "push", "-q", "origin", "--tags")
	b.UpdatesAvailable()
	if b.lastProblem[cur] != "" {
		t.Fatalf("복구되면 문제를 지워야 함: %q", b.lastProblem[cur])
	}
	if b.tagFailures[cur] != 0 {
		t.Fatal("성공 시 공유 카운터 초기화")
	}
	// 태그 확인 뒤의 진짜 환경 오류는 횟수에 넣지 않으며 원격 성공으로 지우지 않습니다.
	k.Vmlinux = filepath.Join(root, "missing-vmlinux")
	if _, err := b.discover(k); err == nil {
		t.Fatal("입력 누락 환경 오류가 필요")
	}
	problem := b.lastProblem[cur]
	if problem == "" || b.tagFailures[cur] != 0 {
		t.Fatalf("환경 오류는 카운터 대상 아님: %q %v", problem, b.tagFailures)
	}
	b.UpdatesAvailable()
	if b.lastProblem[cur] != problem {
		t.Fatal("태그 성공으로 다른 문제를 지우면 안 됨")
	}
}
