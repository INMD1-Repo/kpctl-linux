// 이 파일: builder 패키지의 TestReadyKernelOnlyClearsProblemAfterCompleteDiscovery, TestOfficialPackageIndex, TestPublishedVersionUsesKernelSourceVersion 회귀 시험.
package builder

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"kpctl/internal/model"
)

func TestReadyKernelOnlyClearsProblemAfterCompleteDiscovery(t *testing.T) {
	const kernel = "6.8.0-987654-generic"
	const tag = "Ubuntu-6.8.0-987654.987654"
	fakePublishedAPT(t, "noble", "6.8.0-987654.987654")
	root := t.TempDir()
	repo := filepath.Join(root, "ubuntu-noble")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	run(t, repo, "init", "-q")
	run(t, repo, "commit", "-q", "--allow-empty", "-m", "base")
	run(t, repo, "tag", tag)
	run(t, repo, "remote", "add", "origin", repo)
	if err := os.WriteFile(filepath.Join(root, "vmlinux-"+kernel), []byte("debug"), 0o644); err != nil {
		t.Fatal(err)
	}
	problem, collected := "이전 시험 빌드 검토 필요", ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/builder/kernels" {
			json.NewEncoder(w).Encode(model.HostKernelsResponse{Kernels: []model.HostKernel{{Kernel: kernel, Signature: "Ubuntu 6.8.0-987654.987654-generic 6.8.12", Hosts: 1}}})
			return
		}
		var req model.UpstreamReport
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
		}
		if req.Problem != nil && req.ProblemKind == "" {
			problem = *req.Problem
		}
		if req.CollectedTag != "" {
			if problem != "" {
				t.Error("문제 해제 전에 수집 완료를 보고하면 안 됨")
			}
			collected = req.CollectedTag
		}
		w.Write([]byte(`{}`))
	}))
	defer server.Close()
	b, err := New(&Config{ControllerURL: server.URL, Series: "noble", GitRoot: root, DebugDir: root})
	if err != nil {
		t.Fatal(err)
	}
	kernels := b.kernels()
	if len(kernels) != 1 || problem == "" {
		t.Fatal("수집 준비 조건만 확인해 이전 시험 빌드 문제를 지우면 안 됨")
	}
	if _, err := b.discover(kernels[0]); err != nil {
		t.Fatal(err)
	}
	if problem != "" || collected != tag {
		t.Fatalf("끝까지 확인한 뒤에만 문제 해제와 완료를 보고해야 함: %q %q", problem, collected)
	}
}

func fakePublishedAPT(t *testing.T, series, version string) string {
	t.Helper()
	fake, err := filepath.Abs("../../test/fake")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", fake+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("KPCTL_TEST_APT_SERIES", series)
	file := filepath.Join(t.TempDir(), "Packages")
	parts := strings.SplitN(version, "-", 2)
	abi := strings.SplitN(parts[1], ".", 2)[0]
	body := fmt.Sprintf("Package: linux-image-unsigned-%s-%s-generic\nArchitecture: %s\nSource: linux\nVersion: %s\n\n", parts[0], abi, aptTestArch(t), version)
	if err := os.WriteFile(file, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KPCTL_TEST_APT_PACKAGES", file)
	return file
}

func aptTestArch(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("dpkg", "--print-architecture").Output()
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(out))
}

func TestOfficialPackageIndex(t *testing.T) {
	base := map[string]string{"Origin": "Ubuntu", "Label": "Ubuntu", "Trusted": "yes", "Codename": "resolute", "Suite": "resolute-updates", "Architecture": "amd64", "Component": "main", "Identifier": "Packages", "Filename": "/Packages"}
	for _, tc := range []struct {
		key, value string
		want       bool
	}{
		{"Suite", "resolute", true}, {"Suite", "resolute-security", true},
		{"Suite", "resolute-proposed", false}, {"Suite", "resolute-backports", false},
		{"Origin", "LP-PPA-kernel", false}, {"Trusted", "no", false},
		{"Codename", "noble", false}, {"Architecture", "arm64", false},
	} {
		t.Run(tc.key+tc.value, func(t *testing.T) {
			r := map[string]string{}
			for k, v := range base {
				r[k] = v
			}
			r[tc.key] = tc.value
			if got := officialPackageIndex(r, "resolute", "amd64"); got != tc.want {
				t.Fatalf("색인 허용=%v, want %v", got, tc.want)
			}
		})
	}
}

func TestPublishedVersionUsesKernelSourceVersion(t *testing.T) {
	file := fakePublishedAPT(t, "jammy", "5.15.0-162.172")
	body := fmt.Sprintf("Package: linux-image-unsigned-5.15.0-163-generic\nArchitecture: %s\nSource: linux (5.15.0-163.173)\nVersion: 5.15.0-163.173.1\n\nPackage: linux-image-generic\nArchitecture: %s\nSource: linux-meta\nVersion: 99.0.0.999\n", aptTestArch(t), aptTestArch(t))
	f, err := os.OpenFile(file, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(body); err != nil {
		t.Fatal(err)
	}
	f.Close()
	got, err := publishedKernelVersion(context.Background(), "jammy", "5.15.0")
	if err != nil || got != "5.15.0-163.173" {
		t.Fatalf("linux 소스 버전을 골라야 함: %q, %v", got, err)
	}
}

func TestTargetExcludesUnpublishedPlainAndInterimTags(t *testing.T) {
	fakePublishedAPT(t, "resolute", "7.0.0-42.42")
	repo := t.TempDir()
	run(t, repo, "init", "-q")
	run(t, repo, "commit", "-q", "--allow-empty", "-m", "base")
	for _, tag := range []string{"Ubuntu-7.0.0-42.42", "Ubuntu-7.0.0-43.43", "Ubuntu-7.0.0-43.43i1"} {
		run(t, repo, "tag", tag)
	}
	run(t, repo, "remote", "add", "origin", repo)
	b := &Builder{cfg: &Config{Series: "resolute"}}
	k := KernelConfig{Kernel: "7.0.0-28-generic", GitDir: repo, TagGlob: "Ubuntu-7.0.0-*"}
	for _, remote := range []bool{false, true} {
		got, err := b.latestTargetTag(k, remote)
		if err != nil || got != "Ubuntu-7.0.0-42.42" {
			t.Fatalf("정식 42만 골라야 함: %q, %v", got, err)
		}
	}
	run(t, repo, "tag", "-d", "Ubuntu-7.0.0-42.42")
	if got, err := b.latestTargetTag(k, false); err == nil || got != "" {
		t.Fatalf("정확한 태그가 없으면 개발 태그로 대체하면 안 됨: %q %v", got, err)
	}
}

// 실제 빌드 서버의 APT/Git 상태는 명시적으로 켰을 때만 읽습니다. 패키지 갱신·설치는 하지 않습니다.
func TestSystemPublishedTarget(t *testing.T) {
	if os.Getenv("KPCTL_TEST_SYSTEM_APT") != "1" {
		t.Skip("explicit system APT check only")
	}
	series := os.Getenv("KPCTL_TEST_SYSTEM_SERIES")
	s := model.LTSByCodename(series)
	if s == nil {
		t.Fatal("지원 시리즈 필요")
	}
	b := &Builder{cfg: &Config{Series: series}}
	k := KernelConfig{Kernel: s.Kernel + "-28-generic", GitDir: "/srv/ubuntu-" + series, TagGlob: "Ubuntu-" + s.Kernel + "-*"}
	got, err := b.latestTargetTag(k, false)
	if err != nil {
		t.Fatal(err)
	}
	if want := os.Getenv("KPCTL_EXPECT_PUBLISHED_TAG"); want != "" && got != want {
		t.Fatalf("%s, want %s", got, want)
	}
	t.Logf("정식 배포 상한: %s", got)
}
