// 이 파일: builder 패키지의 TestBusyDiscoveryDefersWithoutCVEReview, TestDependentCVEUsesVerifiedPrerequisites, TestCumulativeTrialConstraintStillRequiresReview 회귀 시험.
package builder

import (
	"encoding/json"
	"errors"
	"fmt"
	"kpctl/internal/client"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"kpctl/internal/model"
)

// 실제 git apply 로 선행 패치 의존성을 재현합니다. 커널 컴파일만 가짜입니다.
func dependencyFixture(t *testing.T) (*Builder, KernelConfig, string, model.DiscoveredPatch, model.DiscoveredPatch) {
	t.Helper()
	root := t.TempDir()
	repo := filepath.Join(root, "repo")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(repo, "test.c")
	write := func(path, body string, mode os.FileMode) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
	}
	write(file, "int base;\n", 0o644)
	run(t, repo, "init", "-q")
	run(t, repo, "add", ".")
	run(t, repo, "commit", "-qm", "base")
	base := "Ubuntu-6.8.0-85.85"
	run(t, repo, "tag", base)
	patch := func(contents, message string) model.DiscoveredPatch {
		write(file, contents, 0o644)
		run(t, repo, "commit", "-qam", message)
		sha, err := git(repo, "rev-parse", "HEAD")
		if err != nil {
			t.Fatal(err)
		}
		body, err := git(repo, "format-patch", "-1", "--stdout", "HEAD")
		if err != nil {
			t.Fatal(err)
		}
		return model.DiscoveredPatch{Commit: strings.TrimSpace(sha), Content: body}
	}
	first := patch("int base;\nint prerequisite;\n", "CVE-2026-1234 prerequisite")
	second := patch("int base;\nint prerequisite;\nint dependent;\n", "CVE-2026-5678 dependent fix")
	run(t, repo, "tag", "Ubuntu-6.8.0-90.90")
	run(t, repo, "remote", "add", "origin", repo)
	kernel := "6.8.0-85-generic"
	write(filepath.Join(root, "src", kernel, ".kpctl-ready"), base, 0o644)
	write(filepath.Join(root, "src", kernel, ".kpctl-source-format"), sourceFormat, 0o644)
	write(filepath.Join(root, "src", kernel, ".config"), "CONFIG_LIVEPATCH=y\n", 0o644)
	write(filepath.Join(root, "config-"+kernel), "CONFIG_LIVEPATCH=y\n", 0o644)
	vmlinux := filepath.Join(root, "vmlinux")
	write(vmlinux, "debug", 0o644)
	helper := filepath.Join(root, "build")
	write(helper, `#!/bin/sh
set -eu
out= name=
while [ "$#" -gt 0 ]; do
 case "$1" in
  -o) out="$2"; shift 2 ;;
  -n) name="$2"; shift 2 ;;
  -a|-v|-j|-s|-c) shift 2 ;;
  *) break ;;
 esac
done
echo "$#" >> "$KPCTL_TEST_DEPENDENCY_CALLS"
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
printf 'int base;\n' > "$stage/test.c"
for p do
 (cd "$stage" && git apply "$p") || exit 1
done
if [ "$KPCTL_TEST_DEPENDENCY_FAIL" = 1 ] && [ "$#" -gt 1 ]; then
 echo 'ERROR: changed data section'
 exit 1
fi
exec "$KPCTL_TEST_DEPENDENCY_FAKE" -a 6.8.0-85-generic -n "$name" -o "$out" "$@"
`, 0o755)
	calls := filepath.Join(root, "calls")
	t.Setenv("KPCTL_TEST_DEPENDENCY_CALLS", calls)
	t.Setenv("KPCTL_TEST_DEPENDENCY_FAIL", "")
	fake, err := filepath.Abs("../../test/fake/kpatch-build")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("KPCTL_TEST_DEPENDENCY_FAKE", fake)
	fakePublishedAPT(t, "noble", "6.8.0-90.90")
	b := &Builder{cfg: &Config{KernelCleanupFreeGiB: -1, WorkDir: root, BootDir: root, Series: "noble", KpatchBuild: helper, BuildTool: BuildToolKpatch, BuildTimeoutMinutes: 1, MaxTrialsPerRun: 10}}
	k := KernelConfig{Kernel: kernel, GitDir: repo, BaseTag: base, TagGlob: "Ubuntu-6.8.0-*", Vmlinux: vmlinux, Paths: []string{"test.c"}}
	return b, k, calls, first, second
}

func TestBusyDiscoveryDefersWithoutCVEReview(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	b, k, _, _, _ := dependencyFixture(t)
	var problems, published int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/known"):
			json.NewEncoder(w).Encode(model.KnownCommitsResponse{})
		case strings.HasSuffix(r.URL.Path, "/upstream"):
			var report model.UpstreamReport
			json.NewDecoder(r.Body).Decode(&report)
			if report.Problem != nil && *report.Problem != "" {
				problems++
			}
			w.Write([]byte(`{}`))
		case strings.HasSuffix(r.URL.Path, "/discovered"):
			published++
			w.Write([]byte(`{}`))
		default:
			w.Write([]byte(`{}`))
		}
	}))
	defer server.Close()
	b.c, _ = client.New(server.URL, "test", "")
	lock, err := lockUserBuild()
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	more, err := b.discover(k)
	if !errors.Is(err, errBuildBusy) || more || !b.retryDiscovery {
		t.Fatalf("contention was not deferred: more=%v retry=%v err=%v", more, b.retryDiscovery, err)
	}
	if problems != 0 || published != 0 {
		t.Fatalf("contention became a persistent review: problems=%d published=%d", problems, published)
	}
	b.cfg.Kernels, b.cfg.PollSeconds = []KernelConfig{k}, 30
	b.DiscoverKernels([]string{k.Kernel})
	if !b.deferredDiscovery[k.Kernel] || b.discoveryRetryAt.IsZero() {
		t.Fatal("manual refresh lost after contention")
	}
	result := b.build(model.BuildTask{Job: model.Job{ID: 1, Kernel: k.Kernel, Version: 1}})
	if result.Success || !result.Deferred {
		t.Fatalf("busy queued build was failed: %+v", result)
	}
}

func TestDependentCVEUsesVerifiedPrerequisites(t *testing.T) {
	for _, previousRun := range []bool{false, true} {
		name := "same batch"
		if previousRun {
			name = "previous batch"
		}
		t.Run(name, func(t *testing.T) {
			b, k, calls, first, second := dependencyFixture(t)
			var posted model.DiscoveredRequest
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case strings.HasSuffix(r.URL.Path, "/known"):
					known := model.KnownCommitsResponse{}
					if previousRun {
						known.Commits = []string{first.Commit}
						known.ActivePatches = []model.DiscoveredPatch{first}
					}
					json.NewEncoder(w).Encode(known)
				case strings.HasSuffix(r.URL.Path, "/discovered"):
					if err := json.NewDecoder(r.Body).Decode(&posted); err != nil {
						t.Error(err)
					}
					w.Write([]byte(`{}`))
				default:
					w.Write([]byte(`{}`))
				}
			}))
			defer server.Close()
			b.cfg.ControllerURL = server.URL
			b, err := New(b.cfg)
			if err != nil {
				t.Fatal(err)
			}
			if more, err := b.discover(k); err != nil || more {
				t.Fatalf("검증된 선행 CVE 와 함께 시험하면 수집 가능해야 함: %v %v", more, err)
			}
			// 다른 활성 CVE는 독립 본문으로 두고 컨트롤러의 실제 활성 본문과 재시험합니다.
			want, attempts := 2, "1 2"
			if previousRun {
				want, attempts = 1, "2"
			}
			data, err := os.ReadFile(calls)
			if err != nil || strings.Join(strings.Fields(string(data)), " ") != attempts || len(posted.Patches) != want || posted.Patches[want-1].Commit != second.Commit || len(posted.Unpatchable) != 0 {
				t.Fatalf("활성 CVE 본문과 별도로 재시험해야 함: calls=%q posted=%+v err=%v", data, posted, err)
			}
			dependent := posted.Patches[want-1]
			if dependent.Content != second.Content || strings.Contains(dependent.Content, "From "+first.Commit+" ") {
				t.Fatalf("다른 활성 CVE의 원본을 저장 본문에 숨기면 안 됨: %s", dependent.Content)
			}
			// 선행 CVE를 비활성화한 뒤 남은 본문만 빌드하면 해당 변경을 되살릴 수 없습니다.
			if _, err := b.trialBuild(k, second.Commit, dependent.Content); !errors.Is(err, errPatchDependency) {
				t.Fatalf("선행 수정 없이 본문만으로 해당 변경을 되살리면 안 됨: %v", err)
			}
		})
	}
}

func TestCumulativeTrialConstraintStillRequiresReview(t *testing.T) {
	b, k, _, first, second := dependencyFixture(t)
	if reason, err := b.trialBuild(k, second.Commit, second.Content); reason != "" || !errors.Is(err, errPatchDependency) {
		t.Fatalf("단독 적용 실패를 의존성으로 구분해야 함: %q %v", reason, err)
	} else if !strings.Contains(firstLineOf(err.Error()), "error: patch failed:") {
		t.Fatalf("웹에 전달되는 첫 줄에 실제 원인이 있어야 함: %v", err)
	}
	t.Setenv("KPCTL_TEST_DEPENDENCY_FAIL", "1")
	if reason, err := b.trialBuildPatches(k, second.Commit, second.Content, []model.DiscoveredPatch{first}); reason != "" || err == nil {
		t.Fatalf("결합 실패를 새 커밋의 불가로 확정하면 안 됨: %q %v", reason, err)
	}
	if _, err := os.Stat(filepath.Join(b.cfg.WorkDir, "trial-"+second.Commit[:12]+"-with-prerequisites", "build.log")); err != nil {
		t.Fatal("결합 실패 로그를 남겨야 함", err)
	}
}

func TestDiscoveryDoesNotReintroduceInactivePrerequisite(t *testing.T) {
	b, k, calls, first, _ := dependencyFixture(t)
	var posted int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/known"):
			// 처리는 끝났지만 활성 목록에 없는 커밋: 비활성·거절·관리자 제외.
			json.NewEncoder(w).Encode(model.KnownCommitsResponse{Commits: []string{first.Commit}})
		case strings.HasSuffix(r.URL.Path, "/discovered"):
			posted++
			w.Write([]byte(`{}`))
		default:
			w.Write([]byte(`{}`))
		}
	}))
	defer server.Close()
	b.c, _ = client.New(server.URL, "test", "")
	more, err := b.discover(k)
	if err == nil || more || !strings.Contains(err.Error(), "비활성") {
		t.Fatalf("비활성 선행 커밋을 다시 넣지 않고 검토를 기다려야 함: more=%v err=%v", more, err)
	}
	if _, err := os.Stat(calls); !os.IsNotExist(err) || posted != 0 {
		t.Fatalf("비활성 선행 커밋이 필요한 후보는 시험·등록하지 않아야 함: calls err=%v posted=%d", err, posted)
	}
}

func TestSymbolOnlyCVEPrerequisiteNeedsIndependentActivePatch(t *testing.T) {
	for _, active := range []bool{false, true} {
		t.Run(fmt.Sprintf("active=%v", active), func(t *testing.T) {
			b, k, calls, _, _ := dependencyFixture(t)
			run(t, k.GitDir, "reset", "--hard", k.BaseTag)
			if err := os.WriteFile(filepath.Join(k.GitDir, "dep.h"), []byte("enum trace { required_value };\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			run(t, k.GitDir, "add", "dep.h")
			run(t, k.GitDir, "commit", "-qm", "CVE-2026-1234 prerequisite enum")
			sha, _ := git(k.GitDir, "rev-parse", "HEAD")
			body, _ := git(k.GitDir, "format-patch", "-1", "--stdout", "HEAD")
			first := model.DiscoveredPatch{Commit: strings.TrimSpace(sha), Content: body}
			if err := os.WriteFile(filepath.Join(k.GitDir, "test.c"), []byte("#include \"dep.h\"\nint base;\nint dependent = required_value;\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			run(t, k.GitDir, "commit", "-qam", "CVE-2026-5678 use enum")
			run(t, k.GitDir, "tag", "-f", "Ubuntu-6.8.0-90.90")
			second, _ := git(k.GitDir, "format-patch", "-1", "--stdout", "HEAD")
			helper, _ := os.ReadFile(b.cfg.KpatchBuild)
			guard := "if grep -q required_value \"$stage/test.c\" && [ ! -f \"$stage/dep.h\" ]; then echo 'unknown type name required_value'; exit 1; fi\n"
			helper = []byte(strings.Replace(string(helper), "exec \"$KPCTL_TEST_DEPENDENCY_FAKE\"", guard+"exec \"$KPCTL_TEST_DEPENDENCY_FAKE\"", 1))
			os.WriteFile(b.cfg.KpatchBuild, helper, 0o755)
			var posted model.DiscoveredRequest
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case strings.HasSuffix(r.URL.Path, "/known"):
					known := model.KnownCommitsResponse{}
					if active {
						known.Commits = []string{first.Commit}
						known.ActivePatches = []model.DiscoveredPatch{first}
					}
					json.NewEncoder(w).Encode(known)
				case strings.HasSuffix(r.URL.Path, "/discovered"):
					json.NewDecoder(r.Body).Decode(&posted)
					w.Write([]byte(`{}`))
				default:
					w.Write([]byte(`{}`))
				}
			}))
			defer server.Close()
			b.c, _ = client.New(server.URL, "builder", "")
			more, err := b.discover(k)
			data, _ := os.ReadFile(calls)
			if !active {
				if err == nil || !strings.Contains(err.Error(), "아직 활성 패치가 아닌 CVE") || more || len(data) != 0 || len(posted.Patches) != 0 {
					t.Fatalf("새 CVE 의존성은 시험·등록 없이 검토 필요: more=%v err=%v calls=%q posted=%+v", more, err, data, posted)
				}
				return
			}
			if err != nil || more || strings.TrimSpace(string(data)) != "2" || len(posted.Patches) != 1 || posted.Patches[0].Content != second {
				t.Fatalf("활성 헤더 CVE는 별도 본문으로 시험하고 저장 본문에는 제외해야 함: more=%v err=%v calls=%q posted=%+v", more, err, data, posted)
			}
		})
	}
}

func TestTrialReviewPreservesToolStartupError(t *testing.T) {
	b, k, _, first, _ := dependencyFixture(t)
	b.cfg.KpatchBuild = filepath.Join(t.TempDir(), "missing-kpatch")
	reason, err := b.trialBuild(k, first.Commit, first.Content)
	if reason != "" || err == nil || !strings.Contains(firstLineOf(err.Error()), "no such file or directory") {
		t.Fatalf("도구 실행 실패의 구체적인 원인을 보존해야 함: %q %v", reason, err)
	}
}

func TestPatchApplyFailureDiagnostics(t *testing.T) {
	for _, tc := range []struct {
		log  string
		want bool
	}{
		{"error: foo.c: patch does not apply", true},
		{"ERROR: failed to apply patch p", true},
		{"Hunk #1 FAILED at 1731.", true},
		{"Hunk #1 succeeded at 1731.\ncompiler failed", false},
		{"make: *** [certs] Error 2", false},
		{`+const char *message = "failed to apply";`, false},
	} {
		if got := patchApplyFailure(tc.log); got != tc.want {
			t.Fatalf("적용 실패 판정=%v want=%v: %s", got, tc.want, tc.log)
		}
	}
}

func TestCVERevertRequiresReviewBeforeTrial(t *testing.T) {
	b, k, calls, _, _ := dependencyFixture(t)
	run(t, k.GitDir, "revert", "--no-edit", "HEAD")
	run(t, k.GitDir, "tag", "-f", "Ubuntu-6.8.0-90.90")
	var posted model.DiscoveredRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/discovered") {
			if err := json.NewDecoder(r.Body).Decode(&posted); err != nil {
				t.Error(err)
			}
		}
		w.Write([]byte(`{}`))
	}))
	defer server.Close()
	b.cfg.ControllerURL = server.URL
	b, err := New(b.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.discover(k); err == nil || !strings.Contains(err.Error(), "되돌리기") {
		t.Fatalf("CVE 되돌리기는 자동 수용하지 말고 검토를 기다려야 함: %v", err)
	}
	data, err := os.ReadFile(calls)
	if err != nil || strings.Join(strings.Fields(string(data)), " ") != "1 2" || len(posted.Patches) != 2 || posted.LatestTag != "" {
		t.Fatalf("앞선 검증 결과는 보존하고 되돌리기는 시험·완료로 취급하지 않아야 함: calls=%q posted=%+v err=%v", data, posted, err)
	}
	for _, msg := range []string{"Revert \"CVE fix\"", "UBUNTU: SAUCE: Revert \"fix\"", "sctp: adjust fix\n\nThis reverts commit 1234567890abcdef."} {
		if !isRevertCommit(msg) {
			t.Fatalf("되돌리기 검토 필요: %s", msg)
		}
	}
}
