// 이 파일: builder 패키지의 TestKernelSourceFromGit, TestTrialBuildEnvFailure, TestTrialBuildUnknownFailuresNeedReview 회귀 시험.
package builder

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"kpctl/internal/model"
)

// 가짜 커널 git: Ubuntu 태그에서 소스 트리를 꺼내 .config·버전 꼬리를 맞추는지
func TestKernelSourceFromGit(t *testing.T) {
	root := t.TempDir()
	git := filepath.Join(root, "ubuntu-resolute")
	os.MkdirAll(filepath.Join(git, "scripts"), 0o755)
	os.WriteFile(filepath.Join(git, "Makefile"), []byte("VERSION = 7\nPATCHLEVEL = 0\nSUBLEVEL = 12\n"), 0o644)
	os.WriteFile(filepath.Join(git, "scripts", "tool.sh"), []byte("#!/bin/sh\n"), 0o644) // 실행 권한 없음
	for dir, contents := range map[string]string{"certs": "trusted public certificate\n", "revoked-certs": "revoked public certificate\n"} {
		if err := os.MkdirAll(filepath.Join(git, "debian", dir), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(git, "debian", dir, "test-all.pem"), []byte(contents), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	rules := "debian/canonical-certs.pem:\n\tcat debian/certs/*-all.pem > $@\ndebian/canonical-revoked-certs.pem:\n\tcat debian/revoked-certs/*-all.pem > $@\n"
	if err := os.WriteFile(filepath.Join(git, "debian", "rules"), []byte(rules), 0o644); err != nil {
		t.Fatal(err)
	}
	run(t, git, "init", "-q")
	run(t, git, "add", ".")
	run(t, git, "commit", "-q", "-m", "a")
	run(t, git, "tag", "Ubuntu-7.0.0-28.28")
	boot := filepath.Join(root, "boot")
	os.MkdirAll(boot, 0o755)
	config := "CONFIG_LIVEPATCH=y\nCONFIG_SYSTEM_TRUSTED_KEYS=\"debian/canonical-certs.pem\"\nCONFIG_SYSTEM_REVOCATION_KEYS=\"debian/canonical-revoked-certs.pem\"\n"
	os.WriteFile(filepath.Join(boot, "config-7.0.0-28-generic"), []byte(config), 0o644)

	b := &Builder{cfg: &Config{KernelCleanupFreeGiB: -1, WorkDir: filepath.Join(root, "work"), BootDir: boot}}
	k := KernelConfig{Kernel: "7.0.0-28-generic", GitDir: git, BaseTag: "Ubuntu-7.0.0-28.28"}
	src, log, err := b.kernelSource(context.Background(), k)
	if err != nil {
		t.Fatalf("소스 준비 실패: %v\n%s", err, log)
	}
	read := func(f string) string { d, _ := os.ReadFile(filepath.Join(src, f)); return string(d) }
	if !strings.Contains(read("Makefile"), "SUBLEVEL = 12") || read("localversion") != "" || read(".kpctl-source-format") != sourceFormat+"\n" ||
		read(".config") != config || strings.TrimSpace(read(".kpctl-ready")) != "Ubuntu-7.0.0-28.28" {
		t.Fatalf("소스 트리 준비가 이상함: Makefile=%q localversion=%q", read("Makefile"), read("localversion"))
	}
	if read("debian/canonical-certs.pem") != "trusted public certificate\n" || read("debian/canonical-revoked-certs.pem") != "revoked public certificate\n" {
		t.Fatal("보안 설정을 바꾸지 않고 원본 공개 인증서를 준비해야 함")
	}
	if fi, _ := os.Stat(filepath.Join(src, "scripts", "tool.sh")); fi.Mode()&0o100 == 0 {
		t.Fatal("스크립트 실행 권한을 복구해야 함")
	}
	// 같은 태그면 다시 만들지 않음
	os.WriteFile(filepath.Join(src, "marker"), []byte("x"), 0o644)
	if src2, _, err := b.kernelSource(context.Background(), k); err != nil || read("marker") != "x" || src2 != src {
		t.Fatal("같은 커널이면 소스를 재사용해야 함")
	}
	// 이전 버전이 만든 캐시에 인증서가 빠져 있어도 소스를 지우지 않고 복구합니다.
	if err := os.Remove(filepath.Join(src, "debian/canonical-certs.pem")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.kernelSource(context.Background(), k); err != nil || read("debian/canonical-certs.pem") != "trusted public certificate\n" || read("marker") != "x" || read(".config") != config {
		t.Fatalf("캐시의 인증서만 보완해야 함: %v", err)
	}
	if err := os.Remove(filepath.Join(src, "debian/canonical-certs.pem")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(src, "debian/rules")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.kernelSource(context.Background(), k); err != nil || read(".config") != config || read("debian/canonical-certs.pem") != "trusted public certificate\n" {
		t.Fatal("삭제된 추적 소스는 기준 태그에서 복구하고 보안 설정을 유지해야 함")
	}
	if err := os.Remove(filepath.Join(git, "debian/rules")); err != nil {
		t.Fatal(err)
	}
	run(t, git, "commit", "-qam", "source missing certificate rules")
	run(t, git, "tag", "Ubuntu-7.0.0-29.29")
	k.BaseTag = "Ubuntu-7.0.0-29.29"
	if _, _, err := b.kernelSource(context.Background(), k); err == nil || read(".config") != config {
		t.Fatal("기준 태그에서도 인증서 생성이 불가능하면 보안 설정을 유지하고 실패해야 함")
	}
	// 없는 태그 → 환경 오류
	k.BaseTag = "Ubuntu-7.0.0-99.99"
	if _, _, err := b.kernelSource(context.Background(), k); err == nil {
		t.Fatal("없는 태그는 실패해야 함")
	}
}

// 소스 다운로드 실패 같은 환경 문제는 "라이브패치 불가"가 아니라 환경 오류로 분류
func TestTrialBuildEnvFailure(t *testing.T) {
	dir := t.TempDir()
	fake := filepath.Join(dir, "kpatch-build")
	os.WriteFile(fake, []byte("#!/bin/sh\necho 'dget: curl linux_7.0.0-28.28.dsc failed'\necho 'curl: (22) The requested URL returned error: 404'\nexit 1\n"), 0o755)
	b := &Builder{cfg: &Config{KernelCleanupFreeGiB: -1, WorkDir: dir, KpatchBuild: fake, BuildTool: BuildToolKpatch, BuildTimeoutMinutes: 1, BootDir: dir}}
	reason, envErr := b.trialBuild(KernelConfig{Kernel: "7.0.0-28-generic"}, "0123456789abcdef", "--- a\n+++ b\n")
	if envErr == nil || reason != "" {
		t.Fatalf("환경 오류여야 함: reason=%q env=%v", reason, envErr)
	}
	// 명시적 도구 제약도 자동 불가 판정 대신 검토 대기
	os.WriteFile(fake, []byte("#!/bin/sh\necho 'ERROR: changed data section'\nexit 1\n"), 0o755)
	reason, envErr = b.trialBuild(KernelConfig{Kernel: "7.0.0-28-generic"}, "0123456789abcdef", "--- a\n+++ b\n")
	if envErr == nil || reason != "" || failureKind(envErr, "") != model.FailureUnsupported {
		t.Fatalf("패치 문제여야 함: reason=%q env=%v", reason, envErr)
	}
}

func TestTrialBuildUnknownFailuresNeedReview(t *testing.T) {
	for _, tc := range []struct{ name, script, log string }{
		{"인증서 오류", "echo 'make[2]: *** [scripts/Makefile.build:548: certs] Error 2'\nexit 1", "certs] Error 2"},
		{"의존성 오류", "echo 'net/sctp/sm_make_chunk.c: patch does not apply'\nexit 1", "patch does not apply"},
		{"미분류 오류", "echo 'foo.c: error: unknown type name'\nexit 1", "unknown type name"},
		{"강제 종료", "echo 'ERROR: changed data section'\nkill -KILL $$", "signal: killed"},
		{"성공 종료한 잘못된 결과물", `out= name=
while [ "$#" -gt 0 ]; do
 case "$1" in
  -o) out="$2"; shift 2 ;;
  -n) name="$2"; shift 2 ;;
  -a|-v|-j|-s|-c) shift 2 ;;
  *) shift ;;
 esac
done
mkdir -p "$out"
printf 'invalid module' > "$out/$name.ko"
echo 'ERROR: changed data section'
exit 0`, "빌드 결과물 검증 실패"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			fake := filepath.Join(dir, "kpatch-build")
			if err := os.WriteFile(fake, []byte("#!/bin/sh\n"+tc.script+"\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			b := &Builder{cfg: &Config{KernelCleanupFreeGiB: -1, WorkDir: dir, KpatchBuild: fake, BuildTool: BuildToolKpatch, BuildTimeoutMinutes: 1, BootDir: dir}}
			reason, reviewErr := b.trialBuild(KernelConfig{Kernel: "6.8.0-136-generic"}, "0123456789abcdef", "--- a\n+++ b\n")
			if reviewErr == nil || reason != "" {
				t.Fatalf("검토 전 불가로 확정하면 안 됨: reason=%q err=%v", reason, reviewErr)
			}
			log, err := os.ReadFile(filepath.Join(dir, "trial-0123456789ab", "build.log"))
			if err != nil || !strings.Contains(string(log), tc.log) {
				t.Fatalf("검토용 실패 로그를 보존해야 함: %v\n%s", err, log)
			}
		})
	}
}

func TestDiscoveryPreservesVerifiedProgressBeforeReview(t *testing.T) {
	fakePublishedAPT(t, "noble", "6.8.0-90.90")
	root := t.TempDir()
	repo := filepath.Join(root, "git")
	file := filepath.Join(repo, "net/test.c")
	write := func(path, content string, mode os.FileMode) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
	}
	write(file, "int base;\n", 0o644)
	run(t, repo, "init", "-q")
	run(t, repo, "add", ".")
	run(t, repo, "commit", "-qm", "base")
	base, latest := "Ubuntu-6.8.0-85.85", "Ubuntu-6.8.0-90.90"
	run(t, repo, "tag", base)
	write(file, "int base;\nint GOOD_FIX;\n", 0o644)
	run(t, repo, "commit", "-qam", "CVE-2026-1234 verified fix")
	write(file, "int base;\nint GOOD_FIX;\nint BAD_ENV;\n", 0o644)
	run(t, repo, "commit", "-qam", "CVE-2026-5678 needs review")
	run(t, repo, "tag", latest)
	run(t, repo, "remote", "add", "origin", repo)
	kernel := "6.8.0-85-generic"
	write(filepath.Join(root, "src", kernel, ".kpctl-ready"), base, 0o644)
	write(filepath.Join(root, "src", kernel, ".kpctl-source-format"), sourceFormat, 0o644)
	write(filepath.Join(root, "src", kernel, ".config"), "CONFIG_LIVEPATCH=y\n", 0o644)
	write(filepath.Join(root, "config-"+kernel), "CONFIG_LIVEPATCH=y\n", 0o644)
	vmlinux := filepath.Join(root, "vmlinux")
	write(vmlinux, "debug symbols", 0o644)
	fake, err := filepath.Abs("../../test/fake/kpatch-build")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("KPCTL_TEST_KPATCH_BUILD", fake)
	calls := filepath.Join(root, "calls")
	t.Setenv("KPCTL_TEST_TRIAL_CALLS", calls)
	wrapper := filepath.Join(root, "kpatch-build")
	write(wrapper, "#!/bin/sh\necho trial >> \"$KPCTL_TEST_TRIAL_CALLS\"\nfor arg in \"$@\"; do\n if [ -f \"$arg\" ] && grep -q BAD_ENV \"$arg\"; then echo 'unexpected compiler failure'; exit 1; fi\ndone\nexec \"$KPCTL_TEST_KPATCH_BUILD\" \"$@\"\n", 0o755)
	var posted model.DiscoveredRequest
	var known model.KnownCommitsResponse
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/known"):
			json.NewEncoder(w).Encode(known)
		case strings.HasSuffix(r.URL.Path, "/discovered"):
			if err := json.NewDecoder(r.Body).Decode(&posted); err != nil {
				t.Error(err)
			}
			for _, p := range posted.Patches {
				known.Commits = append(known.Commits, p.Commit)
				known.ActivePatches = append(known.ActivePatches, p)
			}
			json.NewEncoder(w).Encode(model.DiscoveredResponse{AddedPatches: len(posted.Patches), JobID: 1})
		default:
			w.Write([]byte(`{}`))
		}
	}))
	defer server.Close()
	b, err := New(&Config{ControllerURL: server.URL, KernelCleanupFreeGiB: -1, WorkDir: root, KpatchBuild: wrapper, Series: "noble",
		BuildTool: BuildToolKpatch, BuildTimeoutMinutes: 1, MaxTrialsPerRun: 10, BootDir: root})
	if err != nil {
		t.Fatal(err)
	}
	k := KernelConfig{Kernel: kernel, GitDir: repo, BaseTag: base, TagGlob: "Ubuntu-6.8.0-*", Vmlinux: vmlinux, Paths: []string{"net/"}}
	if _, err := b.discover(k); err == nil {
		t.Fatal("미확인 커밋에서 검토를 요청해야 함")
	}
	if len(posted.Patches) != 1 || len(posted.Unpatchable) != 0 || posted.LatestTag != "" || len(known.Commits) != 1 {
		t.Fatalf("성공분은 보존하고 미확인 실패와 최신 수집 완료 표시는 확정하지 않아야 함: %+v", posted)
	}
	if _, err := b.discover(k); err == nil {
		t.Fatal("다시 시도해도 미확인 커밋을 자동으로 건너뛰면 안 됨")
	}
	data, err := os.ReadFile(calls)
	if err != nil || len(strings.Fields(string(data))) != 2 {
		t.Fatalf("이미 보존한 성공분을 반복 빌드하면 안 됨: %v, %q", err, data)
	}
	if _, err := b.discoverWithForce(k, true); err == nil {
		t.Fatal("관리자 재시험도 미확인 실패를 자동 제외하면 안 됨")
	}
	data, err = os.ReadFile(calls)
	if err != nil || len(strings.Fields(string(data))) != 3 {
		t.Fatalf("명시적 재시험은 실패 커밋만 다시 시험해야 함: %v, %q", err, data)
	}
}
