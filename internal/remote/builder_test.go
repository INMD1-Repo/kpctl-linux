// 이 파일: remote 패키지의 InstallBuilder·배포판별 빌더 묶음(OpenBuilderBundle) 회귀 시험 (가짜 ssh/scp 로 로컬 실행).
package remote

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// fakeTools 는 ssh·scp 를 흉내 내는 스크립트를 만듭니다. ssh 는 마지막 인자를 로컬 bash 로 실행하고,
// scp 는 "host:경로" 의 경로로 cp -R 합니다.
func fakeTools(t *testing.T) (sshBin, scpBin string) {
	dir := t.TempDir()
	sshBin, scpBin = filepath.Join(dir, "ssh"), filepath.Join(dir, "scp")
	write := func(p, body string) {
		if err := os.WriteFile(p, []byte("#!/bin/bash\n"+body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write(sshBin, `exec bash -c "${@: -1}"`+"\n")
	write(scpBin, `args=(); for a in "$@"; do case "$a" in -o|-i|-P) skip=1; continue ;; esac; [ -n "$skip" ] && { skip=; continue; }; case "$a" in -*) ;; *) args+=("$a") ;; esac; done
dst=${args[-1]#*:}; unset 'args[-1]'; cp -R "${args[@]}" "$dst"`+"\n")
	return sshBin, scpBin
}

func TestInstallBuilderReportsOriginalAndCleanupFailures(t *testing.T) {
	sshBin := filepath.Join(t.TempDir(), "ssh")
	fake := `#!/bin/bash
case "${@: -1}" in
  mktemp*) echo /tmp/kpctl-builder.test ;;
  "rm -rf "*) echo 'cleanup connection lost' >&2; exit 255 ;;
  *) exit 2 ;;
esac
`
	if err := os.WriteFile(sshBin, []byte(fake), 0o755); err != nil {
		t.Fatal(err)
	}
	s := &Session{SSH: &SSH{SSHBin: sshBin}, Target: "test", Facts: Facts{UID: "0"}}
	err := s.InstallBuilder(&Bundle{Dir: filepath.Join(t.TempDir(), "missing-bundle")}, BuilderInstallOptions{})
	var exitErr *exec.ExitError
	if !errors.Is(err, os.ErrNotExist) || !errors.As(err, &exitErr) || exitErr.ExitCode() != 255 ||
		!strings.Contains(err.Error(), "/tmp/kpctl-builder.test 삭제 실패") ||
		!strings.Contains(err.Error(), "cleanup connection lost") {
		t.Fatalf("expected the bundle and cleanup failures with their paths, got %v", err)
	}
}

func TestInstallBuilderCopiesBundleAndRunsSetup(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash 없음")
	}
	bundle := t.TempDir()
	for _, f := range ubuntuBuilderFiles {
		p := filepath.Join(bundle, f)
		if f == "kpatch-fixes" || f == "build-environment" {
			if err := os.MkdirAll(p, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(p, "marker"), []byte("x"), 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	report := filepath.Join(t.TempDir(), "report")
	// 가짜 setup-builder.sh: 받은 인자, 설정 내용, 묶음 하위 디렉터리, 실행 권한을 기록
	setup := `#!/bin/bash
HERE=$(cd "$(dirname "$0")" && pwd)
{ echo "args=$*"
  while [ $# -gt 0 ]; do case "$1" in --config) echo "config=$(cat "$2")"; echo "mode=$(stat -c %a "$2")"; shift ;; --ca-file) echo "ca=$(cat "$2")"; shift ;; esac; shift; done
  test -f "$HERE/kpatch-fixes/marker" && echo "tree=ok"
  test -x "$HERE/kpctl-builder" && echo "exec=ok"
} > ` + report + `
echo "■ 빌드 사용자"
echo "기타 출력"
`
	if err := os.WriteFile(filepath.Join(bundle, "setup-builder.sh"), []byte(setup), 0o644); err != nil {
		t.Fatal(err)
	}
	ca := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(ca, []byte("CA"), 0o644); err != nil {
		t.Fatal(err)
	}

	sshBin, scpBin := fakeTools(t)
	var steps []string
	s := &Session{SSH: &SSH{SSHBin: sshBin, SCPBin: scpBin}, Target: "build-01",
		Facts: Facts{UID: "0"}, OnStep: func(_, m string) { steps = append(steps, m) }}
	err := s.InstallBuilder(&Bundle{Dir: bundle}, BuilderInstallOptions{
		ControllerURL: "https://ctl.example:8443", Config: []byte(`{"token":"secret-token"}`), CAFile: ca,
		Kernels: []string{"6.8.0-136-generic"}, SetupArgs: []string{"--memory-mib", "16384"},
	})
	if err != nil {
		t.Fatalf("InstallBuilder: %v\n%s", err, s.Log.String())
	}
	out, err := os.ReadFile(report)
	if err != nil {
		t.Fatal(err)
	}
	got := string(out)
	for _, want := range []string{`config={"token":"secret-token"}`, "mode=600", "ca=CA", "tree=ok", "exec=ok",
		"--memory-mib 16384 6.8.0-136-generic"} {
		if !strings.Contains(got, want) {
			t.Errorf("setup-builder.sh 기록에 %q 없음:\n%s", want, got)
		}
	}
	if strings.Contains(s.Log.String(), "secret-token") {
		t.Error("토큰이 로그에 남았습니다")
	}
	joined := strings.Join(steps, "\n")
	if !strings.Contains(joined, "■ 빌드 사용자") || strings.Contains(joined, "기타 출력") {
		t.Errorf("진행 표시: %s", joined)
	}
	for _, line := range strings.Split(s.Log.String(), "\n") {
		if rest, ok := strings.CutPrefix(line, "/tmp/kpctl-builder."); ok {
			if _, err := os.Stat("/tmp/kpctl-builder." + rest); err == nil {
				t.Errorf("임시 디렉터리가 남았습니다: /tmp/kpctl-builder.%s", rest)
			}
		}
	}
}

// 네이티브 빌더 설치 (codex 구현): 묶음 복사, worker.json·토큰(0600, 표준 입력), CA, --target 인자, 진행 표시, 임시 디렉터리 정리.
// 토큰은 명령줄·로그 어디에도 남지 않아야 합니다.
func TestInstallNativeBuilderCopiesBundleAndRunsSetup(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash 없음")
	}
	bundle := t.TempDir()
	for _, f := range nativeBuilderFiles {
		p := filepath.Join(bundle, f)
		if f == "kpatch-fixes" || f == "build-environment" {
			if err := os.MkdirAll(p, 0o755); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	report := filepath.Join(t.TempDir(), "report")
	setup := `#!/bin/bash
HERE=$(cd "$(dirname "$0")" && pwd)
{ echo "args=$*"
  while [ $# -gt 0 ]; do case "$1" in
    --worker) echo "worker=$(cat "$2")"; echo "wmode=$(stat -c %a "$2")"; shift ;;
    --token-file) echo "token=$(cat "$2")"; echo "tmode=$(stat -c %a "$2")"; shift ;;
    --ca-file) echo "ca=$(cat "$2")"; shift ;;
  esac; shift; done
  test -f "$HERE/kpctl-native-builder.py" && echo "driver=ok"
} > ` + report + `
echo "■ 대상 커널 계획"
echo "기타 출력"
`
	if err := os.WriteFile(filepath.Join(bundle, "setup-native-builder.sh"), []byte(setup), 0o644); err != nil {
		t.Fatal(err)
	}
	ca := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(ca, []byte("CA"), 0o644); err != nil {
		t.Fatal(err)
	}
	sshBin, scpBin := fakeTools(t)
	var steps []string
	s := &Session{SSH: &SSH{SSHBin: sshBin, SCPBin: scpBin}, Target: "build-rocky10",
		Facts: Facts{UID: "0"}, OnStep: func(_, m string) { steps = append(steps, m) }}
	track := "native__rocky__10__amd64__6.12.0-264.21.1.el10_3.x86_64__6.12.0-264.21.1.el10_3__" + strings.Repeat("a", 40)
	err := s.InstallNativeBuilder(&Bundle{Dir: bundle}, NativeBuilderInstallOptions{
		ControllerURL: "https://ctl.example:8443", Worker: []byte(`{"builder":"build-rocky10"}`), Token: "native-secret-token-0123", CAFile: ca,
		Targets:   []NativeTarget{{ABI: "6.12.0-264.21.1.el10_3.x86_64", Track: track}, {ABI: "6.12.0-265.1.1.el10_3.x86_64"}},
		SetupArgs: []string{"--jobs", "4"},
	})
	if err != nil {
		t.Fatalf("InstallNativeBuilder: %v\n%s", err, s.Log.String())
	}
	out, err := os.ReadFile(report)
	if err != nil {
		t.Fatal(err)
	}
	got := string(out)
	for _, want := range []string{`worker={"builder":"build-rocky10"}`, "wmode=600", "token=native-secret-token-0123", "tmode=600", "ca=CA", "driver=ok",
		"--jobs 4 --target 6.12.0-264.21.1.el10_3.x86_64=" + track + " --target 6.12.0-265.1.1.el10_3.x86_64"} {
		if !strings.Contains(got, want) {
			t.Errorf("setup-native-builder.sh 기록에 %q 없음:\n%s", want, got)
		}
	}
	if strings.Contains(s.Log.String(), "native-secret-token-0123") {
		t.Error("토큰이 로그에 남았습니다")
	}
	joined := strings.Join(steps, "\n")
	if !strings.Contains(joined, "■ 대상 커널 계획") || strings.Contains(joined, "기타 출력") {
		t.Errorf("진행 표시: %s", joined)
	}
	for _, line := range strings.Split(s.Log.String(), "\n") {
		if rest, ok := strings.CutPrefix(line, "/tmp/kpctl-native-builder."); ok {
			if _, err := os.Stat("/tmp/kpctl-native-builder." + rest); err == nil {
				t.Errorf("임시 디렉터리가 남았습니다: /tmp/kpctl-native-builder.%s", rest)
			}
		}
	}
	// Worker 를 주면서 토큰이 없거나 짧으면 원격에 아무것도 하지 않고 오류
	for _, tok := range []string{"", "short"} {
		s := &Session{SSH: &SSH{SSHBin: "/nonexistent-ssh"}, Target: "x", Facts: Facts{UID: "0"}}
		if err := s.InstallNativeBuilder(&Bundle{Dir: bundle}, NativeBuilderInstallOptions{Worker: []byte("{}"), Token: tok}); err == nil || strings.Contains(s.Log.String(), "mktemp") {
			t.Errorf("토큰 %q: err=%v log=%s", tok, err, s.Log.String())
		}
	}
}

// writeFlavorBundle 은 root/<flavor>/ 에 그 종류 전용 묶음을 만듭니다. kpctl-builder 는 ELF 아키텍처만 읽으므로 시험 바이너리로 대신합니다.
func writeFlavorBundle(t *testing.T, root, flavor, marker string) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	elfData, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, flavor)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range BuilderBundleFiles(flavor) {
		p, body := filepath.Join(dir, f), []byte("x")
		switch f {
		case "kpatch-fixes", "build-environment":
			if err := os.MkdirAll(p, 0o755); err != nil {
				t.Fatal(err)
			}
			continue
		case "kpctl-builder":
			body = elfData
		case builderFlavorMarker:
			body = []byte(marker + "\n")
		}
		if err := os.WriteFile(p, body, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestOpenBuilderBundleFlavors(t *testing.T) {
	root := t.TempDir()
	ub := writeFlavorBundle(t, root, FlavorUbuntu, FlavorUbuntu)
	rk := writeFlavorBundle(t, root, FlavorRocky, FlavorRocky)
	bs, err := OpenBuilderBundle(root)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(bs.Flavors(), ","); got != "ubuntu,rocky" || bs.Arch == "" {
		t.Fatalf("Flavors=%s Arch=%q", got, bs.Arch)
	}
	if b, err := bs.Flavor(FlavorUbuntu); err != nil || b.Dir != ub {
		t.Errorf("ubuntu: %v %v", b, err)
	}
	if b, err := bs.Flavor(FlavorRocky); err != nil || b.Dir != rk {
		t.Errorf("rocky: %v %v", b, err)
	}
	if _, err := bs.Flavor(FlavorDebian); err == nil || !strings.Contains(err.Error(), "Debian 전용 묶음(debian/)") {
		t.Errorf("debian 묶음이 없는데 err=%v", err)
	}

	// Ubuntu 묶음에는 네이티브 빌더 파일이, 네이티브 묶음에는 Ubuntu 전용 파일이 없어야 합니다 (서로 영향 없음)
	for _, f := range ubuntuBuilderFiles {
		if f == "setup-builder.sh" || f == "build-environment" || f == "builder.example.json" {
			for _, nf := range nativeBuilderFiles {
				if nf == f {
					t.Errorf("네이티브 묶음에 Ubuntu 전용 %s", f)
				}
			}
		}
	}
	for _, f := range []string{"setup-native-builder.sh", "kpctl-native-builder.py", "kpctl-native-builder.timer"} {
		if _, err := os.Stat(filepath.Join(ub, f)); err == nil {
			t.Errorf("Ubuntu 묶음에 %s", f)
		}
	}
}

func TestOpenBuilderBundleRejects(t *testing.T) {
	// 표식이 다른 종류
	root := t.TempDir()
	writeFlavorBundle(t, root, FlavorDebian, FlavorRocky)
	if _, err := OpenBuilderBundle(root); err == nil || !strings.Contains(err.Error(), `"rocky" 입니다 ("debian" 여야 함)`) {
		t.Errorf("표식 불일치: %v", err)
	}
	// 파일 빠짐
	root = t.TempDir()
	dir := writeFlavorBundle(t, root, FlavorUbuntu, FlavorUbuntu)
	if err := os.Remove(filepath.Join(dir, "setup-builder.sh")); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenBuilderBundle(root); err == nil || !strings.Contains(err.Error(), "setup-builder.sh 가 없습니다") {
		t.Errorf("파일 누락: %v", err)
	}
	// 나뉘기 전 통합 묶음
	root = t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "setup-builder.sh"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenBuilderBundle(root); err == nil || !strings.Contains(err.Error(), "통합 묶음") {
		t.Errorf("통합 묶음: %v", err)
	}
	// 빈 디렉터리
	if _, err := OpenBuilderBundle(t.TempDir()); err == nil || !strings.Contains(err.Error(), "묶음이 없습니다") {
		t.Errorf("빈 디렉터리: %v", err)
	}
}

func TestFactsBuilderFlavor(t *testing.T) {
	for distro, want := range map[string]string{"ubuntu": FlavorUbuntu, "debian": FlavorDebian, "rocky": FlavorRocky, "almalinux": "", "": ""} {
		if got := (Facts{Distro: distro}).BuilderFlavor(); got != want {
			t.Errorf("%q → %q, want %q", distro, got, want)
		}
	}
}
