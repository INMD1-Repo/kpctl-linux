// 이 파일: builder 패키지의 TestRemoteLatestTag, TestDiscoverDefaults, TestGCCRegexp 회귀 시험.
package builder

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func run(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v %s", args, err, out)
	}
}

func TestRemoteLatestTag(t *testing.T) {
	root := t.TempDir()
	up := filepath.Join(root, "upstream")
	clone := filepath.Join(root, "clone")
	os.MkdirAll(up, 0o755)
	run(t, up, "init", "-q")
	run(t, up, "commit", "-q", "--allow-empty", "-m", "a")
	run(t, up, "tag", "Ubuntu-6.8.0-85.85")
	run(t, root, "clone", "-q", up, clone)

	remote, err := remoteLatestTag(clone, "Ubuntu-6.8.0-*")
	if err != nil {
		t.Fatal(err)
	}
	local, _ := latestTag(clone, "Ubuntu-6.8.0-*")
	if remote != "Ubuntu-6.8.0-85.85" || remote != local {
		t.Fatalf("원격 %q 로컬 %q", remote, local)
	}

	// 원격에 새 태그 (버전 정렬: 100 > 99 > 85)
	run(t, up, "commit", "-q", "--allow-empty", "-m", "b")
	run(t, up, "tag", "Ubuntu-6.8.0-99.99")
	run(t, up, "tag", "Ubuntu-6.8.0-100.100")
	run(t, up, "tag", "Ubuntu-5.15.0-200.210") // 다른 계열은 무시
	remote, err = remoteLatestTag(clone, "Ubuntu-6.8.0-*")
	if err != nil {
		t.Fatal(err)
	}
	if remote != "Ubuntu-6.8.0-100.100" {
		t.Fatalf("새 원격 태그 = %q", remote)
	}
}

func TestDiscoverDefaults(t *testing.T) {
	write := func(body string) string {
		p := filepath.Join(t.TempDir(), "b.json")
		os.WriteFile(p, []byte(body), 0o600)
		return p
	}
	base := `"controller_url":"https://c","token":"x","series":"noble","work_dir":"` + t.TempDir() + `"`
	cfg, err := LoadConfig(write("{" + base + "}"))
	if err != nil {
		t.Fatal(err)
	}
	if *cfg.DiscoverMinutes != 60 || *cfg.UpdateCheckMinutes != 5 {
		t.Fatalf("기본값 = %d, %d", *cfg.DiscoverMinutes, *cfg.UpdateCheckMinutes)
	}
	cfg, err = LoadConfig(write(`{` + base + `,"discover_minutes":0}`))
	if err != nil {
		t.Fatal(err)
	}
	if *cfg.DiscoverMinutes != 0 {
		t.Fatalf("0 은 끔이어야 함: %d", *cfg.DiscoverMinutes)
	}
	if _, err := LoadConfig(write(`{` + base + `,"update_check_minutes":-1}`)); err == nil {
		t.Fatal("음수는 거부해야 함")
	}
}

func TestGCCRegexp(t *testing.T) {
	h := `#define LINUX_COMPILER "gcc (Ubuntu 15.2.0-16ubuntu1) 15.2.0, GNU ld (GNU Binutils for Ubuntu) 2.45"`
	if got := gccRe.FindString(h); got != "gcc (Ubuntu 15.2.0-16ubuntu1) 15.2.0" {
		t.Fatalf("compile.h → %q", got)
	}
	v := "gcc (Ubuntu 15.2.0-16ubuntu1) 15.2.0\nCopyright (C) 2025"
	if got := gccRe.FindString(v); got != "gcc (Ubuntu 15.2.0-16ubuntu1) 15.2.0" {
		t.Fatalf("gcc --version → %q", got)
	}
}

func TestInstallDebugNeedsHelper(t *testing.T) {
	on, off := true, false
	b := &Builder{cfg: &Config{AutoDebugSymbols: &off, DebugHelper: "/bin/true"}}
	if err := b.installDebug("7.0.0-28-generic", "7.0.0-28.28"); err == nil {
		t.Fatal("꺼져 있으면 설치하면 안 됨")
	}
	b.cfg = &Config{AutoDebugSymbols: &on, DebugHelper: filepath.Join(t.TempDir(), "none")}
	if err := b.installDebug("7.0.0-28-generic", ""); err == nil || !strings.Contains(err.Error(), "builder-migration.md") || !strings.Contains(err.Error(), "sudo 규칙") {
		t.Fatalf("도우미가 없으면 안내해야 함: %v", err)
	}
}

func TestGCCIDIgnoresProgramName(t *testing.T) {
	k := gccRe.FindString(`#define LINUX_COMPILER "gcc-13 (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0, GNU ld (GNU Binutils for Ubuntu) 2.42"`)
	m := gccRe.FindString("gcc (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0\nCopyright")
	if k == "" || m == "" || gccID(k) != gccID(m) {
		t.Fatalf("이름만 다른 같은 gcc 는 같아야 함: %q / %q", k, m)
	}
	other := gccRe.FindString("x86_64-linux-gnu-gcc-13 (Ubuntu 13.2.0-23ubuntu4) 13.2.0")
	if gccID(other) == gccID(m) {
		t.Fatalf("패키지 버전이 다르면 달라야 함: %q", other)
	}
}
