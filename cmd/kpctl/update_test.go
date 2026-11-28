// 이 파일: kpctl update CLI 인자 조합(-dev, now/-now, -check, -install-hook/-uninstall-hook) 회귀 시험.
package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func initTestRepo(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	bare := filepath.Join(root, "origin.git")
	work := filepath.Join(root, "repo")
	run := func(dir string, args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=Tester", "GIT_AUTHOR_EMAIL=t@example.test",
			"GIT_COMMITTER_NAME=Tester", "GIT_COMMITTER_EMAIL=t@example.test",
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, string(out))
		}
	}
	run(root, "init", "--bare", bare)
	run(root, "init", "-b", "main", work)
	run(work, "remote", "add", "origin", bare)
	if err := os.MkdirAll(filepath.Join(work, "cmd/kpctl"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(work, "go.mod"), []byte("module kpctl\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(work, "cmd/kpctl/main.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run(work, "add", "-A")
	run(work, "commit", "-m", "v1.0.0")
	run(work, "tag", "v1.0.0")
	run(work, "push", "-u", "origin", "main", "--tags")
	run(work, "checkout", "-b", "Dev")
	if err := os.WriteFile(filepath.Join(work, "dev.txt"), []byte("dev\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run(work, "add", "-A")
	run(work, "commit", "-m", "dev commit")
	run(work, "push", "-u", "origin", "Dev")
	run(work, "checkout", "main")
	return work
}

func TestUpdateCLIValidationAndCheck(t *testing.T) {
	repo := initTestRepo(t)
	sysRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(sysRoot, "etc/kpctl"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sysRoot, "etc/kpctl/controller.json"), []byte("{}"), 0o640); err != nil {
		t.Fatal(err)
	}

	// 상호 배타적 옵션 거부
	for _, badArgs := range [][]string{
		{"-dev", "-now"},
		{"now", "-dev"},
		{"-dev", "now"},
		{"-branch", "foo", "-dev"},
		{"-branch", "foo", "-now"},
		{"-install-hook", "-uninstall-hook"},
		{"unknown-arg"},
	} {
		var out, errBuf bytes.Buffer
		if err := runUpdateCommand(badArgs, &out, &errBuf, sysRoot); err == nil {
			t.Errorf("args %v expected error, got nil", badArgs)
		}
	}

	// 릴리즈 -check
	var out, errBuf bytes.Buffer
	if err := runUpdateCommand([]string{"-check", "-repo", repo}, &out, &errBuf, sysRoot); err != nil {
		t.Fatalf("release -check failed: %v", err)
	}
	if !strings.Contains(out.String(), "릴리즈 → v1.0.0") || !strings.Contains(out.String(), "컨트롤러") {
		t.Errorf("unexpected release -check output:\n%s", out.String())
	}

	// -dev -check
	out.Reset()
	if err := runUpdateCommand([]string{"-dev", "-check", "-repo", repo}, &out, &errBuf, sysRoot); err != nil {
		t.Fatalf("-dev -check failed: %v", err)
	}
	if !strings.Contains(out.String(), "개발 (-dev)") || !strings.Contains(out.String(), "Dev") {
		t.Errorf("unexpected -dev -check output:\n%s", out.String())
	}

	// now -check (위치 인자 + 플래그 모두 지원)
	for _, args := range [][]string{
		{"now", "-check", "-repo", repo},
		{"-now", "-check", "-repo", repo},
		{"-check", "-repo", repo, "now"},
	} {
		out.Reset()
		if err := runUpdateCommand(args, &out, &errBuf, sysRoot); err != nil {
			t.Fatalf("%v failed: %v", args, err)
		}
		if !strings.Contains(out.String(), "현재 브랜치 (now)") {
			t.Errorf("%v unexpected output:\n%s", args, out.String())
		}
	}

	// -install-hook / -uninstall-hook
	out.Reset()
	if err := runUpdateCommand([]string{"-install-hook", "-repo", repo}, &out, &errBuf, sysRoot); err != nil {
		t.Fatalf("-install-hook failed: %v", err)
	}
	if !strings.Contains(out.String(), "post-merge") {
		t.Errorf("unexpected -install-hook output:\n%s", out.String())
	}
	out.Reset()
	if err := runUpdateCommand([]string{"-uninstall-hook", "-repo", repo}, &out, &errBuf, sysRoot); err != nil {
		t.Fatalf("-uninstall-hook failed: %v", err)
	}
	if !strings.Contains(out.String(), "제거했습니다") {
		t.Errorf("unexpected -uninstall-hook output:\n%s", out.String())
	}
}
