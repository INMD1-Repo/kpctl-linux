// 이 파일: updater 패키지의 역할 감지, 릴리즈/-dev/now Git 업데이트, 원자적 설치, post-merge 훅 회귀 시험.
package updater

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func mustRun(t *testing.T, dir string, name string, args ...string) string {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=Tester",
		"GIT_AUTHOR_EMAIL=tester@example.test",
		"GIT_COMMITTER_NAME=Tester",
		"GIT_COMMITTER_EMAIL=tester@example.test",
		"KPCTL_UPDATE_RUNNING=1",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v failed: %v\n%s", name, args, err, string(out))
	}
	return strings.TrimSpace(string(out))
}

func writeTestFile(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
}

// makeRepoFixture 는 실제 kpctl 저장소 구조의 bare origin 과 clone 작업 트리를 만듭니다.
func makeRepoFixture(t *testing.T) (bareDir, workDir string) {
	t.Helper()
	root := t.TempDir()
	bareDir = filepath.Join(root, "origin.git")
	seedDir := filepath.Join(root, "seed")
	workDir = filepath.Join(root, "work")

	mustRun(t, root, "git", "init", "--bare", bareDir)
	mustRun(t, root, "git", "init", "-b", "main", seedDir)
	mustRun(t, seedDir, "git", "remote", "add", "origin", bareDir)

	populateKpctlRepoFiles(t, seedDir, "v1.0.0")
	mustRun(t, seedDir, "git", "add", "-A")
	mustRun(t, seedDir, "git", "commit", "-m", "initial release")
	mustRun(t, seedDir, "git", "tag", "v1.0.0")
	mustRun(t, seedDir, "git", "push", "-u", "origin", "main", "--tags")

	// Dev 브랜치 생성
	mustRun(t, seedDir, "git", "checkout", "-b", "Dev")
	writeTestFile(t, filepath.Join(seedDir, "deploy/kpctl-kernel-debug.sh"), "#!/bin/sh\n# dev-build\n", 0o755)
	mustRun(t, seedDir, "git", "add", "-A")
	mustRun(t, seedDir, "git", "commit", "-m", "dev feature")
	mustRun(t, seedDir, "git", "push", "-u", "origin", "Dev")

	// workDir 에 main 체크아웃 상태로 clone
	mustRun(t, root, "git", "clone", "-b", "main", bareDir, workDir)
	return bareDir, workDir
}

func populateKpctlRepoFiles(t *testing.T, dir, marker string) {
	t.Helper()
	writeTestFile(t, filepath.Join(dir, "go.mod"), "module kpctl\n\ngo 1.24\n", 0o644)
	writeTestFile(t, filepath.Join(dir, "cmd/kpctl/main.go"), "package main\n", 0o644)
	writeTestFile(t, filepath.Join(dir, "internal/controller/web/index.html"), "<html>"+marker+"</html>\n", 0o644)

	// deploy 파일들
	deployFiles := map[string]string{
		"deploy/install-agent.sh":                      "#!/bin/sh\n# " + marker + "\n",
		"deploy/uninstall-agent.sh":                    "#!/bin/sh\n# " + marker + "\n",
		"deploy/kpctl-prepare-kernel.py":               "#!/usr/bin/env python3\n# " + marker + "\n",
		"deploy/mirrors.list":                          "https://mirror.example.test\n",
		"deploy/systemd/kpctl-agent.service":           "[Unit]\nDescription=agent " + marker + "\n",
		"configs/reboot-hook.example.sh":               "#!/bin/sh\n",
		"deploy/kpatch/kpatch":                         "#!/bin/sh\n",
		"deploy/kpatch/kpatch.service":                 "[Unit]\nDescription=kpatch\n",
		"deploy/setup-builder.sh":                      "#!/bin/sh\n",
		"deploy/kpctl-kernel-debug.sh":                 "#!/bin/sh\n# " + marker + "\n",
		"deploy/kpctl-kernel-inputs.py":                "#!/usr/bin/env python3\n# " + marker + "\n",
		"deploy/kpctl-kpatch-fixes.sh":                 "#!/bin/sh\n",
		"deploy/kpctl-kpatch-cold-test.py":             "#!/usr/bin/env python3\n",
		"deploy/setup-build-environment.sh":            "#!/bin/sh\n",
		"deploy/kpctl-build-environment.py":            "#!/usr/bin/env python3\n# " + marker + "\n",
		"deploy/kpatch-fixes/0001-test.patch":          "diff --git a/x b/x\n",
		"deploy/build-environment/Containerfile":       "FROM ubuntu:24.04\n# " + marker + "\n",
		"deploy/build-environment/install-packages.sh": "#!/bin/sh\n",
		"deploy/build-environment/configure-apt.sh":    "#!/bin/sh\n",
		"deploy/build-environment/toolchain-pins.sh":   "#!/bin/sh\n",
		"configs/builder.example.json":                 "{}\n",
		"deploy/setup-native-builder.sh":               "#!/bin/sh\n",
		"deploy/kpctl-native-builder.py":               "#!/usr/bin/env python3\n# " + marker + "\n",
		"deploy/native_inputs.py":                      "# " + marker + "\n",
		"deploy/kpctl-native-work.sh":                  "#!/bin/sh\n# " + marker + "\n",
		"deploy/kpctl-cve-inventory.py":                "#!/usr/bin/env python3\n# " + marker + "\n",
		"deploy/systemd/kpctl-controller.service":      "[Unit]\nDescription=controller " + marker + "\n",
		"deploy/systemd/kpctl-cve-inventory.service":   "[Unit]\nDescription=cve\n",
		"deploy/systemd/kpctl-cve-inventory.timer":     "[Timer]\n",
		"deploy/systemd/kpctl-autoenroll.service":      "[Unit]\nDescription=autoenroll\n",
		"deploy/systemd/kpctl-autoenroll.timer":        "[Timer]\n",
		"deploy/systemd/kpctl-dnsmasq.service":         "[Unit]\nDescription=dnsmasq\n",
		"deploy/systemd/kpctl-native-builder.service":  "[Service]\nUser=kpbuild\nGroup=kpbuild\n# " + marker + "\n",
		"deploy/systemd/kpctl-native-builder.timer":    "[Timer]\n# " + marker + "\n",
		"deploy/systemd/kpctl-builder.service":         "[Service]\nUser=kpbuild\nGroup=kpbuild\n# kpbuild 소유\n# ~kpbuild\nExecStartPre=+/bin/sh -c '[ \"$(stat -c %%U:%%h \"$u\")\" = kpbuild:1 ]'\n# " + marker + "\n",
	}
	for rel, body := range deployFiles {
		writeTestFile(t, filepath.Join(dir, rel), body, 0o644)
	}
}

func fakeBuildFunc(t *testing.T) func(ctx context.Context, repoDir, outDir string, plan *Plan, roles []Role, buildWeb bool) error {
	t.Helper()
	return func(_ context.Context, _ string, outDir string, plan *Plan, roles []Role, _ bool) error {
		bins := []string{"kpctl", "kpctl-builder"}
		if hasRole(roles, RoleController) {
			bins = append(bins, "kpctl-controller", "kpctl-agent")
		}
		for _, name := range bins {
			writeTestFile(t, filepath.Join(outDir, name), "#!/bin/sh\necho "+name+"-"+plan.TargetCommit+"\n", 0o755)
		}
		return nil
	}
}

func TestDetectRoles(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		if got := DetectRoles(t.TempDir()); len(got) != 0 {
			t.Fatalf("got=%v, want empty", got)
		}
	})

	t.Run("controller only", func(t *testing.T) {
		root := t.TempDir()
		writeTestFile(t, filepath.Join(root, "etc/kpctl/controller.json"), "{}", 0o640)
		got := DetectRoles(root)
		if len(got) != 1 || got[0] != RoleController {
			t.Fatalf("got=%v, want [controller]", got)
		}
	})

	t.Run("native builder does not trigger ubuntu builder", func(t *testing.T) {
		root := t.TempDir()
		writeTestFile(t, filepath.Join(root, "usr/local/bin/kpctl-builder"), "bin", 0o755)
		writeTestFile(t, filepath.Join(root, "opt/kpctl/native-builder/kpctl-native-builder.py"), "py", 0o755)
		got := DetectRoles(root)
		if len(got) != 1 || got[0] != RoleNativeBuilder {
			t.Fatalf("got=%v, want [native-builder]", got)
		}
	})

	t.Run("ubuntu builder only", func(t *testing.T) {
		root := t.TempDir()
		writeTestFile(t, filepath.Join(root, "etc/kpctl/builder.json"), "{}", 0o640)
		got := DetectRoles(root)
		if len(got) != 1 || got[0] != RoleBuilder {
			t.Fatalf("got=%v, want [builder]", got)
		}
	})
}

func TestReleaseUpdateControllerAndIdempotent(t *testing.T) {
	bareDir, workDir := makeRepoFixture(t)
	sysRoot := t.TempDir()
	writeTestFile(t, filepath.Join(sysRoot, "etc/kpctl/controller.json"), `{"listen":":8443"}`, 0o640)

	// 원격 main 에 새 릴리즈 v1.1.0 커밋 추가
	pusher := t.TempDir()
	mustRun(t, pusher, "git", "clone", "-b", "main", bareDir, ".")
	writeTestFile(t, filepath.Join(pusher, "deploy/kpctl-cve-inventory.py"), "#!/usr/bin/env python3\n# v1.1.0\n", 0o755)
	mustRun(t, pusher, "git", "add", "-A")
	mustRun(t, pusher, "git", "commit", "-m", "release v1.1.0")
	mustRun(t, pusher, "git", "tag", "v1.1.0")
	mustRun(t, pusher, "git", "push", "origin", "main", "--tags")
	wantCommit := mustRun(t, pusher, "git", "rev-parse", "HEAD")

	var ctlCalls []string
	ctlFn := func(args ...string) (string, error) {
		ctlCalls = append(ctlCalls, strings.Join(args, " "))
		return "", nil
	}

	// 1) -check: 아무것도 수정하지 않고 업데이트 필요만 보고
	var checkBuf bytes.Buffer
	plan, err := Run(context.Background(), Options{
		Channel:       ChannelRelease,
		RepoDir:       workDir,
		Check:         true,
		SysRoot:       sysRoot,
		Stdout:        &checkBuf,
		Stderr:        &checkBuf,
		SkipRootCheck: true,
		BuildFunc:     fakeBuildFunc(t),
		SystemctlFunc: ctlFn,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !plan.NeedsPull || !plan.NeedsInstall || plan.TargetVersion != "v1.1.0" || plan.TargetCommit != wantCommit {
		t.Fatalf("unexpected check plan: %+v", plan)
	}
	if len(ctlCalls) != 0 {
		t.Fatalf("-check ran systemctl: %v", ctlCalls)
	}

	// 2) 실제 업데이트 실행
	var runBuf bytes.Buffer
	plan, err = Run(context.Background(), Options{
		Channel:       ChannelRelease,
		RepoDir:       workDir,
		SysRoot:       sysRoot,
		Stdout:        &runBuf,
		Stderr:        &runBuf,
		SkipRootCheck: true,
		BuildFunc:     fakeBuildFunc(t),
		SystemctlFunc: ctlFn,
	})
	if err != nil {
		t.Fatalf("Run failed: %v\n%s", err, runBuf.String())
	}
	if got := mustRun(t, workDir, "git", "rev-parse", "HEAD"); got != wantCommit {
		t.Fatalf("HEAD=%s, want %s", got, wantCommit)
	}
	// 설치된 파일 확인
	for _, rel := range []string{
		"usr/local/bin/kpctl-controller",
		"usr/local/bin/kpctl",
		"usr/local/share/kpctl/agent/kpctl-agent",
		"usr/local/share/kpctl/builder/kpctl-builder",
		"usr/local/share/kpctl/builder/ubuntu/builder-flavor",
		"usr/local/share/kpctl/builder/debian/builder-flavor",
		"usr/local/share/kpctl/builder/rocky/builder-flavor",
		"usr/local/libexec/kpctl-cve-inventory",
		"etc/systemd/system/kpctl-controller.service",
	} {
		if !pathExists(filepath.Join(sysRoot, rel)) {
			t.Errorf("missing installed file: %s", rel)
		}
	}
	cveData, _ := os.ReadFile(filepath.Join(sysRoot, "usr/local/libexec/kpctl-cve-inventory"))
	if !strings.Contains(string(cveData), "v1.1.0") {
		t.Errorf("cve inventory not updated: %q", string(cveData))
	}
	// 기존 controller.json 보존
	cfgData, _ := os.ReadFile(filepath.Join(sysRoot, "etc/kpctl/controller.json"))
	if string(cfgData) != `{"listen":":8443"}` {
		t.Errorf("controller.json modified: %q", string(cfgData))
	}
	// systemctl 재시작 확인
	if strings.Join(ctlCalls, ";") != "daemon-reload;restart kpctl-controller" {
		t.Errorf("systemctl calls = %v", ctlCalls)
	}
	// post-merge 훅 자동 설치 확인
	if installed, _, err := HookInstalled(workDir); err != nil || !installed {
		t.Errorf("post-merge hook not installed: installed=%v err=%v", installed, err)
	}
	// 상태 저장 확인
	st, err := LoadState(sysRoot)
	if err != nil || st.Commit != wantCommit || st.Version != "v1.1.0" || st.Channel != "release" {
		t.Fatalf("unexpected saved state: %+v err=%v", st, err)
	}

	// 3) 같은 커밋에서 재실행 시 빌드·재시작 생략
	ctlCalls = nil
	buildCalled := false
	var againBuf bytes.Buffer
	plan, err = Run(context.Background(), Options{
		Channel:       ChannelRelease,
		RepoDir:       workDir,
		SysRoot:       sysRoot,
		Stdout:        &againBuf,
		Stderr:        &againBuf,
		SkipRootCheck: true,
		BuildFunc: func(_ context.Context, _, _ string, _ *Plan, _ []Role, _ bool) error {
			buildCalled = true
			return nil
		},
		SystemctlFunc: ctlFn,
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.NeedsUpdate() || buildCalled || len(ctlCalls) != 0 {
		t.Fatalf("expected no-op second run: needs=%v build=%v ctl=%v", plan.NeedsUpdate(), buildCalled, ctlCalls)
	}
}

func TestDevChannelUpdatesUbuntuBuilderAndPreservesUser(t *testing.T) {
	_, workDir := makeRepoFixture(t)
	sysRoot := t.TempDir()
	// 커스텀 빌드 사용자(mybuild)로 설치된 Ubuntu 빌더 + sandbox 환경
	writeTestFile(t, filepath.Join(sysRoot, "etc/kpctl/builder.json"), `{"series":"noble"}`, 0o640)
	writeTestFile(t, filepath.Join(sysRoot, "etc/systemd/system/kpctl-builder.service"),
		"[Service]\nUser=mybuild\nGroup=mygroup\n", 0o644)
	writeTestFile(t, filepath.Join(sysRoot, "usr/local/libexec/kpctl-build-environment"), "old", 0o755)

	var ctlCalls []string
	var buf bytes.Buffer
	plan, err := Run(context.Background(), Options{
		Channel:       ChannelDev,
		RepoDir:       workDir,
		SysRoot:       sysRoot,
		Stdout:        &buf,
		Stderr:        &buf,
		SkipRootCheck: true,
		BuildFunc:     fakeBuildFunc(t),
		SystemctlFunc: func(args ...string) (string, error) {
			ctlCalls = append(ctlCalls, strings.Join(args, " "))
			return "", nil
		},
	})
	if err != nil {
		t.Fatalf("Run(-dev) failed: %v\n%s", err, buf.String())
	}
	if plan.TargetBranch != "Dev" {
		t.Fatalf("TargetBranch=%q, want Dev", plan.TargetBranch)
	}
	if got := mustRun(t, workDir, "git", "rev-parse", "--abbrev-ref", "HEAD"); got != "Dev" {
		t.Fatalf("HEAD branch=%q, want Dev", got)
	}
	debugScript, _ := os.ReadFile(filepath.Join(sysRoot, "usr/local/sbin/kpctl-kernel-debug"))
	if !strings.Contains(string(debugScript), "dev-build") {
		t.Errorf("kpctl-kernel-debug not updated from Dev: %q", string(debugScript))
	}
	unit, _ := os.ReadFile(filepath.Join(sysRoot, "etc/systemd/system/kpctl-builder.service"))
	if !strings.Contains(string(unit), "User=mybuild") || !strings.Contains(string(unit), "Group=mygroup") ||
		!strings.Contains(string(unit), "= mybuild:1 ]") {
		t.Errorf("custom build user not preserved in unit:\n%s", string(unit))
	}
	if !pathExists(filepath.Join(sysRoot, "usr/local/share/kpctl/build-environment/Containerfile")) {
		t.Errorf("sandbox build-environment assets not updated")
	}
	if strings.Join(ctlCalls, ";") != "daemon-reload;restart kpctl-builder" {
		t.Errorf("systemctl calls = %v", ctlCalls)
	}
}

func TestNowChannelPullsCurrentBranchAndSupportsLocalAhead(t *testing.T) {
	bareDir, workDir := makeRepoFixture(t)
	sysRoot := t.TempDir()
	writeTestFile(t, filepath.Join(sysRoot, "opt/kpctl/native-builder/kpctl-native-builder.py"), "old", 0o755)
	writeTestFile(t, filepath.Join(sysRoot, "etc/systemd/system/kpctl-native-builder.service"),
		"[Service]\nUser=natbuild\nGroup=natgroup\n", 0o644)

	// 피처 브랜치 생성 후 원격에 푸시
	mustRun(t, workDir, "git", "checkout", "-b", "feat/rocky-fix")
	mustRun(t, workDir, "git", "push", "-u", "origin", "feat/rocky-fix")

	// 다른 클론에서 feat/rocky-fix 에 새 커밋 푸시
	pusher := t.TempDir()
	mustRun(t, pusher, "git", "clone", "-b", "feat/rocky-fix", bareDir, ".")
	writeTestFile(t, filepath.Join(pusher, "deploy/kpctl-native-builder.py"), "#!/usr/bin/env python3\n# remote-feature\n", 0o755)
	mustRun(t, pusher, "git", "add", "-A")
	mustRun(t, pusher, "git", "commit", "-m", "remote feature commit")
	mustRun(t, pusher, "git", "push", "origin", "feat/rocky-fix")
	remoteFeatCommit := mustRun(t, pusher, "git", "rev-parse", "HEAD")

	var ctlCalls []string
	var buf bytes.Buffer
	plan, err := Run(context.Background(), Options{
		Channel:       ChannelNow,
		RepoDir:       workDir,
		SysRoot:       sysRoot,
		Stdout:        &buf,
		Stderr:        &buf,
		SkipRootCheck: true,
		BuildFunc:     fakeBuildFunc(t),
		SystemctlFunc: func(args ...string) (string, error) {
			ctlCalls = append(ctlCalls, strings.Join(args, " "))
			return "", nil
		},
	})
	if err != nil {
		t.Fatalf("Run(now) failed: %v\n%s", err, buf.String())
	}
	if plan.TargetBranch != "feat/rocky-fix" || plan.TargetCommit != remoteFeatCommit {
		t.Fatalf("unexpected plan: %+v", plan)
	}
	pyData, _ := os.ReadFile(filepath.Join(sysRoot, "opt/kpctl/native-builder/kpctl-native-builder.py"))
	if !strings.Contains(string(pyData), "remote-feature") {
		t.Errorf("native builder script not updated: %q", string(pyData))
	}
	unit, _ := os.ReadFile(filepath.Join(sysRoot, "etc/systemd/system/kpctl-native-builder.service"))
	if !strings.Contains(string(unit), "User=natbuild") || !strings.Contains(string(unit), "Group=natgroup") {
		t.Errorf("native builder user not preserved:\n%s", string(unit))
	}
	if strings.Join(ctlCalls, ";") != "daemon-reload;is-active --quiet kpctl-native-builder.timer;restart kpctl-native-builder.timer" {
		t.Errorf("systemctl calls = %v", ctlCalls)
	}

	// 이제 같은 브랜치에서 푸시하지 않은 로컬 커밋 추가 → now 모드는 로컬 최신 커밋으로 업데이트
	writeTestFile(t, filepath.Join(workDir, "deploy/kpctl-native-builder.py"), "#!/usr/bin/env python3\n# local-ahead\n", 0o755)
	mustRun(t, workDir, "git", "add", "-A")
	mustRun(t, workDir, "git", "commit", "-m", "local unpushed commit")
	localAheadCommit := mustRun(t, workDir, "git", "rev-parse", "HEAD")

	buf.Reset()
	plan, err = Run(context.Background(), Options{
		Channel:       ChannelNow,
		RepoDir:       workDir,
		SysRoot:       sysRoot,
		Stdout:        &buf,
		Stderr:        &buf,
		SkipRootCheck: true,
		BuildFunc:     fakeBuildFunc(t),
		SystemctlFunc: func(args ...string) (string, error) { return "", nil },
	})
	if err != nil {
		t.Fatalf("Run(now local-ahead) failed: %v\n%s", err, buf.String())
	}
	if !plan.LocalAhead || plan.NeedsPull || plan.TargetCommit != localAheadCommit {
		t.Fatalf("unexpected local-ahead plan: %+v", plan)
	}
	pyData, _ = os.ReadFile(filepath.Join(sysRoot, "opt/kpctl/native-builder/kpctl-native-builder.py"))
	if !strings.Contains(string(pyData), "local-ahead") {
		t.Errorf("native builder script not updated to local-ahead: %q", string(pyData))
	}
}

func TestDirtyWorkingTreeRefusesPull(t *testing.T) {
	bareDir, workDir := makeRepoFixture(t)
	sysRoot := t.TempDir()
	writeTestFile(t, filepath.Join(sysRoot, "etc/kpctl/controller.json"), `{}`, 0o640)

	// 원격에 새 커밋 추가
	pusher := t.TempDir()
	mustRun(t, pusher, "git", "clone", "-b", "main", bareDir, ".")
	writeTestFile(t, filepath.Join(pusher, "README.md"), "updated\n", 0o644)
	mustRun(t, pusher, "git", "add", "-A")
	mustRun(t, pusher, "git", "commit", "-m", "update readme")
	mustRun(t, pusher, "git", "push", "origin", "main")

	// 로컬에 커밋되지 않은 수정
	writeTestFile(t, filepath.Join(workDir, "dirty.txt"), "wip\n", 0o644)

	var buf bytes.Buffer
	_, err := Run(context.Background(), Options{
		Channel:       ChannelRelease,
		RepoDir:       workDir,
		SysRoot:       sysRoot,
		Stdout:        &buf,
		Stderr:        &buf,
		SkipRootCheck: true,
		BuildFunc:     fakeBuildFunc(t),
		SystemctlFunc: func(args ...string) (string, error) { return "", nil },
	})
	if err == nil || !strings.Contains(err.Error(), "커밋되지 않은 변경") {
		t.Fatalf("expected dirty working tree error, got: %v", err)
	}
}

func TestHookLifecycleAndFromHook(t *testing.T) {
	_, workDir := makeRepoFixture(t)

	// 설치·확인·제거
	p, err := InstallHook(workDir)
	if err != nil {
		t.Fatal(err)
	}
	if ok, gotPath, err := HookInstalled(workDir); err != nil || !ok || gotPath != p {
		t.Fatalf("HookInstalled=%v path=%q err=%v", ok, gotPath, err)
	}
	if _, removed, err := UninstallHook(workDir); err != nil || !removed {
		t.Fatalf("UninstallHook removed=%v err=%v", removed, err)
	}
	if ok, _, _ := HookInstalled(workDir); ok {
		t.Fatal("hook still reported installed after uninstall")
	}

	// 다른 도구가 만든 post-merge 훅은 덮어쓰지 않음
	writeTestFile(t, p, "#!/bin/sh\necho custom\n", 0o755)
	if _, err := InstallHook(workDir); err == nil || !strings.Contains(err.Error(), "다른 post-merge 훅") {
		t.Fatalf("expected foreign hook rejection, got: %v", err)
	}
	if _, _, err := UninstallHook(workDir); err == nil || !strings.Contains(err.Error(), "kpctl 이 설치한 훅이 아닙니다") {
		t.Fatalf("expected foreign hook uninstall rejection, got: %v", err)
	}

	// -from-hook: 설치된 역할이 없으면 오류 없이 건너뜀
	var buf bytes.Buffer
	if _, err := Run(context.Background(), Options{
		RepoDir:       workDir,
		FromHook:      true,
		SysRoot:       t.TempDir(),
		Stdout:        &buf,
		Stderr:        &buf,
		SkipRootCheck: true,
	}); err != nil {
		t.Fatalf("from-hook with no roles should succeed: %v", err)
	}
	if !strings.Contains(buf.String(), "건너뜁니다") {
		t.Errorf("expected skip message, got: %q", buf.String())
	}
}

func TestRealGitPullTriggersPostMergeHook(t *testing.T) {
	bareDir, workDir := makeRepoFixture(t)
	if _, err := InstallHook(workDir); err != nil {
		t.Fatal(err)
	}

	// 원격에 새 커밋 추가
	pusher := t.TempDir()
	mustRun(t, pusher, "git", "clone", "-b", "main", bareDir, ".")
	writeTestFile(t, filepath.Join(pusher, "README.md"), "pulled\n", 0o644)
	mustRun(t, pusher, "git", "add", "-A")
	mustRun(t, pusher, "git", "commit", "-m", "trigger hook")
	mustRun(t, pusher, "git", "push", "origin", "main")

	// 가짜 kpctl 바이너리로 post-merge 훅이 실제로 호출되는지 확인
	logFile := filepath.Join(t.TempDir(), "hook.log")
	fakeBin := filepath.Join(t.TempDir(), "kpctl")
	writeTestFile(t, fakeBin, "#!/bin/sh\nprintf '%s\\n' \"$*\" > \""+logFile+"\"\n", 0o755)

	cmd := exec.Command("git", "pull", "--ff-only", "origin", "main")
	cmd.Dir = workDir
	// KPCTL_UPDATE_RUNNING 없이 실행해야 훅이 동작함
	cmd.Env = append(os.Environ(), "KPCTL_BIN="+fakeBin, "KPCTL_HOOK_NO_SUDO=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git pull failed: %v\n%s", err, string(out))
	}

	gotBytes, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("post-merge hook did not invoke kpctl: %v", err)
	}
	got := strings.TrimSpace(string(gotBytes))
	if !strings.Contains(got, "update -from-hook -repo "+workDir) {
		t.Fatalf("unexpected hook invocation args: %q", got)
	}
}

func TestRealBuildArtifactsAndInstalledBinary(t *testing.T) {
	if testing.Short() {
		t.Skip("short 모드에서는 실제 go build 시험을 건너뜁니다")
	}
	repoRoot, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	if !IsKpctlRepo(repoRoot) {
		t.Fatalf("repoRoot %s is not kpctl repo", repoRoot)
	}

	// 현재 저장소를 임시 디렉터리에 로컬 clone 하여 실제 빌드·설치 전체 흐름을 검증합니다.
	cloneDir := filepath.Join(t.TempDir(), "kpctl-clone")
	mustRun(t, t.TempDir(), "git", "clone", "--no-hardlinks", repoRoot, cloneDir)
	// 현재 작업 디렉터리에 아직 커밋되지 않은 새 updater/version 코드가 있을 수 있으므로
	// 실제 go build 검증은 현재 작업 저장소(repoRoot)를 -from-hook 모드로 빌드해 확인합니다.
	sysRoot := t.TempDir()
	writeTestFile(t, filepath.Join(sysRoot, "etc/kpctl/controller.json"), `{"listen":":8443"}`, 0o640)

	var ctlCalls []string
	var buf bytes.Buffer
	plan, err := Run(context.Background(), Options{
		RepoDir:       repoRoot,
		FromHook:      true,
		Force:         true,
		NoHook:        true,
		SysRoot:       sysRoot,
		Stdout:        &buf,
		Stderr:        &buf,
		SkipRootCheck: true,
		SystemctlFunc: func(args ...string) (string, error) {
			ctlCalls = append(ctlCalls, strings.Join(args, " "))
			return "", nil
		},
	})
	if err != nil {
		t.Fatalf("real build Run failed: %v\n%s", err, buf.String())
	}
	if strings.Join(ctlCalls, ";") != "daemon-reload;restart kpctl-controller" {
		t.Fatalf("unexpected systemctl calls: %v", ctlCalls)
	}

	// 실제로 빌드·설치된 kpctl 바이너리를 실행해 버전 주입과 -check 동작을 검증합니다.
	installedCLI := filepath.Join(sysRoot, "usr/local/bin/kpctl")
	cmd := exec.Command(installedCLI, "update", "now", "-check", "-repo", cloneDir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("installed kpctl update now -check failed: %v\n%s", err, string(out))
	}
	outStr := string(out)
	shortCommit := plan.TargetCommit[:7]
	if !strings.Contains(outStr, shortCommit) || !strings.Contains(outStr, "현재 브랜치 (now)") {
		t.Fatalf("installed kpctl output missing version/channel info:\n%s", outStr)
	}

	// 컨트롤러·에이전트·빌더 바이너리가 모두 실제 실행 가능한 파일인지 확인
	for _, rel := range []string{
		"usr/local/bin/kpctl-controller",
		"usr/local/share/kpctl/agent/kpctl-agent",
		"usr/local/share/kpctl/builder/kpctl-builder",
		"usr/local/share/kpctl/builder/ubuntu/kpctl",
		"usr/local/share/kpctl/builder/debian/kpctl",
		"usr/local/share/kpctl/builder/rocky/kpctl",
	} {
		fi, err := os.Stat(filepath.Join(sysRoot, rel))
		if err != nil || fi.Size() < 1024 || fi.Mode()&0o111 == 0 {
			t.Errorf("invalid installed binary %s: err=%v info=%v", rel, err, fi)
		}
	}
}
