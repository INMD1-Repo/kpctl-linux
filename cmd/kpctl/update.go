// 이 파일: kpctl update — Git 릴리즈(-dev 개발판 / now 현재 브랜치) 확인·pull 후 컨트롤러·빌더 자동 업데이트.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"kpctl/internal/client"
	"kpctl/internal/updater"
)

const updateUsage = `사용법: kpctl update [옵션]
        kpctl update -dev [옵션]          개발 버전(Dev 브랜치)으로 업데이트
        kpctl update now [옵션]           현재 체크아웃된 자기 브랜치의 최신 커밋으로 업데이트
        kpctl update -install-hook        git pull 시 자동 업데이트하는 post-merge 훅 설치

  현재 서버에 설치된 역할(컨트롤러 / Ubuntu 빌더 / Debian·Rocky 네이티브 빌더)을 자동으로 감지해
  Git 에서 새 커밋을 받은 뒤 바이너리·도우미·systemd 유닛을 갱신하고 서비스를 재시작합니다.
  기본(옵션 없음)은 릴리즈 채널(main)을 기준으로 비교하며, -dev 는 개발 채널(Dev),
  now(또는 -now)는 현재 브랜치의 최신 커밋을 가져옵니다.

  예) sudo kpctl update                     릴리즈 최신 버전으로 업데이트
      sudo kpctl update -dev                개발 버전(Dev)으로 업데이트
      sudo kpctl update now                 현재 브랜치의 최신 커밋으로 업데이트
      kpctl update -check                   업데이트 가능 여부·감지 역할만 확인
      kpctl update -dev -check              개발 버전 업데이트 여부 확인
      kpctl update -install-hook            저장소에 git pull 자동 업데이트 훅 설치
      kpctl update -uninstall-hook          설치한 자동 업데이트 훅 제거

옵션:`

func cmdUpdate(_ *client.Client, args []string) error {
	return runUpdateCommand(args, os.Stdout, os.Stderr, "")
}

func runUpdateCommand(args []string, stdout, stderr io.Writer, sysRoot string) error {
	nowArg := false
	if len(args) > 0 && args[0] == "now" {
		nowArg = true
		args = args[1:]
	}

	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintln(stderr, updateUsage)
		fs.PrintDefaults()
	}

	dev := fs.Bool("dev", false, "개발 버전 채널(origin/Dev)로 업데이트")
	nowFlag := fs.Bool("now", false, "현재 체크아웃된 자기 브랜치의 최신 커밋으로 업데이트")
	branch := fs.String("branch", "", "특정 브랜치를 직접 지정해 업데이트")
	check := fs.Bool("check", false, "버전 비교와 감지 역할만 출력하고 실제 업데이트는 하지 않음")
	force := fs.Bool("force", false, "이미 같은 커밋이어도 강제로 다시 빌드·설치")
	repo := fs.String("repo", "", "kpctl-linux Git 저장소 경로 (미지정 시 자동 탐색, 없으면 /opt/kpctl/src 에 복제)")
	remote := fs.String("remote", updater.DefaultRemote, "Git 원격 이름")
	remoteURL := fs.String("remote-url", updater.DefaultRemoteURL, "저장소가 없을 때 복제할 원격 주소")
	roleSpec := fs.String("role", "auto", "업데이트할 역할 (auto, controller, builder, native-builder; 쉼표로 복수 지정)")
	buildWeb := fs.Bool("web", false, "관리자 웹(npm)을 다시 빌드한 뒤 컨트롤러에 포함")
	noRestart := fs.Bool("no-restart", false, "파일만 갱신하고 서비스 재시작 생략")
	installHook := fs.Bool("install-hook", false, "저장소에 git pull 자동 업데이트(post-merge) 훅만 설치")
	uninstallHook := fs.Bool("uninstall-hook", false, "저장소의 git pull 자동 업데이트 훅 제거")
	noHook := fs.Bool("no-hook", false, "업데이트 시 post-merge 훅 자동 설치 생략")
	fromHook := fs.Bool("from-hook", false, "git post-merge 훅에서 호출하는 내부 모드 (재-pull 생략)")

	if err := fs.Parse(args); err != nil {
		return err
	}

	rest := fs.Args()
	for _, a := range rest {
		if a == "now" && !nowArg && !*nowFlag {
			nowArg = true
			continue
		}
		return fmt.Errorf("알 수 없는 인자: %s (사용법: kpctl update -h)", a)
	}

	useNow := nowArg || *nowFlag
	if *installHook && *uninstallHook {
		return fmt.Errorf("-install-hook 과 -uninstall-hook 은 함께 지정할 수 없습니다")
	}
	if *dev && useNow {
		return fmt.Errorf("-dev 와 now(-now) 는 함께 지정할 수 없습니다")
	}
	if *branch != "" && (*dev || useNow) {
		return fmt.Errorf("-branch 는 -dev 또는 now(-now) 와 함께 지정할 수 없습니다")
	}

	if *installHook || *uninstallHook {
		return runUpdateHookCommand(*installHook, *repo, sysRoot, stdout)
	}

	roles, err := updater.ParseRoles(*roleSpec)
	if err != nil {
		return err
	}

	channel := updater.ChannelRelease
	switch {
	case *dev:
		channel = updater.ChannelDev
	case useNow:
		channel = updater.ChannelNow
	case strings.TrimSpace(*branch) != "":
		channel = updater.ChannelCustom
	}

	opts := updater.Options{
		Channel:   channel,
		Branch:    strings.TrimSpace(*branch),
		RepoDir:   strings.TrimSpace(*repo),
		Remote:    strings.TrimSpace(*remote),
		RemoteURL: strings.TrimSpace(*remoteURL),
		Roles:     roles,
		Check:     *check,
		Force:     *force,
		NoRestart: *noRestart,
		BuildWeb:  *buildWeb,
		FromHook:  *fromHook,
		NoHook:    *noHook,
		SysRoot:   sysRoot,
		Stdout:    stdout,
		Stderr:    stderr,
	}
	_, err = updater.Run(context.Background(), opts)
	return err
}

func runUpdateHookCommand(install bool, explicitRepo, sysRoot string, stdout io.Writer) error {
	state, _ := updater.LoadState(sysRoot)
	cwd, _ := os.Getwd()
	repoDir := updater.FindRepo(sysRoot, explicitRepo, cwd, state)
	if repoDir == "" {
		if explicitRepo != "" {
			abs, _ := filepath.Abs(explicitRepo)
			return fmt.Errorf("지정한 경로가 kpctl-linux Git 저장소가 아닙니다: %s", abs)
		}
		return fmt.Errorf("kpctl-linux Git 저장소를 찾지 못했습니다 (저장소 디렉터리에서 실행하거나 -repo 로 지정하세요)")
	}
	if install {
		p, err := updater.InstallHook(repoDir)
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "git pull 자동 업데이트 훅을 설치했습니다: %s\n", p)
		fmt.Fprintln(stdout, "이제 이 저장소에서 git pull 을 실행하면 설치된 컨트롤러·빌더가 자동으로 업데이트됩니다.")
		fmt.Fprintln(stdout, "(건너뛰기: KPCTL_SKIP_AUTO_UPDATE=1 git pull)")
		return nil
	}
	p, removed, err := updater.UninstallHook(repoDir)
	if err != nil {
		return err
	}
	if !removed {
		fmt.Fprintf(stdout, "제거할 자동 업데이트 훅이 없습니다 (%s)\n", p)
		return nil
	}
	fmt.Fprintf(stdout, "git pull 자동 업데이트 훅을 제거했습니다: %s\n", p)
	return nil
}
