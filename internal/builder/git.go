// 이 파일: 소스 Git 실행과 태그 조회.
package builder

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// git 은 dir 저장소에서 git 명령을 실행하고 출력(stdout)을 돌려줍니다.
func git(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	// git 오류 문구("patch does not apply" 등)를 읽어 판단하는 곳이 있어 로캘을 고정합니다.
	cmd.Env = append(os.Environ(), "LC_ALL=C", "LANGUAGE=C")
	out, err := cmd.Output()
	if err != nil {
		msg := ""
		if ee, ok := err.(*exec.ExitError); ok {
			msg = strings.TrimSpace(string(ee.Stderr))
		}
		return "", fmt.Errorf("git %s 실패: %v %s", strings.Join(args, " "), err, msg)
	}
	return string(out), nil
}

// lines 는 출력을 줄 단위로 나누고 빈 줄을 버립니다.
func lines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

// remoteLatestTag 는 원격(origin)에서 glob 에 맞는 태그 중 버전이 가장 높은 것을 돌려줍니다.
// 태그 이름만 받아 오므로 fetch 보다 훨씬 가볍습니다. Launchpad 가 느릴 수 있어 2분 제한을 둡니다.
func remoteLatestTag(dir, glob string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", "-C", dir, "ls-remote", "--tags", "--refs", "--sort=-v:refname", "origin", "refs/tags/"+glob)
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return "", fmt.Errorf("git ls-remote 실패: %v %s", err, strings.TrimSpace(string(ee.Stderr)))
		}
		return "", fmt.Errorf("git ls-remote 실패: %w", err)
	}
	for _, l := range lines(string(out)) {
		if f := strings.Fields(l); len(f) == 2 {
			return strings.TrimPrefix(f[1], "refs/tags/"), nil
		}
	}
	return "", nil
}

// latestTag 는 glob 에 맞는 태그 중 버전이 가장 높은 것을 돌려줍니다.
// 예: "Ubuntu-6.8.0-*" → "Ubuntu-6.8.0-86.86"
func latestTag(dir, glob string) (string, error) {
	out, err := git(dir, "tag", "-l", glob, "--sort=-v:refname")
	if err != nil {
		return "", err
	}
	tags := lines(out)
	if len(tags) == 0 {
		return "", nil
	}
	return tags[0], nil
}
