// 이 파일: Git 저장소 탐색·복제, 릴리즈/-dev/now 브랜치 해석, 안전한 fast-forward pull, post-merge 훅 관리.
package updater

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"kpctl/internal/version"
)

const hookMarker = "# kpctl-auto-update-hook"

const postMergeHookScript = `#!/bin/sh
# kpctl-auto-update-hook
# git pull(merge) 후 설치된 kpctl 컨트롤러·빌더를 자동 업데이트합니다.
# 건너뛰려면: KPCTL_SKIP_AUTO_UPDATE=1 git pull
set -eu

[ "${KPCTL_UPDATE_RUNNING:-0}" = "1" ] && exit 0
[ "${KPCTL_SKIP_AUTO_UPDATE:-0}" = "1" ] && exit 0

REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
KPCTL_BIN="${KPCTL_BIN:-}"
if [ -n "$KPCTL_BIN" ] && [ -x "$KPCTL_BIN" ]; then
  :
elif [ -x /usr/local/bin/kpctl ]; then
  KPCTL_BIN=/usr/local/bin/kpctl
elif [ -x "$REPO_ROOT/bin/kpctl" ]; then
  KPCTL_BIN="$REPO_ROOT/bin/kpctl"
elif command -v kpctl >/dev/null 2>&1; then
  KPCTL_BIN=$(command -v kpctl)
else
  echo "[kpctl-update] kpctl 실행 파일을 찾지 못해 자동 업데이트를 건너뜁니다." >&2
  exit 0
fi

if [ "$(id -u)" = "0" ] || [ "${KPCTL_HOOK_NO_SUDO:-0}" = "1" ]; then
  exec "$KPCTL_BIN" update -from-hook -repo "$REPO_ROOT"
elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
  exec sudo -n "$KPCTL_BIN" update -from-hook -repo "$REPO_ROOT"
elif [ -t 0 ] && [ -t 1 ] && command -v sudo >/dev/null 2>&1; then
  exec sudo "$KPCTL_BIN" update -from-hook -repo "$REPO_ROOT"
else
  echo "[kpctl-update] git pull 완료. root 권한이 없어 자동 적용을 건너뜁니다." >&2
  echo "[kpctl-update] 수동 적용: sudo $KPCTL_BIN update -from-hook -repo \"$REPO_ROOT\"" >&2
  exit 0
fi
`

// IsKpctlRepo 는 주어진 경로가 kpctl-linux Git 저장소인지 확인합니다.
func IsKpctlRepo(dir string) bool {
	if dir == "" {
		return false
	}
	if !pathExists(filepath.Join(dir, ".git")) {
		return false
	}
	modBytes, err := os.ReadFile(filepath.Join(dir, "go.mod"))
	if err != nil {
		return false
	}
	firstLine := strings.TrimSpace(strings.SplitN(string(modBytes), "\n", 2)[0])
	return firstLine == "module kpctl" && pathExists(filepath.Join(dir, "cmd", "kpctl", "main.go"))
}

// FindRepo 는 옵션 → 환경변수 → 이전 저장 상태 → 현재 작업 디렉터리 → 기본 경로 순으로 kpctl 저장소를 찾습니다.
func FindRepo(sysRoot, explicit, cwd string, state *State) string {
	candidates := []string{
		explicit,
		os.Getenv("KPCTL_REPO_DIR"),
	}
	if state != nil && state.RepoDir != "" {
		candidates = append(candidates, state.RepoDir)
	}
	for _, c := range candidates {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if abs, err := filepath.Abs(c); err == nil {
			c = abs
		}
		if IsKpctlRepo(c) {
			return c
		}
	}
	if cwd != "" {
		if top := walkGitTopLevel(cwd); top != "" && IsKpctlRepo(top) {
			return top
		}
	}
	defRepo := sysPath(sysRoot, strings.TrimPrefix(DefaultRepoPath, "/"))
	if IsKpctlRepo(defRepo) {
		return defRepo
	}
	return ""
}

func walkGitTopLevel(start string) string {
	cur, err := filepath.Abs(start)
	if err != nil {
		return ""
	}
	for {
		if pathExists(filepath.Join(cur, ".git")) {
			return cur
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return ""
		}
		cur = parent
	}
}

func resolveOrCloneRepo(ctx context.Context, opts Options, state *State) (string, bool, error) {
	if opts.RepoDir != "" {
		abs, err := filepath.Abs(opts.RepoDir)
		if err != nil {
			return "", false, err
		}
		if !IsKpctlRepo(abs) {
			return "", false, fmt.Errorf("지정한 경로가 kpctl-linux Git 저장소가 아닙니다: %s", abs)
		}
		return abs, false, nil
	}
	if found := FindRepo(opts.SysRoot, "", opts.WorkDir, state); found != "" {
		return found, false, nil
	}
	defRepo := sysPath(opts.SysRoot, strings.TrimPrefix(DefaultRepoPath, "/"))
	if opts.Check {
		return "", false, fmt.Errorf("kpctl-linux Git 저장소를 찾지 못했습니다 (저장소 디렉터리에서 실행하거나 -repo 로 지정, 또는 sudo kpctl update 로 %s 에 자동 복제)", defRepo)
	}
	if opts.FromHook {
		return "", false, fmt.Errorf("post-merge 훅에서 kpctl-linux 저장소를 찾지 못했습니다")
	}
	if err := os.MkdirAll(filepath.Dir(defRepo), 0o755); err != nil {
		return "", false, fmt.Errorf("저장소 상위 디렉터리 생성 실패: %w", err)
	}
	fmt.Fprintf(opts.Stdout, "■ 0. 저장소 복제 (%s → %s)\n", opts.RemoteURL, defRepo)
	cmd := exec.CommandContext(ctx, "git", "clone", opts.RemoteURL, defRepo)
	cmd.Env = append(os.Environ(), "KPCTL_UPDATE_RUNNING=1")
	var stderr bytes.Buffer
	cmd.Stdout = opts.Stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", false, fmt.Errorf("git clone 실패: %w\n%s", err, strings.TrimSpace(stderr.String()))
	}
	return defRepo, true, nil
}

// repoOwnerUser 는 root 로 실행 중이고 저장소 소유자가 일반 사용자일 때 그 사용자 이름을 돌려줍니다.
// 소유자 계정으로 git 을 실행하면 safe.directory 경고와 .git 파일 소유권 오염, SSH 키 불일치를 막을 수 있습니다.
func repoOwnerUser(repoDir string) (string, string) {
	if os.Geteuid() != 0 {
		return "", ""
	}
	fi, err := os.Stat(repoDir)
	if err != nil {
		return "", ""
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st.Uid == 0 {
		return "", ""
	}
	u, err := user.LookupId(strconv.FormatUint(uint64(st.Uid), 10))
	if err != nil || u.Username == "" {
		return "", ""
	}
	return u.Username, u.HomeDir
}

func gitCommand(ctx context.Context, repoDir string, args ...string) *exec.Cmd {
	fullArgs := append([]string{"-c", "safe.directory=" + repoDir, "-C", repoDir}, args...)
	env := append(os.Environ(), "KPCTL_UPDATE_RUNNING=1", "GIT_TERMINAL_PROMPT=0")

	if owner, home := repoOwnerUser(repoDir); owner != "" {
		if runuserPath, err := exec.LookPath("runuser"); err == nil {
			ruArgs := append([]string{"-u", owner, "--", "git"}, fullArgs...)
			cmd := exec.CommandContext(ctx, runuserPath, ruArgs...)
			if home != "" {
				env = setEnvVar(env, "HOME", home)
			}
			cmd.Env = env
			return cmd
		}
	}
	cmd := exec.CommandContext(ctx, "git", fullArgs...)
	cmd.Env = env
	return cmd
}

func setEnvVar(env []string, key, val string) []string {
	prefix := key + "="
	out := make([]string, 0, len(env)+1)
	for _, e := range env {
		if strings.HasPrefix(e, prefix) {
			continue
		}
		out = append(out, e)
	}
	return append(out, prefix+val)
}

func gitOutput(ctx context.Context, repoDir string, args ...string) (string, error) {
	cmd := gitCommand(ctx, repoDir, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = strings.TrimSpace(stdout.String())
		}
		return "", fmt.Errorf("git %s 실패: %w (%s)", strings.Join(args, " "), err, msg)
	}
	return strings.TrimSpace(stdout.String()), nil
}

func gitRefExists(ctx context.Context, repoDir, ref string) bool {
	_, err := gitOutput(ctx, repoDir, "rev-parse", "--verify", "--quiet", ref+"^{commit}")
	return err == nil
}

func gitIsAncestor(ctx context.Context, repoDir, ancestor, descendant string) bool {
	cmd := gitCommand(ctx, repoDir, "merge-base", "--is-ancestor", ancestor, descendant)
	return cmd.Run() == nil
}

func describeCommit(ctx context.Context, repoDir, commit string) string {
	if tag, err := gitOutput(ctx, repoDir, "describe", "--tags", "--exact-match", commit); err == nil && tag != "" {
		return tag
	}
	if desc, err := gitOutput(ctx, repoDir, "describe", "--tags", "--always", commit); err == nil && desc != "" {
		return desc
	}
	return version.Short(commit)
}

func resolveRemoteBranch(ctx context.Context, repoDir, remote string, candidates ...string) (string, error) {
	for _, b := range candidates {
		if b == "" {
			continue
		}
		if gitRefExists(ctx, repoDir, "refs/remotes/"+remote+"/"+b) {
			return b, nil
		}
	}
	return "", fmt.Errorf("원격(%s)에서 브랜치(%s)를 찾지 못했습니다", remote, strings.Join(candidates, ", "))
}

func planUpdate(ctx context.Context, repoDir string, opts Options, state *State, roles []Role) (*Plan, error) {
	localBranch, err := gitOutput(ctx, repoDir, "rev-parse", "--abbrev-ref", "HEAD")
	if err != nil {
		return nil, err
	}
	localCommit, err := gitOutput(ctx, repoDir, "rev-parse", "HEAD")
	if err != nil {
		return nil, err
	}
	localVersion := describeCommit(ctx, repoDir, localCommit)

	installedCommit := strings.TrimSpace(state.Commit)
	installedVersion := strings.TrimSpace(state.Version)
	installedChannel := strings.TrimSpace(state.Channel)
	if installedCommit == "" {
		cur := version.Current()
		if len(cur.Commit) >= 7 {
			installedCommit = cur.Commit
			installedVersion = cur.Version
		}
	}

	hookInstalled, _, _ := HookInstalled(repoDir)

	plan := &Plan{
		RepoDir:          repoDir,
		Channel:          opts.Channel,
		Remote:           opts.Remote,
		LocalBranch:      localBranch,
		LocalCommit:      localCommit,
		LocalVersion:     localVersion,
		InstalledCommit:  installedCommit,
		InstalledVersion: installedVersion,
		InstalledChannel: installedChannel,
		Roles:            roles,
		HookInstalled:    hookInstalled,
	}

	// post-merge 훅에서 호출된 경우: 이미 git pull 이 끝난 현재 HEAD 를 그대로 설치합니다.
	if opts.FromHook {
		plan.Channel = ChannelNow
		plan.TargetBranch = localBranch
		plan.TargetRef = "HEAD"
		plan.TargetCommit = localCommit
		plan.TargetVersion = localVersion
		plan.NeedsPull = false
		plan.NeedsInstall = opts.Force || !commitMatches(installedCommit, localCommit) || !sameRoleSet(state.Roles, roles)
		return plan, nil
	}

	// 원격 fetch (now 모드에서 원격이 아예 없는 로컬 전용 저장소는 허용)
	hasRemote := false
	if _, err := gitOutput(ctx, repoDir, "remote", "get-url", opts.Remote); err == nil {
		hasRemote = true
	}
	if hasRemote {
		if _, err := gitOutput(ctx, repoDir, "fetch", "--tags", "--prune", opts.Remote); err != nil {
			return nil, err
		}
	} else if opts.Channel != ChannelNow {
		return nil, fmt.Errorf("Git 원격 %q 가 설정되어 있지 않습니다", opts.Remote)
	}

	switch opts.Channel {
	case ChannelRelease:
		// 릴리즈 채널: origin/main (fallback: master, origin/HEAD)
		headDefault := ""
		if sym, err := gitOutput(ctx, repoDir, "symbolic-ref", "--short", "refs/remotes/"+opts.Remote+"/HEAD"); err == nil {
			headDefault = strings.TrimPrefix(sym, opts.Remote+"/")
		}
		branch, err := resolveRemoteBranch(ctx, repoDir, opts.Remote, "main", "master", headDefault)
		if err != nil {
			return nil, fmt.Errorf("릴리즈 브랜치를 찾지 못했습니다: %w", err)
		}
		plan.TargetBranch = branch
		plan.TargetRef = opts.Remote + "/" + branch

	case ChannelDev:
		// 개발 채널: origin/Dev (fallback: origin/dev)
		branch, err := resolveRemoteBranch(ctx, repoDir, opts.Remote, "Dev", "dev")
		if err != nil {
			return nil, fmt.Errorf("개발 브랜치(Dev)를 찾지 못했습니다: %w", err)
		}
		plan.TargetBranch = branch
		plan.TargetRef = opts.Remote + "/" + branch

	case ChannelCustom:
		branch, err := resolveRemoteBranch(ctx, repoDir, opts.Remote, opts.Branch)
		if err != nil {
			return nil, err
		}
		plan.TargetBranch = branch
		plan.TargetRef = opts.Remote + "/" + branch

	case ChannelNow:
		// 현재 체크아웃된 자기 브랜치의 최신 커밋
		if localBranch == "" || localBranch == "HEAD" {
			return nil, fmt.Errorf("현재 분리된 HEAD 상태입니다. 브랜치를 체크아웃하거나 -branch/-dev 를 지정하세요")
		}
		plan.TargetBranch = localBranch
		// 1) 설정된 upstream (@{u})  2) origin/<localBranch>  3) 없으면 로컬 전용 브랜치
		var remoteRef string
		if up, err := gitOutput(ctx, repoDir, "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"); err == nil && up != "" {
			if gitRefExists(ctx, repoDir, up) {
				remoteRef = up
			}
		}
		if remoteRef == "" && hasRemote && gitRefExists(ctx, repoDir, "refs/remotes/"+opts.Remote+"/"+localBranch) {
			remoteRef = opts.Remote + "/" + localBranch
		}
		if remoteRef == "" {
			plan.LocalOnly = true
			plan.TargetRef = "HEAD"
			plan.TargetCommit = localCommit
			plan.TargetVersion = localVersion
		} else {
			remoteCommit, err := gitOutput(ctx, repoDir, "rev-parse", remoteRef+"^{commit}")
			if err != nil {
				return nil, err
			}
			if remoteCommit == localCommit {
				plan.TargetRef = remoteRef
				plan.TargetCommit = localCommit
			} else if gitIsAncestor(ctx, repoDir, localCommit, remoteCommit) {
				// 원격이 더 최신 → fast-forward pull 대상
				plan.TargetRef = remoteRef
				plan.TargetCommit = remoteCommit
			} else if gitIsAncestor(ctx, repoDir, remoteCommit, localCommit) {
				// 로컬 브랜치가 원격보다 앞서 있음(방금 로컬 커밋함) → 로컬 최신 커밋으로 업데이트
				plan.LocalAhead = true
				plan.TargetRef = "HEAD"
				plan.TargetCommit = localCommit
			} else {
				return nil, fmt.Errorf("현재 브랜치(%s)와 원격(%s)이 갈라졌습니다. git pull --rebase 등으로 정리한 뒤 다시 실행하세요", localBranch, remoteRef)
			}
		}
	default:
		return nil, fmt.Errorf("지원하지 않는 채널: %s", opts.Channel)
	}

	if plan.TargetCommit == "" {
		targetCommit, err := gitOutput(ctx, repoDir, "rev-parse", plan.TargetRef+"^{commit}")
		if err != nil {
			return nil, err
		}
		plan.TargetCommit = targetCommit
	}
	plan.TargetVersion = describeCommit(ctx, repoDir, plan.TargetCommit)

	if !plan.LocalOnly && !plan.LocalAhead {
		plan.NeedsPull = localBranch != plan.TargetBranch || localCommit != plan.TargetCommit
	}
	plan.NeedsInstall = opts.Force || !commitMatches(installedCommit, plan.TargetCommit) || !sameRoleSet(state.Roles, roles)

	// 변경 커밋 목록 (로컬 → 대상)
	baseCommit := localCommit
	if installedCommit != "" && gitRefExists(ctx, repoDir, installedCommit) && baseCommit == plan.TargetCommit {
		baseCommit = installedCommit
	}
	if baseCommit != "" && baseCommit != plan.TargetCommit && gitIsAncestor(ctx, repoDir, baseCommit, plan.TargetCommit) {
		if cntStr, err := gitOutput(ctx, repoDir, "rev-list", "--count", baseCommit+".."+plan.TargetCommit); err == nil {
			plan.CommitCount, _ = strconv.Atoi(cntStr)
		}
		if logOut, err := gitOutput(ctx, repoDir, "log", "--oneline", "-n", "5", baseCommit+".."+plan.TargetCommit); err == nil && logOut != "" {
			plan.Commits = strings.Split(logOut, "\n")
		}
	}

	return plan, nil
}

func commitMatches(installed, target string) bool {
	if installed == "" || target == "" {
		return false
	}
	if installed == target {
		return true
	}
	// 짧은 커밋 해시(7자 이상)로 기록된 경우도 비교 허용
	if len(installed) >= 7 && strings.HasPrefix(target, installed) {
		return true
	}
	return false
}

func applyGitPull(ctx context.Context, plan *Plan, opts Options) error {
	status, err := gitOutput(ctx, plan.RepoDir, "status", "--porcelain")
	if err != nil {
		return err
	}
	if status != "" {
		lines := strings.Split(status, "\n")
		if len(lines) > 5 {
			lines = append(lines[:5], fmt.Sprintf("... 외 %d건", len(lines)-5))
		}
		return fmt.Errorf("저장소에 커밋되지 않은 변경이 있어 pull 할 수 없습니다. 정리한 뒤 다시 실행하세요:\n  %s", strings.Join(lines, "\n  "))
	}

	if plan.LocalBranch != plan.TargetBranch {
		if gitRefExists(ctx, plan.RepoDir, "refs/heads/"+plan.TargetBranch) {
			if _, err := gitOutput(ctx, plan.RepoDir, "checkout", plan.TargetBranch); err != nil {
				return err
			}
		} else {
			if _, err := gitOutput(ctx, plan.RepoDir, "checkout", "-b", plan.TargetBranch, "--track", plan.TargetRef); err != nil {
				return err
			}
		}
	}

	// 이미 체크아웃 과정에서 대상 커밋과 같아졌는지 확인
	headNow, err := gitOutput(ctx, plan.RepoDir, "rev-parse", "HEAD")
	if err != nil {
		return err
	}
	if headNow != plan.TargetCommit {
		if _, err := gitOutput(ctx, plan.RepoDir, "merge", "--ff-only", plan.TargetRef); err != nil {
			return fmt.Errorf("fast-forward pull 실패 (%s 브랜치가 원격 %s 와 갈라졌을 수 있습니다): %w", plan.TargetBranch, plan.TargetRef, err)
		}
	}
	plan.LocalBranch = plan.TargetBranch
	plan.LocalCommit = plan.TargetCommit
	plan.LocalVersion = plan.TargetVersion
	return nil
}

func hookPathFor(repoDir string) (string, error) {
	out, err := gitOutput(context.Background(), repoDir, "rev-parse", "--git-path", "hooks/post-merge")
	if err != nil {
		return "", err
	}
	if filepath.IsAbs(out) {
		return out, nil
	}
	return filepath.Join(repoDir, out), nil
}

// HookInstalled 는 저장소에 kpctl post-merge 훅이 설치되어 있는지 확인합니다.
func HookInstalled(repoDir string) (bool, string, error) {
	p, err := hookPathFor(repoDir)
	if err != nil {
		return false, "", err
	}
	data, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return false, p, nil
	}
	if err != nil {
		return false, p, err
	}
	return strings.Contains(string(data), hookMarker), p, nil
}

// InstallHook 은 git pull 시 자동 업데이트를 실행하는 post-merge 훅을 설치합니다.
func InstallHook(repoDir string) (string, error) {
	p, err := hookPathFor(repoDir)
	if err != nil {
		return "", err
	}
	if existing, err := os.ReadFile(p); err == nil {
		if !strings.Contains(string(existing), hookMarker) {
			return p, fmt.Errorf("이미 다른 post-merge 훅이 존재합니다 (%s). 덮어쓰지 않았습니다", p)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return p, err
	}
	if err := atomicWriteFile(p, []byte(postMergeHookScript), 0o755); err != nil {
		return p, err
	}
	// 저장소가 일반 사용자 소유이면 훅 파일 소유권도 맞춤
	if fi, err := os.Stat(repoDir); err == nil {
		if st, ok := fi.Sys().(*syscall.Stat_t); ok && os.Geteuid() == 0 && st.Uid != 0 {
			_ = os.Chown(p, int(st.Uid), int(st.Gid))
		}
	}
	return p, nil
}

// UninstallHook 은 kpctl 이 설치한 post-merge 훅을 제거합니다.
func UninstallHook(repoDir string) (string, bool, error) {
	p, err := hookPathFor(repoDir)
	if err != nil {
		return "", false, err
	}
	data, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return p, false, nil
	}
	if err != nil {
		return p, false, err
	}
	if !strings.Contains(string(data), hookMarker) {
		return p, false, fmt.Errorf("kpctl 이 설치한 훅이 아닙니다 (%s). 제거하지 않았습니다", p)
	}
	if err := os.Remove(p); err != nil {
		return p, false, err
	}
	return p, true, nil
}
