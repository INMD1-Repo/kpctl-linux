// 이 파일: 컨트롤러·빌더 자동 업데이트 엔진 — 역할 자동 감지, 상태 저장, 채널(릴리즈/-dev/now) 실행 흐름.
package updater

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"kpctl/internal/version"
)

// Channel 은 업데이트 대상 채널입니다.
type Channel string

const (
	ChannelRelease Channel = "release" // 기본: 릴리즈 채널 (main)
	ChannelDev     Channel = "dev"     // -dev: 개발 채널 (Dev)
	ChannelNow     Channel = "now"     // now / -now: 현재 체크아웃된 브랜치의 최신 커밋
	ChannelCustom  Channel = "custom"  // -branch: 지정한 브랜치
)

// Role 은 이 서버에 설치된 kpctl 구성 요소 역할입니다.
type Role string

const (
	RoleController    Role = "controller"
	RoleBuilder       Role = "builder"
	RoleNativeBuilder Role = "native-builder"
)

const (
	DefaultRemote    = "origin"
	DefaultRemoteURL = "https://github.com/INMD1-Repo/kpctl-linux.git"
	DefaultRepoPath  = "/opt/kpctl/src"
	StateRelPath     = "etc/kpctl/update.json"
)

// State 는 마지막으로 설치한 버전·저장소·역할 기록(/etc/kpctl/update.json)입니다.
type State struct {
	RepoDir   string   `json:"repo_dir,omitempty"`
	RemoteURL string   `json:"remote_url,omitempty"`
	Channel   string   `json:"channel,omitempty"`
	Branch    string   `json:"branch,omitempty"`
	Commit    string   `json:"commit,omitempty"`
	Version   string   `json:"version,omitempty"`
	Roles     []string `json:"roles,omitempty"`
	UpdatedAt string   `json:"updated_at,omitempty"`
}

// Options 는 업데이트 실행 옵션입니다.
type Options struct {
	Channel       Channel
	Branch        string
	RepoDir       string
	Remote        string
	RemoteURL     string
	Roles         []Role
	Check         bool
	Force         bool
	NoRestart     bool
	BuildWeb      bool
	FromHook      bool
	NoHook        bool
	SysRoot       string
	WorkDir       string
	Stdout        io.Writer
	Stderr        io.Writer
	SkipRootCheck bool
	BuildFunc     func(ctx context.Context, repoDir, outDir string, plan *Plan, roles []Role, buildWeb bool) error
	SystemctlFunc func(args ...string) (string, error)
}

// Plan 은 원격·로컬 버전 비교와 업데이트 계획입니다.
type Plan struct {
	RepoDir          string
	Cloned           bool
	Channel          Channel
	Remote           string
	LocalBranch      string
	LocalCommit      string
	LocalVersion     string
	InstalledCommit  string
	InstalledVersion string
	InstalledChannel string
	TargetBranch     string
	TargetRef        string
	TargetCommit     string
	TargetVersion    string
	LocalOnly        bool
	LocalAhead       bool
	NeedsPull        bool
	NeedsInstall     bool
	CommitCount      int
	Commits          []string
	Roles            []Role
	HookInstalled    bool
}

// NeedsUpdate 는 Git pull 또는 바이너리 재설치가 필요한지 돌려줍니다.
func (p *Plan) NeedsUpdate() bool {
	return p.NeedsPull || p.NeedsInstall
}

// RoleLabel 은 역할의 한글 표시 이름입니다.
func RoleLabel(r Role) string {
	switch r {
	case RoleController:
		return "컨트롤러 (kpctl-controller)"
	case RoleBuilder:
		return "Ubuntu 빌더 (kpctl-builder)"
	case RoleNativeBuilder:
		return "Debian·Rocky 네이티브 빌더 (kpctl-native-builder)"
	default:
		return string(r)
	}
}

// ChannelLabel 은 채널의 한글 표시 이름입니다.
func ChannelLabel(c Channel) string {
	switch c {
	case ChannelRelease:
		return "릴리즈"
	case ChannelDev:
		return "개발 (-dev)"
	case ChannelNow:
		return "현재 브랜치 (now)"
	case ChannelCustom:
		return "지정 브랜치"
	default:
		return string(c)
	}
}

func sysPath(sysRoot string, elems ...string) string {
	if sysRoot == "" {
		sysRoot = "/"
	}
	parts := append([]string{sysRoot}, elems...)
	return filepath.Join(parts...)
}

func pathExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// DetectRoles 는 sysRoot 아래에 설치된 kpctl 역할을 자동 감지합니다.
func DetectRoles(sysRoot string) []Role {
	var roles []Role
	if pathExists(sysPath(sysRoot, "etc/systemd/system/kpctl-controller.service")) ||
		pathExists(sysPath(sysRoot, "etc/kpctl/controller.json")) ||
		pathExists(sysPath(sysRoot, "usr/local/bin/kpctl-controller")) {
		roles = append(roles, RoleController)
	}
	if pathExists(sysPath(sysRoot, "etc/systemd/system/kpctl-builder.service")) ||
		pathExists(sysPath(sysRoot, "etc/kpctl/builder.json")) {
		roles = append(roles, RoleBuilder)
	}
	if pathExists(sysPath(sysRoot, "etc/systemd/system/kpctl-native-builder.service")) ||
		pathExists(sysPath(sysRoot, "etc/systemd/system/kpctl-native-builder.timer")) ||
		pathExists(sysPath(sysRoot, "etc/kpctl/native-builder/worker.json")) ||
		pathExists(sysPath(sysRoot, "opt/kpctl/native-builder/kpctl-native-builder.py")) {
		roles = append(roles, RoleNativeBuilder)
	}
	return roles
}

// ParseRoles 는 -role 플래그("auto" 또는 쉼표 구분 역할 목록)를 해석합니다.
func ParseRoles(spec string) ([]Role, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" || spec == "auto" {
		return nil, nil
	}
	seen := map[Role]bool{}
	var out []Role
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		var r Role
		switch part {
		case "controller":
			r = RoleController
		case "builder", "ubuntu-builder":
			r = RoleBuilder
		case "native-builder", "native":
			r = RoleNativeBuilder
		default:
			return nil, fmt.Errorf("알 수 없는 역할 %q (auto, controller, builder, native-builder 중 선택)", part)
		}
		if !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	return out, nil
}

// LoadState 는 /etc/kpctl/update.json 을 읽습니다. 파일이 없으면 빈 상태를 돌려줍니다.
func LoadState(sysRoot string) (*State, error) {
	p := sysPath(sysRoot, StateRelPath)
	data, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return &State{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("업데이트 상태 파일(%s) 읽기 실패: %w", p, err)
	}
	var st State
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, fmt.Errorf("업데이트 상태 파일(%s) 해석 실패: %w", p, err)
	}
	return &st, nil
}

// SaveState 는 /etc/kpctl/update.json 을 원자적으로 기록합니다.
func SaveState(sysRoot string, st *State) error {
	p := sysPath(sysRoot, StateRelPath)
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return atomicWriteFile(p, data, 0o644)
}

func sameRoleSet(installed []string, target []Role) bool {
	if len(installed) != len(target) {
		return false
	}
	a := append([]string(nil), installed...)
	b := make([]string, len(target))
	for i, r := range target {
		b[i] = string(r)
	}
	sort.Strings(a)
	sort.Strings(b)
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func hasRole(roles []Role, target Role) bool {
	for _, r := range roles {
		if r == target {
			return true
		}
	}
	return false
}

func formatRoles(roles []Role) string {
	names := make([]string, len(roles))
	for i, r := range roles {
		names[i] = RoleLabel(r)
	}
	return strings.Join(names, ", ")
}

// Run 은 버전 확인, Git pull, 빌드, 설치 및 서비스 재시작 전체 흐름을 실행합니다.
func Run(ctx context.Context, opts Options) (*Plan, error) {
	if opts.SysRoot == "" {
		opts.SysRoot = "/"
	}
	if opts.Remote == "" {
		opts.Remote = DefaultRemote
	}
	if opts.RemoteURL == "" {
		opts.RemoteURL = DefaultRemoteURL
	}
	if opts.Channel == "" {
		opts.Channel = ChannelRelease
	}
	if opts.Branch != "" && opts.Channel == ChannelRelease {
		opts.Channel = ChannelCustom
	}
	if opts.Stdout == nil {
		opts.Stdout = os.Stdout
	}
	if opts.Stderr == nil {
		opts.Stderr = os.Stderr
	}
	if opts.WorkDir == "" {
		opts.WorkDir, _ = os.Getwd()
	}

	roles := opts.Roles
	if len(roles) == 0 {
		roles = DetectRoles(opts.SysRoot)
	}
	if len(roles) == 0 {
		if opts.FromHook {
			fmt.Fprintln(opts.Stdout, "[kpctl-update] 설치된 컨트롤러·빌더가 없어 자동 업데이트를 건너뜁니다.")
			return &Plan{}, nil
		}
		if !opts.Check {
			return nil, fmt.Errorf("이 서버에 설치된 컨트롤러·빌더를 찾지 못했습니다 (직접 지정하려면 -role controller|builder|native-builder)")
		}
	}

	if !opts.Check && !opts.SkipRootCheck && os.Geteuid() != 0 {
		return nil, fmt.Errorf("시스템 파일 갱신과 서비스 재시작에는 root 권한이 필요합니다 (sudo kpctl update)")
	}

	state, err := LoadState(opts.SysRoot)
	if err != nil {
		fmt.Fprintf(opts.Stderr, "경고: %v (새 상태로 진행)\n", err)
		state = &State{}
	}

	repoDir, cloned, err := resolveOrCloneRepo(ctx, opts, state)
	if err != nil {
		return nil, err
	}

	plan, err := planUpdate(ctx, repoDir, opts, state, roles)
	if err != nil {
		return nil, err
	}
	plan.Cloned = cloned

	printPlanSummary(opts.Stdout, plan, opts)

	if opts.Check {
		return plan, nil
	}

	if !plan.NeedsUpdate() {
		if !opts.NoHook && !opts.FromHook && !plan.HookInstalled {
			if hookPath, herr := InstallHook(plan.RepoDir); herr == nil {
				plan.HookInstalled = true
				fmt.Fprintf(opts.Stdout, "git pull 자동 업데이트 훅 설치: %s\n", hookPath)
			}
		}
		fmt.Fprintf(opts.Stdout, "이미 최신 상태입니다 (%s). 강제로 다시 설치하려면 -force 를 붙이세요.\n",
			version.Label(plan.TargetVersion, plan.TargetCommit, plan.TargetBranch))
		return plan, nil
	}

	if plan.NeedsPull {
		fmt.Fprintf(opts.Stdout, "■ 1. Git 업데이트 (%s → %s)\n",
			version.Label(plan.LocalVersion, plan.LocalCommit, plan.LocalBranch),
			version.Label(plan.TargetVersion, plan.TargetCommit, plan.TargetBranch))
		if err := applyGitPull(ctx, plan, opts); err != nil {
			return plan, err
		}
	} else if opts.FromHook {
		fmt.Fprintf(opts.Stdout, "■ 1. git pull 감지 (%s)\n",
			version.Label(plan.TargetVersion, plan.TargetCommit, plan.TargetBranch))
	} else if plan.LocalOnly || plan.LocalAhead {
		fmt.Fprintf(opts.Stdout, "■ 1. 현재 브랜치 최신 커밋 사용 (%s)\n",
			version.Label(plan.TargetVersion, plan.TargetCommit, plan.TargetBranch))
	}

	// 빌드 임시 디렉터리
	buildOut, err := os.MkdirTemp("", "kpctl-update-build-*")
	if err != nil {
		return plan, fmt.Errorf("빌드 임시 디렉터리 생성 실패: %w", err)
	}
	defer os.RemoveAll(buildOut)

	fmt.Fprintf(opts.Stdout, "■ 2. 바이너리 빌드 (대상: %s)\n", formatRoles(roles))
	buildFn := opts.BuildFunc
	if buildFn == nil {
		buildFn = func(ctx context.Context, repo, out string, p *Plan, rs []Role, web bool) error {
			return buildArtifacts(ctx, repo, out, p, rs, web, opts.Stdout, opts.Stderr)
		}
	}
	if err := buildFn(ctx, plan.RepoDir, buildOut, plan, roles, opts.BuildWeb); err != nil {
		return plan, err
	}

	fmt.Fprintf(opts.Stdout, "■ 3. 파일 설치 (%s)\n", formatRoles(roles))
	installedItems, err := installRoles(opts.SysRoot, plan.RepoDir, buildOut, roles, opts)
	if err != nil {
		return plan, err
	}
	for _, item := range installedItems {
		fmt.Fprintf(opts.Stdout, "  갱신: %s\n", item)
	}

	if !opts.NoRestart {
		fmt.Fprintln(opts.Stdout, "■ 4. 서비스 반영 및 재시작")
		if err := restartServices(opts.SysRoot, roles, opts); err != nil {
			return plan, err
		}
	} else {
		fmt.Fprintln(opts.Stdout, "■ 4. 서비스 재시작 생략 (-no-restart)")
	}

	// 상태 저장
	roleNames := make([]string, len(roles))
	for i, r := range roles {
		roleNames[i] = string(r)
	}
	remoteURL, _ := gitOutput(ctx, plan.RepoDir, "remote", "get-url", plan.Remote)
	newState := &State{
		RepoDir:   plan.RepoDir,
		RemoteURL: strings.TrimSpace(remoteURL),
		Channel:   string(plan.Channel),
		Branch:    plan.TargetBranch,
		Commit:    plan.TargetCommit,
		Version:   plan.TargetVersion,
		Roles:     roleNames,
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	if err := SaveState(opts.SysRoot, newState); err != nil {
		fmt.Fprintf(opts.Stderr, "경고: 업데이트 상태 저장 실패: %v\n", err)
	}

	if !opts.NoHook && !opts.FromHook && !plan.HookInstalled {
		if hookPath, herr := InstallHook(plan.RepoDir); herr == nil {
			plan.HookInstalled = true
			fmt.Fprintf(opts.Stdout, "■ 5. git pull 자동 업데이트 훅 설치: %s\n", hookPath)
		} else {
			fmt.Fprintf(opts.Stderr, "경고: post-merge 훅 설치 건너뜀: %v\n", herr)
		}
	}

	fmt.Fprintf(opts.Stdout, "완료: %s 업데이트를 마쳤습니다 (%s).\n",
		formatRoles(roles), version.Label(plan.TargetVersion, plan.TargetCommit, plan.TargetBranch))
	return plan, nil
}

func printPlanSummary(w io.Writer, p *Plan, opts Options) {
	fmt.Fprintf(w, "저장소:     %s\n", p.RepoDir)
	if len(p.Roles) > 0 {
		fmt.Fprintf(w, "감지 역할:  %s\n", formatRoles(p.Roles))
	} else {
		fmt.Fprintln(w, "감지 역할:  없음 (설치된 컨트롤러·빌더 없음)")
	}
	curInstalled := p.InstalledVersion
	if curInstalled == "" {
		curInstalled = "미기록"
	}
	if p.InstalledCommit != "" {
		curInstalled = version.Label(p.InstalledVersion, p.InstalledCommit, "")
	}
	fmt.Fprintf(w, "설치 버전:  %s\n", curInstalled)
	fmt.Fprintf(w, "로컬 Git:   %s\n", version.Label(p.LocalVersion, p.LocalCommit, p.LocalBranch))
	targetDesc := version.Label(p.TargetVersion, p.TargetCommit, p.TargetBranch)
	if p.LocalOnly {
		targetDesc += " (원격 브랜치 없음, 로컬 최신 커밋)"
	} else if p.LocalAhead {
		targetDesc += " (로컬이 원격보다 앞섬)"
	}
	fmt.Fprintf(w, "업데이트:   %s → %s\n", ChannelLabel(p.Channel), targetDesc)
	if p.CommitCount > 0 {
		fmt.Fprintf(w, "새 커밋:    %d개\n", p.CommitCount)
		for _, line := range p.Commits {
			fmt.Fprintf(w, "  - %s\n", line)
		}
	}
	if opts.Check {
		if p.NeedsUpdate() {
			fmt.Fprintln(w, "상태:       업데이트 가능")
		} else {
			fmt.Fprintln(w, "상태:       최신 상태")
		}
	}
}
