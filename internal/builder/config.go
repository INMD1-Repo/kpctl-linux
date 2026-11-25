// Package builder 는 빌드 서버입니다.
//
// 하는 일 두 가지:
//  1. 컨트롤러 대기열에서 빌드 작업을 가져와 kpatch-build 로 누적 패치 모듈(.ko)을 만들어 올림
//  2. Ubuntu 커널 git 에서 새 릴리스 태그의 CVE 수정 커밋을 찾아 컨트롤러에 등록 (자동 수집)
//
// 파일 안내:
//
//	config.go   ← 지금 파일. 설정 구조
//	filter.go   어떤 CVE 커밋을 라이브패치 대상으로 볼지 (경로 필터) — 가장 자주 고치게 될 곳
//	worker.go   메인 루프, 빌드 작업 처리
//	discover.go Ubuntu git 에서 CVE 커밋 찾기
//	kernels.go  자동 모드: 호스트들이 쓰는 커널 중 이 시리즈의 LTS GA 커널 고르기
//	kpatch.go   kpatch-build 실행
//	klp.go      빌드 도구 선택, klp-build 실행 (CONFIG_KLP_BUILD 커널)
//	git.go      git 명령 도우미
package builder

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"kpctl/internal/model"
)

// KernelConfig 는 자동 수집할 커널 하나의 설정입니다.
type KernelConfig struct {
	// Kernel: 대상 호스트의 uname -r 그대로. 예: "6.8.0-85-generic"
	Kernel string `json:"kernel"`
	// GitDir: Ubuntu 커널 git 을 clone 한 디렉터리
	//   예: git clone https://git.launchpad.net/~ubuntu-kernel/ubuntu/+source/linux/+git/noble /srv/ubuntu-noble
	GitDir string `json:"git_dir"`
	// BaseTag: 지금 호스트가 쓰는 커널의 태그. 예: "Ubuntu-6.8.0-85.85"
	BaseTag string `json:"base_tag"`
	// TagGlob: 같은 계열의 새 태그를 찾을 패턴. 예: "Ubuntu-6.8.0-*"
	TagGlob string `json:"tag_glob"`
	// Vmlinux: 디버그 심볼 vmlinux 경로. 비우면 <debug_dir>/vmlinux-<kernel>
	Vmlinux string `json:"vmlinux"`
	// Paths: 라이브패치 대상으로 볼 소스 경로. 비우면 설정의 paths, 그것도 없으면 filter.go 의 DefaultPaths
	Paths      []string          `json:"paths"`
	Prerelease *PrereleaseConfig `json:"prerelease,omitempty"` // 명시적으로 켠 커널만 정식 상한 이후를 별도 수집
}

// PrereleaseConfig는 Ubuntu 개발 브랜치의 수정본을 별도 수동 승인 채널로 수집합니다.
type PrereleaseConfig struct {
	Enabled     bool   `json:"enabled"`
	Branch      string `json:"branch"`
	PollMinutes int    `json:"poll_minutes"`
}

// Config 는 빌드 서버 설정 파일 구조입니다. 예시: configs/builder.example.json
type Config struct {
	ControllerURL string `json:"controller_url"`
	Token         string `json:"token"`
	CAFile        string `json:"ca_file"`
	Name          string `json:"name"` // 비우면 hostname

	WorkDir     string `json:"work_dir"`     // 작업 디렉터리
	KpatchBuild string `json:"kpatch_build"` // kpatch-build 실행 파일
	// BuildTool: auto(기본) = CONFIG_KLP_BUILD 커널은 klp-build, 나머지는 kpatch-build. kpatch 또는 klp 로 고정 가능.
	BuildTool string `json:"build_tool"`
	// BootDir: 커널 설정(config-<kernel>)이 있는 디렉터리
	BootDir string `json:"boot_dir"`
	Jobs    int    `json:"jobs"` // make -j 값 (0 = kpatch-build 기본값)

	PollSeconds int `json:"poll_seconds"` // 작업 확인 주기
	// DiscoverMinutes: 자동 수집(전체 fetch + CVE 커밋 확인) 주기. 비우면 60, 0 이면 자동 수집 끔.
	DiscoverMinutes *int `json:"discover_minutes"`
	// UpdateCheckMinutes: 정식 APT 배포 버전과 대응 Git 태그를 확인하는 주기. 비우면 5, 0 이면 끔.
	// 상한이 바뀌면 discover_minutes 를 기다리지 않고 바로 수집·빌드합니다.
	UpdateCheckMinutes *int `json:"update_check_minutes"`
	// SelfUpdate: 컨트롤러에 새 kpctl-builder 가 있으면 10분 안에 받아서 스스로 바꿈. 비우면 true.
	SelfUpdate *bool `json:"self_update"`
	// AutoDebugSymbols: 호스트 커널의 디버그 심볼이 없으면 debug_helper 로 자동 설치. 비우면 true.
	AutoDebugSymbols *bool `json:"auto_debug_symbols"`
	// ControllerKernelInputs: 디버그 심볼·이미지·헤더·모듈 패키지를 컨트롤러 캐시에서 받습니다.
	// 새 컨트롤러와 kpctl-kernel-inputs 도우미가 필요합니다. 기본 false (기존 직접 취득).
	ControllerKernelInputs bool `json:"controller_kernel_inputs"`
	// DebugHelper: 디버그 심볼 설치 도우미 (sudo 로 실행). 비우면 /usr/local/sbin/kpctl-kernel-debug
	DebugHelper string `json:"debug_helper"`

	// SkipTrialBuild: true 면 CVE 커밋마다 하는 단독 시험 빌드를 생략 (빠르지만 불가 판정을 못 함)
	SkipTrialBuild bool `json:"skip_trial_build"`
	// MaxTrialsPerRun: 한 번에 시험 빌드할 최대 커밋 수 (나머지는 다음 주기에)
	MaxTrialsPerRun int `json:"max_trials_per_run"`
	// MaxPrereqs: CVE 커밋 하나에 딸려 들어갈 수 있는 선행 커밋 수 한도 (0 = 12).
	// 넘으면 자동으로 묶지 않고 관리자 검토를 기다립니다 (prereq.go)
	MaxPrereqs int `json:"max_prereqs"`
	// BuildTimeoutMinutes: kpatch-build 한 번의 최대 시간. 격리 빌드는 커널마다 처음 한 번 하는
	// 패치 없는 기준 빌드(ccache 준비)에도 같은 시간을 따로 줍니다.
	BuildTimeoutMinutes int `json:"build_timeout_minutes"`

	// Series: 이 빌드 서버가 맡는 Ubuntu LTS 시리즈 (jammy, noble, resolute).
	// 비우면 이 서버의 /etc/os-release 를 따릅니다. 컨트롤러는 이 시리즈의 커널 작업만 줍니다.
	Series string `json:"series"`
	// GitRoot: Ubuntu 커널 git 을 둘 곳. 자동 모드에서는 <git_root>/ubuntu-<series> 를 씁니다.
	GitRoot string `json:"git_root"`
	// DebugDir: 디버그 심볼 vmlinux 가 있는 디렉터리
	DebugDir string `json:"debug_dir"`
	// Paths: 라이브패치 대상으로 볼 소스 경로. 비우면 filter.go 의 DefaultPaths. 자동 모드에도 적용됩니다.
	Paths []string `json:"paths"`

	// MaxKernels: 자동 모드에서 수집할 커널 범위. 정식 배포 최신 ABI 를 포함한 최근 N개 ABI(Git 태그 기준)만
	// 수집하고, 그보다 오래된 호스트 커널은 "지원 범위 밖"으로 보고합니다. 비우면 -1(제한 없음, 누적).
	MaxKernels int `json:"max_kernels"`
	// KernelCleanupFreeGiB: 이 값 미만이면 미사용 커널 자료·재생성 가능한 캐시를 정리합니다.
	// 비우면 활성 프로파일의 빌드 최소 여유 + 20. 빌드는 최소 여유 미만일 때만 보류합니다.
	// -1 이면 자동 정리·보류 검사를 끕니다(격리 도우미 자체 검사는 유지).
	KernelCleanupFreeGiB int `json:"kernel_cleanup_free_gib"`

	// Kernels: 자동 수집할 커널을 직접 정할 때만 적습니다.
	// 비우면 자동 모드: 컨트롤러에 등록된 호스트들이 쓰는 커널 중 이 시리즈의 GA 커널을 모두 대상으로 합니다.
	Kernels []KernelConfig `json:"kernels"`
	Sandbox *SandboxConfig `json:"sandbox,omitempty"`
	CVEFeed *CVEFeedConfig `json:"cve_feed,omitempty"` // 기본 꺼짐; 커널 CNA의 upstream 수정 커밋 대조
}

// Sandbox enables disposable rootless builds, without a host fallback.
type SandboxConfig struct {
	Profile       string              `json:"profile"`
	ProfilesDir   string              `json:"profiles_dir,omitempty"`
	Helper        string              `json:"helper,omitempty"`
	RetryClean    bool                `json:"retry_clean"`
	WorkerBinary  string              `json:"worker_binary,omitempty"`
	AutoPrepare   *bool               `json:"auto_prepare,omitempty"`
	Prepare       *SandboxPreparation `json:"prepare,omitempty"`
	RetentionDays int                 `json:"retention_days,omitempty"`
}

type SandboxPreparation struct {
	BaseImage              string   `json:"base_image,omitempty"`
	MemoryMiB              int      `json:"memory_mib"`
	PIDs                   int      `json:"pids"`
	MinFreeGiB             int      `json:"min_free_gib"`
	CacheGiB               *int     `json:"cache_gib,omitempty"`
	CacheTotalGiB          int      `json:"cache_total_gib"`
	Snapshot               string   `json:"snapshot,omitempty"`
	SnapshotTimeoutMinutes *int     `json:"snapshot_timeout_minutes,omitempty"`
	ImageTimeoutMinutes    *int     `json:"image_timeout_minutes,omitempty"`
	Sources                string   `json:"sources,omitempty"`
	Packages               []string `json:"packages,omitempty"`
}

func intp(n int) *int { return &n }

// autoKernels 는 대상 커널을 컨트롤러에서 받아오는 자동 모드인지 봅니다.
func (c *Config) autoKernels() bool { return len(c.Kernels) == 0 }

func (c *Config) autoControllerInputs() bool {
	return c.ControllerKernelInputs && c.AutoDebugSymbols != nil && *c.AutoDebugSymbols
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg, err := ParseConfig(data)
	if err != nil {
		return nil, fmt.Errorf("설정 파일 %s: %w", path, err)
	}
	return cfg, os.MkdirAll(cfg.WorkDir, 0o750)
}

// ParseConfig는 실제 로더의 JSON·기본값·검증을 공유하며 디렉터리는 만들지 않습니다.
func ParseConfig(data []byte) (*Config, error) {
	cfg := &Config{}
	// 폐기한 키 하나만 무시합니다. 나머지 오타·알 수 없는 키 검사는 유지합니다.
	var legacy map[string]json.RawMessage
	if json.Unmarshal(data, &legacy) == nil {
		if _, ok := legacy["min_kernels"]; ok {
			delete(legacy, "min_kernels")
			var err error
			data, err = json.Marshal(legacy)
			if err != nil {
				return nil, err
			}
		}
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(cfg); err != nil {
		return nil, fmt.Errorf("설정 JSON 해석 실패: %w", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return nil, fmt.Errorf("설정 JSON 뒤에는 추가 값이나 문자를 쓸 수 없습니다")
	}

	if cfg.Name == "" {
		cfg.Name, _ = os.Hostname()
	}
	if cfg.WorkDir == "" {
		cfg.WorkDir = "/var/lib/kpctl-builder"
	}
	if cfg.KpatchBuild == "" {
		cfg.KpatchBuild = "kpatch-build"
	}
	if cfg.BuildTool == "" {
		cfg.BuildTool = BuildToolAuto
	}
	if cfg.BuildTool != BuildToolAuto && cfg.BuildTool != BuildToolKpatch && cfg.BuildTool != BuildToolKLP {
		return nil, fmt.Errorf("build_tool %q 이 잘못됐습니다 (auto, kpatch, klp)", cfg.BuildTool)
	}
	if cfg.BootDir == "" {
		cfg.BootDir = "/boot"
	}
	if cfg.DiscoverMinutes == nil {
		cfg.DiscoverMinutes = intp(60)
	}
	if cfg.UpdateCheckMinutes == nil {
		cfg.UpdateCheckMinutes = intp(5)
	}
	if cfg.SelfUpdate == nil {
		t := true
		cfg.SelfUpdate = &t
	}
	if cfg.AutoDebugSymbols == nil {
		t := true
		cfg.AutoDebugSymbols = &t
	}
	if cfg.DebugHelper == "" {
		cfg.DebugHelper = "/usr/local/sbin/kpctl-kernel-debug"
	}
	if *cfg.DiscoverMinutes < 0 || *cfg.UpdateCheckMinutes < 0 {
		return nil, fmt.Errorf("discover_minutes, update_check_minutes 는 0 이상이어야 합니다 (0 = 끔)")
	}
	if cfg.PollSeconds == 0 {
		cfg.PollSeconds = 30
	}
	if cfg.MaxTrialsPerRun == 0 {
		cfg.MaxTrialsPerRun = 10
	}
	if cfg.BuildTimeoutMinutes == 0 {
		cfg.BuildTimeoutMinutes = 180
	}
	if cfg.MaxKernels == 0 {
		cfg.MaxKernels = -1
	}
	if cfg.MaxKernels < -1 || cfg.MaxKernels > 100 {
		return nil, fmt.Errorf("max_kernels 는 1~100 또는 -1(제한 없음)이어야 합니다")
	}
	if cfg.KernelCleanupFreeGiB < -1 || cfg.KernelCleanupFreeGiB > 65536 {
		return nil, fmt.Errorf("kernel_cleanup_free_gib 는 1~65536 또는 -1(끔)이어야 합니다")
	}
	if cfg.GitRoot == "" {
		cfg.GitRoot = "/srv"
	}
	if cfg.DebugDir == "" {
		cfg.DebugDir = "/usr/lib/debug/boot"
	}

	if cfg.ControllerURL == "" || cfg.Token == "" {
		return nil, fmt.Errorf("controller_url 과 token 은 꼭 넣어야 합니다")
	}
	if cfg.CVEFeed != nil {
		if cfg.CVEFeed.URL == "" {
			cfg.CVEFeed.URL = defaultCVEFeedURL
		}
		if cfg.CVEFeed.Enabled {
			if err := validateCVEFeedSource(cfg.CVEFeed.URL); err != nil {
				return nil, err
			}
		}
	}
	if cfg.Sandbox != nil {
		if cfg.Sandbox.RetentionDays == 0 {
			cfg.Sandbox.RetentionDays = 14
		}
		if cfg.Sandbox.RetentionDays < 1 || cfg.Sandbox.RetentionDays > 3650 {
			return nil, fmt.Errorf("sandbox.retention_days는 1~3650일이어야 합니다")
		}
		if cfg.Sandbox.AutoPrepare == nil {
			enabled := cfg.Sandbox.ProfilesDir != ""
			cfg.Sandbox.AutoPrepare = &enabled
		}
		if cfg.Sandbox.Prepare == nil {
			cfg.Sandbox.Prepare = &SandboxPreparation{}
		}
		p := cfg.Sandbox.Prepare
		if p.MemoryMiB == 0 {
			p.MemoryMiB = 12288
		}
		if p.PIDs == 0 {
			p.PIDs = 4096
		}
		if p.MinFreeGiB == 0 {
			p.MinFreeGiB = 60
		}
		if p.CacheGiB == nil {
			p.CacheGiB = intp(20)
		}
		if p.CacheTotalGiB == 0 {
			p.CacheTotalGiB = 40
		}
		if p.Snapshot == "" {
			p.Snapshot = "auto"
		}
		if p.Snapshot != "auto" && p.Snapshot != "none" {
			if _, err := time.Parse("20060102T150405Z", p.Snapshot); err != nil {
				return nil, fmt.Errorf("sandbox.prepare.snapshot ID가 잘못됐습니다: %w", err)
			}
		}
		if n := p.SnapshotTimeoutMinutes; n != nil && (*n < 1 || *n > 1440) {
			return nil, fmt.Errorf("sandbox.prepare.snapshot_timeout_minutes는 1~1440분이어야 합니다")
		}
		if n := p.ImageTimeoutMinutes; n != nil && (*n < 10 || *n > 1440) {
			return nil, fmt.Errorf("sandbox.prepare.image_timeout_minutes는 10~1440분이어야 합니다")
		}
		if p.MemoryMiB < 1024 || p.MemoryMiB > 1048576 || p.PIDs < 128 || p.PIDs > 32768 || p.MinFreeGiB < 8 || p.MinFreeGiB > 65536 ||
			*p.CacheGiB < 0 || *p.CacheGiB > 1024 || p.CacheTotalGiB < *p.CacheGiB || p.CacheTotalGiB > 4096 || (p.Sources != "" && !filepath.IsAbs(p.Sources)) {
			return nil, fmt.Errorf("sandbox.prepare 자원 한도·sources 경로가 잘못됐습니다")
		}
		if cfg.BuildTimeoutMinutes < 1 || cfg.BuildTimeoutMinutes > 1440 || cfg.Jobs < 0 {
			return nil, fmt.Errorf("격리 빌드 시간은 1~1440분, jobs는 0 이상이어야 합니다")
		}
		if (cfg.Sandbox.Profile == "") == (cfg.Sandbox.ProfilesDir == "") ||
			(cfg.Sandbox.Profile != "" && !filepath.IsAbs(cfg.Sandbox.Profile)) ||
			(cfg.Sandbox.ProfilesDir != "" && !filepath.IsAbs(cfg.Sandbox.ProfilesDir)) {
			return nil, fmt.Errorf("sandbox.profile 또는 profiles_dir 중 하나의 절대 경로를 지정하세요")
		}
		if cfg.Sandbox.Helper == "" {
			cfg.Sandbox.Helper = "/usr/local/libexec/kpctl-build-environment"
		}
		if !filepath.IsAbs(cfg.Sandbox.Helper) || (cfg.Sandbox.WorkerBinary != "" && !filepath.IsAbs(cfg.Sandbox.WorkerBinary)) {
			return nil, fmt.Errorf("sandbox helper·worker_binary는 절대 경로여야 합니다")
		}
	}
	for i, k := range cfg.Kernels {
		if k.Kernel == "" || k.GitDir == "" || k.BaseTag == "" || k.TagGlob == "" {
			return nil, fmt.Errorf("kernels[%d]: kernel, git_dir, base_tag, tag_glob 는 꼭 넣어야 합니다", i)
		}
		if k.Vmlinux == "" {
			cfg.Kernels[i].Vmlinux = cfg.vmlinuxFor(k.Kernel)
		}
		if len(k.Paths) == 0 {
			cfg.Kernels[i].Paths = cfg.Paths
		}
		if pre := k.Prerelease; pre != nil {
			if pre.Branch == "" {
				pre.Branch = "master-next"
			}
			if pre.PollMinutes == 0 {
				pre.PollMinutes = 30
			}
			// git check-ref-format --help의 완전한 refname 검사 계약을 사용합니다.
			// --branch shorthand는 해석하지 않고 refs/heads/ 아래 이름만 허용합니다.
			if len(pre.Branch) > 255 || exec.Command("git", "check-ref-format", "refs/heads/"+pre.Branch).Run() != nil {
				return nil, fmt.Errorf("kernels[%d].prerelease.branch가 올바른 Git 브랜치 이름이 아닙니다", i)
			}
			if pre.PollMinutes < 1 || pre.PollMinutes > 525600 {
				return nil, fmt.Errorf("kernels[%d].prerelease.poll_minutes는 1~525600이어야 합니다", i)
			}
		}
	}

	if cfg.autoKernels() {
		if cfg.Series == "" {
			cfg.Series = osCodename("/etc/os-release")
		}
		if model.LTSByCodename(cfg.Series) == nil {
			return nil, fmt.Errorf("자동 모드는 지원 LTS(%s)에서만 됩니다. 이 서버 시리즈: %q — series 를 정하거나 kernels 를 직접 적으세요",
				ltsNames(), cfg.Series)
		}
	}
	return cfg, nil
}

// osCodename 은 os-release 파일의 VERSION_CODENAME 값입니다. 못 읽으면 "".
func osCodename(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	for _, l := range strings.Split(string(data), "\n") {
		if v, ok := strings.CutPrefix(l, "VERSION_CODENAME="); ok {
			return strings.Trim(strings.TrimSpace(v), `"`)
		}
	}
	return ""
}

func ltsNames() string {
	var names []string
	for _, s := range model.SupportedLTS {
		names = append(names, s.Codename)
	}
	return strings.Join(names, ", ")
}

func (c *Config) vmlinuxFor(kernel string) string {
	return filepath.Join(c.DebugDir, "vmlinux-"+kernel)
}

// kernelConfig 는 커널 이름으로 설정을 찾습니다. 없으면 기본값만 채운 설정을 돌려줍니다.
// (자동 수집 대상이 아닌 커널도 수동 제출 패치는 빌드할 수 있어야 하므로)
func (c *Config) kernelConfig(kernel string) KernelConfig {
	for _, k := range c.Kernels {
		if k.Kernel == kernel {
			return k
		}
	}
	return KernelConfig{Kernel: kernel, Vmlinux: c.vmlinuxFor(kernel)}
}

func (k KernelConfig) paths() []string {
	if len(k.Paths) > 0 {
		return k.Paths
	}
	return DefaultPaths
}
