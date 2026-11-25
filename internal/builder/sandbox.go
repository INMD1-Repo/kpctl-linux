// 이 파일: builder 패키지의 runSandboxBuild, sandboxResponseFailure, RunBuildRequest 구현·자료형.
package builder

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"kpctl/internal/model"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// No controller credentials or signing keys are part of the worker protocol.
type BuildRequest struct {
	Kernel         KernelConfig `json:"kernel"`
	BaseCommit     string       `json:"base_commit"`
	Name           string       `json:"name"`
	WorkDir        string       `json:"work_dir"`
	OutDir         string       `json:"out_dir"`
	BootDir        string       `json:"boot_dir"`
	PatchFiles     []string     `json:"patch_files"`
	BuildTool      string       `json:"build_tool"`
	Jobs           int          `json:"jobs"`
	TimeoutMinutes int          `json:"timeout_minutes"`
	CacheWarmup    bool         `json:"cache_warmup,omitempty"`
}

type BuildResponse struct {
	Timings map[string]float64     `json:"timings,omitempty"`
	Success bool                   `json:"success"`
	Kind    string                 `json:"kind,omitempty"`
	Error   string                 `json:"error,omitempty"`
	Log     string                 `json:"log"`
	Cache   *model.BuildCacheStats `json:"cache,omitempty"`
}

var sandboxKernel = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+-[0-9]+-[A-Za-z0-9_-]+$`)
var fullCommit = regexp.MustCompile(`^[0-9a-f]{40}$`)
var sandboxModule = regexp.MustCompile(`^[a-z][a-z0-9_]{0,54}$`)
var sandboxImage = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func (b *Builder) runSandboxBuild(k KernelConfig, name, outDir string, patches []string) (buildOutput, error) {
	out := buildOutput{ModuleName: name}
	profile, err := b.ensureSandboxProfile(k)
	if err != nil {
		return out, fmt.Errorf("%w: %w", errBuildEnv, err)
	}
	if !sandboxKernel.MatchString(k.Kernel) || !sandboxModule.MatchString(name) || k.GitDir == "" || k.BaseTag == "" {
		return out, fmt.Errorf("%w: 격리 빌드에는 정확한 커널·Git 저장소·기준 태그가 필요합니다", errBuildEnv)
	}
	base, err := git(k.GitDir, "rev-parse", "--verify", k.BaseTag+"^{commit}")
	if err != nil {
		return out, fmt.Errorf("%w: %v", errBuildEnv, err)
	}
	if err = os.MkdirAll(outDir, 0o750); err != nil {
		return out, err
	}
	outDir, err = filepath.Abs(outDir)
	if err != nil {
		return out, err
	}
	files := make([]string, len(patches))
	for i, file := range patches {
		files[i], err = filepath.Abs(file)
		if err != nil {
			return out, err
		}
	}
	req := BuildRequest{Kernel: k, BaseCommit: strings.TrimSpace(base), Name: name, WorkDir: b.cfg.WorkDir, OutDir: outDir, BootDir: b.cfg.BootDir, PatchFiles: files, BuildTool: b.cfg.buildTool(k.Kernel), Jobs: b.cfg.Jobs, TimeoutMinutes: b.cfg.BuildTimeoutMinutes}
	data, err := json.Marshal(req)
	if err != nil {
		return out, err
	}
	file := filepath.Join(outDir, "environment-request.json")
	if err = os.WriteFile(file, data, 0o600); err != nil {
		return out, err
	}
	resultPath := filepath.Join(outDir, "environment-result.json")
	for _, stale := range []string{resultPath, filepath.Join(outDir, name+".ko")} {
		if err = os.Remove(stale); err != nil && !os.IsNotExist(err) {
			return out, err
		}
	}
	worker := b.cfg.Sandbox.WorkerBinary
	if worker == "" {
		worker = "/proc/" + strconv.Itoa(os.Getpid()) + "/exe"
	}
	// 도우미가 단계마다 build_timeout_minutes 를 지킵니다: 처음 한 번의 기준 빌드(ccache 준비)와
	// 실제 빌드가 각각 그 시간을 씁니다. 여기는 도우미가 멈췄을 때만 끊는 바깥 안전장치라
	// 두 단계와 컨테이너 정리 여유(15분)를 합친 만큼 기다립니다.
	ctx, cancel := context.WithTimeout(context.Background(), sandboxTimeout(b.cfg.BuildTimeoutMinutes))
	defer cancel()
	args := []string{"run", "--profile", profile, "--request", file, "--worker", worker}
	for _, kernel := range b.activeKernels {
		args = append(args, "--active-kernel", kernel)
	}
	if b.cfg.Sandbox.RetryClean {
		args = append(args, "--retry-clean")
	}
	cmd := exec.CommandContext(ctx, b.cfg.Sandbox.Helper, args...)
	log.Printf("[%s] 일회용 격리 빌드: %s (프로파일 %s)", k.Kernel, name, profile)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	// Let the helper remove its container before escalating. Killing only the
	// Podman client would leave compilers running in another process group.
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM) }
	cmd.WaitDelay = 30 * time.Second
	b.setStep("일회용 격리 환경 준비·컴파일")
	output, runErr := b.commandOutput(cmd)
	out.Log = string(output)
	result, err := os.ReadFile(resultPath)
	if err != nil {
		return out, sandboxResponseFailure(runErr, ctx.Err(), "격리 결과 읽기 실패", err, out.Log)
	}
	var response BuildResponse
	if err = json.Unmarshal(result, &response); err != nil {
		return out, sandboxResponseFailure(runErr, ctx.Err(), "격리 응답 해석 실패", err, out.Log)
	}
	b.setCacheStats(response.Cache)
	out.Log += response.Log
	if writer := b.liveOutput(); writer != nil {
		_, _ = writer.Write([]byte(lastLines(response.Log, 40) + "\n"))
	}
	if runErr != nil || !response.Success {
		if response.Kind == "disk_space" {
			return out, fmt.Errorf("%w: %s", errDiskSpace, response.Error)
		}
		if response.Kind == "busy" {
			return out, fmt.Errorf("%w: %s", errBuildBusy, response.Error)
		}
		if response.Kind == "artifact" || response.Kind == "validation" {
			return out, fmt.Errorf("%w: %s", errBuildArtifact, response.Error)
		}
		if response.Kind == "environment" || response.Kind == "preflight" {
			return out, fmt.Errorf("%w: %s", errBuildEnv, response.Error)
		}
		if response.Kind == model.FailureUnsupported || response.Kind == model.FailureUnknown {
			return out, &buildFailure{response.Kind, fmt.Errorf("격리 빌드 실패: %s", response.Error)}
		}
		return out, fmt.Errorf("격리 빌드 실패: %s (%v)", response.Error, runErr)
	}
	out.ModulePath = filepath.Join(outDir, name+".ko")
	return out, nil // The caller also verifies the exported ELF on the host.
}

// A compiler warning at the end of stdout is context, not the reason the
// helper failed to return a response. Retain the actual exit/signal and timeout
// separately, including their error identities for callers and diagnostics.
func sandboxResponseFailure(runErr, contextErr error, action string, resultErr error, output string) error {
	var processErr error
	switch {
	case contextErr != nil && runErr != nil && !errors.Is(runErr, contextErr):
		processErr = fmt.Errorf("제한 시간/취소: %w (도우미 종료: %w)", contextErr, runErr)
	case contextErr != nil:
		processErr = fmt.Errorf("제한 시간/취소: %w", contextErr)
	case runErr != nil:
		processErr = fmt.Errorf("도우미 종료: %w", runErr)
	default:
		processErr = errors.New("도우미 정상 종료 후 유효한 결과가 없습니다")
	}
	class := errBuildEnv
	var exit *exec.ExitError
	if contextErr == nil && errors.As(runErr, &exit) && exit.ExitCode() == 73 {
		// ENOSPC/EDQUOT can prevent even the helper's result file from being written.
		class = errDiskSpace
	}
	failure := fmt.Errorf("%w: 격리 실행 실패: %w; %s: %v", class, processErr, action, resultErr)
	if tail := strings.TrimSpace(lastLines(output, 20)); tail != "" {
		return fmt.Errorf("%w\n도우미 로그 끝부분 (참고):\n%s", failure, tail)
	}
	return failure
}

// RunBuildRequest is an offline worker, without collection, controller access,
// approval, signing, module loading or reboot capabilities.
func RunBuildRequest(path string) error {
	if os.Geteuid() == 0 || os.Getenv("KPCTL_ISOLATED_WORKER") != "1" {
		return fmt.Errorf("worker는 비특권 격리 컨테이너에서만 실행합니다")
	}
	if _, err := os.Stat("/run/.containerenv"); err != nil {
		return fmt.Errorf("Podman 컨테이너 표식이 없습니다")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var req BuildRequest
	if err = json.Unmarshal(data, &req); err != nil {
		return err
	}
	const work = "/var/lib/kpctl-builder"
	if !sandboxKernel.MatchString(req.Kernel.Kernel) || !fullCommit.MatchString(req.BaseCommit) || !sandboxModule.MatchString(req.Name) || req.WorkDir != work || req.OutDir != work+"/out" || req.BootDir != "/inputs/boot" || req.Kernel.GitDir != "/inputs/repository" || req.Kernel.Vmlinux != "/inputs/vmlinux" || req.TimeoutMinutes < 1 || req.Jobs < 0 || (req.BuildTool != BuildToolKpatch && req.BuildTool != BuildToolKLP) {
		return fmt.Errorf("격리 요청의 대상·경로·도구가 잘못됐습니다")
	}
	for _, file := range req.PatchFiles {
		if filepath.Dir(file) != "/inputs/patches" || filepath.Ext(file) != ".patch" {
			return fmt.Errorf("격리 패치 경로가 잘못됐습니다")
		}
	}
	if req.CacheWarmup && len(req.PatchFiles) != 0 {
		return fmt.Errorf("기준 빌드에는 패치를 전달할 수 없습니다")
	}
	response := BuildResponse{}
	err = runLocalBuild(req, &response)
	if err != nil {
		response.Error = err.Error()
	}
	encoded, encodeErr := json.Marshal(response)
	if encodeErr != nil {
		return encodeErr
	}
	if writeErr := os.WriteFile(filepath.Join(work, "result.json"), encoded, 0o600); writeErr != nil {
		return writeErr
	}
	return err
}

func runLocalBuild(req BuildRequest, response *BuildResponse) error {
	response.Kind = model.FailureEnvironment
	for _, tool := range []string{"git", "make", "gcc", "ld", "modinfo", "patch", "gawk", "python3", "readelf", "objcopy", "rsync", "bc", "bison", "flex"} {
		if _, err := exec.LookPath(tool); err != nil {
			return fmt.Errorf("환경 패키지 누락: %s", tool)
		}
	}
	if target, actual := gccVersions(req.Kernel.Kernel); target == "" || actual == "" || gccID(target) != gccID(actual) {
		return fmt.Errorf("대상 GCC와 이미지 GCC가 다릅니다: %q / %q", target, actual)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(req.TimeoutMinutes)*time.Minute)
	defer cancel()
	repo := filepath.Join(req.WorkDir, "repository")
	repositoryStarted := time.Now()
	cmd := exec.CommandContext(ctx, "git", "clone", "--shared", "--no-checkout", "--quiet", req.Kernel.GitDir, repo)
	killProcessGroup(cmd)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("개인 Git 준비 실패: %v: %s", err, out)
	}
	if _, err := git(repo, "update-ref", "refs/tags/"+req.Kernel.BaseTag, req.BaseCommit); err != nil {
		return err
	}
	req.Kernel.GitDir = repo
	// 컨트롤러 없는 격리 워커: 호스트 빌더와 Python 도우미가 공간을 검사합니다.
	cfg := &Config{KernelCleanupFreeGiB: -1, WorkDir: req.WorkDir, BootDir: req.BootDir, BuildTool: req.BuildTool, KpatchBuild: "/usr/local/bin/kpatch-build", Jobs: req.Jobs, BuildTimeoutMinutes: req.TimeoutMinutes}
	b := &Builder{cfg: cfg, output: os.Stdout}
	b.timings = map[string]float64{}
	b.timings["private_repository_seconds"] = time.Since(repositoryStarted).Seconds()
	defer func() { response.Timings = b.timings }()
	if req.CacheWarmup {
		response.Kind = "environment"
		out, err := b.warmBuildCache(ctx, req.Kernel)
		if err == nil {
			cleanup := exec.CommandContext(ctx, "ccache", "--cleanup")
			killProcessGroup(cleanup)
			output, cleanupErr := b.commandOutput(cleanup)
			out.Log += string(output)
			err = cleanupErr
		}
		response.Log = out.Log
		response.Success = err == nil
		if err == nil {
			response.Kind = ""
		}
		return err
	}
	out, err := b.runBuild(req.Kernel, req.Name, req.OutDir, req.PatchFiles)
	response.Log = out.Log
	response.Kind = ""
	if err != nil {
		response.Kind = failureKind(err, out.Log)
	}
	response.Success = err == nil
	return err
}

// sandboxTimeout 은 격리 빌드 도우미 전체를 기다리는 최대 시간입니다 (기준 빌드 + 실제 빌드 + 정리 여유).
// 0 이하(시험에서 쓰는 즉시 만료)는 그대로 0 입니다. 설정 검사는 1~1440분만 허용합니다.
func sandboxTimeout(buildMinutes int) time.Duration {
	if buildMinutes <= 0 {
		return 0
	}
	return time.Duration(2*buildMinutes+15) * time.Minute
}
