// 이 파일: builder 패키지의 buildTool, configHasKLPBuild, runBuild 구현·자료형.
package builder

import (
	"bytes"
	"context"
	_ "embed"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// 이 파일: 빌드 도구 선택과 klp-build 실행
//
// kpatch-build 는 CONFIG_KLP_BUILD 커널(Ubuntu 26.04 의 7.0 부터)을 지원하지 않습니다.
// 이런 커널은 커널 소스에 들어 있는 scripts/livepatch/klp-build 로 빌드합니다.
// kpatch 가 지원하게 되면 canary 에서 검증한 뒤 build_tool 을 "kpatch" 로 바꾸세요.

const (
	BuildToolAuto   = "auto"
	BuildToolKpatch = "kpatch"
	BuildToolKLP    = "klp"
)

//go:embed klp-prepare-source.sh
var klpPrepareScript string

const sourceFormat = "ubuntu-build-v2"

// buildTool 은 이 커널을 어떤 도구로 빌드할지 정합니다.
func (c *Config) buildTool(kernel string) string {
	if c.BuildTool == BuildToolKpatch || c.BuildTool == BuildToolKLP {
		return c.BuildTool
	}
	if configHasKLPBuild(filepath.Join(c.BootDir, "config-"+kernel)) {
		return BuildToolKLP
	}
	return BuildToolKpatch
}

func configHasKLPBuild(path string) bool {
	data, err := os.ReadFile(path)
	return err == nil && bytes.Contains(append([]byte("\n"), data...), []byte("\nCONFIG_KLP_BUILD=y\n"))
}

// runBuild 는 커널에 맞는 도구로 패치 모듈을 만듭니다.
func (b *Builder) runBuild(k KernelConfig, name, outDir string, patchFiles []string) (buildOutput, error) {
	// 정리 후 다른 프로세스가 공간을 썼을 수도 있습니다. 이미 시작한 빌드를 중단하지는 않습니다.
	if space, spaceErr := b.diskSpace(k.Kernel); spaceErr != nil || space.free < space.minimum {
		b.diskBlocked = true
		b.reportProblemKind(k.Kernel, space.problem(spaceErr), problemDiskSpace, false)
		if spaceErr != nil {
			return buildOutput{}, fmt.Errorf("%w: %v", errDiskSpace, spaceErr)
		}
		return buildOutput{}, errDiskSpace
	}
	b.setStep("빌드 공간 잠금·환경 준비")
	lock, lockErr := b.lockBuild()
	if lockErr != nil {
		return buildOutput{}, fmt.Errorf("%w: %w", errBuildEnv, lockErr)
	}
	defer lock.Close()
	if b.cfg.Sandbox == nil {
		userLock, err := lockUserBuild()
		if err != nil {
			return buildOutput{}, fmt.Errorf("%w: %w", errBuildEnv, err)
		}
		defer userLock.Close()
	}
	var out buildOutput
	var err error
	if b.cfg.Sandbox != nil {
		out, err = b.runSandboxBuild(k, name, outDir, patchFiles)
	} else if b.cfg.buildTool(k.Kernel) == BuildToolKLP {
		out, err = b.runKLPBuild(k, name, outDir, patchFiles)
	} else {
		out, err = b.runKpatchBuild(k, name, outDir, patchFiles)
	}
	if err == nil {
		b.setStep("ELF·vermagic·참조 심볼 CRC 검증")
		finishMeasurement := b.measurePhase("module_validation_seconds")
		var report string
		report, err = b.verifyModule(k, out)
		finishMeasurement()
		if err != nil {
			err = fmt.Errorf("%w: 빌드 결과물 검증 실패: %v", errBuildArtifact, err)
		} else {
			out.Log += "\n" + report
			if writer := b.liveOutput(); writer != nil {
				_, _ = writer.Write([]byte(report + "\n"))
			}
		}
	}
	return out, err
}

// klpBuildArgs 는 klp-build 인자입니다. -o 의 파일 이름이 곧 모듈 이름입니다.
// 기본값이 atomic replace 라서 kpatch-build 의 누적 모듈과 동작이 같습니다.
func klpBuildArgs(jobs int, modulePath string, patchFiles []string) []string {
	args := []string{"-o", modulePath}
	if jobs > 0 {
		args = append(args, "-j", strconv.Itoa(jobs))
	}
	return append(args, patchFiles...)
}

func (b *Builder) runKLPBuild(k KernelConfig, name, outDir string, patchFiles []string) (buildOutput, error) {
	out := buildOutput{ModuleName: name}
	if err := os.MkdirAll(outDir, 0o750); err != nil {
		return out, err
	}
	modulePath := filepath.Join(outDir, name+".ko")
	timeout := time.Duration(b.cfg.BuildTimeoutMinutes) * time.Minute
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	inputs, err := b.cumulativeKLPPatches(ctx, k, outDir, patchFiles)
	if err != nil {
		if errors.Is(err, errPatchDependency) {
			return out, err
		}
		return out, fmt.Errorf("%w: %v", errBuildEnv, err)
	}
	src, prepLog, err := b.kernelSource(ctx, k)
	if err != nil {
		out.Log = prepLog
		return out, fmt.Errorf("%w: %v", errBuildEnv, err)
	}
	env, err := b.buildEnvironment(ctx, k, src)
	if err != nil {
		return out, fmt.Errorf("%w: %v", errBuildEnv, err)
	}

	args := klpBuildArgs(b.cfg.Jobs, modulePath, inputs)
	cmd := exec.CommandContext(ctx, filepath.Join(src, "scripts/livepatch/klp-build"), args...)
	cmd.Dir = src
	cmd.Env = env
	killProcessGroup(cmd)
	finish, err := b.trackSourceBuild(ctx, k, src)
	if err != nil {
		return out, fmt.Errorf("%w: %v", errBuildEnv, err)
	}

	start := time.Now()
	b.setStep("klp-build 컴파일·모듈 생성")
	stopLog := b.followBuildLog(filepath.Join(src, "klp-tmp", "build.log"))
	defer stopLog()
	finishMeasurement := b.measurePhase("tool_build_seconds")
	output, runErr := b.commandOutput(cmd)
	finishMeasurement()
	// 컴파일러 경고가 많으므로 뒷부분만 남깁니다.
	out.Log = fmt.Sprintf("$ klp-build %s\n\n%s\n(소요 %s)\n", strings.Join(args, " "), lastLines(string(output), 500), time.Since(start).Round(time.Second))
	if len(patchFiles) > 1 {
		out.Log = fmt.Sprintf("선택 패치 %d개를 %s 기준의 단일 누적 diff로 전달\n", len(patchFiles), k.BaseTag) + out.Log
	}
	if tools, toolsErr := b.klpTools(k); toolsErr == nil && tools != nil {
		out.Log = tools.describe() + "\n" + out.Log
	}
	if err := finish(runErr); err != nil {
		return out, fmt.Errorf("%w: %v", errBuildEnv, err)
	}
	if runErr != nil {
		return out, fmt.Errorf("klp-build 실패: %w", runErr)
	}
	if _, err := os.Stat(modulePath); err != nil {
		return out, fmt.Errorf("%w: 결과 .ko 를 찾지 못했습니다: %v", errBuildArtifact, err)
	}
	out.ModulePath = modulePath
	return out, nil
}

// errBuildEnv 는 패치 내용과 상관없는 빌드 환경 문제입니다 (소스 준비 실패 등).
// 시험 빌드에서 이 오류가 나면 커밋을 "라이브패치 불가"로 기록하지 않고 수집을 멈춥니다.
var errBuildEnv = errors.New("빌드 환경 오류")

var errBuildDeferred = fmt.Errorf("%w: 빌드 보류", errBuildEnv)
var errBuildBusy = fmt.Errorf("%w: 다른 커널 빌드가 실행 중입니다", errBuildDeferred)

// kernelSource 는 upstream 버전을 보존한 소스와 대상 .config 를 돌려줍니다. 없으면 만듭니다.
// 커널 git 과 기준 태그를 알면 git 에서 꺼내고(오래된 커널도 가능), 모르면 Ubuntu 저장소에서 받습니다.
// 소스가 수 GB 라서 다른 커널의 소스는 지우고 한 벌만 둡니다.
func (b *Builder) kernelSource(ctx context.Context, k KernelConfig) (string, string, error) {
	defer b.measurePhase("source_prepare_seconds")()
	root := filepath.Join(b.cfg.WorkDir, "src")
	src := filepath.Join(root, k.Kernel)
	tools, err := b.klpTools(k)
	if err != nil {
		return "", "", err
	}
	want := sourceMark(k.BaseTag, tools)
	if k.GitDir == "" || k.BaseTag == "" {
		want = "dsc"
	}
	format, _ := os.ReadFile(filepath.Join(src, ".kpctl-source-format"))
	_, interrupted := os.Stat(filepath.Join(src, sourceBuildMarker))
	clean := os.IsNotExist(interrupted)
	if interrupted != nil && !clean {
		return "", "", interrupted
	}
	if data, err := os.ReadFile(filepath.Join(src, ".kpctl-ready")); err == nil && strings.TrimSpace(string(data)) == want && strings.TrimSpace(string(format)) == sourceFormat && clean {
		if err := b.verifySourceTree(ctx, k, src); err != nil {
			if !errors.Is(err, errSourceDirty) {
				return "", "", err
			}
			log.Printf("[%s] 소스 캐시 변경 감지 → 기준 태그에서 다시 준비", k.Kernel)
		} else {
			cmd := exec.CommandContext(ctx, "bash", "-c", klpPrepareScript, "kernel-prepare-certificates", "--certificates-only", src)
			killProcessGroup(cmd)
			out, err := b.commandOutput(cmd)
			return src, lastLines(string(out), 100), err
		}
	}
	if err := os.RemoveAll(root); err != nil {
		return "", "", err
	}
	_ = os.RemoveAll(filepath.Join(b.cfg.WorkDir, "klp-src")) // 예전 위치
	if err := os.MkdirAll(root, 0o750); err != nil {
		return "", "", err
	}
	args := []string{"-c", klpPrepareScript, "kernel-prepare-source", k.Kernel, src}
	if want != "dsc" {
		args = append(args, k.GitDir, k.BaseTag)
		if tools != nil {
			args = append(args, tools.Tree)
		}
	}
	log.Printf("[%s] 커널 소스 준비 (%s)", k.Kernel, want)
	b.setStep("커널 소스·설정 준비")
	cmd := exec.CommandContext(ctx, "bash", args...)
	cmd.Env = append(os.Environ(), "KPCTL_BOOT_DIR="+b.cfg.BootDir)
	killProcessGroup(cmd)
	out, err := b.commandOutput(cmd)
	return src, lastLines(string(out), 100), err
}

// killProcessGroup 은 시간 초과 때 make 와 컴파일러까지 함께 끝냅니다.
func killProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 10 * time.Second
}
