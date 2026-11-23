// 이 파일: builder 패키지의 runKpatchBuild, runKpatchMode, moduleName 구현·자료형.
package builder

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// buildOutput 은 kpatch-build 한 번의 결과입니다.
type buildOutput struct {
	ModulePath string // 만들어진 .ko 경로
	ModuleName string // 커널 모듈 이름
	Log        string // 실행 로그
}

// runKpatchBuild 는 kpatch-build 를 실행해 패치 파일들로 라이브패치 모듈을 만듭니다.
//
//	kpatch-build -a <kernel> -v <vmlinux> -n <name> -o <outDir> [-j N] patch1 patch2 ...
//
// 커널 git 과 기준 태그를 알면 git 에서 꺼낸 소스를 -s 로 줍니다 (오래된 커널도 가능).
// 모르면 -a 로 커널 버전만 주고 kpatch-build 가 Ubuntu 저장소에서 소스를 받습니다 (deb-src 필요). 패치 파일을 여러 개 주면 순서대로 모두 적용한
// 누적 모듈 하나를 만듭니다. 기본값으로 "atomic replace" 모듈이 만들어져서, 올리면 이전
// 패치를 통째로 교체합니다.
func (b *Builder) runKpatchBuild(k KernelConfig, name, outDir string, patchFiles []string) (buildOutput, error) {
	return b.runKpatchMode(k, name, outDir, patchFiles, false)
}

func (b *Builder) runKpatchMode(k KernelConfig, name, outDir string, patchFiles []string, baseline bool) (buildOutput, error) {
	out := buildOutput{ModuleName: name}
	if err := os.MkdirAll(outDir, 0o750); err != nil {
		return out, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(b.cfg.BuildTimeoutMinutes)*time.Minute)
	defer cancel()

	// 커널 git 과 기준 태그를 알면 소스를 git 에서 꺼내 -s 로 넘깁니다.
	// kpatch-build 가 스스로 받는 Ubuntu 저장소(pool)에는 오래된 커널의 소스가 없기 때문입니다.
	var args []string
	var source string
	if k.GitDir != "" && k.BaseTag != "" {
		src, prepLog, err := b.kernelSource(ctx, k)
		if err != nil {
			out.Log = prepLog
			return out, fmt.Errorf("%w: %v", errBuildEnv, err)
		}
		source = src
		args = []string{"-s", src, "-c", filepath.Join(b.cfg.BootDir, "config-"+k.Kernel), "-v", k.Vmlinux, "-n", name, "-o", outDir}
	} else {
		args = []string{"-a", k.Kernel, "-v", k.Vmlinux, "-n", name, "-o", outDir}
	}
	if b.cfg.Jobs > 0 {
		args = append(args, "-j", strconv.Itoa(b.cfg.Jobs))
	}
	args = append(args, patchFiles...)
	env, err := b.buildEnvironment(ctx, k, source)
	if err != nil {
		return out, fmt.Errorf("%w: %v", errBuildEnv, err)
	}
	cmd := exec.CommandContext(ctx, b.cfg.KpatchBuild, args...)
	cmd.Env = env
	if baseline {
		cmd.Env = append(cmd.Env, "KPCTL_BASELINE_ONLY=1")
	}
	killProcessGroup(cmd)
	finish, err := b.trackSourceBuild(ctx, k, source)
	if err != nil {
		return out, fmt.Errorf("%w: %v", errBuildEnv, err)
	}

	start := time.Now()
	b.setStep("kpatch-build 컴파일·모듈 생성")
	if home, err := os.UserHomeDir(); err == nil {
		stop := b.followBuildLog(filepath.Join(home, ".kpatch", "build.log"))
		defer stop()
	}
	finishMeasurement := b.measurePhase("tool_build_seconds")
	output, runErr := b.commandOutput(cmd)
	finishMeasurement()
	out.Log = fmt.Sprintf("$ %s %s\n\n%s\n(소요 %s)\n", b.cfg.KpatchBuild, strings.Join(args, " "), string(output), time.Since(start).Round(time.Second))
	if err := finish(runErr); err != nil {
		return out, fmt.Errorf("%w: %v", errBuildEnv, err)
	}

	if runErr != nil {
		// kpatch-build 는 자세한 로그를 ~/.kpatch/build.log 에 남깁니다. 마지막 부분을 붙여 줍니다.
		if home, err := os.UserHomeDir(); err == nil {
			if detail, err := os.ReadFile(filepath.Join(home, ".kpatch", "build.log")); err == nil {
				out.Log += "\n----- ~/.kpatch/build.log (마지막 200줄) -----\n" + lastLines(string(detail), 200)
			}
		}
		return out, fmt.Errorf("kpatch-build 실패: %w", runErr)
	}
	if baseline {
		return out, nil
	}

	// 결과 .ko 찾기: 보통 <name>.ko, 버전에 따라 이름이 다를 수 있어 *.ko 도 확인
	path := filepath.Join(outDir, name+".ko")
	if _, err := os.Stat(path); err != nil {
		matches, _ := filepath.Glob(filepath.Join(outDir, "*.ko"))
		if len(matches) != 1 {
			return out, fmt.Errorf("%w: 결과 .ko 를 찾지 못했습니다 (%s, 후보 %d개)", errBuildArtifact, outDir, len(matches))
		}
		path = matches[0]
		// 커널 모듈 이름은 파일 이름의 '-' 를 '_' 로 바꾼 것
		out.ModuleName = strings.ReplaceAll(strings.TrimSuffix(filepath.Base(path), ".ko"), "-", "_")
	}
	out.ModulePath = path
	return out, nil
}

// moduleName 은 커널과 버전으로 모듈 이름을 만듭니다.
// 커널 모듈 이름은 영문 소문자, 숫자, _ 만 쓰고 55자를 넘으면 안 됩니다.
//
//	예: ("6.8.0-85-generic", 3) → "kpctl_6_8_0_85_generic_v3"
func moduleName(kernel string, version int) string {
	var sb strings.Builder
	for _, r := range strings.ToLower(kernel) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			sb.WriteRune(r)
		} else {
			sb.WriteRune('_')
		}
	}
	// 접두사 "kpctl_" 는 반드시 남겨야 합니다 (에이전트가 이 접두사로 우리 패치를 구분함).
	// 너무 길면 커널 부분을 자릅니다.
	suffix := fmt.Sprintf("_v%d", version)
	if version < 0 {
		// 음수 버전은 컨트롤러가 따로 매긴 출시 전 계열입니다. '-'는 모듈 이름에 쓰지 않습니다.
		suffix = fmt.Sprintf("_pre%d", uint(-(version+1))+1)
	}
	k := sb.String()
	if max := 55 - len("kpctl_") - len(suffix); len(k) > max {
		k = k[:max]
	}
	return "kpctl_" + k + suffix
}

func lastLines(s string, n int) string {
	ls := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(ls) > n {
		ls = ls[len(ls)-n:]
	}
	return strings.Join(ls, "\n")
}
