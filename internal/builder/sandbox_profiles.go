// 이 파일: builder 패키지의 compilerProfileName, kernelCompiler, sandboxProfile 구현·자료형.
package builder

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

var errSandboxProfileMissing = errors.New("대상 컴파일러 프로파일 없음")
var regexpBaseDigest = regexp.MustCompile(`^[^\s]+@sha256:[0-9a-f]{64}$`)

func compilerProfileName(compiler string) string {
	return "compiler-" + fmt.Sprintf("%x", sha256.Sum256([]byte(compiler)))[:20]
}

// The compiler identity comes from the target headers, never the host GCC.
func kernelCompiler(kernel, headersRoot string) string {
	if headersRoot == "" {
		headersRoot = "/usr/src"
	}
	data, err := os.ReadFile(filepath.Join(headersRoot, "linux-headers-"+kernel, "include/generated/compile.h"))
	if err != nil {
		return ""
	}
	return gccRe.FindString(string(data))
}

func (b *Builder) sandboxProfile(kernel string) (string, error) {
	target := kernelCompiler(kernel, b.headersRoot)
	if target == "" {
		return "", fmt.Errorf("%s 대상 헤더의 GCC 정보가 없습니다 (linux-headers-%s 확인)", kernel, kernel)
	}
	sandbox := b.cfg.Sandbox
	path := sandbox.Profile
	if sandbox.ProfilesDir != "" {
		path = filepath.Join(sandbox.ProfilesDir, compilerProfileName(gccID(target)), "profile.json")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("%w: %s (%s): prepare --kernel %s 로 준비하세요", errSandboxProfileMissing, gccID(target), path, kernel)
		}
		return "", fmt.Errorf("격리 프로파일 읽기 실패: %s: %w", path, err)
	}
	var profile struct {
		Schema   int    `json:"schema"`
		Image    string `json:"image"`
		Settings struct {
			Compiler string `json:"compiler_identity"`
		} `json:"settings"`
	}
	if err := json.Unmarshal(data, &profile); err != nil || profile.Schema != 1 || !sandboxImage.MatchString(profile.Image) {
		return "", fmt.Errorf("격리 프로파일이 잘못됐습니다: %s", path)
	}
	if profile.Settings.Compiler != gccID(target) {
		return "", fmt.Errorf("대상 GCC %s와 격리 프로파일 GCC %s가 다릅니다: prepare --kernel %s", gccID(target), profile.Settings.Compiler, kernel)
	}
	return path, nil
}

// Only an unpatched offline worker can populate a baseline compiler cache.
// It emits no livepatch module and verifies the source restoration afterwards.
func (b *Builder) warmBuildCache(ctx context.Context, k KernelConfig) (buildOutput, error) {
	if b.cfg.buildTool(k.Kernel) == BuildToolKpatch {
		return b.runKpatchMode(k, "kpctl_baseline", filepath.Join(b.cfg.WorkDir, "out"), nil, true)
	}
	out := buildOutput{}
	src, prepLog, err := b.kernelSource(ctx, k)
	if err != nil {
		out.Log = prepLog
		return out, err
	}
	env, err := b.buildEnvironment(ctx, k, src)
	if err != nil {
		return out, err
	}
	script := filepath.Join(src, "scripts", "livepatch", "klp-build")
	original, err := os.ReadFile(script)
	if err != nil {
		return out, err
	}
	program, err := klpBaselineProgram(string(original))
	if err != nil {
		return out, err
	}
	// Keep SCRIPT_DIR in the real livepatch directory. No tracked source file
	// is modified, and the actual tool's clean_kernel/build_kernel are used.
	worker, err := os.CreateTemp(filepath.Dir(script), ".kpctl-baseline-")
	if err != nil {
		return out, err
	}
	defer os.Remove(worker.Name())
	if _, err = worker.WriteString(program); err != nil {
		worker.Close()
		return out, err
	}
	if err = worker.Chmod(0o700); err != nil {
		worker.Close()
		return out, err
	}
	if err = worker.Close(); err != nil {
		return out, err
	}
	var args []string
	if b.cfg.Jobs > 0 {
		args = []string{"-j", strconv.Itoa(b.cfg.Jobs)}
	}
	cmd := exec.CommandContext(ctx, worker.Name(), args...)
	cmd.Dir = src
	cmd.Env = env
	killProcessGroup(cmd)
	finish, err := b.trackSourceBuild(ctx, k, src)
	if err != nil {
		return out, err
	}
	b.setStep("패치 없는 native 기준 빌드·ccache 준비")
	finishMeasurement := b.measurePhase("tool_build_seconds")
	output, runErr := b.commandOutput(cmd)
	finishMeasurement()
	out.Log = string(output)
	if err := os.Remove(worker.Name()); err != nil {
		return out, err
	}
	if err := finish(runErr); err != nil {
		return out, err
	}
	return out, runErr
}

// These narrow, checked edits expose the original-only path without copying
// compiler flags into Go. A changed upstream entry point fails explicitly.
func klpBaselineProgram(original string) (string, error) {
	required := "\tif [[ $# -eq 0 ]]; then\n\t\tusage\n\t\texit 1\n\tfi"
	originalBuild := "\tbuild_kernel\n\tstatus \"Copying original object files\""
	if strings.Count(original, required) != 1 || strings.Count(original, originalBuild) != 1 {
		return "", fmt.Errorf("klp-build 원본 빌드 진입점이 변경됐습니다. 기준 빌드 경로를 검토하세요")
	}
	program := strings.Replace(original, required, "\tif [[ $# -ne 0 ]]; then\n\t\tdie \"baseline cannot apply patches\"\n\tfi", 1)
	return strings.Replace(program, originalBuild, "\tbuild_kernel\n\texit 0 # kpctl original-only baseline\n\tstatus \"Copying original object files\"", 1), nil
}
