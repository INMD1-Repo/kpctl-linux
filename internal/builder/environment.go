// 이 파일: builder 패키지의 buildEnvironment, configString, exactBuildTool 구현·자료형.
package builder

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

var makeValue = regexp.MustCompile(`^[A-Za-z0-9_./+-]+$`)

// buildEnvironment 는 Ubuntu ABI·인라인·Rust 빌드 조건을 두 도구에 전달합니다.
// upstream 버전과 공개 ABI 이름을 따로 유지합니다.
func (b *Builder) buildEnvironment(ctx context.Context, k KernelConfig, src string) ([]string, error) {
	if !makeValue.MatchString(k.Kernel) {
		return nil, fmt.Errorf("make 에 전달할 수 없는 커널 이름: %q", k.Kernel)
	}
	vars := []string{"KERNELRELEASE=" + k.Kernel, "CONFIG_DEBUG_SECTION_MISMATCH=y"}
	parts := strings.Split(k.Kernel, "-")
	if len(parts) >= 3 && regexp.MustCompile(`^[0-9]+$`).MatchString(parts[1]) {
		vars = append(vars, "CFLAGS_MODULE=-DPKG_ABI="+parts[1])
	}
	config, _ := os.ReadFile(filepath.Join(b.cfg.BootDir, "config-"+k.Kernel))
	rust := strings.Contains("\n"+string(config)+"\n", "\nCONFIG_RUST=y\n")
	if rust {
		rustc, err := exactBuildTool(ctx, "rustc", configString(string(config), "CONFIG_RUSTC_VERSION_TEXT"))
		if err != nil {
			return nil, err
		}
		bindgen, err := exactBuildTool(ctx, "bindgen", configString(string(config), "CONFIG_BINDGEN_VERSION_TEXT"))
		if err != nil {
			return nil, err
		}
		vars = append(vars, "RUSTC="+rustc, "HOSTRUSTC="+rustc, "BINDGEN="+bindgen)
	}
	flags := strings.TrimSpace(os.Getenv("MAKEFLAGS") + " " + strings.Join(vars, " "))
	// 빌드 로그의 git apply·patch 오류 문구("patch does not apply" 등)로 실패를 분류하므로 로캘을 고정합니다.
	env := append(os.Environ(), "MAKEFLAGS="+flags, "PATH=/usr/lib/ccache:"+os.Getenv("PATH"), "LC_ALL=C", "LANGUAGE=C")
	if rust && src != "" {
		cmd := exec.CommandContext(ctx, "make", "-s", "-C", src, "rustavailable")
		cmd.Env = env
		killProcessGroup(cmd)
		if out, err := b.commandOutput(cmd); err != nil {
			return nil, fmt.Errorf("대상 CONFIG_RUST 를 유지할 빌드 환경 확인 실패: %v\n%s", err, lastLines(string(out), 20))
		}
	}
	return env, nil
}

func configString(config, key string) string {
	for _, line := range strings.Split(config, "\n") {
		if strings.HasPrefix(line, key+"=\"") {
			return strings.TrimSuffix(strings.TrimPrefix(line, key+"=\""), "\"")
		}
	}
	return ""
}

func exactBuildTool(ctx context.Context, name, expected string) (string, error) {
	fields := strings.Fields(expected)
	if len(fields) < 2 || fields[0] != name {
		return "", fmt.Errorf("대상 커널의 %s 버전 정보가 없습니다", name)
	}
	version := strings.Split(fields[1], ".")
	if len(version) < 2 {
		return "", fmt.Errorf("대상 %s 버전 정보가 잘못됐습니다: %s", name, expected)
	}
	for _, candidate := range []string{name + "-" + strings.Join(version[:2], "."), name} {
		path, err := exec.LookPath(candidate)
		if err != nil || !makeValue.MatchString(path) {
			continue
		}
		out, err := exec.CommandContext(ctx, path, "--version").Output()
		if err == nil && strings.TrimSpace(string(out)) == expected {
			return path, nil
		}
	}
	return "", fmt.Errorf("대상 커널과 같은 %s 가 필요합니다: %s (CONFIG_RUST 를 자동 해제하지 않음)", name, expected)
}
