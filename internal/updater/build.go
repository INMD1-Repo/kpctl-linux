// 이 파일: 업데이트 시 Go 바이너리 및(선택) React 웹 번들 빌드.
package updater

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func findTool(name string, fallbacks ...string) (string, error) {
	if p, err := exec.LookPath(name); err == nil {
		return p, nil
	}
	for _, cand := range fallbacks {
		if fi, err := os.Stat(cand); err == nil && !fi.IsDir() && fi.Mode()&0o111 != 0 {
			return cand, nil
		}
	}
	return "", fmt.Errorf("%s 명령을 찾지 못했습니다 (PATH 를 확인하세요)", name)
}

func buildArtifacts(ctx context.Context, repoDir, outDir string, plan *Plan, roles []Role, buildWeb bool, stdout, stderr io.Writer) error {
	needController := hasRole(roles, RoleController)

	if needController {
		webIndex := filepath.Join(repoDir, "internal", "controller", "web", "index.html")
		if buildWeb || !pathExists(webIndex) {
			if err := buildWebBundle(ctx, repoDir, stdout, stderr); err != nil {
				if buildWeb || !pathExists(webIndex) {
					return err
				}
				fmt.Fprintf(stderr, "경고: 웹 번들 빌드를 건너뜁니다 (%v)\n", err)
			}
		}
	}

	goBin, err := findTool("go", "/usr/local/go/bin/go", "/usr/bin/go", "/snap/bin/go")
	if err != nil {
		return fmt.Errorf("Go 컴파일러가 필요합니다: %w", err)
	}

	targets := []string{"./cmd/kpctl"}
	if needController {
		targets = append(targets, "./cmd/kpctl-controller", "./cmd/kpctl-builder", "./cmd/kpctl-agent")
	} else {
		targets = append(targets, "./cmd/kpctl-builder")
	}

	ldflags := fmt.Sprintf("-s -w -X kpctl/internal/version.Version=%s -X kpctl/internal/version.Commit=%s -X kpctl/internal/version.Branch=%s",
		plan.TargetVersion, plan.TargetCommit, plan.TargetBranch)

	env := setEnvVar(os.Environ(), "CGO_ENABLED", "0")
	// root 로 실행 시 저장소 소유자의 Go 캐시를 오염시키지 않도록 임시 캐시 또는 기본 캐시 사용
	for _, pkg := range targets {
		binName := filepath.Base(pkg)
		outPath := filepath.Join(outDir, binName)
		fmt.Fprintf(stdout, "  go build %s\n", binName)
		cmd := exec.CommandContext(ctx, goBin, "build", "-trimpath", "-ldflags="+ldflags, "-o", outPath, pkg)
		cmd.Dir = repoDir
		cmd.Env = env
		var out bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &out
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("%s 빌드 실패: %w\n%s", binName, err, strings.TrimSpace(out.String()))
		}
	}
	return nil
}

func buildWebBundle(ctx context.Context, repoDir string, stdout, stderr io.Writer) error {
	npmBin, err := findTool("npm", "/usr/local/bin/npm", "/usr/bin/npm")
	if err != nil {
		return fmt.Errorf("웹 빌드에 npm 이 필요합니다: %w", err)
	}
	webDir := filepath.Join(repoDir, "web")
	fmt.Fprintln(stdout, "  npm ci / npm run build (관리자 웹)")
	ci := exec.CommandContext(ctx, npmBin, "ci", "--prefix", webDir, "--ignore-scripts", "--no-fund")
	ci.Dir = repoDir
	ci.Stdout = stdout
	ci.Stderr = stderr
	if err := ci.Run(); err != nil {
		return fmt.Errorf("웹 의존성 설치(npm ci) 실패: %w", err)
	}
	build := exec.CommandContext(ctx, npmBin, "run", "build", "--prefix", webDir)
	build.Dir = repoDir
	build.Stdout = stdout
	build.Stderr = stderr
	if err := build.Run(); err != nil {
		return fmt.Errorf("웹 빌드(npm run build) 실패: %w", err)
	}
	return nil
}
