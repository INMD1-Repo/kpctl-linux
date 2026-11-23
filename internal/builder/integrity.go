// 이 파일: builder 패키지의 verifySourceTree, trackSourceBuild, lockBuild 구현·자료형.
package builder

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

const sourceBuildMarker = ".kpctl-building"

var errSourceDirty = errors.New("기준 Git 태그와 소스가 다릅니다")

// 개인 인덱스를 써서 커널 저장소의 checkout·index 를 바꾸지 않고 대조합니다.
func (b *Builder) verifySourceTree(ctx context.Context, k KernelConfig, src string) error {
	if k.GitDir == "" || k.BaseTag == "" {
		return nil
	}
	tmp, err := os.MkdirTemp(b.cfg.WorkDir, "source-index-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	git := func(args ...string) ([]byte, error) {
		prefix := []string{"-C", k.GitDir, "--work-tree=" + src, "-c", "core.filemode=false", "-c", "core.fsmonitor=false"}
		cmd := exec.CommandContext(ctx, "git", append(prefix, args...)...)
		cmd.Env = append(os.Environ(), "GIT_INDEX_FILE="+filepath.Join(tmp, "index"), "GIT_OPTIONAL_LOCKS=0")
		killProcessGroup(cmd)
		return cmd.CombinedOutput()
	}
	// 기대하는 트리 = 기준 태그 + 고정 조합의 빌드 도구 경로 (klptools.go).
	// 인덱스도 같은 트리를 써야 새 도구 파일을 삭제·추가 소스로 오판하지 않습니다.
	expected := k.BaseTag
	tools, err := b.klpTools(k)
	if err != nil {
		return fmt.Errorf("빌드 도구 출처 확인 실패: %w", err)
	}
	if tools != nil {
		expected = tools.Tree
	}
	if out, err := git("read-tree", expected); err != nil {
		return fmt.Errorf("소스 기준 인덱스 생성 실패: %v: %s", err, lastLines(string(out), 5))
	}
	if out, err := git("diff", "--quiet", "--no-ext-diff", "--no-textconv", expected, "--"); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) && exit.ExitCode() == 1 {
			return errSourceDirty
		}
		return fmt.Errorf("소스 대조 실패: %v: %s", err, lastLines(string(out), 5))
	}
	files, err := git("ls-files", "--others", "--exclude-standard", "-z")
	if err != nil {
		return fmt.Errorf("추가 소스 확인 실패: %w", err)
	}
	for _, path := range strings.Split(string(files), "\x00") {
		if strings.HasPrefix(path, "klp-tmp/") { // native 도구의 별도 객체·임시 소스 디렉터리
			continue
		}
		base := filepath.Base(path)
		switch filepath.Ext(path) {
		case ".c", ".h", ".S", ".rs":
			return fmt.Errorf("%w: 추가 파일 %s", errSourceDirty, path)
		}
		if base == "Makefile" || base == "Kbuild" || base == "Kconfig" {
			return fmt.Errorf("%w: 추가 파일 %s", errSourceDirty, path)
		}
	}
	return nil
}

func (b *Builder) trackSourceBuild(ctx context.Context, k KernelConfig, src string) (func(error) error, error) {
	if src == "" {
		return func(error) error { return nil }, nil
	}
	marker := filepath.Join(src, sourceBuildMarker)
	f, err := os.OpenFile(marker, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	err = f.Sync()
	closeErr := f.Close()
	if err != nil {
		return nil, err
	}
	if closeErr != nil {
		return nil, closeErr
	}
	return func(runErr error) error {
		if ctx.Err() != nil || (runErr != nil && (k.GitDir == "" || k.BaseTag == "")) {
			return nil // 중단되거나 대조 근거가 없는 실패는 표식을 남겨 다음번에 다시 추출
		}
		if err := b.verifySourceTree(ctx, k, src); err != nil {
			return fmt.Errorf("빌드 뒤 소스 복구 확인 실패 (캐시 재준비 필요): %w", err)
		}
		return os.Remove(marker)
	}, nil
}

// 같은 작업 디렉터리의 두 프로세스가 활성 소스·캐시를 함께 지우거나 바꾸지 못하게 합니다.
func (b *Builder) lockBuild() (*os.File, error) {
	if err := os.MkdirAll(b.cfg.WorkDir, 0o750); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(b.cfg.WorkDir, ".build.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, errBuildBusy
		}
		return nil, fmt.Errorf("다른 빌드가 작업 디렉터리를 사용 중입니다: %w", err)
	}
	return f, nil
}

// Shared with the disposable helper. A dedicated build account runs only one
// kernel build at a time, even if separate instances use different work dirs.
func lockUserBuild() (*os.File, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(home, ".local", "state", "kpctl-build-environment")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, "kernel-build.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, errBuildBusy
		}
		return nil, fmt.Errorf("같은 빌드 계정의 다른 커널 빌드가 진행 중입니다: %w", err)
	}
	return f, nil
}
