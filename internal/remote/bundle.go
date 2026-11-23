// 이 파일: remote 패키지의 OpenBundle, Path, binaryArch 구현·자료형.
package remote

import (
	"debug/elf"
	"fmt"
	"os"
	"path/filepath"
)

// 설치 묶음(bundle) 디렉터리에 있어야 하는 파일들. make dist 가 dist/controller/agent/ 에 만들어 줍니다.
var bundleFiles = []string{
	"kpctl-agent",
	"install-agent.sh",
	"uninstall-agent.sh",
	"kpctl-agent.service",
	"reboot-hook.example.sh",
	"kpctl-prepare-kernel.py", // 에이전트가 /usr/local/sbin/kpctl-prepare-kernel 로 실행 (커널 점프 1단계)
	"mirrors.list",            // Ubuntu 미러 순서 (공식 → 한국 미러). 설치 전 점검도 이 목록을 씁니다
}

// bundleOptionalFiles 는 저장소에 kpatch 패키지가 없는 시리즈(24.04)용입니다. 있으면 함께 복사합니다.
var bundleOptionalFiles = []string{"kpatch", "kpatch.service"}

// Bundle 은 원격 호스트에 복사할 파일 묶음입니다.
type Bundle struct {
	Dir     string
	Arch    string // kpctl-agent 바이너리의 아키텍처 (uname -m 형식: x86_64, aarch64)
	Mirrors string // 검사를 마친 mirrors.list 내용 (설치 전 점검에 그대로 넘김)
}

// OpenBundle 은 묶음 디렉터리에 필요한 파일이 다 있는지 확인하고, 에이전트 바이너리의 아키텍처를 읽습니다.
func OpenBundle(dir string) (*Bundle, error) {
	for _, f := range bundleFiles {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			return nil, fmt.Errorf("설치 묶음 %s 에 %s 가 없습니다 (make dist 결과의 dist/controller/agent 를 지정하세요)", dir, f)
		}
	}
	arch, err := binaryArch(filepath.Join(dir, "kpctl-agent"))
	if err != nil {
		return nil, err
	}
	mirrors, err := os.ReadFile(filepath.Join(dir, "mirrors.list"))
	if err != nil {
		return nil, err
	}
	if _, err := ParseMirrors(string(mirrors)); err != nil {
		return nil, fmt.Errorf("설치 묶음 %s: %w", dir, err)
	}
	return &Bundle{Dir: dir, Arch: arch, Mirrors: string(mirrors)}, nil
}

// Path 는 묶음 안 파일의 전체 경로입니다.
func (b *Bundle) Path(name string) string { return filepath.Join(b.Dir, name) }

// binaryArch 는 ELF 실행 파일 헤더를 읽어 아키텍처를 uname -m 형식으로 돌려줍니다.
// (amd64 로 빌드한 에이전트를 arm 서버에 설치하는 실수를 막기 위해)
func binaryArch(path string) (string, error) {
	f, err := elf.Open(path)
	if err != nil {
		return "", fmt.Errorf("%s 은 리눅스 실행 파일이 아닙니다: %w", path, err)
	}
	defer f.Close()
	switch f.Machine {
	case elf.EM_X86_64:
		return "x86_64", nil
	case elf.EM_AARCH64:
		return "aarch64", nil
	default:
		return f.Machine.String(), nil
	}
}
