// 이 파일: builder 패키지의 selectAdaptation, verifiedContent 구현·자료형.
package builder

import (
	_ "embed"
	"fmt"
	"runtime"
	"strings"
)

// Reviewed per-CVE source adaptation; no ABI check is bypassed.
//
//go:embed adaptations/cve-2026-43198-6.8.0-136.patch
var tcpMappedChildPatch string

//go:embed adaptations/cve-2026-53359-6.8.0-136.patch
var kvmChildRolePatch string

type patchAdaptation struct {
	commit, kernel, baseTag, baseCommit, patch, name, label string
}

func selectAdaptation(k KernelConfig, commit string) *patchAdaptation {
	if runtime.GOARCH != "amd64" {
		return nil
	}
	for _, a := range []patchAdaptation{{
		commit:     "25e02a1564bb0cd0cb9fc926e9ddde4ece8ce800",
		kernel:     "6.8.0-136-generic",
		baseTag:    "Ubuntu-6.8.0-136.136",
		baseCommit: "9e2939f04a28bd00cfbd4a1643fc99e75667a8b7",
		patch:      tcpMappedChildPatch,
		name:       "CVE-2026-43198 TCP callback ABI 보존",
		label:      "kpctl ABI 보존 수정",
	}, {
		commit:     "8c3fb26c9d258976db78d7fe1e4a996e22770373",
		kernel:     "6.8.0-136-generic",
		baseTag:    "Ubuntu-6.8.0-136.136",
		baseCommit: "9e2939f04a28bd00cfbd4a1643fc99e75667a8b7",
		patch:      kvmChildRolePatch,
		name:       "CVE-2026-53359 KVM MMU 소스 위치 보존",
		label:      "kpctl 소스 위치 보존 수정",
	}} {
		if commit == a.commit && k.Kernel == a.kernel && k.BaseTag == a.baseTag {
			return &a
		}
	}
	return nil
}

func (a *patchAdaptation) verifiedContent(k KernelConfig) (string, error) {
	base, err := git(k.GitDir, "rev-parse", k.BaseTag+"^{commit}")
	if err != nil {
		return "", fmt.Errorf("%s 기준 소스 확인 실패: %w", a.name, err)
	}
	if strings.TrimSpace(base) != a.baseCommit {
		return "", fmt.Errorf("%s 기준 태그의 커밋이 검토한 소스와 다릅니다", a.name)
	}
	return a.patch, nil
}
