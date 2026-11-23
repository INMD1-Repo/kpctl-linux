// 이 파일: builder 패키지의 cumulativeKLPPatches 구현·자료형.
package builder

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// cumulativeKLPPatches keeps dependent changes in one native-tool input.
// klp-build's fix_patches refreshes each input against the original tree, so
// a later patch which needs an earlier one fails even after validate_patches.
// Apply only the selected inputs, in order, to a private Git index. Neither
// the source tree nor the repository's checkout/index is modified.
func (b *Builder) cumulativeKLPPatches(ctx context.Context, k KernelConfig, outDir string, patches []string) ([]string, error) {
	if len(patches) == 0 {
		return patches, nil
	}
	if k.GitDir == "" || k.BaseTag == "" {
		if len(patches) < 2 {
			return patches, nil
		}
		return nil, fmt.Errorf("native 누적 패치 준비에는 정확한 git_dir와 base_tag가 필요합니다")
	}
	tmp, err := os.MkdirTemp(b.cfg.WorkDir, "cumulative-index-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	git := func(args ...string) ([]byte, error) {
		cmd := exec.CommandContext(ctx, "git", append([]string{"-C", k.GitDir}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_INDEX_FILE="+filepath.Join(tmp, "index"), "GIT_OPTIONAL_LOCKS=0", "LC_ALL=C", "LANGUAGE=C")
		killProcessGroup(cmd)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return nil, fmt.Errorf("누적 diff git %s 실패: %w: %s", args[0], err, lastLines(string(out), 8))
		}
		return out, nil
	}
	base, err := git("rev-parse", "--verify", k.BaseTag+"^{commit}")
	if err != nil {
		return nil, err
	}
	baseID := strings.TrimSpace(string(base))
	if _, err := git("read-tree", baseID); err != nil {
		return nil, err
	}
	for i, patch := range patches {
		path, err := filepath.Abs(patch)
		if err != nil {
			return nil, err
		}
		if _, err := git("apply", "--cached", "--whitespace=nowarn", "--", path); err != nil {
			if len(patches) == 1 {
				return patches, nil // 패치 하나는 예전처럼 도구에 그대로 넘겨 도구가 판단하게 함
			}
			if patchApplyFailure(err.Error()) {
				return nil, fmt.Errorf("%w: 선택 패치 %d/%d (%s): %v", errPatchDependency, i+1, len(patches), filepath.Base(patch), err)
			}
			return nil, fmt.Errorf("선택 패치 %d/%d (%s): %w", i+1, len(patches), filepath.Base(patch), err)
		}
	}
	// 변경이 여러 줄 매크로 중간에서 끝나면 klp-build 의 #line 보정이 매크로를 깨뜨립니다 (linefix.go).
	names, err := git("diff", "--cached", "--name-only", "--no-renames", "-z", baseID, "--")
	if err != nil {
		return nil, err
	}
	for _, name := range strings.Split(string(names), "\x00") {
		if ext := filepath.Ext(name); ext != ".c" && ext != ".h" {
			continue
		}
		u0, err := git("diff", "--cached", "-U0", "--no-ext-diff", "--no-textconv", "--no-renames", "--no-color", baseID, "--", name)
		if err != nil {
			return nil, err
		}
		entry, err := git("ls-files", "-s", "--", name)
		if err != nil {
			return nil, err
		}
		fields := strings.Fields(string(entry))
		if len(fields) < 2 { // 삭제된 파일
			continue
		}
		body, err := git("cat-file", "blob", fields[1])
		if err != nil {
			return nil, err
		}
		fixed, changed, ok := extendMacroChanges(string(body), changeGroupEnds(string(u0)))
		if !ok {
			log.Printf("[%s] %s: 여러 줄 매크로 안의 변경을 안전하게 넓히지 못했습니다 (줄을 넘는 문자열). 그대로 진행합니다", k.Kernel, name)
			continue
		}
		if !changed {
			continue
		}
		blobFile := filepath.Join(tmp, "blob")
		if err := os.WriteFile(blobFile, []byte(fixed), 0o600); err != nil {
			return nil, err
		}
		id, err := git("hash-object", "-w", "--", blobFile)
		if err != nil {
			return nil, err
		}
		if _, err := git("update-index", "--cacheinfo", fields[0]+","+strings.TrimSpace(string(id))+","+name); err != nil {
			return nil, err
		}
		log.Printf("[%s] %s: 변경이 여러 줄 매크로 중간에서 끝나 매크로 끝까지 공백을 맞춤 (klp-build #line 보정 대응)", k.Kernel, name)
	}
	diff, err := git("diff", "--cached", "--binary", "--full-index", "--no-ext-diff", "--no-textconv", "--no-renames", "--no-color", "--src-prefix=a/", "--dst-prefix=b/", baseID, "--")
	if err != nil {
		return nil, err
	}
	if len(diff) == 0 {
		return nil, fmt.Errorf("선택 패치의 최종 누적 diff가 비어 있습니다")
	}
	path, err := filepath.Abs(filepath.Join(outDir, "cumulative.patch"))
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, diff, 0o640); err != nil {
		return nil, err
	}
	return []string{path}, nil
}
