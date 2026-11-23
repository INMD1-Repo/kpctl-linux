// 이 파일: builder 패키지의 klpToolsBroken, sourceMark, describe 구현·자료형.
package builder

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// 이 파일: klp-build 빌드 도구(objtool·klp-build)를 검증된 조합으로 바꾸기
//
// klp-build 와 objtool 은 패치 대상 커널 소스 안에 들어 있어서, 기준 태그가 오래되면
// 그 뒤에 고쳐진 도구 결함을 그대로 안고 빌드합니다. 예: Ubuntu-7.0.0-14 의 objtool 은
// 다른 모듈의 함수를 부르는 패치에서 klp 재배치 섹션 이름을 잘못 만들고, 그 모듈은 적재해도
// 재배치가 적용되지 않습니다 (klpcheck 가 거부).
//
// "같은 계열의 최신 태그 도구"를 그대로 쓸 수는 없습니다. Ubuntu-7.0.0-39.39i0 부터는
// klp-checksum.c 가 선언되지 않은 decode_file() 을 불러 objtool 의 klp 기능이 컴파일되지 않습니다.
// 그래서 계열마다 "온전한 마지막 태그 + 그 뒤의 필요한 수정 커밋"을 아래 표로 고정합니다.
// 커널 코드는 기준 태그 그대로 두고 klpToolPaths 만 바꿉니다.
type klpToolSet struct {
	TagGlob string   // KernelConfig.TagGlob 과 같은 계열
	Tag     string   // 도구를 가져올 태그
	Picks   []string // Tag 뒤의 커밋 중 추가로 적용할 것 (제목으로 찾음, 도구 경로의 변경만 순서대로 적용)
}

var klpToolSets = []klpToolSet{{
	TagGlob: "Ubuntu-7.0.0-*",
	Tag:     "Ubuntu-7.0.0-39.39",
	// 모두 "다른 모듈의 심볼을 쓰는 패치"의 klp 심볼·재배치 이름을 바로잡는 수정입니다 (이력 순서).
	Picks: []string{
		"objtool/klp: Fix module name normalization for paths with dots",
		"objtool/klp: Normalize Module.symvers paths to module names",
		"objtool/klp: Fix false module dependencies caused by dead relocs",
		"objtool/klp: Fix cross-module klp relocation section naming",
	},
}}

// 도구와, 그 도구가 넘겨받는 옵션·섹션을 정하는 빌드 스크립트입니다.
// 커널 코드(.c)는 scripts/mod/modpost.c(호스트 도구)뿐입니다.
var klpToolPaths = []string{
	"tools/objtool",
	"scripts/livepatch",
	"scripts/Makefile.lib",
	"scripts/Makefile.vmlinux_o",
	"scripts/mod/modpost.c",
	"scripts/module.lds.S",
	"include/asm-generic/vmlinux.lds.h",
}

// klpToolDirs 는 도구 자체만입니다 (기준이 도구 태그보다 새로울 때).
var klpToolDirs = []string{"tools/objtool", "scripts/livepatch"}

// klpToolsBroken 은 이 커밋의 objtool klp 기능이 컴파일되지 않는 알려진 상태인지 봅니다:
// klp-checksum.c 가 decode_file() 을 부르는데 그 선언이 어디에도 없음 (Ubuntu-7.0.0-39.39i0 ~ 44.44 에서 확인).
func klpToolsBroken(gitDir, commit string) bool {
	if _, err := git(gitDir, "cat-file", "-e", commit+":tools/objtool/klp-checksum.c"); err != nil {
		return false
	}
	if _, err := git(gitDir, "grep", "-q", "-E", `decode_file[[:space:]]*\(`, commit, "--", "tools/objtool/klp-checksum.c"); err != nil {
		return false // Ubuntu가 호출을 제거한 경우에도 고정 도구로 되돌리지 않습니다.
	}
	_, err := git(gitDir, "grep", "-q", "-w", "decode_file", commit, "--", "tools/objtool/include", "tools/objtool/check.c")
	return err != nil
}

type klpTools struct {
	Tag   string
	Picks []string // 추가 적용한 커밋
	Tree  string   // 기준 태그 + 도구를 합친 소스 트리 (git tree)
}

// sourceMark 는 준비된 소스 캐시가 어떤 기준·도구로 만들어졌는지 나타냅니다 (.kpctl-ready).
func sourceMark(baseTag string, tools *klpTools) string {
	if tools == nil {
		return baseTag
	}
	return baseTag + " tools=" + tools.Tree
}

func (t *klpTools) describe() string {
	text := fmt.Sprintf("빌드 도구(objtool·klp-build): %s", t.Tag)
	if len(t.Picks) > 0 {
		short := make([]string, len(t.Picks))
		for i, sha := range t.Picks {
			short[i] = shortSHA(sha)
		}
		text += fmt.Sprintf(" + 수정 %d건(%s)", len(t.Picks), strings.Join(short, " "))
	}
	return text + " · 커널 소스는 기준 태그 그대로"
}

// klpTools 는 이 커널 빌드에 쓸 도구를 정하고, 기준 태그에 그 도구를 합친 트리를 만듭니다.
// nil 이면 기준 태그의 도구를 그대로 씁니다. 저장소의 checkout·index 는 건드리지 않습니다.
// 격리 컨테이너 안에서도 같은 저장소(태그 포함)를 보므로 호스트와 같은 트리가 나옵니다.
func (b *Builder) klpTools(k KernelConfig) (*klpTools, error) {
	if k.GitDir == "" || k.BaseTag == "" || k.TagGlob == "" || b.cfg.buildTool(k.Kernel) != BuildToolKLP {
		return nil, nil
	}
	var set *klpToolSet
	for i := range klpToolSets {
		if klpToolSets[i].TagGlob == k.TagGlob {
			set = &klpToolSets[i]
		}
	}
	if set == nil {
		return nil, nil
	}
	base, err := git(k.GitDir, "rev-parse", "--verify", k.BaseTag+"^{commit}")
	if err != nil {
		return nil, err
	}
	base = strings.TrimSpace(base)
	tagCommit, err := git(k.GitDir, "rev-parse", "--verify", "refs/tags/"+set.Tag+"^{commit}")
	if err != nil {
		return nil, fmt.Errorf("빌드 도구 태그 %s 가 커널 git 에 없습니다 (git fetch --tags 확인): %w", set.Tag, err)
	}
	tagCommit = strings.TrimSpace(tagCommit)
	// 기준이 도구 태그보다 오래됐으면: 도구와 그에 맞는 빌드 스크립트를 도구 태그 것으로 올립니다.
	// 기준이 더 새로우면(커널 점프 뒤): 기준 태그의 도구가 컴파일되지 않을 때만 도구 디렉터리 두 개를
	// 도구 태그 것으로 내립니다. 빌드 스크립트는 기준 태그의 Kconfig 와 짝이므로 그대로 둡니다.
	// Ubuntu 가 도구를 고치면 이 교체는 저절로 멈춥니다.
	paths := klpToolPaths
	if _, err := git(k.GitDir, "merge-base", "--is-ancestor", base, tagCommit); err != nil {
		if _, err := git(k.GitDir, "merge-base", "--is-ancestor", tagCommit, base); err != nil {
			return nil, nil // 다른 갈래
		}
		if !klpToolsBroken(k.GitDir, base) {
			return nil, nil
		}
		paths = klpToolDirs
	}
	tools := &klpTools{Tag: set.Tag}
	for _, subject := range set.Picks {
		out, err := git(k.GitDir, append([]string{"log", "--format=%H %s", "--fixed-strings", "--grep=" + subject,
			"--tags=" + k.TagGlob, "--not", tagCommit, "--"}, klpToolPaths...)...)
		if err != nil {
			return nil, err
		}
		sha := ""
		for _, line := range lines(out) { // 최신순 → 같은 제목이 여럿이면 가장 오래된 것
			if id, title, ok := strings.Cut(line, " "); ok && title == subject {
				sha = id
			}
		}
		if sha == "" {
			return nil, fmt.Errorf("빌드 도구 수정 커밋을 찾지 못했습니다: %q (%s 뒤의 태그, git fetch --tags 확인)", subject, set.Tag)
		}
		tools.Picks = append(tools.Picks, sha)
	}

	tmp, err := os.MkdirTemp("", "kpctl-tools-index-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	run := func(input []byte, args ...string) ([]byte, error) {
		cmd := exec.Command("git", append([]string{"-C", k.GitDir}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_INDEX_FILE="+filepath.Join(tmp, "index"), "GIT_OPTIONAL_LOCKS=0", "LC_ALL=C", "LANGUAGE=C")
		cmd.Stdin = bytes.NewReader(input)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("빌드 도구 트리 git %s 실패: %v: %s", args[0], err, lastLines(stderr.String(), 5))
		}
		return out, nil
	}
	if _, err := run(nil, "read-tree", base); err != nil {
		return nil, err
	}
	old, err := run(nil, append([]string{"ls-files", "-z", "--"}, paths...)...)
	if err != nil {
		return nil, err
	}
	if _, err := run(old, "update-index", "-z", "--force-remove", "--stdin"); err != nil {
		return nil, err
	}
	entries, err := run(nil, append([]string{"ls-tree", "-r", "-z", tagCommit, "--"}, paths...)...)
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("빌드 도구 태그 %s 에 도구 경로가 없습니다", set.Tag)
	}
	if _, err := run(entries, "update-index", "-z", "--index-info"); err != nil {
		return nil, err
	}
	for _, sha := range tools.Picks {
		diff, err := run(nil, append([]string{"diff", "--no-ext-diff", "--no-textconv", "--no-renames", "--no-color", "--binary", sha + "^", sha, "--"}, paths...)...)
		if err != nil {
			return nil, err
		}
		if _, err := run(diff, "apply", "--cached", "--whitespace=nowarn", "-"); err != nil {
			return nil, fmt.Errorf("빌드 도구 수정 %s 를 %s 도구에 적용하지 못했습니다: %w", shortSHA(sha), set.Tag, err)
		}
	}
	tree, err := run(nil, "write-tree")
	if err != nil {
		return nil, err
	}
	tools.Tree = strings.TrimSpace(string(tree))
	return tools, nil
}
