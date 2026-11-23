// 이 파일: builder 패키지의 resolvePatchSet, Error, validatePatchSet 구현·자료형.
package builder

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"kpctl/internal/model"
)

// 선행 커밋 해결 (prerequisite resolution)
//
// CVE 수정 커밋은 기준 태그(base)와 최신 태그 사이 어딘가에 있고, 그 사이의 다른 커밋에 기대는 일이 많습니다.
// 커밋 하나만 떼어 기준 커널 소스에 올리면 이런 식으로 깨집니다.
//
//	net/rxrpc/conn_event.c:257: error: 'rxrpc_skb_put_response_copy' undeclared
//	  → 이 enum 값은 CVE 커밋보다 먼저 들어간 다른 커밋이 include/trace/events/rxrpc.h 에 추가한 것
//
// 빌드 환경(샌드박스, 컴파일러, 설정)을 아무리 맞춰도 고쳐지지 않습니다. 소스에 선언이 없기 때문입니다.
// 그래서 빌드를 시작하기 전에 git 만으로(몇 초) 다음을 확인하고, 필요한 커밋을 묶음에 넣습니다.
//
//  1. 기호 검사: 커밋이 새로 쓰는 식별자 중 "기준 태그에는 없고 커밋 직전(sha^)에는 있는 것"
//     → 그 사이의 어느 커밋이 추가한 것이므로, 추가한 커밋을 찾아 선행 커밋으로 넣음
//  2. 적용 검사: 임시 인덱스에 기준 태그를 올리고 묶음을 순서대로 git apply
//     → 실패한 파일을 base..sha^ 에서 건드린 커밋을 선행 커밋으로 넣음
//
// 새로 넣은 선행 커밋에도 같은 검사를 반복합니다. 묶음이 한도를 넘으면 라이브패치 대상이 아니라고
// 판단합니다(그 CVE 는 재부팅/커널 점프로 해결).

// maxPrereqDefault 는 CVE 커밋 하나에 딸려 들어갈 수 있는 선행 커밋 수 한도입니다.
const maxPrereqDefault = 12

// patchSet 은 CVE 커밋 하나를 기준 커널에 올리는 데 필요한 커밋 묶음입니다.
type patchSet struct {
	Commits             []string // 오래된 것부터. 마지막이 CVE 커밋
	Content             string   // format-patch 를 순서대로 이어 붙인 것 (mbox)
	Notes               []string // 선행 커밋을 넣은 이유 (로그용)
	ActivePrerequisites bool     // 독립 활성 CVE 본문을 시험에 함께 전달해야 함
}

// resolvePatchSet 은 sha 를 base 위에 올리는 데 필요한 커밋을 찾아 묶음을 만듭니다.
// latest 는 수집 상한 태그입니다. sha 뒤에 온 보완 커밋은 sha..latest 에서만 찾습니다 ("" 이면 찾지 않음).
func resolvePatchSet(dir, base, latest, sha string, maxPrereqs int) (*patchSet, error) {
	if maxPrereqs <= 0 {
		maxPrereqs = maxPrereqDefault
	}
	tip := latest
	if tip == "" {
		tip = sha
	}
	out, err := git(dir, "rev-list", "--reverse", base+".."+tip)
	if err != nil {
		return nil, err
	}
	pos := map[string]int{}
	for i, c := range lines(out) {
		pos[c] = i
	}
	if _, ok := pos[sha]; !ok {
		return nil, fmt.Errorf("%s 는 %s..%s 사이 커밋이 아닙니다", shortSHA(sha), base, tip)
	}

	ps := &patchSet{}
	in := map[string]bool{sha: true}
	symChecked := map[string]bool{}
	add := func(c, why string) bool {
		if in[c] {
			return false
		}
		if _, ok := pos[c]; !ok {
			return false // base 이전 커밋은 이미 기준 소스에 들어 있음
		}
		in[c] = true
		ps.Notes = append(ps.Notes, fmt.Sprintf("%s ← %s", shortSHA(c), why))
		return true
	}
	ordered := func() []string {
		var cs []string
		for c := range in {
			cs = append(cs, c)
		}
		sort.Slice(cs, func(i, j int) bool { return pos[cs[i]] < pos[cs[j]] })
		return cs
	}

	for {
		changed := false

		// 1) 기호 검사
		for _, c := range ordered() {
			if symChecked[c] {
				continue
			}
			symChecked[c] = true
			deps, err := missingSymbolDeps(dir, base, latest, c)
			if err != nil {
				return nil, err
			}
			for _, d := range deps {
				why := fmt.Sprintf("%s 가 쓰는 '%s' 를 추가한 커밋", shortSHA(c), d.Symbol)
				if d.Later {
					why = fmt.Sprintf("%s 가 쓰는 '%s' 의 정의를 나중에 추가한 보완 커밋", shortSHA(c), d.Symbol)
				}
				if add(d.Commit, why) {
					changed = true
				}
			}
		}

		// 2) 적용 검사
		if !changed {
			failed, files, applyErr, err := applyCheck(dir, base, ordered())
			if err != nil {
				return nil, err
			}
			if failed != "" {
				args := []string{"log", "--format=%H", base + ".." + failed + "^", "--"}
				args = append(args, files...)
				out, err := git(dir, args...)
				if err != nil {
					return nil, err
				}
				for _, c := range lines(out) {
					if add(c, fmt.Sprintf("%s 보다 먼저 %s 를 고친 커밋", shortSHA(failed), strings.Join(files, ", "))) {
						changed = true
					}
				}
				if !changed {
					return nil, &unresolvedError{fmt.Sprintf("%s 를 %s 소스에 적용할 수 없습니다 (선행 커밋을 찾지 못함): %s", shortSHA(failed), base, applyErr)}
				}
			}
		}

		if n := len(in) - 1; n > maxPrereqs {
			return nil, &unresolvedError{fmt.Sprintf("선행 커밋이 %d개 필요해 한도(%d)를 넘습니다 — 기준 커널에서 너무 멀어 라이브패치로 만들지 않습니다\n%s",
				n, maxPrereqs, strings.Join(ps.Notes, "\n"))}
		}
		if !changed {
			break
		}
	}

	ps.Commits = ordered()
	var sb strings.Builder
	for _, c := range ps.Commits {
		p, err := git(dir, "format-patch", "-1", "--stdout", c)
		if err != nil {
			return nil, err
		}
		sb.WriteString(p)
		if !strings.HasSuffix(p, "\n") {
			sb.WriteString("\n")
		}
	}
	ps.Content = sb.String()
	return ps, nil
}

// unresolvedError 는 "git 은 정상인데 이 커밋은 기준 커널에 올릴 수 없다"는 판정입니다.
// (git 실행 오류와 구분: 판정은 라이브패치 불가로 기록하고, 실행 오류는 다음 주기에 다시 시도)
type unresolvedError struct{ msg string }

func (e *unresolvedError) Error() string { return e.msg }

// 자동으로 끌어온 선행·보완 커밋에도 수집 후보와 같은 검토 규칙을 적용합니다.
// 이미 비활성·불가·관리자 제외로 처리한 커밋을 의존성이라는 이유로 되살리지 않습니다.
func validatePatchSet(dir string, ps *patchSet, inactive map[string]bool) error {
	for _, sha := range ps.Commits {
		if inactive[sha] {
			return &unresolvedError{fmt.Sprintf("선행·보완 커밋 %s 은 비활성 또는 제외된 커밋이라 자동으로 포함하지 않습니다", shortSHA(sha))}
		}
		message, err := git(dir, "log", "-1", "--format=%B", sha)
		if err != nil {
			return err
		}
		if isRevertCommit(message) {
			return &unresolvedError{fmt.Sprintf("선행·보완 커밋 %s 은 되돌리기 커밋이라 관리자 검토가 필요합니다", shortSHA(sha))}
		}
	}
	return nil
}

// CVE 수정은 독립적인 승인·비활성화 단위로 남깁니다. 아직 활성화되지 않은 CVE를
// 다른 수정의 본문에 숨겨 넣지 않고, 활성 CVE도 원래 Git 본문을 복사하지 않습니다.
// 활성 수정은 trialBuildPatches가 컨트롤러에서 받은 실제 본문으로 따로 전달합니다.
func independentPatchSet(dir string, ps *patchSet, main, raw string, active []model.DiscoveredPatch) (*patchSet, error) {
	available := map[string]bool{}
	for _, patch := range active {
		available[patch.Commit] = true
	}
	filtered := &patchSet{Notes: append([]string(nil), ps.Notes...)}
	for _, sha := range ps.Commits {
		if sha != main {
			message, err := git(dir, "log", "-1", "--format=%B", sha)
			if err != nil {
				return nil, err
			}
			if len(extractCVEs(message)) > 0 {
				if !available[sha] {
					return nil, &unresolvedError{fmt.Sprintf("선행·보완 커밋 %s 은 아직 활성 패치가 아닌 CVE 수정이라 관리자 검토가 필요합니다", shortSHA(sha))}
				}
				filtered.ActivePrerequisites = true
				continue
			}
		}
		filtered.Commits = append(filtered.Commits, sha)
	}
	if len(filtered.Commits) == 1 && filtered.Commits[0] == main {
		filtered.Content = raw
		return filtered, nil
	}
	if len(filtered.Commits) == len(ps.Commits) {
		filtered.Content = ps.Content
		return filtered, nil
	}
	var content strings.Builder
	for _, sha := range filtered.Commits {
		patch, err := git(dir, "format-patch", "-1", "--stdout", sha)
		if err != nil {
			return nil, err
		}
		content.WriteString(patch)
		if !strings.HasSuffix(patch, "\n") {
			content.WriteByte('\n')
		}
	}
	filtered.Content = content.String()
	return filtered, nil
}

type symbolDep struct {
	Symbol, Commit string
	Later          bool // 커밋보다 뒤에 온 보완 커밋 (정의가 나중에 들어옴)
}

var (
	identRe   = regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]{3,}`)
	stringRe  = regexp.MustCompile(`"(?:[^"\\]|\\.)*"`)
	commentRe = regexp.MustCompile(`/\*.*?\*/|//.*$`)
)

// missingSymbolDeps 는 커밋 c 가 새로 쓰는 식별자 중 기준 소스에 없는 것을 찾아, 그 식별자를 넣은 커밋을 돌려줍니다.
//
//   - base 에는 없고 c^ 에는 있음 → base..c^ 사이의 커밋이 추가함 (선행 커밋)
//   - c 가 처음 쓰는데 c 시점 어느 헤더에도 없고, 뒤의 커밋(c..latest)이 헤더에 추가함 → 보완 커밋.
//     Ubuntu 가 수정과 그 선언을 두 커밋으로 나눠 넣은 경우로, c 시점 트리는 그 파일이 컴파일되지 않습니다.
//     (실제 사례: 14c36133bd24 가 쓰는 rxrpc_skb_put_response_copy 를 뒤의 7b6136bb17fc 가 정의)
func missingSymbolDeps(dir, base, latest, c string) ([]symbolDep, error) {
	diff, err := git(dir, "show", "--format=", "--unified=0", c, "--", "*.c", "*.h", "*.S")
	if err != nil {
		return nil, err
	}
	added, old := map[string]bool{}, map[string]bool{}
	var addedCode []string
	for _, l := range strings.Split(diff, "\n") {
		switch {
		case strings.HasPrefix(l, "+++"), strings.HasPrefix(l, "---"):
		case strings.HasPrefix(l, "+"):
			code := strings.TrimSpace(l[1:])
			if strings.HasPrefix(code, "*") || strings.HasPrefix(code, "/*") {
				continue // 주석 줄
			}
			code = commentRe.ReplaceAllString(stringRe.ReplaceAllString(code, `""`), "")
			addedCode = append(addedCode, code)
			for _, t := range identRe.FindAllString(code, -1) {
				added[t] = true
			}
		case strings.HasPrefix(l, "-"):
			for _, t := range identRe.FindAllString(l[1:], -1) {
				old[t] = true
			}
		}
	}

	// 고치는 파일의 기준 버전에 이미 있는 식별자는 볼 필요 없음 (git grep 횟수를 줄임)
	files, err := git(dir, "diff-tree", "--no-commit-id", "--name-only", "-r", c)
	if err != nil {
		return nil, err
	}
	var baseText strings.Builder
	for _, f := range lines(files) {
		if txt, err := git(dir, "show", base+":"+f); err == nil {
			baseText.WriteString(txt)
		}
	}
	inBaseFiles := map[string]bool{}
	for _, t := range identRe.FindAllString(baseText.String(), -1) {
		inBaseFiles[t] = true
	}

	var cands []string
	for t := range added {
		if !old[t] && !inBaseFiles[t] && !cKeywords[t] {
			cands = append(cands, t)
		}
	}
	sort.Strings(cands)

	var deps []symbolDep
	for _, t := range cands {
		if treeHasWord(dir, base, t) {
			continue // 기준 소스에 있음
		}
		if !treeHasWord(dir, c+"^", t) {
			// 이 커밋이 처음 쓰는 이름. 스스로 선언한 것(지역 변수, 새 함수 등)이면 끝.
			// 선언 없이 쓰기만 하고 헤더 정의가 뒤의 커밋에 있으면 그 커밋이 필요합니다.
			if latest == "" || declaredInCode(addedCode, t) || treeHasWord(dir, c, t, "*.h") || !treeHasWord(dir, latest, t, "*.h") {
				continue
			}
			out, err := git(dir, "log", "--reverse", "--format=%H", "--pickaxe-regex", `-S\b`+t+`\b`, c+".."+latest, "--", "*.h")
			if err != nil {
				return nil, err
			}
			if ls := lines(out); len(ls) > 0 {
				deps = append(deps, symbolDep{Symbol: t, Commit: ls[0], Later: true})
			}
			continue
		}
		// base..c^ 사이에서 이 식별자를 처음 넣은 커밋
		out, err := git(dir, "log", "--reverse", "--format=%H", "--pickaxe-regex", `-S\b`+t+`\b`, base+".."+c+"^")
		if err != nil {
			return nil, err
		}
		if ls := lines(out); len(ls) > 0 {
			deps = append(deps, symbolDep{Symbol: t, Commit: ls[0]})
		}
	}
	return deps, nil
}

// treeHasWord 는 tree 의 소스(paths 를 주면 그 경로만)에 word 가 단어 단위로 있는지 봅니다.
func treeHasWord(dir, tree, word string, paths ...string) bool {
	args := append([]string{"-C", dir, "grep", "-q", "-w", "-F", "-e", word, tree, "--"}, paths...)
	return exec.Command("git", args...).Run() == nil
}

// cKeywords 는 기호가 아닌 C 예약어·기본 자료형입니다 (식별자 정규식이 4글자 이상만 보므로 그 범위만).
var cKeywords = func() map[string]bool {
	m := map[string]bool{}
	for _, w := range strings.Fields(`auto break case char const continue default double else enum extern float goto
		inline long register restrict return short signed sizeof static struct switch typedef typeof union unsigned
		void volatile while bool true false NULL define ifdef ifndef endif elif include undef defined pragma
		__always_inline noinline __init __exit __user __must_check __maybe_unused likely unlikely`) {
		m[w] = true
	}
	return m
}()

var notTypeWords = map[string]bool{"return": true, "goto": true, "case": true, "else": true, "sizeof": true, "typeof": true, "do": true}

// declaredInCode 는 추가된 코드 줄에서 word 가 선언·정의되는 모양으로 나오는지 봅니다.
// (자료형 뒤의 이름, #define, 레이블, enum 항목). 정확한 구문 분석이 아니라 보수적인 추정입니다:
// 선언으로 보이면 "스스로 만든 이름"으로 치고 보완 커밋을 찾지 않습니다.
func declaredInCode(code []string, word string) bool {
	q := regexp.QuoteMeta(word)
	decl := regexp.MustCompile(`(?:^|[^A-Za-z0-9_])([A-Za-z_][A-Za-z0-9_]*)\s*\**\s+\**\s*` + q + `\s*(?:=[^=]|;|,|\)|\(|\[|$)`)
	ptr := regexp.MustCompile(`(?:^|[^A-Za-z0-9_])([A-Za-z_][A-Za-z0-9_]*)\s*\*+\s*` + q + `\s*(?:=[^=]|;|,|\)|\(|\[|$)`)
	own := regexp.MustCompile(`^(?:#\s*define\s+` + q + `\b|` + q + `\s*(?::[^:]?|,|=[^=])|` + q + `\s*$)`)
	for _, l := range code {
		if own.MatchString(l) {
			return true
		}
		for _, re := range []*regexp.Regexp{decl, ptr} {
			for _, m := range re.FindAllStringSubmatch(l, -1) {
				if !notTypeWords[m[1]] {
					return true
				}
			}
		}
	}
	return false
}

var applyFileRe = regexp.MustCompile(`(?m)^error: (?:patch failed: )?([^:\s]+):`)

// applyCheck 는 임시 인덱스에 base 를 올리고 commits 를 순서대로 적용해 봅니다 (작업 트리는 건드리지 않음).
// 적용에 실패한 첫 커밋과 문제가 된 파일들을 돌려줍니다. 모두 적용되면 failed 는 "".
func applyCheck(dir, base string, commits []string) (failed string, files []string, applyErr string, err error) {
	tmp, err := os.CreateTemp("", "kpctl-index-*")
	if err != nil {
		return "", nil, "", err
	}
	tmp.Close()
	os.Remove(tmp.Name()) // git 이 새로 만들게 함
	defer os.Remove(tmp.Name())
	defer os.Remove(tmp.Name() + ".lock")
	env := append(os.Environ(), "GIT_INDEX_FILE="+tmp.Name(), "GIT_OPTIONAL_LOCKS=0", "LC_ALL=C", "LANGUAGE=C")

	run := func(stdin string, args ...string) (string, error) {
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = env
		if stdin != "" {
			cmd.Stdin = strings.NewReader(stdin)
		}
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			return stderr.String(), err
		}
		return string(out), nil
	}

	if msg, err := run("", "read-tree", base); err != nil {
		return "", nil, "", fmt.Errorf("git read-tree %s 실패: %v %s", base, err, strings.TrimSpace(msg))
	}
	for _, c := range commits {
		patch, err := git(dir, "format-patch", "-1", "--stdout", c)
		if err != nil {
			return "", nil, "", err
		}
		msg, err := run(patch, "apply", "--cached", "-")
		if err == nil {
			continue
		}
		seen := map[string]bool{}
		for _, m := range applyFileRe.FindAllStringSubmatch(msg, -1) {
			if !seen[m[1]] {
				seen[m[1]] = true
				files = append(files, m[1])
			}
		}
		if len(files) == 0 { // 메시지를 못 읽으면 커밋이 건드린 파일 전부
			out, err := git(dir, "diff-tree", "--no-commit-id", "--name-only", "-r", c)
			if err != nil {
				return "", nil, "", err
			}
			files = lines(out)
		}
		return c, files, strings.TrimSpace(msg), nil
	}
	return "", nil, "", nil
}

// ─────────────────────────────────────────────
// 누적 빌드: 묶음 풀기 · 중복 제거 · 순서 맞추기
// ─────────────────────────────────────────────

// patchUnit 은 실제로 적용할 패치 하나입니다 (커밋 하나, 또는 수동 제출 패치 하나).
type patchUnit struct {
	Label   string // 파일 이름에 쓸 표시 (패치 ID)
	Commit  string // format-patch 머리에서 읽은 커밋 해시. 수동 패치는 ""
	Content string
}

var mboxFromRe = regexp.MustCompile(`(?m)^From ([0-9a-f]{40}) Mon Sep 17 00:00:00 2001$`)

// splitPatchSet 은 format-patch 를 이어 붙인 본문을 커밋 단위로 나눕니다.
// format-patch 형식이 아니면(수동 제출 패치) 통째로 하나로 둡니다.
func splitPatchSet(label, content string) []patchUnit {
	idx := mboxFromRe.FindAllStringSubmatchIndex(content, -1)
	if len(idx) == 0 || idx[0][0] != 0 {
		return []patchUnit{{Label: label, Content: content}}
	}
	var units []patchUnit
	for i, m := range idx {
		end := len(content)
		if i+1 < len(idx) {
			end = idx[i+1][0]
		}
		units = append(units, patchUnit{Label: label, Commit: content[m[2]:m[3]], Content: content[m[0]:end]})
	}
	return units
}

// flattenPatches 는 누적 빌드에 들어갈 패치들을 커밋 단위로 풀고, 여러 패치가 같은 선행 커밋을
// 들고 있으면 한 번만 남기고, 커밋들을 git 이력 순서로 맞춥니다.
//
// 순서를 맞추는 이유: 패치 B 의 선행 커밋 P 가 먼저 등록된 패치 A 보다 이력상 앞일 수 있습니다.
// 등록 순서(A, P, B)대로 적용하면 같은 파일을 고칠 때 깨질 수 있어, 원래 이력 순서(P, A, B)로 적용합니다.
// 수동 제출 패치는 원래 자리에 그대로 둡니다. gitDir 이 비었거나 커밋을 모르면 순서는 바꾸지 않습니다.
func flattenPatches(gitDir string, labels, contents []string) []patchUnit {
	var units []patchUnit
	seen := map[string]bool{}
	for i, c := range contents {
		for _, u := range splitPatchSet(labels[i], c) {
			if u.Commit != "" {
				if seen[u.Commit] {
					continue
				}
				seen[u.Commit] = true
			}
			units = append(units, u)
		}
	}
	if gitDir == "" {
		return units
	}

	var slots []int
	var commits []patchUnit
	for i, u := range units {
		if u.Commit != "" {
			slots = append(slots, i)
			commits = append(commits, u)
		}
	}
	if len(commits) < 2 {
		return units
	}
	depth := map[string]int{}
	for _, u := range commits {
		// 조상 커밋 수: 한 줄기 이력에서는 뒤에 온 커밋일수록 큼
		out, err := git(gitDir, "rev-list", "--count", u.Commit)
		if err != nil {
			return units // 이 git 에 없는 커밋이 섞임 → 등록 순서 유지
		}
		var n int
		fmt.Sscanf(strings.TrimSpace(out), "%d", &n)
		depth[u.Commit] = n
	}
	sort.SliceStable(commits, func(i, j int) bool { return depth[commits[i].Commit] < depth[commits[j].Commit] })
	for i, s := range slots {
		units[s] = commits[i]
	}
	return units
}

// writePatchUnits 는 패치를 적용 순서가 보이게 저장합니다: 001-p0003-<커밋>.patch, 002-p0007.patch ...
func writePatchUnits(dir string, units []patchUnit) ([]string, error) {
	var files []string
	for i, u := range units {
		name := fmt.Sprintf("%03d-%s", i+1, u.Label)
		if u.Commit != "" {
			name += "-" + shortSHA(u.Commit)
		}
		f := filepath.Join(dir, name+".patch")
		if err := os.WriteFile(f, []byte(u.Content), 0o640); err != nil {
			return nil, err
		}
		files = append(files, f)
	}
	return files, nil
}

func shortSHA(sha string) string {
	if len(sha) > 12 {
		return sha[:12]
	}
	return sha
}
