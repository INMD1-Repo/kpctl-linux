// 이 파일: builder 패키지의 TestKLPLineFixStaysOutsideMacros, TestExtendMacroChanges, TestSystemKLPLineFix 회귀 시험.
package builder

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// simulateFixPatchLines 는 klp-build 의 scripts/livepatch/fix-patch-lines 와 같은 규칙으로
// 패치에 "+#line N" 을 넣습니다: 변경 묶음 뒤 첫 문맥 줄 앞.
func simulateFixPatchLines(patch string) string {
	hunk := regexp.MustCompile(`^@@ -(\d+)(?:,(\d+))? \+\d+(?:,\d+)? @@`)
	var out []string
	inHunk, need, skip := false, false, false
	cur, last := 0, 0
	for _, l := range strings.Split(patch, "\n") {
		switch {
		case strings.HasPrefix(l, "--- "):
			skip = !strings.HasSuffix(strings.Fields(l)[1], ".c") && !strings.HasSuffix(strings.Fields(l)[1], ".h")
		case strings.HasPrefix(l, "@@"):
			if m := hunk.FindStringSubmatch(l); m != nil && !skip {
				cur, _ = strconv.Atoi(m[1])
				n := 1
				if m[2] != "" {
					n, _ = strconv.Atoi(m[2])
				}
				last, inHunk, need = cur+n-1, true, false
			}
		case skip || !inHunk || strings.HasPrefix(l, `\ No newline`):
		case strings.HasPrefix(l, "+") || strings.HasPrefix(l, "-"):
			need = true
			if strings.HasPrefix(l, "-") {
				cur++
			}
		default:
			if need {
				out = append(out, "+#line "+strconv.Itoa(cur))
				need = false
			}
			if cur == last {
				inHunk = false
			}
			cur++
		}
		out = append(out, l)
	}
	return strings.Join(out, "\n")
}

// lineDirectiveInsideMacro 는 보정된 패치를 적용한 결과에서 #line 이 `\` 로 이어지는 줄 뒤에 있는지 봅니다.
func lineDirectiveInsideMacro(content string) bool {
	ls := strings.Split(content, "\n")
	for i, l := range ls {
		if strings.HasPrefix(l, "#line ") && i > 0 && strings.HasSuffix(strings.TrimRight(ls[i-1], " \t"), `\`) {
			return true
		}
	}
	return false
}

const traceHeaderBase = `#define rxrpc_call_poke_traces \
	E_(rxrpc_call_poke_timer_now,		"Timer-now")

#define rxrpc_skb_traces \
	EM(rxrpc_skb_eaten_by_unshare,		"ETN unshare  ") \
	EM(rxrpc_skb_eaten_by_unshare_nomem,	"ETN unshar-nm") \
	EM(rxrpc_skb_get_call_rx,		"GET call-rx  ") \
	EM(rxrpc_skb_get_conn_work,		"GET conn-work") \
	EM(rxrpc_skb_put_purge,			"PUT purge    ") \
	EM(rxrpc_skb_put_response,		"PUT response ") \
	EM(rxrpc_skb_put_rotate,		"PUT rotate   ") \
	EM(rxrpc_skb_see_reject,		"SEE reject   ") \
	EM(rxrpc_skb_see_rotate,		"SEE rotate   ") \
	E_(rxrpc_skb_see_version,		"SEE version  ")

#define rxrpc_local_traces \
	E_(rxrpc_local_free,			"FREE        ")

static inline int after(void)
{
	return __LINE__;
}
`

// 실제 실패(7b6136bb17fc): 여러 줄 매크로 가운데 세 군데를 고치는 헤더 변경.
func traceHeaderPatched() string {
	s := strings.Replace(traceHeaderBase, "\tEM(rxrpc_skb_eaten_by_unshare,\t\t\"ETN unshare  \") \\\n\tEM(rxrpc_skb_eaten_by_unshare_nomem,\t\"ETN unshar-nm\") \\\n", "", 1)
	s = strings.Replace(s, "\tEM(rxrpc_skb_put_rotate,", "\tEM(rxrpc_skb_put_response_copy,\t\t\"PUT resp-cpy \") \\\n\tEM(rxrpc_skb_put_rotate,", 1)
	s = strings.Replace(s, "\tE_(rxrpc_skb_see_version,", "\tEM(rxrpc_skb_see_unshare_nomem,\t\t\"SEE unshar-nm\") \\\n\tE_(rxrpc_skb_see_version,", 1)
	return s
}

func normalizeSpace(s string) string {
	return regexp.MustCompile(`[ \t]+`).ReplaceAllString(s, " ")
}

func TestKLPLineFixStaysOutsideMacros(t *testing.T) {
	repo := t.TempDir()
	hdr := filepath.Join(repo, "include", "trace.h")
	other := filepath.Join(repo, "net", "x.c")
	os.MkdirAll(filepath.Dir(hdr), 0o755)
	os.MkdirAll(filepath.Dir(other), 0o755)
	os.WriteFile(hdr, []byte(traceHeaderBase), 0o644)
	os.WriteFile(other, []byte("int x(void)\n{\n\treturn 1;\n}\n\nint y(void)\n{\n\treturn 2;\n}\n"), 0o644)
	run(t, repo, "init", "-q")
	run(t, repo, "add", ".")
	run(t, repo, "commit", "-qm", "base")
	run(t, repo, "tag", "Ubuntu-7.0.0-14.14")
	os.WriteFile(hdr, []byte(traceHeaderPatched()), 0o644)
	os.WriteFile(other, []byte("int x(void)\n{\n\tint a = 1;\n\n\treturn a;\n}\n\nint y(void)\n{\n\treturn 2;\n}\n"), 0o644)
	run(t, repo, "commit", "-qam", "fix")
	patch, err := git(repo, "format-patch", "-1", "--stdout", "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	in := filepath.Join(out, "in.patch")
	os.WriteFile(in, []byte(patch), 0o600)

	// 보정 없이는 실제로 깨지는 입력인지 먼저 확인 (시험 설정 검증)
	check := func(patchFile string) (string, string) {
		t.Helper()
		stage := t.TempDir()
		os.MkdirAll(filepath.Join(stage, "include"), 0o755)
		os.MkdirAll(filepath.Join(stage, "net"), 0o755)
		os.WriteFile(filepath.Join(stage, "include", "trace.h"), []byte(traceHeaderBase), 0o644)
		os.WriteFile(filepath.Join(stage, "net", "x.c"), []byte("int x(void)\n{\n\treturn 1;\n}\n\nint y(void)\n{\n\treturn 2;\n}\n"), 0o644)
		run(t, stage, "init", "-q")
		// klp-build 처럼: 적용 → 깨끗한 diff 로 다시 만들기 → #line 넣기 → 적용
		run(t, stage, "add", ".")
		run(t, stage, "commit", "-qm", "orig")
		run(t, stage, "apply", "--recount", patchFile)
		refreshed, err := git(stage, "diff")
		if err != nil {
			t.Fatal(err)
		}
		run(t, stage, "checkout", "-q", ".")
		fixed := filepath.Join(t.TempDir(), "fixed.patch")
		os.WriteFile(fixed, []byte(simulateFixPatchLines(refreshed)), 0o600)
		run(t, stage, "apply", "--recount", fixed)
		h, _ := os.ReadFile(filepath.Join(stage, "include", "trace.h"))
		c, _ := os.ReadFile(filepath.Join(stage, "net", "x.c"))
		return string(h), string(c)
	}
	if h, _ := check(in); !lineDirectiveInsideMacro(h) {
		t.Fatalf("보정 전 입력이 매크로를 깨뜨려야 시험이 의미 있음:\n%s", h)
	}

	b := &Builder{cfg: &Config{WorkDir: t.TempDir()}}
	k := KernelConfig{Kernel: "7.0.0-14-generic", GitDir: repo, BaseTag: "Ubuntu-7.0.0-14.14"}
	inputs, err := b.cumulativeKLPPatches(context.Background(), k, out, []string{in})
	if err != nil || len(inputs) != 1 || inputs[0] == in {
		t.Fatalf("패치 하나도 보정된 누적 diff 로 넘겨야 함: %v %v", inputs, err)
	}
	h, c := check(inputs[0])
	if lineDirectiveInsideMacro(h) {
		t.Fatalf("#line 이 여러 줄 매크로 안에 들어감:\n%s", h)
	}
	if !strings.Contains(h, "#line ") || !strings.Contains(c, "#line ") {
		t.Fatalf("줄 번호 보정 자체는 유지돼야 함:\n%s\n%s", h, c)
	}
	// 공백과 #line 을 빼면 원래 커밋 결과와 같아야 함
	strip := regexp.MustCompile(`(?m)^#line \d+\n`)
	if got := normalizeSpace(strip.ReplaceAllString(h, "")); got != normalizeSpace(traceHeaderPatched()) {
		t.Fatalf("헤더 내용이 달라짐:\n%s", got)
	}
	// 매크로 뒤 함수의 __LINE__ 이 원본과 같아야 함 (#line 이 매크로 끝난 뒤 올바른 번호로 들어감)
	origLine := lineOf(traceHeaderBase, "\treturn __LINE__;")
	if got := effectiveLineOf(h, "\treturn __LINE__;"); got != origLine {
		t.Fatalf("__LINE__ 보정이 어긋남: got %d want %d\n%s", got, origLine, h)
	}
}

func lineOf(content, line string) int {
	for i, l := range strings.Split(content, "\n") {
		if l == line {
			return i + 1
		}
	}
	return -1
}

// effectiveLineOf 는 #line 지시문을 반영한 줄 번호입니다.
func effectiveLineOf(content, line string) int {
	n := 0
	for _, l := range strings.Split(content, "\n") {
		if strings.HasPrefix(l, "#line ") {
			v, _ := strconv.Atoi(strings.TrimPrefix(l, "#line "))
			n = v - 1
			continue
		}
		n++
		if l == line {
			return n
		}
	}
	return -1
}

func TestExtendMacroChanges(t *testing.T) {
	// 매크로 밖의 변경은 건드리지 않음
	if _, changed, ok := extendMacroChanges("int a;\nint b;\n", []int{1}); changed || !ok {
		t.Fatal("매크로가 아닌 곳을 바꾸면 안 됨")
	}
	// 매크로 마지막 줄에서 끝난 변경도 그대로
	if _, changed, _ := extendMacroChanges("#define A \\\n\tx \\\n\ty\nint z;\n", []int{3}); changed {
		t.Fatal("매크로 끝에서 끝난 변경은 그대로 둬야 함")
	}
	got, changed, ok := extendMacroChanges("#define A \\\n\tx \\\n\ty \\\n\tz\nint w;\n", []int{2})
	if !changed || !ok || got != "#define A \\\n\tx \\\n\ty  \\\n\t\tz\nint w;\n" {
		t.Fatalf("매크로 끝까지 공백만 바꿔야 함: %q", got)
	}
	// 줄을 넘는 문자열은 손대지 않음
	if _, _, ok := extendMacroChanges("#define A \\\n\tx \\\n\t\"abc \\\n\tdef\"\n", []int{2}); ok {
		t.Fatal("줄을 넘는 문자열은 안전하지 않다고 알려야 함")
	}
	if unbalancedQuotes(`EM(a, "x \" y") \`) || unbalancedQuotes(`c = '"'; \`) || !unbalancedQuotes(`"abc \`) {
		t.Fatal("따옴표 판정")
	}
}

// 실제 커널 git·실제 패치·실제 fix-patch-lines 로 확인 (평소에는 건너뜀). 아무것도 빌드하지 않습니다.
//
//	KPCTL_SYSTEM_GIT=/srv/ubuntu-resolute KPCTL_SYSTEM_BASE=Ubuntu-7.0.0-14.14 \
//	KPCTL_SYSTEM_PATCHES=a.patch:b.patch KPCTL_SYSTEM_FIXLINES=/path/fix-patch-lines go test -run TestSystemKLPLineFix
func TestSystemKLPLineFix(t *testing.T) {
	paths := filepath.SplitList(os.Getenv("KPCTL_SYSTEM_PATCHES"))
	fixLines := os.Getenv("KPCTL_SYSTEM_FIXLINES")
	if len(paths) == 0 || fixLines == "" {
		t.Skip("KPCTL_SYSTEM_PATCHES, KPCTL_SYSTEM_FIXLINES 지정 시 실행")
	}
	k := KernelConfig{Kernel: "system", GitDir: os.Getenv("KPCTL_SYSTEM_GIT"), BaseTag: os.Getenv("KPCTL_SYSTEM_BASE")}
	b := &Builder{cfg: &Config{WorkDir: t.TempDir()}}
	for _, mode := range []string{"원본 그대로", "보정"} {
		input := paths
		if mode == "보정" {
			var err error
			if input, err = b.cumulativeKLPPatches(context.Background(), k, t.TempDir(), paths); err != nil {
				t.Fatal(err)
			}
		}
		stage := t.TempDir()
		run(t, stage, "init", "-q")
		// 패치가 건드리는 파일만 기준 태그에서 꺼냄
		seen := map[string]bool{}
		for _, p := range input {
			body, _ := os.ReadFile(p)
			for _, m := range regexp.MustCompile(`(?m)^\+\+\+ b/(\S+)`).FindAllStringSubmatch(string(body), -1) {
				if seen[m[1]] {
					continue
				}
				seen[m[1]] = true
				content, err := git(k.GitDir, "show", k.BaseTag+":"+m[1])
				if err != nil {
					continue // 새 파일
				}
				os.MkdirAll(filepath.Dir(filepath.Join(stage, m[1])), 0o755)
				os.WriteFile(filepath.Join(stage, m[1]), []byte(content), 0o644)
			}
		}
		run(t, stage, "add", ".")
		run(t, stage, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "orig")
		bad := 0
		for _, p := range input { // klp-build 의 fix_patches 와 같은 순서: 적용 → diff → #line → 적용
			run(t, stage, "apply", "--recount", p)
			refreshed, err := git(stage, "diff")
			if err != nil {
				t.Fatal(err)
			}
			run(t, stage, "checkout", "-q", ".")
			raw := filepath.Join(t.TempDir(), "refreshed.patch")
			os.WriteFile(raw, []byte(refreshed), 0o600)
			fixed, err := exec.Command(fixLines, raw).Output()
			if err != nil {
				t.Fatalf("fix-patch-lines: %v", err)
			}
			fp := filepath.Join(t.TempDir(), "fixed.patch")
			os.WriteFile(fp, fixed, 0o600)
			run(t, stage, "apply", "--recount", fp)
			for f := range seen {
				body, _ := os.ReadFile(filepath.Join(stage, f))
				if lineDirectiveInsideMacro(string(body)) {
					bad++
					t.Logf("[%s] #line 이 매크로 안에 들어감: %s", mode, f)
				}
			}
			run(t, stage, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qam", "applied")
		}
		t.Logf("[%s] 입력 %d개, 매크로가 깨진 파일 %d개", mode, len(input), bad)
		if mode == "보정" && bad != 0 {
			t.Fatal("보정 후에도 #line 이 매크로 안에 있음")
		}
	}
}
