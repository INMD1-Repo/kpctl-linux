// 이 파일: builder 패키지의 TestResolvePatchSet, TestFlattenPatches, TestValidatePatchSetRejectsInactiveAndRevertedDependencies 회귀 시험.
package builder

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// prereqRepo 는 실제로 겪은 실패(rxrpc)를 흉내 낸 작은 커널 git 을 만듭니다.
//
//	base  : 기준 태그
//	P     : (CVE 아님) 헤더에 enum rxrpc_skb_put_response_copy 추가, output.c 에서 사용
//	U     : (CVE 아님) 관계없는 파일 수정
//	A     : CVE — other.c 수정 (선행 커밋 필요 없음)
//	C     : CVE — conn_event.c 가 P 의 enum 을 사용 (P 없이는 컴파일 불가)
//	Q     : (CVE 아님) conn_event.c 의 같은 줄을 고침
//	D     : CVE — Q 가 고친 줄을 다시 고침 (Q 없이는 적용 불가)
type prereqRepo struct {
	dir                          string
	base, latest                 string
	P, U, A, C, Q, D, E, F, G, H string
}

func newPrereqRepo(t *testing.T) *prereqRepo {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git 없음")
	}
	r := &prereqRepo{dir: t.TempDir(), base: "Ubuntu-7.0.0-14.14", latest: "Ubuntu-7.0.0-16.16"}
	run := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", r.dir}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	write := func(path, content string) {
		t.Helper()
		f := filepath.Join(r.dir, path)
		os.MkdirAll(filepath.Dir(f), 0o755)
		if err := os.WriteFile(f, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	commit := func(msg string) string {
		run("add", ".")
		run("commit", "-q", "-m", msg)
		return run("rev-parse", "HEAD")
	}
	const hdr = "enum rxrpc_skb_trace {\n\trxrpc_skb_put_response,\n%s};\n"
	conn := func(verify string) string {
		return "#include <trace/events/rxrpc.h>\n\nint rxrpc_verify_response(void *skb)\n{\n" + verify + "\treturn 0;\n}\n\n\n\n\nint tail(void)\n{\n\treturn 1;\n}\n"
	}

	run("init", "-q")
	write("include/trace/events/rxrpc.h", strings.Replace(hdr, "%s", "", 1))
	write("net/rxrpc/conn_event.c", conn("\trxrpc_free_skb(skb, rxrpc_skb_put_response);\n"))
	write("net/rxrpc/output.c", "int out(void)\n{\n\treturn 0;\n}\n")
	write("net/other.c", "int other = 1;\n")
	commit("base")
	run("tag", r.base)

	write("include/trace/events/rxrpc.h", strings.Replace(hdr, "%s", "\trxrpc_skb_put_response_copy,\n", 1))
	write("net/rxrpc/output.c", "int out(void)\n{\n\treturn rxrpc_skb_put_response_copy;\n}\n")
	r.P = commit("rxrpc: add response copy trace")

	write("docs.txt", "unrelated\n")
	r.U = commit("docs: unrelated")

	write("net/other.c", "int other = 2;\n")
	r.A = commit("net: fix other\n\nCVE-2026-00001")

	write("net/rxrpc/conn_event.c", conn("\tvoid *nskb = skb;\n\trxrpc_free_skb(nskb, rxrpc_skb_put_response_copy);\n"))
	r.C = commit("rxrpc: fix verify response\n\nCVE-2026-00002")

	write("net/rxrpc/conn_event.c", strings.Replace(conn("\tvoid *nskb = skb;\n\trxrpc_free_skb(nskb, rxrpc_skb_put_response_copy);\n"), "return 1;", "return 2;", 1))
	r.Q = commit("rxrpc: tail tweak")

	write("net/rxrpc/conn_event.c", strings.Replace(conn("\tvoid *nskb = skb;\n\trxrpc_free_skb(nskb, rxrpc_skb_put_response_copy);\n"), "return 1;", "return 3;", 1))
	r.D = commit("rxrpc: fix tail\n\nCVE-2026-00003")
	run("tag", "Ubuntu-7.0.0-15.15")

	// 실제 사례(14c36133bd24 → 7b6136bb17fc): CVE 커밋 E 가 쓰는 enum 을 "뒤의" 커밋 F 가 헤더에 정의.
	// E 는 지역 변수(tmp_local)와 새 함수(out_helper)도 만드는데, 이건 스스로 선언한 이름입니다.
	write("net/rxrpc/output.c", "static int out_helper(int v)\n{\n\treturn v;\n}\n\nint out(void)\n{\n\tint tmp_local = out_helper(rxrpc_skb_see_unshare_nomem);\n\n\treturn tmp_local + rxrpc_skb_put_response_copy;\n}\n")
	r.E = commit("rxrpc: fix output\n\nCVE-2026-00004")
	write("docs.txt", "unrelated\nmore: tmp_local out_helper\n")
	r.G = commit("docs: mentions names")
	write("include/trace/events/rxrpc.h", strings.Replace(hdr, "%s", "\trxrpc_skb_put_response_copy,\n\trxrpc_skb_see_unshare_nomem,\n", 1))
	r.F = commit("rxrpc: add unshare trace")
	write("include/linux/later.h", "static inline int later(void) { int tmp_local = 0; return tmp_local; }\n")
	r.H = commit("later: header reuses a local name")
	run("tag", r.latest)
	return r
}

func TestResolvePatchSet(t *testing.T) {
	r := newPrereqRepo(t)

	t.Run("선행 커밋이 필요 없는 커밋은 그대로", func(t *testing.T) {
		ps, err := resolvePatchSet(r.dir, r.base, r.latest, r.A, 0)
		if err != nil || len(ps.Commits) != 1 || ps.Commits[0] != r.A {
			t.Fatalf("got %+v err=%v", ps, err)
		}
	})

	// 실제 실패: 'rxrpc_skb_put_response_copy' undeclared.
	// 단독 패치는 git apply 로는 잘 적용되지만, 쓰는 enum 이 기준 소스에 없습니다.
	t.Run("기준 소스에 없는 기호를 추가한 커밋을 끌어옴", func(t *testing.T) {
		if failed, _, _, err := applyCheck(r.dir, r.base, []string{r.C}); err != nil || failed != "" {
			t.Fatalf("이 경우는 적용 검사만으로는 못 잡아야 함: failed=%q err=%v", failed, err)
		}
		ps, err := resolvePatchSet(r.dir, r.base, r.latest, r.C, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(ps.Commits) != 2 || ps.Commits[0] != r.P || ps.Commits[1] != r.C {
			t.Fatalf("P, C 순서여야 함: %v\n%v", ps.Commits, ps.Notes)
		}
		if !strings.Contains(strings.Join(ps.Notes, "\n"), "rxrpc_skb_put_response_copy") {
			t.Fatalf("이유에 기호 이름이 있어야 함: %v", ps.Notes)
		}
		// 묶음 전체가 기준 소스에 적용돼야 함
		if failed, _, msg, err := applyCheck(r.dir, r.base, ps.Commits); err != nil || failed != "" {
			t.Fatalf("묶음 적용 실패: %s %s %v", failed, msg, err)
		}
	})

	t.Run("같은 줄을 먼저 고친 커밋을 끌어옴", func(t *testing.T) {
		ps, err := resolvePatchSet(r.dir, r.base, r.latest, r.D, 0)
		if err != nil {
			t.Fatal(err)
		}
		want := []string{r.P, r.C, r.Q, r.D}
		if strings.Join(ps.Commits, ",") != strings.Join(want, ",") {
			t.Fatalf("got %v\nwant %v\n%v", ps.Commits, want, ps.Notes)
		}
		for _, c := range ps.Commits {
			if c == r.U || c == r.A {
				t.Fatal("관계없는 커밋이 들어감")
			}
		}
	})

	t.Run("정의를 나중에 추가한 보완 커밋을 끌어옴", func(t *testing.T) {
		ps, err := resolvePatchSet(r.dir, r.base, r.latest, r.E, 0)
		if err != nil {
			t.Fatal(err)
		}
		// P: E 가 쓰는 rxrpc_skb_put_response_copy (선행), F: rxrpc_skb_see_unshare_nomem (보완).
		// G(문서), H(지역 변수 이름을 우연히 쓰는 헤더)는 들어오면 안 됨.
		want := []string{r.P, r.E, r.F}
		if strings.Join(ps.Commits, ",") != strings.Join(want, ",") {
			t.Fatalf("got %v\nwant %v\n%v", ps.Commits, want, ps.Notes)
		}
		if failed, _, msg, err := applyCheck(r.dir, r.base, ps.Commits); err != nil || failed != "" {
			t.Fatalf("묶음 적용 실패: %s %s %v", failed, msg, err)
		}
		// 상한 태그를 모르면 뒤의 커밋은 찾지 않음
		ps, err = resolvePatchSet(r.dir, r.base, "", r.E, 0)
		if err != nil || len(ps.Commits) != 2 {
			t.Fatalf("got %+v err=%v", ps, err)
		}
	})

	t.Run("한도를 넘으면 판정 오류", func(t *testing.T) {
		_, err := resolvePatchSet(r.dir, r.base, r.latest, r.D, 1)
		var u *unresolvedError
		if !errors.As(err, &u) {
			t.Fatalf("unresolvedError 여야 함: %v", err)
		}
	})
}

// 누적 빌드: 묶음을 풀고, 겹치는 선행 커밋은 한 번만, git 이력 순서로.
func TestFlattenPatches(t *testing.T) {
	r := newPrereqRepo(t)
	var contents, labels []string
	for i, sha := range []string{r.A, r.C, r.D} { // 등록 순서
		ps, err := resolvePatchSet(r.dir, r.base, r.latest, sha, 0)
		if err != nil {
			t.Fatal(err)
		}
		contents = append(contents, ps.Content)
		labels = append(labels, []string{"p0001", "p0002", "p0003"}[i])
	}
	manual := "--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n+b\n"
	contents = append(contents, manual)
	labels = append(labels, "p0004")

	units := flattenPatches(r.dir, labels, contents)
	var got []string
	for _, u := range units {
		got = append(got, u.Commit)
	}
	want := []string{r.P, r.A, r.C, r.Q, r.D, ""} // P 는 A 보다 이력상 앞, 수동 패치는 제자리(끝)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("got  %v\nwant %v", got, want)
	}
	if units[5].Content != manual {
		t.Fatal("수동 패치 본문이 바뀜")
	}
	// 풀어 놓은 순서대로 기준 소스에 모두 적용돼야 함
	if failed, _, msg, err := applyCheck(r.dir, r.base, got[:5]); err != nil || failed != "" {
		t.Fatalf("누적 적용 실패: %s %s %v", failed, msg, err)
	}
	files, err := writePatchUnits(t.TempDir(), units)
	if err != nil || len(files) != 6 || !strings.Contains(filepath.Base(files[0]), "001-p0002-"+r.P[:12]) {
		t.Fatalf("files=%v err=%v", files, err)
	}
}

func TestValidatePatchSetRejectsInactiveAndRevertedDependencies(t *testing.T) {
	r := newPrereqRepo(t)
	ps := &patchSet{Commits: []string{r.P, r.C}}
	if err := validatePatchSet(r.dir, ps, nil); err != nil {
		t.Fatal(err)
	}
	var review *unresolvedError
	if err := validatePatchSet(r.dir, ps, map[string]bool{r.P: true}); !errors.As(err, &review) || !strings.Contains(err.Error(), "비활성") {
		t.Fatalf("제외한 선행 커밋은 검토가 필요해야 함: %v", err)
	}
	run(t, r.dir, "revert", "--no-edit", r.H)
	sha, err := git(r.dir, "rev-parse", "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	if err := validatePatchSet(r.dir, &patchSet{Commits: []string{strings.TrimSpace(sha), r.C}}, nil); !errors.As(err, &review) || !strings.Contains(err.Error(), "되돌리기") {
		t.Fatalf("되돌리기 선행 커밋은 검토가 필요해야 함: %v", err)
	}
}

func TestDeclaredInCode(t *testing.T) {
	for _, tc := range []struct {
		code string
		word string
		want bool
	}{
		{"struct sk_buff *nskb;", "nskb", true},
		{"void *nskb = skb;", "nskb", true},
		{"int ret, nskb;", "ret", true},
		{"static int out_helper(int v)", "out_helper", true},
		{"#define RXRPC_NEW 1", "RXRPC_NEW", true},
		{"out_unlock:", "out_unlock", true},
		{"rxrpc_free_skb(nskb, rxrpc_skb_put_response_copy);", "rxrpc_skb_put_response_copy", false},
		{"rxrpc_see_skb(skb, rxrpc_skb_see_unshare_nomem);", "rxrpc_skb_see_unshare_nomem", false},
		{"return rxrpc_new_value;", "rxrpc_new_value", false},
		{"goto out_unlock;", "out_unlock", false},
		{"if (x == rxrpc_new_value)", "rxrpc_new_value", false},
	} {
		if got := declaredInCode([]string{tc.code}, tc.word); got != tc.want {
			t.Errorf("declaredInCode(%q, %q) = %v, want %v", tc.code, tc.word, got, tc.want)
		}
	}
}

// 실제 커널 git 으로 확인 (평소에는 건너뜀):
//
//	KPCTL_REAL_GIT=/srv/ubuntu-resolute KPCTL_REAL_BASE=Ubuntu-7.0.0-14.14 KPCTL_REAL_LATEST=Ubuntu-7.0.0-44.44 \
//	KPCTL_REAL_SHA=14c36133bd24... go test ./internal/builder -run TestResolveRealRepo -v
func TestResolveRealRepo(t *testing.T) {
	dir := os.Getenv("KPCTL_REAL_GIT")
	if dir == "" {
		t.Skip("KPCTL_REAL_GIT 없음")
	}
	for _, sha := range strings.Fields(os.Getenv("KPCTL_REAL_SHA")) {
		ps, err := resolvePatchSet(dir, os.Getenv("KPCTL_REAL_BASE"), os.Getenv("KPCTL_REAL_LATEST"), sha, 0)
		if err != nil {
			t.Errorf("%s: %v", sha, err)
			continue
		}
		t.Logf("%s → %d개: %v\n  %s", shortSHA(sha), len(ps.Commits), ps.Commits, strings.Join(ps.Notes, "\n  "))
		if failed, _, msg, err := applyCheck(dir, os.Getenv("KPCTL_REAL_BASE"), ps.Commits); err != nil || failed != "" {
			t.Errorf("%s: 묶음 적용 실패 %s %s %v", sha, failed, msg, err)
		}
	}
}
