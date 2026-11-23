// 이 파일: builder 패키지의 TestKLPToolsComeFromPinnedSet, TestKLPToolsRealRepo 회귀 시험.
package builder

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 커널 코드는 기준 태그, 빌드 도구는 표에 고정한 태그 + 지정한 수정 커밋에서 가져오는지, 그리고 무결성 검사가
// 그 조합을 정상으로 보되 도구·커널 코드의 임의 변경은 잡아내는지 확인합니다.
func TestKLPToolsComeFromPinnedSet(t *testing.T) {
	saved := klpToolSets
	defer func() { klpToolSets = saved }()
	const fix = "objtool/klp: Fix cross-module klp relocation section naming"
	klpToolSets = []klpToolSet{{TagGlob: "Ubuntu-7.0.0-*", Tag: "Ubuntu-7.0.0-39.39", Picks: []string{fix}}}

	root := t.TempDir()
	repo := filepath.Join(root, "repo")
	write := func(dir, name, body string) {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	commit := func(message, tag string) {
		t.Helper()
		run(t, repo, "add", "-A", ".")
		run(t, repo, "commit", "-qm", message)
		if tag != "" {
			run(t, repo, "tag", tag)
		}
	}
	write(repo, "kernel/a.c", "int base;\n")
	write(repo, "tools/objtool/klp-diff.c", "int old_tool;\n")
	write(repo, "tools/objtool/removed.c", "int removed_later;\n")
	write(repo, "tools/objtool/sync-check.sh", "#!/bin/sh\n")
	write(repo, "scripts/livepatch/klp-build", "#!/bin/bash\necho old\n")
	write(repo, "scripts/Makefile.lib", "old\n")
	run(t, repo, "init", "-q")
	commit("base", "Ubuntu-7.0.0-14.14")
	// 도구 태그: 커널 코드와 도구가 모두 바뀜
	write(repo, "kernel/a.c", "int newer_kernel;\n")
	write(repo, "tools/objtool/klp-diff.c", "int new_tool;\n")
	write(repo, "tools/objtool/new-tool.c", "int added_tool;\n")
	write(repo, "scripts/livepatch/klp-build", "#!/bin/bash\necho new\n")
	write(repo, "scripts/Makefile.lib", "new\n")
	if err := os.Remove(filepath.Join(repo, "tools/objtool/removed.c")); err != nil {
		t.Fatal(err)
	}
	commit("tools", "Ubuntu-7.0.0-39.39")
	// 그 뒤: 도구를 깨뜨린 커밋(가져오면 안 됨)과, 골라 넣을 수정 커밋(커널 코드도 함께 건드림)
	write(repo, "tools/objtool/klp-checksum.c", "int broken = decode_file();\n")
	commit("objtool/klp: Add \"objtool klp checksum\" subcommand", "Ubuntu-7.0.0-40.40")
	write(repo, "tools/objtool/klp-diff.c", "int new_tool;\nint fixed;\n")
	write(repo, "kernel/a.c", "int newest_kernel;\n")
	commit(fix, "")
	write(repo, "scripts/Makefile.lib", "newest\n")
	commit("kbuild: change objtool arguments", "Ubuntu-7.0.0-43.43")
	// 더 뒤: 배포판이 도구를 고침 (선언 추가)
	write(repo, "tools/objtool/include/objtool/check.h", "int decode_file(void);\n")
	commit("objtool: Consolidate file decoding into decode_file()", "Ubuntu-7.0.0-45.45")
	// 선언을 추가하는 대신 문제 호출 자체를 없애도 Ubuntu의 수정을 존중합니다.
	if err := os.Remove(filepath.Join(repo, "tools/objtool/include/objtool/check.h")); err != nil {
		t.Fatal(err)
	}
	write(repo, "tools/objtool/klp-checksum.c", "int checksum_without_decode_file;\n")
	commit("objtool: remove obsolete decode_file call", "Ubuntu-7.0.0-46.46")

	kernel := "7.0.0-14-generic"
	write(root, "config-"+kernel, "CONFIG_LIVEPATCH=y\nCONFIG_KLP_BUILD=y\n")
	b := &Builder{cfg: &Config{KernelCleanupFreeGiB: -1, WorkDir: filepath.Join(root, "work"), BootDir: root}}
	k := KernelConfig{Kernel: kernel, GitDir: repo, BaseTag: "Ubuntu-7.0.0-14.14", TagGlob: "Ubuntu-7.0.0-*"}

	indexBefore, _ := os.ReadFile(filepath.Join(repo, ".git/index"))
	tools, err := b.klpTools(k)
	if err != nil || tools == nil || tools.Tag != "Ubuntu-7.0.0-39.39" || len(tools.Picks) != 1 || tools.Tree == "" {
		t.Fatalf("도구 출처: %+v %v", tools, err)
	}
	if again, err := b.klpTools(k); err != nil || again.Tree != tools.Tree {
		t.Fatalf("같은 입력이면 같은 트리여야 함: %+v %v", again, err)
	}
	if indexAfter, _ := os.ReadFile(filepath.Join(repo, ".git/index")); string(indexAfter) != string(indexBefore) {
		t.Fatal("저장소 index 를 바꾸면 안 됨")
	}
	src, log, err := b.kernelSource(context.Background(), k)
	if err != nil {
		t.Fatalf("소스 준비: %v\n%q", err, log)
	}
	read := func(name string) string { data, _ := os.ReadFile(filepath.Join(src, name)); return string(data) }
	if read("kernel/a.c") != "int base;\n" {
		t.Fatalf("커널 코드는 기준 태그여야 함: %q", read("kernel/a.c"))
	}
	if read("tools/objtool/klp-diff.c") != "int new_tool;\nint fixed;\n" ||
		!strings.Contains(read("scripts/livepatch/klp-build"), "echo new") || read("scripts/Makefile.lib") != "new\n" {
		t.Fatalf("빌드 도구는 도구 태그 + 수정 커밋이어야 함: %q", read("tools/objtool/klp-diff.c"))
	}
	for _, gone := range []string{"tools/objtool/removed.c", "tools/objtool/klp-checksum.c"} {
		if _, err := os.Stat(filepath.Join(src, gone)); !os.IsNotExist(err) {
			t.Fatalf("%s 가 있으면 안 됨", gone)
		}
	}
	if fi, _ := os.Stat(filepath.Join(src, "scripts/livepatch/klp-build")); fi.Mode()&0o100 == 0 {
		t.Fatal("도구 스크립트 실행 권한")
	}
	if got := strings.TrimSpace(read(".kpctl-ready")); got != "Ubuntu-7.0.0-14.14 tools="+tools.Tree {
		t.Fatalf("캐시 표식: %q", got)
	}
	ctx := context.Background()
	if err := b.verifySourceTree(ctx, k, src); err != nil {
		t.Fatalf("기준+고정 도구 조합은 정상이어야 함: %v", err)
	}
	// 준비된 캐시는 다시 풀지 않음
	write(src, "marker", "x")
	if _, _, err := b.kernelSource(ctx, k); err != nil || read("marker") != "x" {
		t.Fatalf("캐시 재사용: %v", err)
	}
	for _, name := range []string{"tools/objtool/klp-diff.c", "tools/objtool/new-tool.c", "kernel/a.c"} {
		original := read(name)
		write(src, name, "int tampered;\n")
		if err := b.verifySourceTree(ctx, k, src); !errors.Is(err, errSourceDirty) {
			t.Fatalf("%s 변경을 잡아야 함: %v", name, err)
		}
		write(src, name, original)
	}
	// 기준 태그의 도구로 되돌려 놓은 트리도 이제는 기대와 다름
	write(src, "tools/objtool/klp-diff.c", "int old_tool;\n")
	if err := b.verifySourceTree(ctx, k, src); !errors.Is(err, errSourceDirty) {
		t.Fatalf("옛 도구는 기대 트리와 달라야 함: %v", err)
	}

	// 커널 점프 뒤(기준이 도구 태그보다 새로움): 기준의 도구가 컴파일되지 않으면 도구 디렉터리만 고정 조합으로 내림
	jumped := k
	jumped.Kernel, jumped.BaseTag = "7.0.0-43-generic", "Ubuntu-7.0.0-43.43"
	write(root, "config-"+jumped.Kernel, "CONFIG_LIVEPATCH=y\nCONFIG_KLP_BUILD=y\n")
	down, err := b.klpTools(jumped)
	if err != nil || down == nil || len(down.Picks) != 1 {
		t.Fatalf("점프 뒤 기준: %+v %v", down, err)
	}
	show := func(tree, path string) string {
		out, err := git(repo, "show", tree+":"+path)
		if err != nil {
			return "<없음>"
		}
		return out
	}
	if show(down.Tree, "tools/objtool/klp-diff.c") != "int new_tool;\nint fixed;\n" || show(down.Tree, "tools/objtool/klp-checksum.c") != "<없음>" {
		t.Fatalf("도구는 고정 조합이어야 함: %q", show(down.Tree, "tools/objtool/klp-diff.c"))
	}
	if show(down.Tree, "kernel/a.c") != "int newest_kernel;\n" || show(down.Tree, "scripts/Makefile.lib") != "newest\n" {
		t.Fatalf("커널 코드와 빌드 스크립트는 새 기준 그대로여야 함: %q %q", show(down.Tree, "kernel/a.c"), show(down.Tree, "scripts/Makefile.lib"))
	}
	// 기준이 도구 태그와 같아도 그 뒤의 재배치 수정은 필요합니다.
	same := jumped
	same.BaseTag = "Ubuntu-7.0.0-39.39"
	if tools, err := b.klpTools(same); err != nil || tools == nil || len(tools.Picks) != 1 || show(tools.Tree, "tools/objtool/klp-diff.c") != "int new_tool;\nint fixed;\n" {
		t.Fatalf("도구 태그 자체에도 수정 커밋을 적용해야 함: %+v %v", tools, err)
	}
	// 새 기준의 도구가 고쳐져 있으면 바꾸지 않음
	for _, base := range []string{"Ubuntu-7.0.0-45.45", "Ubuntu-7.0.0-46.46"} {
		same := jumped
		same.BaseTag = base
		if tools, err := b.klpTools(same); err != nil || tools != nil {
			t.Fatalf("기준 %s: %+v %v", base, tools, err)
		}
	}
	other := k
	// 소스 태그가 같아도 고정 도구 조합이 바뀌면 이전 실패의 재시험을 허용합니다.
	before, err := b.trialEnvironmentFingerprint(k, "Ubuntu-7.0.0-43.43")
	if err != nil {
		t.Fatal(err)
	}
	picks := klpToolSets[0].Picks
	klpToolSets[0].Picks = nil
	after, err := b.trialEnvironmentFingerprint(k, "Ubuntu-7.0.0-43.43")
	klpToolSets[0].Picks = picks
	if err != nil || before == after {
		t.Fatalf("고정 도구 변경은 재시험 입력을 바꿔야 함: %v", err)
	}
	other.TagGlob = "Ubuntu-7.2.0-*"
	if tools, err := b.klpTools(other); err != nil || tools != nil {
		t.Fatalf("다른 계열: %+v %v", tools, err)
	}
	// 수정 커밋이나 도구 태그가 저장소에 없으면 옛 도구로 조용히 빌드하지 않고 멈춤
	klpToolSets = []klpToolSet{{TagGlob: "Ubuntu-7.0.0-*", Tag: "Ubuntu-7.0.0-39.39", Picks: []string{"objtool/klp: no such fix"}}}
	if _, err := b.klpTools(k); err == nil {
		t.Fatal("없는 수정 커밋은 오류여야 함")
	}
	klpToolSets = []klpToolSet{{TagGlob: "Ubuntu-7.0.0-*", Tag: "Ubuntu-7.0.0-38.38"}}
	if _, err := b.klpTools(k); err == nil {
		t.Fatal("없는 도구 태그는 오류여야 함")
	}
	klpToolSets = saved
	write(root, "config-"+kernel, "CONFIG_LIVEPATCH=y\n")
	if tools, err := b.klpTools(k); err != nil || tools != nil {
		t.Fatalf("kpatch 커널: %+v %v", tools, err)
	}
}

// 실제 Ubuntu 커널 git 으로 확인 (평소에는 건너뜀):
//
//	KPCTL_TEST_GIT=/srv/ubuntu-resolute KPCTL_TEST_BASE_TAG=Ubuntu-7.0.0-14.14 KPCTL_TEST_KERNEL=7.0.0-14-generic \
//	KPCTL_TEST_WORK=/var/tmp/x go test ./internal/builder -run TestKLPToolsRealRepo -v
func TestKLPToolsRealRepo(t *testing.T) {
	repo, base, kernel, work := os.Getenv("KPCTL_TEST_GIT"), os.Getenv("KPCTL_TEST_BASE_TAG"), os.Getenv("KPCTL_TEST_KERNEL"), os.Getenv("KPCTL_TEST_WORK")
	if repo == "" || base == "" || kernel == "" || work == "" {
		t.Skip("KPCTL_TEST_GIT / KPCTL_TEST_BASE_TAG / KPCTL_TEST_KERNEL / KPCTL_TEST_WORK 필요")
	}
	b := &Builder{cfg: &Config{KernelCleanupFreeGiB: -1, WorkDir: work, BootDir: "/boot"}}
	k := KernelConfig{Kernel: kernel, GitDir: repo, BaseTag: base, TagGlob: base[:strings.LastIndex(base, "-")] + "-*"}
	tools, err := b.klpTools(k)
	if err != nil || tools == nil {
		t.Fatalf("도구 출처: %+v %v", tools, err)
	}
	t.Logf("%s · 트리 %s", tools.describe(), tools.Tree)
	src, log, err := b.kernelSource(context.Background(), k)
	if err != nil {
		t.Fatalf("소스 준비: %v\n%s", err, log)
	}
	if err := b.verifySourceTree(context.Background(), k, src); err != nil {
		t.Fatalf("무결성: %v", err)
	}
	t.Logf("소스 %s", src)
}
