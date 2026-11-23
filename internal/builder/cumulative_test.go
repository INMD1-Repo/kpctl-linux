// 이 파일: builder 패키지의 TestNativeDependentPatchesBecomeOneExactDiff, TestSystemCumulativeKLPPatches 회귀 시험.
package builder

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestNativeDependentPatchesBecomeOneExactDiff(t *testing.T) {
	b, k, _, first, second := dependencyFixture(t)
	out := t.TempDir()
	paths := []string{filepath.Join(out, "first.patch"), filepath.Join(out, "second.patch")}
	for i, p := range []string{first.Content, second.Content} {
		if err := os.WriteFile(paths[i], []byte(p), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	index := filepath.Join(k.GitDir, ".git", "index")
	before, err := os.ReadFile(index)
	if err != nil {
		t.Fatal(err)
	}
	// User-level diff settings must not alter the native tool's input format.
	run(t, k.GitDir, "config", "diff.noprefix", "true")
	run(t, k.GitDir, "config", "color.ui", "always")
	inputs, err := b.cumulativeKLPPatches(context.Background(), k, out, paths)
	if err != nil || len(inputs) != 1 {
		t.Fatalf("누적 입력을 만들어야 함: %v %v", inputs, err)
	}
	stage := t.TempDir()
	file := filepath.Join(stage, "test.c")
	if err := os.WriteFile(file, []byte("int base;\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// This is the real failure mode: the dependent patch cannot be refreshed
	// against the original source, whereas the cumulative input can.
	if _, err := git(stage, "apply", "--check", paths[1]); err == nil {
		t.Fatal("선행 패치 없이 후행 패치가 적용되면 시험 설정 오류")
	}
	run(t, stage, "apply", inputs[0])
	got, err := os.ReadFile(file)
	if err != nil || string(got) != "int base;\nint prerequisite;\nint dependent;\n" {
		t.Fatalf("선택한 변경 전부가 그대로 남아야 함: %q %v", got, err)
	}
	after, err := os.ReadFile(index)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("원본 저장소 인덱스를 바꾸면 안 됨", err)
	}
	if _, err := b.cumulativeKLPPatches(context.Background(), k, out, []string{paths[1], paths[0]}); !errors.Is(err, errPatchDependency) {
		t.Fatalf("잘못된 적용 순서는 선행 수정 검토로 구분: %v", err)
	}
	if _, err := b.runKLPBuild(k, "kpctl_trial", out, []string{paths[1], paths[0]}); failureKind(err, "") != "unsupported" {
		t.Fatalf("native 누적 입력의 적용 실패를 환경 오류로 감싸면 안 됨: %v", err)
	}
	if _, err := b.cumulativeKLPPatches(context.Background(), KernelConfig{}, out, paths); err == nil {
		t.Fatal("검증된 기준 없이 누적 diff를 만들면 안 됨")
	}
	if _, err := b.cumulativeKLPPatches(context.Background(), k, out, []string{paths[0], paths[0]}); err == nil {
		t.Fatal("중복 적용 실패를 무시하면 안 됨")
	}
}

// Optional read-only check using the exact on-server patch inputs. No module
// is built or loaded; it only creates a private index and a temporary diff.
func TestSystemCumulativeKLPPatches(t *testing.T) {
	paths := filepath.SplitList(os.Getenv("KPCTL_SYSTEM_PATCHES"))
	if len(paths) < 2 {
		t.Skip("KPCTL_SYSTEM_PATCHES로 실제 입력 지정 시 실행")
	}
	k := KernelConfig{GitDir: os.Getenv("KPCTL_SYSTEM_GIT"), BaseTag: os.Getenv("KPCTL_SYSTEM_BASE")}
	b := &Builder{cfg: &Config{WorkDir: t.TempDir()}}
	inputs, err := b.cumulativeKLPPatches(context.Background(), k, t.TempDir(), paths)
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(inputs[0])
	if err != nil || !strings.Contains(string(body), "diff --git ") {
		t.Fatalf("실제 누적 diff 확인 실패: %v", err)
	}
	t.Logf("실제 패치 %d개, 누적 diff %d바이트", len(paths), len(body))
}
