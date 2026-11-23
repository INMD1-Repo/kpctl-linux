// 이 파일: builder 패키지의 TestFailureKinds, TestEnvironmentTrialRetriesOnceWithoutDecision, TestCommitDecisionSkipsOnlyThatCommitAndCancelRetries 회귀 시험.
package builder

import (
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kpctl/internal/client"
	"kpctl/internal/controller"
	"kpctl/internal/model"
)

func TestFailureKinds(t *testing.T) {
	for _, tc := range []struct {
		name      string
		err       error
		log, want string
	}{
		{"lock", errBuildBusy, "", model.FailureBusy},
		{"disk", errDiskSpace, "", model.FailureBusy},
		{"prepare", errBuildEnv, "ERROR: changed data section", model.FailureEnvironment},
		{"artifact", errBuildArtifact, "objtool: unexpected klp reloc for new symbol", model.FailureArtifact},
		{"non-CVE prerequisite", errPatchDependency, "0017.patch: error: patch failed", model.FailureUnsupported},
		{"apply diagnostic", errors.New("exit status 1"), "error: net/mptcp/pm.c: patch does not apply", model.FailureUnsupported},
		{"new cross-module symbol", errors.New("exit status 1"), "rpcrdma.o: objtool: unexpected klp reloc for new symbol xprt_add_backlog_noncongested", model.FailureUnsupported},
		{"data change", errors.New("exit status 1"), "ERROR: changed data section", model.FailureUnsupported},
		{"unknown", errors.New("exit status 1"), "foo.c: error: unknown type name", model.FailureUnknown},
		{"killed", errors.New("signal: killed"), "ERROR: changed data section", model.FailureUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := failureKind(tc.err, tc.log); got != tc.want {
				t.Fatalf("got %s want %s", got, tc.want)
			}
		})
	}
}

func TestEnvironmentTrialRetriesOnceWithoutDecision(t *testing.T) {
	b, k, calls, first, _ := dependencyFixture(t)
	script := "#!/bin/sh\necho attempt >> \"$KPCTL_TEST_DEPENDENCY_CALLS\"\necho 'curl: (22) The requested URL returned error: 404'\nexit 1\n"
	if err := os.WriteFile(b.cfg.KpatchBuild, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	reason, err := b.trialBuild(k, first.Commit, first.Content)
	if reason != "" || failureKind(err, "") != model.FailureEnvironment {
		t.Fatalf("reason=%q err=%v", reason, err)
	}
	data, _ := os.ReadFile(calls)
	if len(strings.Fields(string(data))) != 2 {
		t.Fatalf("환경 실패는 한 번만 재시도: %q", data)
	}
}

// 실제 controller known/결정 API와 실제 Git 수집을 연결합니다. 컴파일만 가짜입니다.
func TestCommitDecisionSkipsOnlyThatCommitAndCancelRetries(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	b, k, calls, first, second := dependencyFixture(t)
	// 두 번째 수정은 첫 수정 없이도 적용되도록 독립 파일로 옮깁니다.
	run(t, k.GitDir, "reset", "--hard", first.Commit)
	if err := os.WriteFile(filepath.Join(k.GitDir, "next.c"), []byte("int independent;\n"), 0644); err != nil {
		t.Fatal(err)
	}
	run(t, k.GitDir, "add", "next.c")
	run(t, k.GitDir, "commit", "-qm", "CVE-2026-1234 independent")
	sha, _ := git(k.GitDir, "rev-parse", "HEAD")
	second.Commit = strings.TrimSpace(sha)
	run(t, k.GitDir, "tag", "-f", "Ubuntu-6.8.0-90.90")
	k.Paths = []string{"*.c"}
	// 실패 커밋의 본문만 명시적 도구 거부로 실패시킵니다.
	wrapper := b.cfg.KpatchBuild
	original, _ := os.ReadFile(wrapper)
	replacement := strings.Replace(string(original), "echo \"$#\" >>", "for p do\n if grep -q '^+int prerequisite;' \"$p\"; then echo failed >> \"$KPCTL_TEST_DEPENDENCY_CALLS\"; echo 'objtool: unexpected klp reloc for new symbol xprt_add_backlog_noncongested'; exit 1; fi\ndone\necho \"$#\" >>", 1)
	if err := os.WriteFile(wrapper, []byte(replacement), 0755); err != nil {
		t.Fatal(err)
	}
	s, err := controller.NewServer(&controller.Config{DataDir: t.TempDir(), AdminTokens: map[string]string{"tester": "admin"}, BuilderToken: "builder"})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(s.Handler())
	defer server.Close()
	b.c, _ = client.New(server.URL, "builder", "")
	admin, _ := client.New(server.URL, "admin", "")
	if _, err := b.discover(k); err == nil {
		t.Fatal("제외 전 실패에서 멈춰야 함")
	}
	var status model.StatusResponse
	if err := admin.Do("GET", "/api/status", nil, &status); err != nil {
		t.Fatal(err)
	}
	u := status.Upstream[k.Kernel]
	if u == nil || u.ProblemKind != model.FailureUnsupported || u.ProblemFailure.Commit != first.Commit || u.ProblemFailure.Input.BaseTag != k.BaseTag {
		t.Fatalf("실패 문맥: %+v", u)
	}
	path := "/api/kernels/" + k.Kernel + "/commits/" + first.Commit + "/exclude"
	if err := admin.Do("POST", path, model.ExcludeCommitRequest{Reason: "별도 완화 후 커널 업데이트 예정", ProblemRef: u.ProblemAt.UTC().Format(time.RFC3339Nano)}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := b.discover(k); err != nil {
		t.Fatalf("제외 뒤 다음 커밋 시험: %v", err)
	}
	data, _ := os.ReadFile(calls)
	if strings.Join(strings.Fields(string(data)), " ") != "failed 1" {
		t.Fatalf("실패 커밋 재시험 없이 다음 커밋 시험: %q", data)
	}
	var known model.KnownCommitsResponse
	if err := b.c.Do("GET", "/api/builder/kernels/"+k.Kernel+"/known", nil, &known); err != nil {
		t.Fatal(err)
	}
	if len(known.Commits) != 2 || len(known.ActivePatches) != 1 || known.ActivePatches[0].Commit != second.Commit {
		t.Fatalf("커밋별 known: %+v", known)
	}
	if err := admin.Do("DELETE", path, nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := b.discover(k); err == nil {
		t.Fatal("취소 후 실패 커밋을 다시 시험해야 함")
	}
	data, _ = os.ReadFile(calls)
	if strings.Join(strings.Fields(string(data)), " ") != "failed 1 failed" {
		t.Fatalf("취소 후 재시험: %q", data)
	}
}

func TestTrialInputRecordsPinnedImage(t *testing.T) {
	root := t.TempDir()
	profile := sandboxProfileFixture(t, root, "6.8.0-136-generic", "(Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0")
	b := &Builder{headersRoot: root, cfg: &Config{BootDir: root, BuildTool: BuildToolKpatch, Sandbox: &SandboxConfig{Profile: profile}}}
	input := b.trialInput(KernelConfig{Kernel: "6.8.0-136-generic", BaseTag: "Ubuntu-6.8.0-136.136"})
	var p struct {
		Image string `json:"image"`
	}
	data, _ := os.ReadFile(profile)
	_ = json.Unmarshal(data, &p)
	if input.Image != p.Image || input.Image == "" || input.Profile != profile {
		t.Fatalf("입력 식별값: %+v", input)
	}
}
