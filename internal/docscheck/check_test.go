// 이 파일: 틀린 실제 설정 예제·CLI·링크·보존 기록이 검사를 통과하지 못하는 회귀시험.
package docscheck

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func repositoryRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	return root
}
func put(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}
func agentExample(state string) string {
	data, _ := json.Marshal(map[string]any{"controller_url": "https://controller.example:8443", "state_dir": state})
	return string(data)
}

func TestConfigExamplesUseActualParsersWithoutCreatingDirectories(t *testing.T) {
	dir := t.TempDir()
	untouched := filepath.Join(dir, "not-created")
	for _, tc := range []struct{ kind, body string }{
		{"controller", `{"admin_tokens":{"admin":"replace-admin-token-012345"},"builder_token":"replace-builder-token-012345"}`},
		{"builder", fmt.Sprintf(`{"controller_url":"https://controller.example:8443","token":"builder-token-0123456789","series":"noble","work_dir":%q}`, untouched)},
		{"agent", agentExample(untouched)},
		{"testvm", `{"test_vm":{"enabled":false,"modes":"auto","negative_sig_test":true,"smoke_cmd":[]}}`},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			if err := validateConfig(tc.kind, []byte(tc.body)); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(untouched); !os.IsNotExist(err) {
				t.Fatalf("검사가 운영 경로를 생성함: %v", err)
			}
		})
	}
}

func TestWrongMarkedExampleAndUnknownKeysFail(t *testing.T) {
	valid := "<!-- config-example: agent -->\n```json\n" + agentExample(filepath.Join(t.TempDir(), "state")) + "\n```\n"
	if count, err := checkConfigExamples(valid); err != nil || count != 1 {
		t.Fatalf("정상 예제 실패 %d %v", count, err)
	}
	for _, body := range []string{
		strings.Replace(valid, "controller_url", "controller_urll", 1),
		strings.Replace(valid, "config-example: agent", "config-example: agnet", 1),
		strings.Replace(valid, "```json", "```text", 1),
		"<!-- config-example: agent -->\n```json\n{}",
	} {
		if _, err := checkConfigExamples(body); err == nil {
			t.Fatalf("틀린 예제를 허용함: %s", body)
		}
	}
	for _, kind := range []string{"controller", "builder", "agent", "testvm"} {
		if err := validateConfig(kind, []byte(`{"not_a_real_setting":true}`)); err == nil {
			t.Fatalf("%s의 모르는 설정을 허용함", kind)
		}
	}
	if err := validateConfig("agent", []byte(`{"controller_url":"https://example"} {"unknown":true}`)); err == nil {
		t.Fatal("추가 JSON을 허용함")
	}
}

func TestCommandsAreReadFromActualCLIDispatch(t *testing.T) {
	catalog, err := loadCommands(repositoryRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{"kpctl status", "kpctl signing list", "kpctl signing rollout-cert prod-2026", "kpctl hosts mok-password canary", "kpctl host cancel-reboot canary", "kpctl auto clear K", "kpctl ssh-key add", "kpctl dhcp leases", "kpctl approve 12 --prerelease"} {
		if _, err := checkCommands(body, catalog); err != nil {
			t.Fatalf("실제 명령 거부: %s: %v", body, err)
		}
	}
	for _, body := range []string{"kpctl nonexistent", "kpctl signing typo", "kpctl host restart", "kpctl dhcp reboot"} {
		if _, err := checkCommands(body, catalog); err == nil {
			t.Fatalf("없는 명령 허용: %s", body)
		}
	}
}

func TestLinksRequireRealFilesAnchorsAndSourceLines(t *testing.T) {
	root := t.TempDir()
	document := filepath.Join(root, "README.md")
	put(t, document, "# 루트\n")
	put(t, filepath.Join(root, "child.md"), "# 검증 제목\n# 검증 제목\n<a id=\"fixed-anchor\"></a>\n")
	put(t, filepath.Join(root, "code.go"), "package example\n\nfunc Ready() {}\n")
	for _, body := range []string{"[검사](child.md#검증-제목)", "[중복](child.md#검증-제목-1)", "[명시](child.md#fixed-anchor)", "[코드](code.go#L3)", "[루트](#루트)"} {
		if _, err := checkLinks(root, document, body); err != nil {
			t.Fatal(err)
		}
	}
	for _, body := range []string{"[없음](absent.md)", "[없음](child.md#absent)", "[범위](code.go#L50)", "[탈출](../outside.md)"} {
		if _, err := checkLinks(root, document, body); err == nil {
			t.Fatalf("깨진 링크 허용: %s", body)
		}
	}
}

func archiveFixture(t *testing.T, root string) {
	t.Helper()
	original := "# 당시 증거\n[원문 상대경로](../../../old.md)\n"
	record := archiveRecord{Path: "docs/history/evidence.md", SourcePath: "docs/operations/history/evidence.md", SHA256: fmt.Sprintf("%x", sha256.Sum256([]byte(original)))}
	data, _ := json.Marshal(archiveManifest{Version: 1, Records: []archiveRecord{record}})
	put(t, filepath.Join(root, record.Path), original)
	put(t, filepath.Join(root, "docs/history/archive-manifest.json"), string(data))
}

func TestAbsentArchiveManifestAllowsPublicSourceTree(t *testing.T) {
	if docs, count, err := archivedDocuments(t.TempDir()); err != nil || count != 0 || len(docs) != 0 {
		t.Fatalf("expected no archives: count=%d err=%v", count, err)
	}
}

func TestArchivedOriginalsAreVerifiedByHash(t *testing.T) {
	root := t.TempDir()
	archiveFixture(t, root)
	if _, count, err := archivedDocuments(root); err != nil || count != 1 {
		t.Fatalf("원문 보존 검증: %d %v", count, err)
	}
	put(t, filepath.Join(root, "docs/history/evidence.md"), "changed")
	if _, _, err := archivedDocuments(root); err == nil {
		t.Fatal("과거 실측 원문 변경을 허용함")
	}
}

func TestFullCheckRejectsDeliberatelyWrongExampleAndNewHistoryDocument(t *testing.T) {
	root := t.TempDir()
	archiveFixture(t, root)
	put(t, filepath.Join(root, "cmd/kpctl/main.go"), `package main
 type command struct { usage string; run func() }
 var commands=map[string]command{"status":{"status",cmdStatus}}
 func cmdStatus() {}`)
	put(t, filepath.Join(root, "deploy/kpatch/README.md"), "# 묶음\n")
	good := agentExample(filepath.Join(root, "not-created"))
	put(t, filepath.Join(root, "configs/agent.example.json"), good)
	put(t, filepath.Join(root, "README.md"), "# 현재\n<!-- config-example: agent -->\n```json\n"+strings.Replace(good, "controller_url", "controller_urll", 1)+"\n```\n")
	if _, err := Check(root); err == nil || !strings.Contains(err.Error(), "controller_urll") {
		t.Fatalf("틀린 설정 예제 전체 검사 실패: %v", err)
	}
	put(t, filepath.Join(root, "README.md"), "# 현재\nkpctl status\n")
	if _, err := Check(root); err != nil {
		t.Fatal(err)
	}
	put(t, filepath.Join(root, "docs/history/new-report.md"), "kpctl nonexistent\n")
	if _, err := Check(root); err == nil {
		t.Fatal("새 이력 문서까지 보존 예외로 숨김")
	}
	if _, err := os.Stat(filepath.Join(root, "not-created")); !os.IsNotExist(err) {
		t.Fatal("검사 중 설정 경로 생성")
	}
}

func TestCodeMapChecksActualDeclarationNamesAndPositions(t *testing.T) {
	root := t.TempDir()
	document := filepath.Join(root, "map.md")
	put(t, filepath.Join(root, "code.go"), "package example\n\nfunc Current() {}\n")
	if err := checkSourceSymbols(document, "[Current](code.go#L3)"); err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{"[Removed](code.go#L3)", "[Current](code.go#L2)"} {
		if err := checkSourceSymbols(document, body); err == nil {
			t.Fatalf("오래된 코드 지도 허용: %s", body)
		}
	}
}
