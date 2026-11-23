// 이 파일: builder 패키지의 TestSandboxSelectsTargetCompilerBeforeCollection 회귀 시험.
package builder

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func sandboxProfileFixture(t *testing.T, root, kernel, compiler string) string {
	t.Helper()
	header := filepath.Join(root, "linux-headers-"+kernel, "include/generated/compile.h")
	if err := os.MkdirAll(filepath.Dir(header), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(header, []byte("#define LINUX_COMPILER \"x86_64-linux-gnu-gcc-13 "+compiler+"\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	key := fmt.Sprintf("%x", sha256.Sum256([]byte(compiler)))[:20]
	path := filepath.Join(root, "compiler-"+key, "profile.json")
	data, _ := json.Marshal(map[string]any{"schema": 1, "image": "sha256:" + strings.Repeat("a", 64), "settings": map[string]string{"compiler_identity": compiler}})
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestSandboxSelectsTargetCompilerBeforeCollection(t *testing.T) {
	root := t.TempDir()
	old := sandboxProfileFixture(t, root, "6.8.0-85-generic", "(Ubuntu 13.2.0-23ubuntu4) 13.2.0")
	current := sandboxProfileFixture(t, root, "6.8.0-136-generic", "(Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0")
	b := &Builder{headersRoot: root, cfg: &Config{Sandbox: &SandboxConfig{ProfilesDir: root}}}
	for kernel, want := range map[string]string{"6.8.0-85-generic": old, "6.8.0-136-generic": current} {
		if got, err := b.sandboxProfile(kernel); err != nil || got != want {
			t.Fatalf("%s: %s %v", kernel, got, err)
		}
	}
	b.cfg.Sandbox = &SandboxConfig{Profile: old}
	if _, err := b.sandboxProfile("6.8.0-136-generic"); err == nil || !strings.Contains(err.Error(), "다릅니다") {
		t.Fatalf("wrong compiler accepted: %v", err)
	}
	b.cfg.Sandbox = &SandboxConfig{ProfilesDir: root}
	if err := os.Remove(current); err != nil {
		t.Fatal(err)
	}
	if _, err := b.sandboxProfile("6.8.0-136-generic"); err == nil || !strings.Contains(err.Error(), "prepare --kernel") {
		t.Fatalf("missing profile accepted: %v", err)
	}
	if _, err := b.sandboxProfile("6.8.0-999-generic"); err == nil || !strings.Contains(err.Error(), "헤더") {
		t.Fatalf("missing compiler accepted: %v", err)
	}
}
