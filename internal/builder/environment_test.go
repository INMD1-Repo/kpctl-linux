// 이 파일: builder 패키지의 TestUbuntuBuildKeepsUpstreamVersionAndPublishedABISeparate, TestUbuntuRustToolsUseExactTargetVersions 회귀 시험.
package builder

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestUbuntuBuildKeepsUpstreamVersionAndPublishedABISeparate(t *testing.T) {
	root := t.TempDir()
	makefile := "VERSION=6\nPATCHLEVEL=8\nSUBLEVEL=12\nKERNELVERSION=$(VERSION).$(PATCHLEVEL).$(SUBLEVEL)\nKERNELRELEASE=$(KERNELVERSION)-wrong\nall:\n\t@printf '%s|%s|%s|%s|%s' '$(KERNELRELEASE)' '$(KERNELVERSION)' '$(CONFIG_DEBUG_SECTION_MISMATCH)' '$(CFLAGS_MODULE)' '$(KEEP_INPUT)'\n"
	if err := os.WriteFile(filepath.Join(root, "Makefile"), []byte(makefile), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MAKEFLAGS", "KEEP_INPUT=ok")
	b := &Builder{cfg: &Config{BootDir: root}}
	env, err := b.buildEnvironment(context.Background(), KernelConfig{Kernel: "6.8.0-136-generic"}, root)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("make", "-s", "-C", root)
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err != nil || string(out) != "6.8.0-136-generic|6.8.12|y|-DPKG_ABI=136|ok" {
		t.Fatalf("Ubuntu 실제 make 인자와 내부 버전을 유지해야 함: %q %v", out, err)
	}
	if _, err := b.buildEnvironment(context.Background(), KernelConfig{Kernel: "6.8.0-136-$(shell false)"}, root); err == nil {
		t.Fatal("커널 이름으로 make 식을 주입할 수 없어야 함")
	}
}

func TestUbuntuRustToolsUseExactTargetVersions(t *testing.T) {
	root := t.TempDir()
	write := func(name, contents string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(root, name), []byte(contents), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write("rustc-1.75", "#!/bin/sh\necho 'rustc 1.75.0 (target-build)'\n")
	write("rustc", "#!/bin/sh\necho 'rustc 99.0.0 (wrong)'\n")
	write("bindgen-0.65", "#!/bin/sh\necho 'bindgen 0.65.1'\n")
	write("bindgen", "#!/bin/sh\necho 'bindgen 99.0.0'\n")
	write("Makefile", "rustavailable:\n\t@test \"$$($(RUSTC) --version)\" = 'rustc 1.75.0 (target-build)'\n\t@test \"$$($(BINDGEN) --version)\" = 'bindgen 0.65.1'\n")
	config := "CONFIG_RUST=y\nCONFIG_RUSTC_VERSION_TEXT=\"rustc 1.75.0 (target-build)\"\nCONFIG_BINDGEN_VERSION_TEXT=\"bindgen 0.65.1\"\n"
	write("config-6.8.0-136-generic", config)
	t.Setenv("PATH", root+string(os.PathListSeparator)+os.Getenv("PATH"))
	b := &Builder{cfg: &Config{BootDir: root}}
	k := KernelConfig{Kernel: "6.8.0-136-generic"}
	if _, err := b.buildEnvironment(context.Background(), k, root); err != nil {
		t.Fatal("기본 bindgen 이 없어도 설치된 정확한 버전 도구를 사용해야 함", err)
	}
	write("rustc-1.75", "#!/bin/sh\necho 'rustc 99.0.0 (wrong)'\n")
	if _, err := b.buildEnvironment(context.Background(), k, root); err == nil || !strings.Contains(err.Error(), "CONFIG_RUST") {
		t.Fatalf("도구 버전이 다르면 Rust 를 해제하지 않고 중단해야 함: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(root, "config-"+k.Kernel))
	if err != nil || string(data) != config {
		t.Fatal("대상 커널의 Rust 설정을 바꾸면 안 됨")
	}
}
