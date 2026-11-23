// 이 파일: builder 패키지의 TestSandboxAutomaticallyPreparesMissingCompilerOnce, TestAutomaticPreparationRefusesFloatingBaseBeforeExecutingHelper, TestSandboxPreparationFailureIsBoundedAndBusyIsRetried 회귀 시험.
package builder

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func automaticProfileFixture(t *testing.T) (*Builder, KernelConfig, string) {
	t.Helper()
	root := t.TempDir()
	k := KernelConfig{Kernel: "6.8.0-136-generic", GitDir: "/kernel-input", BaseTag: "Ubuntu-6.8.0-136.136", TagGlob: "Ubuntu-6.8.0-*"}
	compiler := "(Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0"
	profile := sandboxProfileFixture(t, root, k.Kernel, compiler)
	if err := os.Remove(profile); err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(root, "prepare")
	cfg, err := LoadConfig(writeConfig(t, `{"controller_url":"https://unused.invalid","token":"never-export-profile-secret","series":"noble","work_dir":"`+root+`","sandbox":{"profiles_dir":"`+root+`","helper":"`+helper+`"}}`))
	if err != nil {
		t.Fatal(err)
	}
	b := &Builder{cfg: cfg, headersRoot: root}
	b.cfg.Sandbox.Prepare.BaseImage = "docker.io/library/ubuntu@sha256:" + strings.Repeat("b", 64)
	return b, k, profile
}

func TestSandboxAutomaticallyPreparesMissingCompilerOnce(t *testing.T) {
	b, k, profile := automaticProfileFixture(t)
	script := `#!/usr/bin/env python3
import hashlib,json,pathlib,sys
args=sys.argv
assert args[1]=='prepare'
assert 'never-export-profile-secret' not in ' '.join(args)
assert args[args.index('--snapshot')+1]=='auto'
assert args[args.index('--git-dir')+1]=='/kernel-input'
assert args[args.index('--base-tag')+1]=='Ubuntu-6.8.0-136.136'
root=pathlib.Path(args[args.index('--profiles-dir')+1])
with (root/'calls').open('a') as out:out.write('prepare\n')
compiler='(Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0'
target=root/('compiler-'+hashlib.sha256(compiler.encode()).hexdigest()[:20])/'profile.json'
target.parent.mkdir(parents=True,exist_ok=True)
target.write_text(json.dumps({'schema':1,'image':'sha256:'+'a'*64,'settings':{'compiler_identity':compiler}}))
`
	if err := os.WriteFile(b.cfg.Sandbox.Helper, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		got, err := b.ensureSandboxProfile(k)
		if err != nil || got != profile {
			t.Fatalf("profile: %s %v", got, err)
		}
	}
	data, err := os.ReadFile(filepath.Join(b.cfg.WorkDir, "calls"))
	if err != nil || string(data) != "prepare\n" {
		t.Fatalf("profile repeatedly rebuilt: %q %v", data, err)
	}
}

func TestAutomaticPreparationRefusesFloatingBaseBeforeExecutingHelper(t *testing.T) {
	b, k, _ := automaticProfileFixture(t)
	b.cfg.Sandbox.Prepare.BaseImage = "docker.io/library/ubuntu:24.04"
	if _, err := b.ensureSandboxProfile(k); err == nil || !strings.Contains(err.Error(), "@sha256") {
		t.Fatalf("floating base accepted: %v", err)
	}
}

func TestSandboxPreparationFailureIsBoundedAndBusyIsRetried(t *testing.T) {
	for _, busy := range []bool{false, true} {
		t.Run(map[bool]string{false: "missing packages", true: "busy"}[busy], func(t *testing.T) {
			b, k, _ := automaticProfileFixture(t)
			status := "1"
			if busy {
				status = "75"
			}
			script := "#!/bin/sh\nprintf x >> '" + filepath.Join(b.cfg.WorkDir, "calls") + "'\necho exact-packages-unavailable >&2\nexit " + status + "\n"
			if err := os.WriteFile(b.cfg.Sandbox.Helper, []byte(script), 0o755); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 2; i++ {
				_, err := b.ensureSandboxProfile(k)
				if busy {
					if !errors.Is(err, errBuildBusy) || !b.retryDiscovery {
						t.Fatalf("busy: %v", err)
					}
				} else if err == nil || !strings.Contains(err.Error(), "30분") {
					t.Fatalf("failure: %v", err)
				}
			}
			data, _ := os.ReadFile(filepath.Join(b.cfg.WorkDir, "calls"))
			want := "x"
			if busy {
				want = "xx"
			}
			if string(data) != want {
				t.Fatalf("unbounded or lost retry: %q", data)
			}
			if busy && len(b.profileFailed) != 0 {
				t.Fatal("busy became a permanent preparation failure")
			}
		})
	}
}

func TestKLPBaselineExecutesToolOriginalBuildAndRejectsPatches(t *testing.T) {
	source := `#!/bin/bash
set -eu
die() { echo "$*" >&2; exit 1; }
usage() { :; }
status() { :; }
process_args() {
	if [[ $# -eq 0 ]]; then
		usage
		exit 1
	fi
}
build_kernel() { printf '%s\n' 'upstream-private-flag=value' >> "$KLP_TEST_CALLS"; }
process_args "$@"
if true; then
	build_kernel
	status "Copying original object files"
	exit 99
fi
`
	program, err := klpBaselineProgram(source)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	script := filepath.Join(root, "klp-baseline")
	if err := os.WriteFile(script, []byte(program), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KLP_TEST_CALLS", filepath.Join(root, "calls"))
	command := exec.Command("bash", script)
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("original-only path: %v %s", err, out)
	}
	data, _ := os.ReadFile(filepath.Join(root, "calls"))
	if string(data) != "upstream-private-flag=value\n" {
		t.Fatal("original tool flags were not used")
	}
	if out, err := exec.Command("bash", script, "security.patch").CombinedOutput(); err == nil || !strings.Contains(string(out), "baseline cannot apply patches") {
		t.Fatal("baseline applied security patches")
	}
	if _, err := klpBaselineProgram(strings.Replace(source, "Copying original object files", "changed upstream entry", 1)); err == nil {
		t.Fatal("changed tool entry point silently accepted")
	}
}
