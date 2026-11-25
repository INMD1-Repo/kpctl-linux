// 이 파일: builder 패키지의 TestSandboxAutomaticallyPreparesMissingCompilerOnce, TestAutomaticPreparationRefusesFloatingBaseBeforeExecutingHelper, TestSandboxPreparationFailureIsBoundedAndBusyIsRetried 회귀 시험.
package builder

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kpctl/internal/model"
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
	b.cfg.Sandbox.Prepare.SnapshotTimeoutMinutes = intp(40)
	b.cfg.Sandbox.Prepare.ImageTimeoutMinutes = intp(360)
	script := `#!/usr/bin/env python3
import hashlib,json,pathlib,sys
args=sys.argv
assert args[1]=='prepare'
assert 'never-export-profile-secret' not in ' '.join(args)
assert args[args.index('--snapshot')+1]=='auto'
assert args[args.index('--snapshot-timeout-minutes')+1]=='40'
assert args[args.index('--image-timeout-minutes')+1]=='360'
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

func TestSandboxPreparationTimeouts(t *testing.T) {
	p := SandboxPreparation{Snapshot: "auto"}
	args, timeout := p.timeouts()
	if len(args) != 0 || timeout < (8*20+180)*time.Minute {
		t.Fatalf("legacy config: args %v, timeout %v", args, timeout)
	}
	p.SnapshotTimeoutMinutes, p.ImageTimeoutMinutes = intp(40), intp(360)
	_, automatic := p.timeouts()
	p.Sources = "/custom.sources"
	_, custom := p.timeouts()
	if custom < (40+360)*time.Minute || automatic-custom != 7*40*time.Minute {
		t.Fatalf("unexpected prepare deadlines: automatic %v, custom %v", automatic, custom)
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

func TestArchiveOutageDefersQueuedAndManualWorkThroughCooldown(t *testing.T) {
	b, k, _ := automaticProfileFixture(t)
	b.cfg.Kernels = []KernelConfig{k}
	b.cfg.DiscoverMinutes = intp(0)
	b.cfg.KernelCleanupFreeGiB = -1
	calls := filepath.Join(b.cfg.WorkDir, "calls")
	script := "#!/bin/sh\n[ \"$1\" = prepare ] || exit 0\necho prepare >> '" + calls + "'\necho '503 Service Unavailable' >&2\nexit 69\n"
	if err := os.WriteFile(b.cfg.Sandbox.Helper, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	task := model.BuildTask{Job: model.Job{ID: 1, Version: 1, Kernel: k.Kernel}}
	var retryAt time.Time
	for range 2 {
		result := b.build(task)
		if !result.Deferred || !strings.Contains(result.Error, "503") || !strings.Contains(result.Error, "30분") {
			t.Fatalf("archive failure should retain its diagnostic and defer the job: %+v", result)
		}
		if ids := b.nextRequest(time.Now()).DeferredJobIDs; len(ids) != 1 || ids[0] != task.Job.ID {
			t.Fatalf("claim did not skip the job in archive cooldown: %v", ids)
		}
		current := b.archiveJobRetryAt[task.Job.ID]
		if !retryAt.IsZero() && !current.Equal(retryAt) {
			t.Fatal("an old controller returning the deferred job extended its cooldown")
		}
		retryAt = current
		b.DiscoverKernels([]string{k.Kernel})
		if !b.deferredDiscovery[k.Kernel] {
			t.Fatal("manual refresh lost while the profile is unavailable")
		}
	}
	if len(b.identity().DeferredJobIDs) != 0 {
		t.Fatal("heartbeat should not read the work loop's cooldown map")
	}
	if ids := b.nextRequest(retryAt).DeferredJobIDs; len(ids) != 0 || len(b.archiveJobRetryAt) != 0 {
		t.Fatalf("job still excluded at its retry deadline: %v", ids)
	}
	if data, err := os.ReadFile(calls); err != nil || string(data) != "prepare\n" {
		t.Fatalf("unexpected probe count during cooldown: %q (%v)", data, err)
	}
	for key, failure := range b.profileFailed {
		failure.at = time.Now().Add(-31 * time.Minute)
		b.profileFailed[key] = failure
	}
	if _, err := b.ensureSandboxProfile(k); !errors.Is(err, errBuildDeferred) {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(calls); err != nil || string(data) != "prepare\nprepare\n" {
		t.Fatalf("archive was not checked after cooldown: %q (%v)", data, err)
	}
}

func TestPrepareDiskPressureIsRecheckedWithoutArchiveCooldown(t *testing.T) {
	b, k, _ := automaticProfileFixture(t)
	if err := os.WriteFile(b.cfg.Sandbox.Helper, []byte("#!/bin/sh\necho '4 GiB free' >&2\nexit 73\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := b.ensureSandboxProfile(k)
	if !errors.Is(err, errDiskSpace) || !strings.Contains(err.Error(), "4 GiB free") || len(b.profileFailed) != 0 {
		t.Fatalf("unexpected disk deferral: %v", err)
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
