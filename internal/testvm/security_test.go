// 이 파일: 실제 시험 셸과 가짜 kpatch로 서명 거부·교체·롤백·정리 실패를 재현합니다.
package testvm

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"kpctl/internal/model"
)

// shellVMRunner는 SSH 대신 격리된 파일 트리에서 실제 guest 스크립트를 실행합니다.
// 커널 동작을 검증하지 않으며 가짜 도구가 남기는 sysfs 상태와 명령 순서만 확인합니다.
type shellVMRunner struct {
	root, boot    string
	env           []string
	copies        []string
	timeoutCancel context.CancelFunc
	cleanupCalls  int
}

func (r *shellVMRunner) guest(s string) string {
	return strings.NewReplacer("/proc/", r.root+"/proc/", "/sys/", r.root+"/sys/", "/tmp/kpctl-test-", r.root+"/tmp/kpctl-test-").Replace(s)
}
func (r *shellVMRunner) Run(ctx context.Context, _ Endpoint, command, stdin string) (string, error) {
	if command == bootProbeScript {
		return r.boot, nil
	}
	if stdin == fixedPostScript {
		r.cleanupCalls++
		if ctx.Err() != nil {
			return "", fmt.Errorf("cleanup inherited canceled context: %w", ctx.Err())
		}
	}
	if stdin == moduleTestScript && r.timeoutCancel != nil {
		if err := os.MkdirAll(filepath.Join(r.root, "sys/module/kpctl_fixture"), 0o700); err != nil {
			return "", err
		}
		r.timeoutCancel()
		return "KPCTL_STEP\tload_new\trunning\tload\n", context.DeadlineExceeded
	}
	command = strings.TrimPrefix(command, "sudo -n ")
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", r.guest(command))
	cmd.Env = append(os.Environ(), r.env...)
	cmd.Stdin = strings.NewReader(r.guest(stdin))
	cmd.WaitDelay = time.Second
	out, err := cmd.CombinedOutput()
	return string(out), err
}
func (r *shellVMRunner) Copy(_ context.Context, _ Endpoint, path, dir string) error {
	r.copies = append(r.copies, path)
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(r.guest(dir), filepath.Base(path)), data, 0o600)
}

func shellVMFixture(t *testing.T, fixed bool, mode string) (*Manager, *memoryRegistry, *shellVMRunner, string, ArtifactSet) {
	t.Helper()
	m, registry, _, root, module := managerFixture(t, func(c *Config, _ string) {
		c.TestTimeout = "3s"
		if fixed {
			c.Images, c.CreateCmd, c.DeleteCmd, c.ConsoleLogCmd, c.ListCmd = nil, nil, nil, nil, nil
			c.Fixed = map[string]map[string]FixedVM{fixtureKernel: {mode: {Host: "fixed.internal"}}}
		}
	})
	guest := filepath.Join(root, "guest")
	for _, dir := range []string{"bin", "tmp", "sys/kernel/livepatch", "sys/module", "proc/sys/kernel/random"} {
		if err := os.MkdirAll(filepath.Join(guest, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	write := func(path, body string, mode os.FileMode) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(guest, "proc/sys/kernel/random/boot_id"), "fixture-boot\n", 0o600)
	write(filepath.Join(guest, "kernel.log"), "[    1.0] initial boot log\n", 0o600)
	write(filepath.Join(guest, "bin/dmesg"), "#!/bin/sh\ncat \"$KPCTL_GUEST_ROOT/kernel.log\"\n", 0o700)
	write(filepath.Join(guest, "bin/kpatch"), `#!/bin/sh
set -eu
command=$1
name=$(basename "$2" .ko)
printf '%s %s\n' "$command" "$name" >> "$KPCTL_GUEST_ROOT/operations"
if [ "$command" = unload ]; then
 rm -rf "$KPCTL_GUEST_ROOT/sys/kernel/livepatch/$name" "$KPCTL_GUEST_ROOT/sys/module/$name"
 exit 0
fi
case "$2" in
 */unsigned/*)
  if [ "${KPCTL_NEGATIVE_ACCEPT:-0}" != 1 ]; then
   echo 'Required key not available' >&2
   exit 1
  fi ;;
 */previous/*)
  if [ -f "$KPCTL_GUEST_ROOT/previous-loaded" ] && [ "${KPCTL_ROLLBACK_FAIL:-0}" = 1 ]; then exit 9; fi
  touch "$KPCTL_GUEST_ROOT/previous-loaded" ;;
esac
if [ "${KPCTL_KEEP_PREVIOUS:-0}" != 1 ]; then
 for patch in "$KPCTL_GUEST_ROOT"/sys/kernel/livepatch/*; do
  [ -d "$patch" ] || continue
  echo 0 > "$patch/enabled"
 done
fi
mkdir -p "$KPCTL_GUEST_ROOT/sys/kernel/livepatch/$name" "$KPCTL_GUEST_ROOT/sys/module/$name"
echo 1 > "$KPCTL_GUEST_ROOT/sys/kernel/livepatch/$name/enabled"
echo 0 > "$KPCTL_GUEST_ROOT/sys/kernel/livepatch/$name/transition"
if [ -n "${KPCTL_NEW_LOG:-}" ]; then printf '%s\n' "$KPCTL_NEW_LOG" >> "$KPCTL_GUEST_ROOT/kernel.log"; fi
`, 0o700)
	boot := fixtureKernel + "\nbios\noff\nnone\noff\n"
	if mode == "sb_on" {
		boot = fixtureKernel + "\nuefi\non\nintegrity\noff\n"
	}
	if mode == "sb_off" {
		boot = fixtureKernel + "\nuefi\noff\nnone\noff\n"
	}
	runner := &shellVMRunner{root: guest, boot: boot, env: []string{"KPCTL_GUEST_ROOT=" + guest, "PATH=" + filepath.Join(guest, "bin") + ":" + os.Getenv("PATH")}}
	m.runner = runner
	unsigned, previous := filepath.Join(root, ".unsigned-kpctl_fixture.ko"), filepath.Join(root, "kpctl_previous.ko")
	write(unsigned, "unsigned module", 0o600)
	write(previous, "previous module", 0o600)
	return m, registry, runner, root, ArtifactSet{ModulePath: module, UnsignedPath: unsigned, PreviousPath: previous}
}

func requireVMClean(t *testing.T, r *shellVMRunner, registry *memoryRegistry, root string, fixed bool) {
	t.Helper()
	for _, dir := range []string{"sys/kernel/livepatch", "sys/module", "tmp"} {
		entries, err := os.ReadDir(filepath.Join(r.root, dir))
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) > 0 {
			t.Errorf("시험 후 %s 잔존: %v", dir, entries)
		}
	}
	if r.cleanupCalls != 1 {
		t.Errorf("독립 cleanup 호출=%d, want 1", r.cleanupCalls)
	}
	if registry.count() != 0 {
		t.Errorf("일회용 VM 등록이 남음")
	}
	deletes := fileLines(t, filepath.Join(root, "deleted"))
	if (!fixed && len(deletes) != 1) || (fixed && len(deletes) != 0) {
		t.Errorf("fixed=%v 삭제 기록=%v", fixed, deletes)
	}
}
func stepStatus(steps []model.VMTestStep, name string) string {
	for _, step := range steps {
		if step.Name == name {
			return step.Status
		}
	}
	return ""
}

func TestSBOnImageMustActuallyEnforceSignatures(t *testing.T) {
	for _, signals := range []string{"none\noff", "unknown\nunknown"} {
		m, registry, r, root, artifacts := shellVMFixture(t, false, "sb_on")
		r.boot = fixtureKernel + "\nuefi\non\n" + signals + "\n"
		steps, err := m.RunWithArtifacts(context.Background(), 70, fixtureKernel, "sb_on", artifacts)
		if err == nil || !strings.Contains(err.Error(), "이미지 설정 오류") || stepStatus(steps, "boot") != "failed" {
			t.Fatalf("서명 강제 없는 이미지가 통과함: %v %+v", err, steps)
		}
		if len(r.copies) != 0 || registry.count() != 0 || len(fileLines(t, filepath.Join(root, "deleted"))) != 1 {
			t.Fatal("이미지 실패 후 모듈 복사 또는 VM 잔존")
		}
	}
}

func TestVMReplaceRollbackAndSmokeRunInOrder(t *testing.T) {
	for _, fixed := range []bool{false, true} {
		t.Run(fmt.Sprint(fixed), func(t *testing.T) {
			m, registry, r, root, artifacts := shellVMFixture(t, fixed, "bios")
			marker := filepath.Join(r.root, "smoke-argument")
			smoke := writeFakeCommand(t, root, "smoke", `test "$(cat "$KPCTL_GUEST_ROOT/sys/kernel/livepatch/kpctl_fixture/enabled")" = 1
printf '%s' "$1" > "$2"`)
			literal := "spaces ; $(touch should-not-exist) ' quotes"
			m.cfg.SmokeCmd = []string{smoke, literal, marker}
			steps, err := m.RunWithArtifacts(context.Background(), 71, fixtureKernel, "bios", artifacts)
			if err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"boot", "load_previous", "load_new", "replace", "smoke", "rollback", "cleanup", "kernel_log"} {
				if stepStatus(steps, name) != "passed" {
					t.Errorf("%s 시험 증거 누락: %+v", name, steps)
				}
			}
			operations := fileLines(t, filepath.Join(r.root, "operations"))
			want := []string{"load", "kpctl_previous", "load", "kpctl_fixture", "load", "kpctl_previous", "unload", "kpctl_fixture", "unload", "kpctl_previous"}
			if !reflect.DeepEqual(operations, want) {
				t.Fatalf("replace/rollback 순서: %v, want %v", operations, want)
			}
			data, err := os.ReadFile(marker)
			if err != nil || string(data) != literal {
				t.Fatalf("smoke argv 경계 변경: %q %v", data, err)
			}
			requireVMClean(t, r, registry, root, fixed)
		})
	}
}

func TestVMFailuresAlwaysCleanKnownModulesAndDestroyDisposableGuests(t *testing.T) {
	cases := []struct {
		name, mode, env, stage, want string
		smoke                        bool
	}{
		{"unsigned accepted", "sb_on", "KPCTL_NEGATIVE_ACCEPT=1", "negative_signature", "서명 강제 미동작", false},
		{"replace failed", "bios", "KPCTL_KEEP_PREVIOUS=1", "replace", "module test", false},
		{"rollback failed", "bios", "KPCTL_ROLLBACK_FAIL=1", "rollback", "module test", false},
		{"smoke failed", "bios", "", "smoke", "module test", true},
		{"new WARNING", "bios", "KPCTL_NEW_LOG=[    2.0] WARNING: regression", "kernel_log", "disallowed new kernel log", false},
		{"new BUG", "bios", "KPCTL_NEW_LOG=[    2.0] BUG: regression", "kernel_log", "disallowed new kernel log", false},
	}
	for _, fixed := range []bool{false, true} {
		for _, tc := range cases {
			t.Run(fmt.Sprintf("fixed=%v/%s", fixed, tc.name), func(t *testing.T) {
				m, registry, r, root, artifacts := shellVMFixture(t, fixed, tc.mode)
				if tc.env != "" {
					r.env = append(r.env, tc.env)
				}
				if tc.smoke {
					m.cfg.SmokeCmd = []string{"sh", "-c", "exit 9"}
				}
				steps, err := m.RunWithArtifacts(context.Background(), 72, fixtureKernel, tc.mode, artifacts)
				if err == nil || !strings.Contains(err.Error(), tc.want) || stepStatus(steps, tc.stage) != "failed" {
					t.Fatalf("실패를 놓침: %v %+v", err, steps)
				}
				requireVMClean(t, r, registry, root, fixed)
				if tc.name == "unsigned accepted" {
					ops := strings.Join(fileLines(t, filepath.Join(r.root, "operations")), " ")
					if !strings.Contains(ops, "load kpctl_fixture unload kpctl_fixture") {
						t.Errorf("잘못 로드된 unsigned 모듈을 즉시 내리지 않음: %s", ops)
					}
				}
			})
		}
	}
}

func TestVMNegativeSignatureTestRequiresOriginalAndCanBeDisabled(t *testing.T) {
	m, registry, r, root, artifacts := shellVMFixture(t, true, "sb_on")
	artifacts.UnsignedPath = ""
	steps, err := m.RunWithArtifacts(context.Background(), 73, fixtureKernel, "sb_on", artifacts)
	if err == nil || stepStatus(steps, "negative_signature") != "failed" {
		t.Fatalf("원본 없이 부정시험을 통과함: %v %+v", err, steps)
	}
	requireVMClean(t, r, registry, root, true)
	disabled := false
	m.cfg.NegativeSigTest = &disabled
	steps, err = m.RunWithArtifacts(context.Background(), 74, fixtureKernel, "sb_on", artifacts)
	if err != nil || stepStatus(steps, "negative_signature") != "skipped" {
		t.Fatalf("명시적 부정시험 끄기 실패: %v %+v", err, steps)
	}
}

func TestSBOnDefaultNegativeTestAndFirstReleaseStages(t *testing.T) {
	for _, signals := range []string{"integrity\noff", "none\non"} {
		m, registry, r, root, artifacts := shellVMFixture(t, true, "sb_on")
		r.boot = fixtureKernel + "\nuefi\non\n" + signals + "\n"
		artifacts.PreviousPath = ""
		steps, err := m.RunWithArtifacts(context.Background(), 78, fixtureKernel, "sb_on", artifacts)
		if err != nil || stepStatus(steps, "negative_signature") != "passed" || stepStatus(steps, "load_new") != "passed" {
			t.Fatalf("기본 unsigned 거부 시험/새 모듈 검증 실패: %v %+v", err, steps)
		}
		for _, name := range []string{"load_previous", "replace", "rollback", "smoke"} {
			if stepStatus(steps, name) != "skipped" {
				t.Errorf("첫 배포에서 %s 생략 이유가 보존되지 않음: %+v", name, steps)
			}
		}
		requireVMClean(t, r, registry, root, true)
	}
}

func TestVMKeepsSeparateEvidenceForSigningKeys(t *testing.T) {
	m, _, _, root, artifacts := shellVMFixture(t, true, "bios")
	for _, key := range []string{"active", "retired"} {
		artifacts.KeyID = key
		steps, err := m.RunWithArtifacts(context.Background(), 79, fixtureKernel, "bios", artifacts)
		if err != nil {
			t.Fatal(err)
		}
		for _, step := range steps {
			if step.KeyID != key || step.Mode != "bios" {
				t.Fatalf("단계의 키/펌웨어 정보 누락: %+v", step)
			}
		}
		for _, suffix := range []string{".test.log", ".console.log"} {
			if _, err := os.Stat(filepath.Join(root, "testlogs", "kpctl-test-79-bios-"+key+suffix)); err != nil {
				t.Fatalf("키별 증거가 덮어써지거나 누락됨: %v", err)
			}
		}
	}
}

func TestVMTimeoutCleanupUsesIndependentContext(t *testing.T) {
	for _, fixed := range []bool{false, true} {
		t.Run(fmt.Sprint(fixed), func(t *testing.T) {
			m, registry, r, root, artifacts := shellVMFixture(t, fixed, "bios")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			r.timeoutCancel = cancel
			_, err := m.RunWithArtifacts(ctx, 75, fixtureKernel, "bios", artifacts)
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("시간 초과 누락: %v", err)
			}
			requireVMClean(t, r, registry, root, fixed)
		})
	}
}

func TestKernelLogOnlyNewLinesAndKnownModuleSignatureTaint(t *testing.T) {
	before := "[    1.0] WARNING: historical warning\n[    1.1] BUG: historical bug\n"
	if err := checkKernelLog("bios", before, before, []string{"kpctl_fixture"}); err != nil {
		t.Fatalf("기존 로그만으로 실패함: %v", err)
	}
	for _, line := range []string{"Oops: fault", "Kernel panic - not syncing", "BUG: fault", "WARNING: fault", "Call Trace:", "livepatch: kpctl_fixture: failed to patch", "[ 5.0] kernel BUG at fs/inode.c:123!", "[ 5.1] WARNING: CPU: 0 PID: 1 at kernel/x.c:1", "[ 5.2] BUG: unable to handle page fault"} {
		if err := checkKernelLog("bios", before, before+line+"\n", nil); err == nil {
			t.Errorf("새 오류 줄을 허용함: %s", line)
		}
	}
	for _, line := range []string{"[ 6.0] usb 1-1: debug: endpoint reset", "[ 6.1] kpctl_fixture: loading out-of-tree module taints kernel.", "[ 6.2] livepatch: enabling patch 'kpctl_fixture'"} {
		if err := checkKernelLog("bios", before, before+line+"\n", []string{"kpctl_fixture"}); err != nil {
			t.Errorf("일반 새 줄을 오류로 판정함: %s (%v)", line, err)
		}
	}
	if err := checkKernelLog("bios", before, "[ 9.0] rotated\n", nil); err == nil {
		t.Fatal("기준 로그 유실을 허용함")
	}
	for _, mode := range []string{"bios", "sb_off", "sb_on"} {
		line := "[    3.0] kpctl_fixture: module verification failed: signature and/or required key missing - tainting kernel"
		if allowedKernelLog(mode, line, []string{"kpctl_fixture"}) != (mode != "sb_on") {
			t.Errorf("%s 시험 모듈 taint 판정 오류", mode)
		}
		if allowedKernelLog(mode, strings.ReplaceAll(line, "kpctl_fixture:", "other_provider:"), []string{"kpctl_fixture"}) {
			t.Errorf("%s 외부 모듈 서명 taint를 허용함", mode)
		}
		if !allowedKernelLog(mode, "livepatch: tainting kernel with TAINT_LIVEPATCH", nil) {
			t.Errorf("%s livepatch K taint를 거부함", mode)
		}
	}
}

func TestFixedHistoricalKernelErrorsAreBaselineOnly(t *testing.T) {
	m, registry, r, root, artifacts := shellVMFixture(t, true, "bios")
	if err := os.WriteFile(filepath.Join(r.root, "kernel.log"), []byte("[    1.0] WARNING: old\n[    1.1] BUG: old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := m.RunWithArtifacts(context.Background(), 76, fixtureKernel, "bios", artifacts); err != nil {
		t.Fatalf("고정 VM의 과거 오류 때문에 시험 실패: %v", err)
	}
	requireVMClean(t, r, registry, root, true)
}

func TestVMFailedOrIncompleteStageCannotPassWithZeroExitStatus(t *testing.T) {
	for _, status := range []string{"failed", "running"} {
		run := &testRun{mode: "bios", key: "active"}
		err := run.scriptSteps("KPCTL_STEP\tload_new\t"+status+"\tdiagnostic\n", nil)
		if err == nil || stepStatus(run.steps, "load_new") != "failed" {
			t.Fatalf("불완전한 단계 증거가 성공 종료와 함께 통과함: %v %+v", err, run.steps)
		}
	}
}
