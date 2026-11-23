// 이 파일: testvm 패키지의 TestFixedVMIsTestedWithoutCreateOrDelete, TestFixedVMDirtyGuestBlocksBeforeModuleCopy, TestFixedVMRebootOrOopsDuringTestFails 회귀 시험.
package testvm

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fixedFixture configures only a fixed bios VM: no images, no external commands.
func fixedFixture(t *testing.T, run func(context.Context, Endpoint, string, string) (string, error)) (*Manager, *recordingRunner, string, string) {
	t.Helper()
	m, _, runner, root, module := managerFixture(t, func(c *Config, _ string) {
		c.Images, c.CreateCmd, c.DeleteCmd, c.ConsoleLogCmd, c.ListCmd = nil, nil, nil, nil, nil
		c.Fixed = map[string]map[string]FixedVM{fixtureKernel: {"bios": {Host: "10.20.0.31", Port: 2222}}}
		c.MaxConcurrent = 4
	})
	runner.run = run
	return m, runner, root, module
}

func fixedGuest(bootIDs ...string) func(context.Context, Endpoint, string, string) (string, error) {
	var posts atomic.Int32
	return func(_ context.Context, _ Endpoint, command, stdin string) (string, error) {
		switch {
		case command == bootProbeScript:
			return fixtureKernel + "\nbios\noff\nnone\noff\n", nil
		case stdin == fixedPreScript:
			return bootIDs[0] + "\n", nil
		case stdin == fixedPostScript:
			id := bootIDs[min(int(posts.Add(1)), len(bootIDs)-1)]
			return id + "\nclean kernel log\n", nil
		}
		return "passed\n", nil
	}
}

func TestFixedVMIsTestedWithoutCreateOrDelete(t *testing.T) {
	m, runner, root, module := fixedFixture(t, fixedGuest("boot-a"))
	if err := m.Run(context.Background(), 40, fixtureKernel, "bios", module); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"created", "deleted"} {
		if lines := fileLines(t, filepath.Join(root, name)); len(lines) != 0 {
			t.Fatalf("fixed VM ran %s command: %v", name, lines)
		}
	}
	for _, e := range append(runner.endpoints, runner.copyEndpoints...) {
		if e.Host != "10.20.0.31" || e.Port != 2222 {
			t.Fatalf("unexpected endpoint %+v", e)
		}
	}
	log, err := os.ReadFile(filepath.Join(root, "testlogs", "kpctl-test-40-bios.console.log"))
	if err != nil || !strings.Contains(string(log), "clean kernel log") {
		t.Fatalf("kernel log not saved: %q %v", log, err)
	}
	if err := m.Recover(context.Background(), nil); err != nil {
		t.Fatalf("recover without commands: %v", err)
	}
}

func TestFixedVMDirtyGuestBlocksBeforeModuleCopy(t *testing.T) {
	m, runner, _, module := fixedFixture(t, func(_ context.Context, _ Endpoint, command, stdin string) (string, error) {
		if command == bootProbeScript {
			return fixtureKernel + "\nbios\noff\nnone\noff\n", nil
		}
		if stdin == fixedPreScript {
			return "livepatch already loaded: old", errors.New("exit status 1")
		}
		return "", nil
	})
	err := m.Run(context.Background(), 41, fixtureKernel, "bios", module)
	if err == nil || !strings.Contains(err.Error(), "not clean") || len(runner.copyEndpoints) != 0 {
		t.Fatalf("dirty guest: err=%v copies=%d", err, len(runner.copyEndpoints))
	}
}

func TestFixedVMRebootOrOopsDuringTestFails(t *testing.T) {
	m, _, _, module := fixedFixture(t, fixedGuest("boot-a", "boot-b"))
	if err := m.Run(context.Background(), 42, fixtureKernel, "bios", module); err == nil || !strings.Contains(err.Error(), "rebooted during the test") {
		t.Fatalf("reboot not detected: %v", err)
	}
	m, _, _, module = fixedFixture(t, func(_ context.Context, _ Endpoint, command, stdin string) (string, error) {
		switch {
		case command == bootProbeScript:
			return fixtureKernel + "\nbios\noff\nnone\noff\n", nil
		case stdin == fixedPostScript:
			return "boot-a\n[ 12.0] Oops: 0000 [#1] SMP\n", nil
		}
		return "boot-a\n", nil
	})
	if err := m.Run(context.Background(), 43, fixtureKernel, "bios", module); err == nil || !strings.Contains(err.Error(), "panic/oops") {
		t.Fatalf("oops not detected: %v", err)
	}
	m, _, _, module = fixedFixture(t, func(_ context.Context, _ Endpoint, command, stdin string) (string, error) {
		switch {
		case command == bootProbeScript:
			return fixtureKernel + "\nbios\noff\nnone\noff\n", nil
		case stdin == fixedPostScript:
			return "", errors.New("connection refused")
		}
		return "boot-a\n", nil
	})
	if err := m.Run(context.Background(), 44, fixtureKernel, "bios", module); err == nil || !strings.Contains(err.Error(), "unreachable") {
		t.Fatalf("lost guest not detected: %v", err)
	}
}

func TestFixedVMRunsOneTestAtATime(t *testing.T) {
	var active, peak atomic.Int32
	guest := fixedGuest("boot-a")
	m, _, _, module := fixedFixture(t, func(ctx context.Context, e Endpoint, command, stdin string) (string, error) {
		if stdin == moduleTestScript {
			n := active.Add(1)
			for old := peak.Load(); n > old && !peak.CompareAndSwap(old, n); old = peak.Load() {
			}
			time.Sleep(20 * time.Millisecond)
			active.Add(-1)
		}
		return guest(ctx, e, command, stdin)
	})
	errs := make(chan error, 3)
	for job := 50; job < 53; job++ {
		go func() { errs <- m.Run(context.Background(), job, fixtureKernel, "bios", module) }()
	}
	for range 3 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	if peak.Load() != 1 {
		t.Fatalf("fixed VM ran %d tests at once", peak.Load())
	}
}

func TestFixedConfigValidation(t *testing.T) {
	base := validTestConfig(t)
	fixedOnly := Config{Enabled: true, SSHKey: base.SSHKey,
		Fixed: map[string]map[string]FixedVM{fixtureKernel: {"sb_on": {Host: "testvm-sb.internal"}}}}
	if err := fixedOnly.Validate(); err != nil {
		t.Fatalf("fixed-only config needs no images or commands: %v", err)
	}
	for name, edit := range map[string]func(*Config){
		"bad host":           func(c *Config) { c.Fixed[fixtureKernel]["sb_on"] = FixedVM{Host: "-oProxyCommand=x"} },
		"bad port":           func(c *Config) { c.Fixed[fixtureKernel]["sb_on"] = FixedVM{Host: "h", Port: 70000} },
		"bad mode":           func(c *Config) { c.Fixed[fixtureKernel]["uefi"] = FixedVM{Host: "h"} },
		"fixed and image":    func(c *Config) { c.Images = base.Images },
		"nothing to test on": func(c *Config) { c.Fixed = nil },
	} {
		c := fixedOnly
		c.Fixed = map[string]map[string]FixedVM{fixtureKernel: {"sb_on": {Host: "testvm-sb.internal"}}}
		edit(&c)
		if name == "fixed and image" {
			c.CreateCmd, c.DeleteCmd, c.ConsoleLogCmd, c.ListCmd = base.CreateCmd, base.DeleteCmd, base.ConsoleLogCmd, base.ListCmd
		}
		if err := c.Validate(); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}
