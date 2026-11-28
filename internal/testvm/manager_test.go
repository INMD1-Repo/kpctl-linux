// 이 파일: testvm 패키지의 TestCreateEndpointPortReachesSSHRunner, TestMalformedLastCreateLineDeletesPlannedVM, TestCreateTimeoutDeletesTwiceAndKillsChildren 회귀 시험.
package testvm

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

const fixtureKernel = "6.8.0-85-generic"

type memoryRegistry struct {
	mu  sync.Mutex
	vms map[string]Instance
}

func (r *memoryRegistry) Remember(vm Instance) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.vms == nil {
		r.vms = map[string]Instance{}
	}
	r.vms[vm.ID] = vm
	return nil
}

func (r *memoryRegistry) Forget(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.vms, id)
	return nil
}

func (r *memoryRegistry) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.vms)
}

type recordingRunner struct {
	mu            sync.Mutex
	endpoints     []Endpoint
	copyEndpoints []Endpoint
	boot          string
	run           func(context.Context, Endpoint, string, string) (string, error)
}

func (r *recordingRunner) Run(ctx context.Context, e Endpoint, command, stdin string) (string, error) {
	r.mu.Lock()
	r.endpoints = append(r.endpoints, e)
	r.mu.Unlock()
	if r.run != nil {
		return r.run(ctx, e, command, stdin)
	}
	if command == bootProbeScript {
		if r.boot != "" {
			return r.boot, nil
		}
		return fixtureKernel + "\nbios\noff\nnone\noff\n", nil
	}
	return "passed\n", nil
}

func (r *recordingRunner) Copy(_ context.Context, e Endpoint, _, _ string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.copyEndpoints = append(r.copyEndpoints, e)
	return nil
}

func writeFakeCommand(t *testing.T, root, name, body string) string {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\nset -eu\n"+body+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func managerFixture(t *testing.T, edit func(*Config, string)) (*Manager, *memoryRegistry, *recordingRunner, string, string) {
	t.Helper()
	root := t.TempDir()
	t.Setenv("KPCTL_VM_TEST_ROOT", root)
	cfg := validTestConfig(t)
	cfg.CreateCmd = []string{writeFakeCommand(t, root, "create", `printf '%s\n' "$1" >> "$KPCTL_VM_TEST_ROOT/created"
printf 'preparing VM\n{"host":"127.0.0.1","port":2201,"id":"%s"}\n' "$1"`), "{{.Name}}"}
	cfg.DeleteCmd = []string{writeFakeCommand(t, root, "delete", `printf '%s\n' "$1" >> "$KPCTL_VM_TEST_ROOT/deleted"`), "{{.ID}}"}
	cfg.ConsoleLogCmd = []string{writeFakeCommand(t, root, "console", `printf 'VM console\n'`), "{{.ID}}"}
	cfg.ListCmd = []string{writeFakeCommand(t, root, "list", `if [ -f "$KPCTL_VM_TEST_ROOT/listed" ]; then cat "$KPCTL_VM_TEST_ROOT/listed"; fi`)}
	cfg.CmdTimeout = "1s"
	cfg.BootTimeout = "1s"
	cfg.TestTimeout = "1s"
	if edit != nil {
		edit(&cfg, root)
	}
	registry, runner := &memoryRegistry{}, &recordingRunner{}
	m, err := New(cfg, registry, runner, filepath.Join(root, "testlogs"))
	if err != nil {
		t.Fatal(err)
	}
	m.PollInterval = time.Millisecond
	module := filepath.Join(root, "kpctl_fixture.ko")
	if err := os.WriteFile(module, []byte("fixture module"), 0o600); err != nil {
		t.Fatal(err)
	}
	return m, registry, runner, root, module
}

func fileLines(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.Fields(string(data))
}

func TestCreateEndpointPortReachesSSHRunner(t *testing.T) {
	for _, tc := range []struct {
		name, portJSON string
		wantPort       int
	}{
		{"explicit port", `,"port":2201`, 2201}, {"default SSH port", "", 22},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, registry, runner, root, module := managerFixture(t, func(c *Config, root string) {
				c.CreateCmd = []string{writeFakeCommand(t, root, "endpoint-create", `printf 'progress before endpoint\n{"host":"127.0.0.1"`+tc.portJSON+`,"id":"provider-vm-42"}\n'`)}
			})
			if err := m.Run(context.Background(), 42, fixtureKernel, "bios", module); err != nil {
				t.Fatal(err)
			}
			if len(runner.endpoints) != 5 || len(runner.copyEndpoints) != 1 {
				t.Fatalf("missing SSH/copy steps: %+v", runner)
			}
			for _, e := range append(runner.endpoints, runner.copyEndpoints...) {
				if e.Host != "127.0.0.1" || e.Port != tc.wantPort || e.ID != "provider-vm-42" {
					t.Fatalf("endpoint lost: %+v", e)
				}
			}
			if got := fileLines(t, filepath.Join(root, "deleted")); !reflect.DeepEqual(got, []string{"provider-vm-42"}) {
				t.Fatalf("wrong VM deleted: %v", got)
			}
			if registry.count() != 0 {
				t.Fatal("cleaned VM remains in registry")
			}
		})
	}
}

func TestMalformedLastCreateLineDeletesPlannedVM(t *testing.T) {
	m, registry, runner, root, module := managerFixture(t, func(c *Config, root string) {
		c.CreateCmd = []string{writeFakeCommand(t, root, "malformed-create", `printf '{"host":"127.0.0.1","id":"kpctl-test-7-bios"}\ntrailing non-JSON log\n'`)}
	})
	err := m.Run(context.Background(), 7, fixtureKernel, "bios", module)
	if err == nil || !strings.Contains(err.Error(), "last stdout line must be JSON") {
		t.Fatalf("unclear create output error: %v", err)
	}
	if len(runner.endpoints) != 0 {
		t.Fatal("SSH ran despite invalid create output")
	}
	if got := fileLines(t, filepath.Join(root, "deleted")); !reflect.DeepEqual(got, []string{"kpctl-test-7-bios"}) {
		t.Fatalf("planned VM not deleted: %v", got)
	}
	if registry.count() != 0 {
		t.Fatal("cleaned intent remains in registry")
	}
}

func TestCreateTimeoutDeletesTwiceAndKillsChildren(t *testing.T) {
	m, registry, _, root, module := managerFixture(t, func(c *Config, root string) {
		c.CmdTimeout = "100ms"
		c.CreateCmd = []string{writeFakeCommand(t, root, "slow-create", `printf '%s\n' "$1" > "$KPCTL_VM_TEST_ROOT/created"
sleep 30`), "{{.Name}}"}
	})
	started := time.Now()
	err := m.Run(context.Background(), 8, fixtureKernel, "bios", module)
	if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "create_cmd") {
		t.Fatalf("expected create timeout: %v", err)
	}
	if time.Since(started) > 3*time.Second {
		t.Fatal("child process retained stdout after timeout")
	}
	if got := fileLines(t, filepath.Join(root, "deleted")); !reflect.DeepEqual(got, []string{"kpctl-test-8-bios", "kpctl-test-8-bios"}) {
		t.Fatalf("timeout cleanup not retried: %v", got)
	}
	if registry.count() != 0 {
		t.Fatal("timed-out VM cleanup left registry entry")
	}
}

func TestDeleteIsIdempotentAndRetriesTimeout(t *testing.T) {
	t.Run("repeated deletion", func(t *testing.T) {
		m, registry, _, root, _ := managerFixture(t, nil)
		_ = registry.Remember(Instance{ID: "kpctl-test-9-bios"})
		for i := 0; i < 2; i++ {
			if err := m.Delete(context.Background(), "kpctl-test-9-bios"); err != nil {
				t.Fatal(err)
			}
		}
		if got := fileLines(t, filepath.Join(root, "deleted")); len(got) != 2 || registry.count() != 0 {
			t.Fatalf("repeated cleanup failed: %v", got)
		}
	})
	t.Run("timeout retry", func(t *testing.T) {
		m, registry, _, root, _ := managerFixture(t, func(c *Config, root string) {
			c.CmdTimeout = "100ms"
			c.DeleteCmd = []string{writeFakeCommand(t, root, "slow-delete", `printf '%s\n' "$1" >> "$KPCTL_VM_TEST_ROOT/deleted"
if [ ! -f "$KPCTL_VM_TEST_ROOT/retried" ]; then
  touch "$KPCTL_VM_TEST_ROOT/retried"
  sleep 30
fi`), "{{.ID}}"}
		})
		_ = registry.Remember(Instance{ID: "kpctl-test-10-bios"})
		if err := m.Delete(context.Background(), "kpctl-test-10-bios"); err != nil {
			t.Fatal(err)
		}
		if got := fileLines(t, filepath.Join(root, "deleted")); len(got) != 2 || registry.count() != 0 {
			t.Fatalf("delete timeout not retried: %v", got)
		}
	})
}

func TestRecoverDeletesUnionOfRecordedAndListedVMs(t *testing.T) {
	m, registry, _, root, _ := managerFixture(t, nil)
	recorded := []Instance{{ID: "kpctl-test-11-bios"}, {ID: "kpctl-test-12-bios"}}
	for _, vm := range recorded {
		_ = registry.Remember(vm)
	}
	if err := os.WriteFile(filepath.Join(root, "listed"), []byte("kpctl-test-12-bios\nkpctl-test-13-bios\nkpctl-test-13-bios\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := m.Recover(context.Background(), recorded); err != nil {
		t.Fatal(err)
	}
	want := []string{"kpctl-test-11-bios", "kpctl-test-12-bios", "kpctl-test-13-bios"}
	if got := fileLines(t, filepath.Join(root, "deleted")); !reflect.DeepEqual(got, want) {
		t.Fatalf("orphan cleanup got %v want %v", got, want)
	}
	if registry.count() != 0 {
		t.Fatal("recovered registry is not empty")
	}
}

func TestMaxConcurrentWaitsUntilPriorVMCleanupFinishes(t *testing.T) {
	m, registry, runner, root, module := managerFixture(t, func(c *Config, root string) {
		c.MaxConcurrent = 1
		c.DeleteCmd = []string{writeFakeCommand(t, root, "blocking-delete", `if [ "$1" = kpctl-test-14-bios ]; then
  touch "$KPCTL_VM_TEST_ROOT/deleting"
  while [ ! -f "$KPCTL_VM_TEST_ROOT/release-delete" ]; do sleep 0.01; done
fi
printf '%s\n' "$1" >> "$KPCTL_VM_TEST_ROOT/deleted"`), "{{.ID}}"}
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered, release := make(chan string, 2), make(chan struct{}, 2)
	runner.run = func(ctx context.Context, e Endpoint, command, _ string) (string, error) {
		if command == bootProbeScript {
			entered <- e.ID
			select {
			case <-release:
				return fixtureKernel + "\nbios\noff\nnone\noff\n", nil
			case <-ctx.Done():
				return "", ctx.Err()
			}
		}
		return "passed", nil
	}
	first, second := make(chan error, 1), make(chan error, 1)
	go func() { first <- m.Run(ctx, 14, fixtureKernel, "bios", module) }()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("first VM did not start")
	}
	go func() { second <- m.Run(ctx, 15, fixtureKernel, "bios", module) }()
	select {
	case id := <-entered:
		t.Fatalf("concurrency limit exceeded by %s", id)
	case <-time.After(100 * time.Millisecond):
	}
	if got := fileLines(t, filepath.Join(root, "created")); len(got) != 1 {
		t.Fatalf("queued VM was created early: %v", got)
	}
	release <- struct{}{}
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(root, "deleting")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("first VM did not reach cleanup")
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case id := <-entered:
		t.Fatalf("next VM %s started while prior cleanup was running", id)
	case <-time.After(100 * time.Millisecond):
	}
	if err := os.WriteFile(filepath.Join(root, "release-delete"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-first:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("first VM did not finish")
	}
	select {
	case id := <-entered:
		if id != "kpctl-test-15-bios" {
			t.Fatalf("wrong queued VM: %s", id)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("queued VM did not start")
	}
	if got := fileLines(t, filepath.Join(root, "deleted")); len(got) != 1 {
		t.Fatalf("slot released before cleanup: %v", got)
	}
	release <- struct{}{}
	select {
	case err := <-second:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("queued VM did not finish")
	}
	if registry.count() != 0 {
		t.Fatal("completed concurrent runs retain VM state")
	}
}

func TestVMRejectsUnexpectedGuestAndSavesPanicConsole(t *testing.T) {
	for _, tc := range []struct{ name, boot, console, want string }{
		{"kernel mismatch", "6.8.0-86-generic\nbios\noff\nnone\noff", "console", "kernel mismatch"},
		{"firmware mismatch", fixtureKernel + "\nuefi\noff\nnone\noff", "console", "firmware mismatch"},
		{"panic console", fixtureKernel + "\nbios\noff\nnone\noff", "Kernel panic - not syncing", "kernel panic/oops"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, registry, runner, root, module := managerFixture(t, func(c *Config, root string) {
				c.ConsoleLogCmd = []string{writeFakeCommand(t, root, "custom-console", "printf '%s\\n' "+shellQuote(tc.console))}
			})
			runner.boot = tc.boot
			err := m.Run(context.Background(), 16, fixtureKernel, "bios", module)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %q error, got %v", tc.want, err)
			}
			log, logErr := os.ReadFile(filepath.Join(root, "testlogs/kpctl-test-16-bios.console.log"))
			if logErr != nil || !strings.Contains(string(log), tc.console) {
				t.Fatalf("missing diagnostic console: %q, %v", log, logErr)
			}
			if len(fileLines(t, filepath.Join(root, "deleted"))) != 1 || registry.count() != 0 {
				t.Fatal("failed guest was not cleaned up")
			}
		})
	}
}

func TestAllowTCGExtendsBootTimeoutWithoutProviderMetadata(t *testing.T) {
	for _, allow := range []bool{false, true} {
		t.Run(map[bool]string{false: "disabled", true: "enabled"}[allow], func(t *testing.T) {
			m, _, runner, root, module := managerFixture(t, func(c *Config, root string) {
				c.AllowTCG = allow
				c.BootTimeout = "500ms"
				c.CreateCmd = []string{writeFakeCommand(t, root, "create", `printf '{"host":"127.0.0.1","id":"%s"}\n' "$1"`), "{{.Name}}"}
			})
			var bootRemaining time.Duration
			runner.run = func(ctx context.Context, _ Endpoint, command, _ string) (string, error) {
				if command == bootProbeScript {
					deadline, ok := ctx.Deadline()
					if ok {
						bootRemaining = time.Until(deadline)
					}
					return fixtureKernel + "\nbios\noff\nnone\noff", nil
				}
				return "passed", nil
			}
			err := m.Run(context.Background(), 17, fixtureKernel, "bios", module)
			if err != nil {
				t.Fatal(err)
			}
			if allow {
				if bootRemaining < 1500*time.Millisecond || bootRemaining > 2*time.Second {
					t.Fatalf("TCG boot timeout was not quadrupled: %s", bootRemaining)
				}
			} else if bootRemaining < 250*time.Millisecond || bootRemaining > 500*time.Millisecond {
				t.Fatalf("normal boot timeout changed: %s", bootRemaining)
			}
			if len(fileLines(t, filepath.Join(root, "deleted"))) != 1 {
				t.Fatal("TCG VM was not cleaned up")
			}
		})
	}
}

func TestMissingModeImageFailsBeforeCreatingVM(t *testing.T) {
	m, registry, _, root, module := managerFixture(t, nil)
	err := m.Run(context.Background(), 18, "missing-kernel", "bios", module)
	if err == nil || !strings.Contains(err.Error(), "no fixed VM or image for missing-kernel/bios") {
		t.Fatalf("missing image error: %v", err)
	}
	if registry.count() != 0 || len(fileLines(t, filepath.Join(root, "created"))) != 0 {
		t.Fatal("missing image created a VM")
	}
}

func TestConsoleFailureBlocksSuccessAndStillDeletesVM(t *testing.T) {
	m, registry, _, root, module := managerFixture(t, func(c *Config, root string) {
		c.ConsoleLogCmd = []string{writeFakeCommand(t, root, "failed-console", `echo 'console unavailable' >&2; exit 1`)}
	})
	err := m.Run(context.Background(), 19, fixtureKernel, "bios", module)
	if err == nil || !strings.Contains(err.Error(), "console_log_cmd") {
		t.Fatalf("console failure did not block success: %v", err)
	}
	if len(fileLines(t, filepath.Join(root, "deleted"))) != 1 || registry.count() != 0 {
		t.Fatal("VM survived console failure")
	}
}

func TestInvalidEndpointDeletesReturnedIDAndPlannedName(t *testing.T) {
	m, registry, _, root, module := managerFixture(t, func(c *Config, root string) {
		c.CreateCmd = []string{writeFakeCommand(t, root, "invalid-endpoint", `echo '{"host":"","id":"provider-vm-invalid","port":2201}'`)}
	})
	err := m.Run(context.Background(), 20, fixtureKernel, "bios", module)
	if err == nil || !strings.Contains(err.Error(), "invalid host") {
		t.Fatalf("invalid endpoint accepted: %v", err)
	}
	if got := fileLines(t, filepath.Join(root, "deleted")); !reflect.DeepEqual(got, []string{"provider-vm-invalid", "kpctl-test-20-bios"}) {
		t.Fatalf("invalid endpoint leaked VM: %v", got)
	}
	if registry.count() != 0 {
		t.Fatal("invalid endpoint left state")
	}
}

func TestIPv6CreateEndpoint(t *testing.T) {
	e, err := parseEndpoint(`{"host":"::1","port":2201,"id":"kpctl-test-ipv6-bios"}`)
	if err != nil || e.Host != "::1" || e.Port != 2201 {
		t.Fatalf("IPv6 endpoint rejected: %+v %v", e, err)
	}
}

func TestNativeVMBootMatchesPackageRevisionAndRunningBuildID(t *testing.T) {
	track := "native__debian__12__amd64__6.1.0-57-amd64__6.1.192-3__" + strings.Repeat("a", 40)
	m, _, runner, _, _ := managerFixture(t, nil)
	for _, observed := range []string{track, strings.Replace(track, "192-3", "192-1", 1), track[:len(track)-1] + "b", "6.1.0-57-amd64"} {
		runner.run = func(_ context.Context, _ Endpoint, probe, _ string) (string, error) {
			if !strings.Contains(probe, "/usr/local/bin/kpctl-agent -identify") {
				t.Fatal("native VM did not check installed package and running identity")
			}
			return observed + "\nuefi\non\nintegrity\non\n", nil
		}
		err := m.waitBoot(context.Background(), Endpoint{}, track, "sb_on", time.Second)
		if (err == nil) != (observed == track) {
			t.Fatalf("probe %q: %v", observed, err)
		}
	}
}
