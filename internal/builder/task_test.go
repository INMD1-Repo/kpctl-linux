// 이 파일: builder 패키지의 TestQueuedTaskOutsideWindowFailsBeforePreparingInputs, TestQueuedTaskInsideWindowPreparesAndKeepsExactInputs, TestQueuedTaskManualKernelsBypassAutomaticWindow 회귀 시험.
package builder

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"kpctl/internal/model"
)

func taskKernelInfo() *model.BuildKernelInfo {
	return &model.BuildKernelInfo{Kernel: "6.8.0-987654-generic", Signature: "Ubuntu 6.8.0-987654.987655-generic 6.8.12",
		PackageVersion: "6.8.0-987654.987655", BaseTag: "Ubuntu-6.8.0-987654.987655"}
}

func TestManualDiscoveryRetainsRequestedKernelsDuringControllerOutage(t *testing.T) {
	for _, code := range []int{http.StatusServiceUnavailable, http.StatusUnauthorized} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, http.StatusText(code), code)
			}))
			defer server.Close()
			b, err := New(&Config{ControllerURL: server.URL, PollSeconds: 30})
			if err != nil {
				t.Fatal(err)
			}
			kernel := taskKernelInfo().Kernel
			b.DiscoverKernels([]string{kernel})
			if b.deferredDiscovery[kernel] != (code == http.StatusServiceUnavailable) {
				t.Fatalf("unexpected discovery state after HTTP %d: %v", code, b.deferredDiscovery)
			}
			if _, err := b.resolveKernel(kernel); errors.Is(err, errBuildDeferred) != (code == http.StatusServiceUnavailable) {
				t.Fatalf("unexpected legacy job lookup result after HTTP %d: %v", code, err)
			}
		})
	}
}

type taskWindowFixture struct {
	b               *Builder
	old, current    *model.BuildKernelInfo
	packages, calls string
	mu              sync.Mutex
	reports         map[string]model.UpstreamReport
}

func newTaskWindowFixture(t *testing.T) *taskWindowFixture {
	t.Helper()
	root := t.TempDir()
	f := &taskWindowFixture{packages: fakePublishedAPT(t, "noble", "6.8.0-987654.987654"), calls: filepath.Join(root, "install.calls"), reports: map[string]model.UpstreamReport{}}
	info := func(abi int) *model.BuildKernelInfo {
		version := fmt.Sprintf("6.8.0-%d.%d", abi, abi)
		return &model.BuildKernelInfo{Kernel: fmt.Sprintf("6.8.0-%d-generic", abi), Signature: "Ubuntu " + version + "-generic 6.8.12", PackageVersion: version, BaseTag: "Ubuntu-" + version}
	}
	f.old, f.current = info(987650), info(987654)
	repo := filepath.Join(root, "ubuntu-noble")
	if err := os.MkdirAll(repo, 0755); err != nil {
		t.Fatal(err)
	}
	run(t, repo, "init", "-q")
	run(t, repo, "commit", "-q", "--allow-empty", "-m", "base")
	for _, abi := range []int{987650, 987652, 987653, 987654} {
		run(t, repo, "tag", fmt.Sprintf("Ubuntu-6.8.0-%d.%d", abi, abi))
	}
	helper := filepath.Join(root, "debug-helper")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$KPCTL_TASK_INSTALL_CALLS\"\n: > \"$KPCTL_TASK_DEBUG_DIR/vmlinux-$1\"\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "sudo"), []byte("#!/bin/sh\n[ \"$1\" = -n ] && shift\nexec \"$@\"\n"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KPCTL_TASK_INSTALL_CALLS", f.calls)
	t.Setenv("KPCTL_TASK_DEBUG_DIR", root)
	t.Setenv("PATH", root+string(os.PathListSeparator)+os.Getenv("PATH"))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/builder/kernels" {
			_ = json.NewEncoder(w).Encode(model.HostKernelsResponse{Kernels: []model.HostKernel{{Kernel: f.old.Kernel, Signature: f.old.Signature, Hosts: 1}, {Kernel: f.current.Kernel, Signature: f.current.Signature, Hosts: 1}}})
			return
		}
		var req model.UpstreamReport
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
		}
		kernel := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/builder/kernels/"), "/upstream")
		f.mu.Lock()
		f.reports[kernel] = req
		f.mu.Unlock()
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(server.Close)
	on := true
	b, err := New(&Config{ControllerURL: server.URL, Series: "noble", GitRoot: root, DebugDir: root, WorkDir: root, MaxKernels: 3, AutoDebugSymbols: &on, DebugHelper: helper, KernelCleanupFreeGiB: -1})
	if err != nil {
		t.Fatal(err)
	}
	f.b = b
	return f
}

func TestQueuedTaskOutsideWindowFailsBeforePreparingInputs(t *testing.T) {
	for _, metadata := range []bool{false, true} {
		t.Run(fmt.Sprintf("metadata=%v", metadata), func(t *testing.T) {
			f := newTaskWindowFixture(t)
			task := model.BuildTask{Job: model.Job{ID: 1, Kernel: f.old.Kernel}}
			if metadata {
				task.KernelInfo = f.old
			}
			_, err := f.b.resolveTaskKernel(task)
			if err == nil || !strings.Contains(err.Error(), "빌더 범위 밖") || !strings.Contains(err.Error(), "공식 커널 준비") || errors.Is(err, errBuildBusy) || failureKind(err, "") != model.FailureUnsupported {
				t.Fatalf("outside queued task must fail permanently with jump guidance: %v", err)
			}
			result := f.b.build(task)
			if result.Success || result.Deferred || !strings.Contains(result.Error, "빌더 범위 밖") {
				t.Fatalf("outside queued job must stop without requeue: %+v", result)
			}
			if _, err := os.Stat(f.calls); !os.IsNotExist(err) {
				t.Fatal("outside task invoked input installer")
			}
			f.mu.Lock()
			report := f.reports[f.old.Kernel]
			f.mu.Unlock()
			if report.Outside == nil || !strings.Contains(*report.Outside, "987654·987653·987652") || report.LatestTag != "Ubuntu-6.8.0-987654.987654" {
				t.Fatalf("outside job did not request jump status: %+v", report)
			}
		})
	}
}

func TestQueuedTaskInsideWindowPreparesAndKeepsExactInputs(t *testing.T) {
	for _, metadata := range []bool{false, true} {
		t.Run(fmt.Sprintf("metadata=%v", metadata), func(t *testing.T) {
			f := newTaskWindowFixture(t)
			task := model.BuildTask{Job: model.Job{Kernel: f.current.Kernel}}
			if metadata {
				task.KernelInfo = f.current
			}
			k, err := f.b.resolveTaskKernel(task)
			if err != nil || k.Kernel != f.current.Kernel || k.BaseTag != f.current.BaseTag {
				t.Fatalf("kept queued task changed inputs: %+v %v", k, err)
			}
			calls, err := os.ReadFile(f.calls)
			if err != nil || !strings.Contains(string(calls), f.current.Kernel+" "+f.current.PackageVersion) || strings.Contains(string(calls), f.old.Kernel) {
				t.Fatalf("kept task installer calls: %q %v", calls, err)
			}
			if f.b.lastWindow.floor != 987652 || f.b.lastWindow.latest != 987654 {
				t.Fatalf("confirmed range was not retained: %+v", f.b.lastWindow)
			}
		})
	}
}

func TestQueuedTaskManualKernelsBypassAutomaticWindow(t *testing.T) {
	f := newTaskWindowFixture(t)
	explicit := KernelConfig{Kernel: f.old.Kernel, GitDir: "/manual/git", Vmlinux: "/manual/vmlinux", BaseTag: f.old.BaseTag}
	f.b.cfg.Kernels = []KernelConfig{explicit}
	if err := os.Remove(f.packages); err != nil {
		t.Fatal(err)
	}
	for _, info := range []*model.BuildKernelInfo{nil, f.old} {
		k, err := f.b.resolveTaskKernel(model.BuildTask{Job: model.Job{Kernel: f.old.Kernel}, KernelInfo: info})
		if err != nil || !reflect.DeepEqual(k, explicit) {
			t.Fatalf("manual kernel settings must bypass automatic range: %+v %v", k, err)
		}
	}
	if f.b.lastWindow.latest != 0 {
		t.Fatal("manual kernel queried automatic range")
	}
	if _, err := os.Stat(f.calls); !os.IsNotExist(err) {
		t.Fatal("manual local inputs unexpectedly invoked installer")
	}
}

func TestQueuedTaskWindowFailureReusesHistoryOrInitiallyFailsOpen(t *testing.T) {
	for _, history := range []bool{false, true} {
		for _, metadata := range []bool{false, true} {
			t.Run(fmt.Sprintf("history=%v/metadata=%v", history, metadata), func(t *testing.T) {
				f := newTaskWindowFixture(t)
				if history {
					if _, err := f.b.resolveTaskKernel(model.BuildTask{Job: model.Job{Kernel: f.current.Kernel}, KernelInfo: f.current}); err != nil {
						t.Fatal(err)
					}
					if err := os.Remove(f.calls); err != nil {
						t.Fatal(err)
					}
				}
				if err := os.Remove(f.packages); err != nil {
					t.Fatal(err)
				}
				task := model.BuildTask{Job: model.Job{Kernel: f.old.Kernel}}
				if metadata {
					task.KernelInfo = f.old
				}
				k, err := f.b.resolveTaskKernel(task)
				if history {
					if err == nil || !strings.Contains(err.Error(), "빌더 범위 밖") {
						t.Fatalf("range outage bypassed retained range: %+v %v", k, err)
					}
					if _, err := os.Stat(f.calls); !os.IsNotExist(err) {
						t.Fatal("retained outside range invoked installer")
					}
				} else {
					if err != nil || k.Kernel != f.old.Kernel || k.BaseTag != f.old.BaseTag {
						t.Fatalf("initial outage changed existing fail-open lookup: %+v %v", k, err)
					}
					calls, err := os.ReadFile(f.calls)
					if err != nil || !strings.Contains(string(calls), f.old.Kernel) {
						t.Fatal("initial fail-open did not use normal input preparation", string(calls), err)
					}
				}
			})
		}
	}
}

func TestResolveTaskKernelUsesControllerInfoWithoutLookup(t *testing.T) {
	root := t.TempDir()
	info := taskKernelInfo()
	if err := os.MkdirAll(filepath.Join(root, "ubuntu-noble", ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "vmlinux-"+info.Kernel), []byte("debug"), 0o644); err != nil {
		t.Fatal(err)
	}
	// No client is configured: a redundant host-kernel lookup would fail.
	b := &Builder{cfg: &Config{Series: "noble", GitRoot: root, DebugDir: root}}
	k, err := b.resolveTaskKernel(model.BuildTask{Job: model.Job{Kernel: info.Kernel}, KernelInfo: info})
	if err != nil || k.BaseTag != info.BaseTag || k.Vmlinux != filepath.Join(root, "vmlinux-"+info.Kernel) || k.GitDir != filepath.Join(root, "ubuntu-noble") {
		t.Fatalf("must use exact controller base and local paths: %+v %v", k, err)
	}
	off := false
	b.cfg.ControllerKernelInputs, b.cfg.AutoDebugSymbols = true, &off
	b.cfg.DebugHelper = filepath.Join(root, "missing-helper")
	if _, err := b.resolveTaskKernel(model.BuildTask{Job: model.Job{Kernel: info.Kernel}, KernelInfo: info}); err != nil {
		t.Fatalf("disabling automatic installation must still allow prepared inputs: %v", err)
	}
	b.cfg.Series = "jammy"
	if _, err := b.resolveTaskKernel(model.BuildTask{Job: model.Job{Kernel: info.Kernel}, KernelInfo: info}); err == nil {
		t.Fatal("controller info must not bypass the series check")
	}
}

func TestResolveTaskKernelPreservesExplicitAndLegacyInputs(t *testing.T) {
	info := taskKernelInfo()
	explicit := KernelConfig{Kernel: info.Kernel, GitDir: "/local/kernel", Vmlinux: "/local/debug", BaseTag: info.BaseTag}
	b := &Builder{cfg: &Config{Kernels: []KernelConfig{explicit}}}
	for _, metadata := range []*model.BuildKernelInfo{nil, info} {
		k, err := b.resolveTaskKernel(model.BuildTask{Job: model.Job{Kernel: info.Kernel}, KernelInfo: metadata})
		if err != nil || k.BaseTag != explicit.BaseTag || k.GitDir != explicit.GitDir || k.Vmlinux != explicit.Vmlinux {
			t.Fatalf("explicit local settings changed: %+v %v", k, err)
		}
	}
	b.cfg.Kernels[0].BaseTag = ""
	k, err := b.resolveTaskKernel(model.BuildTask{Job: model.Job{Kernel: info.Kernel}, KernelInfo: info})
	if err != nil || k.BaseTag != info.BaseTag {
		t.Fatalf("missing explicit base should use controller base: %+v %v", k, err)
	}
	b.cfg.Kernels[0].BaseTag = "Ubuntu-6.8.0-987654.987654"
	if _, err := b.resolveTaskKernel(model.BuildTask{Job: model.Job{Kernel: info.Kernel}, KernelInfo: info}); err == nil {
		t.Fatal("conflicting configured base must not silently change")
	}
}

func TestBuildRejectsInvalidInputBeforeWritingOrCompiling(t *testing.T) {
	for _, kind := range []string{"content", "size", "filename", "legacy traversal", "kernel"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			info := taskKernelInfo()
			patch := model.NewTaskPatch("p0001", []byte("patch"))
			switch kind {
			case "content":
				patch.Content = "other"
			case "size":
				patch.Size++
			case "filename":
				patch.Filename = "../other.patch"
			case "legacy traversal":
				patch = model.TaskPatch{ID: "../../other", Content: "patch"}
			case "kernel":
				info.BaseTag = "Ubuntu-6.8.0-987655.987655"
			}
			b := &Builder{cfg: &Config{WorkDir: root}}
			result := b.build(model.BuildTask{Job: model.Job{ID: 1, Kernel: info.Kernel}, Patches: []model.TaskPatch{patch}, KernelInfo: info})
			if result.Success || result.Error == "" || result.Deferred {
				t.Fatalf("invalid input must fail: %+v", result)
			}
			entries, err := os.ReadDir(root)
			if err != nil || len(entries) != 0 {
				t.Fatalf("must reject before creating files or invoking compiler: %v %v", entries, err)
			}
		})
	}
}

func TestResolveTaskKernelDoesNotFallbackWhenPinnedInputsMissing(t *testing.T) {
	info := taskKernelInfo()
	b := &Builder{cfg: &Config{Series: "noble", GitRoot: t.TempDir()}}
	_, err := b.resolveTaskKernel(model.BuildTask{Job: model.Job{Kernel: info.Kernel}, KernelInfo: info})
	if err == nil || !strings.Contains(err.Error(), "커널 git") {
		t.Fatalf("missing pinned input must fail without a repository-source fallback: %v", err)
	}
}

func TestInstallDebugRequestsControllerDeliveryExplicitly(t *testing.T) {
	root := t.TempDir()
	helper := filepath.Join(root, "debug-helper")
	if err := os.WriteFile(helper, nil, 0o755); err != nil {
		t.Fatal(err)
	}
	argsFile := filepath.Join(root, "arguments")
	t.Setenv("KPCTL_INPUT_TEST_ARGS", argsFile)
	if err := os.WriteFile(filepath.Join(root, "sudo"), []byte("#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$KPCTL_INPUT_TEST_ARGS\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", root+string(os.PathListSeparator)+os.Getenv("PATH"))
	on := true
	b := &Builder{cfg: &Config{AutoDebugSymbols: &on, DebugHelper: helper, ControllerKernelInputs: true}}
	info := taskKernelInfo()
	if err := b.installDebug(info.Kernel, info.PackageVersion); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(argsFile)
	want := "-n\n" + helper + "\n--controller\n" + info.Kernel + "\n" + info.PackageVersion + "\n"
	if err != nil || string(got) != want {
		t.Fatalf("controller mode must be explicit so old helpers fail instead of downloading externally: %q %v", got, err)
	}
	if err := os.Remove(argsFile); err != nil {
		t.Fatal(err)
	}
	if err := b.installDebug(info.Kernel, ""); err == nil {
		t.Fatal("controller mode cannot guess a package version")
	}
	if _, err := os.Stat(argsFile); !os.IsNotExist(err) {
		t.Fatal("missing version must not invoke a helper")
	}
	b.cfg.Kernels = []KernelConfig{{Kernel: info.Kernel, GitDir: root, BaseTag: info.BaseTag}}
	if _, err := b.resolveTaskKernel(model.BuildTask{Job: model.Job{Kernel: info.Kernel}, KernelInfo: info}); err != nil {
		t.Fatalf("explicitly configured GA kernels must also receive controller files: %v", err)
	}
	got, err = os.ReadFile(argsFile)
	if err != nil || string(got) != want {
		t.Fatalf("explicit kernel skipped controller input preparation: %q %v", got, err)
	}
}
