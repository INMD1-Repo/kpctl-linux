// 이 파일: 실제 Git·가짜 APT/HTTP/컴파일 도구로 출시 전 수집의 경계와 채널 분리를 검증합니다.
package builder

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"kpctl/internal/client"
	"kpctl/internal/model"
)

type prereleaseRecorder struct {
	mu       sync.Mutex
	requests []model.DiscoveredRequest
	upstream []model.UpstreamReport
	queries  []string
	stable   []model.DiscoveredPatch
	preview  []model.DiscoveredPatch
	allCalls int
}

func (record *prereleaseRecorder) serveHTTP(w http.ResponseWriter, r *http.Request) {
	record.mu.Lock()
	defer record.mu.Unlock()
	record.allCalls++
	switch {
	case strings.HasSuffix(r.URL.Path, "/known"):
		record.queries = append(record.queries, r.URL.RawQuery)
		active := append([]model.DiscoveredPatch(nil), record.stable...)
		if r.URL.Query().Get("prerelease") == "true" {
			active = append(active, record.preview...)
		}
		response := model.KnownCommitsResponse{ActivePatches: active}
		for _, patch := range active {
			response.Commits = append(response.Commits, patch.Commit)
		}
		_ = json.NewEncoder(w).Encode(response)
	case strings.HasSuffix(r.URL.Path, "/discovered"):
		var request model.DiscoveredRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		record.requests = append(record.requests, request)
		if request.Prerelease {
			record.preview = append(record.preview, request.Patches...)
		} else {
			record.stable = append(record.stable, request.Patches...)
		}
		_ = json.NewEncoder(w).Encode(model.DiscoveredResponse{AddedPatches: len(request.Patches), JobID: len(record.requests)})
	case strings.HasSuffix(r.URL.Path, "/upstream"):
		var report model.UpstreamReport
		_ = json.NewDecoder(r.Body).Decode(&report)
		record.upstream = append(record.upstream, report)
		_, _ = w.Write([]byte(`{}`))
	default:
		_, _ = w.Write([]byte(`{}`))
	}
}

func attachPrereleaseRecorder(t *testing.T, b *Builder) *prereleaseRecorder {
	t.Helper()
	record := &prereleaseRecorder{}
	server := httptest.NewServer(http.HandlerFunc(record.serveHTTP))
	t.Cleanup(server.Close)
	b.cfg.ControllerURL, b.cfg.Token = server.URL, "builder-token"
	var err error
	b.c, err = client.New(server.URL, "builder-token", "")
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func prereleaseFixture(t *testing.T) (*Builder, KernelConfig, string, map[string]string, *prereleaseRecorder) {
	t.Helper()
	fakePublishedAPT(t, "noble", "6.8.0-86.86")
	root := t.TempDir()
	upstream := filepath.Join(root, "origin")
	if err := os.MkdirAll(upstream, 0o755); err != nil {
		t.Fatal(err)
	}
	run(t, upstream, "init", "-q")
	commit := func(name, file, content, message string) string {
		t.Helper()
		path := filepath.Join(upstream, file)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		run(t, upstream, "add", ".")
		run(t, upstream, "commit", "-qm", message)
		sha, err := git(upstream, "rev-parse", "HEAD")
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(sha)
	}
	commits := map[string]string{}
	commits["base"] = commit("base", "net/base.c", "int base;\n", "base")
	run(t, upstream, "tag", "Ubuntu-6.8.0-85.85")
	commits["official"] = commit("official", "net/official.c", "int official;\n", "CVE-2026-1001 official fix")
	run(t, upstream, "tag", "Ubuntu-6.8.0-86.86")
	commits["preview"] = commit("preview", "net/preview.c", "int preview;\n", "CVE-2026-1002 preview fix")
	commits["unlabelled"] = commit("unlabelled", "net/unlabelled.c", "int unlabelled;\n", "unlabelled cleanup")
	commits["excluded"] = commit("excluded", "drivers/excluded.c", "int excluded;\n", "CVE-2026-1003 excluded driver")
	run(t, upstream, "tag", "Ubuntu-6.8.0-999.999")
	run(t, upstream, "branch", "master-next")
	repo := filepath.Join(root, "clone")
	run(t, root, "clone", "-q", upstream, repo)
	kernel := KernelConfig{Kernel: "6.8.0-85-generic", GitDir: repo, BaseTag: "Ubuntu-6.8.0-85.85", TagGlob: "Ubuntu-6.8.0-*", Paths: []string{"net/"}, Prerelease: &PrereleaseConfig{Enabled: true, Branch: "master-next", PollMinutes: 30}}
	b := &Builder{cfg: &Config{WorkDir: root, Series: "noble", Kernels: []KernelConfig{kernel}, SkipTrialBuild: true, MaxTrialsPerRun: 10}}
	record := attachPrereleaseRecorder(t, b)
	return b, kernel, upstream, commits, record
}

func TestPrereleaseConfigDefaultsAndUnknownKeys(t *testing.T) {
	for _, tc := range []struct {
		name, block string
		wantError   bool
	}{
		{"omitted", "", false}, {"empty", `,"prerelease":{}`, false},
		{"enabled", `,"prerelease":{"enabled":true}`, false},
		{"disabled", `,"prerelease":{"enabled":false}`, false},
		{"branch", `,"prerelease":{"enabled":true,"branch":"ubuntu/master-next","poll_minutes":15}`, false},
		{"unknown", `,"prerelease":{"enabled":true,"poll_minute":30}`, true},
		{"invalid branch", `,"prerelease":{"branch":"../bad"}`, true},
		{"negative interval", `,"prerelease":{"poll_minutes":-1}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := `{"controller_url":"https://controller","token":"token","work_dir":"` + t.TempDir() + `","kernels":[{"kernel":"6.8.0-85-generic","git_dir":"/repo","base_tag":"Ubuntu-6.8.0-85.85","tag_glob":"Ubuntu-6.8.0-*"` + tc.block + `}]}`
			cfg, err := LoadConfig(writeConfig(t, body))
			if (err != nil) != tc.wantError {
				t.Fatalf("error=%v wantError=%v", err, tc.wantError)
			}
			if err == nil && tc.name != "omitted" && tc.name != "branch" {
				pre := cfg.Kernels[0].Prerelease
				if pre.Branch != "master-next" || pre.PollMinutes != 30 {
					t.Fatalf("defaults=%+v", pre)
				}
			}
		})
	}
}

func TestPrereleaseDisabledHasNoCallsAndKeepsLegacyCollectionIdentical(t *testing.T) {
	b, kernel, _, _, record := prereleaseFixture(t)
	kernel.Prerelease.Enabled = false
	b.cfg.Kernels[0] = kernel
	if b.DiscoverPrereleases() {
		t.Fatal("disabled prerelease scheduler ran")
	}
	if more, err := b.discoverPrerelease(kernel); err != nil || more || record.allCalls != 0 {
		t.Fatalf("disabled collector had side effects: more=%v err=%v calls=%d", more, err, record.allCalls)
	}
	if _, err := b.discover(kernel); err != nil {
		t.Fatal(err)
	}
	withDisabled := append([]model.DiscoveredRequest(nil), record.requests...)
	record.requests, record.stable, record.preview = nil, nil, nil
	kernel.Prerelease = nil
	b.cfg.Kernels[0] = kernel
	if _, err := b.discover(kernel); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(withDisabled, record.requests) || len(record.requests) != 1 || record.requests[0].LatestTag != "Ubuntu-6.8.0-999.999" {
		t.Fatalf("disabled changed explicit legacy collection: disabled=%+v omitted=%+v", withDisabled, record.requests)
	}
}

func TestPrereleaseUsesExactPublishedBoundaryAndSeparateChannel(t *testing.T) {
	b, kernel, _, commits, record := prereleaseFixture(t)
	b.lastTarget = map[string]string{kernel.Kernel: "unchanged-formal-tag"}
	b.lastProblem = map[string]string{kernel.Kernel: "formal review remains"}
	if more, err := b.discoverPrerelease(kernel); err != nil || more {
		t.Fatal(more, err)
	}
	if len(record.requests) != 1 || !record.requests[0].Prerelease || record.requests[0].LatestTag != "" || len(record.requests[0].Patches) != 1 || record.requests[0].Patches[0].Commit != commits["preview"] {
		t.Fatalf("wrong prerelease candidates/channel: %+v", record.requests)
	}
	if len(record.upstream) != 0 || len(record.queries) != 1 || record.queries[0] != "prerelease=true" || b.lastTarget[kernel.Kernel] != "unchanged-formal-tag" || b.lastProblem[kernel.Kernel] != "formal review remains" {
		t.Fatalf("prerelease modified formal state: upstream=%+v queries=%v", record.upstream, record.queries)
	}
	var evidence prereleaseEvidence
	data, err := os.ReadFile(filepath.Join(b.cfg.WorkDir, "prerelease", kernel.Kernel+".json"))
	if err != nil || json.Unmarshal(data, &evidence) != nil || evidence.PublishedTag != "Ubuntu-6.8.0-86.86" || evidence.TipCommit != commits["excluded"] || evidence.Error != "" {
		t.Fatalf("missing exact provenance evidence: %s (%v)", data, err)
	}
}

func TestPrereleaseEnabledAlsoBoundsFormalCollectionToAPT(t *testing.T) {
	b, kernel, _, commits, record := prereleaseFixture(t)
	if _, err := b.discover(kernel); err != nil {
		t.Fatal(err)
	}
	if len(record.requests) != 1 || record.requests[0].Prerelease || record.requests[0].LatestTag != "Ubuntu-6.8.0-86.86" || len(record.requests[0].Patches) != 1 || record.requests[0].Patches[0].Commit != commits["official"] {
		t.Fatalf("formal collection swallowed prerelease commits: %+v", record.requests)
	}
	if _, err := b.discoverPrerelease(kernel); err != nil {
		t.Fatal(err)
	}
	if len(record.requests) != 2 || !record.requests[1].Prerelease || len(record.requests[1].Patches) != 1 || record.requests[1].Patches[0].Commit != commits["preview"] {
		t.Fatalf("separate prerelease collection failed: %+v", record.requests)
	}
}

func TestPrereleaseCommitMovesToFormalAndIsNotCollectedAgain(t *testing.T) {
	b, kernel, upstream, commits, record := prereleaseFixture(t)
	if _, err := b.discoverPrerelease(kernel); err != nil {
		t.Fatal(err)
	}
	run(t, upstream, "tag", "Ubuntu-6.8.0-87.87", commits["preview"])
	fakePublishedAPT(t, "noble", "6.8.0-87.87")
	if _, err := b.discover(kernel); err != nil {
		t.Fatal(err)
	}
	if _, err := b.discoverPrerelease(kernel); err != nil {
		t.Fatal(err)
	}
	pre, stable := 0, 0
	formalCommit := false
	for _, request := range record.requests {
		if request.Prerelease {
			pre++
		} else {
			stable++
			for _, patch := range request.Patches {
				formalCommit = formalCommit || patch.Commit == commits["preview"]
			}
		}
	}
	if pre != 1 || stable != 1 || !formalCommit || b.lastTarget[kernel.Kernel] != "Ubuntu-6.8.0-87.87" {
		t.Fatalf("released commit did not move into formal collection: %+v", record.requests)
	}
}

func TestPrereleaseRejectsMissingPublicationBranchAndDivergedHistory(t *testing.T) {
	for _, kind := range []string{"missing published tag", "missing branch", "diverged branch"} {
		t.Run(kind, func(t *testing.T) {
			b, kernel, upstream, commits, record := prereleaseFixture(t)
			switch kind {
			case "missing published tag":
				fakePublishedAPT(t, "noble", "6.8.0-87.87")
			case "missing branch":
				kernel.Prerelease.Branch = "does-not-exist"
			case "diverged branch":
				run(t, upstream, "branch", "-f", "master-next", commits["base"])
			}
			if more, err := b.discoverPrerelease(kernel); err == nil || more {
				t.Fatalf("unverified boundary should stop: more=%v err=%v", more, err)
			}
			if len(record.requests) != 0 || len(record.upstream) != 0 {
				t.Fatal("unverified prerelease altered formal state or posted patches")
			}
		})
	}
}

func TestPrereleaseSchedulerUsesIndependentPerKernelInterval(t *testing.T) {
	b, _, _, _, record := prereleaseFixture(t)
	b.cfg.DiscoverMinutes = intp(0)
	now := time.Now()
	if !b.discoverPrereleasesAt(now) || b.discoverPrereleasesAt(now.Add(time.Minute)) || !b.discoverPrereleasesAt(now.Add(31*time.Minute)) {
		t.Fatal("prerelease interval did not run independently of disabled formal collection")
	}
	if len(record.queries) != 2 || len(record.requests) != 1 {
		t.Fatalf("unexpected polling/deduplication: queries=%v requests=%+v", record.queries, record.requests)
	}
}

func TestPrereleaseFailurePreservesFormalReviewAndTrialEvidence(t *testing.T) {
	b, kernel, _, first, _ := dependencyFixture(t)
	kernel.Prerelease = &PrereleaseConfig{Enabled: true, Branch: "master-next"}
	b.cfg.Kernels = []KernelConfig{kernel}
	run(t, kernel.GitDir, "branch", "master-next")
	fakePublishedAPT(t, "noble", "6.8.0-85.85")
	record := attachPrereleaseRecorder(t, b)
	b.lastProblem = map[string]string{kernel.Kernel: "formal review must remain"}
	if err := b.saveTrialFailure(kernel.Kernel, "formal-commit", "formal-fingerprint", errors.New("formal failure")); err != nil {
		t.Fatal(err)
	}
	formalPath := b.trialFailurePath(kernel.Kernel)
	before, err := os.ReadFile(formalPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b.cfg.KpatchBuild, []byte("#!/bin/sh\necho 'foo.c: error: unknown type name'\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if more, err := b.discoverPrerelease(kernel); err == nil || more {
		t.Fatalf("unknown trial failure did not stop prerelease: more=%v err=%v", more, err)
	}
	after, err := os.ReadFile(formalPath)
	if err != nil || string(after) != string(before) || b.lastProblem[kernel.Kernel] != "formal review must remain" || len(record.upstream) != 0 || len(record.requests) != 0 {
		t.Fatal("prerelease failure overwrote official evidence/state", err)
	}
	preLog := filepath.Join(b.cfg.WorkDir, "prerelease-trial-"+first.Commit[:12], "build.log")
	if data, err := os.ReadFile(preLog); err != nil || !strings.Contains(string(data), "unknown type name") {
		t.Fatalf("prerelease review log missing: %s (%v)", data, err)
	}
	var evidence prereleaseEvidence
	data, err := os.ReadFile(filepath.Join(b.cfg.WorkDir, "prerelease", kernel.Kernel+".json"))
	if err != nil || json.Unmarshal(data, &evidence) != nil || evidence.Error == "" || evidence.Failure == nil || evidence.Failure.Commit != first.Commit {
		t.Fatalf("prerelease failure not recorded for review: %s (%v)", data, err)
	}
}

func TestPrereleaseModuleNamesAndCapability(t *testing.T) {
	valid := regexp.MustCompile(`^kpctl_[a-z0-9_]+_pre[0-9]+$`)
	for _, version := range []int{-1, -27, -int(^uint(0)>>1) - 1} {
		name := moduleName(strings.Repeat("long-kernel-", 10), version)
		if !valid.MatchString(name) || len(name) > 55 {
			t.Fatalf("invalid prerelease module name: version=%d name=%q", version, name)
		}
	}
	if got := moduleName("6.8.0-85-generic", 3); got != "kpctl_6_8_0_85_generic_v3" {
		t.Fatal("formal module naming changed", got)
	}
	b := &Builder{cfg: &Config{Name: "builder"}}
	if !b.identity().CanPrerelease {
		t.Fatal("updated builder does not advertise prerelease capability")
	}
}

func TestPrereleasePreparesConfiguredInputsWithoutFormalDiscovery(t *testing.T) {
	b, kernel, _, _, _ := prereleaseFixture(t)
	root := t.TempDir()
	kernel.Vmlinux = filepath.Join(root, "vmlinux")
	b.cfg.Kernels[0] = kernel
	b.cfg.SkipTrialBuild, b.cfg.ControllerKernelInputs, b.cfg.KernelCleanupFreeGiB = false, true, -1
	on := true
	b.cfg.AutoDebugSymbols = &on
	b.cfg.DebugHelper = filepath.Join(root, "debug-helper")
	calls := filepath.Join(root, "debug.calls")
	t.Setenv("KPCTL_PRERELEASE_PREPARE_CALLS", calls)
	t.Setenv("KPCTL_PRERELEASE_VMLINUX", kernel.Vmlinux)
	for file, body := range map[string]string{
		"debug-helper": "#!/bin/sh\nprintf '%s\\n' \"$*\" > \"$KPCTL_PRERELEASE_PREPARE_CALLS\"\nprintf debug > \"$KPCTL_PRERELEASE_VMLINUX\"\n",
		"sudo":         "#!/bin/sh\n[ \"$1\" = -n ] && shift\nexec \"$@\"\n",
	} {
		if err := os.WriteFile(filepath.Join(root, file), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", root+string(os.PathListSeparator)+os.Getenv("PATH"))
	// 나머지 빌드 준비는 이 fixture에 없으므로 실패해도 됩니다. 실제 대상 입력을
	// 먼저 요청했으며 vmlinux 미설치만으로 조기 종료하지 않았는지를 확인합니다.
	_, _ = b.discoverPrerelease(kernel)
	data, err := os.ReadFile(calls)
	if err != nil || strings.TrimSpace(string(data)) != "--controller "+kernel.Kernel+" 6.8.0-85.85" {
		t.Fatalf("pre-only collection skipped exact configured input preparation: %s (%v)", data, err)
	}
	if _, err := os.Stat(kernel.Vmlinux); err != nil {
		t.Fatal("configured debug helper was not run", err)
	}
}
