// 이 파일: 실제 로컬 Git 이력과 가짜 APT·HTTP로 CNA 매핑의 수집 연결을 검증합니다.
// 커널 컴파일·실제 취약점 차단 검증은 포함하지 않습니다.
package builder

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"kpctl/internal/model"
)

const (
	feedMappedUpstream      = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	feedDyadUpstream        = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	feedMainUpstream        = "cccccccccccccccccccccccccccccccccccccccc"
	feedIntroducedUpstream  = "dddddddddddddddddddddddddddddddddddddddd"
	feedUnpublishedUpstream = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	feedLateUpstream        = "ffffffffffffffffffffffffffffffffffffffff"
)

type cveFeedFixture struct {
	b                *Builder
	kernel           KernelConfig
	repository, feed string
	commits          map[string]string
	record           *prereleaseRecorder
}

func writeCVEFeedFixtureFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func (fixture *cveFeedFixture) commit(t *testing.T, name, file, message string) string {
	t.Helper()
	writeCVEFeedFixtureFile(t, filepath.Join(fixture.repository, file), "int "+name+";\n")
	run(t, fixture.repository, "add", ".")
	run(t, fixture.repository, "commit", "-qm", message)
	sha, err := git(fixture.repository, "rev-parse", "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	fixture.commits[name] = strings.TrimSpace(sha)
	return fixture.commits[name]
}

func newCVEFeedFixture(t *testing.T) *cveFeedFixture {
	t.Helper()
	fakePublishedAPT(t, "noble", "6.8.0-86.86")
	root := t.TempDir()
	fixture := &cveFeedFixture{repository: filepath.Join(root, "kernel"), feed: filepath.Join(root, "feed"), commits: map[string]string{}}
	if err := os.MkdirAll(fixture.repository, 0o755); err != nil {
		t.Fatal(err)
	}
	run(t, fixture.repository, "init", "-q")
	fixture.commit(t, "base", "net/base.c", "base")
	run(t, fixture.repository, "tag", "Ubuntu-6.8.0-85.85")
	fixture.commit(t, "mapped", "net/mapped.c", "net: repair bounds\n\n(cherry picked from commit "+feedMappedUpstream+")")
	fixture.commit(t, "dyad", "net/dyad.c", "net: stable backport\n\n(backported from commit "+feedDyadUpstream+")")
	fixture.commit(t, "square", "net/square.c", "net: repair lifetime\n\n[ Upstream commit "+feedMappedUpstream+" ]")
	fixture.commit(t, "upstream", "net/upstream.c", "net: repair reference\n\ncommit "+feedMappedUpstream+" upstream.")
	fixture.commit(t, "outside", "drivers/outside.c", "driver: repair bounds\n\n(cherry picked from commit "+feedMappedUpstream+")")
	fixture.commit(t, "introduced", "net/introduced.c", "net: unrelated change\n\n(cherry picked from commit "+feedIntroducedUpstream+")")
	fixture.commit(t, "body", "net/body.c", "net: mention historical hash\n\nDiscussion refers to "+feedMappedUpstream+" for background.")
	fixture.commit(t, "fixes", "net/fixes.c", "net: unrelated cleanup\n\nFixes: "+feedMappedUpstream+" (historic change)")
	fixture.commit(t, "short", "net/short.c", "net: abbreviated reference\n\n(cherry picked from commit "+feedMappedUpstream[:12]+")")
	fixture.commit(t, "unpublished", "net/unpublished.c", "net: unconfirmed mapping\n\n(cherry picked from commit "+feedUnpublishedUpstream+")")
	fixture.commit(t, "late", "net/late.c", "net: mapping added later\n\n(cherry picked from commit "+feedLateUpstream+")")
	fixture.commit(t, "message", "net/message.c", "net: CVE-2026-41005 repair")
	fixture.commit(t, "merged", "net/merged.c", "net: CVE-2026-41006 repair\n\n(cherry picked from commit "+feedMappedUpstream+")")
	run(t, fixture.repository, "tag", "Ubuntu-6.8.0-86.86")
	run(t, fixture.repository, "remote", "add", "origin", fixture.repository)
	// 실제 kernel.org vulns clone에서 확인한 published .sha1 및 dyad 형식입니다.
	// .sha1은 끝 개행이 없어도 읽을 수 있어야 하며 dyad 두 번째 열은 introduced입니다.
	writeCVEFeedFixtureFile(t, filepath.Join(fixture.feed, "cve/published/2026/CVE-2026-41001.sha1"), feedMappedUpstream)
	writeCVEFeedFixtureFile(t, filepath.Join(fixture.feed, "cve/published/2026/CVE-2026-41002.sha1"), feedMainUpstream+"\n")
	writeCVEFeedFixtureFile(t, filepath.Join(fixture.feed, "cve/published/2026/CVE-2026-41002.dyad"), "# dyad version: 1.2.0\n5.15:"+feedIntroducedUpstream+":6.8:"+feedDyadUpstream+"\n")
	writeCVEFeedFixtureFile(t, filepath.Join(fixture.feed, "cve/rejected/2026/CVE-2026-41003.sha1"), feedUnpublishedUpstream)
	run(t, fixture.feed, "init", "-q")
	run(t, fixture.feed, "add", ".")
	run(t, fixture.feed, "commit", "-qm", "published kernel CNA mappings")
	fixture.kernel = KernelConfig{Kernel: "6.8.0-85-generic", GitDir: fixture.repository, BaseTag: "Ubuntu-6.8.0-85.85", TagGlob: "Ubuntu-6.8.0-*", Paths: []string{"net/"}}
	fixture.b = &Builder{cfg: &Config{WorkDir: root, Series: "noble", Kernels: []KernelConfig{fixture.kernel}, SkipTrialBuild: true, MaxTrialsPerRun: 10,
		CVEFeed: &CVEFeedConfig{Enabled: true, URL: fixture.feed}}}
	fixture.record = attachPrereleaseRecorder(t, fixture.b)
	return fixture
}

func TestCVEFeedDiscoveryMapsUnlabelledFixesAndPreservesPathFilter(t *testing.T) {
	fixture := newCVEFeedFixture(t)
	if more, err := fixture.b.discover(fixture.kernel); err != nil || more {
		t.Fatal(more, err)
	}
	if len(fixture.record.requests) != 1 || fixture.record.requests[0].Prerelease || fixture.record.requests[0].LatestTag != "Ubuntu-6.8.0-86.86" {
		t.Fatalf("unexpected discovered request: %+v", fixture.record.requests)
	}
	patches := map[string]model.DiscoveredPatch{}
	for _, patch := range fixture.record.requests[0].Patches {
		patches[patch.Commit] = patch
	}
	wanted := map[string][]string{
		"mapped": {"CVE-2026-41001"}, "dyad": {"CVE-2026-41002"},
		"square": {"CVE-2026-41001"}, "upstream": {"CVE-2026-41001"},
		"message": {"CVE-2026-41005"}, "merged": {"CVE-2026-41001", "CVE-2026-41006"},
	}
	if len(patches) != len(wanted) {
		t.Errorf("got %d candidates, want %d: %+v", len(patches), len(wanted), fixture.record.requests[0].Patches)
	}
	for name, cves := range wanted {
		patch, found := patches[fixture.commits[name]]
		if !found || !reflect.DeepEqual(patch.CVEs, cves) || patch.Content == "" {
			t.Errorf("%s: CVE mapping or full patch missing: %+v", name, patch)
		}
	}
	for _, name := range []string{"outside", "introduced", "body", "fixes", "short", "unpublished", "late"} {
		if patch, found := patches[fixture.commits[name]]; found {
			t.Errorf("%s incorrectly selected through path/hash mapping: %+v", name, patch)
		}
	}
}

func TestCVEFeedDisabledMatchesMessageOnlyDiscoveryAndDoesNotCreateCache(t *testing.T) {
	fixture := newCVEFeedFixture(t)
	fixture.b.cfg.CVEFeed = nil
	if _, err := fixture.b.discover(fixture.kernel); err != nil {
		t.Fatal(err)
	}
	baseline := append([]model.DiscoveredRequest(nil), fixture.record.requests...)
	fixture.record.requests, fixture.record.stable = nil, nil
	fixture.b.cfg.CVEFeed = &CVEFeedConfig{Enabled: false, URL: filepath.Join(t.TempDir(), "missing-feed")}
	if _, err := fixture.b.discover(fixture.kernel); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(baseline, fixture.record.requests) || len(baseline) != 1 || len(baseline[0].Patches) != 2 {
		t.Fatalf("disabled feed changed message-only collection: before=%+v after=%+v", baseline, fixture.record.requests)
	}
	if _, err := os.Stat(filepath.Join(fixture.b.cfg.WorkDir, "cve-feed")); !os.IsNotExist(err) {
		t.Fatal("disabled feed touched its cache", err)
	}
}

func TestCVEFeedUpdateFindsPreviouslyUnmappedCommit(t *testing.T) {
	fixture := newCVEFeedFixture(t)
	if _, err := fixture.b.discover(fixture.kernel); err != nil {
		t.Fatal(err)
	}
	writeCVEFeedFixtureFile(t, filepath.Join(fixture.feed, "cve/published/2026/CVE-2026-41007.sha1"), feedLateUpstream+"\n")
	run(t, fixture.feed, "add", ".")
	run(t, fixture.feed, "commit", "-qm", "publish mapping for prior upstream fix")
	if _, err := fixture.b.discover(fixture.kernel); err != nil {
		t.Fatal(err)
	}
	if len(fixture.record.requests) != 2 || len(fixture.record.requests[1].Patches) != 1 || fixture.record.requests[1].Patches[0].Commit != fixture.commits["late"] || !reflect.DeepEqual(fixture.record.requests[1].Patches[0].CVEs, []string{"CVE-2026-41007"}) {
		t.Fatalf("updated feed was not applied to unlabelled kernel commit: %+v", fixture.record.requests)
	}
}

func TestCVEFeedRefreshFailureStopsWithoutUsingCachedMappings(t *testing.T) {
	fixture := newCVEFeedFixture(t)
	if _, err := fixture.b.discover(fixture.kernel); err != nil {
		t.Fatal(err)
	}
	requestsBefore := len(fixture.record.requests)
	if err := os.Rename(fixture.feed, fixture.feed+"-offline"); err != nil {
		t.Fatal(err)
	}
	fixture.commit(t, "next", "net/next.c", "net: CVE-2026-41008 later published fix")
	run(t, fixture.repository, "tag", "Ubuntu-6.8.0-87.87")
	if more, err := fixture.b.discover(fixture.kernel); err == nil || more || !errors.Is(err, errBuildEnv) {
		t.Fatalf("unavailable feed should stop for review: more=%v err=%v", more, err)
	}
	if len(fixture.record.requests) != requestsBefore {
		t.Fatal("stale CNA cache was used after failed refresh")
	}
	problem := false
	for _, report := range fixture.record.upstream {
		if report.CollectedTag == "Ubuntu-6.8.0-87.87" {
			t.Error("feed failure advanced completed collection boundary")
		}
		problem = problem || (report.Problem != nil && *report.Problem != "")
	}
	if !problem {
		t.Fatal("feed refresh failure was not reported for review")
	}
}

func TestCVEFeedMappingAlsoWorksInSeparatePrereleaseChannel(t *testing.T) {
	fixture := newCVEFeedFixture(t)
	fixture.kernel.Prerelease = &PrereleaseConfig{Enabled: true, Branch: "master-next"}
	fixture.b.cfg.Kernels[0] = fixture.kernel
	run(t, fixture.repository, "tag", "-d", "Ubuntu-6.8.0-86.86")
	run(t, fixture.repository, "tag", "Ubuntu-6.8.0-86.86", fixture.commits["base"])
	run(t, fixture.repository, "branch", "master-next")
	if more, err := fixture.b.discoverPrerelease(fixture.kernel); err != nil || more {
		t.Fatal(more, err)
	}
	if len(fixture.record.requests) != 1 || !fixture.record.requests[0].Prerelease || fixture.record.requests[0].LatestTag != "" || len(fixture.record.upstream) != 0 {
		t.Fatalf("CNA mapping polluted formal state from prerelease channel: %+v", fixture.record.requests)
	}
	found := false
	for _, patch := range fixture.record.requests[0].Patches {
		found = found || patch.Commit == fixture.commits["mapped"]
	}
	if !found {
		t.Fatal("unlabelled prerelease fix was not mapped")
	}
	data, err := os.ReadFile(filepath.Join(fixture.b.cfg.WorkDir, "prerelease", fixture.kernel.Kernel+".json"))
	var evidence prereleaseEvidence
	if err != nil || json.Unmarshal(data, &evidence) != nil || evidence.Error != "" {
		t.Fatalf("prerelease mapping evidence missing: %s (%v)", data, err)
	}
}
