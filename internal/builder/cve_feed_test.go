// 이 파일: 공개 CNA 데이터 파서·upstream trailer·설정·Git 캐시 및 실제 clone 선택 검증.
package builder

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

type cveTarEntry struct {
	name, body string
	kind       byte
}

func unitCVEArchive(t *testing.T, entries ...cveTarEntry) []byte {
	t.Helper()
	var out bytes.Buffer
	writer := tar.NewWriter(&out)
	for _, entry := range entries {
		kind := entry.kind
		if kind == 0 {
			kind = tar.TypeReg
		}
		size := int64(len(entry.body))
		if kind != tar.TypeReg && kind != tar.TypeRegA {
			size = 0
		}
		header := &tar.Header{Name: entry.name, Size: size, Mode: 0o644, Typeflag: kind}
		if kind == tar.TypeSymlink || kind == tar.TypeLink {
			header.Linkname = "/private/do-not-follow"
		}
		if err := writer.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if size > 0 {
			if _, err := writer.Write([]byte(entry.body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}
func cveUnitContains(ids []string, want string) bool {
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}

func TestCVEFeedParsesPublishedFixesAndNeverIntroducedIDs(t *testing.T) {
	fixed, stable, introduced := strings.Repeat("a", 40), strings.Repeat("b", 40), strings.Repeat("c", 40)
	archive := unitCVEArchive(t,
		cveTarEntry{"cve/published/2099/CVE-2099-1234.sha1", fixed + "\n" + fixed + "\n", 0},
		cveTarEntry{"cve/published/2099/CVE-2099-1234.dyad", "# dyad version\n5.0:" + introduced + ":6.0:" + stable + "\n7.4:" + introduced + ":0:0\n0:0:6.1:" + stable + "\n", 0},
		cveTarEntry{"cve/published/2099/CVE-2099-1235.sha1", fixed + "\n", 0},
		cveTarEntry{"cve/published/2099/CVE-2099-1234.vulnerable", introduced, 0},
		cveTarEntry{"cve/rejected/2099/CVE-2099-9999.sha1", "malformed rejected record", 0},
		cveTarEntry{"cve/testing/published/2099/CVE-2099-9999.sha1", introduced, 0},
	)
	index, err := parseCVEFeedArchive(bytes.NewReader(archive))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(index[fixed], []string{"CVE-2099-1234", "CVE-2099-1235"}) || !reflect.DeepEqual(index[stable], []string{"CVE-2099-1234"}) || len(index[introduced]) != 0 || len(index) != 2 {
		t.Fatalf("공개 수정 ID 매핑 오류: %+v", index)
	}
}

func TestCVEFeedRejectsMalformedPublicRecordsWithoutLoggingTheirContents(t *testing.T) {
	sha := strings.Repeat("a", 40)
	cases := []cveTarEntry{
		{"cve/published/2099/CVE-2099-1234.sha1", "private-token-do-not-log", 0},
		{"cve/published/2099/CVE-2099-1234.sha1", "", 0},
		{"cve/published/2099/CVE-2099-1234.dyad", "malformed-private-token-do-not-log", 0},
		{"cve/published/2099/CVE-2099-1234.dyad", "5.0:not-a-sha:6.0:" + sha, 0},
		{"cve/published/2099/CVE-2099-1234.dyad", "5.0:" + sha + ":6.0:0", 0},
		{"cve/published/2099/CVE-2099-1234.dyad", "5.0:" + sha + ":0:" + sha, 0},
		{"cve/published/2098/CVE-2099-1234.sha1", sha, 0},
		{"cve/published/2099/nested/CVE-2099-1234.sha1", sha, 0},
		{"cve/published/2099/CVE-2099-1234.sha1", "", tar.TypeSymlink},
		{"cve/published/2099/CVE-2099-1234.dyad", "", tar.TypeLink},
		{"cve/published/2099/CVE-2099-1234.sha1", "", tar.TypeFifo},
	}
	for i, bad := range cases {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			archive := unitCVEArchive(t, cveTarEntry{"cve/published/2099/CVE-2099-9998.sha1", sha, 0}, bad)
			index, err := parseCVEFeedArchive(bytes.NewReader(archive))
			if err == nil || index != nil {
				t.Fatalf("잘못된 공개 매핑이 허용됨: %+v %v", index, err)
			}
			if strings.Contains(err.Error(), "private-token-do-not-log") || strings.Contains(err.Error(), "/private/") {
				t.Fatalf("feed 임의 내용/링크 경로가 로그 오류에 노출됨: %v", err)
			}
		})
	}
	duplicate := cveTarEntry{"cve/published/2099/CVE-2099-1234.sha1", sha, 0}
	if _, err := parseCVEFeedArchive(bytes.NewReader(unitCVEArchive(t, duplicate, duplicate))); err == nil {
		t.Fatal("중복 public record 허용")
	}
}

func TestCVEFeedBoundsArchiveAndFileSizes(t *testing.T) {
	var archive bytes.Buffer
	writer := tar.NewWriter(&archive)
	if err := writer.WriteHeader(&tar.Header{Name: "cve/published/2099/CVE-2099-1234.sha1", Size: cveFeedFileLimit + 1, Mode: 0o644}); err != nil {
		t.Fatal(err)
	}
	if _, err := parseCVEFeedArchive(bytes.NewReader(archive.Bytes())); err == nil {
		t.Fatal("과대한 mapping file 허용")
	}
	reader := &cveFeedReader{input: strings.NewReader("larger than configured limit"), left: 8}
	data, err := io.ReadAll(reader)
	if err == nil || len(data) != 8 {
		t.Fatalf("archive bound가 잘림을 정상 EOF로 처리함: %q %v", data, err)
	}
}

func TestCVEFeedOnlyExplicitFullUpstreamTrailersAreMapped(t *testing.T) {
	sha := strings.Repeat("a", 40)
	index := cveFeedIndex{sha: {"CVE-2099-1234", "CVE-2099-1235"}}
	for _, trailer := range []string{
		"(cherry picked from commit " + sha + ")",
		"(backported from commit " + sha + ")",
		"[ Upstream commit " + sha + " ]",
		"commit " + sha + " upstream.",
		"(cherry picked from commit " + strings.ToUpper(sha) + ")",
	} {
		got := mappedCVEs("kernel fix\n\n"+trailer+"\nSigned-off-by: Test <t@t>\nCVE-2099-1234", index)
		if !reflect.DeepEqual(got, []string{"CVE-2099-1234", "CVE-2099-1235"}) {
			t.Errorf("명시적 upstream trailer 매핑 실패: %q %+v", trailer, got)
		}
	}
	for _, body := range []string{"Fixes: " + sha, "Referenced commit " + sha, "quoted (cherry picked from commit " + sha + ")", "(cherry picked from commit " + sha[:12] + ")"} {
		if got := mappedCVEs(body, index); len(got) != 0 {
			t.Errorf("도입/본문/짧은 SHA를 수정으로 오인: %q %+v", body, got)
		}
	}
	if got := mappedCVEs("CVE-2099-1234 cve-2099-1234", nil); !reflect.DeepEqual(got, []string{"CVE-2099-1234"}) {
		t.Fatalf("feed 없이 기존 CVE 표기 결과 변경: %+v", got)
	}
}

func TestCVEFeedDisabledDoesNotTouchFilesystemOrGit(t *testing.T) {
	t.Setenv("PATH", filepath.Join(t.TempDir(), "no-git"))
	for _, cfg := range []*CVEFeedConfig{nil, {Enabled: false, URL: "invalid-but-disabled"}} {
		work := filepath.Join(t.TempDir(), "must-not-be-created")
		b := &Builder{cfg: &Config{WorkDir: work, CVEFeed: cfg}}
		if index, err := b.loadCVEFeed(); err != nil || index != nil {
			t.Fatalf("비활성 feed가 동작을 바꿈: %+v %v", index, err)
		}
		if _, err := os.Stat(work); !os.IsNotExist(err) {
			t.Fatalf("비활성 feed가 작업 디렉터리를 생성함: %v", err)
		}
	}
}

func unitCVEFeedRepo(t *testing.T, cve, sha string) string {
	t.Helper()
	repo := t.TempDir()
	dir := filepath.Join(repo, "cve/published/2099")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, cve+".sha1"), []byte(sha+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	run(t, repo, "init", "-q")
	run(t, repo, "add", ".")
	run(t, repo, "commit", "-qm", "feed fixture")
	return repo
}

func TestCVEFeedCachePinsCommitAndRefreshesWithoutStaleFallback(t *testing.T) {
	sha := strings.Repeat("a", 40)
	repo := unitCVEFeedRepo(t, "CVE-2099-1234", sha)
	b := &Builder{cfg: &Config{WorkDir: t.TempDir(), CVEFeed: &CVEFeedConfig{Enabled: true, URL: repo}}}
	first, err := b.loadCVEFeed()
	if err != nil {
		t.Fatal(err)
	}
	if !cveUnitContains(first[sha], "CVE-2099-1234") {
		t.Fatalf("초기 clone mapping 없음: %+v", first)
	}
	saved := b.cveFeedSnapshot
	if _, err := b.loadCVEFeed(); err != nil || b.cveFeedSnapshot != saved {
		t.Fatalf("동일 URL/HEAD의 index를 재사용하지 않음: %v", err)
	}
	secondFile := filepath.Join(repo, "cve/published/2099/CVE-2099-1235.sha1")
	if err := os.WriteFile(secondFile, []byte(sha+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	run(t, repo, "add", ".")
	run(t, repo, "commit", "-qm", "new published CVE")
	second, err := b.loadCVEFeed()
	if err != nil {
		t.Fatal(err)
	}
	if b.cveFeedSnapshot.commit == saved.commit || !cveUnitContains(second[sha], "CVE-2099-1235") {
		t.Fatalf("새 remote HEAD를 반영하지 않음: %+v", second)
	}
	moved := repo + "-offline"
	if err := os.Rename(repo, moved); err != nil {
		t.Fatal(err)
	}
	defer os.Rename(moved, repo)
	if index, err := b.loadCVEFeed(); err == nil || index != nil {
		t.Fatalf("갱신 실패에도 stale cache로 수집을 진행함: %+v %v", index, err)
	}
}

func TestCVEFeedSourceChangesCannotReuseAnotherRepositoryMapping(t *testing.T) {
	sha := strings.Repeat("a", 40)
	first := unitCVEFeedRepo(t, "CVE-2099-1234", sha)
	second := unitCVEFeedRepo(t, "CVE-2099-5678", sha)
	b := &Builder{cfg: &Config{WorkDir: t.TempDir(), CVEFeed: &CVEFeedConfig{Enabled: true, URL: first}}}
	if _, err := b.loadCVEFeed(); err != nil {
		t.Fatal(err)
	}
	b.cfg.CVEFeed.URL = second
	index, err := b.loadCVEFeed()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(index[sha], []string{"CVE-2099-5678"}) {
		t.Fatalf("다른 feed URL의 mapping이 섞임: %+v", index)
	}
}

func TestCVEFeedConfigIsOptionalStrictAndDefaultsToOfficialSource(t *testing.T) {
	for _, tc := range []struct {
		name, extra string
		wantError   bool
	}{
		{"생략", "", false},
		{"기본 URL", `,"cve_feed":{"enabled":false}`, false},
		{"HTTPS", `,"cve_feed":{"enabled":true,"url":"https://mirror.example/vulns.git"}`, false},
		{"오타", `,"cve_feed":{"enabeld":true}`, true},
		{"값 타입", `,"cve_feed":{"enabled":"true"}`, true},
		{"외부 helper", `,"cve_feed":{"enabled":true,"url":"ext::untrusted"}`, true},
		{"평문 HTTP", `,"cve_feed":{"enabled":true,"url":"http://mirror.example/vulns.git"}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := `{"controller_url":"https://controller","token":"token","series":"noble","work_dir":"` + t.TempDir() + `"` + tc.extra + `}`
			cfg, err := LoadConfig(writeConfig(t, body))
			if (err != nil) != tc.wantError {
				t.Fatalf("설정 오류=%v, want=%v", err, tc.wantError)
			}
			if err == nil && tc.name == "기본 URL" && (cfg.CVEFeed == nil || cfg.CVEFeed.Enabled || cfg.CVEFeed.URL != defaultCVEFeedURL) {
				t.Fatalf("기본 feed 설정: %+v", cfg.CVEFeed)
			}
		})
	}
}

func TestSystemCVEFeedCloneParser(t *testing.T) {
	repo := os.Getenv("KPCTL_TEST_CVE_FEED_REPO")
	if repo == "" {
		t.Skip("실제 clone 파싱은 KPCTL_TEST_CVE_FEED_REPO로 명시 실행")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	commit, err := cveFeedGit(ctx, repo, "rev-parse", "--verify", "HEAD^{commit}")
	if err != nil {
		t.Fatal(err)
	}
	commit = strings.TrimSpace(commit)
	index, err := readCVEFeedIndex(ctx, repo, commit)
	if err != nil {
		t.Fatal(err)
	}
	if !cveUnitContains(index["5578de4834fe0f2a34fedc7374be691443396d1f"], "CVE-2019-25160") || cveUnitContains(index["446fda4f26822b2d42ab3396aafcedf38a9ff2b6"], "CVE-2019-25160") {
		t.Fatal("실제 공개 기록의 fix/introduction 판정 오류")
	}
	t.Logf("실제 clone HEAD=%s mapped_commits=%d; 공개 SHA/본문 파싱만 검증(커널 실행 아님)", commit, len(index))
}
