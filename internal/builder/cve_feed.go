// 이 파일: 선택적 커널 CNA feed의 Git commit 고정, 공개 수정 ID 파싱과 Ubuntu trailer 대조.
package builder

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"
)

const defaultCVEFeedURL = "https://git.kernel.org/pub/scm/linux/security/vulns.git"
const cveFeedFileLimit = 1 << 20
const cveFeedArchiveLimit = 128 << 20

type CVEFeedConfig struct {
	Enabled bool   `json:"enabled"`
	URL     string `json:"url,omitempty"`
}
type cveFeedIndex map[string][]string

type cveFeedSnapshot struct {
	source, commit string
	index          cveFeedIndex
}

func validateCVEFeedSource(source string) error {
	if strings.ContainsAny(source, "\x00\r\n") || source == "" {
		return fmt.Errorf("cve_feed.url이 비었거나 잘못됐습니다")
	}
	if filepath.IsAbs(source) {
		return nil
	}
	parsed, err := url.Parse(source)
	if err == nil && ((parsed.Scheme == "https" && parsed.Host != "") || (parsed.Scheme == "file" && (parsed.Host == "" || parsed.Host == "localhost") && filepath.IsAbs(parsed.Path))) {
		return nil
	}
	return fmt.Errorf("cve_feed.url은 HTTPS 주소 또는 로컬 Git 저장소의 절대 경로/file URL이어야 합니다")
}

// 비활성 상태에서는 경로 확인·디렉터리 생성·Git 실행을 전혀 하지 않습니다.
func (b *Builder) loadCVEFeed() (cveFeedIndex, error) {
	if b.cfg.CVEFeed == nil || !b.cfg.CVEFeed.Enabled {
		return nil, nil
	}
	source := b.cfg.CVEFeed.URL
	if source == "" {
		source = defaultCVEFeedURL
	}
	if err := validateCVEFeedSource(source); err != nil {
		return nil, err
	}
	ctx := b.runContext
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	root := filepath.Join(b.cfg.WorkDir, "cve-feed")
	if err := os.MkdirAll(root, 0o750); err != nil {
		return nil, fmt.Errorf("CVE feed 캐시 생성 실패: %w", err)
	}
	digest := sha256.Sum256([]byte(source))
	key := hex.EncodeToString(digest[:])
	lock, err := os.OpenFile(filepath.Join(root, key+".lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("CVE feed 캐시 잠금 파일 생성 실패: %w", err)
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, fmt.Errorf("%w: CVE feed 캐시 사용 중", errBuildBusy)
		}
		return nil, fmt.Errorf("CVE feed 캐시 잠금 실패: %w", err)
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	cache := filepath.Join(root, key)
	info, err := os.Lstat(cache)
	created := false
	if os.IsNotExist(err) {
		temp, err := os.MkdirTemp(root, ".clone-")
		if err != nil {
			return nil, err
		}
		defer os.RemoveAll(temp)
		// git clone -h의 --bare/--depth/--single-branch/-- 계약을 확인했습니다.
		// checkout하지 않아 feed의 symlink·필터·untracked 파일을 실행/추종하지 않습니다.
		if _, err := cveFeedGit(ctx, "", "clone", "--quiet", "--bare", "--depth=1", "--single-branch", "--", source, filepath.Join(temp, "repo")); err != nil {
			return nil, err
		}
		if err := os.Rename(filepath.Join(temp, "repo"), cache); err != nil {
			return nil, err
		}
		created = true
	} else if err != nil {
		return nil, err
	} else if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("CVE feed 캐시가 일반 Git 디렉터리가 아닙니다")
	}
	bare, err := cveFeedGit(ctx, cache, "rev-parse", "--is-bare-repository")
	if err != nil || strings.TrimSpace(bare) != "true" {
		return nil, fmt.Errorf("CVE feed 캐시가 bare 저장소가 아닙니다")
	}
	origin, err := cveFeedGit(ctx, cache, "config", "--get", "remote.origin.url")
	if err != nil || strings.TrimSpace(origin) != source {
		return nil, fmt.Errorf("CVE feed 캐시의 원본 URL이 설정과 다릅니다")
	}
	ref := "HEAD"
	if !created {
		// git fetch -h의 repository/refspec 계약: 원격 HEAD만 FETCH_HEAD로 받고
		// 운영 소스의 branch/tag/working tree를 변경하지 않습니다.
		if _, err := cveFeedGit(ctx, cache, "fetch", "--quiet", "--depth=1", "--no-tags", "origin", "HEAD"); err != nil {
			return nil, err
		}
		ref = "FETCH_HEAD"
	}
	commit, err := cveFeedGit(ctx, cache, "rev-parse", "--verify", ref+"^{commit}")
	if err != nil {
		return nil, err
	}
	commit = strings.TrimSpace(commit)
	if !fullCommit.MatchString(commit) {
		return nil, fmt.Errorf("CVE feed의 정확한 Git commit ID를 확인하지 못했습니다")
	}
	if saved := b.cveFeedSnapshot; saved != nil && saved.source == source && saved.commit == commit {
		return saved.index, nil
	}
	index, err := readCVEFeedIndex(ctx, cache, commit)
	if err != nil {
		return nil, err
	}
	b.cveFeedSnapshot = &cveFeedSnapshot{source: source, commit: commit, index: index}
	return index, nil
}

// Git 명령은 hook/ext helper를 끄고 고정된 명령만 실행합니다. feed의 임의 응답은 로그에 넣지 않습니다.
func cveFeedCommand(ctx context.Context, dir string, args ...string) *exec.Cmd {
	argv := []string{"-c", "core.hooksPath=/dev/null", "-c", "protocol.ext.allow=never"}
	if dir != "" {
		argv = append(argv, "-C", dir)
	}
	cmd := exec.CommandContext(ctx, "git", append(argv, args...)...)
	cmd.Env = append(os.Environ(), "LC_ALL=C", "LANGUAGE=C", "GIT_TERMINAL_PROMPT=0")
	cmd.Stderr = io.Discard
	killProcessGroup(cmd)
	return cmd
}

type cveFeedOutput struct{ buffer bytes.Buffer }

func (b *cveFeedOutput) Write(p []byte) (int, error) {
	if b.buffer.Len()+len(p) > 16<<20 {
		return 0, fmt.Errorf("CVE feed Git 출력 한도 초과")
	}
	return b.buffer.Write(p)
}
func cveFeedGit(ctx context.Context, dir string, args ...string) (string, error) {
	cmd := cveFeedCommand(ctx, dir, args...)
	var out cveFeedOutput
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return "", fmt.Errorf("CVE feed git %s 중단: %w", args[0], ctx.Err())
		}
		return "", fmt.Errorf("CVE feed git %s 실패: %w", args[0], err)
	}
	return out.buffer.String(), nil
}

func readCVEFeedIndex(ctx context.Context, repo, commit string) (cveFeedIndex, error) {
	// git ls-tree/archive -h와 실제 vulns clone에서 두 glob의 동작을 확인했습니다.
	tree, err := cveFeedGit(ctx, repo, "ls-tree", "-r", "-z", "--name-only", commit, "--", "cve/published")
	if err != nil {
		return nil, err
	}
	sha1, dyad := false, false
	for _, name := range strings.Split(tree, "\x00") {
		sha1 = sha1 || strings.HasSuffix(name, ".sha1")
		dyad = dyad || strings.HasSuffix(name, ".dyad")
	}
	if !sha1 {
		return nil, fmt.Errorf("CVE feed에 공개 .sha1 수정 기록이 없습니다")
	}
	args := []string{"archive", "--format=tar", commit, "cve/published/*/*.sha1"}
	if dyad {
		args = append(args, "cve/published/*/*.dyad")
	}
	cmd := cveFeedCommand(ctx, repo, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("CVE feed git archive 시작 실패: %w", err)
	}
	index, parseErr := parseCVEFeedArchive(stdout)
	if parseErr != nil {
		_ = cmd.Cancel()
	}
	runErr := cmd.Wait()
	if parseErr != nil {
		return nil, parseErr
	}
	if runErr != nil {
		return nil, fmt.Errorf("CVE feed git archive 실패: %w", runErr)
	}
	return index, nil
}

var cveFeedPath = regexp.MustCompile(`^cve/published/([0-9]{4})/(CVE-([0-9]{4})-[0-9]{4,})\.(sha1|dyad)$`)

// schema와 실제 clone(84a53c896276bc79eb2c0b9864fc2a53afe270b8)을 기준으로 합니다.
// .sha1은 fixing commits, .dyad는 vulnerable-version:introduced:fixed-version:fixed입니다.
// https://git.kernel.org/pub/scm/linux/security/vulns.git/tree/cve/schema
func parseCVEFeedArchive(input io.Reader) (cveFeedIndex, error) {
	counted := &cveFeedReader{input: input, left: cveFeedArchiveLimit}
	archive := tar.NewReader(counted)
	index := cveFeedIndex{}
	seen := map[string]bool{}
	shaFiles, entries := 0, 0
	for {
		header, err := archive.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("CVE feed archive 형식/크기 검토 필요: %w", err)
		}
		if header.Typeflag == tar.TypeDir {
			continue
		}
		if !strings.HasPrefix(header.Name, "cve/published/") || (!strings.HasSuffix(header.Name, ".sha1") && !strings.HasSuffix(header.Name, ".dyad")) {
			continue
		}
		match := cveFeedPath.FindStringSubmatch(header.Name)
		if match == nil || match[1] != match[3] {
			return nil, fmt.Errorf("CVE feed 공개 수정 기록의 경로/연도가 잘못됐습니다")
		}
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA {
			return nil, fmt.Errorf("CVE feed 공개 수정 기록에 symlink 또는 비정규 파일이 있습니다")
		}
		if header.Size < 1 || header.Size > cveFeedFileLimit {
			return nil, fmt.Errorf("CVE feed 공개 수정 기록의 크기가 잘못됐습니다")
		}
		if seen[header.Name] {
			return nil, fmt.Errorf("CVE feed 공개 수정 기록이 중복됐습니다")
		}
		seen[header.Name] = true
		data, err := io.ReadAll(archive)
		if err != nil {
			return nil, fmt.Errorf("CVE feed 공개 수정 기록 읽기 실패: %w", err)
		}
		cve := match[2]
		var fixes []string
		if match[4] == "sha1" {
			shaFiles++
			fixes = strings.Fields(string(data))
			if len(fixes) == 0 {
				return nil, fmt.Errorf("CVE feed 공개 .sha1이 비어 있습니다: %s", cve)
			}
			for _, sha := range fixes {
				if !fullCommit.MatchString(sha) {
					return nil, fmt.Errorf("CVE feed 공개 .sha1의 수정 ID 형식 오류: %s", cve)
				}
			}
		} else {
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				fields := strings.Split(line, ":")
				if len(fields) != 4 || fields[0] == "" || fields[2] == "" || (fields[1] != "0" && !fullCommit.MatchString(fields[1])) {
					return nil, fmt.Errorf("CVE feed 공개 .dyad 행 형식 오류: %s", cve)
				}
				// 실제 저장소의 0:0은 아직 수정이 없다는 sentinel이며 취약점 도입 ID가 아닙니다.
				if fields[2] == "0" && fields[3] == "0" {
					continue
				}
				if fields[2] == "0" || !fullCommit.MatchString(fields[3]) {
					return nil, fmt.Errorf("CVE feed 공개 .dyad 수정 ID 형식 오류: %s", cve)
				}
				fixes = append(fixes, fields[3])
			}
		}
		for _, sha := range fixes {
			duplicate := false
			for _, id := range index[sha] {
				duplicate = duplicate || id == cve
			}
			if !duplicate {
				index[sha] = append(index[sha], cve)
				entries++
			}
			if entries > 1000000 {
				return nil, fmt.Errorf("CVE feed 수정 매핑 수 한도 초과")
			}
		}
	}
	if shaFiles == 0 || len(index) == 0 {
		return nil, fmt.Errorf("CVE feed에 유효한 공개 수정 매핑이 없습니다")
	}
	for sha := range index {
		sort.Strings(index[sha])
	}
	return index, nil
}

type cveFeedReader struct {
	input io.Reader
	left  int64
}

func (r *cveFeedReader) Read(p []byte) (int, error) {
	if r.left <= 0 {
		return 0, fmt.Errorf("CVE feed archive 크기 한도 초과")
	}
	if int64(len(p)) > r.left {
		p = p[:r.left]
	}
	n, err := r.input.Read(p)
	r.left -= int64(n)
	return n, err
}

// Git -x의 '(cherry picked from commit ...)' 및 커널 stable/Ubuntu의 명시 trailer만 읽습니다.
// Fixes:와 본문에 인용한 ID는 취약점 도입 커밋일 수 있어 추출하지 않습니다.
var upstreamCVECommits = regexp.MustCompile(`(?im)^(?:\((?:cherry picked|backported) from commit ([0-9a-f]{40})\)|\[\s*Upstream commit ([0-9a-f]{40})\s*\]|commit ([0-9a-f]{40}) upstream\.?)\s*$`)

func mappedCVEs(message string, index cveFeedIndex) []string {
	ids := map[string]bool{}
	for _, id := range extractCVEs(message) {
		ids[id] = true
	}
	for _, match := range upstreamCVECommits.FindAllStringSubmatch(message, -1) {
		for _, sha := range match[1:] {
			for _, id := range index[strings.ToLower(sha)] {
				ids[id] = true
			}
		}
	}
	var out []string
	for id := range ids {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}
