// 이 파일: 빌드 시 주입된 버전·커밋·브랜치 정보와 Go VCS 메타데이터 읽기.
package version

import (
	"fmt"
	"runtime/debug"
	"strings"
)

// 빌드 시 -ldflags "-X kpctl/internal/version.Version=... -X kpctl/internal/version.Commit=... -X kpctl/internal/version.Branch=..." 로 채웁니다.
var (
	Version = ""
	Commit  = ""
	Branch  = ""
)

// Info 는 현재 실행 중인 바이너리의 빌드 버전 정보입니다.
type Info struct {
	Version string
	Commit  string
	Branch  string
}

// Current 는 빌드 시 주입된 버전 정보를 반환하며, 커밋이 비어 있으면 Go VCS 정보에서 읽습니다.
func Current() Info {
	info := Info{
		Version: strings.TrimSpace(Version),
		Commit:  strings.TrimSpace(Commit),
		Branch:  strings.TrimSpace(Branch),
	}
	if info.Commit == "" || info.Commit == "unknown" {
		if bi, ok := debug.ReadBuildInfo(); ok {
			for _, s := range bi.Settings {
				if s.Key == "vcs.revision" && s.Value != "" {
					info.Commit = s.Value
					break
				}
			}
		}
	}
	if info.Commit == "unknown" {
		info.Commit = ""
	}
	if info.Branch == "unknown" || info.Branch == "HEAD" {
		info.Branch = ""
	}
	if info.Version == "" || info.Version == "unknown" {
		if info.Commit != "" {
			info.Version = Short(info.Commit)
		} else {
			info.Version = "dev"
		}
	}
	return info
}

// Short 는 Git 커밋 해시의 앞 7자리를 돌려줍니다.
func Short(commit string) string {
	commit = strings.TrimSpace(commit)
	if len(commit) > 7 {
		return commit[:7]
	}
	return commit
}

// Label 은 버전·커밋·브랜치를 사람이 읽기 쉬운 한 줄로 묶습니다.
func Label(ver, commit, branch string) string {
	short := Short(commit)
	ver = strings.TrimSpace(ver)
	branch = strings.TrimSpace(branch)

	base := ver
	if base == "" {
		base = short
	}
	if base == "" {
		base = "unknown"
	}

	var meta []string
	if short != "" && base != short && !strings.HasSuffix(base, "-g"+short) {
		meta = append(meta, short)
	}
	if branch != "" && branch != "HEAD" {
		meta = append(meta, branch)
	}
	if len(meta) == 0 {
		return base
	}
	return fmt.Sprintf("%s (%s)", base, strings.Join(meta, ", "))
}
