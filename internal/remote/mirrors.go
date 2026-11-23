// 이 파일: 설치 묶음의 mirrors.list 해석 — ParseMirrors.
//
// 형식은 deploy/mirrors.list 머리말에 있습니다. 같은 파일을 설치 스크립트(install-agent.sh)와
// 커널 준비 도우미(kpctl-prepare-kernel.py)도 읽으므로, 여기서는 설치 전에 잘못된 줄을 막기만 합니다.
package remote

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// Mirror 는 mirrors.list 의 한 줄입니다.
type Mirror struct {
	Name, Arch, Archive, Security string
}

var mirrorNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

// ParseMirrors 는 mirrors.list 를 검사합니다. 아키텍처마다 미러가 하나 이상 있어야 합니다.
func ParseMirrors(text string) ([]Mirror, error) {
	var out []Mirror
	seen := map[string]bool{}
	for n, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || strings.HasPrefix(f[0], "#") {
			continue
		}
		bad := func(why string) error {
			return fmt.Errorf("mirrors.list %d번째 줄: %s: %q", n+1, why, strings.TrimSpace(line))
		}
		if len(f) < 3 || len(f) > 4 {
			return nil, bad("'이름 아키텍처 저장소-주소 [보안-주소]' 형식이 아닙니다")
		}
		m := Mirror{Name: f[0], Arch: f[1], Archive: f[2], Security: f[2]}
		if len(f) == 4 {
			m.Security = f[3]
		}
		if !mirrorNameRe.MatchString(m.Name) {
			return nil, bad("이름은 영문 소문자·숫자·- 만 씁니다")
		}
		if m.Arch != "amd64" && m.Arch != "arm64" {
			return nil, bad("아키텍처는 amd64 또는 arm64 입니다")
		}
		for _, u := range []string{m.Archive, m.Security} {
			p, err := url.Parse(u)
			if err != nil || (p.Scheme != "http" && p.Scheme != "https") || p.Host == "" || p.RawQuery != "" || p.Fragment != "" {
				return nil, bad("주소는 http(s)://호스트/경로 형식이어야 합니다")
			}
		}
		if seen[m.Name+" "+m.Arch] {
			return nil, bad("같은 이름·아키텍처가 두 번 나옵니다")
		}
		seen[m.Name+" "+m.Arch] = true
		out = append(out, m)
	}
	for _, arch := range []string{"amd64", "arm64"} {
		if !seen["official "+arch] {
			return nil, fmt.Errorf("mirrors.list 에 official %s 줄이 없습니다 (공식 저장소를 맨 위에 두세요)", arch)
		}
	}
	return out, nil
}
