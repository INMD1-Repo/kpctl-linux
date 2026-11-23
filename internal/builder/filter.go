// 이 파일: builder 패키지의 extractCVEs 구현·자료형.
package builder

import (
	"regexp"
	"sort"
	"strings"
)

// DefaultPaths 는 라이브패치 대상으로 볼 커널 소스 경로입니다.
//
// VM 을 올리지 않는 단독 CPU 서버 기준입니다. 로컬 권한 상승과 네트워크로 닿는 공통 코드를 고르고,
// 하드웨어마다 다른 drivers/ 는 뺐습니다. 이 경로를 건드린 CVE 수정 커밋만 자동 수집합니다.
// 나머지 CVE 는 완화 조치나 다음 재부팅으로 처리합니다.
//
// 경로를 추가/삭제하려면 여기를 고치거나, 설정 파일의 paths(전체) 또는 kernels[].paths(커널별)로 덮어쓰세요.
var DefaultPaths = []string{
	"kernel/",   // 스케줄러, BPF, 시스템 콜 공통
	"mm/",       // 메모리 관리
	"fs/",       // 파일 시스템
	"net/",      // 네트워크 스택
	"security/", // LSM, 권한
	"ipc/",      // 프로세스 간 통신
	"io_uring/", // io_uring
	"crypto/",   // 커널 암호화
	"block/",    // 블록 계층
	"lib/",      // 공통 라이브러리
	"arch/x86/", // x86 공통 (KVM 포함)
}

// cveRe 는 커밋 메시지에서 CVE 번호를 찾는 정규식입니다.
var cveRe = regexp.MustCompile(`(?i)CVE-\d{4}-\d{4,}`)

// extractCVEs 는 커밋 메시지에서 CVE 번호를 모두 찾아 대문자, 중복 제거, 정렬해서 돌려줍니다.
// Ubuntu 커널 SRU 커밋은 메시지에 "CVE-2026-12345" 줄을 넣습니다.
func extractCVEs(message string) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range cveRe.FindAllString(message, -1) {
		m = strings.ToUpper(m)
		if !seen[m] {
			seen[m] = true
			out = append(out, m)
		}
	}
	sort.Strings(out)
	return out
}
