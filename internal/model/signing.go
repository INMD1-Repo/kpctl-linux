// 이 파일: 공통 서명 정책, 공개 인증서, MOK 등록 예약과 배포 자격 보고.
package model

import (
	"strings"
	"time"
)

// SignaturePolicy는 비어 있거나 읽지 못한 신호도 서명 필요로 판단합니다.
// BIOS에서도 lockdown 또는 CONFIG_MODULE_SIG_FORCE가 서명을 요구할 수 있습니다.
func SignaturePolicy(secureBoot, lockdown, sigEnforce string) (required bool, warning string) {
	var missing []string
	for _, signal := range []struct {
		name, value string
		known       []string
	}{
		{"secure_boot", secureBoot, []string{"on", "off"}},
		{"lockdown", lockdown, []string{"none", "integrity", "confidentiality"}},
		{"sig_enforce", sigEnforce, []string{"on", "off"}},
	} {
		known := false
		for _, value := range signal.known {
			known = known || signal.value == value
		}
		if !known {
			missing = append(missing, signal.name)
		}
	}
	required = secureBoot == "on" || lockdown == "integrity" || lockdown == "confidentiality" || sigEnforce == "on" || len(missing) > 0
	if len(missing) > 0 {
		warning = strings.Join(missing, ", ") + " 상태를 읽지 못해 서명 필요로 판단"
	}
	return
}

type SigningCert struct {
	ID     string `json:"id"`
	SHA256 string `json:"sha256"`
	DER    []byte `json:"der"`
	Active bool   `json:"active"`
}

type MOKImportRequest struct {
	ID           string `json:"id"`
	KeyID        string `json:"key_id"`
	PasswordHash string `json:"password_hash"`
}

type MOKImportResult struct {
	ID     string `json:"id"`
	KeyID  string `json:"key_id"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// SigningArtifact는 동일한 모듈 이름을 유지하면서 키별 바이트와 해시를 고정합니다.
type SigningArtifact struct {
	KeyID  string        `json:"key_id"`
	File   string        `json:"file"`
	SHA256 string        `json:"sha256"`
	Signed bool          `json:"signed"`
	VMTest *VMTestResult `json:"vm_test,omitempty"`
}

type RolloutEligibility struct {
	Status  string `json:"status"`
	Reason  string `json:"reason,omitempty"`
	KeyID   string `json:"key_id,omitempty"`
	Warning string `json:"warning,omitempty"`
}

type ExcludedHost struct {
	ID       string `json:"id"`
	Hostname string `json:"hostname"`
	Reason   string `json:"reason"`
}

type SigningKeyInfo struct {
	ID            string     `json:"id"`
	Active        bool       `json:"active"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	EnrolledHosts int        `json:"enrolled_hosts"`
	Warning       string     `json:"warning,omitempty"`
}

type SigningStatus struct {
	Mode     string           `json:"mode"`
	Keys     []SigningKeyInfo `json:"keys"`
	Warnings []string         `json:"warnings,omitempty"`
}
