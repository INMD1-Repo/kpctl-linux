// 이 파일: 승인 전에 실제 산출물을 검증한 VM 시험과 단계별 증거.
package model

import "time"

// VMTestResult describes the exact artifact tested before an approval attempt.
type VMTestResult struct {
	Status     string       `json:"status"` // running, passed, failed
	SHA256     string       `json:"sha256"`
	Modes      []string     `json:"modes"`
	Error      string       `json:"error,omitempty"`
	StartedAt  time.Time    `json:"started_at"`
	FinishedAt time.Time    `json:"finished_at,omitempty"`
	Steps      []VMTestStep `json:"steps,omitempty"`
}

// VMTestStep은 펌웨어 모드와 서명 키별 실행 결과를 보존합니다.
type VMTestStep struct {
	Mode   string `json:"mode"`
	KeyID  string `json:"key_id,omitempty"`
	Name   string `json:"name"`
	Status string `json:"status"` // passed, failed, skipped
	Detail string `json:"detail,omitempty"`
}
