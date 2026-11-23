// 이 파일: 에이전트 토큰·설치·승인·공개 인증서 결과를 원자적으로 저장합니다.
package agent

import (
	"encoding/json"
	"kpctl/internal/model"
	"os"
	"path/filepath"
	"time"
)

// localState 는 에이전트가 기억하는 것입니다. state_dir/state.json (권한 0600) 에 저장됩니다.
// 이 파일을 지우면 다음 실행 때 다시 등록합니다.
type localState struct {
	HostID    string `json:"host_id"`
	HostToken string `json:"host_token"`

	Version      int                    `json:"version"`                 // 적용한 패치 버전 (0 = 없음)
	ModuleName   string                 `json:"module_name"`             // 적용한 모듈 이름
	Installed    []string               `json:"installed"`               // kpatch install 로 설치한 모듈 이름들
	Kernel       string                 `json:"kernel,omitempty"`        // 위 버전·설치 목록의 ABI
	SigningCerts []model.SigningCert    `json:"signing_certs,omitempty"` // 공개 DER·해시만 보관
	MOKImport    *model.MOKImportResult `json:"mok_import,omitempty"`    // 비밀번호와 해시는 저장하지 않음

	LastRebootID    int                        `json:"last_reboot_id"`              // 마지막으로 실행한 재부팅 요청 번호
	BootConfirmedID int                        `json:"boot_confirmed_id,omitempty"` // GRUB 영구 기본값 확정과 준비 기록 정리 완료
	RebootError     string                     `json:"reboot_error,omitempty"`
	PendingReboot   *model.RebootApproval      `json:"pending_reboot,omitempty"`
	BootChoiceArmed bool                       `json:"boot_choice_armed,omitempty"`
	KernelPrepare   *model.KernelPrepareStatus `json:"kernel_prepare,omitempty"`

	// 같은 버전 적용이 계속 실패할 때 1분마다 반복하지 않도록
	FailedVersion int       `json:"failed_version"`
	FailedAt      time.Time `json:"failed_at"`
}

func (a *Agent) statePath() string { return filepath.Join(a.cfg.StateDir, "state.json") }

func (a *Agent) loadState() error {
	a.st = &localState{}
	data, err := os.ReadFile(a.statePath())
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(data, a.st)
}

func (a *Agent) saveState() error {
	data, err := json.MarshalIndent(a.st, "", "  ")
	if err != nil {
		return err
	}
	tmp := a.statePath() + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(tmp, a.statePath()); err != nil {
		return err
	}
	dir, err := os.Open(a.cfg.StateDir)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
