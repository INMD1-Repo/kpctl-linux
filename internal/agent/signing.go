// 이 파일: 공개 DER 무결성 확인, 호스트별 MOK 조회·등록 예약. 재부팅은 실행하지 않습니다.
package agent

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"kpctl/internal/model"
)

const mokCommandTimeout = 10 * time.Second

func (a *Agent) mokutil(args ...string) ([]byte, error) {
	bin := a.cfg.MokutilBin
	if bin == "" {
		bin = "mokutil"
	}
	ctx, cancel := context.WithTimeout(context.Background(), mokCommandTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	return cmd.CombinedOutput()
}

// mokutil 공식 src/mokutil.c의 test_key()/print_skip_message()를 기준으로 합니다.
// https://github.com/lcp/mokutil/blob/master/src/mokutil.c
// pending·blocked도 종료 0이므로 종료 코드만으로 enrolled라 판단하지 않습니다.
func mokTestResult(out []byte, err error) (state string, pending bool) {
	text := strings.TrimSpace(string(out))
	if err == nil && (strings.HasSuffix(text, " is already enrolled") || strings.HasSuffix(text, " is already in db") || strings.HasSuffix(text, " is already in the built-in trusted keyring")) {
		return "enrolled", false
	}
	if err == nil && strings.HasSuffix(text, " is already in the enrollment request") {
		return "not_enrolled", true
	}
	if err == nil && (strings.HasSuffix(text, " is blocked in dbx") || strings.HasSuffix(text, " is blocked in MokListX")) {
		return "not_enrolled", false
	}
	if exit, ok := err.(*exec.ExitError); ok && exit.ExitCode() == 1 && strings.HasSuffix(text, " is not enrolled") {
		return "not_enrolled", false
	}
	return "unknown", false
}

func mokListPending(out []byte) (pending, known bool) {
	text := strings.TrimSpace(string(out))
	if text == "" || text == "MokNew is empty" {
		return false, true
	}
	// list_keys_in_var()는 없는 MokNew를 출력 없이 반환하고, list_keys()는
	// 실제 항목을 [key N]으로 출력합니다. 단순 진단 문자열은 예약으로 보지 않습니다.
	if strings.Contains(text, "[key ") || strings.Contains(text, "SHA1 Fingerprint:") || strings.Contains(text, "SHA256 Fingerprint:") || strings.Contains(text, "Certificate:") {
		return true, true
	}
	return false, false
}

func (a *Agent) certFile(cert model.SigningCert) (string, error) {
	if cert.ID == "" || len(cert.DER) == 0 || len(cert.DER) > 1024*1024 || cert.SHA256 != fmt.Sprintf("%x", sha256.Sum256(cert.DER)) {
		return "", fmt.Errorf("인증서 ID·DER·SHA256을 확인하지 못했습니다")
	}
	if _, err := x509.ParseCertificate(cert.DER); err != nil {
		return "", fmt.Errorf("DER 인증서를 해석하지 못했습니다")
	}
	dir := filepath.Join(a.cfg.StateDir, "certs")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	// ID는 경로에 사용하지 않고 검증한 DER의 SHA256으로 파일을 고릅니다.
	path := filepath.Join(dir, cert.SHA256+".der")
	if data, err := os.ReadFile(path); err == nil && fmt.Sprintf("%x", sha256.Sum256(data)) == cert.SHA256 {
		return path, nil
	}
	file, err := os.CreateTemp(dir, ".cert-*")
	if err != nil {
		return "", err
	}
	defer os.Remove(file.Name())
	_, writeErr := file.Write(cert.DER)
	closeErr := file.Close()
	if writeErr != nil {
		return "", writeErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	return path, os.Rename(file.Name(), path)
}

func (a *Agent) enrollmentStatus(security hostSecurity) (map[string]string, bool, string) {
	var statuses map[string]string
	if len(a.st.SigningCerts) > 0 {
		statuses = make(map[string]string, len(a.st.SigningCerts))
	}
	for _, cert := range a.st.SigningCerts {
		statuses[cert.ID] = "unknown"
	}
	if security.firmware != "uefi" {
		return statuses, false, ""
	}
	pendingOut, pendingErr := a.mokutil("--list-new")
	pending, pendingKnown := mokListPending(pendingOut)
	pending = pending && pendingErr == nil
	var warnings []string
	if (pendingErr != nil || !pendingKnown) && len(a.st.SigningCerts) > 0 {
		warnings = append(warnings, "MOK 등록 대기 상태를 읽지 못했습니다")
	}
	for _, cert := range a.st.SigningCerts {
		path, err := a.certFile(cert)
		if err != nil {
			warnings = append(warnings, cert.ID+": 공개 인증서 무결성 확인 실패")
			continue
		}
		out, err := a.mokutil("--test-key", path)
		state, certPending := mokTestResult(out, err)
		statuses[cert.ID] = state
		pending = pending || certPending
		if state == "unknown" {
			warnings = append(warnings, cert.ID+": MOK 등록 상태를 읽지 못했습니다")
		}
	}
	return statuses, pending, strings.Join(warnings, "; ")
}

// reconcileSigning은 인증서·최종 결과만 저장하며 비밀번호 원문·해시는 저장하지 않습니다.
func (a *Agent) reconcileSigning(resp model.ReportResponse) bool {
	changed := false
	a.securityWarning = ""
	if resp.SigningCerts != nil && !reflect.DeepEqual(a.st.SigningCerts, resp.SigningCerts) {
		certs := make([]model.SigningCert, len(resp.SigningCerts))
		for i, cert := range resp.SigningCerts {
			certs[i] = cert
			if _, err := a.certFile(cert); err != nil {
				// ID는 남겨 다음 보고에서 unknown으로 표시합니다. 잘못된 DER는 저장하지 않습니다.
				certs[i].DER = nil
				a.securityWarning = "컨트롤러 공개 인증서 무결성 확인 실패"
			}
		}
		a.st.SigningCerts = certs
		changed = true
	}
	if request := resp.MOKImport; request != nil && (a.st.MOKImport == nil || a.st.MOKImport.ID != request.ID) {
		result := a.importMOK(*request)
		a.st.MOKImport = &result
		changed = true
	}
	if changed {
		if err := a.saveState(); err != nil {
			a.securityWarning = "인증서·MOK 등록 예약 결과 저장 실패"
		}
	}
	return changed
}

func (a *Agent) importMOK(request model.MOKImportRequest) model.MOKImportResult {
	result := model.MOKImportResult{ID: request.ID, KeyID: request.KeyID, Status: "unsupported"}
	manual := "수동 mokutil --import <인증서.der> 후 다음 계획된 재부팅 때 콘솔에서 MOK 승인 필요; 자동 재부팅하지 않음"
	if a.securityStatus().firmware != "uefi" {
		result.Detail = "UEFI 환경이 아니므로 자동 MOK 등록 예약 미지원. " + manual
		return result
	}
	// 현 호스트 mokutil --help와 공식 man/mokutil.1의 --hash-file 계약을 확인했습니다.
	// https://github.com/lcp/mokutil/blob/master/man/mokutil.1
	help, err := a.mokutil("--help")
	if err != nil || !strings.Contains(string(help), "--hash-file") {
		result.Detail = "mokutil --hash-file 미지원 또는 도구 실행 불가. " + manual
		return result
	}
	var cert *model.SigningCert
	for i := range a.st.SigningCerts {
		if a.st.SigningCerts[i].ID == request.KeyID {
			cert = &a.st.SigningCerts[i]
			break
		}
	}
	if cert == nil {
		result.Status, result.Detail = "failed", "등록할 공개 인증서가 없습니다. "+manual
		return result
	}
	path, err := a.certFile(*cert)
	if err != nil {
		result.Status, result.Detail = "failed", "공개 인증서 무결성 확인 실패. "+manual
		return result
	}
	out, err := a.mokutil("--test-key", path)
	state, pending := mokTestResult(out, err)
	if state == "enrolled" {
		result.Status, result.Detail = "enrolled", "이미 등록된 인증서"
		return result
	}
	if pending {
		result.Status, result.Detail = "pending", "다음 계획된 재부팅 때 콘솔에서 MOK 승인 필요"
		return result
	}
	if !strings.HasPrefix(request.PasswordHash, "$6$") || strings.ContainsAny(request.PasswordHash, "\r\n\x00") || len(request.PasswordHash) > 256 {
		result.Status, result.Detail = "failed", "MOK 비밀번호 해시 형식 오류. "+manual
		return result
	}
	hash, err := os.CreateTemp(a.cfg.StateDir, ".mok-hash-*")
	if err != nil {
		result.Status, result.Detail = "failed", "MOK 비밀번호 해시 임시 파일 생성 실패. "+manual
		return result
	}
	defer os.Remove(hash.Name())
	_, writeErr := hash.WriteString(request.PasswordHash)
	closeErr := hash.Close()
	if writeErr != nil || closeErr != nil {
		result.Status, result.Detail = "failed", "MOK 비밀번호 해시 임시 파일 기록 실패. "+manual
		return result
	}
	if _, err := a.mokutil("--import", path, "--hash-file", hash.Name()); err != nil {
		result.Status, result.Detail = "failed", "MOK 등록 예약 명령 실패. "+manual
		return result
	}
	// 종료 0이어도 차단된 키를 건너뛸 수 있으므로 실제 pending 상태를 재확인합니다.
	out, err = a.mokutil("--test-key", path)
	state, pending = mokTestResult(out, err)
	if state == "enrolled" {
		result.Status, result.Detail = "enrolled", "이미 등록된 인증서"
	} else if pending {
		result.Status, result.Detail = "pending", "다음 계획된 재부팅 때 콘솔에서 MOK 승인 필요"
	} else {
		result.Status, result.Detail = "failed", "MOK 등록 예약을 확인하지 못했습니다. "+manual
	}
	return result
}
