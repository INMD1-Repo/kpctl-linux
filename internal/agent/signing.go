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

// mokutil 0.5/0.6 and newer tools use opposite 0/1 exit conventions.
// --ignore-keyring tests the EFI lists and excludes older tools that gave
// the same "already enrolled" answer for pending or blocked certificates.
func (a *Agent) mokTestResult(path string) (state string, pending bool) {
	out, err := a.mokutil("--test-key", path, "--ignore-keyring")
	if err != nil {
		if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 1 {
			return "unknown", false
		}
	}
	switch strings.TrimSpace(string(out)) {
	case path + " is already enrolled":
		return "enrolled", false
	case path + " is already in db":
		return "in_db", false
	case path + " is already in the enrollment request":
		return "not_enrolled", true
	case path + " is not enrolled", path + " is blocked in dbx", path + " is blocked in MokListX", path + " is blocked in MokListXRT":
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

func (a *Agent) enrollmentStatus(security hostSecurity) (map[string]string, bool, bool, string) {
	var statuses map[string]string
	if len(a.st.SigningCerts) > 0 {
		statuses = make(map[string]string, len(a.st.SigningCerts))
	}
	for _, cert := range a.st.SigningCerts {
		statuses[cert.ID] = "unknown"
	}
	if security.firmware != "uefi" {
		return statuses, false, false, ""
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
		state, certPending := a.mokTestResult(path)
		statuses[cert.ID] = state
		pending = pending || certPending
		if state == "unknown" {
			warnings = append(warnings, cert.ID+": MOK 등록 상태를 읽지 못했습니다")
		}
		if state == "in_db" {
			warnings = append(warnings, cert.ID+": UEFI db 일치, MOK 등록·커널 모듈 신뢰 미확인")
		}
	}
	return statuses, pending, pendingKnown && pendingErr == nil && !pending, strings.Join(warnings, "; ")
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
	// Some releases print their full help and return 255.
	help, _ := a.mokutil("--help")
	if !strings.Contains(string(help), "--hash-file") || !strings.Contains(string(help), "--ignore-keyring") {
		result.Detail = "mokutil --hash-file·--ignore-keyring 미지원 또는 도구 실행 불가. " + manual
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
	state, pending := a.mokTestResult(path)
	if state == "enrolled" {
		result.Status, result.Detail = "enrolled", "이미 등록된 인증서"
		return result
	}
	if pending {
		result.Status, result.Detail = "pending_existing", "기존 MOK 예약 감지: 최초 예약자가 지정한 비밀번호로 콘솔 승인 필요"
		return result
	}
	if state != "not_enrolled" {
		result.Detail = "MOK 미등록 여부를 확인할 수 없습니다 (" + state + "). EFI 상태와 대상 커널의 모듈 신뢰를 확인하세요"
		return result
	}
	list, listErr := a.mokutil("--list-new")
	if anyPending, known := mokListPending(list); listErr != nil || !known || anyPending {
		result.Status, result.Detail = "failed", "기존 MOK 예약을 보존합니다. 대기 목록 확인 및 기존 콘솔 승인 후 다시 예약하세요"
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
	importOut, err := a.mokutil("--import", path, "--hash-file", hash.Name())
	if err != nil {
		result.Status, result.Detail = "failed", "MOK 등록 예약 명령 실패. "+manual
		return result
	}
	// 종료 0이어도 차단된 키를 건너뛸 수 있으므로 실제 pending 상태를 재확인합니다.
	state, pending = a.mokTestResult(path)
	if state == "enrolled" {
		result.Status, result.Detail = "enrolled", "이미 등록된 인증서"
	} else if pending {
		result.Status, result.Detail, result.PasswordSet = mokImportOutcome(path, string(importOut))
	} else {
		result.Status, result.Detail = "failed", "MOK 등록 예약을 확인하지 못했습니다. "+manual
	}
	return result
}

// Classify only after the exact DER is reported in MokNew. Do not disclose
// raw tool output, which may contain local paths or credential material.
func mokImportOutcome(path, output string) (string, string, bool) {
	ambiguous := false
	warned := false
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		msg := strings.TrimPrefix(line, "SKIP: ")
		if msg == path+" is already in the enrollment request" {
			return "pending_existing", "기존 MOK 예약 감지: 최초 예약자의 콘솔 비밀번호 필요", false
		}
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "warning:") && !strings.Contains(lower, "skip") && !strings.Contains(lower, "already") {
			warned = true
		} else if line != "" {
			ambiguous = true
		}
	}
	if ambiguous {
		return "pending_uncertain", "MokNew에서 인증서를 확인했습니다. 도구의 추가 출력만으로 비밀번호 출처를 확인할 수 없어 이 요청의 후보 비밀번호를 제공합니다. 최초 예약자와 대조하세요.", false
	}
	if warned {
		return "pending", "등록 명령이 경고와 함께 완료됐고 해당 인증서의 예약을 확인했습니다. 콘솔 비밀번호는 이 요청에 저장된 후보와 대조하세요", false
	}
	return "pending", "다음 계획된 재부팅 때 콘솔에서 MOK 승인 필요", true
}
