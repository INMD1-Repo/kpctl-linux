// 이 파일: 공개 서명 키 현황, 만료·키 제거 경고와 재부팅 없는 호스트별 MOK 등록 예약.
package controller

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base32"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"kpctl/internal/model"
)

// MOKEnrollment의 원문 비밀번호는 컨트롤러 state.json에만 보관합니다.
// 에이전트에는 Request의 해시만 전달하고, 일반 상태 API에는 이 구조체를 넣지 않습니다.
type MOKEnrollment struct {
	Request    model.MOKImportRequest `json:"request"`
	Password   string                 `json:"password"`
	Result     *model.MOKImportResult `json:"result,omitempty"`
	CertSHA256 string                 `json:"cert_sha256,omitempty"`
}

func (s *Server) signingStatus() model.SigningStatus { return s.signingStatusAt(time.Now()) }

func (s *Server) signingStatusAt(now time.Time) model.SigningStatus {
	cfg := s.signingConfig()
	status := model.SigningStatus{Mode: cfg.Mode, Keys: []model.SigningKeyInfo{}}
	configured := map[string]bool{}
	for _, key := range cfg.Keys {
		configured[key.ID] = true
		info := model.SigningKeyInfo{ID: key.ID, Active: key.Active}
		if key.Cert != "" {
			der, err := os.ReadFile(key.Cert)
			if err != nil {
				info.Warning = "인증서를 읽지 못했습니다"
			} else if cert, err := x509.ParseCertificate(der); err != nil {
				info.Warning = "DER 인증서를 해석하지 못했습니다"
			} else {
				info.ExpiresAt = &cert.NotAfter
				if !cert.NotAfter.After(now.Add(30 * 24 * time.Hour)) {
					info.Warning = "인증서 만료가 30일 이내입니다"
				}
			}
		}
		status.Keys = append(status.Keys, info)
	}
	s.store.View(func(st *State) {
		for _, h := range st.Hosts {
			configuredEnrolled := false
			var removed []string
			for keyID, enrollment := range h.Status.EnrolledCerts {
				if enrollment != "enrolled" {
					continue
				}
				if configured[keyID] {
					configuredEnrolled = true
				} else {
					removed = append(removed, keyID)
				}
			}
			for i := range status.Keys {
				if h.Status.EnrolledCerts[status.Keys[i].ID] == "enrolled" {
					status.Keys[i].EnrolledHosts++
				}
			}
			if len(removed) > 0 && !configuredEnrolled {
				sort.Strings(removed)
				status.Warnings = append(status.Warnings, fmt.Sprintf("%s: 등록된 옛 키 %s가 설정에서 빠졌습니다. 현재 키가 미등록이면 blocked_mok_missing으로 배포 제외됩니다", h.Hostname, strings.Join(removed, ", ")))
			}
		}
	})
	sort.Strings(status.Warnings)
	return status
}

// initSigning은 재시작 때에도 만료·옛 키 제거 위험을 감사 기록에 남깁니다.
func (s *Server) initSigning() error {
	certs, certErr := s.signingCerts()
	if certErr != nil {
		if s.cfg.Signing != nil {
			return certErr
		}
		// 기존 sign_command의 .der 추정은 추가 메타데이터 수집입니다.
		// 예전 설정에서 읽지 못하던 경로를 새 시작 실패 조건으로 바꾸지 않습니다.
		s.audit("signing", "기존 서명 설정의 인증서 확인 실패: %s", certErr)
	}
	current := map[string]string{}
	for _, cert := range certs {
		current[cert.ID] = cert.SHA256
	}
	if err := s.store.Update(func(st *State) error {
		for id, sum := range current {
			if pinned := st.SigningCertSHA256[id]; pinned != "" && pinned != sum {
				return fmt.Errorf("서명 키 %s의 인증서 내용이 바뀌었습니다. 이전 호스트 등록 상태를 재사용할 수 없으므로 새 key ID를 사용하세요", id)
			}
		}
		// 삭제한 ID도 보존하여 이후 같은 이름으로 다른 인증서를 등록하지 못하게 합니다.
		pins := map[string]string{}
		for id, sum := range st.SigningCertSHA256 {
			pins[id] = sum
		}
		for id, sum := range current {
			pins[id] = sum
		}
		st.SigningCertSHA256 = pins
		return nil
	}); err != nil {
		return err
	}
	s.signingCertSHA256 = map[string]string{}
	s.store.View(func(st *State) {
		for id, sum := range st.SigningCertSHA256 {
			s.signingCertSHA256[id] = sum
		}
	})
	s.auditSigningWarnings(s.signingStatus())
	return nil
}

func (s *Server) handleSigningList(w http.ResponseWriter, r *http.Request, who string) {
	writeJSON(w, http.StatusOK, s.signingStatus())
}

// mokPasswordHash는 OpenSSL의 확인된 passwd -6 -stdin 옵션을 사용합니다.
// 근거: openssl passwd -help의 SHA512 crypt(-6), 표준 입력(-stdin).
// 원문은 명령 인자·로그·에이전트로 보내지 않습니다.
func mokPasswordHash(password string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "openssl", "passwd", "-6", "-stdin")
	cmd.Stdin = strings.NewReader(password + "\n")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("MOK 비밀번호 해시 생성 실패: openssl passwd -6 -stdin 지원을 확인하세요")
	}
	hash := strings.TrimSpace(string(output))
	if !strings.HasPrefix(hash, "$6$") || strings.ContainsAny(hash, "\r\n") {
		return "", fmt.Errorf("MOK 비밀번호 해시 형식이 올바르지 않습니다")
	}
	return hash, nil
}

// scheduleMOK는 store.Update 안에서 호출합니다. 콘솔 승인 예약만 하며 재부팅하지 않습니다.
func (s *Server) scheduleMOK(st *State, h *model.Host, keyID string) error {
	certs, err := s.signingCerts()
	if err != nil {
		return err
	}
	var cert *model.SigningCert
	for i := range certs {
		if certs[i].ID == keyID {
			cert = &certs[i]
			break
		}
	}
	if cert == nil {
		return fail(http.StatusBadRequest, "서명 키 %q의 공개 인증서가 없습니다", keyID)
	}
	if h.Status.EnrolledCerts[keyID] == "enrolled" {
		return nil
	}
	if old := st.MOKRequests[h.ID]; old != nil && old.Request.KeyID == keyID && old.CertSHA256 == cert.SHA256 {
		return nil
	}
	var random [10]byte
	if _, err := rand.Read(random[:]); err != nil {
		return fmt.Errorf("MOK 비밀번호 생성 실패: %w", err)
	}
	password := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(random[:])
	hash, err := mokPasswordHash(password)
	if err != nil {
		return err
	}
	if st.MOKRequests == nil {
		st.MOKRequests = map[string]*MOKEnrollment{}
	}
	st.MOKRequests[h.ID] = &MOKEnrollment{
		Request:  model.MOKImportRequest{ID: randHex(16), KeyID: keyID, PasswordHash: hash},
		Password: password, CertSHA256: cert.SHA256,
	}
	return nil
}

func (s *Server) handleRolloutCert(w http.ResponseWriter, r *http.Request, who string) {
	keyID := r.PathValue("id")
	found := false
	for _, key := range s.signingConfig().Keys {
		found = found || key.ID == keyID
	}
	if !found {
		writeErr(w, fail(http.StatusNotFound, "서명 키 %q가 없습니다", keyID))
		return
	}
	certs, err := s.signingCerts()
	if err != nil {
		writeErr(w, err)
		return
	}
	publicCert := false
	for _, cert := range certs {
		publicCert = publicCert || cert.ID == keyID
	}
	if !publicCert {
		writeErr(w, fail(http.StatusBadRequest, "서명 키 %q의 공개 인증서가 없습니다", keyID))
		return
	}
	count := 0
	var warnings []string
	err = s.store.Update(func(st *State) error {
		// 외부 해시 도구 실패 시 일부 호스트만 메모리에서 예약되는 것을 막습니다.
		pending := *st
		pending.MOKRequests = map[string]*MOKEnrollment{}
		for id, enrollment := range st.MOKRequests {
			pending.MOKRequests[id] = enrollment
		}
		// map 순회 순서와 무관하게 예약 결과·경고 순서를 일정하게 유지합니다.
		var ids []string
		for id := range st.Hosts {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			h := st.Hosts[id]
			if h.Status.EnrolledCerts[keyID] == "enrolled" {
				continue
			}
			if old := pending.MOKRequests[id]; old != nil && old.Result != nil && (old.Result.Status == "failed" || old.Result.Status == "unsupported") {
				delete(pending.MOKRequests, id) // 명시적인 재예약은 새 요청으로 다시 시도합니다.
			}
			if err := s.scheduleMOK(&pending, h, keyID); err != nil {
				return err
			}
			count++
			if h.Status.Firmware != "uefi" {
				warnings = append(warnings, h.Hostname+": UEFI 상태를 확인하지 못했습니다. 자동 등록이 unsupported이면 수동 등록 절차를 확인하세요")
			}
		}
		st.MOKRequests = pending.MOKRequests
		return nil
	})
	if err != nil {
		writeErr(w, err)
		return
	}
	s.audit(who, "MOK 인증서 등록 예약 key=%s hosts=%d (재부팅 없음)", keyID, count)
	writeJSON(w, http.StatusOK, map[string]any{"scheduled_hosts": count, "warnings": warnings})
}

func (s *Server) handleMOKPassword(w http.ResponseWriter, r *http.Request, who string) {
	var result map[string]string
	var checkErr error
	hostID := r.PathValue("id")
	s.store.View(func(st *State) {
		if st.Hosts[hostID] == nil {
			checkErr = fail(http.StatusNotFound, "호스트 %q가 없습니다", hostID)
			return
		}
		enrollment := st.MOKRequests[hostID]
		if enrollment == nil {
			checkErr = fail(http.StatusNotFound, "이 호스트에 MOK 등록 예약이 없습니다")
			return
		}
		result = map[string]string{"key_id": enrollment.Request.KeyID, "password": enrollment.Password}
		if enrollment.Result != nil {
			result["status"] = enrollment.Result.Status
			result["warning"] = enrollment.Result.Detail
		}
	})
	if checkErr != nil {
		writeErr(w, checkErr)
		return
	}
	s.audit(who, "MOK 비밀번호 조회 host=%s key=%s", hostID, result["key_id"])
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, result)
}

// auditSigningWarnings는 장기 실행 중 만료 경계 진입도 감시하고 같은 경고의 로그 반복을 막습니다.
func (s *Server) auditSigningWarnings(status model.SigningStatus) {
	next := map[string]string{}
	for _, key := range status.Keys {
		if key.Warning != "" {
			next["key:"+key.ID] = "서명 키 " + key.ID + ": " + key.Warning
		}
	}
	for _, warning := range status.Warnings {
		next["fleet:"+warning] = warning
	}
	s.signingWarningMu.Lock()
	var changed []string
	for id, warning := range next {
		if s.signingWarnings[id] != warning {
			changed = append(changed, warning)
		}
	}
	s.signingWarnings = next
	s.signingWarningMu.Unlock()
	sort.Strings(changed)
	for _, warning := range changed {
		s.audit("signing", "%s", warning)
	}
}
