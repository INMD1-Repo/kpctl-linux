// 이 파일: 공개 서명 키 현황, 만료·키 제거 경고와 재부팅 없는 호스트별 MOK 등록 예약.
package controller

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
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
		if cfg.Mode != "never" && len(key.SignCommand) > 0 && key.Cert == "" {
			info.Warning = joinSecurityWarnings(info.Warning, "서명 승인 불가: 서명자의 공개 DER를 signing.keys[].cert에 지정하세요")
		}
		if pin, exists := s.signingCertSHA256[key.ID]; exists && pin == "" {
			info.Warning = joinSecurityWarnings(info.Warning, "공개 DER 복구 후 컨트롤러 재시작 필요: 지문 고정 전 서명 승인·인증서 배포 보류")
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
	if certErr != nil && s.signingCertSHA256["default"] == "" {
		// The inferred legacy DER was unavailable during startup. Pin it on
		// the next restart before distributing or signing under this ID.
		s.signingCertSHA256["default"] = ""
	}
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
func (s *Server) scheduleMOK(st *State, h *model.Host, cert model.SigningCert, manual bool, replaceID string) (scheduled bool, warning string, err error) {
	old := st.MOKRequests[h.ID]
	if replaceID != "" && (old == nil || old.Request.ID != replaceID) {
		return false, "", fail(http.StatusConflict, "기존 MOK 요청 ID가 달라졌습니다. mok-status를 확인하세요")
	}
	if old != nil {
		same := old.Request.KeyID == cert.ID
		if same && old.CertSHA256 != cert.SHA256 {
			return false, "", fail(http.StatusConflict, "같은 키 ID의 DER가 바뀌었습니다")
		}
		outcome := ""
		if old.Result != nil {
			outcome = old.Result.Status
		}
		terminal := outcome == "failed" || outcome == "unsupported"
		// Only a recent, positive observation tied to this completed request
		// can release a credential whose MokNew write may have succeeded.
		empty := old.Result != nil && !s.hostStale(h) && h.Status.MOKListEmpty && !h.Status.MOKPending
		reported := h.Status.MOKImport != nil && h.Status.MOKImport.ID == old.Request.ID && h.Status.MOKImport.KeyID == old.Request.KeyID
		if replaceID != "" && !empty {
			return false, "", fail(http.StatusConflict, "기존 요청 처리 결과와 최근의 빈 MokNew 확인 필요. 기존 예약·비밀번호 보존")
		}
		if same {
			if replaceID != "" || manual && terminal && !h.Status.MOKPending {
				retry := *old
				retry.Request.ID, retry.Result = randHex(16), nil
				st.MOKRequests[h.ID] = &retry
				return true, "", nil
			}
			if !manual {
				return false, "", nil
			}
			return false, preservedMOKReason(h, old, cert.ID, empty), nil
		}
		// An unsupported result is issued before invoking --import. An enrolled
		// result needs no console credential. A failed import may have written it.
		completed := h.Status.EnrolledCerts[old.Request.KeyID] == "enrolled" || outcome == "enrolled" || outcome == "unsupported" || outcome == "failed" && empty && reported
		if replaceID == "" && (h.Status.MOKPending || !completed) {
			return false, preservedMOKReason(h, old, cert.ID, empty), nil
		}
	}
	var random [10]byte
	if _, err := rand.Read(random[:]); err != nil {
		return false, "", fmt.Errorf("MOK 비밀번호 생성 실패: %w", err)
	}
	password := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(random[:])
	hash, err := mokPasswordHash(password)
	if err != nil {
		return false, "", err
	}
	if st.MOKRequests == nil {
		st.MOKRequests = map[string]*MOKEnrollment{}
	}
	st.MOKRequests[h.ID] = &MOKEnrollment{
		Request:  model.MOKImportRequest{ID: randHex(16), KeyID: cert.ID, PasswordHash: hash},
		Password: password, CertSHA256: cert.SHA256,
	}
	return true, "", nil
}

func preservedMOKReason(h *model.Host, old *MOKEnrollment, target string, empty bool) string {
	reason := fmt.Sprintf("%s: 키 %s 요청 %s의 기존 예약·비밀번호 보존. ", h.Hostname, old.Request.KeyID, old.Request.ID)
	switch {
	case old.Result == nil:
		return reason + "awaiting_agent: 에이전트 연결·버전을 확인하고 기존 요청의 처리 보고를 기다리세요."
	case h.Status.MOKPending:
		return reason + "MokNew 대기 보고가 있습니다. 대상 인증서와 기존 콘솔 예약을 확인하세요."
	case empty && h.Status.EnrolledCerts[target] == "not_enrolled":
		return reason + fmt.Sprintf("최근 보고에서 MokNew가 비었고 키 %s는 미등록입니다. 재예약하려면 kpctl signing rollout-cert -host %s -replace-request %s %s", target, h.ID, old.Request.ID, target)
	default:
		return reason + "최근 MokNew 빈 목록과 대상 키의 미등록 여부를 확인하세요: kpctl hosts mok-status " + h.ID
	}
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
	var cert *model.SigningCert
	for i := range certs {
		if certs[i].ID == keyID {
			cert = &certs[i]
			break
		}
	}
	if cert == nil {
		writeErr(w, fail(http.StatusBadRequest, "서명 키 %q의 공개 인증서가 없습니다", keyID))
		return
	}
	target := r.PathValue("host")
	query, err := url.ParseQuery(r.URL.RawQuery)
	replaceID := query.Get("replace_request")
	if err != nil || len(query) > 0 && (len(query) != 1 || len(query["replace_request"]) != 1 || strings.TrimSpace(replaceID) == "" || target == "") {
		writeErr(w, fail(http.StatusBadRequest, "호스트 지정은 단일 호스트 API 경로를 사용하세요. replace_request에는 기존 요청 ID 하나가 필요합니다"))
		return
	}
	// Older fleet clients can send {}. Never silently ignore a host selector.
	if r.ContentLength != 0 {
		data, readErr := io.ReadAll(http.MaxBytesReader(w, r.Body, 1024))
		var body map[string]json.RawMessage
		if readErr != nil || len(strings.TrimSpace(string(data))) > 0 && (json.Unmarshal(data, &body) != nil || body == nil || len(body) != 0) {
			writeErr(w, fail(http.StatusBadRequest, "요청 본문은 비우세요. 대상 호스트는 경로에 지정합니다"))
			return
		}
	}
	count := 0
	var warnings []string
	scope := "all"
	err = s.store.UpdateAtomic(func(st *State) error {
		var ids []string
		for id, h := range st.Hosts {
			if target == "" || id == target || h.Hostname == target {
				ids = append(ids, id)
			}
		}
		if target != "" {
			if len(ids) == 0 {
				return fail(http.StatusNotFound, "호스트 %q가 없습니다", target)
			}
			if len(ids) != 1 {
				return fail(http.StatusConflict, "호스트 이름이 중복됩니다. 고유 ID를 지정하세요")
			}
			scope = "host=" + ids[0]
		}
		sort.Strings(ids)
		for _, id := range ids {
			h := st.Hosts[id]
			if h.Status.EnrolledCerts[keyID] == "enrolled" {
				if replaceID != "" {
					return fail(http.StatusConflict, "대상 키가 이미 enrolled입니다. 교체할 예약이 필요하지 않습니다")
				}
				if target != "" {
					warnings = append(warnings, h.Hostname+": 해당 키가 이미 enrolled입니다")
				}
				continue
			}
			scheduled, warning, err := s.scheduleMOK(st, h, *cert, true, replaceID)
			if err != nil {
				return err
			}
			if !scheduled {
				if target != "" {
					return fail(http.StatusConflict, "%s", warning)
				}
				warnings = append(warnings, warning)
				continue
			}
			count++
			if h.Status.Firmware != "uefi" {
				warnings = append(warnings, h.Hostname+": UEFI 상태를 확인하지 못했습니다. 자동 등록이 unsupported이면 수동 등록 절차를 확인하세요")
			}
		}
		return nil
	})
	if err != nil {
		writeErr(w, err)
		return
	}
	s.audit(who, "MOK 인증서 등록 예약 key=%s scope=%s hosts=%d replace_request=%q (재부팅 없음)", keyID, scope, count, replaceID)
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
		result = map[string]string{"key_id": enrollment.Request.KeyID, "status": "awaiting_agent", "warning": "에이전트의 예약 결과를 기다리세요"}
		if st.Hosts[hostID].Status.EnrolledCerts[enrollment.Request.KeyID] == "enrolled" {
			result["status"], result["warning"] = "enrolled", "이미 등록된 인증서"
		} else if enrollment.Result != nil {
			result["status"] = enrollment.Result.Status
			result["warning"] = enrollment.Result.Detail
			if enrollment.Result.Status == "pending_uncertain" {
				result["candidate_password"] = enrollment.Password
			}
			if enrollment.Result.Status == "failed" && st.Hosts[hostID].Status.MOKPending {
				result["candidate_password"] = enrollment.Password
				result["warning"] = joinSecurityWarnings(enrollment.Result.Detail, "호스트에 MOK 대기가 있지만 이 요청이 만든 대기인지 미확인입니다. 대상 DER와 최초 예약자를 확인한 뒤 후보 비밀번호를 대조하세요.")
			}
			if enrollment.Result.Status == "pending" && !strings.HasPrefix(enrollment.Result.Detail, "기존 MOK 예약 감지") {
				result["password"] = enrollment.Password
				if !enrollment.Result.PasswordSet {
					result["warning"] = joinSecurityWarnings(enrollment.Result.Detail, "비밀번호 출처 미확인. 아래 값이 콘솔 비밀번호와 다를 수 있으므로 최초 예약자에게 확인하세요.")
				}
			}
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
