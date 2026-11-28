// 이 파일: 공개 키 목록의 비밀값 차단, 만료·키 제거 경고와 호스트별 MOK 예약 검증.
package controller

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kpctl/internal/model"
)

func signingAdminCert(t *testing.T, expires time.Time) string {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "kpctl test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: expires}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, public, private)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "test.der")
	if err := os.WriteFile(path, der, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestSigningAdminExpiryAndRemovedKeyWarnings(t *testing.T) {
	s := newAutoServer(t, AutoRollout{})
	certPath := signingAdminCert(t, time.Now().Add(15*24*time.Hour))
	s.cfg.Signing = &SigningConfig{Mode: "always", Keys: []SigningKey{{ID: "active", Active: true, Cert: certPath, SignCommand: []string{"private-key-secret", "{module}"}}}}
	addHost(t, s, "current", 1)
	addHost(t, s, "firmware-db", 1)
	addHost(t, s, "old-only", 2)
	_ = s.store.Update(func(st *State) error {
		st.Hosts["current"].Status.EnrolledCerts = map[string]string{"active": "enrolled"}
		st.Hosts["firmware-db"].Status.EnrolledCerts = map[string]string{"active": "in_db"}
		st.Hosts["old-only"].Status.EnrolledCerts = map[string]string{"retired": "enrolled", "active": "not_enrolled"}
		return nil
	})
	body := callAPI(t, s, "GET", "/api/signing", "", http.StatusOK)
	if strings.Contains(body, certPath) || strings.Contains(body, "private-key-secret") {
		t.Fatalf("공개 키 응답에 비밀 경로가 노출됨: %s", body)
	}
	var status model.SigningStatus
	if err := json.Unmarshal([]byte(body), &status); err != nil {
		t.Fatal(err)
	}
	if len(status.Keys) != 1 || status.Keys[0].EnrolledHosts != 1 || status.Keys[0].ExpiresAt == nil || !strings.Contains(status.Keys[0].Warning, "30일") {
		t.Fatalf("서명 현황 = %+v", status)
	}
	if len(status.Warnings) != 1 || !strings.Contains(status.Warnings[0], "old-only") || !strings.Contains(status.Warnings[0], "blocked_mok_missing") {
		t.Fatalf("키 제거 경고 = %v", status.Warnings)
	}
	if err := s.initSigning(); err != nil {
		t.Fatal(err)
	}
	audit, err := os.ReadFile(filepath.Join(s.cfg.DataDir, "audit.log"))
	if err != nil || !strings.Contains(string(audit), "30일") || !strings.Contains(string(audit), "old-only") {
		t.Fatalf("만료·키 제거 감사 기록 = %s, %v", audit, err)
	}
}

func TestMOKRolloutStoresOnlyHostPasswordsAndNeverReboots(t *testing.T) {
	s := newAutoServer(t, AutoRollout{})
	s.cfg.Signing = &SigningConfig{Mode: "always", Keys: []SigningKey{{ID: "prod", Active: true, Cert: signingAdminCert(t, time.Now().Add(90*24*time.Hour)), SignCommand: []string{"unused"}}}}
	for _, id := range []string{"a", "b", "enrolled"} {
		addHost(t, s, id, 1)
	}
	_ = s.store.Update(func(st *State) error {
		for _, h := range st.Hosts {
			h.Status.Firmware = "uefi"
			h.Status.EnrolledCerts = map[string]string{"prod": "not_enrolled"}
		}
		st.Hosts["enrolled"].Status.EnrolledCerts["prod"] = "enrolled"
		return nil
	})
	body := callAPI(t, s, "POST", "/api/signing/prod/rollout-cert", "", http.StatusOK)
	if !strings.Contains(body, `"scheduled_hosts":2`) {
		t.Fatalf("등록 예약 결과 = %s", body)
	}
	var password, requestID string
	s.store.View(func(st *State) {
		if len(st.MOKRequests) != 2 {
			t.Fatalf("등록 예약 = %+v", st.MOKRequests)
		}
		a, b := st.MOKRequests["a"], st.MOKRequests["b"]
		password, requestID = a.Password, a.Request.ID
		if password == "" || password == b.Password || a.Request.PasswordHash == b.Request.PasswordHash || !strings.HasPrefix(a.Request.PasswordHash, "$6$") {
			t.Fatal("호스트별 임의 비밀번호·SHA512 crypt 해시가 필요함")
		}
		requestJSON := string(mustJSON(a.Request))
		if strings.Contains(requestJSON, password) {
			t.Fatal("에이전트 요청에 원문 비밀번호 노출")
		}
		for _, h := range st.Hosts {
			if h.RebootRequestID != 0 || h.RebootApproval != nil {
				t.Fatal("MOK 예약으로 재부팅이 승인됨")
			}
		}
	})
	callAPI(t, s, "POST", "/api/signing/prod/rollout-cert", "", http.StatusOK)
	s.store.View(func(st *State) {
		if st.MOKRequests["a"].Request.ID != requestID {
			t.Fatal("동일한 미완료 요청은 보존해야 함")
		}
	})
	public := callAPI(t, s, "GET", "/api/status", "", http.StatusOK)
	if strings.Contains(public, password) || strings.Contains(public, "password_hash") {
		t.Fatal("일반 상태 API에 MOK 비밀값 노출")
	}
	req := httptest.NewRequest("GET", "/api/hosts/a/mok-password", nil)
	req.Header.Set("Authorization", "Bearer "+testAdmin)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-store" || strings.Contains(rec.Body.String(), password) || !strings.Contains(rec.Body.String(), "awaiting_agent") {
		t.Fatalf("비밀번호 전용 조회 = %d, %s", rec.Code, rec.Body.String())
	}
	for _, tc := range []struct {
		status, detail string
		reveal, owned  bool
	}{
		{"pending_existing", "최초 예약자에게 확인", false, false},
		{"pending_uncertain", "이 요청 비밀번호가 다를 수 있습니다", true, false},
		{"pending", "기존 MOK 예약 감지: 콘솔 승인 필요", false, false},
		{"pending", "다음 계획된 재부팅 때 콘솔에서 MOK 승인 필요", true, false},
		{"pending", "다음 계획된 재부팅 때 콘솔에서 MOK 승인 필요", true, true},
	} {
		if err := s.store.Update(func(st *State) error {
			st.MOKRequests["a"].Result = &model.MOKImportResult{ID: requestID, KeyID: "prod", Status: tc.status, Detail: tc.detail, PasswordSet: tc.owned}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		result := callAPI(t, s, "GET", "/api/hosts/a/mok-password", "", http.StatusOK)
		if strings.Contains(result, password) != tc.reveal || tc.reveal && !tc.owned && !strings.Contains(result, "다를 수") {
			t.Fatalf("unexpected password handling for %s", tc.status)
		}
	}
	callAPI(t, s, "GET", "/api/hosts/enrolled/mok-password", "", http.StatusNotFound)
	second := s.cfg.Signing.Keys[0]
	second.ID, second.Active = "next", false
	s.cfg.Signing.Keys = append(s.cfg.Signing.Keys, second)
	response := callAPI(t, s, "POST", "/api/signing/next/rollout-cert", "", http.StatusOK)
	if !strings.Contains(response, "비밀번호 보존") {
		t.Fatal("other key rollout ignored existing request")
	}
	s.store.View(func(st *State) {
		if st.MOKRequests["a"].Password != password || st.MOKRequests["a"].Request.ID != requestID {
			t.Fatal("lost password on other key rollout")
		}
	})
	if err := s.store.Update(func(st *State) error { st.MOKRequests["a"].Result.Status = "failed"; return nil }); err != nil {
		t.Fatal(err)
	}
	callAPI(t, s, "POST", "/api/signing/prod/rollout-cert", "", http.StatusOK)
	s.store.View(func(st *State) {
		retry := st.MOKRequests["a"]
		if retry.Result != nil || retry.Request.ID == requestID || retry.Password != password {
			t.Fatal("explicit retry lost the previous password or reused a completed request ID")
		}
	})
	audit, _ := os.ReadFile(filepath.Join(s.cfg.DataDir, "audit.log"))
	if !strings.Contains(string(audit), "MOK 비밀번호 조회 host=a") || strings.Contains(string(audit), password) {
		t.Fatal("비밀번호 조회는 감사되지만 비밀번호 원문은 감사 로그에 없어야 함")
	}
	callAPI(t, s, "POST", "/api/signing/missing/rollout-cert", "", http.StatusNotFound)
}

func TestMOKPasswordHashToolFailureIsSanitized(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "openssl"), []byte("#!/bin/sh\nread -r password\nprintf '%s' \"$password\" >&2\nexit 1\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	_, err := mokPasswordHash("do-not-disclose")
	if err == nil || strings.Contains(err.Error(), "do-not-disclose") {
		t.Fatalf("비밀값을 출력하지 않는 도구 실패 필요: %v", err)
	}
}

func TestMOKRolloutHashFailureDoesNotPartiallySchedule(t *testing.T) {
	s := newAutoServer(t, AutoRollout{})
	s.cfg.Signing = &SigningConfig{Mode: "always", Keys: []SigningKey{{ID: "prod", Active: true, Cert: signingAdminCert(t, time.Now().Add(90*24*time.Hour)), SignCommand: []string{"unused"}}}}
	addHost(t, s, "a", 1)
	addHost(t, s, "b", 1)
	dir := t.TempDir()
	marker := filepath.Join(dir, "called")
	script := "#!/bin/sh\nif [ -f '" + marker + "' ]; then exit 1; fi\n: > '" + marker + "'\nprintf '$6$test$hash\\n'\n"
	if err := os.WriteFile(filepath.Join(dir, "openssl"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	callAPI(t, s, "POST", "/api/signing/prod/rollout-cert", "", http.StatusInternalServerError)
	s.store.View(func(st *State) {
		if len(st.MOKRequests) != 0 {
			t.Fatalf("해시 도구 실패 뒤 일부 예약이 메모리에 남음: %+v", st.MOKRequests)
		}
	})
}
