// 이 파일: 설정 조회·저장 응답의 서명 공개 정보와 비밀 경로 비노출 검증.
package controller

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSettingsPublishesOnlySigningSummaryOnReadAndWrite(t *testing.T) {
	s := newAutoServer(t, AutoRollout{})
	cert := signingAdminCert(t, time.Now().Add(10*24*time.Hour))
	s.cfg.Signing = &SigningConfig{Mode: "always", Keys: []SigningKey{{ID: "public-id", Active: true, Cert: cert, SignCommand: []string{"/private/signer", "/secret/private.priv", "{module}"}}}}
	for _, method := range []string{"GET", "POST"} {
		body := ""
		if method == "POST" {
			body = `{"host_stale_minutes":12}`
		}
		response := callAPI(t, s, method, "/api/settings", body, http.StatusOK)
		if !strings.Contains(response, `"signing"`) || !strings.Contains(response, `"id":"public-id"`) || !strings.Contains(response, "30일") {
			t.Fatalf("공개 서명 목록·만료 경고 누락: %s", response)
		}
		for _, secret := range []string{cert, "/private/signer", "/secret/private.priv", "sign_command", "password_hash"} {
			if strings.Contains(response, secret) {
				t.Fatalf("설정 응답에 비밀 경로/명령 노출: %s", secret)
			}
		}
	}
}

func TestSigningExpiryBoundaryIsAuditedDuringLongRunningController(t *testing.T) {
	s := newAutoServer(t, AutoRollout{})
	now := time.Now()
	cert := signingAdminCert(t, now.Add(31*24*time.Hour))
	s.cfg.Signing = &SigningConfig{Mode: "always", Keys: []SigningKey{{ID: "long-running", Active: true, Cert: cert, SignCommand: []string{"unused"}}}}
	if err := s.initSigning(); err != nil {
		t.Fatal(err)
	}
	s.auditSigningWarnings(s.signingStatusAt(now.Add(2 * 24 * time.Hour)))
	s.auditSigningWarnings(s.signingStatusAt(now.Add(2 * 24 * time.Hour)))
	audit, err := os.ReadFile(filepath.Join(s.cfg.DataDir, "audit.log"))
	if err != nil || strings.Count(string(audit), "서명 키 long-running: 인증서 만료가 30일 이내입니다") != 1 {
		t.Fatalf("만료 경계 감사는 한 번 기록해야 함: %s (%v)", audit, err)
	}
}
