// 이 파일: 키 ID와 DER 바이트의 영구 고정으로 이전 MOK 등록 보고를 다른 인증서에 재사용하지 않도록 검증.
package controller

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSigningIdentityPinsCertAcrossRestartAndRejectsReplacement(t *testing.T) {
	s := newAutoServer(t, AutoRollout{})
	certPath := signingAdminCert(t, time.Now().Add(90*24*time.Hour))
	s.cfg.Signing = &SigningConfig{Mode: "always", Keys: []SigningKey{{ID: "prod", Cert: certPath, Active: true, SignCommand: []string{"unused"}}}}
	addHost(t, s, "enrolled-host", 1)
	_ = s.store.Update(func(st *State) error {
		st.Hosts["enrolled-host"].Status.EnrolledCerts = map[string]string{"prod": "enrolled"}
		return nil
	})
	if err := s.initSigning(); err != nil {
		t.Fatal(err)
	}
	pinned := s.signingCertSHA256["prod"]
	if pinned == "" {
		t.Fatal("인증서 ID와 DER SHA256을 고정해야 함")
	}
	restarted, err := NewServer(s.cfg)
	if err != nil || restarted.signingCertSHA256["prod"] != pinned {
		t.Fatalf("같은 인증서로 재시작 실패: %v", err)
	}
	replacement, err := os.ReadFile(signingAdminCert(t, time.Now().Add(180*24*time.Hour)))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, replacement, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.signingCerts(); err == nil {
		t.Fatal("실행 중 DER 교체를 거부해야 함")
	}
	if _, err := NewServer(s.cfg); err == nil || !strings.Contains(err.Error(), "새 key ID") {
		t.Fatalf("기존 key ID를 새 인증서에 재사용함: %v", err)
	}
	// 새 ID는 별개의 등록 상태를 요구하므로 키 교체가 허용됩니다.
	s.cfg.Signing.Keys[0].ID = "prod-next"
	next, err := NewServer(s.cfg)
	if err != nil {
		t.Fatal(err)
	}
	next.store.View(func(st *State) {
		if st.SigningCertSHA256["prod"] != pinned || st.SigningCertSHA256["prod-next"] == "" {
			t.Fatalf("삭제된 ID의 인증서 고정도 보존해야 함: %v", st.SigningCertSHA256)
		}
		if st.Hosts["enrolled-host"].Status.EnrolledCerts["prod-next"] != "" {
			t.Fatal("옛 키 등록 상태를 새 ID로 이월하면 안 됨")
		}
	})
}

func TestSigningIdentityLegacyMissingCertWarnsExplicitMissingCertFails(t *testing.T) {
	s := newAutoServer(t, AutoRollout{})
	missing := filepath.Join(t.TempDir(), "missing.der")
	s.cfg.SignCommand = []string{"legacy-tool", missing, "{module}"}
	if _, err := NewServer(s.cfg); err != nil {
		t.Fatalf("기존 sign_command의 추정 인증서 경로는 시작 오류가 되면 안 됨: %v", err)
	}
	audit, err := os.ReadFile(filepath.Join(s.cfg.DataDir, "audit.log"))
	if err != nil || !strings.Contains(string(audit), "인증서 확인 실패") {
		t.Fatalf("추정 인증서 경고 누락: %s, %v", audit, err)
	}
	s.cfg.SignCommand = nil
	s.cfg.Signing = &SigningConfig{Mode: "always", Keys: []SigningKey{{ID: "prod", Cert: missing, Active: true, SignCommand: []string{"unused"}}}}
	if _, err := NewServer(s.cfg); err == nil {
		t.Fatal("명시 signing의 잘못된 인증서는 시작을 거부해야 함")
	}
}

func TestSigningIdentityLegacyPinnedCertChangeBlocksApproval(t *testing.T) {
	s := newAutoServer(t, AutoRollout{})
	certPath := signingAdminCert(t, time.Now().Add(90*24*time.Hour))
	s.cfg.SignCommand = []string{"unused-signer", certPath, "{module}"}
	if err := s.initSigning(); err != nil {
		t.Fatal(err)
	}
	replacement, err := os.ReadFile(signingAdminCert(t, time.Now().Add(180*24*time.Hour)))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, replacement, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.prepareSigningArtifacts(1, testKernel, "kpctl_test"); err == nil {
		t.Fatal("pinned legacy DER replacement must block signing")
	}
}
