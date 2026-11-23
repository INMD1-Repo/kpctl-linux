// 이 파일: 읽지 못한 보안 신호와 이전 에이전트를 포함한 공통 서명 정책 시험.
package model

import (
	"strings"
	"testing"
)

func TestSignaturePolicyKnownSignals(t *testing.T) {
	for _, sb := range []string{"on", "off"} {
		for _, lockdown := range []string{"none", "integrity", "confidentiality"} {
			for _, enforce := range []string{"on", "off"} {
				t.Run(sb+"/"+lockdown+"/"+enforce, func(t *testing.T) {
					required, warning := SignaturePolicy(sb, lockdown, enforce)
					want := sb == "on" || lockdown != "none" || enforce == "on"
					if required != want || warning != "" {
						t.Fatalf("서명 필요=%v 경고=%q, want %v/빈 경고", required, warning, want)
					}
				})
			}
		}
	}
}

func TestSignaturePolicyUnreadableSignalsRequireSignatures(t *testing.T) {
	for _, signal := range []string{"secure_boot", "lockdown", "sig_enforce"} {
		for _, value := range []string{"", "unknown", "invalid"} {
			t.Run(signal+"/"+value, func(t *testing.T) {
				sb, lockdown, enforce := "off", "none", "off"
				switch signal {
				case "secure_boot":
					sb = value
				case "lockdown":
					lockdown = value
				case "sig_enforce":
					enforce = value
				}
				required, warning := SignaturePolicy(sb, lockdown, enforce)
				if !required || !strings.Contains(warning, signal) {
					t.Fatalf("읽지 못한 %s=%q: 서명 필요=%v 경고=%q", signal, value, required, warning)
				}
			})
		}
	}
}

func TestSignaturePolicyLegacyReportWarnsForEveryMissingSignal(t *testing.T) {
	required, warning := SignaturePolicy("", "", "")
	if !required {
		t.Fatal("보안 필드가 없는 이전 보고도 서명이 필요해야 함")
	}
	for _, field := range []string{"secure_boot", "lockdown", "sig_enforce"} {
		if !strings.Contains(warning, field) {
			t.Errorf("이전 보고 경고에서 %s 누락: %q", field, warning)
		}
	}
}
