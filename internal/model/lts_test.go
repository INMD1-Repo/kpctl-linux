// 이 파일: model 패키지의 TestLTSForKernel, TestSignature, TestKernelABI 회귀 시험.
package model

import "testing"

func TestLTSForKernel(t *testing.T) {
	cases := map[string]string{
		"5.15.0-125-generic":  "jammy",
		"6.8.0-85-generic":    "noble",
		"7.0.0-12-generic":    "resolute",
		"6.8.0-1020-nvidia":   "", // 파생 커널
		"6.14.0-29-generic":   "", // HWE
		"6.8.0-85-lowlatency": "",
		"5.4.0-200-generic":   "", // 표준 지원 끝난 20.04
	}
	for kernel, want := range cases {
		got := ""
		if s := LTSForKernel(kernel); s != nil {
			got = s.Codename
		}
		if got != want {
			t.Errorf("LTSForKernel(%q) = %q, want %q", kernel, got, want)
		}
	}
}

func TestSignature(t *testing.T) {
	cases := []struct {
		sig, version string
		hwe          bool
	}{
		{"Ubuntu 6.8.0-85.85-generic 6.8.12", "6.8.0-85.85", false},
		{"Ubuntu 6.8.0-85.85~22.04.1-generic 6.8.12", "6.8.0-85.85~22.04.1", true},
		{"Ubuntu 5.15.0-125.135-generic 5.15.167", "5.15.0-125.135", false},
		{"", "", false},
		{"Debian 6.1.0", "", false},
	}
	for _, c := range cases {
		if got := SignatureVersion(c.sig); got != c.version {
			t.Errorf("SignatureVersion(%q) = %q, want %q", c.sig, got, c.version)
		}
		if got := IsHWESignature(c.sig); got != c.hwe {
			t.Errorf("IsHWESignature(%q) = %v, want %v", c.sig, got, c.hwe)
		}
	}
}

func TestKernelABI(t *testing.T) {
	if got := KernelABI("6.8.0-85-generic"); got != "6.8.0-85" {
		t.Errorf("KernelABI = %q", got)
	}
}
