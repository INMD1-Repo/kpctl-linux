// 이 파일: agent 패키지의 TestFirmwareAndSignaturePolicy, TestFirmwareUnknownWhenSysfsUnavailable, TestReportIncludesFirmwareAndSignaturePolicy 회귀 시험.
package agent

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"kpctl/internal/client"
	"kpctl/internal/model"
)

func TestFirmwareAndSignaturePolicy(t *testing.T) {
	for _, tc := range []struct {
		name       string
		efi        bool
		secureBoot string
		lockdown   string
		sigEnforce string
		want       hostSecurity
		required   bool
	}{
		{"UEFI Secure Boot", true, "\x07\x00\x00\x00\x01", "[none] integrity confidentiality", "N", hostSecurity{"uefi", "on", "none", "off"}, true},
		{"UEFI without Secure Boot", true, "\x07\x00\x00\x00\x00", "[none] integrity confidentiality", "0", hostSecurity{"uefi", "off", "none", "off"}, false},
		{"BIOS", false, "", "[none] integrity confidentiality", "N", hostSecurity{"bios", "off", "none", "off"}, false},
		{"BIOS lockdown integrity", false, "", "none [integrity] confidentiality", "N", hostSecurity{"bios", "off", "integrity", "off"}, true},
		{"BIOS lockdown confidentiality", false, "", "none integrity [confidentiality]", "N", hostSecurity{"bios", "off", "confidentiality", "off"}, true},
		{"BIOS module signature enforcement", false, "", "[none] integrity confidentiality", "Y", hostSecurity{"bios", "off", "none", "on"}, true},
		{"UEFI unreadable variables", true, "", "", "", hostSecurity{"uefi", "unknown", "unknown", "unknown"}, true},
		{"UEFI truncated variable", true, "\x01", "[other]", "invalid", hostSecurity{"uefi", "unknown", "unknown", "unknown"}, true},
		{"UEFI invalid variable", true, "\x07\x00\x00\x00\x02", "[none]", "N", hostSecurity{"uefi", "unknown", "none", "off"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			a := &Agent{cfg: &Config{SysfsRoot: root}}
			if tc.efi {
				if err := os.MkdirAll(filepath.Join(root, "firmware/efi"), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			for path, data := range map[string]string{
				"firmware/efi/efivars/" + secureBootVariable: tc.secureBoot,
				"kernel/security/lockdown":                   tc.lockdown,
				"module/module/parameters/sig_enforce":       tc.sigEnforce,
			} {
				if data != "" {
					writeTestFile(t, filepath.Join(root, path), data)
				}
			}
			got := a.securityStatus()
			if got != tc.want || got.signatureRequired() != tc.required {
				t.Fatalf("got %+v required=%v; want %+v required=%v", got, got.signatureRequired(), tc.want, tc.required)
			}
			if (got.warning() != "") != (got.secureBoot == "unknown" || got.lockdown == "unknown" || got.sigEnforce == "unknown") {
				t.Fatalf("unknown policy warning missing: %+v warning=%q", got, got.warning())
			}
		})
	}
}

func TestFirmwareUnknownWhenSysfsUnavailable(t *testing.T) {
	a := &Agent{cfg: &Config{SysfsRoot: filepath.Join(t.TempDir(), "unmounted")}}
	got := a.securityStatus()
	if got.firmware != "unknown" || got.secureBoot != "unknown" {
		t.Fatalf("unavailable sysfs reported as disabled: %+v", got)
	}
}

func TestReportIncludesFirmwareAndSignaturePolicy(t *testing.T) {
	a, root := newTestAgent(t)
	a.cfg.SysfsRoot = filepath.Join(root, "sys")
	writeTestFile(t, filepath.Join(a.cfg.SysfsRoot, "module/module/parameters/sig_enforce"), "Y\n")
	var got model.ReportRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Error(err)
		}
		_ = json.NewEncoder(w).Encode(model.ReportResponse{})
	}))
	defer srv.Close()
	var err error
	a.c, err = client.New(srv.URL, "token", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.report(); err != nil {
		t.Fatal(err)
	}
	if got.Status.Firmware != "bios" || got.Status.SecureBoot != "off" || got.Status.SigEnforce != "on" || !got.Status.SignatureRequired {
		t.Fatalf("policy missing from API report: %+v", got.Status)
	}
}
