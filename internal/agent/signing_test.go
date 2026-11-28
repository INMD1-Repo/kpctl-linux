// 이 파일: 가짜 mokutil로 인증서 판정·무결성·예약과 재부팅 분리를 확인합니다.
package agent

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kpctl/internal/client"
	"kpctl/internal/model"
)

func signingCertFixture(t *testing.T) model.SigningCert {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "kpctl signing test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return model.SigningCert{ID: "prod-2026", SHA256: fmt.Sprintf("%x", sha256.Sum256(der)), DER: der, Active: true}
}

func fakeMOKFixture(t *testing.T, a *Agent, root, state string) {
	t.Helper()
	a.cfg.SysfsRoot = filepath.Join(root, "security-sys")
	if err := os.MkdirAll(filepath.Join(a.cfg.SysfsRoot, "firmware/efi"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(a.cfg.SysfsRoot, "firmware/efi/efivars", secureBootVariable), "\x07\x00\x00\x00\x01")
	writeTestFile(t, filepath.Join(a.cfg.SysfsRoot, "kernel/security/lockdown"), "none [integrity] confidentiality")
	writeTestFile(t, filepath.Join(a.cfg.SysfsRoot, "module/module/parameters/sig_enforce"), "Y")
	mokRoot := filepath.Join(root, "mok")
	writeTestFile(t, filepath.Join(mokRoot, "state"), state)
	t.Setenv("MOK_TEST_ROOT", mokRoot)
	a.cfg.MokutilBin = filepath.Join(root, "mokutil")
	writeTestFile(t, a.cfg.MokutilBin, `#!/bin/sh
set -eu
printf '%s\n' "$*" >> "$MOK_TEST_ROOT/calls"
case "$1" in
  --help) printf '%s\n' '--hash-file <hash file>' '--ignore-keyring'; exit 255 ;;
  --list-new) if [ -f "$MOK_TEST_ROOT/pending" ] || [ -f "$MOK_TEST_ROOT/other" ]; then printf '[key 1]\n'; fi ;;
  --test-key)
    [ "$3" = --ignore-keyring ]
    if [ -f "$MOK_TEST_ROOT/pending" ]; then
      printf '%s is already in the enrollment request\n' "$2"
    else
      case "$(cat "$MOK_TEST_ROOT/state")" in
        enrolled) printf '%s is already enrolled\n' "$2" ;;
        db) printf '%s is already in db\n' "$2" ;;
        not_enrolled) printf '%s is not enrolled\n' "$2"; exit 1 ;;
        pending) printf '%s is already in the enrollment request\n' "$2" ;;
        enrolled06) printf '%s is already enrolled\n' "$2"; exit 1 ;;
        missing06) printf '%s is not enrolled\n' "$2" ;;
        pending06) printf '%s is already in the enrollment request\n' "$2"; exit 1 ;;
        badexit) printf '%s is already enrolled\n' "$2"; exit 2 ;;
        unrelated) printf 'another.der is already enrolled\n'; exit 1 ;;
        blocked) printf '%s is blocked in dbx\n' "$2" ;;
        *) printf '%s\n' 'cannot read EFI variables'; exit 2 ;;
      esac
    fi ;;
  --import)
    [ "$3" = --hash-file ]
    [ -f "$4" ]
    [ "$(stat -c %a "$4")" = 600 ]
    printf '%s\n' "$*" >> "$MOK_TEST_ROOT/imports"
    touch "$MOK_TEST_ROOT/pending"
    case "${MOK_TEST_OUTPUT:-}" in
      warn) echo 'Warning: locale diagnostic' >&2 ;;
      race) echo "SKIP: $2 is already in the enrollment request" ;;
      skip) echo "SKIP: unrecognized diagnostic" ;;
      misc) echo "unspecified output" ;;
    esac
    ;;
  *) exit 2 ;;
esac
`)
	if err := os.Chmod(a.cfg.MokutilBin, 0o700); err != nil {
		t.Fatal(err)
	}
}

func TestMOKEnrollmentReportsExactOutputAndExitContract(t *testing.T) {
	for _, tc := range []struct {
		state, want string
		pending     bool
	}{
		{"enrolled", "enrolled", false}, {"db", "in_db", false},
		{"not_enrolled", "not_enrolled", false}, {"pending", "not_enrolled", true},
		{"blocked", "not_enrolled", false}, {"unreadable", "unknown", false},
		{"enrolled06", "enrolled", false}, {"missing06", "not_enrolled", false},
		{"pending06", "not_enrolled", true}, {"badexit", "unknown", false}, {"unrelated", "unknown", false},
	} {
		t.Run(tc.state, func(t *testing.T) {
			a, root := newTestAgent(t)
			fakeMOKFixture(t, a, root, tc.state)
			cert := signingCertFixture(t)
			a.st.SigningCerts = []model.SigningCert{cert}
			states, pending, empty, warning := a.enrollmentStatus(a.securityStatus())
			if states[cert.ID] != tc.want || empty == tc.pending || pending != tc.pending || (warning != "") != (tc.want == "unknown" || tc.want == "in_db") {
				t.Fatalf("states=%v pending=%v warning=%q", states, pending, warning)
			}
		})
	}
}

func TestMOKNonUEFIAndMissingToolAreUnknown(t *testing.T) {
	for _, firmware := range []string{"uefi", "bios"} {
		t.Run(firmware, func(t *testing.T) {
			a, root := newTestAgent(t)
			fakeMOKFixture(t, a, root, "enrolled")
			a.cfg.MokutilBin = filepath.Join(root, "missing-mokutil")
			cert := signingCertFixture(t)
			a.st.SigningCerts = []model.SigningCert{cert}
			states, pending, empty, _ := a.enrollmentStatus(hostSecurity{firmware: firmware})
			if states[cert.ID] != "unknown" || pending || empty {
				t.Fatal(states, pending)
			}
		})
	}
}

func TestMOKRejectsChangedDERBeforeToolChecks(t *testing.T) {
	a, root := newTestAgent(t)
	fakeMOKFixture(t, a, root, "enrolled")
	cert := signingCertFixture(t)
	cert.DER[0] ^= 0xff
	a.st.SigningCerts = []model.SigningCert{cert}
	states, _, _, warning := a.enrollmentStatus(a.securityStatus())
	calls, _ := os.ReadFile(filepath.Join(root, "mok/calls"))
	if states[cert.ID] != "unknown" || warning == "" || strings.Contains(string(calls), "--test-key") {
		t.Fatalf("tampered DER checked by mokutil: states=%v warning=%s calls=%s", states, warning, calls)
	}
}

func TestMOKImportCycleDefersIndependentRebootUntilNextCycle(t *testing.T) {
	a, approval, root, _ := rebootAgentFixture(t)
	fakeMOKFixture(t, a, root, "not_enrolled")
	a.st.HostID, a.st.HostToken = "host", "host-token"
	a.cfg.MOKAutoImport = true
	cert := signingCertFixture(t)
	request := &model.MOKImportRequest{ID: "request-1", KeyID: cert.ID, PasswordHash: "$6$test$only-a-fake-password-hash"}
	var reports []model.ReportRequest
	claims := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/agent/reboot/claim" {
			claims++
			_ = json.NewEncoder(w).Encode(map[string]string{"result": "claimed"})
			return
		}
		var req model.ReportRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
		}
		reports = append(reports, req)
		response := model.ReportResponse{SigningCerts: []model.SigningCert{cert}, Reboot: approval}
		if req.Status.MOKImport == nil {
			response.MOKImport = request
		}
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer srv.Close()
	a.c, _ = client.New(srv.URL, "host-token", "")
	a.Cycle()
	if claims != 0 || a.st.LastRebootID != 0 {
		t.Fatal("MOK import entered reboot path")
	}
	if _, err := os.Stat(filepath.Join(root, "rebooted")); !os.IsNotExist(err) {
		t.Fatal("MOK import called reboot hook")
	}
	if len(reports) < 2 || reports[1].Status.MOKImport == nil || reports[1].Status.MOKImport.Status != "pending" || !reports[1].Status.MOKImport.PasswordSet || !reports[1].Status.MOKPending || !reports[1].AutoImportCert {
		t.Fatalf("MOK result not reported: %+v", reports)
	}
	imports, err := os.ReadFile(filepath.Join(root, "mok/imports"))
	if err != nil || strings.Count(string(imports), "--import") != 1 || strings.Contains(string(imports), request.PasswordHash) {
		t.Fatalf("unexpected imports: %s (%v)", imports, err)
	}
	state, err := os.ReadFile(a.statePath())
	if err != nil || strings.Contains(string(state), request.PasswordHash) {
		t.Fatal("agent persisted MOK password hash", err)
	}
	files, err := filepath.Glob(filepath.Join(a.cfg.StateDir, ".mok-hash-*"))
	if err != nil || len(files) != 0 {
		t.Fatal("MOK hash file was not removed", files, err)
	}
	if err := a.loadState(); err != nil {
		t.Fatal(err)
	}
	if a.reconcileSigning(model.ReportResponse{SigningCerts: []model.SigningCert{cert}, MOKImport: request}) {
		t.Fatal("same MOK request replayed after state reload")
	}
	// 요청 결과를 받은 컨트롤러가 MOK 요청을 내리지 않으면 별도 scoped 승인은
	// 다음 주기에 정상 실행할 수 있습니다. MOK 자체가 재부팅을 승인하지는 않습니다.
	a.Cycle()
	if claims != 1 || a.st.LastRebootID != approval.ID {
		t.Fatalf("independent scoped reboot was blocked: claims=%d state=%+v", claims, a.st)
	}
}

func TestMOKListPendingIgnoresEmptyDiagnostics(t *testing.T) {
	for _, tc := range []struct {
		out            string
		pending, known bool
	}{
		{"", false, true}, {"MokNew is empty\n", false, true},
		{"[key 1]\n", true, true}, {"SHA1 Fingerprint: ab:cd", true, true},
		{"EFI variable read failed", false, false},
	} {
		pending, known := mokListPending([]byte(tc.out))
		if pending != tc.pending || known != tc.known {
			t.Fatalf("%q: pending=%v known=%v", tc.out, pending, known)
		}
	}
}

func TestNewCertificatesAreReportedBeforeApplyingDesired(t *testing.T) {
	a, root := newTestAgent(t)
	fakeMOKFixture(t, a, root, "not_enrolled")
	a.st.HostID, a.st.HostToken = "host", "token"
	cert := signingCertFixture(t)
	reports, downloads := 0, 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/agent/report" {
			downloads++
			http.Error(w, "must not download", http.StatusForbidden)
			return
		}
		var req model.ReportRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		reports++
		response := model.ReportResponse{SigningCerts: []model.SigningCert{cert}, Desired: model.DesiredPatch{Version: 2, ModuleName: "kpctl_test_v2", URL: "/module.ko"}}
		if req.Status.EnrolledCerts[cert.ID] == "not_enrolled" {
			response.Desired = model.DesiredPatch{Blocked: true}
		}
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer srv.Close()
	a.c, _ = client.New(srv.URL, "token", "")
	a.Cycle()
	if reports != 2 || downloads != 0 || a.lastErr != "" {
		t.Fatalf("did not reconcile before applying: reports=%d downloads=%d error=%s", reports, downloads, a.lastErr)
	}
}

func TestMOKCollectionFailureDoesNotFailReport(t *testing.T) {
	a, root := newTestAgent(t)
	fakeMOKFixture(t, a, root, "enrolled")
	a.cfg.MokutilBin = filepath.Join(root, "missing-mokutil")
	a.st.SigningCerts = []model.SigningCert{signingCertFixture(t)}
	var report model.ReportRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&report)
		_ = json.NewEncoder(w).Encode(model.ReportResponse{})
	}))
	defer srv.Close()
	a.c, _ = client.New(srv.URL, "token", "")
	if _, err := a.report(); err != nil {
		t.Fatal(err)
	}
	if report.Status.SecurityWarning == "" || report.Status.Error != "" || report.Status.EnrolledCerts["prod-2026"] != "unknown" {
		t.Fatalf("collection error incorrectly failed report: %+v", report.Status)
	}
}

func TestBlockedDesiredPreservesExistingProtection(t *testing.T) {
	a, _ := newTestAgent(t)
	old := previousVersion(t, a)
	if a.apply(model.DesiredPatch{Blocked: true}) || !a.moduleLoaded(old) || a.st.Version != 1 || len(a.st.Installed) != 1 {
		t.Fatal("blocked deployment unloaded the current protection")
	}
}

func TestMOKImportUnsupportedReportsManualProcedure(t *testing.T) {
	a, root := newTestAgent(t)
	a.cfg.SysfsRoot = filepath.Join(root, "sys")
	cert := signingCertFixture(t)
	a.st.SigningCerts = []model.SigningCert{cert}
	result := a.importMOK(model.MOKImportRequest{ID: "request", KeyID: cert.ID})
	if result.Status != "unsupported" || !strings.Contains(result.Detail, "수동 mokutil --import") || !strings.Contains(result.Detail, "자동 재부팅하지 않음") {
		t.Fatal(result)
	}
}

func TestImportPreservesPendingRequests(t *testing.T) {
	for _, tc := range []struct {
		state, status string
		other         bool
	}{
		{"pending", "pending_existing", false}, {"not_enrolled", "failed", true}, {"db", "unsupported", false},
	} {
		t.Run(tc.state, func(t *testing.T) {
			a, root := newTestAgent(t)
			fakeMOKFixture(t, a, root, tc.state)
			cert := signingCertFixture(t)
			a.st.SigningCerts = []model.SigningCert{cert}
			if tc.other {
				writeTestFile(t, filepath.Join(root, "mok/other"), "existing request")
			}
			result := a.importMOK(model.MOKImportRequest{ID: "new", KeyID: cert.ID, PasswordHash: "$6$fixture"})
			if result.Status != tc.status || result.Detail == "" || result.PasswordSet {
				t.Fatal(result)
			}
			if _, err := os.Stat(filepath.Join(root, "mok/imports")); !os.IsNotExist(err) {
				t.Fatalf("unexpected import: %v", err)
			}
		})
	}
}

func TestImportMOKSuccessWithDiagnostics(t *testing.T) {
	for _, tc := range []struct {
		output, status string
		owned          bool
	}{
		{"", "pending", true}, {"warn", "pending", false}, {"race", "pending_existing", false}, {"skip", "pending_uncertain", false}, {"misc", "pending_uncertain", false},
	} {
		t.Run(tc.output, func(t *testing.T) {
			a, root := newTestAgent(t)
			fakeMOKFixture(t, a, root, "not_enrolled")
			cert := signingCertFixture(t)
			a.st.SigningCerts = []model.SigningCert{cert}
			t.Setenv("MOK_TEST_OUTPUT", tc.output)
			got := a.importMOK(model.MOKImportRequest{ID: "r", KeyID: cert.ID, PasswordHash: "$6$test"})
			if got.Status != tc.status || got.PasswordSet != tc.owned || got.Detail == "" {
				t.Fatal(got)
			}
		})
	}
}
