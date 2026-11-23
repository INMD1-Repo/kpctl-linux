// 이 파일: 펌웨어·커널 서명 정책을 읽고 공통 보수적 판정으로 보고합니다.
package agent

import (
	"os"
	"path/filepath"
	"strings"

	"kpctl/internal/model"
)

const secureBootVariable = "SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"

// Keep unreadable or unavailable policy signals distinct from disabled ones.
// A BIOS machine can still require module signatures through lockdown or
// CONFIG_MODULE_SIG_FORCE / module.sig_enforce.
type hostSecurity struct {
	firmware   string
	secureBoot string
	lockdown   string
	sigEnforce string
}

func (s hostSecurity) signatureRequired() bool {
	required, _ := model.SignaturePolicy(s.secureBoot, s.lockdown, s.sigEnforce)
	return required
}

func (s hostSecurity) warning() string {
	_, warning := model.SignaturePolicy(s.secureBoot, s.lockdown, s.sigEnforce)
	return warning
}

func (a *Agent) securityStatus() hostSecurity {
	root := a.cfg.SysfsRoot
	if root == "" {
		root = "/sys"
	}
	s := hostSecurity{firmware: "unknown", secureBoot: "unknown", lockdown: "unknown", sigEnforce: "unknown"}
	if info, err := os.Stat(root); err == nil && info.IsDir() {
		efi := filepath.Join(root, "firmware/efi")
		if info, err := os.Stat(efi); err == nil && info.IsDir() {
			s.firmware = "uefi"
			// efivarfs prefixes each value with four bytes of EFI attributes.
			if data, err := os.ReadFile(filepath.Join(efi, "efivars", secureBootVariable)); err == nil && len(data) == 5 {
				switch data[4] {
				case 0:
					s.secureBoot = "off"
				case 1:
					s.secureBoot = "on"
				}
			}
		} else if os.IsNotExist(err) {
			s.firmware, s.secureBoot = "bios", "off"
		}
	}
	if data, err := os.ReadFile(filepath.Join(root, "kernel/security/lockdown")); err == nil {
		for _, level := range []string{"none", "integrity", "confidentiality"} {
			if strings.Contains(string(data), "["+level+"]") {
				s.lockdown = level
				break
			}
		}
	}
	if data, err := os.ReadFile(filepath.Join(root, "module/module/parameters/sig_enforce")); err == nil {
		switch strings.ToLower(strings.TrimSpace(string(data))) {
		case "1", "y", "yes", "true":
			s.sigEnforce = "on"
		case "0", "n", "no", "false":
			s.sigEnforce = "off"
		}
	}
	return s
}
