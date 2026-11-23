// 이 파일: 컨트롤러 서버에서 kpctl status 가 재부팅 뒤 자동으로 켜지지 않을 서비스를 알려 줍니다 — bootWarnings.
//
// 현재 실행 중인 서비스도 자동 시작이 비활성화되어 있으면 다음 부팅에 시작되지 않을 수 있습니다.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// bootUnits 는 컨트롤러가 재부팅 뒤 스스로 켜야 하는 유닛과, 설치되어 있을 때만 검사할 표시 파일입니다.
var bootUnits = []struct{ unit, installedIf string }{
	{"kpctl-controller.service", ""},
	{"kpctl-dnsmasq.service", "/etc/kpctl/dnsmasq.conf"},
	{"kpctl-autoenroll.timer", "/etc/systemd/system/kpctl-autoenroll.timer"},
	{"kpctl-cve-inventory.timer", "/etc/systemd/system/kpctl-cve-inventory.timer"},
}

// bootWarnings 는 컨트롤러 서버(/etc/kpctl/controller.json 있음)에서만 검사합니다. root 아닌 원격 사용자는 해당 없음.
// isEnabled 는 시험에서 바꿔 끼웁니다.
func bootWarnings(etc string, isEnabled func(unit string) string) []string {
	if _, err := os.Stat(filepath.Join(etc, "controller.json")); err != nil {
		return nil
	}
	var off []string
	for _, u := range bootUnits {
		if u.installedIf != "" {
			if _, err := os.Stat(u.installedIf); err != nil {
				continue
			}
		}
		if state := isEnabled(u.unit); state != "enabled" && state != "" {
			off = append(off, u.unit+"("+state+")")
		}
	}
	if len(off) == 0 {
		return nil
	}
	return []string{fmt.Sprintf("재부팅하면 자동으로 켜지지 않습니다: %s → sudo systemctl enable %s",
		strings.Join(off, ", "), strings.Join(unitNames(off), " "))}
}

func unitNames(off []string) []string {
	out := make([]string, len(off))
	for i, s := range off {
		out[i], _, _ = strings.Cut(s, "(")
	}
	return out
}

// systemctlEnabled 는 "enabled", "disabled" 등을 돌려줍니다. systemctl 이 없으면 "" (검사 안 함).
func systemctlEnabled(unit string) string {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return ""
	}
	out, _ := exec.Command("systemctl", "is-enabled", unit).Output()
	return strings.TrimSpace(string(out))
}
