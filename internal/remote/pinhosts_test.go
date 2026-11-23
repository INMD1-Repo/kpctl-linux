// 이 파일: remote 패키지의 TestPinHostsSurvivesCloudInit 회귀 시험.
package remote

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// cloud-init(manage_etc_hosts)이 부팅마다 템플릿으로 /etc/hosts 를 다시 쓰면 설치 때 넣은 줄이 사라져
// cloud-init이 호스트 파일을 다시 생성해도 이름을 찾도록 템플릿 갱신을 확인합니다.
func TestPinHostsSurvivesCloudInit(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash 없음")
	}
	root := t.TempDir()
	tmpl := filepath.Join(root, "etc/cloud/templates/hosts.debian.tmpl")
	hosts := filepath.Join(root, "etc/hosts")
	if err := os.MkdirAll(filepath.Dir(tmpl), 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(hosts, []byte("127.0.0.1 localhost\n10.0.0.9 ctl.mgmt.example.test # kpctl\n"), 0o644)
	os.WriteFile(tmpl, []byte("127.0.1.1 {{fqdn}} {{hostname}}\n"), 0o644)
	pin := func(entry string) {
		cmd := exec.Command("bash", "-c", "set -e\n"+PinHostsFunc+`kpctl_pin_host "${1%% *}" "${1#* }"`, "pin", entry)
		cmd.Env = append(os.Environ(), "KPCTL_ROOT="+root)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
	}
	pin("10.0.0.1 ctl.mgmt.example.test")
	pin("10.0.0.1 ctl.mgmt.example.test") // 다시 해도 한 줄
	for path, keep := range map[string]string{hosts: "127.0.0.1 localhost", tmpl: "{{fqdn}}"} {
		data, _ := os.ReadFile(path)
		got := string(data)
		if strings.Count(got, "ctl.mgmt.example.test # kpctl") != 1 || !strings.Contains(got, "10.0.0.1 ctl.mgmt.example.test # kpctl") ||
			strings.Contains(got, "10.0.0.9") || !strings.Contains(got, keep) {
			t.Errorf("%s:\n%s", path, got)
		}
	}
	// 템플릿이 없는 시스템은 /etc/hosts 만
	os.Remove(tmpl)
	pin("10.0.0.2 other.example.test")
	if data, _ := os.ReadFile(hosts); !strings.Contains(string(data), "10.0.0.2 other.example.test # kpctl") {
		t.Errorf("템플릿 없음:\n%s", data)
	}
	if _, err := os.Stat(tmpl); !os.IsNotExist(err) {
		t.Error("없던 템플릿을 만들면 안 됩니다")
	}
}
