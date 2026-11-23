// 이 파일: remote 패키지의 TestHostChecks, TestPreflightScriptReportsHostFacts 회귀 시험.
package remote

import (
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestHostChecks(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	good := Facts{
		Kernel: "6.8.0-85-generic", Livepatch: "yes", SecureBoot: "SecureBoot disabled",
		Container: "none", Systemd: "yes", Modules: "yes", Lockdown: "none",
		BootFreeKB: "900000", VarFreeKB: "5000000", Python3: "yes", Dpkg: "ok", Now: fmt.Sprint(now.Unix()),
		BootFS: "ext4 /dev/sda2", Archive: "200", ArchiveVia: "official",
	}
	if p, w := hostChecks(good, now); len(p)+len(w) != 0 {
		t.Fatalf("정상 호스트: 문제 %v 경고 %v", p, w)
	}
	// 각 경우: 바꿀 값, 문제(P)/경고(W), 안내 문구 일부
	cases := []struct {
		name   string
		edit   func(*Facts)
		kind   string
		phrase string
	}{
		{"컨테이너", func(f *Facts) { f.Container = "lxc" }, "P", "컨테이너(lxc)"},
		{"systemd 없음", func(f *Facts) { f.Systemd = "no" }, "P", "systemd"},
		{"livepatch 없음", func(f *Facts) { f.Livepatch = "no" }, "P", "CONFIG_LIVEPATCH"},
		{"커널 모듈 없음", func(f *Facts) { f.Modules = "no" }, "P", "재부팅"},
		{"/var 부족", func(f *Facts) { f.VarFreeKB = "100000" }, "P", "/var 여유 97MB: apt 설치와 패치 보관에 500MB"},
		{"HWE 커널", func(f *Facts) { f.Kernel = "6.11.0-29-generic" }, "W", "자동으로 빌드되지"},
		{"Secure Boot", func(f *Facts) { f.SecureBoot = "SecureBoot enabled"; f.Lockdown = "integrity" }, "W", "MOK"},
		{"lockdown", func(f *Facts) { f.Lockdown = "confidentiality" }, "W", "lockdown(confidentiality)"},
		{"Canonical Livepatch", func(f *Facts) { f.OtherPatches = "lkp_Ubuntu_6_8_0_85 " }, "W", "lkp_Ubuntu_6_8_0_85"},
		{"외부 라이브패치", func(f *Facts) { f.OtherPatches = "vendor_fix " }, "W", "vendor_fix"},
		{"GRUB 없음", func(f *Facts) { f.BootFS = "none " }, "W", "GRUB 아님"},
		{"/boot LVM", func(f *Facts) { f.BootFS = "ext4 /dev/dm-0" }, "W", "/dev/dm-0"},
		{"/boot RAID", func(f *Facts) { f.BootFS = "ext4 /dev/md0" }, "W", "/dev/md0"},
		{"/boot btrfs", func(f *Facts) { f.BootFS = "btrfs /dev/sda2" }, "W", "btrfs"},
		{"저장소 차단", func(f *Facts) { f.Archive, f.ArchiveVia = "000", "kakao" }, "W", "모두 접속하지 못해"},
		{"한국 미러 대체", func(f *Facts) { f.ArchiveVia = "kaist" }, "W", "kaist 미러를 씁니다"},
		{"/boot 부족", func(f *Facts) { f.BootFreeKB = "102400" }, "W", "여유 100MB: 다음 GA 커널 준비에 300MB"},
		{"dpkg 멈춤", func(f *Facts) { f.Dpkg = "broken" }, "W", "dpkg --configure -a"},
		{"python3 없음", func(f *Facts) { f.Python3 = "no" }, "W", "python3"},
		{"시계 느림", func(f *Facts) { f.Now = fmt.Sprint(now.Unix() - 3600) }, "W", "-1h0m0s"},
		{"재설치", func(f *Facts) { f.Agent = "installed" }, "W", "재설치"},
	}
	for _, c := range cases {
		f := good
		c.edit(&f)
		p, w := hostChecks(f, now)
		got, other := w, p
		if c.kind == "P" {
			got, other = p, w
		}
		if len(got) != 1 || len(other) != 0 || !strings.Contains(got[0], c.phrase) {
			t.Errorf("%s: 문제 %v 경고 %v (기대 %s %q)", c.name, p, w, c.kind, c.phrase)
		}
	}
	// 값을 읽지 못한 경우(오래된 셸, df 없음)는 판정하지 않음
	unknown := good
	unknown.BootFreeKB, unknown.VarFreeKB, unknown.Now, unknown.Lockdown, unknown.BootFS, unknown.Archive = "", "", "", "", "", ""
	if p, w := hostChecks(unknown, now); len(p)+len(w) != 0 {
		t.Errorf("모르는 값: 문제 %v 경고 %v", p, w)
	}
}

// 실제 점검 스크립트가 새 항목을 모두 출력하는지 로컬 bash 로 확인합니다.
func TestPreflightScriptReportsHostFacts(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash 없음")
	}
	out, err := exec.Command("bash", "-c", preflightScript, "preflight", "", "", "").CombinedOutput()
	if err != nil {
		t.Fatalf("스크립트 실패: %v\n%s", err, out)
	}
	kv := map[string]string{}
	for _, l := range strings.Split(string(out), "\n") {
		if k, v, ok := strings.Cut(l, "="); ok {
			kv[k] = v
		}
	}
	for _, k := range []string{"container", "systemd", "modules", "lockdown", "otherpatches", "bootfree", "varfree", "python3", "dpkg", "now", "bootfs"} {
		if _, ok := kv[k]; !ok {
			t.Errorf("%s 항목 없음:\n%s", k, out)
		}
	}
	for k, allowed := range map[string]string{"systemd": "yes no", "modules": "yes no", "python3": "yes no", "dpkg": "ok broken"} {
		if !strings.Contains(" "+allowed+" ", " "+kv[k]+" ") {
			t.Errorf("%s=%q", k, kv[k])
		}
	}
	if sec := kv["now"]; len(sec) < 10 {
		t.Errorf("now=%q", sec)
	}
}
