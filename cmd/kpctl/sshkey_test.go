// 이 파일: main 패키지의 TestCloudInitKey 회귀 시험.
package main

import (
	"strings"
	"testing"
)

// 새 VM 용 cloud-init 은 공개키 줄만 넣고(토큰 없음), 계정에 맞는 방식으로 넣어야 합니다.
func TestCloudInitKey(t *testing.T) {
	line := `from="10.0.0.1",restrict ssh-ed25519 AAAAkey kpctl@ctl`
	root, err := cloudInitKey(line, "root")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"#cloud-config\n", "disable_root: false\n", "path: /root/.ssh/authorized_keys\n",
		"append: true\n", "content: |\n      " + line + "\n"} {
		if !strings.Contains(root, want) {
			t.Fatalf("root 설정에 %q 가 없음:\n%s", want, root)
		}
	}
	if !strings.HasPrefix(root, "#cloud-config\n") {
		t.Fatal("첫 줄이 #cloud-config 여야 cloud-init 이 읽습니다")
	}

	ops, err := cloudInitKey(line, "ops")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"  - default\n", "  - name: ops\n", "sudo: 'ALL=(ALL) NOPASSWD:ALL'\n",
		"      - '" + line + "'\n"} {
		if !strings.Contains(ops, want) {
			t.Fatalf("ops 설정에 %q 가 없음:\n%s", want, ops)
		}
	}
	if strings.Contains(ops, "disable_root") {
		t.Fatal("root 가 아니면 root 로그인 설정을 건드리지 않아야 함")
	}

	// 작은따옴표는 YAML 규칙대로 두 번 씁니다.
	if out, _ := cloudInitKey("ssh-ed25519 AAAA it's", "ops"); !strings.Contains(out, "'ssh-ed25519 AAAA it''s'") {
		t.Fatalf("작은따옴표 처리:\n%s", out)
	}
	for _, bad := range []string{"", "a;b", "-x", "a b", "ROOT$"} {
		if _, err := cloudInitKey(line, bad); err == nil {
			t.Fatalf("계정 %q 를 받아들임", bad)
		}
	}
}
