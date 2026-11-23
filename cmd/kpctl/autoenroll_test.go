// 이 파일: main 패키지의 TestAutoenrollTargets, TestCanaryKernels, TestClassifyProbe 회귀 시험.
package main

import (
	"errors"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"kpctl/internal/dhcp"
	"kpctl/internal/model"
	"kpctl/internal/remote"
)

func TestAutoenrollTargets(t *testing.T) {
	now := time.Unix(1000, 0)
	at := func(sec int64) time.Time { return time.Unix(sec, 0) }
	leases := []dhcp.Lease{
		{MAC: "aa:01", IP: "10.0.0.10", Name: "new-host", Expires: at(2000)},
		{MAC: "aa:02", IP: "10.0.0.9", Name: "Registered-Host", Expires: at(2000)},
		{MAC: "aa:03", IP: "10.0.0.11", Name: "builder-1", Expires: at(2000)},
		{MAC: "aa:04", IP: "10.0.0.12", Name: "expired", Expires: at(500)},
		// 같은 MAC 의 옛 임대는 늦게 만료되는 임대에 밀립니다
		{MAC: "aa:05", IP: "10.0.0.13", Expires: at(1500)},
		{MAC: "aa:05", IP: "10.0.0.14", Name: "moved", Expires: at(1600)},
		{MAC: "aa:06", IP: "10.0.0.8", Name: "no-expiry"},
	}
	hosts := []*model.Host{{Hostname: "registered-host"}}
	ignore := map[string]bool{"builder-1": true}

	var got []string
	for _, l := range autoenrollTargets(leases, hosts, ignore, now) {
		got = append(got, l.IP)
	}
	want := []string{"10.0.0.8", "10.0.0.10", "10.0.0.14"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("대상 = %v, 기대 = %v", got, want)
	}
}

func TestCanaryKernels(t *testing.T) {
	hosts := []*model.Host{
		{Ring: 1, Status: model.HostStatus{Kernel: "a"}},
		{Ring: 2, Status: model.HostStatus{Kernel: "b"}},
	}
	got := canaryKernels(hosts)
	if !got["a"] || got["b"] {
		t.Fatalf("카나리 커널 = %v", got)
	}
}

func TestClassifyProbe(t *testing.T) {
	err := errors.New("ssh 실패: exit status 255")
	cases := []struct {
		out  string
		want keyState
	}{
		{"ops@10.0.0.10: Permission denied (publickey,password).", keyMissing},
		{"ssh: connect to host 10.0.0.10 port 22: Connection refused", keyUnreachable},
		{"ssh: connect to host 10.0.0.10 port 22: Connection timed out", keyUnreachable},
		{"ssh: connect to host 10.0.0.10 port 22: No route to host", keyUnreachable},
		{"@@@@\n@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @\nHost key verification failed.", keyError},
		{"something else", keyError},
	}
	for _, c := range cases {
		if got, _ := classifyProbe(c.out, err); got != c.want {
			t.Errorf("%q → %v, 기대 %v", c.out, got, c.want)
		}
	}
}

func TestWaitingFile(t *testing.T) {
	p := t.TempDir() + "/key-waiting"
	if len(readWaiting(p)) != 0 {
		t.Fatal("없는 파일은 빈 목록이어야 함")
	}
	writeWaiting(p, map[string]bool{"aa:02": true, "aa:01": true})
	got := readWaiting(p)
	if !got["aa:01"] || !got["aa:02"] || len(got) != 2 {
		t.Fatalf("읽은 값 = %v", got)
	}
}

func TestKeyStore(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KPCTL_SSH_KEY_DIR", dir)
	t.Setenv("KPCTL_SSH_KEY", "")
	src := filepath.Join(t.TempDir(), "admin_key")
	if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", src).CombinedOutput(); err != nil {
		t.Skipf("ssh-keygen 없음: %v %s", err, out)
	}
	if err := keyStoreAdd(src, "admin", "", ""); err != nil {
		t.Fatal(err)
	}
	if err := keyStoreAdd(src, "admin", "", ""); err != nil { // 같은 키 다시: 그대로 통과
		t.Fatal(err)
	}
	if err := keyStoreAdd(src+".pub", "pub", "", ""); err == nil {
		t.Fatal("공개키는 거부해야 함")
	}
	locked := filepath.Join(t.TempDir(), "locked")
	exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "secret", "-f", locked).Run()
	if err := keyStoreAdd(locked, "locked", "", ""); err == nil {
		t.Fatal("암호 걸린 키는 거부해야 함")
	}
	if err := keyStoreAdd(src, "../evil", "", ""); err == nil {
		t.Fatal("이상한 이름은 거부해야 함")
	}
	if got := storedKeys(); len(got) != 1 || filepath.Base(got[0]) != "admin" {
		t.Fatalf("저장된 키 = %v", got)
	}
	if err := keyStoreAdd(src, "admin", "ubuntu", ""); err != nil { // 같은 키에 계정만 정하기
		t.Fatal(err)
	}
	if u := keyUser(filepath.Join(dir, "admin")); u != "ubuntu" {
		t.Fatalf("계정 = %q", u)
	}
	if got := storedKeys(); len(got) != 1 {
		t.Fatalf(".user 파일이 키로 잡힘: %v", got)
	}
	cs := loginCandidates(&remote.SSH{User: "ops", KeyFile: "/ctl"}, storedKeys())
	if len(cs) != 2 || cs[0].User != "ops" || cs[1].User != "ubuntu" || cs[1].KeyFile != filepath.Join(dir, "admin") {
		t.Fatalf("접속 조합 = %+v", cs)
	}
	// 빌드 서버 전용으로 표시하면 클라이언트 설치 키에서 빠짐 (.role 파일은 키로 잡히지 않음)
	if err := keyStoreAdd(src, "admin", "", keyRoleBuilder); err != nil {
		t.Fatal(err)
	}
	if got := storedKeys(); len(got) != 1 || keyRole(got[0]) != keyRoleBuilder {
		t.Fatalf("용도 표시 후 = %v", got)
	}
	if got := clientKeys(); len(got) != 0 {
		t.Fatalf("빌드 서버 키가 클라이언트 키로 잡힘: %v", got)
	}
	if err := keyStoreAdd(src, "admin", "", keyRoleClient); err != nil {
		t.Fatal(err)
	}
	if got := clientKeys(); len(got) != 1 {
		t.Fatalf("client 로 되돌린 뒤 = %v", got)
	}
	if err := keyStoreRemove([]string{"admin"}); err != nil {
		t.Fatal(err)
	}
	if got := storedKeys(); len(got) != 0 {
		t.Fatalf("삭제 후 = %v", got)
	}
}

func TestUserArg(t *testing.T) {
	cases := []struct {
		args  []string
		other bool
		user  string
	}{
		{[]string{"root", "10.0.0.10"}, false, "root"},
		{[]string{"ubuntu"}, true, "ubuntu"},            // -from-dhcp ubuntu
		{[]string{"root"}, false, ""},                   // 대상이 하나뿐이면 호스트
		{[]string{"10.0.0.10", "10.0.0.11"}, false, ""}, // IP
		{[]string{"srv.mgmt.internal", "x"}, false, ""}, // 점 있음
		{[]string{"localhost", "10.0.0.10"}, false, ""}, // DNS 로 풀림
	}
	for _, c := range cases {
		u, ok := userArg(c.args, c.other)
		if (c.user != "") != ok || u != c.user {
			t.Errorf("%v → %q %v, 기대 %q", c.args, u, ok, c.user)
		}
	}
}

func TestRememberedUsersInCandidates(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KPCTL_SSH_KEY_DIR", filepath.Join(dir, "keys"))
	key := filepath.Join(dir, "id_ed25519")
	if err := rememberUser(key, "root"); err != nil {
		t.Fatal(err)
	}
	rememberUser(key, "root") // 중복은 한 번만
	if got := rememberedUsers(key); len(got) != 1 || got[0] != "root" {
		t.Fatalf("기억한 계정 = %v", got)
	}
	cs := loginCandidates(&remote.SSH{User: "ops", KeyFile: key}, nil)
	if len(cs) != 2 || cs[1].User != "root" || cs[1].KeyFile != key {
		t.Fatalf("접속 조합 = %+v", cs)
	}
}

func TestListedLeasesAndSkipDone(t *testing.T) {
	dhcpLeases := []dhcp.Lease{{MAC: "aa:01", IP: "10.0.0.10"}}
	got := listedLeases([]string{"10.0.0.10", "10.0.0.20", "node-03", "10.0.0.20"}, dhcpLeases)
	want := []dhcp.Lease{{MAC: "host:10.0.0.20", IP: "10.0.0.20"}, {MAC: "host:node-03", IP: "node-03", Name: "node-03"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("목록 대상 = %+v", got)
	}
	// 이름으로 적은 호스트는 이미 등록돼 있으면 접속 전에 빠짐
	hosts := []*model.Host{{Hostname: "node-03.mgmt"}, {Hostname: "node-20"}}
	targets := autoenrollTargets(append(dhcpLeases, got...), hosts, nil, time.Now())
	if len(targets) != 2 {
		t.Fatalf("대상 = %+v", targets)
	}
	done := map[string]string{"host:10.0.0.20": "node-20", "aa:01": doneInfra}
	if left := skipDone(targets, done, hosts); len(left) != 0 {
		t.Fatalf("등록 확인한 대상이 남음: %+v", left)
	}
	// 등록이 지워지면 다시 대상
	if left := skipDone(targets, done, nil); len(left) != 1 || left[0].IP != "10.0.0.20" {
		t.Fatalf("등록 삭제 후 = %+v", left)
	}
	p := filepath.Join(t.TempDir(), "enrolled")
	writeDone(p, done)
	if !reflect.DeepEqual(readDone(p), done) {
		t.Fatalf("기록 = %v", readDone(p))
	}
}
