// 이 파일: remote 패키지의 TestURLHostPort, TestHostsEntry, TestPreflightScriptFallsBackToSSHAddress 회귀 시험.
package remote

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestURLHostPort(t *testing.T) {
	cases := []struct{ in, name, port string }{
		{"https://kpatch.internal:8443", "kpatch.internal", "8443"},
		{"https://kpatch.internal", "kpatch.internal", "443"},
		{"http://ctl.example", "ctl.example", "80"},
		{"https://10.0.0.1:8443", "", ""},
		{"https://[fd00::1]:8443", "", ""},
		{"", "", ""},
	}
	for _, c := range cases {
		n, p := urlHostPort(c.in)
		if n != c.name || p != c.port {
			t.Errorf("urlHostPort(%q) = %q,%q, want %q,%q", c.in, n, p, c.name, c.port)
		}
	}
}

func TestHostsEntry(t *testing.T) {
	u := "https://kpatch.internal:8443"
	ok := Facts{NameResolves: "no", ControllerIP: "10.0.0.1", ViaIP: "200"}
	if got := ok.HostsEntry(u); got != "10.0.0.1 kpatch.internal" {
		t.Fatalf("HostsEntry = %q", got)
	}
	for name, f := range map[string]Facts{
		"이름을 찾음":    {NameResolves: "yes", ControllerIP: "10.0.0.1", ViaIP: "200"},
		"IP 로도 실패":  {NameResolves: "no", ControllerIP: "10.0.0.1", ViaIP: "000"},
		"SSH 주소 모름": {NameResolves: "no", ViaIP: "200"},
		"URL 이 IP":  {NameResolves: "ip"},
	} {
		if got := f.HostsEntry(u); got != "" {
			t.Errorf("%s: HostsEntry = %q, want 빈 값", name, got)
		}
	}
	if got := ok.HostsEntry("https://10.0.0.1:8443"); got != "" {
		t.Errorf("IP URL: HostsEntry = %q", got)
	}
}

// 실제 점검 스크립트를 로컬 bash 로 돌립니다. 이름은 풀리지 않고(.invalid), SSH 로 접속해 온 주소(127.0.0.1)로는 접속됩니다.
func TestPreflightScriptFallsBackToSSHAddress(t *testing.T) {
	for _, c := range []string{"bash", "curl", "getent"} {
		if _, err := exec.LookPath(c); err != nil {
			t.Skip(c + " 없음")
		}
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			w.WriteHeader(200)
		}
	}))
	defer srv.Close()
	port := strings.TrimPrefix(srv.URL, "https://127.0.0.1:")
	ctrl := "https://kpctl-test.invalid:" + port

	run := func(sshConn string) map[string]string {
		name, p := urlHostPort(ctrl)
		cmd := exec.Command("bash", "-s", "--", ctrl, name, p)
		cmd.Stdin = strings.NewReader(preflightScript)
		cmd.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin", "SSH_CONNECTION=" + sshConn}
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("스크립트 실패: %v\n%s", err, out)
		}
		kv := map[string]string{}
		for _, l := range strings.Split(string(out), "\n") {
			if k, v, ok := strings.Cut(l, "="); ok {
				kv[k] = v
			}
		}
		return kv
	}

	kv := run("127.0.0.1 50000 127.0.0.1 22")
	if kv["controller"] == "200" || kv["nameresolves"] != "no" || kv["controllerip"] != "127.0.0.1" || kv["viaip"] != "200" {
		t.Fatalf("점검 결과: %v", kv)
	}
	f := Facts{NameResolves: kv["nameresolves"], ControllerIP: kv["controllerip"], ViaIP: kv["viaip"]}
	if got := f.HostsEntry(ctrl); got != "127.0.0.1 kpctl-test.invalid" {
		t.Fatalf("HostsEntry = %q", got)
	}

	// SSH 로 접속해 온 주소에서 컨트롤러가 응답하지 않으면 /etc/hosts 에 넣지 않음
	kv = run("127.0.0.2 50000 127.0.0.1 22")
	f = Facts{Controller: kv["controller"], NameResolves: kv["nameresolves"], ControllerIP: kv["controllerip"], ViaIP: kv["viaip"]}
	if f.HostsEntry(ctrl) != "" {
		t.Fatalf("응답 없는 주소인데 HostsEntry = %q (%v)", f.HostsEntry(ctrl), kv)
	}
	if p := controllerProblem(ctrl, f); !strings.Contains(p, "SSH 로 접속한 주소 127.0.0.2") {
		t.Errorf("안내 문구: %s", p)
	}
}

// 빌드 서버 점검: Rocky(VERSION_CODENAME 없음)·Debian 호스트는 빈 시리즈 "" 대신 OS 와 네이티브 빌더 안내를 보여야 합니다.
func TestPreflightBuilderNonUbuntuHosts(t *testing.T) {
	for _, tc := range []struct {
		name, facts, want, avoid string
		ok                       bool
	}{
		{"rocky10", "distro=rocky\nrelease=10.1\ncodename=\nkernel=6.12.0-264.21.1.el10_3.x86_64\n", "Rocky 10.1 호스트입니다", `""`, false},
		{"debian12", "distro=debian\nrelease=12\ncodename=bookworm\nkernel=6.1.0-57-amd64\n", "Debian 12 (bookworm) 호스트입니다", `""`, false},
		{"focal", "distro=ubuntu\nrelease=20.04\ncodename=focal\nkernel=5.4.0-200-generic\n", "지원하지 않는 Ubuntu 시리즈 Ubuntu 20.04 (focal)", "kpctl-native-builder.py", false},
		{"alpine", "distro=alpine\nrelease=3.20\ncodename=\nkernel=6.6.0-0-lts\n", "지원하지 않는 OS alpine 3.20", "kpctl-native-builder.py", false},
		{"noble", "distro=ubuntu\nrelease=24.04\ncodename=noble\nkernel=6.8.0-136-generic\n", "", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sshBin := filepath.Join(t.TempDir(), "ssh")
			body := "#!/bin/bash\ncat >/dev/null\ncat <<'FACTS'\nhostname=build\nuid=0\narch=x86_64\nsudo=ok\ncontroller=200\nnameresolves=yes\nagent=none\nbuilderactive=no\nbuilderconfig=no\n" + tc.facts + "FACTS\n"
			if err := os.WriteFile(sshBin, []byte(body), 0o755); err != nil {
				t.Fatal(err)
			}
			s := &Session{SSH: &SSH{SSHBin: sshBin}, Target: "10.0.0.175"}
			problems, _, err := s.Preflight(PreflightOptions{ForBuilder: true, Arch: "x86_64", ControllerURL: "https://ctl:8443", Series: []string{"jammy", "noble", "resolute"}})
			if err != nil {
				t.Fatal(err)
			}
			all := strings.Join(problems, "\n")
			if tc.ok != (len(problems) == 0) || tc.want != "" && !strings.Contains(all, tc.want) || tc.avoid != "" && strings.Contains(all, tc.avoid) {
				t.Fatalf("problems:\n%s", all)
			}
			if (tc.name == "rocky10" || tc.name == "debian12") && !strings.Contains(all, "kpctl-native-builder.py") {
				t.Fatalf("네이티브 빌더 안내가 없습니다:\n%s", all)
			}
		})
	}
}
