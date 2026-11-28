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

// 빌드 서버 점검: Debian 12·Rocky 9·10 은 네이티브 빌더 점검을, 그 밖의 OS 는 빈 시리즈 "" 대신 OS 이름을 보여야 합니다.
func TestPreflightBuilderNonUbuntuHosts(t *testing.T) {
	native := "release_type=stable\nx86v3=yes\nvirt=kvm\ncontainer=none\nsystemd=yes\nvarfree=209715200\nnativebuilderactive=no\nnativebuilderconfig=no\n"
	for _, tc := range []struct {
		name, facts, want, avoid string
		ok                       bool
	}{
		{"rocky10", native + "distro=rocky\nrelease=10.1\ncodename=\n", "", "", true},
		{"rocky10-no-v3", strings.Replace(native, "x86v3=yes", "x86v3=no", 1) + "distro=rocky\nrelease=10.1\ncodename=\n", "x86-64-v3", `""`, false},
		{"rocky9-agent", native + "distro=rocky\nrelease=9.9\ncodename=\nagent=installed\n", "-force 로도 넘길 수 없음", "", false},
		{"debian12", native + "distro=debian\nrelease=12\ncodename=bookworm\n", "", "", true},
		{"debian12-small", strings.Replace(native, "varfree=209715200", "varfree=10485760", 1) + "distro=debian\nrelease=12\ncodename=bookworm\n", "40 GiB", "", false},
		{"debian12-container", strings.Replace(native, "container=none", "container=lxc", 1) + "distro=debian\nrelease=12\ncodename=bookworm\n", "컨테이너(lxc)", "", false},
		{"debian13", native + "distro=debian\nrelease=13\ncodename=trixie\n", "IBT", "", false},
		{"rocky-beta", strings.Replace(native, "release_type=stable", "release_type=development", 1) + "distro=rocky\nrelease=10.0\ncodename=\n", "정식(stable)", "", false},
		{"rocky8", native + "distro=rocky\nrelease=8.10\ncodename=\n", "Rocky 8 는 네이티브 빌더 지원 릴리스가 아닙니다", "", false},
		{"native-running", strings.Replace(native, "nativebuilderactive=no", "nativebuilderactive=yes", 1) + "distro=rocky\nrelease=9.9\ncodename=\n", "-stop-running", "", false},
		{"focal", "distro=ubuntu\nrelease=20.04\ncodename=focal\nkernel=5.4.0-200-generic\n", "지원하지 않는 Ubuntu 시리즈 Ubuntu 20.04 (focal)", "", false},
		{"alpine", "distro=alpine\nrelease=3.20\ncodename=\nkernel=6.6.0-0-lts\n", "지원하지 않는 OS alpine 3.20", "", false},
		{"noble", "distro=ubuntu\nrelease=24.04\ncodename=noble\nkernel=6.8.0-136-generic\n", "", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sshBin := filepath.Join(t.TempDir(), "ssh")
			// 뒤에 오는 같은 키가 이깁니다 (tc.facts 의 agent=installed 등)
			body := "#!/bin/bash\ncat >/dev/null\ncat <<'FACTS'\nhostname=build\nuid=0\narch=x86_64\nsudo=ok\ncontroller=200\nnameresolves=yes\nagent=none\nbuilderactive=no\nbuilderconfig=no\n" + tc.facts + "FACTS\n"
			if err := os.WriteFile(sshBin, []byte(body), 0o755); err != nil {
				t.Fatal(err)
			}
			s := &Session{SSH: &SSH{SSHBin: sshBin}, Target: "10.0.0.176"}
			problems, _, err := s.Preflight(PreflightOptions{ForBuilder: true, Arch: "x86_64", ControllerURL: "https://ctl:8443", Series: []string{"jammy", "noble", "resolute"}})
			if err != nil {
				t.Fatal(err)
			}
			all := strings.Join(problems, "\n")
			if tc.ok != (len(problems) == 0) || tc.want != "" && !strings.Contains(all, tc.want) || tc.avoid != "" && strings.Contains(all, tc.avoid) {
				t.Fatalf("problems:\n%s", all)
			}
			if strings.Count(all, "에이전트가 설치된") > 1 {
				t.Fatalf("에이전트 문제가 중복됐습니다:\n%s", all)
			}
		})
	}
}
