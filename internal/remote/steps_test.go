// 이 파일: remote 패키지의 TestURLHostPort, TestHostsEntry, TestPreflightScriptFallsBackToSSHAddress 회귀 시험.
package remote

import (
	"net/http"
	"net/http/httptest"
	"os/exec"
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
