// 이 파일: 서명 관리 CLI의 API 계약, 배포 제외·만료 경고와 감사되는 MOK 비밀번호 출력 검증.
package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"kpctl/internal/client"
)

func signingCLIClient(t *testing.T, handler http.HandlerFunc) *client.Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer cli-test-token" {
			t.Errorf("관리자 토큰이 전달되지 않음")
		}
		w.Header().Set("Content-Type", "application/json")
		handler(w, r)
	}))
	t.Cleanup(server.Close)
	c, err := client.New(server.URL, "cli-test-token", "")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func signingCLIOutput(t *testing.T, run func() error) (string, error) {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = writer
	defer func() { os.Stdout = old }()
	err = run()
	_ = writer.Close()
	output, readErr := io.ReadAll(reader)
	_ = reader.Close()
	if readErr != nil {
		t.Fatal(readErr)
	}
	return string(output), err
}

func TestSigningCLIListShowsExpiryAndHostCounts(t *testing.T) {
	c := signingCLIClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/api/signing" {
			t.Errorf("요청 = %s %s", r.Method, r.URL.Path)
		}
		io.WriteString(w, `{"mode":"always","keys":[{"id":"prod-2026","active":true,"expires_at":"2026-11-30T00:00:00Z","enrolled_hosts":12,"warning":"인증서 만료가 30일 이내입니다"}],"warnings":["old-only: 옛 키 등록 필요"]}`)
	})
	output, err := signingCLIOutput(t, func() error { return cmdSigning(c, []string{"list"}) })
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"always", "prod-2026", "2026-11-30", "12", "30일", "old-only"} {
		if !strings.Contains(output, want) {
			t.Errorf("키 목록에 %q 없음: %s", want, output)
		}
	}
}

func TestSigningCLIRolloutAndPassword(t *testing.T) {
	var methods []string
	c := signingCLIClient(t, func(w http.ResponseWriter, r *http.Request) {
		methods = append(methods, r.Method+" "+r.URL.Path)
		switch r.URL.Path {
		case "/api/signing/prod/rollout-cert":
			io.WriteString(w, `{"scheduled_hosts":2,"warnings":["bios-host: 수동 절차 확인"]}`)
		case "/api/status":
			io.WriteString(w, `{"hosts":[{"id":"h-1","hostname":"node-1"}]}`)
		case "/api/hosts/h-1/mok-password":
			io.WriteString(w, `{"key_id":"prod","password":"CONSOLE-TEST","status":"unsupported","warning":"mokutil 수동 등록 필요"}`)
		default:
			t.Errorf("예상하지 못한 API: %s", r.URL.Path)
		}
	})
	output, err := signingCLIOutput(t, func() error { return cmdSigning(c, []string{"rollout-cert", "prod"}) })
	if err != nil || !strings.Contains(output, "2대") || !strings.Contains(output, "재부팅은 수행하지 않습니다") || !strings.Contains(output, "수동 절차") {
		t.Fatalf("예약 결과 = %s, %v", output, err)
	}
	output, err = signingCLIOutput(t, func() error { return cmdHosts(c, []string{"mok-password", "node-1"}) })
	if err != nil || !strings.Contains(output, "CONSOLE-TEST") || !strings.Contains(output, "unsupported") || !strings.Contains(output, "감사 로그") {
		t.Fatalf("비밀번호 조회 = %s, %v", output, err)
	}
	if got := strings.Join(methods, ","); got != "POST /api/signing/prod/rollout-cert,GET /api/status,GET /api/hosts/h-1/mok-password" {
		t.Fatalf("호출 순서 = %s", got)
	}
	for _, args := range [][]string{nil, {"list", "extra"}, {"rollout-cert"}} {
		if err := cmdSigning(c, args); err == nil {
			t.Errorf("잘못된 signing 인자 허용: %v", args)
		}
	}
	if err := cmdHosts(c, []string{"mok-password"}); err == nil {
		t.Fatal("조회 호스트가 없는 명령을 거부해야 함")
	}
}

func TestSigningCLIHostsAndPromoteShowExcludedReasons(t *testing.T) {
	c := signingCLIClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/status":
			io.WriteString(w, `{"now":"2026-11-15T00:00:00Z","hosts":[{"id":"h-1","hostname":"missing-mok","last_seen":"2026-11-15T00:00:00Z","status":{"kernel":"6.8.0-85-generic","secure_boot":"on","lockdown":"integrity","sig_enforce":"off"},"rollout_eligibility":{"status":"blocked_mok_missing","reason":"다음 계획된 재부팅 때 콘솔에서 MOK 승인 필요"}}]}`)
		case "/api/kernels/k/promote":
			io.WriteString(w, `{"version":3,"excluded_count":1,"excluded_hosts":[{"id":"h-1","hostname":"missing-mok","reason":"MOK 등록 필요"}]}`)
		default:
			t.Errorf("예상하지 못한 API: %s", r.URL.Path)
		}
	})
	output, err := signingCLIOutput(t, func() error { return cmdHosts(c, nil) })
	if err != nil || !strings.Contains(output, "배포 제외: 1대") || !strings.Contains(output, "계획된 재부팅") || !strings.Contains(output, "blocked_mok_missing") {
		t.Fatalf("제외 호스트 출력 = %s, %v", output, err)
	}
	output, err = signingCLIOutput(t, func() error { return cmdPromote(c, []string{"-kernel", "k", "-ring", "2"}) })
	if err != nil || !strings.Contains(output, "배포 제외: 1대") || !strings.Contains(output, "missing-mok") || !strings.Contains(output, "MOK 등록 필요") {
		t.Fatalf("promote 제외 출력 = %s, %v", output, err)
	}
}
