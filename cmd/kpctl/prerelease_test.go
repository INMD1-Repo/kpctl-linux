// 이 파일: 출시 전 조작의 명시 플래그와 정식 버전과 분리된 CLI 표시 검증.
package main

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"kpctl/internal/model"
)

func TestPrereleaseCLIApproveRequiresAndTransmitsExplicitFlag(t *testing.T) {
	var flags []bool
	c := signingCLIClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/api/jobs/4/approve" {
			t.Errorf("승인 API = %s %s", r.Method, r.URL.Path)
		}
		var req model.ApproveRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
		}
		flags = append(flags, req.Prerelease)
		io.WriteString(w, `{"kernel":"k","version":-2,"ring":1,"prerelease":true,"prerelease_version":2}`)
	})
	for _, args := range [][]string{{"4"}, {"4", "--prerelease"}, {"--prerelease", "4"}} {
		output, err := signingCLIOutput(t, func() error { return cmdApprove(c, args) })
		if err != nil || !strings.Contains(output, "출시 전 pre2") || strings.Contains(output, "v-2") {
			t.Fatalf("출시 전 승인 표시 = %s, %v", output, err)
		}
	}
	if len(flags) != 3 || flags[0] || !flags[1] || !flags[2] {
		t.Fatalf("명시 승인 플래그 = %v", flags)
	}
	if err := cmdApprove(c, []string{"4", "--unknown"}); err == nil {
		t.Fatal("모르는 승인 플래그는 거부해야 함")
	}
}

func TestPrereleaseCLIBuildPromoteAndRollbackFlags(t *testing.T) {
	c := signingCLIClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/kernels/k/build":
			var req model.BuildRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil || !req.Prerelease {
				t.Errorf("출시 전 빌드 플래그 누락: %+v, %v", req, err)
			}
			io.WriteString(w, `{"id":5,"version":-3,"prerelease":true,"prerelease_version":3,"patch_ids":["p1","p2"]}`)
		case "/api/kernels/k/promote":
			var req model.PromoteRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil || !req.Prerelease || req.Ring != 2 {
				t.Errorf("출시 전 승급 플래그 누락: %+v, %v", req, err)
			}
			io.WriteString(w, `{"version":-3}`)
		case "/api/kernels/k/rollback":
			var req model.RollbackRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil || !req.Prerelease || req.Version != -2 {
				t.Errorf("출시 전 롤백 번호 분리 누락: %+v, %v", req, err)
			}
			io.WriteString(w, `{}`)
		default:
			t.Errorf("예상하지 못한 API: %s", r.URL.Path)
		}
	})
	for _, command := range []struct {
		run   func() error
		label string
	}{
		{func() error { return cmdBuild(c, []string{"-kernel", "k", "--prerelease"}) }, "출시 전 pre3"},
		{func() error { return cmdPromote(c, []string{"-kernel", "k", "-ring", "2", "--prerelease"}) }, "출시 전 pre3"},
		{func() error { return cmdRollback(c, []string{"-kernel", "k", "-version", "2", "--prerelease"}) }, "출시 전 pre2"},
	} {
		output, err := signingCLIOutput(t, command.run)
		if err != nil || !strings.Contains(output, command.label) {
			t.Fatalf("출시 전 조작 = %s, %v", output, err)
		}
	}
	if err := cmdRollback(c, []string{"-kernel", "k", "-version", "0", "--prerelease"}); err == nil {
		t.Fatal("출시 전 전용 번호에 v0은 없음")
	}
}
