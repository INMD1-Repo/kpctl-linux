// 이 파일: 출시 전 음수 전송 버전의 적용·재시작·제외 시 기존 보호 유지를 검증합니다.
package agent

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"kpctl/internal/client"
	"kpctl/internal/klpcheck/klptest"
	"kpctl/internal/model"
)

func TestPrereleaseVersionAppliesAndSurvivesRestartWithoutRollback(t *testing.T) {
	a, _ := newTestAgent(t)
	old := previousVersion(t, a)
	content := klptest.Module(klptest.Options{})
	reports := make(chan model.ReportRequest, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/agent/report" {
			var report model.ReportRequest
			if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
				t.Error(err)
			}
			reports <- report
			_ = json.NewEncoder(w).Encode(model.ReportResponse{})
			return
		}
		_, _ = w.Write(content)
	}))
	defer server.Close()
	var err error
	a.c, err = client.New(server.URL, "host-token", "")
	if err != nil {
		t.Fatal(err)
	}
	desired := model.DesiredPatch{Version: -1, ModuleName: "kpctl_test_pre1", URL: "/pre.ko", SHA256: fmt.Sprintf("%x", sha256.Sum256(content))}
	if !a.apply(desired) || a.lastErr != "" {
		t.Fatalf("출시 전 적용 실패: %s", a.lastErr)
	}
	if a.st.Version != -1 || !a.patchEnabled(desired.ModuleName) || a.moduleLoaded(old) {
		t.Fatalf("출시 전 누적본으로 교체 실패: %+v", a.st)
	}
	if err := a.loadState(); err != nil {
		t.Fatal(err)
	}
	if a.st.Version != -1 {
		t.Fatalf("재시작 후 출시 전 버전 손실: %+v", a.st)
	}
	if _, err := a.report(); err != nil {
		t.Fatal(err)
	}
	if report := <-reports; report.Status.ModuleSHA256 != desired.SHA256 || report.Status.Version != -1 {
		t.Fatalf("실제 설치 사본 SHA와 출시 전 버전 보고 누락: %+v", report.Status)
	}
	if a.apply(model.DesiredPatch{Blocked: true}) || !a.patchEnabled(desired.ModuleName) || a.st.Version != -1 {
		t.Fatal("제외 보고는 출시 전 기존 보호도 유지해야 함")
	}
}
