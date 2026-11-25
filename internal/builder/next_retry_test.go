// 이 파일: builder 패키지의 TestControllerOutageDoesNotMarkBuilderFailed 회귀 시험.
package builder

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"kpctl/internal/model"
)

// 컨트롤러가 재부팅되는 동안의 연결 거부는 빌더 활동을 실패로 남기면 안 됩니다.
// 컨트롤러가 돌아와 "할 일 없음"만 주면 그 실패를 지울 기회가 없어 웹에 계속 보였습니다.
func TestControllerOutageDoesNotMarkBuilderFailed(t *testing.T) {
	status := http.StatusNoContent
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		if status >= 400 {
			w.Write([]byte(`{"error":"거부"}`))
		}
	}))
	url := server.URL
	server.Close() // 컨트롤러가 꺼져 있음 → connection refused

	b, err := New(&Config{ControllerURL: url, Series: "noble", PollSeconds: 30})
	if err != nil {
		t.Fatal(err)
	}
	b.progress = &liveProgress{}
	b.setActivity(model.BuilderActivity{Phase: "idle", Message: "작업 대기"})

	if b.BuildNext() {
		t.Fatal("연결 실패에서 작업을 처리했다고 하면 안 됨")
	}
	if got := b.progress.activity; got.Phase != "idle" {
		t.Fatalf("연결 거부가 활동을 바꿈: %+v", got)
	}

	// 인증 거부처럼 사람이 고쳐야 하는 오류는 계속 실패로 보여야 합니다.
	server = httptest.NewServer(server.Config.Handler)
	defer server.Close()
	b, err = New(&Config{ControllerURL: server.URL, Series: "noble", PollSeconds: 30})
	if err != nil {
		t.Fatal(err)
	}
	b.progress = &liveProgress{}
	status = http.StatusForbidden
	b.BuildNext()
	if got := b.progress.activity; got.Phase != "failed" {
		t.Fatalf("인증 거부는 실패로 보여야 함: %+v", got)
	}
}
