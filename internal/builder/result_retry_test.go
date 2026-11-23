// 이 파일: builder 패키지의 TestSendResultRetriesTransientFailuresOnly 회귀 시험.
package builder

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"kpctl/internal/model"
)

func TestSendResultRetriesTransientFailuresOnly(t *testing.T) {
	old := resultRetryDelays
	resultRetryDelays = []time.Duration{time.Millisecond, time.Millisecond, time.Millisecond}
	defer func() { resultRetryDelays = old }()

	var calls atomic.Int32
	status := http.StatusServiceUnavailable
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) <= 2 {
			w.WriteHeader(status)
			w.Write([]byte(`{"error":"잠시 후"}`))
			return
		}
		w.Write([]byte(`{}`))
	}))
	defer server.Close()
	b, err := New(&Config{ControllerURL: server.URL, Series: "noble"})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.sendResult(7, model.BuildResult{}); err != nil || calls.Load() != 3 {
		t.Fatalf("일시 장애는 다시 보내 성공해야 함: err=%v calls=%d", err, calls.Load())
	}

	calls.Store(0)
	status = http.StatusBadRequest
	if err := b.sendResult(7, model.BuildResult{}); err == nil || calls.Load() != 1 {
		t.Fatalf("4xx 는 다시 보내지 않아야 함: err=%v calls=%d", err, calls.Load())
	}

	server.Close()
	calls.Store(0)
	if err := b.sendResult(7, model.BuildResult{}); err == nil {
		t.Fatal("컨트롤러가 계속 없으면 실패를 돌려줘야 함")
	}
}
