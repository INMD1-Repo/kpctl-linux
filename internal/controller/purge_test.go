// 이 파일: controller 패키지의 TestKernelPurgeOnlyOutsideAndOnlyToCapableBuilder 회귀 시험.
package controller

import (
	"net/http"
	"strings"
	"testing"
)

func TestKernelPurgeOnlyOutsideAndOnlyToCapableBuilder(t *testing.T) {
	s := newAutoServer(t, AutoRollout{})
	addHost(t, s, "gpu-01", 1)
	k := "/api/kernels/" + testKernel
	up := "/api/builder/kernels/" + testKernel + "/upstream"

	// 범위 안 커널은 지울 수 없음
	callAPI(t, s, "POST", k+"/purge", "", http.StatusConflict)

	// 범위 밖 보고는 이전 수집 문제를 지우고 자동 배포 보류를 새로 걸지 않음
	callBuilderAPI(t, s, "POST", up, `{"problem":"시험 빌드 검토 필요"}`, http.StatusOK)
	callBuilderAPI(t, s, "POST", up, `{"problem":"","outside":"최근 4개 ABI(147·146·145·142) 밖 · 자동 수집하지 않음"}`, http.StatusOK)
	status := callAPI(t, s, "GET", "/api/status", "", http.StatusOK)
	if !strings.Contains(status, `"outside":"최근 4개 ABI`) || strings.Contains(status, `"problem":"시험`) {
		t.Fatalf("범위 밖 상태: %s", status)
	}

	callAPI(t, s, "POST", k+"/purge", "", http.StatusOK)
	next := `{"builder":"b1","series":"noble","can_refresh":true`
	// 예전 빌드 서버·다른 시리즈 빌드 서버에는 주지 않음
	callBuilderAPI(t, s, "POST", "/api/builder/next", next+`}`, http.StatusNoContent)
	callBuilderAPI(t, s, "POST", "/api/builder/next", `{"builder":"b2","series":"jammy","can_purge":true}`, http.StatusNoContent)
	body := callBuilderAPI(t, s, "POST", "/api/builder/next", next+`,"can_purge":true}`, http.StatusOK)
	if !strings.Contains(body, `"purge":["`+testKernel+`"]`) {
		t.Fatalf("삭제 요청이 없음: %s", body)
	}
	callBuilderAPI(t, s, "POST", "/api/builder/next", next+`,"can_purge":true}`, http.StatusNoContent)

	callBuilderAPI(t, s, "POST", up, `{"purged":"격리 캐시 1개(18.0 GiB) · 커널 패키지 6개 삭제"}`, http.StatusOK)
	if status := callAPI(t, s, "GET", "/api/status", "", http.StatusOK); !strings.Contains(status, `"purge_result":"격리 캐시 1개`) {
		t.Fatalf("삭제 결과가 없음: %s", status)
	}

	// 요청 취소
	callAPI(t, s, "POST", k+"/purge", "", http.StatusOK)
	callAPI(t, s, "POST", k+"/purge", `{"cancel":true}`, http.StatusOK)
	callBuilderAPI(t, s, "POST", "/api/builder/next", next+`,"can_purge":true}`, http.StatusNoContent)

	// 다시 범위 안이 되면 삭제 요청 불가
	callBuilderAPI(t, s, "POST", up, `{"outside":""}`, http.StatusOK)
	callAPI(t, s, "POST", k+"/purge", "", http.StatusConflict)
}
