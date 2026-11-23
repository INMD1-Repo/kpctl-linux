// 이 파일: controller 패키지의 TestBuilderCanBuild, TestOutsideQueuedJobWaitsUnlessBuilderExplicitlyTargetsIt, TestNextQueuedJobBySeries 회귀 시험.
package controller

import (
	"testing"

	"kpctl/internal/model"
)

func TestBuilderCanBuild(t *testing.T) {
	noble := model.NextJobRequest{Builder: "b1", Series: "noble"}
	cases := []struct {
		name   string
		req    model.NextJobRequest
		kernel string
		want   bool
	}{
		{"같은 시리즈", noble, "6.8.0-85-generic", true},
		{"다른 시리즈", noble, "5.15.0-125-generic", false},
		{"LTS 아닌 커널", noble, "6.8.0-1020-nvidia", false},
		{"직접 적은 커널", model.NextJobRequest{Series: "noble", Kernels: []string{"6.8.0-1020-nvidia"}}, "6.8.0-1020-nvidia", true},
		{"시리즈 없는 예전 빌드 서버", model.NextJobRequest{Builder: "old"}, "5.15.0-125-generic", true},
	}
	for _, c := range cases {
		if got := builderCanBuild(c.req, c.kernel); got != c.want {
			t.Errorf("%s: builderCanBuild(%q) = %v, want %v", c.name, c.kernel, got, c.want)
		}
	}
}

func TestOutsideQueuedJobWaitsUnlessBuilderExplicitlyTargetsIt(t *testing.T) {
	old := "7.0.0-14-generic"
	current := "7.0.0-43-generic"
	st := &State{
		Jobs: []*model.Job{
			{ID: 1, Kernel: old, Status: model.JobQueued, Urgent: true},
			{ID: 2, Kernel: current, Status: model.JobQueued},
		},
		Upstream: map[string]*model.Upstream{old: {Outside: "최근 3개 ABI 밖"}},
	}
	if got := nextQueuedJob(st, model.NextJobRequest{Series: "resolute"}); got == nil || got.ID != 2 {
		t.Fatalf("범위 밖 긴급 작업도 자동 빌더에 넘기지 않아야 함: %+v", got)
	}
	if got := nextQueuedJob(st, model.NextJobRequest{Series: "resolute", Kernels: []string{old}}); got == nil || got.ID != 1 {
		t.Fatalf("명시적 커널 설정은 범위 밖 작업 허용: %+v", got)
	}
	if got := nextQueuedJob(st, model.NextJobRequest{}); got == nil || got.ID != 1 {
		t.Fatalf("시리즈 없는 예전 빌더 호환성 유지: %+v", got)
	}
	st.Upstream[old].Outside = ""
	if got := nextQueuedJob(st, model.NextJobRequest{Series: "resolute"}); got == nil || got.ID != 1 {
		t.Fatalf("지원 범위에 다시 들어온 작업은 기존 우선순위로 전달: %+v", got)
	}
}

func TestNextQueuedJobBySeries(t *testing.T) {
	st := &State{Jobs: []*model.Job{
		{ID: 1, Kernel: "5.15.0-125-generic", Status: model.JobQueued, Urgent: true},
		{ID: 2, Kernel: "6.8.0-85-generic", Status: model.JobQueued},
	}}
	if j := nextQueuedJob(st, model.NextJobRequest{Series: "noble"}); j == nil || j.ID != 2 {
		t.Fatalf("noble 빌드 서버는 jammy 긴급 작업을 건너뛰고 job 2 를 받아야 함: %+v", j)
	}
	if j := nextQueuedJob(st, model.NextJobRequest{Series: "jammy"}); j == nil || j.ID != 1 {
		t.Fatalf("jammy 빌드 서버는 job 1: %+v", j)
	}
	if j := nextQueuedJob(st, model.NextJobRequest{Series: "resolute"}); j != nil {
		t.Fatalf("resolute 빌드 서버에 줄 작업 없음: %+v", j)
	}
}
