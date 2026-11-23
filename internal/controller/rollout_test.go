// 이 파일: controller 패키지의 TestPromoteRequiresActualActiveModule 회귀 시험.
package controller

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"kpctl/internal/model"
)

func TestPromoteRequiresConfirmedVersionEvenWithForce(t *testing.T) {
	s := newAutoServer(t, AutoRollout{})
	if err := s.store.Update(func(st *State) error {
		track := st.track(testKernel)
		setRingTarget(track, 1, 3, time.Now())
		setRingTarget(track, 2, 1, time.Now())
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	path := "/api/kernels/" + testKernel + "/promote"
	for _, body := range []string{
		`{"ring":2,"expected_version":2}`,
		`{"ring":2,"force":true,"expected_version":2}`,
		`{"ring":2,"force":true,"expected_version":0}`,
		`{"ring":2,"force":true,"prerelease":true,"expected_version":-1}`,
	} {
		callAPI(t, s, "POST", path, body, http.StatusPreconditionFailed)
	}
	s.store.View(func(st *State) {
		if version := st.track(testKernel).TargetVersion(2); version != 1 {
			t.Fatalf("이전 버전 확인으로 링 2 변경: v%d", version)
		}
	})
	var result struct {
		Version int `json:"version"`
	}
	body := callAPI(t, s, "POST", path, `{"ring":2,"force":true,"expected_version":3}`, http.StatusOK)
	if err := json.Unmarshal([]byte(body), &result); err != nil || result.Version != 3 {
		t.Fatalf("확인된 v3 승급 응답 오류: %s (%v)", body, err)
	}
	s.store.View(func(st *State) {
		if version := st.track(testKernel).TargetVersion(2); version != 3 {
			t.Fatalf("확인한 버전 대신 v%d 승급", version)
		}
	})
}

func TestPromoteRequiresActualActiveModule(t *testing.T) {
	for _, tc := range []struct {
		name   string
		loaded []model.LoadedPatch
		wantOK bool
	}{
		{"로컬 버전 기록만 있음", nil, false},
		{"다른 모듈만 활성", []model.LoadedPatch{{Name: "canonical_livepatch", Enabled: true}}, false},
		{"목표 모듈 비활성", []model.LoadedPatch{{Name: "kpctl_test_v1"}}, false},
		{"목표 모듈 전환 중", []model.LoadedPatch{{Name: "kpctl_test_v1", Enabled: true, Transition: true}}, false},
		{"목표 모듈 활성 및 전환 완료", []model.LoadedPatch{{Name: "kpctl_test_v1", Enabled: true}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newAutoServer(t, AutoRollout{})
			st := &State{
				Jobs: []*model.Job{{Kernel: testKernel, Version: 1, Status: model.JobReleased, ModuleName: "kpctl_test_v1"}},
				Hosts: map[string]*model.Host{"canary": {
					Hostname: "canary", Ring: 1, LastSeen: time.Now(),
					Status: model.HostStatus{Kernel: testKernel, Version: 1, Loaded: tc.loaded},
				}},
			}
			problems := s.promoteProblems(st, testKernel, 1, 1, time.Now().Add(-24*time.Hour), 2)
			if gotOK := len(problems) == 0; gotOK != tc.wantOK {
				t.Fatalf("승급 허용 = %v, want %v: %v", gotOK, tc.wantOK, problems)
			}
		})
	}
}
