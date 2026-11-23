// 이 파일: 키 교체 후 처음 합류하는 구형 에이전트의 기본 사본 일관성과 서명 차단 경계를 검증합니다.
package controller

import (
	"testing"

	"kpctl/internal/model"
)

func TestSigningLegacyNewHostKeepsJobDefaultAcrossFirstApply(t *testing.T) {
	s, j := signingFixture()
	// 작업은 old 키가 active일 때 승인됐고, 이후 회전 시험으로 new 사본이 추가됐습니다.
	j.ActiveSigningKey, j.SHA256 = "old", "old-sha"
	h := &model.Host{Ring: 1, Status: model.HostStatus{Kernel: testKernel}}
	st := &State{Jobs: []*model.Job{j}, Tracks: map[string]*model.Track{testKernel: {RingVersions: map[int]int{1: j.Version}}}}
	before := s.desired(st, h)
	if before.Blocked || before.Version != j.Version || before.SHA256 != "old-sha" || before.Warning == "" {
		t.Fatalf("최초 적용부터 승인 작업의 기본 사본을 경고와 함께 사용해야 함: %+v", before)
	}
	if want := "/artifacts/" + testKernel + "/" + j.ModuleName + ".ko"; before.URL != want {
		t.Fatalf("이전 에이전트 기본 URL=%q, want %q", before.URL, want)
	}
	h.Status.Version = j.Version
	after := s.desired(st, h)
	if after.Blocked || after.Version != before.Version || after.ModuleName != before.ModuleName || after.SHA256 != before.SHA256 || after.URL != before.URL {
		t.Fatalf("최초 적용 후 다른 서명 바이트를 요구함: before=%+v after=%+v", before, after)
	}
	// 새 누적본 자체의 기본 키가 바뀌면 구형 에이전트도 새 키를 적용합니다.
	next := *j
	next.ID, next.Version, next.ModuleName = 2, 2, "kpctl_signed_v2"
	next.ActiveSigningKey, next.SHA256 = "new", "new-sha"
	st.Jobs = append(st.Jobs, &next)
	st.Tracks[testKernel].RingVersions[1] = next.Version
	if got := s.desired(st, h); got.Blocked || got.Version != next.Version || got.SHA256 != next.SHA256 {
		t.Fatalf("새 누적본에서 기본 키 전환이 반영되지 않음: %+v", got)
	}
}

func TestSigningLegacyDefaultSelectionCannotBypassSignatureBlocks(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*Server, *model.Job)
		want   string
	}{
		{"never", func(s *Server, _ *model.Job) { s.cfg.Signing.Mode = "never" }, "blocked_signing_disabled"},
		{"unsigned default", func(s *Server, j *model.Job) {
			s.cfg.Signing.Mode = "when_required"
			a := j.SigningArtifacts["old"]
			a.Signed = false
			j.SigningArtifacts["old"] = a
		}, "blocked_artifact"},
		{"missing default", func(_ *Server, j *model.Job) { delete(j.SigningArtifacts, "old") }, "blocked_artifact"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, version := range []int{0, 1} {
				s, j := signingFixture()
				j.ActiveSigningKey, j.SHA256 = "old", "old-sha"
				tc.change(s, j)
				h := &model.Host{Status: model.HostStatus{Kernel: testKernel, Version: version}}
				if got := s.rolloutEligibility(h, j); got.Status != tc.want {
					t.Fatalf("version=%d legacy 선택이 서명 차단을 우회함: %+v, want %s", version, got, tc.want)
				}
			}
		})
	}
}

func TestSigningNewAgentUnknownEnrollmentStillPrefersCurrentActive(t *testing.T) {
	s, j := signingFixture()
	j.ActiveSigningKey, j.SHA256 = "old", "old-sha"
	h := signingHost(map[string]string{"old": "unknown", "new": "unknown"})
	st := &State{Jobs: []*model.Job{j}, Tracks: map[string]*model.Track{testKernel: {RingVersions: map[int]int{1: j.Version}}}}
	first := s.desired(st, h)
	if first.Blocked || first.SHA256 != "new-sha" || first.Warning == "" || first.URL != "/artifacts/"+testKernel+"/"+j.ModuleName+".ko?key=new" {
		t.Fatalf("등록 미확인 신형 에이전트의 active 우선 정책이 바뀜: %+v", first)
	}
	h.Status.Version, h.Status.ModuleSHA256 = j.Version, first.SHA256
	if got := s.desired(st, h); got.Blocked || got.SHA256 != first.SHA256 || got.URL != first.URL {
		t.Fatalf("신형 에이전트의 설치 해시 유지 실패: %+v", got)
	}
}

func TestSigningLegacyNoSignerKeepsApprovedAnonymousArtifact(t *testing.T) {
	s := newAutoServer(t, AutoRollout{})
	addHost(t, s, "legacy", 1)
	id := addBuilt(t, s, "ubuntu")
	if _, _, _, err := s.approveJob(id, "tester"); err != nil {
		t.Fatal(err)
	}
	s.store.View(func(st *State) {
		j, h := st.job(id), st.Hosts["legacy"]
		if a, ok := j.SigningArtifacts[""]; !ok || a.Signed || j.ActiveSigningKey != "" {
			t.Fatalf("기존 무서명 승인 메타 형식이 달라짐: %+v", j)
		}
		first := s.desired(st, h)
		if first.Blocked || first.Version != j.Version || first.SHA256 != j.SHA256 || first.Warning == "" {
			t.Fatalf("서명 설정 생략 시 기존 익명 사본을 배포하지 못함: %+v", first)
		}
	})
	if err := s.store.Update(func(st *State) error {
		st.Hosts["legacy"].Status.Version = st.job(id).Version
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	s.store.View(func(st *State) {
		j := st.job(id)
		if got := s.desired(st, st.Hosts["legacy"]); got.Blocked || got.Version != j.Version || got.SHA256 != j.SHA256 {
			t.Fatalf("적용 후 기존 무서명 사본의 호환성이 달라짐: %+v", got)
		}
	})
}

func TestSigningLegacyNoSignerCannotTreatNamedUnsignedAsAnonymous(t *testing.T) {
	s, j := signingFixture()
	s.cfg.Signing = nil
	j.ActiveSigningKey, j.SHA256 = "old", "old-sha"
	a := j.SigningArtifacts["old"]
	a.Signed = false
	j.SigningArtifacts = map[string]model.SigningArtifact{"old": a}
	h := &model.Host{Status: model.HostStatus{Kernel: testKernel}}
	if got := s.rolloutEligibility(h, j); got.Status != "blocked_artifact" {
		t.Fatalf("설정 삭제로 이름 있는 unsigned 키 사본이 legacy 예외를 통과함: %+v", got)
	}
}
