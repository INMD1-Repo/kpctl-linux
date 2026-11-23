// 이 파일: 같은 버전의 active 키 변경은 기존 보호를 유지하고 새 누적본에서 반영하는지 검증.
package controller

import (
	"kpctl/internal/model"
	"strings"
	"testing"
)

func TestSigningActiveKeyChangeRetainsInstalledCopyUntilNewVersion(t *testing.T) {
	s, j := signingFixture()
	j.ActiveSigningKey, j.SHA256 = "old", "old-sha"
	h := signingHost(map[string]string{"new": "enrolled", "old": "enrolled"})
	h.Status.Version, h.Status.ModuleSHA256 = j.Version, "old-sha"
	got := s.rolloutEligibility(h, j)
	if got.Status != "eligible" || got.KeyID != "old" || !strings.Contains(got.Warning, "새 누적본") {
		t.Fatalf("동일 코드의 기존 사본 유지 실패: %+v", got)
	}
	next := *j
	next.Version++
	if got := s.rolloutEligibility(h, &next); got.KeyID != "new" {
		t.Fatalf("새 누적본은 active 우선: %+v", got)
	}
	h.Status.EnrolledCerts["old"] = "not_enrolled"
	if got := s.rolloutEligibility(h, j); got.Status != "blocked_artifact" {
		t.Fatalf("동일 이름의 설치 SHA를 강제로 교체하면 안 됨: %+v", got)
	}
}

func TestSigningLegacyAppliedVersionKeepsDefaultOnActiveKeyChange(t *testing.T) {
	s, j := signingFixture()
	j.ActiveSigningKey, j.SHA256 = "old", "old-sha"
	h := &model.Host{Ring: 1, Status: model.HostStatus{Kernel: testKernel, Version: j.Version}}
	st := &State{Jobs: []*model.Job{j}, Tracks: map[string]*model.Track{testKernel: {RingVersions: map[int]int{1: j.Version}}}}
	got := s.desired(st, h)
	if got.Blocked || got.Version != j.Version || got.SHA256 != "old-sha" || strings.Contains(got.URL, "?key=") {
		t.Fatalf("이전 에이전트의 동일 버전 보호를 바꾸면 안 됨: %+v", got)
	}
}
