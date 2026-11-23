// 이 파일: 정식 누적본과 분리한 출시 전 입력·승인·링 목표의 안전 조건.
package controller

import (
	"net/http"
	"time"

	"kpctl/internal/model"
)

// activePrereleasePatches는 정식 활성 패치에 아직 정식 경로에 없는 출시 전 패치만 더합니다.
// 정식 경로에서 관리자가 비활성화한 SHA도 출시 전 경로로 다시 끼워 넣지 않습니다.
func (st *State) activePrereleasePatches(kernel string) []*model.Patch {
	active := st.activePatches(kernel)
	formal := map[string]bool{}
	for _, p := range st.Patches {
		if p.Kernel == kernel && !p.Prerelease && p.Commit != "" {
			formal[p.Commit] = true
		}
	}
	for _, p := range st.Patches {
		if p.Kernel == kernel && p.Prerelease && p.State == model.PatchActive && !formal[p.Commit] {
			active = append(active, p)
		}
	}
	return active
}

func (st *State) knownPrereleaseCommits(kernel string) []string {
	known := st.knownCommits(kernel)
	seen := map[string]bool{}
	for _, sha := range known {
		seen[sha] = true
	}
	for _, p := range st.Patches {
		if p.Kernel == kernel && p.Prerelease && p.Commit != "" && !seen[p.Commit] {
			known = append(known, p.Commit)
			seen[p.Commit] = true
		}
	}
	return known
}

func (s *Server) prereleaseApprovalProblem(st *State, j *model.Job, allow, automated bool) error {
	if !j.Prerelease {
		if t := st.Tracks[j.Kernel]; automated && t != nil && t.HasPrerelease() {
			return fail(http.StatusConflict, "출시 전 배포가 있어 정식 자동 승인을 보류합니다")
		}
		return nil
	}
	if !allow || automated {
		return fail(http.StatusConflict, "출시 전 작업은 관리자가 --prerelease를 명시하여 승인해야 합니다")
	}
	if !s.cfg.TestVM.Enabled {
		return fail(http.StatusConflict, "출시 전 작업은 test_vm.enabled=true인 환경에서 VM 시험을 거쳐야 합니다")
	}
	if j.Version >= 0 || j.PrereleaseVersion <= 0 || j.Version != -j.PrereleaseVersion {
		return fail(http.StatusConflict, "출시 전 전용 버전 번호가 잘못됐습니다")
	}
	ids := map[string]bool{}
	for _, id := range j.PatchIDs {
		ids[id] = true
	}
	for _, p := range st.activePatches(j.Kernel) {
		if !ids[p.ID] {
			return fail(http.StatusConflict, "출시 전 작업의 정식 누적 입력이 오래됐습니다. build --prerelease로 다시 빌드하세요")
		}
	}
	return nil
}

// setRingTarget은 출시 전 overlay와 정식 목표의 저장 위치를 한 곳에서 결정합니다.
func setRingTarget(t *model.Track, ring, version int, at time.Time) {
	if version < 0 {
		if t.PrereleaseRingVersions == nil {
			t.PrereleaseRingVersions = map[int]int{}
		}
		if t.PrereleaseRingSetAt == nil {
			t.PrereleaseRingSetAt = map[int]time.Time{}
		}
		t.PrereleaseRingVersions[ring], t.PrereleaseRingSetAt[ring] = version, at
		return
	}
	if t.RingVersions == nil {
		t.RingVersions = map[int]int{}
	}
	if t.RingSetAt == nil {
		t.RingSetAt = map[int]time.Time{}
	}
	t.RingVersions[ring], t.RingSetAt[ring] = version, at
	delete(t.PrereleaseRingVersions, ring)
	delete(t.PrereleaseRingSetAt, ring)
}
