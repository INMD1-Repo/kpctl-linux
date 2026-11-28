// 이 파일: 정식/출시 전 누적 작업 생성과 빌더 기능별 배정.
package controller

import (
	"net/http"
	"strings"
	"time"

	"kpctl/internal/model"
)

// createJob 은 커널의 "지금 활성 패치 전부"로 새 누적 패치 빌드 작업을 만듭니다.
//
// 핵심 규칙:
//   - 패치는 항상 누적본 하나입니다. 새 버전 = 이전 패치 + 새 패치 전부.
//     (kpatch 는 새 패치를 올리면 이전 패치를 통째로 교체하기 때문입니다.)
//   - 버전 번호는 커널별로 계속 증가하고, 컨트롤러만 매깁니다.
//   - 같은 정식/출시 전 계열의 미배포 작업은 새 누적본에 포함되므로 폐기합니다.
//
// 반드시 store.Update 안에서 불러야 합니다.
func (s *Server) createJob(st *State, kernel, requestedBy string, urgent bool) (*model.Job, error) {
	return s.createJobChannel(st, kernel, requestedBy, urgent, false)
}

func (s *Server) createPrereleaseJob(st *State, kernel, requestedBy string, urgent bool) (*model.Job, error) {
	return s.createJobChannel(st, kernel, requestedBy, urgent, true)
}

func (s *Server) createJobChannel(st *State, kernel, requestedBy string, urgent, prerelease bool) (*model.Job, error) {
	if reason := model.KernelBuildBlock(kernel); reason != "" {
		return nil, fail(http.StatusConflict, "%s", reason)
	}
	active := st.activePatches(kernel)
	if prerelease {
		active = st.activePrereleasePatches(kernel)
		candidates := false
		for _, p := range active {
			candidates = candidates || p.Prerelease
		}
		if !candidates {
			return nil, fail(http.StatusConflict, "%s 커널에 미출시 활성 패치가 없습니다", kernel)
		}
	}
	if len(active) == 0 {
		return nil, fail(http.StatusConflict, "%s 커널에 활성 패치가 없습니다", kernel)
	}
	now := time.Now()

	// 이전 미배포 작업 폐기
	for _, j := range st.Jobs {
		if j.Kernel != kernel || j.Prerelease != prerelease {
			continue
		}
		switch j.Status {
		case model.JobQueued, model.JobRunning, model.JobBuilt:
			j.Status = model.JobSuperseded
			j.FinishedAt = now
		}
	}

	// 직전 배포 버전과 비교해서 "새 패치" 표시
	prev := map[string]bool{}
	last := st.latestReleased(kernel)
	if prerelease {
		for _, j := range st.Jobs {
			if j.Kernel == kernel && j.Prerelease && j.Status == model.JobReleased && (last == nil || j.ID > last.ID) {
				last = j
			}
		}
	}
	if last != nil {
		for _, id := range last.PatchIDs {
			prev[id] = true
		}
	}
	var ids, newIDs []string
	for _, p := range active {
		ids = append(ids, p.ID)
		if !prev[p.ID] {
			newIDs = append(newIDs, p.ID)
		}
	}

	t := st.track(kernel)
	version, prereleaseVersion := 0, 0
	if prerelease {
		t.NextPrereleaseVersion++
		prereleaseVersion = t.NextPrereleaseVersion
		version = -prereleaseVersion
	} else {
		t.NextVersion++
		version = t.NextVersion
	}
	st.NextJobID++
	j := &model.Job{
		ID:                st.NextJobID,
		Kernel:            kernel,
		Version:           version,
		Prerelease:        prerelease,
		PrereleaseVersion: prereleaseVersion,
		PatchIDs:          ids,
		NewPatchIDs:       newIDs,
		Urgent:            urgent,
		Status:            model.JobQueued,
		RequestedBy:       requestedBy,
		CreatedAt:         now,
	}
	// 지금까지 수집한 Ubuntu 태그까지 반영한 버전 (수집 결과로 만든 작업이면 handleDiscovered 가 먼저 갱신해 둠)
	if u := st.Upstream[kernel]; u != nil {
		j.UpToTag = u.CollectedTag
	}

	st.Jobs = append(st.Jobs, j)
	return j, nil
}

// nextQueuedJob 은 빌드 서버에 줄 다음 작업을 고릅니다.
// 그 빌드 서버가 만들 수 있는 커널 작업 중에서, 긴급(urgent) 작업이 먼저, 그다음은 먼저 만든 순서입니다.
func nextQueuedJob(st *State, req model.NextJobRequest) *model.Job {
	deferred := make(map[int]bool, len(req.DeferredJobIDs))
	for _, id := range req.DeferredJobIDs {
		deferred[id] = true
	}
	var pick *model.Job
	for _, j := range st.Jobs {
		if j.Status != model.JobQueued || deferred[j.ID] || !builderCanBuild(req, j.Kernel) || j.Prerelease && !req.CanPrerelease {
			continue
		}
		if req.Series != "" && !explicitBuilderKernel(req, j.Kernel) {
			if upstream := st.Upstream[j.Kernel]; upstream != nil && upstream.Outside != "" {
				continue
			}
		}
		if pick == nil || (j.Urgent && !pick.Urgent) || (j.Urgent == pick.Urgent && j.ID < pick.ID) {
			pick = j
		}
	}
	return pick
}

func explicitBuilderKernel(req model.NextJobRequest, kernel string) bool {
	for _, configured := range req.Kernels {
		if configured == kernel {
			return true
		}
	}
	return false
}

// builderCanBuild 는 빌드 서버가 이 커널을 빌드할 수 있는지 봅니다.
//
// kpatch-build 는 커널을 빌드한 gcc 와 같은 gcc 가 있어야 하므로, LTS 시리즈마다 그 시리즈의
// Ubuntu 를 쓰는 빌드 서버가 따로 있습니다. 시리즈를 알리지 않은 빌드 서버는 예전처럼 다 받습니다.
func builderCanBuild(req model.NextJobRequest, kernel string) bool {
	if model.KernelBuildBlock(kernel) != "" {
		return false
	}
	if strings.HasPrefix(kernel, "native__") || req.NativeTrack != "" {
		_, ok := model.DistributionTrack(kernel)
		return ok && req.NativeTrack == kernel
	}
	if req.Series == "" {
		return true
	}
	if explicitBuilderKernel(req, kernel) {
		return true
	}
	s := model.LTSForKernel(kernel)
	return s != nil && s.Codename == req.Series
}
