// 이 파일: 호스트 목표·서명 사본 자격·링 승급의 실제 적용 상태 판단.
package controller

import (
	"fmt"
	"time"

	"kpctl/internal/model"
)

// desired 는 "이 호스트에는 지금 어떤 패치 버전이 올라가 있어야 하나"를 계산합니다.
//
//	호스트의 커널 → 그 커널의 Track → 호스트가 속한 링의 버전 → 해당 버전의 배포 작업
//
// 버전이 0 이면 에이전트는 우리 패치를 모두 내립니다.
// 반드시 store.View/Update 안에서 불러야 합니다.
func (s *Server) desired(st *State, h *model.Host) model.DesiredPatch {
	// 트랙의 모듈은 GA 커널용이므로 이름만 같은 HWE 커널 호스트에는 주지 않습니다.
	if reason := h.Status.ManagementBlock(); reason != "" {
		return model.DesiredPatch{Blocked: true, Warning: reason, Track: h.Status.TrackKey()}
	}
	if model.HWEWithGAName(h.Status) {
		return model.DesiredPatch{}
	}
	t := st.Tracks[h.Status.TrackKey()]
	if t == nil {
		if h.Status.Distribution != nil {
			return model.DesiredPatch{Blocked: true, Warning: nativeUnverified, Track: h.Status.TrackKey()}
		}
		return model.DesiredPatch{}
	}
	v := t.TargetVersion(h.Ring)
	// 관리자가 이 호스트만 "즉시 업데이트" 했으면 링보다 앞선 버전을 줍니다 (같은 커널일 때만)
	if v >= 0 && h.UpdateNowKernel == h.Status.TrackKey() && h.UpdateNowVersion > v {
		v = h.UpdateNowVersion
	}
	if v == 0 {
		return model.DesiredPatch{Track: h.Status.TrackKey()}
	}
	j := st.releasedJob(h.Status.TrackKey(), v)
	if j == nil {
		return model.DesiredPatch{}
	}
	eligibility := s.rolloutEligibility(h, j)
	if eligibility.Status != "eligible" {
		blocked := model.DesiredPatch{Blocked: true, Warning: eligibility.Reason}
		// blocked를 모르는 이전 에이전트도 현재 보호를 v0로 내리지 않게 합니다.
		if current := st.releasedJob(h.Status.TrackKey(), h.Status.Version); h.Status.Version != 0 && current != nil {
			blocked.Version, blocked.ModuleName = current.Version, current.ModuleName
			if !reportedSigningStatus(h.Status) {
				blocked.SHA256 = current.SHA256
				blocked.URL = fmt.Sprintf("/artifacts/%s/%s.ko", current.Kernel, current.ModuleName)
			}
		}
		return blocked
	}
	url := fmt.Sprintf("/artifacts/%s/%s.ko", j.Kernel, j.ModuleName)
	sum := j.SHA256
	if artifact, ok := j.SigningArtifacts[eligibility.KeyID]; ok {
		sum = artifact.SHA256
		if eligibility.KeyID != j.ActiveSigningKey {
			url += "?key=" + eligibility.KeyID
		}
	}
	return model.DesiredPatch{
		Track:      j.Kernel,
		Warning:    eligibility.Warning,
		Version:    j.Version,
		ModuleName: j.ModuleName,
		URL:        url,
		SHA256:     sum,
	}
}

func hostTransitioning(h *model.Host) bool {
	for _, lp := range h.Status.Loaded {
		if lp.Transition {
			return true
		}
	}
	return false
}

func hostPatchApplied(h *model.Host, name string) bool {
	for _, lp := range h.Status.Loaded {
		if lp.Name == name && lp.Enabled && !lp.Transition {
			return true
		}
	}
	return false
}

func (s *Server) hostStale(h *model.Host) bool {
	return time.Since(h.LastSeen) > time.Duration(s.settings().HostStaleMinutes)*time.Minute
}

// promoteProblems 는 다음 링으로 넘기기 전에 이전 링이 건강한지 검사합니다.
// 문제가 하나라도 있으면 promote 를 막습니다 (kpctl promote --force 로 무시 가능).
//
// 검사 항목을 추가하고 싶으면 이 함수에 넣으세요.
func (s *Server) promoteProblems(st *State, kernel string, prevRing, version int, prevSetAt time.Time, ring int) []string {
	var problems []string

	// 1) 최소 관찰 시간
	if soak := s.settings().MinSoakMinutes[ring]; soak > 0 {
		need := time.Duration(soak) * time.Minute
		if since := time.Since(prevSetAt); since < need {
			problems = append(problems, fmt.Sprintf("링 %d 관찰 시간 부족: %s 지남 / 최소 %s",
				prevRing, since.Round(time.Minute), need))
		}
	}

	// 2) 이전 링 호스트 상태
	job := st.releasedJob(kernel, version)
	count, excluded := 0, 0
	for _, h := range st.Hosts {
		if h.Ring != prevRing || h.Status.TrackKey() != kernel || model.HWEWithGAName(h.Status) {
			continue
		}
		if eligibility := s.rolloutEligibility(h, job); eligibility.Status != "eligible" {
			excluded++
			continue
		}
		count++
		switch {
		case s.hostStale(h):
			problems = append(problems, fmt.Sprintf("%s: 연락 끊김 (마지막 보고 %s)", h.Hostname, h.LastSeen.Format(time.RFC3339)))
		case h.Status.Error != "":
			problems = append(problems, fmt.Sprintf("%s: 오류 보고 — %s", h.Hostname, h.Status.Error))
		case h.Status.Version != version:
			problems = append(problems, fmt.Sprintf("%s: 아직 v%d (목표 v%d)", h.Hostname, h.Status.Version, version))
		case hostTransitioning(h):
			problems = append(problems, fmt.Sprintf("%s: 패치 전환(transition)이 끝나지 않음", h.Hostname))
		case version != 0 && (job == nil || !hostPatchApplied(h, job.ModuleName)):
			problems = append(problems, fmt.Sprintf("%s: v%d 모듈의 실제 활성 상태를 확인할 수 없습니다", h.Hostname, version))
		}
	}
	if count == 0 && excluded == 0 {
		problems = append(problems, fmt.Sprintf("링 %d 에 %s 커널 호스트가 없어 검증할 수 없습니다", prevRing, kernel))
	}
	return problems
}

// hostSecurityPolicy는 이전 에이전트의 빈 신호도 공통 정책으로 정규화합니다.
func hostSecurityPolicy(status model.HostStatus) (bool, string) {
	required, warning := model.SignaturePolicy(status.SecureBoot, status.Lockdown, status.SigEnforce)
	return required || status.SignatureRequired, warning
}
func hostSignatureRequired(status model.HostStatus) bool {
	required, _ := hostSecurityPolicy(status)
	return required
}

// Older agents omitted all signing fields. An explicit "unknown" is still a report.
func reportedSigningStatus(h model.HostStatus) bool {
	return h.SignatureRequired || h.SecureBoot != "" || h.Lockdown != "" || h.SigEnforce != "" ||
		h.Firmware != "" || h.ModuleSHA256 != "" || len(h.EnrolledCerts) != 0 || h.MOKPending || h.MOKImport != nil
}

// rolloutEligibility는 키 선택과 제외 사유를 결정하는 유일한 정책 함수입니다.
const nativeUnverified = "실행 커널의 패키지 버전과 GNU build ID에 일치하는 배포 트랙이 없습니다. 독립 prepare 결과와 -identify 출력을 대조하세요."

func (s *Server) rolloutEligibility(h *model.Host, j *model.Job) model.RolloutEligibility {
	if reason := h.Status.ManagementBlock(); reason != "" {
		return model.RolloutEligibility{Status: "blocked_unsupported", Reason: reason}
	}
	if h.Status.Distribution != nil && j != nil && j.Status == model.JobReleased && !j.CandidateProofVerified {
		return model.RolloutEligibility{Status: "blocked_unverified", Reason: "과거 승인에 후보 본문 핀이 없습니다. 독립 candidate-proof로 누적본을 다시 승인하세요."}
	}
	result := model.RolloutEligibility{Status: "eligible"}
	required, warning := hostSecurityPolicy(h.Status)
	result.Warning = warning
	cfg := s.signingConfig()
	active := ""
	for _, key := range cfg.Keys {
		if key.Active {
			active = key.ID
		}
	}
	result.KeyID = active
	if !required {
		if j != nil && j.ActiveSigningKey != "" {
			result.KeyID = j.ActiveSigningKey
		}
		return result
	}
	if cfg.Mode == "never" {
		result.Status, result.Reason = "blocked_signing_disabled", "서명이 필요한 호스트: signing.mode=never로 배포 제외"
		result.Warning = result.Reason
		return result
	}
	if reportedSigningStatus(h.Status) {
		if len(cfg.Keys) == 0 {
			result.Status, result.Reason = "blocked_signing_disabled", "서명이 필요한 호스트: 컨트롤러 서명 키·명령 설정 필요"
			return result
		}
		if j != nil && len(j.SigningArtifacts) == 0 {
			result.Status, result.Reason = "blocked_artifact", "서명 사본을 확인할 수 없는 이전 작업: 새 누적 빌드·승인 필요"
			return result
		}
	}
	if h.Status.Distribution != nil {
		enrolled := false
		for _, key := range cfg.Keys {
			enrolled = enrolled || h.Status.EnrolledCerts[key.ID] == "enrolled"
		}
		if !enrolled {
			result.Status, result.Reason = "blocked_mok_missing", "배포용 MOK 등록 확인 필요"
			return result
		}
	}
	// 설치 해시와 키 등록 상태가 없는 이전 에이전트는 첫 적용부터 작업의 기본 사본을 씁니다.
	// 처음에는 현재 active, 적용 후에는 작업 기본 키를 고르면 같은 이름의 설치 SHA가 바뀝니다.
	if j != nil && h.Status.ModuleSHA256 == "" && len(h.Status.EnrolledCerts) == 0 {
		if len(j.SigningArtifacts) > 0 {
			artifact, ok := j.SigningArtifacts[j.ActiveSigningKey]
			// 서명 설정을 생략한 기존 경로는 이름 없는 미서명 사본 하나를 기록합니다.
			// 이 호환 형식만 보존하며 이름 있는 키나 명시 signing의 unsigned는 허용하지 않습니다.
			legacyUnsigned := s.cfg.Signing == nil && len(s.cfg.SignCommand) == 0 && j.ActiveSigningKey == "" && len(j.SigningArtifacts) == 1 && artifact.KeyID == ""
			if !ok || !artifact.Signed && !legacyUnsigned {
				result.Status, result.Reason = "blocked_artifact", "기본 키의 서명 사본이 없어 새 누적 빌드·승인 필요"
				return result
			}
		}
		result.KeyID = j.ActiveSigningKey
		result.Warning = joinSecurityWarnings(result.Warning, "인증서 등록 상태와 설치 해시를 확인하지 못해 승인 작업의 기본 사본 배포 (이전 에이전트; active 키는 새 누적본부터 반영)")
		return result
	}
	// 같은 코드 버전의 서명만 바꾸려고 활성 모듈을 내리거나 부팅 파일을 덮지 않습니다.
	if j != nil && h.Status.Version == j.Version && j.Version != 0 {
		for _, key := range cfg.Keys {
			artifact, ok := j.SigningArtifacts[key.ID]
			if ok && artifact.Signed && artifact.SHA256 == h.Status.ModuleSHA256 && (h.Status.EnrolledCerts[key.ID] == "enrolled" || h.Status.Distribution == nil && h.Status.EnrolledCerts[key.ID] != "not_enrolled") {
				result.KeyID = key.ID
				if h.Status.EnrolledCerts[key.ID] != "enrolled" {
					result.Warning = joinSecurityWarnings(result.Warning, "기존 서명 사본의 인증서 등록 상태 미확인")
				}
				if key.ID != active {
					result.Warning = joinSecurityWarnings(result.Warning, "동일 버전의 기존 서명 사본 유지: active 키는 새 누적본부터 반영")
				}
				return result
			}
		}
	}
	knownMissing := false
	enrolledWithoutArtifact := false
	unknown := len(cfg.Keys) == 0
	candidates := []string{active}
	for _, key := range cfg.Keys {
		if key.ID != active {
			candidates = append(candidates, key.ID)
		}
	}
	for _, id := range candidates {
		switch h.Status.EnrolledCerts[id] {
		case "enrolled":
			if j != nil && len(j.SigningArtifacts) > 0 {
				if artifact, ok := j.SigningArtifacts[id]; !ok || !artifact.Signed {
					enrolledWithoutArtifact = true
					continue
				}
			}
			if j != nil && h.Status.Version == j.Version && h.Status.ModuleSHA256 != "" {
				if artifact, ok := j.SigningArtifacts[id]; ok && artifact.SHA256 != h.Status.ModuleSHA256 {
					result.Status, result.Reason = "blocked_artifact", "동일 버전의 서명 사본 교체 대신 새 누적본 빌드·승인 필요"
					return result
				}
			}
			result.KeyID = id
			return result
		case "not_enrolled":
			knownMissing = true
		default:
			unknown = true
		}
	}
	if enrolledWithoutArtifact {
		result.Status, result.Reason = "blocked_artifact", "등록된 키의 서명 사본이 없어 재승인 필요"
		return result
	}
	if unknown {
		if j != nil && len(j.SigningArtifacts) > 0 {
			if artifact, ok := j.SigningArtifacts[active]; !ok || !artifact.Signed {
				result.Status, result.Reason = "blocked_artifact", "active 키의 서명 사본이 없어 새 누적 빌드·승인 필요"
				return result
			}
			if h.Status.Version == j.Version && h.Status.ModuleSHA256 != "" && j.SigningArtifacts[active].SHA256 != h.Status.ModuleSHA256 {
				result.Status, result.Reason = "blocked_artifact", "동일 버전의 서명 사본 교체 대신 새 누적본 빌드·승인 필요"
				return result
			}
		}
		result.Warning = joinSecurityWarnings(result.Warning, "인증서 등록 상태를 확인하지 못해 active 사본 배포 (이전 에이전트 포함)")
		return result
	}
	if knownMissing {
		result.Status, result.Reason, result.KeyID = "blocked_mok_missing", "MOK 등록 필요", ""
		if h.Status.MOKPending {
			result.Reason = "다음 계획된 재부팅 때 콘솔에서 MOK 승인 필요"
		}
		return result
	}
	result.Status, result.Reason = "blocked_artifact", "등록된 키의 서명 사본이 없어 재승인 필요"
	return result
}
func joinSecurityWarnings(a, b string) string {
	if a == "" {
		return b
	}
	if b == "" {
		return a
	}
	return a + "; " + b
}
func (s *Server) excludedHosts(kernel string) []model.ExcludedHost {
	var out []model.ExcludedHost
	s.store.View(func(st *State) {
		for _, h := range st.Hosts {
			if h.Status.TrackKey() != kernel {
				continue
			}
			var job *model.Job
			if t := st.Tracks[kernel]; t != nil {
				job = st.releasedJob(kernel, t.TargetVersion(h.Ring))
			}
			e := s.rolloutEligibility(h, job)
			if e.Status != "eligible" {
				out = append(out, model.ExcludedHost{ID: h.ID, Hostname: h.Hostname, Reason: e.Reason})
			}
		}
	})
	return out
}
