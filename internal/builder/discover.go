// 이 파일: 정식/출시 전 경로의 CVE 선택·선행 수정·시험과 검토 중단.
package builder

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"kpctl/internal/buildlog"
	"kpctl/internal/model"
)

var errPatchDependency = errors.New("패치 적용 문맥 불일치, 선행 수정 검증 필요")

// DiscoverAll 은 설정된 모든 커널에 대해 자동 수집을 실행합니다.
// 시험 빌드 한도에 걸려 남은 커밋이 있으면 true (Run 이 다음 주기를 기다리지 않고 이어서 부름).
func (b *Builder) DiscoverAll() (more bool) {
	b.retryDiscovery = false
	for _, k := range b.kernels() {
		if b.stopping() {
			return more
		}
		m, err := b.discover(k)
		if errors.Is(err, errBuildDeferred) {
			b.retryDiscovery = true
		}
		if err != nil {
			log.Printf("[%s] 자동 수집 실패: %v", k.Kernel, err)
		}
		more = more || m
	}
	return more
}

// DiscoverKernels 는 지정한 커널만 바로 수집합니다 (관리자 요청). 한도에 걸린 나머지도 끝까지 이어서 합니다.
func (b *Builder) DiscoverKernels(names []string) {
	want := map[string]error{}
	for _, n := range names {
		want[n] = nil
	}
	for _, k := range b.availableKernels(want) {
		if b.stopping() {
			return
		}
		if _, requested := want[k.Kernel]; !requested {
			continue
		}
		delete(want, k.Kernel)
		delete(b.deferredDiscovery, k.Kernel)
		for {
			if b.stopping() {
				return
			}
			more, err := b.discoverWithForce(k, true)
			if err != nil {
				if errors.Is(err, errBuildDeferred) {
					b.deferDiscovery(k.Kernel)
				}
				log.Printf("[%s] 수집 실패: %v", k.Kernel, err)
				break
			}
			if !more {
				break
			}
		}
	}
	for n, err := range want {
		if err != nil {
			b.deferDiscovery(n)
			log.Printf("[%s] 수동 수집 요청 보류: %v", n, err)
			continue
		}
		log.Printf("[%s] 이 빌드 서버에서 수집할 수 없는 커널입니다", n)
	}
}

// reportUpstream 은 Ubuntu 최신 태그와 수집 기준 태그를 컨트롤러에 알립니다 (웹의 호스트 화면에 표시).
func (b *Builder) reportUpstream(kernel, latest, collected string) {
	if latest == "" && collected == "" {
		return
	}
	req := model.UpstreamReport{LatestTag: latest, CollectedTag: collected}
	if err := b.c.Do("POST", "/api/builder/kernels/"+kernel+"/upstream", req, nil); err != nil {
		log.Printf("[%s] Ubuntu 최신 태그 보고 실패: %v", kernel, err)
	}
}

// tagFailureLimit 은 fetch·태그 확인의 커널별 연속 실패 허용 횟수입니다.
const tagFailureLimit = 3

const problemTagFetch = "tag_fetch"

// 원격 확인과 정기 수집의 fetch·태그 실패가 같은 커널별 카운터를 사용합니다.
func (b *Builder) tagCheckResult(kernel string, err error) {
	if b.tagFailures == nil {
		b.tagFailures = map[string]int{}
	}
	if err != nil {
		b.tagFailures[kernel]++
		log.Printf("[%s] fetch·태그 확인 실패 %d/%d회: %v", kernel, b.tagFailures[kernel], tagFailureLimit, err)
		if b.tagFailures[kernel] >= tagFailureLimit {
			b.reportProblemKind(kernel, fmt.Sprintf("fetch·태그 확인이 %d회 연속 실패: %v", b.tagFailures[kernel], err), problemTagFetch, false)
		}
		return
	}
	delete(b.tagFailures, kernel)
	// 재시작 뒤에도 컨트롤러의 같은 종류만 해제합니다.
	b.reportProblemKind(kernel, "", problemTagFetch, true)
}

// UpdatesAvailable 은 정식 APT 배포 상한이 마지막 수집에서 확인한 태그와 다른지 확인합니다.
func (b *Builder) UpdatesAvailable() bool {
	type tagResult struct {
		tag string
		err error
	}
	seen := map[string]tagResult{} // git+계열 → 정식 배포 태그 또는 실패
	found := false
	for _, k := range b.kernels() {
		key := k.GitDir + " " + k.TagGlob
		r, ok := seen[key]
		if !ok {
			r.tag, r.err = b.latestTargetTag(k, true)
			seen[key] = r
		}
		b.tagCheckResult(k.Kernel, r.err)
		if r.err != nil {
			continue
		}
		remote := r.tag
		b.reportUpstream(k.Kernel, remote, "")
		if remote != "" && remote != b.lastTarget[k.Kernel] {
			log.Printf("[%s] 정식 배포 태그 %s (이전 확인 %s) → 수집·빌드 확인", k.Kernel, remote, dash(b.lastTarget[k.Kernel]))
			found = true
		}
	}
	return found
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// discover 는 Ubuntu 커널 git 에서 새 CVE 수정 커밋을 찾아 컨트롤러에 등록합니다.
//
// 흐름:
//  1. git fetch --tags 로 새 태그 받기
//  2. base_tag 이후 정식 배포 태그까지, 메시지에 CVE 가 있고 대상 경로를 건드린 커밋 찾기
//  3. 컨트롤러가 이미 아는 커밋은 건너뛰기
//  4. 커밋마다 시험 → 성공하면 패치, 실패하면 유형과 입력을 보고하고 검토 대기
//  5. 결과를 컨트롤러에 올림 (새 패치가 있으면 컨트롤러가 누적 빌드 작업을 만듦)
func (b *Builder) discover(k KernelConfig) (more bool, err error) {
	return b.discoverWithForce(k, false)
}

func (b *Builder) discoverWithForce(k KernelConfig, force bool) (more bool, err error) {
	b.setActivity(model.BuilderActivity{Phase: "discovering", Kernel: k.Kernel, Message: "정식 배포 태그·CVE 수집"})
	defer func() {
		if errors.Is(err, errDiskSpace) {
			b.finishActivity(k.Kernel, "디스크 부족 · 빌드 보류", nil)
		} else if errors.Is(err, errBuildDeferred) {
			b.finishActivity(k.Kernel, firstLineOf(err.Error()), nil)
		} else {
			b.finishActivity(k.Kernel, "수집 주기 완료", err)
		}
	}()
	var latest string
	var failedCommit *model.TrialFailure
	tagFailed := false
	defer func() {
		if errors.Is(err, errBuildDeferred) {
			b.retryDiscovery = true
		} else if err != nil && !tagFailed {
			b.reportTrialFailure(k, err, failedCommit)
		} else if err == nil && !more && latest != "" {
			b.reportProblem(k.Kernel, "")
			b.reportUpstream(k.Kernel, latest, latest)
		}
	}()
	if _, err := git(k.GitDir, "fetch", "--tags", "--quiet"); err != nil {
		tagFailed = true
		b.tagCheckResult(k.Kernel, err)
		return false, err
	}
	if k.BaseTag == "" {
		tag, err := resolveBaseTag(k)
		if err != nil {
			tagFailed = true
			b.tagCheckResult(k.Kernel, err)
			return false, err
		}
		k.BaseTag = tag
	}
	latest, err = b.latestTargetTag(k, false)
	if err != nil {
		tagFailed = true
		b.tagCheckResult(k.Kernel, err)
		return false, err
	}
	b.tagCheckResult(k.Kernel, nil)
	// 환경·시험 빌드 오류는 fetch·태그 카운터에 넣지 않습니다.
	if !b.cfg.SkipTrialBuild {
		if _, err := os.Stat(k.Vmlinux); err != nil {
			return false, fmt.Errorf("%w: 디버그 심볼 %s 이 없어 시험 빌드를 할 수 없습니다 (linux-image-%s-dbgsym 설치)", errBuildEnv, k.Vmlinux, k.Kernel)
		}
	}
	if b.lastTarget == nil {
		b.lastTarget = map[string]string{}
	}
	b.lastTarget[k.Kernel] = latest
	b.reportUpstream(k.Kernel, latest, "")
	if latest == "" || latest == k.BaseTag {
		log.Printf("[%s] 새 태그 없음 (기준 %s)", k.Kernel, k.BaseTag)
		return false, nil
	}
	if _, err := git(k.GitDir, "merge-base", "--is-ancestor", k.BaseTag, latest); err != nil {
		problem := fmt.Sprintf("기준 커널 %s → 정식 배포 %s 의 순방향 이력을 확인하지 못해 수집을 중단합니다", k.BaseTag, latest)
		return false, fmt.Errorf("%s", problem)
	}
	log.Printf("[%s] %s..%s 에서 CVE 커밋 확인", k.Kernel, k.BaseTag, latest)
	return b.discoverRange(k, k.BaseTag, latest, force, false, &failedCommit)
}

// discoverRange는 공식/출시 전 채널의 경로 필터·의존성·시험 실패 정책을 공유합니다.
// lower는 후보 선택 경계이며, 실제 시험 소스 기준은 언제나 원래 k.BaseTag입니다.
func (b *Builder) discoverRange(k KernelConfig, lower, latest string, force, prerelease bool, failedCommit **model.TrialFailure) (more bool, err error) {
	// 켠 feed를 읽지 못하면 후보 일부도 등록하기 전에 멈춰 검토를 기다립니다.
	feed, err := b.loadCVEFeed()
	if err != nil {
		return false, fmt.Errorf("%w: 커널 CNA CVE feed 검토 필요: %w", errBuildEnv, err)
	}
	// feed를 켰을 때만 메시지 CVE grep을 풀고 같은 소스 경로에서 upstream ID를 대조합니다.
	args := []string{"log", "--reverse", "--format=%H"}
	if b.cfg.CVEFeed == nil || !b.cfg.CVEFeed.Enabled {
		args = append(args, "-E", `--grep=CVE-[0-9]{4}-[0-9]+`)
	}
	args = append(args, lower+".."+latest, "--")
	args = append(args, k.paths()...)
	out, err := git(k.GitDir, args...)
	if err != nil {
		return false, err
	}
	commits := lines(out)

	var known model.KnownCommitsResponse
	knownURL := "/api/builder/kernels/" + k.Kernel + "/known"
	if prerelease {
		knownURL += "?prerelease=true"
	}
	if err := b.c.Do("GET", knownURL, nil, &known); err != nil {
		return false, fmt.Errorf("%w: 이미 처리한 커밋 조회 실패: %v", errBuildEnv, err)
	}
	isKnown := map[string]bool{}
	inactive := map[string]bool{}
	for _, c := range known.Commits {
		isKnown[c] = true
		inactive[c] = true
	}
	for _, p := range known.ActivePatches {
		delete(inactive, p.Commit)
	}
	var decisions []string
	for sha := range inactive {
		decisions = append(decisions, sha)
	}

	req := model.DiscoveredRequest{LatestTag: latest}
	if prerelease {
		req.Prerelease, req.LatestTag = true, ""
	}
	prerequisites := append([]model.DiscoveredPatch(nil), known.ActivePatches...)
	trials := 0
	current, total := 0, 0
	for _, sha := range commits {
		if !isKnown[sha] {
			total++
		}
	}
	var reviewErr error
	var environment string
	environmentChecked := false
	for _, sha := range commits {
		if b.stopping() {
			more = true // Publish verified inputs, without claiming the whole tag.
			break
		}
		if isKnown[sha] {
			continue
		}
		if !b.cfg.SkipTrialBuild && trials >= b.cfg.MaxTrialsPerRun {
			log.Printf("[%s] 시험 빌드 한도(%d) 도달, 나머지는 이 결과를 올린 뒤 바로 이어서", k.Kernel, b.cfg.MaxTrialsPerRun)
			more = true
			break
		}

		msg, err := git(k.GitDir, "log", "-1", "--format=%B", sha)
		if err != nil {
			return false, err
		}
		title, _ := git(k.GitDir, "log", "-1", "--format=%s", sha)
		title = strings.TrimSpace(title)
		cves := mappedCVEs(msg, feed)
		if len(cves) == 0 {
			continue
		}
		if isRevertCommit(msg) {
			reviewErr = fmt.Errorf("CVE 수정의 되돌리기 커밋 %s 은 관리자 검토가 필요해 수집을 멈췄습니다: %s", sha[:12], title)
			break
		}
		content, err := git(k.GitDir, "format-patch", "-1", "--stdout", sha)
		if err != nil {
			return false, err
		}
		// 이 커밋이 기대는 선행·보완 커밋(CVE 가 아닌 것 포함)을 빌드 전에 git 만으로 찾아 한 묶음으로 만듭니다 (prereq.go).
		// 단독 패치가 적용은 되지만 선언이 없어 컴파일이 깨지는 경우를 긴 빌드 없이 걸러 냅니다.
		ps, err := resolvePatchSet(k.GitDir, k.BaseTag, latest, sha, b.cfg.MaxPrereqs)
		if err == nil {
			err = validatePatchSet(k.GitDir, ps, inactive)
		}
		if err == nil {
			ps, err = independentPatchSet(k.GitDir, ps, sha, content, prerequisites)
		}
		var unresolved *unresolvedError
		if errors.As(err, &unresolved) {
			*failedCommit = &model.TrialFailure{Commit: sha, CVEs: cves, Title: title, Input: b.trialInput(k)}
			reviewErr = fmt.Errorf("시험 빌드 검토가 필요해 수집을 멈췄습니다: %w", &buildFailure{model.FailureUnsupported, err})
			break
		}
		if err != nil {
			return false, err
		}
		if n := len(ps.Commits) - 1; n > 0 {
			content = ps.Content
			log.Printf("[%s] %s 선행·보완 커밋 %d개 포함:\n  %s", k.Kernel, sha[:12], n, strings.Join(ps.Notes, "\n  "))
		}
		if adaptation := selectAdaptation(k, sha); adaptation != nil {
			if b.cfg.SkipTrialBuild {
				return false, fmt.Errorf("%s 수정본은 시험 빌드 생략을 허용하지 않습니다", adaptation.name)
			}
			content, err = adaptation.verifiedContent(k)
			if err != nil {
				return false, err
			}
			title += " [" + adaptation.label + "]"
			log.Printf("[%s] %s: 검토한 라이브패치 수정본으로 시험 (원본 %s)", k.Kernel, adaptation.name, sha[:12])
		}

		if !b.cfg.SkipTrialBuild {
			if !environmentChecked {
				environmentChecked = true
				var fingerprintErr error
				environment, fingerprintErr = b.trialEnvironmentFingerprint(k, latest)
				if fingerprintErr != nil {
					log.Printf("[%s] 시험 입력 식별 실패, 재시험 보류 기록을 사용하지 않습니다: %v", k.Kernel, fingerprintErr)
				}
			}
			fingerprint := ""
			if environment != "" {
				fingerprint = trialFingerprint(environment, content, prerequisites, decisions)
			}
			if !force {
				if previous := b.previousTrialFailure(k.Kernel, sha, fingerprint, prerelease); previous != nil {
					log.Printf("[%s] %s: 같은 입력의 실패 재시험 보류 (입력 변경 또는 관리자 빌드 요청 때 재시도)", k.Kernel, shortSHA(sha))
					*failedCommit = &model.TrialFailure{Commit: sha, CVEs: cves, Title: title, Input: b.trialInput(k)}
					reviewErr = previous
					break
				}
			}
			trials++
			current++
			b.setActivity(model.BuilderActivity{Phase: "trial", Kernel: k.Kernel, Commit: sha, CVEs: cves,
				Current: current, Total: total, Message: title})
			log.Printf("[%s] 시험 빌드 %s %v", k.Kernel, sha[:12], cves)
			var envErr error
			if ps.ActivePrerequisites {
				_, envErr = b.trialBuildPatches(k, sha, content, prerequisites, prerelease)
			} else {
				_, envErr = b.trialBuildPatches(k, sha, content, nil, prerelease)
			}
			if !ps.ActivePrerequisites && errors.Is(envErr, errPatchDependency) && len(prerequisites) > 0 {
				log.Printf("[%s] %s 단독 적용 문맥 불일치 → 기존 활성 패치와 앞서 검증한 CVE %d건을 포함해 재시험", k.Kernel, sha[:12], len(prerequisites))
				_, envErr = b.trialBuildPatches(k, sha, content, prerequisites, prerelease)
			}
			if envErr != nil {
				if errors.Is(envErr, errBuildDeferred) {
					reviewErr = envErr
					break
				}
				*failedCommit = &model.TrialFailure{Commit: sha, CVEs: cves, Title: title, Input: b.trialInput(k)}
				reviewErr = fmt.Errorf("시험 빌드 검토가 필요해 수집을 멈췄습니다: %w", envErr)
				if saveErr := b.saveTrialFailure(k.Kernel, sha, fingerprint, reviewErr, prerelease); saveErr != nil {
					log.Printf("[%s] 시험 실패 입력 기록 저장 실패: %v", k.Kernel, saveErr)
				}
				break // 앞서 검증한 결과만 보존하고 관리자 결정을 기다립니다.
			}
			b.clearTrialFailure(k.Kernel, prerelease)
		}
		req.Patches = append(req.Patches, model.DiscoveredPatch{
			Commit: sha, CVEs: cves, Title: title, Content: content,
		})
		prerequisites = append(prerequisites, req.Patches[len(req.Patches)-1])
	}

	if more || reviewErr != nil {
		req.LatestTag = "" // 한도에 걸려 latest 까지 다 보지 못함 → "어디까지 반영" 은 다음 결과에서
	}
	if len(req.Patches) == 0 && len(req.Unpatchable) == 0 {
		log.Printf("[%s] %s..%s 새 대상 커밋 없음", k.Kernel, k.BaseTag, latest)
		return more, reviewErr
	}
	var resp model.DiscoveredResponse
	b.setStep("검증한 수집 결과 등록")
	if err := b.c.Do("POST", "/api/builder/kernels/"+k.Kernel+"/discovered", req, &resp); err != nil {
		*failedCommit = nil // 통신 실패를 앞선 시험 커밋의 문제로 보고하지 않습니다.
		return false, fmt.Errorf("%w: 수집 결과 등록 실패: %v", errBuildEnv, err)
	}
	log.Printf("[%s] 등록: 패치 %d건, 불가 %d건, 빌드 작업 %d",
		k.Kernel, resp.AddedPatches, len(req.Unpatchable), resp.JobID)
	return more, reviewErr
}

// trialBuild 는 커밋 하나만으로 kpatch-build 를 해 봅니다.
// reason은 호환을 위해 빈 값으로 둡니다. 모든 실패는 검토 대상으로 반환합니다.
func (b *Builder) trialBuild(k KernelConfig, sha, content string) (reason string, envErr error) {
	return b.trialBuildPatches(k, sha, content, nil)
}

// trialBuildPatches 는 적용 문맥이 맞지 않을 때만 기존 활성 패치와 검증된 앞선 수정을
// 함께 시험합니다. 누적 시험의 실패는 상호작용일 수도 있으므로 새 커밋의 "불가"로 확정하지 않습니다.
func (b *Builder) trialBuildPatches(k KernelConfig, sha, content string, prerequisites []model.DiscoveredPatch, prerelease ...bool) (reason string, envErr error) {
	name := "trial-" + sha[:12]
	if len(prerelease) > 0 && prerelease[0] {
		name = "prerelease-" + name
	}
	if len(prerequisites) > 0 {
		name += "-with-prerequisites"
	}
	dir := filepath.Join(b.cfg.WorkDir, name)
	_ = os.RemoveAll(dir)
	keepLogs := false
	defer func() {
		if !keepLogs {
			os.RemoveAll(dir)
		}
	}()
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", fmt.Errorf("%w: %v", errBuildEnv, err)
	}
	// 묶음을 커밋 단위로 풀고, 기존 패치와 겹치는 선행 커밋은 한 번만 남겨 이력 순서로 적용합니다 (prereq.go).
	var labels, contents []string
	for _, p := range prerequisites {
		labels = append(labels, "prerequisite")
		contents = append(contents, p.Content)
	}
	labels = append(labels, "trial")
	contents = append(contents, content)
	files, werr := writePatchUnits(dir, flattenPatches(k.GitDir, labels, contents))
	if werr != nil {
		return "", fmt.Errorf("%w: %v", errBuildEnv, werr)
	}
	var out buildOutput
	var err error
	var retryLog string
	for attempt := 0; attempt < 2; attempt++ {
		out, err = b.runBuild(k, "kpctl_trial", filepath.Join(dir, "out"), files)
		if err == nil || failureKind(err, out.Log) != model.FailureEnvironment || attempt == 1 {
			break
		}
		retryLog = err.Error() + "\n" + out.Log
		log.Printf("[%s] 환경 오류 → 같은 입력으로 시험 1회 재시도: %s", k.Kernel, firstLineOf(err.Error()))
		if cleanErr := os.RemoveAll(filepath.Join(dir, "out")); cleanErr != nil {
			err = fmt.Errorf("%w: 재시도 작업 공간 정리 실패: %v", errBuildEnv, cleanErr)
			break
		}
	}
	if errors.Is(err, errBuildDeferred) {
		return "", err
	}
	if err != nil {
		kind := failureKind(err, out.Log)
		if (kind == model.FailureUnknown || kind == model.FailureUnsupported) && patchApplyFailure(out.Log) {
			err = fmt.Errorf("%w: %v", errPatchDependency, err)
			kind = model.FailureUnsupported
		}
		keepLogs = true
		path := filepath.Join(dir, "build.log")
		full := err.Error() + "\n" + out.Log
		if retryLog != "" {
			full = "첫 환경 오류 시도:\n" + retryLog + "\n재시도:\n" + full
		}
		detail := buildlog.Summary(out.Log)
		if detail == "" || kind == model.FailureEnvironment || kind == model.FailureArtifact {
			detail = firstLineOf(err.Error())
		}
		if logErr := os.WriteFile(path, []byte(full), 0o640); logErr != nil {
			return "", &buildFailure{kind, fmt.Errorf("%w; 로그 저장 실패: %v", err, logErr)}
		}
		return "", &buildFailure{kind, fmt.Errorf("%s (로그 %s): %w\n%s", detail, path, err, lastLines(out.Log, 30))}
	}
	return "", nil
}

func patchApplyFailure(log string) bool {
	for _, line := range strings.Split(strings.ToLower(log), "\n") {
		line = strings.TrimSpace(line)
		diagnostic := strings.HasPrefix(line, "error:") || strings.Contains(line, ": error:")
		if diagnostic && (strings.Contains(line, "patch does not apply") || strings.Contains(line, "failed to apply")) || strings.HasSuffix(line, ": patch does not apply") {
			return true
		}
		if strings.HasPrefix(line, "hunk #") {
			fields := strings.Fields(line)
			if len(fields) >= 3 && fields[2] == "failed" {
				return true
			}
		}
	}
	return false
}

func isRevertCommit(message string) bool {
	for i, line := range strings.Split(strings.ToLower(message), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "this reverts commit ") {
			return true
		}
		if i == 0 && (strings.HasPrefix(line, "revert ") || strings.Contains(line, ": revert ")) {
			return true
		}
	}
	return false
}

func firstLineOf(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
