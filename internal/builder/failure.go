// 이 파일: builder 패키지의 Error, Unwrap, failureKind 구현·자료형.
package builder

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"unicode/utf8"

	"kpctl/internal/buildlog"
	"kpctl/internal/model"
)

var errBuildArtifact = errors.New("빌드 산출물 검증 오류")

type buildFailure struct {
	kind string
	err  error
}

func (e *buildFailure) Error() string { return e.err.Error() }
func (e *buildFailure) Unwrap() error { return e.err }

func failureKind(err error, log string) string {
	switch {
	case errors.Is(err, errBuildBusy):
		return model.FailureBusy
	case errors.Is(err, errBuildArtifact):
		return model.FailureArtifact
	case errors.Is(err, errBuildEnv):
		return model.FailureEnvironment
	case errors.Is(err, errPatchDependency):
		return model.FailureUnsupported
	}
	var classified *buildFailure
	if errors.As(err, &classified) {
		return classified.kind
	}
	var pathErr *os.PathError
	var execErr *exec.Error
	if errors.As(err, &pathErr) || errors.As(err, &execErr) {
		return model.FailureEnvironment // 실행 파일·작업 공간 접근 실패
	}
	for _, marker := range []string{"dget: could not fetch", "curl: (22)", "could not resolve host", "command not found", "gcc/kernel version mismatch", "no space left on device", "permission denied"} {
		if strings.Contains(strings.ToLower(log), marker) {
			return model.FailureEnvironment
		}
	}
	// 강제 종료나 시간 초과 뒤에 남은 도구 진단으로 제약을 확정하지 않습니다.
	if err != nil {
		text := strings.ToLower(err.Error() + "\n" + log)
		for _, marker := range []string{"signal: killed", "context deadline exceeded", "timed out"} {
			if strings.Contains(text, marker) {
				return model.FailureUnknown
			}
		}
	}
	if buildlog.Unsupported(log) || patchApplyFailure(log) {
		return model.FailureUnsupported
	}
	return model.FailureUnknown
}

func failureMessage(kind string) string {
	switch kind {
	case model.FailureEnvironment:
		return "빌드 환경 오류 — 제한 재시도 후 보류, 환경 확인 필요"
	case model.FailureUnsupported:
		return "도구가 지원하지 않는 변경 — 새 커널로 업데이트 권장 또는 관리자 결정 필요"
	case model.FailureArtifact:
		return "산출물 검증 실패 — 배포 차단, 관리자 검토 필요"
	default:
		return "시험 빌드 원인 미확인 — 관리자 검토 필요"
	}
}

// 이미 선택한 프로파일만 읽습니다. 보고 때문에 prepare나 원격 조회를 하지 않습니다.
func (b *Builder) trialInput(k KernelConfig) model.BuildInput {
	input := model.BuildInput{BaseTag: k.BaseTag, BuildTool: b.cfg.buildTool(k.Kernel)}
	if b.cfg.Sandbox != nil {
		input.Profile, _ = b.sandboxProfile(k.Kernel)
		if data, err := os.ReadFile(input.Profile); err == nil {
			var profile struct {
				Image string `json:"image"`
			}
			if json.Unmarshal(data, &profile) == nil {
				input.Image = profile.Image
			}
		}
	}
	return input
}

func (b *Builder) reportTrialFailure(k KernelConfig, err error, failure *model.TrialFailure) {
	kind := failureKind(err, "")
	problem := fmt.Sprintf("%s: %s", failureMessage(kind), firstLineOf(err.Error()))
	for len(problem) > 1000 {
		_, size := utf8.DecodeLastRuneInString(problem)
		problem = problem[:len(problem)-size]
	}
	req := model.UpstreamReport{Problem: &problem, ProblemKind: kind, ProblemFailure: failure}
	// 문구가 같아도 실패 커밋·입력이 바뀔 수 있어 문구만으로 중복 제거하지 않습니다.
	if reportErr := b.c.Do("POST", "/api/builder/kernels/"+k.Kernel+"/upstream", req, nil); reportErr != nil {
		log.Printf("[%s] 시험 실패 보고 실패: %v", k.Kernel, reportErr)
		return
	}
	if b.lastProblem == nil {
		b.lastProblem = map[string]string{}
	}
	if b.lastProblemKind == nil {
		b.lastProblemKind = map[string]string{}
	}
	b.lastProblem[k.Kernel], b.lastProblemKind[k.Kernel] = problem, kind
}
