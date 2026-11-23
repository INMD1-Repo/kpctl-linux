// Package buildlog 는 빌드 로그에서 명확한 라이브패치 제약만 구분합니다.
// 원인을 확정할 수 없는 실패는 검토 대상으로 남깁니다.
package buildlog

import "strings"

// Unsupported는 커널·CVE 예외 없이 명시적인 도구 거부만 인식합니다.
// 기존 kpatch 진단 표와 native objtool의 새 교차 객체 심볼 거부만 허용합니다.
func Unsupported(log string) bool {
	if Unpatchable(log) {
		return true
	}
	for _, line := range strings.Split(strings.ToLower(log), "\n") {
		line = strings.TrimSpace(line)
		if (strings.HasPrefix(line, "objtool:") || strings.Contains(line, ": objtool:")) &&
			strings.Contains(line, "unexpected klp reloc for new symbol") {
			return true
		}
	}
	return false
}

// Summary exposes a diagnostic instead of just the tool's exit status. It
// does not decide whether the patch can be livepatched; unknowns need review.
func Summary(log string) string {
	var fallback string
	var versionWarning string
	for _, line := range strings.Split(log, "\n") {
		line = strings.TrimSpace(line)
		lower := strings.ToLower(line)
		if strings.Contains(lower, "objtool:") && strings.Contains(lower, "unexpected klp reloc for new symbol") {
			return summaryLine(line)
		}
		if strings.HasPrefix(lower, "error:") || strings.Contains(lower, ": error:") || strings.Contains(lower, ": fatal error:") || strings.Contains(lower, "no rule to make target") {
			// kpatch logs every exported type-graph difference before the
			// fatal object comparison or imported-symbol validation error.
			if strings.Contains(lower, "version disagreement for symbol ") {
				if versionWarning == "" {
					versionWarning = line
				}
				continue
			}
			// Native shell ERR traps quote the failed command, not its cause.
			if strings.Contains(lower, "error: klp-build: line ") {
				if fallback == "" {
					fallback = line
				}
				continue
			}
			return summaryLine(line)
		}
		if fallback == "" && (strings.Contains(lower, "no space left on device") || strings.Contains(lower, "permission denied") || strings.Contains(lower, "command not found") || strings.Contains(lower, "hunk #") && strings.Contains(lower, "failed")) {
			fallback = line
		}
	}
	if fallback == "" {
		fallback = versionWarning
	}
	return summaryLine(fallback)
}

func summaryLine(line string) string {
	runes := []rune(line)
	if len(runes) > 300 {
		return string(runes[:300]) + "…"
	}
	return line
}

// Unpatchable 은 도구가 명시적으로 거부한 패치 내용의 제약만 인정합니다.
// 환경 오류가 섞여 있거나 알 수 없는 실패이면 false 입니다.
func Unpatchable(log string) bool {
	lower := strings.ToLower(log)
	for _, marker := range []string{
		"커널 소스 준비 실패", "빌드 환경 오류", "빌드 결과물 검증 실패", "디버그 심볼", "dget: curl", "dget: could not fetch",
		"curl: (22)", "could not resolve host", "temporary failure in name resolution",
		"no space left on device", "permission denied", "no rule to make target",
		"gcc version mismatch", "gcc/kernel version mismatch", "clang/kernel version mismatch",
		"kernel version mismatch", "command not found", "signal: killed", "context deadline exceeded",
		"certs] error", "patch does not apply", "failed to apply", "hunks failed",
	} {
		if strings.Contains(lower, marker) {
			return false
		}
	}
	for _, line := range strings.Split(lower, "\n") {
		line = strings.TrimSpace(line)
		line = strings.TrimPrefix(line, "create-diff-object: ")
		if !strings.HasPrefix(line, "error:") {
			continue
		}
		for _, marker := range []string{
			"changed data section", "unsupported changes detected",
			"unsupported section change(s)",
			"unsupported jump label(s)",
			"patch module referencing altered exported kernel symbols cannot be loaded",
		} {
			if strings.Contains(line, marker) {
				return true
			}
		}
	}
	return false
}
