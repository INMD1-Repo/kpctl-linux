// 이 파일: Debian/Rocky 네이티브 빌더 원격 설치 (kpctl install-builder 가 Debian 12·Rocky 9·10 호스트에서 씀).
//
// Ubuntu 빌더(builder.go, setup-builder.sh)와 같은 흐름입니다: 점검 → 묶음 복사 → worker.json·토큰·CA 전달
// → setup-native-builder.sh 실행. 원격 스크립트가 배포판 패키지·고정 kpatch·공식 Git·서명 패키지를 준비하고,
// 대상 커널마다 discover 로 계획(base.json)을, prepare --fetch 로 영수증(base-proof.json)을 만든 뒤
// kpctl-native-builder.timer 로 kpctl-native-builder.py work 를 주기 실행합니다.
//
// 보안 경계 (docs/operations/distribution-kernels.md):
//   - 빌더 호스트는 대상과 같은 릴리스의 전용 VM 입니다. 에이전트 호스트·컨테이너에는 -force 로도 설치하지 않습니다.
//   - 컨트롤러 승인 핀(distribution-proofs/<track>.json)은 독립 환경에서 운영자가 넣습니다. 여기서 만들지 않습니다.
//   - 수정 후보 수집(collect)은 사람이 검토합니다. 여기서 실행하지 않습니다.
package remote

import (
	"fmt"
	"strconv"
	"strings"

	"kpctl/internal/model"
)

// 네이티브 빌더 디스크 기준: 서명 디버그 패키지·기준 트리·빌드가 /var/lib/kpctl-native 에 쌓입니다.
const (
	nativeMinVarFreeKB  = 40 << 20 // 40 GiB 미만이면 설치 거부
	nativeWarnVarFreeKB = 80 << 20 // 80 GiB 미만이면 경고
)

// IsNativeBuilderOS 는 네이티브 빌더 경로(setup-native-builder.sh)로 다룰 배포판인지 봅니다 (지원 릴리스 여부는 따로 판정).
func (f Facts) IsNativeBuilderOS() bool {
	return f.Distro == "debian" || f.Distro == "rocky"
}

// NativeRelease 는 os-release 의 VERSION_ID 에서 주 릴리스만 뗍니다. 예: "10.1" → "10".
func (f Facts) NativeRelease() string {
	release, _, _ := strings.Cut(f.Release, ".")
	return release
}

// NativeBuilderHardBlock 은 -force 로도 넘길 수 없는 네이티브 빌더 설치 거부 이유입니다. 없으면 "".
// 지원하지 않는 릴리스·컨테이너·에이전트(운영) 호스트에는 빌더 토큰과 빌드 환경을 두지 않습니다.
func NativeBuilderHardBlock(f Facts) string {
	if ok, reason := model.NativeBuilderRelease(f.Distro, f.NativeRelease()); !ok {
		return reason
	}
	if f.Distro == "debian" && f.Codename != "bookworm" {
		return fmt.Sprintf("Debian 12 빌더는 bookworm 이어야 합니다 (현재 %s)", f.OSLabel())
	}
	if f.Distro == "rocky" && !model.RockyStable(f.ReleaseType, f.ReleaseDescription) {
		return fmt.Sprintf("Rocky 정식(stable) 릴리스가 아닙니다 (%s %s)", f.OSLabel(), f.ReleaseDescription)
	}
	if f.Arch != "x86_64" {
		return fmt.Sprintf("네이티브 빌더는 AMD64(x86_64) 전용입니다 (현재 %s)", f.Arch)
	}
	if f.Container != "" && f.Container != "none" {
		return fmt.Sprintf("컨테이너(%s) 안입니다. 네이티브 빌더는 대상과 같은 릴리스의 전용 VM 에 설치합니다", f.Container)
	}
	if f.Agent == "installed" {
		return "에이전트가 설치된 운영 호스트입니다. 네이티브 빌더는 패치 대상과 분리된 전용 VM 에 설치합니다 (-force 로도 넘길 수 없음)"
	}
	return ""
}

// nativeBuilderChecks 는 Preflight(ForBuilder) 의 Debian/Rocky 판정입니다.
func nativeBuilderChecks(f Facts, o PreflightOptions) (problems, warnings []string) {
	if reason := NativeBuilderHardBlock(f); reason != "" {
		problems = append(problems, reason)
	}
	if f.Distro == "rocky" && f.NativeRelease() == "10" && f.X86V3 != "yes" {
		problems = append(problems, "Rocky 10 빌더에는 x86-64-v3 CPU 기능(AVX2·BMI2·FMA·MOVBE)이 필요합니다. VM CPU 모델을 host 또는 v3 이상으로 바꾸세요")
	}
	if f.Systemd == "no" {
		problems = append(problems, "systemd 로 부팅하지 않은 시스템입니다 (kpctl-native-builder.timer 필요)")
	}
	if kb, err := strconv.ParseInt(f.VarFreeKB, 10, 64); err == nil {
		switch {
		case kb < nativeMinVarFreeKB:
			problems = append(problems, fmt.Sprintf("/var 여유 공간 %d GiB: 네이티브 빌더는 서명 디버그 패키지·기준 트리에 40 GiB 이상 필요합니다", kb>>20))
		case kb < nativeWarnVarFreeKB:
			warnings = append(warnings, fmt.Sprintf("/var 여유 공간 %d GiB: 커널 2개 이상이면 부족할 수 있습니다 (80 GiB 권장)", kb>>20))
		}
	}
	if f.Virt == "none" {
		warnings = append(warnings, "물리 서버입니다. 네이티브 빌더는 대상과 같은 릴리스의 전용 VM 을 권장합니다")
	}
	if f.NativeBuilderActive == "yes" {
		if o.StopBuilder {
			warnings = append(warnings, "켜져 있는 kpctl-native-builder.timer 를 멈추고 다시 설치합니다 (진행 중인 빌드는 실패로 끝납니다)")
		} else {
			problems = append(problems, "kpctl-native-builder.timer 가 켜져 있습니다. 작업이 끝난 뒤 -stop-running 으로 다시 실행하세요")
		}
	}
	return problems, warnings
}

// NativeTarget 은 네이티브 빌더가 빌드할 커널 하나입니다.
// Track 을 알면(컨트롤러 등록 호스트에서) setup-native-builder.sh 가 prepare 영수증의 track 과 정확히 같은지 확인합니다.
// 빌드 ID 까지 들어 있어 같은 ABI 의 다른 빌드에 맞춘 모듈을 만들지 않습니다.
type NativeTarget struct {
	ABI   string // uname -r, 예: 6.12.0-264.21.1.el10_3.x86_64
	Track string // native__rocky__10__amd64__<ABI>__<버전>__<build ID> (모르면 "")
}

// Arg 는 setup-native-builder.sh 의 --target 값입니다: "ABI" 또는 "ABI=TRACK".
func (t NativeTarget) Arg() string {
	if t.Track == "" {
		return t.ABI
	}
	return t.ABI + "=" + t.Track
}

// NativeBuilderInstallOptions 는 네이티브 빌더 설치 값입니다.
type NativeBuilderInstallOptions struct {
	ControllerURL string
	// Worker 는 원격 /etc/kpctl/native-builder/worker.json 내용입니다 (controller_url, ca_file, token_file, builder).
	// 토큰은 들어 있지 않습니다. 비우면 원격에 이미 있는 worker.json·토큰을 그대로 씁니다.
	Worker      []byte
	Token       string // 빌더 토큰 (Worker 를 줄 때만). 표준 입력으로 0600 파일에 써서 넘깁니다 (명령줄·로그에 남기지 않음)
	CAFile      string // 로컬 CA 인증서 (선택) → /etc/kpctl/tls/ca.crt
	Targets     []NativeTarget
	SetupArgs   []string // setup-native-builder.sh 에 그대로 넘길 추가 옵션 (--jobs, --no-start, --user)
	StopRunning bool     // 켜져 있는 kpctl-native-builder.timer·service 를 먼저 멈춤
}

// InstallNativeBuilder 는 묶음을 복사하고 setup-native-builder.sh 를 실행합니다. Preflight(ForBuilder) 를 먼저 불러야 합니다.
// 설치 스크립트의 "■" 단계 줄은 OnStep 으로 바로 보여 줍니다 (서명 패키지 내려받기·prepare 로 오래 걸리므로).
//
// TODO(codex): InstallBuilder(builder.go) 와 같은 방식으로 구현합니다.
//  1. mktemp -d /tmp/kpctl-native-builder.XXXXXX (이름 검증), defer 로 성공·실패 모두 sudo rm -rf. 삭제 실패는 errors.Join.
//  2. 묶음 전체 CopyTree, CA 는 하위 ca/ 디렉터리로 Copy.
//  3. Worker 가 있으면 worker.json 과 token 을 각각 "umask 077; cat > FILE" 표준 입력으로 씀. Token 이 비면 오류.
//     Worker 가 있는데 Token 이 16자 미만이면 오류. 로그(s.Log)에 토큰이 남지 않아야 함 (run 은 stdin 을 기록하지 않음).
//  4. HostsEntry 가 있으면 hostsEntryScript 실행 (InstallBuilder 와 같음).
//  5. StopRunning && Facts.NativeBuilderActive == "yes" 이면 systemctl stop kpctl-native-builder.timer kpctl-native-builder.service.
//  6. sudo bash setup-native-builder.sh [--worker F --token-file F] [--ca-file F] [SetupArgs...] --target <t.Arg()>...
//     RunStream 으로 "■", "!!", "경고" 줄을 OnStep 에 넘김. 실패 시 lastLines(out, 15) 포함.
func (s *Session) InstallNativeBuilder(b *Bundle, o NativeBuilderInstallOptions) error {
	return fmt.Errorf("InstallNativeBuilder: 아직 구현되지 않았습니다")
}
