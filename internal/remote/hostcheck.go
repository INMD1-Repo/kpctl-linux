// 이 파일: 에이전트(kpatch) 설치 전 호스트 상태 판정 — hostChecks.
//
// 점검 스크립트(preflightScript)가 읽어 온 값만 보고 판정하는 순수 함수라 표로 시험합니다.
// 규칙을 더하려면: preflightScript 에 echo 줄 → Facts 필드 → 여기 한 줄 → hostcheck_test.go 한 줄.
// 설치 스크립트가 스스로 고치는 것(dpkg 복구, python3 설치)은 경고로만 알립니다.
package remote

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"kpctl/internal/model"
)

const (
	minBootFreeKB = 300 << 10 // 다음 GA 커널 준비: 도우미는 256MB 미만이면 거부, 여유를 두고 경고
	minVarFreeKB  = 500 << 10 // apt 내려받기·패치 모듈·상태 파일
	maxClockSkew  = 5 * time.Minute
)

// hostChecks 는 패치 대상 호스트로서의 문제(설치 중단)와 경고를 돌려줍니다. now 는 컨트롤러 쪽 시각.
func hostChecks(f Facts, now time.Time) (problems, warnings []string) {
	problem := func(format string, a ...any) { problems = append(problems, fmt.Sprintf(format, a...)) }
	warn := func(format string, a ...any) { warnings = append(warnings, fmt.Sprintf(format, a...)) }

	if f.Container != "" && f.Container != "none" {
		problem("컨테이너(%s) 안입니다. 라이브패치는 커널 모듈이라 VM·물리 서버에 설치하세요", f.Container)
	}
	if f.Systemd == "no" {
		problem("systemd 로 부팅하지 않은 시스템입니다 (kpctl-agent.service 필요)")
	}
	if f.Livepatch != "yes" {
		problem("커널 %s 에 CONFIG_LIVEPATCH=y 가 없습니다", f.Kernel)
	}
	if f.Modules == "no" {
		problem("/lib/modules/%s 가 없습니다. 실행 중인 커널 패키지가 지워졌으니 설치된 커널로 재부팅한 뒤 다시 하세요", f.Kernel)
	}
	ubuntu := f.Distro == "ubuntu"
	if f.Distro == "debian" && f.Release == "13" && f.Codename == "trixie" {
		warn("%s", model.TrixieBlocked)
	}
	if !ubuntu {
		release, _, _ := strings.Cut(f.Release, ".")
		if f.Distro == "rocky" && !model.RockyStable(f.ReleaseType, f.ReleaseDescription) || !model.SupportsDistributionABI(f.Distro, release, f.Arch, f.Kernel) || f.Distro == "debian" && !(f.Release == "12" && f.Codename == "bookworm" || f.Release == "13" && f.Codename == "trixie") {
			problem("지원하지 않는 배포판 기본 AMD64 커널: %s %s %s %s", f.Distro, f.Release, f.Arch, f.Kernel)
		} else if f.NativePackage == "" {
			problem("실행 커널 %s와 일치하는 정식 배포판 이미지 패키지를 확인할 수 없습니다", f.Kernel)
		}
	}
	if ubuntu && model.LTSForKernel(f.Kernel) == nil {
		var names []string
		for _, l := range model.SupportedLTS {
			names = append(names, l.Codename)
		}
		warn("커널 %s 는 지원 LTS(%s)의 GA generic 커널이 아니어서 패치가 자동으로 빌드되지 않습니다", f.Kernel, strings.Join(names, ", "))
	}
	if strings.Contains(strings.ToLower(f.SecureBoot), "enabled") {
		warn("Secure Boot 켜짐: 패치 모듈 서명 인증서를 MOK 로 등록해야 합니다")
	} else if f.Lockdown != "" && f.Lockdown != "none" {
		warn("커널 lockdown(%s): 서명된 패치 모듈만 올라갑니다 (서명 인증서를 커널 키링에 등록 필요)", f.Lockdown)
	}
	if lp := strings.TrimSpace(f.OtherPatches); lp != "" {
		warn("다른 라이브패치가 올라가 있습니다 (%s). 기존 패치가 활성인 동안 kpctl 패치는 적용되지 않습니다", lp)
	}
	if fs, dev, _ := strings.Cut(f.BootFS, " "); ubuntu && f.BootFS != "" {
		switch {
		case fs == "none":
			warn("/boot/grub/grubenv 가 없어(GRUB 아님) 다음 GA 커널 자동 준비를 할 수 없습니다")
		case !strings.HasPrefix(fs, "ext") || strings.HasPrefix(dev, "/dev/dm-") || strings.HasPrefix(dev, "/dev/md"):
			warn("/boot 가 %s(%s)라 다음 GA 커널 자동 준비를 할 수 없습니다 (일반 ext2/3/4 파티션 필요). 커널 점프는 수동으로 하세요", fs, dev)
		}
	}
	switch ok := strings.HasPrefix(f.Archive, "2") || strings.HasPrefix(f.Archive, "3"); {
	case !ubuntu || f.Archive == "":
	case !ok:
		warn("mirrors.list 의 Ubuntu 미러에 모두 접속하지 못해(응답 %s) 다음 GA 커널 자동 준비가 실패합니다 (목록의 미러 중 하나에 HTTP 허용 필요)", f.Archive)
	case f.ArchiveVia != "official":
		warn("Ubuntu 공식 저장소에 접속하지 못해 %s 미러를 씁니다 (설치·커널 준비 모두 자동 전환)", f.ArchiveVia)
	}
	if kb, err := strconv.Atoi(f.BootFreeKB); ubuntu && err == nil && kb < minBootFreeKB {
		warn("/boot 여유 %dMB: 다음 GA 커널 준비에 %dMB 이상 필요합니다 (sudo apt autoremove --purge 로 옛 커널 정리)", kb>>10, minBootFreeKB>>10)
	}
	if kb, err := strconv.Atoi(f.VarFreeKB); err == nil && kb < minVarFreeKB {
		problem("/var 여유 %dMB: 패키지 설치와 패치 보관에 %dMB 이상 필요합니다", kb>>10, minVarFreeKB>>10)
	}
	if f.Dpkg == "broken" {
		warn("dpkg 가 설치 도중 멈춘 상태입니다. 설치하며 dpkg --configure -a 로 먼저 복구합니다")
	}
	if ubuntu && f.Python3 == "no" {
		warn("python3 가 없어 설치하며 함께 설치합니다 (커널 준비 도우미에 필요)")
	}
	if sec, err := strconv.ParseInt(f.Now, 10, 64); err == nil {
		if d := time.Unix(sec, 0).Sub(now); d > maxClockSkew || d < -maxClockSkew {
			warn("호스트 시계가 컨트롤러와 %s 어긋나 TLS 인증서 검증이 실패할 수 있습니다 (sudo timedatectl set-ntp true)", d.Round(time.Second))
		}
	}
	if f.Agent == "installed" {
		warn("이미 설치되어 있어 재설치(업그레이드)합니다. 등록과 적용 중인 패치는 유지됩니다")
	}
	return problems, warnings
}
