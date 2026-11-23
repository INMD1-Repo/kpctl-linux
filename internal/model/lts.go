// 이 파일: model 패키지의 LTSByCodename, LTSForKernel, KernelABI 구현·자료형.
package model

import "strings"

// LTSSeries 는 기본으로 지원하는 Ubuntu LTS 시리즈 하나입니다.
//
// 대상은 GA 커널(설치 기본 커널, LTS 기간 내내 같은 버전)의 generic 변형뿐입니다.
// HWE 커널, nvidia·aws 같은 파생 커널은 git 트리와 빌드 컴파일러가 달라 자동 대상이 아닙니다
// (빌드 서버 설정 kernels 에 직접 넣으면 빌드할 수 있습니다).
type LTSSeries struct {
	Codename string // 예: "noble". Ubuntu 커널 git 트리 이름과 같음
	Version  string // 예: "24.04"
	Kernel   string // GA 커널 버전. uname -r 이 "<Kernel>-<ABI>-generic" 모양
}

// SupportedLTS 는 표준 지원(standard support) 중인 LTS 입니다.
// 새 LTS 가 나오면 추가하고, 표준 지원이 끝난 LTS 는 빼세요.
//
//	22.04 jammy    표준 지원 ~2027-04
//	24.04 noble    표준 지원 ~2029-04
//	26.04 resolute 표준 지원 ~2031-04
var SupportedLTS = []LTSSeries{
	{Codename: "jammy", Version: "22.04", Kernel: "5.15.0"},
	{Codename: "noble", Version: "24.04", Kernel: "6.8.0"},
	{Codename: "resolute", Version: "26.04", Kernel: "7.0.0"},
}

// LTSByCodename 은 코드네임으로 지원 LTS 를 찾습니다. 없으면 nil.
func LTSByCodename(codename string) *LTSSeries {
	for i := range SupportedLTS {
		if SupportedLTS[i].Codename == codename {
			return &SupportedLTS[i]
		}
	}
	return nil
}

// LTSForKernel 은 uname -r 값이 어느 지원 LTS 의 GA generic 커널인지 돌려줍니다. 아니면 nil.
// 예: "6.8.0-85-generic" → noble
func LTSForKernel(kernel string) *LTSSeries {
	if !strings.HasSuffix(kernel, "-generic") {
		return nil
	}
	for i := range SupportedLTS {
		if strings.HasPrefix(kernel, SupportedLTS[i].Kernel+"-") {
			return &SupportedLTS[i]
		}
	}
	return nil
}

// KernelABI 는 uname -r 에서 변형 이름을 뗀 값입니다. 예: "6.8.0-85-generic" → "6.8.0-85"
func KernelABI(kernel string) string {
	if i := strings.LastIndex(kernel, "-"); i > 0 {
		return kernel[:i]
	}
	return kernel
}

// SignatureVersion 은 /proc/version_signature 에서 Ubuntu 패키지 버전을 꺼냅니다.
//
//	"Ubuntu 6.8.0-85.85-generic 6.8.12"            → "6.8.0-85.85"
//	"Ubuntu 6.8.0-85.85~22.04.1-generic 6.8.12"    → "6.8.0-85.85~22.04.1" (HWE)
//
// 형식이 다르면 "".
func SignatureVersion(sig string) string {
	f := strings.Fields(sig)
	if len(f) < 2 || f[0] != "Ubuntu" {
		return ""
	}
	if i := strings.LastIndex(f[1], "-"); i > 0 {
		return f[1][:i]
	}
	return ""
}

// IsHWESignature 는 version_signature 가 HWE(다음 시리즈에서 백포트한) 커널인지 봅니다.
// HWE 커널은 패키지 버전에 "~22.04.1" 처럼 원래 시리즈가 붙습니다.
func IsHWESignature(sig string) bool {
	return strings.Contains(SignatureVersion(sig), "~")
}

// HWEWithGAName 은 HWE 커널인데 uname -r 이 지원 LTS 의 GA 커널과 같은 호스트입니다.
// 예: 22.04 의 HWE 6.8 커널은 24.04 GA 커널과 똑같이 "6.8.0-85-generic" 이지만 다른 컴파일러로
// 빌드한 다른 커널입니다. 이 호스트에는 GA 트랙 모듈을 주지 않고, 배포 검사에서도 뺍니다.
func HWEWithGAName(s HostStatus) bool {
	return IsHWESignature(s.KernelSignature) && LTSForKernel(s.Kernel) != nil
}
