// Package identities for official AMD64 distribution kernels.
package model

import (
	"crypto/sha256"
	"fmt"
	"regexp"
	"strings"
)

type DistributionKernel struct {
	Distro  string `json:"distro"`
	Release string `json:"release"`
	Arch    string `json:"arch"`
	ABI     string `json:"abi"`
	Version string `json:"version"`
	BuildID string `json:"build_id"`
}

var profiles = map[string][2]*regexp.Regexp{
	"debian12": {regexp.MustCompile(`^6\.1\.0-[0-9]+-amd64$`), regexp.MustCompile(`^6\.1\.[0-9]+-[0-9]+([+~]deb12u[0-9]+)?$`)},
	"debian13": {regexp.MustCompile(`^6\.12\.[0-9]+\+deb13(\.[0-9]+)?-amd64$`), regexp.MustCompile(`^6\.12\.[0-9]+-[0-9]+([+~]deb13u[0-9]+)?$`)},
	"rocky9":   {regexp.MustCompile(`^5\.14\.0-[0-9]+(\.[0-9]+)*\.el9(_[0-9]+)?\.x86_64$`), nil},
	"rocky10":  {regexp.MustCompile(`^6\.12\.0-[0-9]+(\.[0-9]+)*\.el10(_[0-9]+)?\.x86_64$`), nil},
}
var buildID = regexp.MustCompile(`^[a-f0-9]{40}$`)

// Rocky release RPMs label current GA installations as stable. Older os-release
// files have no RELEASE_TYPE. Their VERSION still identifies beta/RC images.
func RockyStable(releaseType, version string) bool {
	description := strings.ToLower(version)
	return (releaseType == "" || releaseType == "stable") && !strings.Contains(description, "beta") && !strings.Contains(description, "candidate") && !strings.Contains(description, " rc")
}

func SupportsDistributionABI(distro, release, arch, abi string) bool {
	p, ok := profiles[distro+release]
	return ok && (distro == "debian" || distro == "rocky") && (arch == "x86_64" || arch == "amd64") && p[0].MatchString(abi)
}

// DistributionForABI 는 uname -r 값이 지원하는 Debian/Rocky 기본 AMD64 커널이면 배포판과 주 릴리스를 돌려줍니다.
// 예: "6.12.0-264.21.1.el10_3.x86_64" → ("rocky", "10"), "6.1.0-57-amd64" → ("debian", "12"). 아니면 ("", "").
func DistributionForABI(abi string) (distro, release string) {
	for _, name := range []string{"debian12", "debian13", "rocky9", "rocky10"} {
		if profiles[name][0].MatchString(abi) {
			d := strings.TrimRight(name, "0123456789")
			return d, name[len(d):]
		}
	}
	return "", ""
}

// nativeKernelNames 는 Debian·RHEL 계열(Rocky 등) uname -r 모양입니다. 지원 여부와 무관합니다.
// 호스트 이름(예: 10.0.0-build-amd64)과 헷갈리지 않도록 Debian 은 ABI 번호(-57-) 또는 +debNN 표식,
// RHEL 계열은 .elN 표식과 RPM 아키텍처를 요구합니다.
//
//	Debian: 6.1.0-57-amd64, 6.1.0-57-686-pae, 6.1.0-57-rt-arm64, 6.12.118+deb13-amd64, 6.12.118+deb13.1-cloud-amd64
//	RHEL:   6.12.0-264.21.1.el10_3.x86_64, 5.14.0-427.el9.ppc64le, 4.18.0-553.el8_10.x86_64+debug
var nativeKernelNames = []*regexp.Regexp{
	regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(-[0-9]+|\+deb[0-9]+(\.[0-9]+)?)-([a-z0-9]+-)*(amd64|arm64|686|686-pae|armmp|armmp-lpae|marvell|rpi|powerpc64le|ppc64el|s390x|loong64|riscv64|mips64r2el|mips32r2el|octeon|4kc-malta|5kc-malta)$`),
	regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+-[0-9]+(\.[0-9A-Za-z_]+)*\.el[0-9]+(_[0-9]+)*(\.[0-9A-Za-z_]+)*\.(x86_64|aarch64|ppc64le|s390x)(\+[a-z0-9_]+)?$`),
}

// IsDistributionKernelName 은 Ubuntu 가 아닌 배포판(Debian·Rocky 등)의 uname -r 모양인지 봅니다.
// 지원 프로필 밖의 커널(예: Rocky 8, Debian arm64)도 참입니다. Ubuntu 빌더 대상이 아님을 판정하는 데 씁니다.
func IsDistributionKernelName(kernel string) bool {
	for _, re := range nativeKernelNames {
		if re.MatchString(kernel) {
			return true
		}
	}
	return false
}

func (k DistributionKernel) Track() string {
	p, ok := profiles[k.Distro+k.Release]
	if !ok || (k.Distro != "debian" && k.Distro != "rocky") || k.Arch != "amd64" || !buildID.MatchString(k.BuildID) || !p[0].MatchString(k.ABI) {
		return ""
	}
	if p[1] != nil {
		if !p[1].MatchString(k.Version) || k.Release == "13" && strings.SplitN(k.ABI, "+", 2)[0] != strings.SplitN(k.Version, "-", 2)[0] {
			return ""
		}
	} else if k.Version != strings.TrimSuffix(k.ABI, ".x86_64") {
		return ""
	}
	track := strings.Join([]string{"native", k.Distro, k.Release, k.Arch, k.ABI, strings.ReplaceAll(k.Version, "~", "_t"), k.BuildID}, "__")
	if len(track) > 200 {
		return ""
	}
	return track
}

func DistributionTrack(track string) (DistributionKernel, bool) {
	f := strings.Split(track, "__")
	if len(f) != 7 || f[0] != "native" {
		return DistributionKernel{}, false
	}
	k := DistributionKernel{f[1], f[2], f[3], f[4], strings.ReplaceAll(f[5], "_t", "~"), f[6]}
	return k, k.Track() == track
}

const TrixieBlocked = "Debian 13 stock 6.12는 식별·공식 소스 조사 전용입니다. IBT 활성, CONFIG_KLP_BUILD 없음: trixie-security의 정식 linux-image-amd64 업데이트를 설치하고 계획된 재부팅 후 실행 커널을 확인하세요."

func (k *DistributionKernel) BuildBlock() string {
	if k != nil && k.Distro == "debian" && k.Release == "13" {
		return TrixieBlocked
	}
	return ""
}

func (s HostStatus) ManagementBlock() string {
	reason := s.Distribution.BuildBlock()
	if s.Distribution == nil {
		reason = KernelBuildBlock(s.Kernel)
	}
	if s.IdentityError != "" {
		return strings.TrimSpace(s.IdentityError + " " + reason)
	}
	if reason != "" {
		return reason
	}
	if s.TrackKey() == "" {
		return "배포판 커널 패키지·실행 build ID 확인 필요"
	}
	return ""
}

// KernelBuildBlock also rejects ambiguous uname-only native job keys.
func KernelBuildBlock(key string) string {
	if k, ok := DistributionTrack(key); ok {
		return k.BuildBlock()
	}
	if profiles["debian13"][0].MatchString(key) {
		return TrixieBlocked
	}
	if strings.HasPrefix(key, "native__") || strings.HasSuffix(key, "-amd64") || strings.HasSuffix(key, ".x86_64") {
		return "정식 패키지 버전과 실행 build ID가 포함된 전체 배포판 트랙이 필요합니다"
	}
	return ""
}

// TrackKey retains historical Ubuntu keys. Old clients cannot address a native track.
func (s HostStatus) TrackKey() string {
	if s.IdentityError != "" {
		return ""
	}
	if s.Distribution != nil {
		if s.Distribution.ABI != s.Kernel {
			return ""
		}
		return s.Distribution.Track()
	}
	if strings.HasPrefix(s.Kernel, "native__") || strings.HasSuffix(s.Kernel, "-amd64") || strings.HasSuffix(s.Kernel, ".x86_64") {
		return ""
	}
	// Older Ubuntu agents may lack a version signature, but a known GA ABI
	// remains identifiable. A custom uname alone cannot establish the OS.
	if LTSForKernel(s.Kernel) == nil && SignatureVersion(s.KernelSignature) == "" {
		return ""
	}
	return s.Kernel
}

// DistributionProof is a receipt from the authenticated release-specific builder.
// PackageSHA256 identifies the signed image package; SourceSHA256 identifies its
// archive-verified DSC or Rocky-signed SRPM. Package signatures are checked before extraction.
type DistributionProof struct {
	Track         string `json:"track"`
	Revision      string `json:"revision"`
	SourceSHA256  string `json:"source_sha256"`
	PackageSHA256 string `json:"package_sha256"`
	Signer        string `json:"signer"`
}

var sha256Hex = regexp.MustCompile(`^[a-f0-9]{64}$`)
var releaseSigners = map[string][]string{
	"debian12": {"05AB90340C0C5E797F44A8C8254CF3B5AEC0A8F0", "B8B80B5B623EAB6AD8775C45B7C5D7D6350947F8", "4D64FEC119C2029067D6E791F8D2585B8783D481"},
	"debian13": {"5E04A1E3223A19A20706E20F9904613D4CCE68C6", "04B54C3CDCA79751B16BC6B5225629DF75B188BD", "41587F7DB8C774BCCF131416762F67A0B2C39DE4"},
	"rocky9":   {"21CB256AE16FC54C6E652949702D426D350D275D"},
	"rocky10":  {"FC226859C0860BF0DDB95B085B106C736FEDFC85"},
}

func (p *DistributionProof) Valid(track string) bool {
	k, ok := DistributionTrack(track)
	if p == nil || !ok || p.Track != track || !buildID.MatchString(p.Revision) || !sha256Hex.MatchString(p.SourceSHA256) || !sha256Hex.MatchString(p.PackageSHA256) {
		return false
	}
	for _, f := range releaseSigners[k.Distro+k.Release] {
		if p.Signer == f {
			return true
		}
	}
	return false
}

func NativeModuleName(track string, version int) string {
	h := sha256.Sum256([]byte(track))
	return fmt.Sprintf("kpctl_%x_v%d", h[:12], version)
}

// FixedRelease identifies the signed source of a reviewed file delta.
// The target module runs on the earlier kernel identified by the job's track.
type FixedRelease struct {
	ABI           string `json:"abi"`
	Version       string `json:"version"`
	Revision      string `json:"revision"`
	SourceSHA256  string `json:"source_sha256"`
	PackageSHA256 string `json:"package_sha256"`
	Signer        string `json:"signer"`
}

func (f *FixedRelease) ValidFor(base DistributionKernel, commit string) bool {
	if f == nil || f.Revision != commit || f.Version == base.Version {
		return false
	}
	base.ABI, base.Version = f.ABI, f.Version
	key := base.Track()
	proof := DistributionProof{Track: key, Revision: f.Revision, SourceSHA256: f.SourceSHA256, PackageSHA256: f.PackageSHA256, Signer: f.Signer}
	return key != "" && proof.Valid(key)
}

// DistroLabel 은 /etc/os-release 의 ID 를 표시용 이름으로 바꿉니다. 모르는 값은 그대로, 빈 값은 "알 수 없는 OS".
func DistroLabel(id string) string {
	switch id {
	case "ubuntu":
		return "Ubuntu"
	case "debian":
		return "Debian"
	case "rocky":
		return "Rocky"
	case "", "unknown":
		return "알 수 없는 OS"
	}
	return id
}
