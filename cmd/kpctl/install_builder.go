// 이 파일: kpctl install-builder — SSH 로 빌드 서버를 한 번에 설치
//
// kpctl install 의 빌더판입니다. 점검 → 호스트 배포판(os-release)과 대상 커널 이름으로 빌더 종류 결정 →
// 그 종류 전용 묶음(dist/builder/ubuntu·debian·rocky)만 복사 → 설정(컨트롤러 주소·빌더 토큰·CA) 작성 →
// setup-builder.sh(Ubuntu) 또는 setup-native-builder.sh(Debian·Rocky) 실행 → 컨트롤러에 빌더가 보고하는지 확인까지 합니다.
// 실제 SSH 작업은 internal/remote/builder.go 가 합니다.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"kpctl/internal/client"
	"kpctl/internal/model"
	"kpctl/internal/remote"
)

const installBuilderUsage = `사용법: kpctl install-builder [옵션] <호스트...> [대상 커널...] [-- 설치 스크립트 옵션]
        kpctl install-builder                         (터미널에서 인자 없이: 질문형 설치)

  SSH 로 호스트를 점검하고 묶음과 설정을 복사한 뒤 설치와 컨트롤러 보고를 확인합니다. 옵션은 호스트 이름보다 앞에 써야 합니다.

  빌더는 Ubuntu·Debian·Rocky 전용 묶음으로 나뉘어 있습니다 (dist/builder/ubuntu, debian, rocky).
  대상 커널 이름(6.8.0-136-generic → Ubuntu, 6.1.0-57-amd64 → Debian, ….el9/el10.x86_64 → Rocky)과
  호스트 OS 를 대조해 맞는 묶음 하나만 복사·설치합니다. 커널과 호스트 배포판이 다르면 설치하지 않습니다.

  Ubuntu 빌더에서 대상 커널(예: 6.8.0-136-generic)을 생략하면, 컨트롤러에 등록된 호스트 중 빌드 서버와 같은
  Ubuntu 시리즈의 GA 커널을 자동으로 고릅니다. 커널 인자는 호스트별로 같은 시리즈인 것만 넘깁니다.
  "--" 뒤의 값은 setup-builder.sh 에 그대로 넘깁니다 (--memory-mib, --jobs, --cache-gib, --no-cache,
  --host-mode, --no-start 등; sudo ./setup-builder.sh --help 참고).

  Debian 12·Rocky 9·10 AMD64 는 대상과 같은 릴리스의 전용 VM 에 설치합니다.
  커널을 생략하면 같은 릴리스의 식별된 등록 호스트 커널을 준비합니다. 등록된 track 은 빌드 ID 까지 대조합니다.
  setup-native-builder.sh 에는 -- 뒤에 --jobs N, --no-start 를 줄 수 있습니다.
  기존 /etc/kpctl/native-builder/worker.json 과 토큰은 -reset-config 를 줄 때 갱신합니다.

  빌드 서비스 실행 계정은 -build-user 로 고릅니다 (기본 kpbuild, 재설치 때는 기존 계정 유지).
  SSH 로 접속할 계정은 -ssh-user (또는 user@호스트) 입니다.

  호스트에 이미 /etc/kpctl/builder.json 이 있으면 그 설정을 유지합니다 (새로 만들려면 -reset-config).
  SSH 키가 아직 없다면 먼저 kpctl ssh-key copy <호스트> 또는 kpctl ssh-key add.

  예) kpctl install-builder -check build-noble                       점검만
      kpctl install-builder build-noble                               등록 호스트 기준 커널 자동 선택
      kpctl install-builder build-jammy 5.15.0-160-generic -- --memory-mib 16384
      kpctl install-builder build-rocky10 6.12.0-264.21.1.el10_3.x86_64 -- --jobs 4
      kpctl install-builder -stop-running build-noble                 실행 중인 빌더 업그레이드
      kpctl install-builder -ssh-user ubuntu -build-user builder build-noble   접속·실행 계정 지정

옵션:`

var buildUserName = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

var kernelArg = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+-[0-9]+-[A-Za-z0-9_-]+$`)

// nativeBuilderHint 는 빌드할 수 없는 배포판 커널을 받았을 때의 안내입니다.
const nativeBuilderHint = "Debian/Rocky 커널은 대상과 같은 배포판·릴리스의 전용 VM 에 kpctl install-builder 로 네이티브 빌더를 설치해 빌드합니다. " +
	"지원: Debian 12, Rocky 9·10 AMD64 (docs/operations/distribution-kernels.md)"

// nativeKernelProblem 은 네이티브 빌더로도 빌드할 수 없는 배포판 커널이면 이유를 돌려줍니다.
// Ubuntu 모양이거나 빌드할 수 있는 Debian 12·Rocky 9·10 커널이면 "".
func nativeKernelProblem(k string) string {
	if !model.IsDistributionKernelName(k) {
		return ""
	}
	d, r := model.DistributionForABI(k)
	if d == "" {
		return fmt.Sprintf("%s 는 지원하지 않는 배포판 커널입니다 (Debian 12·13, Rocky 9·10 AMD64 지원 프로필에 없음)", k)
	}
	if ok, reason := model.NativeBuilderRelease(d, r); !ok {
		return fmt.Sprintf("%s 는 %s %s 커널이라 빌드할 수 없습니다: %s", k, model.DistroLabel(d), r, reason)
	}
	return ""
}

// registeredNativeKernels 는 컨트롤러 등록 호스트 중 식별이 끝난(track 이 있는) 빌드 가능한 Debian/Rocky 커널입니다 (track 순, 중복 제거).
func registeredNativeKernels(st *model.StatusResponse) []model.DistributionKernel {
	seen := map[string]bool{}
	var out []model.DistributionKernel
	for _, h := range st.Hosts {
		d := h.Status.Distribution
		if d == nil || h.Status.TrackKey() == "" || seen[h.Status.TrackKey()] {
			continue
		}
		if ok, _ := model.NativeBuilderRelease(d.Distro, d.Release); !ok {
			continue
		}
		seen[h.Status.TrackKey()] = true
		out = append(out, *d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Track() < out[j].Track() })
	return out
}

// nativeTargetsFor 는 네이티브 빌더 호스트(distro, release) 하나의 대상 커널입니다.
// 커널을 지정했으면 그중 같은 릴리스의 것만, 아니면 같은 릴리스의 등록 호스트 커널 전부입니다.
// 등록 호스트와 ABI 가 같은 커널은 그 track(빌드 ID 포함)을 붙여, 원격 prepare 영수증과 정확히 대조하게 합니다.
// 같은 ABI 의 track 이 여럿이면(패키지 재빌드) 모두 대상으로 넣습니다.
func nativeTargetsFor(kernels []string, registered []model.DistributionKernel, distro, release string) []remote.NativeTarget {
	var out []remote.NativeTarget
	add := func(abi string) {
		matched := false
		for _, k := range registered {
			if k.ABI == abi && k.Distro == distro && k.Release == release {
				out = append(out, remote.NativeTarget{ABI: abi, Track: k.Track()})
				matched = true
			}
		}
		if !matched {
			out = append(out, remote.NativeTarget{ABI: abi})
		}
	}
	if len(kernels) > 0 {
		for _, k := range kernels {
			if d, r := model.DistributionForABI(k); d == distro && r == release {
				add(k)
			}
		}
		return out
	}
	var abis []string
	for _, k := range registered {
		if k.Distro == distro && k.Release == release {
			abis = append(abis, k.ABI)
		}
	}
	for _, abi := range unique(abis) {
		add(abi)
	}
	return out
}

// nativeWorkerConfig 는 원격 /etc/kpctl/native-builder/worker.json 입니다 (토큰은 token_file 로 따로).
// builder 는 컨트롤러에 보고할 빌더 이름입니다 (hostname).
func nativeWorkerConfig(ctrlURL, caFile, builder string) ([]byte, error) {
	cfg := map[string]string{"controller_url": ctrlURL, "token_file": "/etc/kpctl/native-builder/token", "builder": builder}
	if caFile != "" {
		cfg["ca_file"] = "/etc/kpctl/tls/ca.crt"
	}
	return json.MarshalIndent(cfg, "", "  ")
}

// nativeProofHint 는 설치 후 운영자가 할 일입니다. 승인 핀은 빌더와 독립된 환경에서 만들어 넣어야 합니다.
func nativeProofHint(targets []remote.NativeTarget) string {
	var hint strings.Builder
	for _, t := range targets {
		if t.Track == "" {
			fmt.Fprintf(&hint, "\n  %s: 빌더의 /var/lib/kpctl-native/tracks/ 아래 base-proof.json 에서 track 을 확인하세요.", t.ABI)
		} else {
			fmt.Fprintf(&hint, "\n  %s", t.Track)
		}
	}
	hint.WriteString("\n  독립된 신뢰 환경에 같은 공식 Git 과 키를 준비하고, 빌더의 /var/lib/kpctl-native/tracks/<track>/base.json 과 같은 계획으로 다시 검증하세요.")
	hint.WriteString("\n  mkdir -p cache work && python3 /opt/kpctl/native-builder/kpctl-native-builder.py prepare --plan base.json --cache cache --work-dir work --fetch > base-proof.json")
	hint.WriteString("\n  영수증의 track 과 대상 kpctl-agent -identify 출력을 대조한 뒤 영수증을 컨트롤러 data_dir/distribution-proofs/<track>.json 에 설치하세요.")
	hint.WriteString("\n  검토한 수정의 fixed-proof와 candidate-proof를 같은 컨트롤러에 설치하면 빌더 타이머가 collect, 시험 컴파일과 누적 빌드를 자동 실행합니다 (docs/operations/distribution-kernels.md).")
	return hint.String()
}

// kernelFlavor 는 커널 이름(uname -r)으로 그 커널을 빌드할 빌더 묶음 종류를 고릅니다.
// 6.1.0-57-amd64 처럼 Debian 모양이면 debian, ….el9_9.x86_64 처럼 RHEL 계열이면 rocky, 그 밖의 Ubuntu 모양이면 ubuntu.
// 커널 이름이 아니면 "".
func kernelFlavor(k string) string {
	if d, _ := model.DistributionForABI(k); d != "" {
		return d
	}
	if model.IsDistributionKernelName(k) {
		if rhelKernel.MatchString(k) {
			return remote.FlavorRocky
		}
		return remote.FlavorDebian
	}
	if kernelArg.MatchString(k) {
		return remote.FlavorUbuntu
	}
	return ""
}

var rhelKernel = regexp.MustCompile(`\.el[0-9]+`)

// kernelsByFlavor 는 대상 커널을 빌더 종류별로 나눕니다 (종류 순서는 remote.BuilderFlavors).
func kernelsByFlavor(kernels []string) map[string][]string {
	out := map[string][]string{}
	for _, k := range kernels {
		f := kernelFlavor(k)
		out[f] = append(out[f], k)
	}
	return out
}

// flavorSummary 는 "Ubuntu 빌더: 6.8.0-136-generic · Rocky 빌더: 6.12.0-…" 처럼 커널 이름으로 고른 빌더 안내입니다.
func flavorSummary(kernels []string) string {
	by := kernelsByFlavor(kernels)
	var parts []string
	for _, f := range remote.BuilderFlavors {
		if len(by[f]) > 0 {
			parts = append(parts, fmt.Sprintf("%s 빌더 %s", model.DistroLabel(f), strings.Join(by[f], " ")))
		}
	}
	return strings.Join(parts, " · ")
}

// flavorMismatch 는 지정한 커널이 모두 이 호스트와 다른 배포판 빌더용일 때의 문제 설명입니다. 하나라도 같은 종류면 "".
func flavorMismatch(kernels []string, flavor, osLabel string) string {
	if len(kernels) == 0 || len(kernelsByFlavor(kernels)[flavor]) > 0 {
		return ""
	}
	return fmt.Sprintf("지정한 커널은 %s 용인데 이 호스트는 %s 입니다. 빌더는 대상 커널과 같은 배포판에 설치합니다 (커널에 맞는 빌드 서버를 지정하세요)",
		flavorSummary(kernels), osLabel)
}

// isKernelArg 는 위치 인자가 호스트가 아니라 커널 이름(uname -r)인지 봅니다. Debian/Rocky 모양도 커널로 봅니다.
func isKernelArg(a string) bool {
	return kernelArg.MatchString(a) || model.IsDistributionKernelName(a)
}

// setup-builder.sh 옵션 중 kpctl install-builder 가 직접 정하는 것
var managedSetupArgs = map[string]string{
	"--target": "대상 커널 위치 인자", "--worker": "-reset-config", "--token-file": "-builder-token-file",
	"--config": "-reset-config / 기존 builder.json", "--ca-file": "-ca", "--plan": "-check", "--user": "-build-user", "--help": "", "-h": "",
}

// defaultBuilderBundleDir: KPCTL_BUILDER_BUNDLE → kpctl 실행 파일 옆 builder/ → /usr/local/share/kpctl/builder
// 묶음 디렉터리 아래에 배포판별 전용 묶음 ubuntu/, debian/, rocky/ 가 있습니다.
func defaultBuilderBundleDir() string {
	if d := os.Getenv("KPCTL_BUILDER_BUNDLE"); d != "" {
		return d
	}
	if exe, err := os.Executable(); err == nil {
		d := filepath.Join(filepath.Dir(exe), "builder")
		for _, f := range remote.BuilderFlavors {
			if _, err := os.Stat(filepath.Join(d, f, "builder-flavor")); err == nil {
				return d
			}
		}
	}
	return "/usr/local/share/kpctl/builder"
}

// splitBuilderArgs 는 위치 인자를 호스트, 대상 커널, "--" 뒤 setup-builder.sh 옵션으로 나눕니다.
// Debian/Rocky 커널을 호스트로 오인해 SSH 로 접속하지 않습니다. 빌드할 수 없는 배포판 커널(Debian 13, Rocky 8 등)은
// 접속 전에 이유와 함께 거부합니다.
func splitBuilderArgs(args []string) (hosts, kernels, setup []string, err error) {
	var native []string
	for i, a := range args {
		if a == "--" {
			setup = append(setup, args[i+1:]...)
			break
		}
		switch {
		case nativeKernelProblem(a) != "":
			native = append(native, nativeKernelProblem(a))
		case isKernelArg(a): // Ubuntu 커널, 또는 네이티브 빌더로 빌드할 Debian 12·Rocky 9·10 커널
			kernels = append(kernels, a)
		case strings.HasPrefix(a, "-"):
			return nil, nil, nil, fmt.Errorf("%q 가 옵션처럼 보입니다. kpctl 옵션은 호스트 앞에, setup-builder.sh 옵션은 -- 뒤에 쓰세요", a)
		default:
			hosts = append(hosts, a)
		}
	}
	if len(native) > 0 {
		return nil, nil, nil, fmt.Errorf("%s.\n%s", strings.Join(unique(native), ".\n"), nativeBuilderHint)
	}
	for _, a := range setup {
		if hint, ok := managedSetupArgs[a]; ok {
			if hint != "" {
				hint = " (대신 " + hint + ")"
			}
			return nil, nil, nil, fmt.Errorf("setup-builder.sh 옵션 %s 는 kpctl install-builder 가 정합니다%s", a, hint)
		}
	}
	return hosts, unique(kernels), setup, nil
}

func hasArg(args []string, name string) bool {
	for _, a := range args {
		if a == name {
			return true
		}
	}
	return false
}

// kernelsForSeries 는 커널 목록에서 codename 시리즈의 것만 고릅니다. GA generic 이 아닌 Ubuntu 커널(시리즈 판정 불가)은
// 그대로 두고, Debian/Rocky 커널은 Ubuntu 빌더 대상이 아니므로 뺍니다.
func kernelsForSeries(kernels []string, codename string) []string {
	var out []string
	for _, k := range kernels {
		if model.IsDistributionKernelName(k) {
			continue
		}
		if lts := model.LTSForKernel(k); lts == nil || lts.Codename == codename {
			out = append(out, k)
		}
	}
	return out
}

// kernelShape 는 안내문에 쓸 그 시리즈 GA generic 커널 이름 모양입니다. 예: jammy → "5.15.0-번호-generic".
func kernelShape(codename string) string {
	if lts := model.LTSByCodename(codename); lts != nil {
		return lts.Kernel + "-번호-generic"
	}
	return "X.Y.Z-번호-generic"
}

// exampleKernels 는 셸에 그대로 붙여 넣을 수 있는 시리즈별 커널 예입니다 (사용법의 예와 같은 값).
var exampleKernels = map[string]string{"jammy": "5.15.0-160-generic", "noble": "6.8.0-136-generic"}

// exampleKernel 은 안내문에 쓸 그 시리즈의 커널 이름 예입니다. 예가 없는 시리즈면 noble 예.
func exampleKernel(codename string) string {
	if k, ok := exampleKernels[codename]; ok {
		return k
	}
	return exampleKernels["noble"]
}

// registeredKernels 는 컨트롤러에 등록된 호스트들이 실행 중인 커널 목록입니다 (정렬, 중복 제거).
func registeredKernels(st *model.StatusResponse) []string {
	var out []string
	for _, h := range st.Hosts {
		if h.Status.Kernel != "" && model.LTSForKernel(h.Status.Kernel) != nil {
			out = append(out, h.Status.Kernel)
		}
	}
	out = unique(out)
	sort.Strings(out)
	return out
}

// builderConfig 는 묶음의 builder.example.json 을 바탕으로 이 컨트롤러에 접속하는 설정을 만듭니다.
// series·git_root·jobs·sandbox 는 setup-builder.sh 가 호스트에 맞춰 채웁니다.
func builderConfig(bundle *remote.Bundle, ctrlURL, token, caFile string) ([]byte, error) {
	data, err := os.ReadFile(bundle.Path("builder.example.json"))
	if err != nil {
		return nil, err
	}
	cfg := map[string]any{}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("builder.example.json: %w", err)
	}
	cfg["controller_url"] = ctrlURL
	cfg["token"] = token
	if caFile != "" {
		cfg["ca_file"] = "/etc/kpctl/tls/ca.crt"
	} else {
		delete(cfg, "ca_file")
	}
	cfg["series"] = "" // setup-builder.sh 가 호스트 시리즈로 채움
	return json.MarshalIndent(cfg, "", "  ")
}

func cmdInstallBuilder(c *client.Client, args []string) error {
	if wantsWizard(args) { // 터미널에서 인자 없이 실행 → 질문형 (wizard.go)
		return builderWizard(c)
	}
	_, err := runBuilderInstall(c, args)
	return err
}

func runBuilderInstall(c *client.Client, args []string) ([]hostResult, error) {
	fs := flag.NewFlagSet("install-builder", flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprintln(os.Stderr, installBuilderUsage); fs.PrintDefaults() }
	r := addRemoteFlags(fs)
	fs.Lookup("bundle").Usage = "빌더 설치 묶음 디렉터리 (ubuntu/·debian/·rocky/ 가 든 dist/builder 전체; 기본: kpctl 옆 builder/ 또는 /usr/local/share/kpctl/builder)"
	fs.Lookup("bundle").DefValue = defaultBuilderBundleDir()
	r.bundleDir = defaultBuilderBundleDir()
	tokenDir := os.Getenv("KPCTL_TOKEN_DIR")
	if tokenDir == "" {
		tokenDir = "/etc/kpctl/tokens"
	}
	tokenFile := fs.String("builder-token-file", filepath.Join(tokenDir, "builder.token"), "빌더 토큰 파일 (컨트롤러 builder_token 과 같은 값)")
	ctrlURL := fs.String("controller-url", os.Getenv("KPCTL_URL"), "빌드 서버가 접속할 컨트롤러 주소 (기본: KPCTL_URL)")
	caFile := fs.String("ca", os.Getenv("KPCTL_CA"), "CA 인증서 파일 → 빌드 서버의 /etc/kpctl/tls/ca.crt (기본: KPCTL_CA)")
	checkOnly := fs.Bool("check", false, "사전 점검만 하고 아무것도 바꾸지 않음")
	force := fs.Bool("force", false, "점검에서 문제가 나와도 설치 진행 (원인을 알 때만)")
	stopRunning := fs.Bool("stop-running", false, "실행 중인 kpctl-builder 를 멈추고 다시 설치 (진행 중인 빌드는 실패)")
	resetConfig := fs.Bool("reset-config", false, "호스트에 있는 builder.json 을 버리고 이 컨트롤러 기준으로 새로 만듦")
	buildUser := fs.String("build-user", "", "빌드 서비스 실행 계정 (비우면 kpbuild, 재설치 때는 기존 서비스 계정). 없으면 만듭니다")
	timeout := fs.Duration("timeout", 4*time.Hour, "설치 명령 하나의 최대 시간 (커널 git clone·이미지 준비 포함)")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if r.fromDHCP {
		return nil, fmt.Errorf("install-builder 에는 -from-dhcp 를 쓸 수 없습니다 (빌드 서버를 직접 지정하세요)")
	}
	hosts, kernels, setupArgs, err := splitBuilderArgs(fs.Args())
	if err != nil {
		return nil, err
	}
	if r.hostsFile != "" {
		fromFile, err := readHostsFile(r.hostsFile)
		if err != nil {
			return nil, err
		}
		hosts = append(hosts, fromFile...)
	}
	hosts = unique(hosts)
	if *buildUser != "" {
		if !buildUserName.MatchString(*buildUser) || *buildUser == "root" {
			return nil, fmt.Errorf("잘못된 빌드 계정 %q (소문자·숫자·_·- 32자 이내, root 불가)", *buildUser)
		}
		setupArgs = append([]string{"--user", *buildUser}, setupArgs...)
	}
	if len(hosts) == 0 {
		return nil, fmt.Errorf("빌드 서버 호스트를 주세요 (kpctl install-builder -h)")
	}
	if r.parallel < 1 {
		r.parallel = 1
	}
	if err := r.build(); err != nil {
		return nil, err
	}
	if err := checkReadable(r.ssh.KeyFile, "SSH 키"); err != nil {
		return nil, err
	}
	r.ssh.Timeout = *timeout
	bundles, err := remote.OpenBuilderBundle(r.bundleDir)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(r.logDir, 0o700); err != nil {
		return nil, err
	}
	if *ctrlURL == "" {
		return nil, fmt.Errorf("-controller-url 이 필요합니다 (기본값 KPCTL_URL 이 비어 있음)")
	}

	var config []byte
	token := ""
	if !*checkOnly {
		if err := checkReadable(*tokenFile, "빌더 토큰"); err != nil {
			return nil, err
		}
		data, err := os.ReadFile(*tokenFile)
		if err != nil {
			return nil, err
		}
		token = strings.TrimSpace(string(data))
		if len(token) < 16 {
			return nil, fmt.Errorf("빌더 토큰이 너무 짧습니다 (%s)", *tokenFile)
		}
		if ub, err := bundles.Flavor(remote.FlavorUbuntu); err == nil { // Ubuntu 묶음이 없으면 Ubuntu 호스트에서 Flavor 가 거부
			if config, err = builderConfig(ub, *ctrlURL, token, *caFile); err != nil {
				return nil, err
			}
		}
	}

	hostMode := hasArg(setupArgs, "--host-mode")
	noStart := hasArg(setupArgs, "--no-start")
	var registered []string
	var registeredNative []model.DistributionKernel
	anyNative := false
	for _, k := range kernels {
		anyNative = anyNative || model.IsDistributionKernelName(k)
	}
	if len(kernels) == 0 && !hostMode || anyNative {
		// 커널을 생략했으면 등록 호스트에서 고르고, Debian/Rocky 커널을 지정했으면 등록 호스트의 track(빌드 ID)과 대조합니다
		var st model.StatusResponse
		if err := c.Do("GET", "/api/status", nil, &st); err != nil {
			if !anyNative {
				return nil, fmt.Errorf("대상 커널을 고르려고 컨트롤러 상태를 읽지 못했습니다 (커널을 직접 지정하세요): %w", err)
			}
			return nil, fmt.Errorf("등록 호스트의 track 을 대조하려고 컨트롤러 상태를 읽지 못했습니다: %w", err)
		} else {
			registered = registeredKernels(&st)
			registeredNative = registeredNativeKernels(&st)
		}
	}
	series := make([]string, 0, len(model.SupportedLTS))
	for _, l := range model.SupportedLTS {
		series = append(series, l.Codename)
	}

	mode := "설치"
	if *checkOnly {
		mode = "점검"
	}
	fmt.Printf("빌드 서버 %d대 %s 시작 (동시 %d대, 빌더 %s, 묶음 %s, 컨트롤러 %s)\n", len(hosts), mode, r.parallel, bundles.Arch, strings.Join(bundles.Flavors(), "·"), *ctrlURL)
	if len(kernels) > 0 {
		fmt.Printf("대상 커널 이름으로 고른 빌더: %s\n", flavorSummary(kernels))
	}
	fmt.Println()
	var assignedMu sync.Mutex
	assigned := map[string]bool{} // 어느 호스트의 대상이 된 지정 커널
	assign := func(ks ...string) {
		assignedMu.Lock()
		defer assignedMu.Unlock()
		for _, k := range ks {
			assigned[k] = true
		}
	}

	results := runAll(hosts, r.parallel, func(target string) (res hostResult) {
		s := &remote.Session{SSH: r.loginFor(target), Target: target, OnStep: progress}
		defer func() { res.logFile = saveLog(r.logDir, target, "install-builder", s) }()

		// 1) 점검
		problems, warnings, err := s.Preflight(remote.PreflightOptions{
			ForBuilder: true, Arch: bundles.Arch, ControllerURL: *ctrlURL, Series: series,
			StopBuilder: *stopRunning, AllowWithAgent: *force,
		})
		res.hostname = s.Facts.Hostname
		if err != nil {
			return hostResult{result: "접속 실패", note: err.Error()}
		}

		// 빌더 종류: 호스트 OS(os-release) 기준. 실행 중인 커널 이름이 다른 배포판 모양이면 알려 주고,
		// 지정한 대상 커널이 모두 다른 배포판용이거나 그 종류 전용 묶음이 없으면 -force 로도 설치하지 않습니다
		// (빌더는 대상과 같은 배포판에서 빌드하며, 다른 배포판 묶음을 대신 보내지 않습니다).
		flavor := s.Facts.BuilderFlavor()
		var bundle *remote.Bundle
		if flavor != "" {
			if kf := kernelFlavor(s.Facts.Kernel); kf != "" && kf != flavor {
				warnings = append(warnings, fmt.Sprintf("호스트 OS 는 %s 인데 실행 중인 커널 %s 는 %s 커널 이름입니다. OS 기준으로 %s 빌더를 설치합니다",
					s.Facts.OSLabel(), s.Facts.Kernel, model.DistroLabel(kf), model.DistroLabel(flavor)))
			}
			hard := false
			if m := flavorMismatch(kernels, flavor, s.Facts.OSLabel()); m != "" {
				problems, hard = append(problems, m), true
			}
			if bundle, err = bundles.Flavor(flavor); err != nil {
				problems, hard = append(problems, err.Error()), true
			}
			if hard {
				for _, w := range warnings {
					progress(target, "경고: "+w)
				}
				res.result, res.note = "점검 실패", strings.Join(problems, "\n")
				return res
			}
		}

		if s.Facts.IsNativeBuilderOS() {
			return installNativeOnHost(c, s, nativeRun{
				target: target, problems: problems, warnings: warnings, kernels: kernels, registered: registeredNative,
				hostMode: hostMode, noStart: noStart, checkOnly: *checkOnly, force: *force, stopRunning: *stopRunning,
				resetConfig: *resetConfig, ctrlURL: *ctrlURL, caFile: *caFile, token: token, setupArgs: setupArgs, bundle: bundle,
				assign: assign,
			}, res)
		}

		// 대상 커널: 지정한 것 중 이 시리즈 → 없으면 등록 호스트 중 이 시리즈
		hostKernels := kernelsForSeries(kernels, s.Facts.Codename)
		if len(kernels) == 0 {
			hostKernels = kernelsForSeries(registered, s.Facts.Codename)
		}
		// Ubuntu 가 아닌 빌드 서버는 Preflight 가 이미 문제로 보고하므로 (빈 시리즈로) 커널 문제를 덧붙이지 않습니다.
		if !hostMode && len(hostKernels) == 0 && s.Facts.Distro == "ubuntu" {
			if len(kernels) > 0 {
				problems = append(problems, fmt.Sprintf("지정한 커널 중 %s 시리즈 커널이 없습니다", s.Facts.Codename))
			} else {
				problems = append(problems, fmt.Sprintf("컨트롤러에 %s 커널을 쓰는 등록 호스트가 없어 대상 커널을 고르지 못했습니다. 대상 호스트의 uname -r 값(%s 모양)을 직접 지정하세요 (예: kpctl install-builder %s %s)", s.Facts.Codename, kernelShape(s.Facts.Codename), target, exampleKernel(s.Facts.Codename)))
			}
		}
		keepConfig := s.Facts.BuilderConfig == "yes" && !*resetConfig
		if keepConfig {
			warnings = append(warnings, "기존 /etc/kpctl/builder.json 을 유지합니다 (토큰·주소를 새로 쓰려면 -reset-config)")
		}
		for _, w := range warnings {
			progress(target, "경고: "+w)
		}
		// Ubuntu 도 Debian/Rocky 도 아닌 빌드 서버는 -force 로도 진행하지 않습니다. setup-builder.sh 가 어차피 거부하며,
		// 그 전에 빌더 토큰이 담긴 builder.json 을 보내거나 (-stop-running 이면) 기존 서비스를 멈추게 됩니다.
		if len(problems) > 0 && (*checkOnly || !*force || s.Facts.Distro != "ubuntu") {
			res.result, res.note = "점검 실패", strings.Join(problems, "\n")
			return res
		}
		assign(hostKernels...)
		if *checkOnly {
			res.ok, res.result = true, "점검 통과"
			res.note = fmt.Sprintf("%s %s, Ubuntu 빌더, 커널 %s", s.Facts.Codename, s.Facts.Arch, strings.Join(hostKernels, " "))
			return res
		}

		// 2) 설치
		opts := remote.BuilderInstallOptions{
			ControllerURL: *ctrlURL, CAFile: *caFile, Kernels: hostKernels,
			SetupArgs: setupArgs, StopRunning: *stopRunning,
		}
		if !keepConfig {
			opts.Config = config
		}
		if err := s.InstallBuilder(bundle, opts); err != nil {
			res.result, res.note = "설치 실패", err.Error()
			return res
		}
		if noStart {
			res.ok, res.result = true, "설치 완료"
			res.note = "서비스 시작 안 함 (--no-start): systemctl enable --now kpctl-builder"
			return res
		}

		// 3) 컨트롤러에 빌더가 보고하는지 확인
		progress(target, "컨트롤러에 빌더 보고 확인")
		b, err := waitBuilder(c, res.hostname, "kpctl-builder", 2*time.Minute)
		if err != nil {
			res.result, res.note = "보고 미확인", err.Error()
			return res
		}
		res.ok, res.result = true, "설치 완료"
		res.note = fmt.Sprintf("%s, Ubuntu 빌더, 시리즈 %s, 커널 %s", b.Name, b.Series, strings.Join(b.Kernels, " "))
		return res
	})
	// 지정했지만 어느 호스트의 대상도 되지 못한 커널 (예: Rocky 커널을 Ubuntu 빌드 서버에만 지정)
	for _, k := range kernels {
		if !assigned[k] {
			fmt.Printf("경고: 대상 커널 %s (%s 빌더용) 을 맡은 빌드 서버가 없습니다. 같은 배포판·릴리스의 빌드 서버를 지정하세요\n", k, model.DistroLabel(kernelFlavor(k)))
		}
	}
	return results, printResults(results, r.logDir)
}

// waitBuilder 는 빌드 서버가 컨트롤러에 최근 작업 확인(보고)을 했는지 기다립니다.
// 빌더 이름은 builder.json 의 name, 비우면 hostname 입니다.
func waitBuilder(c *client.Client, name, service string, timeout time.Duration) (*model.BuilderInfo, error) {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for {
		var st model.StatusResponse
		if err := c.Do("GET", "/api/status", nil, &st); err != nil {
			lastErr = err
		} else if b := st.Builders[name]; b != nil && st.Now.Sub(b.LastSeen) < 2*time.Minute {
			return b, nil
		} else {
			lastErr = fmt.Errorf("컨트롤러에 빌더 %s 의 최근 보고가 없습니다 (빌드 서버에서 journalctl -u %s 확인. 빌더 이름을 따로 줬다면 웹의 빌드 서버 목록 확인)", name, service)
		}
		if time.Now().After(deadline) {
			return nil, lastErr
		}
		time.Sleep(3 * time.Second)
	}
}

// nativeRun 은 호스트 한 대의 네이티브 빌더 설치에 필요한 runBuilderInstall 의 값입니다.
type nativeRun struct {
	target             string
	problems, warnings []string
	kernels            []string
	registered         []model.DistributionKernel
	hostMode, noStart  bool
	checkOnly, force   bool
	stopRunning        bool
	resetConfig        bool
	ctrlURL, caFile    string
	token              string
	setupArgs          []string
	bundle             *remote.Bundle       // 이 호스트 배포판 전용 묶음 (dist/builder/debian 또는 rocky)
	assign             func(abis ...string) // 대상이 된 지정 커널 기록 (nil 이면 기록 안 함)
}

// nativeSetupArgs 는 setup-native-builder.sh 가 받는 "--" 뒤 옵션입니다 (나머지는 Ubuntu setup-builder.sh 전용).
var nativeSetupArgs = map[string]bool{"--jobs": true, "--no-start": true, "--user": true}

// installNativeOnHost 는 Preflight 가 끝난 Debian/Rocky 호스트에 네이티브 빌더를 점검·설치합니다.
// -force 는 일반 점검 문제만 넘기고, NativeBuilderHardBlock(지원 릴리스·컨테이너·에이전트 호스트)은 넘기지 않습니다.
func installNativeOnHost(c *client.Client, s *remote.Session, n nativeRun, res hostResult) hostResult {
	problems, warnings := n.problems, n.warnings
	distro, release := s.Facts.Distro, s.Facts.NativeRelease()
	targets := nativeTargetsFor(n.kernels, n.registered, distro, release)
	if n.hostMode {
		problems = append(problems, "--host-mode 는 Ubuntu 빌더 전용입니다 (네이티브 빌더는 항상 호스트의 배포판 패키지로 빌드)")
	}
	for i := 0; i < len(n.setupArgs); i++ {
		a := n.setupArgs[i]
		if !nativeSetupArgs[a] {
			problems = append(problems, fmt.Sprintf("setup-native-builder.sh 는 %s 옵션을 받지 않습니다 (가능: --jobs N, --no-start, -build-user)", a))
		} else if a == "--jobs" || a == "--user" {
			i++ // 값
		}
	}
	if len(targets) == 0 {
		if len(n.kernels) > 0 {
			problems = append(problems, fmt.Sprintf("지정한 커널 중 %s %s 커널이 없습니다", model.DistroLabel(distro), release))
		} else {
			problems = append(problems, fmt.Sprintf("컨트롤러에 %s %s 커널을 쓰는 식별된 등록 호스트가 없어 대상 커널을 고르지 못했습니다. 대상 호스트의 uname -r 값을 직접 지정하세요 (예: kpctl install-builder %s %s)",
				model.DistroLabel(distro), release, n.target, nativeExampleKernel(distro, release)))
		}
	}
	for _, t := range targets {
		if t.Track == "" {
			warnings = append(warnings, fmt.Sprintf("%s 를 쓰는 식별된 등록 호스트가 없어 빌드 ID 대조 없이 준비합니다 (호스트 등록 후 다시 설치하면 대조)", t.ABI))
		}
	}
	keepConfig := s.Facts.NativeBuilderConfig == "yes" && !n.resetConfig
	if keepConfig {
		warnings = append(warnings, "기존 /etc/kpctl/native-builder/worker.json·토큰을 유지합니다 (새로 쓰려면 -reset-config)")
	}
	for _, w := range warnings {
		progress(n.target, "경고: "+w)
	}
	hard := remote.NativeBuilderHardBlock(s.Facts)
	if len(problems) > 0 && (n.checkOnly || !n.force || hard != "") {
		res.result, res.note = "점검 실패", strings.Join(problems, "\n")
		return res
	}
	var labels []string
	for _, t := range targets {
		labels = append(labels, t.ABI)
	}
	if n.assign != nil {
		n.assign(labels...)
	}
	if n.checkOnly {
		res.ok, res.result = true, "점검 통과"
		res.note = fmt.Sprintf("%s 네이티브 빌더, 커널 %s", s.Facts.OSLabel(), strings.Join(labels, " "))
		return res
	}

	opts := remote.NativeBuilderInstallOptions{
		ControllerURL: n.ctrlURL, CAFile: n.caFile, Targets: targets, SetupArgs: n.setupArgs, StopRunning: n.stopRunning,
	}
	if !keepConfig {
		worker, err := nativeWorkerConfig(n.ctrlURL, n.caFile, s.Facts.Hostname)
		if err != nil {
			res.result, res.note = "설치 실패", err.Error()
			return res
		}
		opts.Worker, opts.Token = worker, n.token
	}
	if err := s.InstallNativeBuilder(n.bundle, opts); err != nil {
		res.result, res.note = "설치 실패", err.Error()
		return res
	}
	hint := "컨트롤러 승인 핀과 수정 후보 준비" + nativeProofHint(targets)
	progress(n.target, hint)
	fmt.Fprintln(&s.Log, hint)
	if n.noStart {
		res.ok, res.result = true, "설치 완료"
		res.note = "서비스 시작 안 함 (--no-start): systemctl enable --now kpctl-native-builder.timer"
		return res
	}
	progress(n.target, "컨트롤러에 빌더 보고 확인")
	b, err := waitBuilder(c, res.hostname, "kpctl-native-builder", 3*time.Minute)
	if err != nil {
		res.result, res.note = "보고 미확인", err.Error()
		return res
	}
	res.ok, res.result = true, "설치 완료"
	res.note = fmt.Sprintf("%s, %s 네이티브 빌더, 커널 %s", b.Name, s.Facts.OSLabel(), strings.Join(labels, " "))
	return res
}

// nativeExampleKernel 은 안내문에 쓸 그 릴리스의 커널 이름 예입니다 (docs/operations/distribution-kernels.md 표의 값).
func nativeExampleKernel(distro, release string) string {
	switch distro + release {
	case "debian12":
		return "6.1.0-57-amd64"
	case "rocky9":
		return "5.14.0-741.27.1.el9_9.x86_64"
	}
	return "6.12.0-264.21.1.el10_3.x86_64"
}
