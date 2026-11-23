// 이 파일: kpctl install-builder — SSH 로 빌드 서버를 한 번에 설치
//
// kpctl install 의 빌더판입니다. 점검 → dist/builder 묶음 복사 → builder.json(컨트롤러 주소·빌더 토큰·CA) 작성 →
// setup-builder.sh 실행 → 컨트롤러에 빌더가 보고하는지 확인까지 합니다.
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
	"time"

	"kpctl/internal/client"
	"kpctl/internal/model"
	"kpctl/internal/remote"
)

const installBuilderUsage = `사용법: kpctl install-builder [옵션] <호스트...> [대상 커널...] [-- setup-builder.sh 옵션]
        kpctl install-builder                         (터미널에서 인자 없이: 질문형 설치)

  SSH 로 빌드 서버를 한 번에 설치합니다: 점검 → 묶음 복사 → builder.json 작성(컨트롤러 주소·빌더 토큰·CA)
  → setup-builder.sh 실행 → 컨트롤러에 빌더가 보고하는지 확인. 옵션은 호스트 이름보다 앞에 써야 합니다.

  대상 커널(예: 6.8.0-136-generic)을 생략하면, 컨트롤러에 등록된 호스트 중 빌드 서버와 같은
  Ubuntu 시리즈의 GA 커널을 자동으로 고릅니다. 커널 인자는 호스트별로 같은 시리즈인 것만 넘깁니다.
  "--" 뒤의 값은 setup-builder.sh 에 그대로 넘깁니다 (--memory-mib, --jobs, --cache-gib, --no-cache,
  --host-mode, --no-start 등; sudo ./setup-builder.sh --help 참고).

  빌드 서비스 실행 계정은 -build-user 로 고릅니다 (기본 kpbuild, 재설치 때는 기존 계정 유지).
  SSH 로 접속할 계정은 -ssh-user (또는 user@호스트) 입니다.

  호스트에 이미 /etc/kpctl/builder.json 이 있으면 그 설정을 유지합니다 (새로 만들려면 -reset-config).
  SSH 키가 아직 없다면 먼저 kpctl ssh-key copy <호스트> 또는 kpctl ssh-key add.

  예) kpctl install-builder -check build-noble                       점검만
      kpctl install-builder build-noble                               등록 호스트 기준 커널 자동 선택
      kpctl install-builder build-jammy 5.15.0-160-generic -- --memory-mib 16384
      kpctl install-builder -stop-running build-noble                 실행 중인 빌더 업그레이드
      kpctl install-builder -ssh-user ubuntu -build-user builder build-noble   접속·실행 계정 지정

옵션:`

var buildUserName = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

var kernelArg = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+-[0-9]+-[A-Za-z0-9_-]+$`)

// setup-builder.sh 옵션 중 kpctl install-builder 가 직접 정하는 것
var managedSetupArgs = map[string]string{
	"--config": "-reset-config / 기존 builder.json", "--ca-file": "-ca", "--plan": "-check", "--user": "-build-user", "--help": "", "-h": "",
}

// defaultBuilderBundleDir: KPCTL_BUILDER_BUNDLE → kpctl 실행 파일 옆 builder/ → /usr/local/share/kpctl/builder
func defaultBuilderBundleDir() string {
	if d := os.Getenv("KPCTL_BUILDER_BUNDLE"); d != "" {
		return d
	}
	if exe, err := os.Executable(); err == nil {
		d := filepath.Join(filepath.Dir(exe), "builder")
		if _, err := os.Stat(filepath.Join(d, "setup-builder.sh")); err == nil {
			return d
		}
	}
	return "/usr/local/share/kpctl/builder"
}

// splitBuilderArgs 는 위치 인자를 호스트, 대상 커널, "--" 뒤 setup-builder.sh 옵션으로 나눕니다.
func splitBuilderArgs(args []string) (hosts, kernels, setup []string, err error) {
	for i, a := range args {
		if a == "--" {
			setup = append(setup, args[i+1:]...)
			break
		}
		switch {
		case kernelArg.MatchString(a):
			kernels = append(kernels, a)
		case strings.HasPrefix(a, "-"):
			return nil, nil, nil, fmt.Errorf("%q 가 옵션처럼 보입니다. kpctl 옵션은 호스트 앞에, setup-builder.sh 옵션은 -- 뒤에 쓰세요", a)
		default:
			hosts = append(hosts, a)
		}
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

// kernelsForSeries 는 커널 목록에서 codename 시리즈의 것만 고릅니다. GA generic 이 아닌 커널(시리즈 판정 불가)은 그대로 둡니다.
func kernelsForSeries(kernels []string, codename string) []string {
	var out []string
	for _, k := range kernels {
		if lts := model.LTSForKernel(k); lts == nil || lts.Codename == codename {
			out = append(out, k)
		}
	}
	return out
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
	fs := flag.NewFlagSet("install-builder", flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprintln(os.Stderr, installBuilderUsage); fs.PrintDefaults() }
	r := addRemoteFlags(fs)
	fs.Lookup("bundle").Usage = "빌더 설치 묶음 디렉터리 (dist/builder 전체; 기본: kpctl 옆 builder/ 또는 /usr/local/share/kpctl/builder)"
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
		return err
	}
	if r.fromDHCP {
		return fmt.Errorf("install-builder 에는 -from-dhcp 를 쓸 수 없습니다 (빌드 서버를 직접 지정하세요)")
	}
	hosts, kernels, setupArgs, err := splitBuilderArgs(fs.Args())
	if err != nil {
		return err
	}
	if r.hostsFile != "" {
		fromFile, err := readHostsFile(r.hostsFile)
		if err != nil {
			return err
		}
		hosts = append(hosts, fromFile...)
	}
	hosts = unique(hosts)
	if *buildUser != "" {
		if !buildUserName.MatchString(*buildUser) || *buildUser == "root" {
			return fmt.Errorf("잘못된 빌드 계정 %q (소문자·숫자·_·- 32자 이내, root 불가)", *buildUser)
		}
		setupArgs = append([]string{"--user", *buildUser}, setupArgs...)
	}
	if len(hosts) == 0 {
		return fmt.Errorf("빌드 서버 호스트를 주세요 (kpctl install-builder -h)")
	}
	if r.parallel < 1 {
		r.parallel = 1
	}
	if err := r.build(); err != nil {
		return err
	}
	if err := checkReadable(r.ssh.KeyFile, "SSH 키"); err != nil {
		return err
	}
	r.ssh.Timeout = *timeout
	bundle, err := remote.OpenBuilderBundle(r.bundleDir)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(r.logDir, 0o700); err != nil {
		return err
	}
	if *ctrlURL == "" {
		return fmt.Errorf("-controller-url 이 필요합니다 (기본값 KPCTL_URL 이 비어 있음)")
	}

	var config []byte
	if !*checkOnly {
		if err := checkReadable(*tokenFile, "빌더 토큰"); err != nil {
			return err
		}
		data, err := os.ReadFile(*tokenFile)
		if err != nil {
			return err
		}
		token := strings.TrimSpace(string(data))
		if len(token) < 16 {
			return fmt.Errorf("빌더 토큰이 너무 짧습니다 (%s)", *tokenFile)
		}
		if config, err = builderConfig(bundle, *ctrlURL, token, *caFile); err != nil {
			return err
		}
	}

	hostMode := hasArg(setupArgs, "--host-mode")
	noStart := hasArg(setupArgs, "--no-start")
	var registered []string
	if len(kernels) == 0 && !hostMode {
		var st model.StatusResponse
		if err := c.Do("GET", "/api/status", nil, &st); err != nil {
			return fmt.Errorf("대상 커널을 고르려고 컨트롤러 상태를 읽지 못했습니다 (커널을 직접 지정하세요): %w", err)
		}
		registered = registeredKernels(&st)
	}
	series := make([]string, 0, len(model.SupportedLTS))
	for _, l := range model.SupportedLTS {
		series = append(series, l.Codename)
	}

	mode := "설치"
	if *checkOnly {
		mode = "점검"
	}
	fmt.Printf("빌드 서버 %d대 %s 시작 (동시 %d대, 빌더 %s, 컨트롤러 %s)\n\n", len(hosts), mode, r.parallel, bundle.Arch, *ctrlURL)

	results := runAll(hosts, r.parallel, func(target string) (res hostResult) {
		s := &remote.Session{SSH: r.loginFor(target), Target: target, OnStep: progress}
		defer func() { res.logFile = saveLog(r.logDir, target, "install-builder", s) }()

		// 1) 점검
		problems, warnings, err := s.Preflight(remote.PreflightOptions{
			ForBuilder: true, Arch: bundle.Arch, ControllerURL: *ctrlURL, Series: series,
			StopBuilder: *stopRunning, AllowWithAgent: *force,
		})
		res.hostname = s.Facts.Hostname
		if err != nil {
			return hostResult{result: "접속 실패", note: err.Error()}
		}

		// 대상 커널: 지정한 것 중 이 시리즈 → 없으면 등록 호스트 중 이 시리즈
		hostKernels := kernelsForSeries(kernels, s.Facts.Codename)
		if len(kernels) == 0 {
			hostKernels = kernelsForSeries(registered, s.Facts.Codename)
		}
		if !hostMode && len(hostKernels) == 0 {
			if len(kernels) > 0 {
				problems = append(problems, fmt.Sprintf("지정한 커널 중 %s 시리즈 커널이 없습니다", s.Facts.Codename))
			} else {
				problems = append(problems, fmt.Sprintf("컨트롤러에 %s 커널을 쓰는 등록 호스트가 없어 대상 커널을 고르지 못했습니다. 커널을 직접 지정하세요 (예: kpctl install-builder %s 6.8.0-136-generic)", s.Facts.Codename, target))
			}
		}
		keepConfig := s.Facts.BuilderConfig == "yes" && !*resetConfig
		if keepConfig {
			warnings = append(warnings, "기존 /etc/kpctl/builder.json 을 유지합니다 (토큰·주소를 새로 쓰려면 -reset-config)")
		}
		for _, w := range warnings {
			progress(target, "경고: "+w)
		}
		if len(problems) > 0 && (*checkOnly || !*force) {
			res.result, res.note = "점검 실패", strings.Join(problems, "\n")
			return res
		}
		if *checkOnly {
			res.ok, res.result = true, "점검 통과"
			res.note = fmt.Sprintf("%s %s, 커널 %s", s.Facts.Codename, s.Facts.Arch, strings.Join(hostKernels, " "))
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
		b, err := waitBuilder(c, res.hostname, 2*time.Minute)
		if err != nil {
			res.result, res.note = "보고 미확인", err.Error()
			return res
		}
		res.ok, res.result = true, "설치 완료"
		res.note = fmt.Sprintf("%s, 시리즈 %s, 커널 %s", b.Name, b.Series, strings.Join(b.Kernels, " "))
		return res
	})
	return printResults(results, r.logDir)
}

// waitBuilder 는 빌드 서버가 컨트롤러에 최근 작업 확인(보고)을 했는지 기다립니다.
// 빌더 이름은 builder.json 의 name, 비우면 hostname 입니다.
func waitBuilder(c *client.Client, name string, timeout time.Duration) (*model.BuilderInfo, error) {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for {
		var st model.StatusResponse
		if err := c.Do("GET", "/api/status", nil, &st); err != nil {
			lastErr = err
		} else if b := st.Builders[name]; b != nil && st.Now.Sub(b.LastSeen) < 2*time.Minute {
			return b, nil
		} else {
			lastErr = fmt.Errorf("컨트롤러에 빌더 %s 의 최근 보고가 없습니다 (빌드 서버에서 journalctl -u kpctl-builder 확인. builder.json 에 name 을 따로 줬다면 웹의 빌드 서버 목록 확인)", name)
		}
		if time.Now().After(deadline) {
			return nil, lastErr
		}
		time.Sleep(3 * time.Second)
	}
}
