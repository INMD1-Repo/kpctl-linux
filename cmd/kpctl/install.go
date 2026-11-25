// 이 파일: kpctl install / uninstall — SSH 로 호스트에 에이전트를 설치·제거
//
// 실제 SSH 작업은 internal/remote 패키지가 하고, 여기서는
// 옵션 읽기 → 여러 호스트 병렬 실행 → 컨트롤러 등록 확인 → 결과 표 출력 만 합니다.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"kpctl/internal/client"
	"kpctl/internal/model"
	"kpctl/internal/remote"
)

const installUsage = `사용법: kpctl install [옵션] <호스트...>
        kpctl install [옵션] -hosts-file hosts.txt
        kpctl install                                 (터미널에서 인자 없이: 질문형 설치)

  SSH 로 접속해 점검 → 파일 복사 → install-agent.sh 실행 → 컨트롤러 등록 확인까지 합니다.
  옵션은 호스트 이름보다 앞에 써야 합니다. 다시 실행하면 재설치(업그레이드)됩니다.

  SSH 키·사용자·토큰 위치는 컨트롤러 구축 때 만든 /etc/kpctl/kpctl.env 의 값을 기본으로 씁니다.
  호스트에 키를 아직 등록하지 않았다면 먼저 kpctl ssh-key copy <호스트...>

  예) kpctl install -check -hosts-file hosts.txt          점검만
      kpctl install -group canary server-01                카나리 1대
      kpctl install -group server -hosts-file hosts.txt      나머지

옵션:`

const uninstallUsage = `사용법: kpctl uninstall [옵션] <호스트...>

  에이전트를 지우고 컨트롤러 등록도 삭제합니다.
  적용 중인 라이브패치는 기본으로 유지합니다 (내리려면 -remove-patches).

옵션:`

// ── 공통 옵션 (SSH 옵션은 sshflags.go) ──

type remoteFlags struct {
	*sshFlags
	bundleDir string
	parallel  int
	logDir    string
	// clientOnly: 빌드 서버 전용 키는 쓰지 않음 (에이전트 설치)
	clientOnly bool
}

func addRemoteFlags(fs *flag.FlagSet) *remoteFlags {
	r := &remoteFlags{sshFlags: addSSHFlags(fs)}
	fs.StringVar(&r.ssh.KeyFile, "ssh-key", os.Getenv("KPCTL_SSH_KEY"),
		"SSH 개인키 (기본: KPCTL_SSH_KEY = 컨트롤러 구축 때 만든 /etc/kpctl/ssh/id_ed25519)")
	fs.StringVar(&r.bundleDir, "bundle", defaultBundleDir(), "설치 묶음 디렉터리 (kpctl-agent, install-agent.sh 등)")
	fs.IntVar(&r.parallel, "parallel", 5, "동시에 작업할 호스트 수")
	fs.StringVar(&r.logDir, "log-dir", "kpctl-install-logs", "호스트별 상세 로그를 저장할 디렉터리")
	return r
}

// loginFor 는 target 에 로그인되는 (계정, 키) 조합을 고릅니다 (컨트롤러 키 → 저장한 관리자 키).
// 아무것도 안 되면 기본 설정을 돌려줘서, 점검 단계가 원래 오류 메시지를 보여 주게 합니다.
func (r *remoteFlags) loginFor(target string) *remote.SSH {
	keys := storedKeys()
	if r.clientOnly {
		keys = clientKeys()
	}
	if len(keys) == 0 {
		return &r.ssh
	}
	if login, state, _ := pickLoginWith(&r.ssh, target, keys); state == keyOK {
		if login.User != r.ssh.User || login.KeyFile != r.ssh.KeyFile {
			progress(target, "저장한 관리자 키로 접속: "+loginDesc(login))
		}
		return login
	}
	return &r.ssh
}

// defaultBundleDir: KPCTL_BUNDLE 환경 변수 → kpctl 실행 파일 옆 agent/ → /usr/local/share/kpctl/agent
func defaultBundleDir() string {
	if d := os.Getenv("KPCTL_BUNDLE"); d != "" {
		return d
	}
	if exe, err := os.Executable(); err == nil {
		d := filepath.Join(filepath.Dir(exe), "agent")
		if _, err := os.Stat(d); err == nil {
			return d
		}
	}
	return "/usr/local/share/kpctl/agent"
}

// prepare 는 옵션을 정리하고 대상 호스트 목록과 설치 묶음을 돌려줍니다.
func (r *remoteFlags) prepare(fs *flag.FlagSet) ([]string, *remote.Bundle, error) {
	if r.parallel < 1 {
		r.parallel = 1
	}
	if err := r.build(); err != nil {
		return nil, nil, err
	}
	if err := checkReadable(r.ssh.KeyFile, "SSH 키"); err != nil {
		return nil, nil, err
	}
	targets, err := r.targets(fs)
	if err != nil {
		return nil, nil, err
	}

	b, err := remote.OpenBundle(r.bundleDir)
	if err != nil {
		return nil, nil, err
	}
	if err := os.MkdirAll(r.logDir, 0o700); err != nil {
		return nil, nil, err
	}
	return targets, b, nil
}

func readHostsFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, strings.Fields(line)[0])
		}
	}
	return out, sc.Err()
}

func unique(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// ── 병렬 실행과 출력 ──

type hostResult struct {
	target   string
	hostname string
	ok       bool
	result   string // 표의 "결과" 칸
	note     string // 표의 "비고" 칸 (실패 시 이유)
	logFile  string
	duration time.Duration
}

var printMu sync.Mutex

// progress 는 "[호스트] 메시지" 한 줄을 출력합니다 (여러 호스트가 동시에 출력해도 줄이 섞이지 않게).
func progress(target, msg string) {
	printMu.Lock()
	defer printMu.Unlock()
	fmt.Printf("[%s] %s\n", target, msg)
}

// runAll 은 최대 parallel 대씩 동시에 fn 을 실행하고, 결과를 입력 순서대로 돌려줍니다.
func runAll(targets []string, parallel int, fn func(target string) hostResult) []hostResult {
	results := make([]hostResult, len(targets))
	sem := make(chan struct{}, parallel)
	var wg sync.WaitGroup
	for i, t := range targets {
		wg.Add(1)
		go func(i int, t string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			start := time.Now()
			r := fn(t)
			r.target = t
			r.duration = time.Since(start).Round(time.Second)
			results[i] = r
		}(i, t)
	}
	wg.Wait()
	return results
}

var unsafeChars = regexp.MustCompile(`[^A-Za-z0-9._@-]`)

func saveLog(dir, target, kind string, s *remote.Session) string {
	path := filepath.Join(dir, unsafeChars.ReplaceAllString(target, "_")+"."+kind+".log")
	_ = os.WriteFile(path, []byte(s.Log.String()), 0o600)
	return path
}

// printResults 는 결과 표를 출력하고, 실패한 호스트의 이유를 자세히 보여줍니다. 실패가 있으면 오류를 돌려줍니다.
func printResults(results []hostResult, logDir string) error {
	fmt.Println()
	tw := newTable()
	fmt.Fprintln(tw, "대상\t호스트 이름\t결과\t소요\t비고")
	failed := 0
	for _, r := range results {
		if !r.ok {
			failed++
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", r.target, r.hostname, r.result, r.duration, cut(r.note, 70))
	}
	tw.Flush()

	if failed > 0 {
		fmt.Println("\n■ 실패 상세")
		for _, r := range results {
			if !r.ok {
				fmt.Printf("[%s] %s\n  %s\n  로그: %s\n", r.target, r.result, strings.ReplaceAll(r.note, "\n", "\n  "), r.logFile)
			}
		}
		return fmt.Errorf("%d대 중 %d대 실패", len(results), failed)
	}
	fmt.Printf("\n%d대 모두 성공. 상세 로그: %s/\n", len(results), logDir)
	return nil
}

func firstLine(err error) string {
	s := err.Error()
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// ── kpctl install ──

func cmdInstall(c *client.Client, args []string) error {
	if wantsWizard(args) { // 터미널에서 인자 없이 실행 → 질문형 (wizard.go)
		return agentWizard(c)
	}
	_, err := runAgentInstall(c, args)
	return err
}

func runAgentInstall(c *client.Client, args []string) ([]hostResult, error) {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprintln(os.Stderr, installUsage); fs.PrintDefaults() }
	r := addRemoteFlags(fs)
	r.clientOnly = true
	group := fs.String("group", "", "등록 그룹 이름 → KPCTL_TOKEN_DIR/enroll-<그룹>.token 사용 (예: canary, server)")
	tokenFile := fs.String("enroll-token-file", "", "등록 토큰 파일 (-group 대신 직접 지정). 토큰에 따라 링·재부팅 정책이 정해짐")
	ctrlURL := fs.String("controller-url", os.Getenv("KPCTL_URL"), "호스트가 접속할 컨트롤러 주소 (기본: KPCTL_URL)")
	caFile := fs.String("ca", os.Getenv("KPCTL_CA"), "CA 인증서 파일 → 호스트의 /etc/kpctl/ca.crt (기본: KPCTL_CA)")
	checkOnly := fs.Bool("check", false, "사전 점검만 하고 아무것도 바꾸지 않음")
	force := fs.Bool("force", false, "점검에서 문제가 나와도 설치 진행 (원인을 알 때만)")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if ok, err := r.loadDHCPTargets(c, fs); !ok {
		return nil, err
	}
	targets, bundle, err := r.prepare(fs)
	if err != nil {
		return nil, err
	}

	var token string
	if !*checkOnly {
		if *group != "" && *tokenFile == "" {
			dir := os.Getenv("KPCTL_TOKEN_DIR")
			if dir == "" {
				dir = "/etc/kpctl/tokens"
			}
			*tokenFile = filepath.Join(dir, "enroll-"+*group+".token")
		}
		if *tokenFile == "" {
			return nil, fmt.Errorf("-group 또는 -enroll-token-file 이 필요합니다 (점검만 하려면 -check)")
		}
		if err := checkReadable(*tokenFile, "등록 토큰"); err != nil {
			return nil, err
		}
		data, err := os.ReadFile(*tokenFile)
		if err != nil {
			return nil, err
		}
		token = strings.TrimSpace(string(data))
		if len(token) < 16 {
			return nil, fmt.Errorf("등록 토큰이 너무 짧습니다 (%s)", *tokenFile)
		}
	}

	mode := "설치"
	if *checkOnly {
		mode = "점검"
	}
	fmt.Printf("%d대 %s 시작 (동시 %d대, 에이전트 %s, 컨트롤러 %s)\n\n", len(targets), mode, r.parallel, bundle.Arch, *ctrlURL)

	results := runAll(targets, r.parallel, func(target string) (res hostResult) {
		s := &remote.Session{SSH: r.loginFor(target), Target: target, OnStep: progress}
		defer func() { res.logFile = saveLog(r.logDir, target, "install", s) }()

		// 1) 점검
		problems, warnings, err := s.Preflight(remote.PreflightOptions{
			ForInstall: true, Arch: bundle.Arch, Mirrors: bundle.Mirrors, ControllerURL: *ctrlURL,
		})
		res.hostname = s.Facts.Hostname
		if err != nil {
			return hostResult{result: "접속 실패", note: err.Error()}
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
			res.note = fmt.Sprintf("%s %s", s.Facts.Kernel, s.Facts.Arch)
			if len(warnings) > 0 {
				res.note += " / " + strings.Join(warnings, " / ")
			}
			return res
		}

		// 2) 설치
		err = s.Install(bundle, remote.InstallOptions{ControllerURL: *ctrlURL, EnrollToken: token, CAFile: *caFile})
		if err != nil {
			res.result, res.note = "설치 실패", err.Error()
			return res
		}

		// 3) 컨트롤러에 등록됐는지 확인
		progress(target, "컨트롤러 등록 확인")
		h, err := waitRegistered(c, res.hostname, time.Minute)
		if err != nil {
			res.result, res.note = "등록 미확인", err.Error()
			return res
		}
		res.ok, res.result = true, "설치 완료"
		res.note = fmt.Sprintf("%s, 링 %d, 정책 %s", h.ID, h.Ring, h.RebootPolicy)
		return res
	})
	return results, printResults(results, r.logDir)
}

// waitRegistered 는 호스트가 컨트롤러에 등록되어 최근에 보고했는지 확인합니다.
func waitRegistered(c *client.Client, hostname string, timeout time.Duration) (*model.Host, error) {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for {
		var st model.StatusResponse
		if err := c.Do("GET", "/api/status", nil, &st); err != nil {
			lastErr = err
		} else {
			for _, h := range st.Hosts {
				if h.Hostname == hostname && st.Now.Sub(h.LastSeen) < 2*time.Minute {
					return h, nil
				}
			}
			lastErr = fmt.Errorf("컨트롤러에 %s 의 최근 보고가 없습니다 (호스트에서 journalctl -u kpctl-agent 확인)", hostname)
		}
		if time.Now().After(deadline) {
			return nil, lastErr
		}
		time.Sleep(2 * time.Second)
	}
}

// ── kpctl uninstall ──

func cmdUninstall(c *client.Client, args []string) error {
	fs := flag.NewFlagSet("uninstall", flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprintln(os.Stderr, uninstallUsage); fs.PrintDefaults() }
	r := addRemoteFlags(fs)
	removePatches := fs.Bool("remove-patches", false, "적용 중인 kpctl_ 라이브패치도 내림 (막은 CVE 가 다시 열림)")
	keepReg := fs.Bool("keep-registration", false, "컨트롤러 등록은 지우지 않음")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if r.fromDHCP {
		return fmt.Errorf("uninstall 에는 -from-dhcp 를 쓸 수 없습니다 (지울 호스트를 직접 지정하세요)")
	}
	targets, bundle, err := r.prepare(fs)
	if err != nil {
		return err
	}
	fmt.Printf("%d대 제거 시작 (패치 %s)\n\n", len(targets), map[bool]string{true: "내림", false: "유지"}[*removePatches])

	results := runAll(targets, r.parallel, func(target string) (res hostResult) {
		s := &remote.Session{SSH: r.loginFor(target), Target: target, OnStep: progress}
		defer func() { res.logFile = saveLog(r.logDir, target, "uninstall", s) }()

		problems, _, err := s.Preflight(remote.PreflightOptions{})
		res.hostname = s.Facts.Hostname
		if err != nil {
			return hostResult{result: "접속 실패", note: err.Error()}
		}
		if len(problems) > 0 {
			res.result, res.note = "점검 실패", strings.Join(problems, "\n")
			return res
		}
		if err := s.Uninstall(bundle, *removePatches); err != nil {
			res.result, res.note = "제거 실패", err.Error()
			return res
		}
		res.ok, res.result = true, "제거 완료"
		res.note = map[bool]string{true: "패치 내림", false: "패치 유지"}[*removePatches]

		if !*keepReg {
			id, _, err := resolveHost(c, res.hostname)
			switch {
			case err != nil:
				res.note += ", 등록 없음"
			case c.Do("DELETE", "/api/hosts/"+id, nil, nil) != nil:
				res.note += ", 등록 삭제 실패 (kpctl host delete 로 직접)"
			default:
				res.note += ", 등록 삭제"
			}
		}
		return res
	})
	return printResults(results, r.logDir)
}
