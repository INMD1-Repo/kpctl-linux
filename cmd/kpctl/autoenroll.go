// 이 파일: kpctl autoenroll — 클라이언트 키로 들어가지는 미등록 서버에 에이전트를 자동 설치 (질문 없음)
//
// 대상: 관리망 DHCP 임대 + 호스트 목록 파일(/etc/kpctl/autoenroll-hosts, DHCP 를 안 쓰는 환경용).
// kpctl-autoenroll.timer 가 1분마다 한 번씩 실행합니다. 실패한 호스트는 다음 실행 때 다시 시도합니다.
// 커널마다 첫 호스트는 카나리 그룹(링 1), 나머지는 일반 그룹으로 등록해서 단계 배포가 되게 합니다.
// 자동 등록하면 안 되는 호스트(빌드 서버 등)는 -ignore-file 에 적습니다.
//
// 설치는 클라이언트 키(컨트롤러 SSH 키, 빌드 서버 전용이 아닌 저장 키)로 로그인되는 호스트에만 합니다.
// 빌드 서버 전용 키(ssh-key add -role builder)로만 들어가지는 서버에는 설치하지 않습니다. 먼저 로그인해 보고,
// 키가 아직 없으면(Permission denied) 실패로 치지 않고 "키 대기" 로 건너뜁니다.
// 그래서 키를 저장하거나 kpctl ssh-key copy·cloud-init 으로 키를 넣는 순간, 다음 실행(1분 안)에 자동으로 설치됩니다.
// 같은 호스트에 대한 "키 대기" 안내는 상태가 바뀔 때만 출력합니다 (1분마다 로그가 쌓이지 않도록).
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"kpctl/internal/client"
	"kpctl/internal/dhcp"
	"kpctl/internal/model"
	"kpctl/internal/remote"
)

const autoenrollUsage = `사용법: kpctl autoenroll [옵션]

  아직 등록되지 않은 호스트에 질문 없이 에이전트를 설치합니다 (한 번 돌고 끝남, 타이머가 1분마다 실행).
  대상은 관리망 DHCP 임대와 호스트 목록 파일(기본 /etc/kpctl/autoenroll-hosts, 한 줄에 IP 또는 이름)입니다.
  클라이언트 키로 로그인되는 호스트에만 설치하고, 키가 없는 호스트는 키가 들어올 때까지 기다립니다.
  빌드 서버 전용 키(kpctl ssh-key add -role builder)로는 설치하지 않습니다.
  컨트롤러·빌드 서버(/etc/kpctl/{controller,builder}.json 이 있는 서버)는 건너뜁니다.

옵션:`

func cmdAutoenroll(c *client.Client, args []string) error {
	fs := flag.NewFlagSet("autoenroll", flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprintln(os.Stderr, autoenrollUsage); fs.PrintDefaults() }
	r := addRemoteFlags(fs)
	canary := fs.String("canary-group", "canary", "커널마다 첫 호스트의 등록 그룹")
	group := fs.String("group", "server", "나머지 호스트의 등록 그룹")
	ignoreFile := fs.String("ignore-file", "/etc/kpctl/autoenroll-ignore", "제외할 호스트 파일 (IP, MAC, 이름. 한 줄에 하나)")
	dryRun := fs.Bool("dry-run", false, "대상만 보여 주고 설치하지 않음")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// 등록 정보를 못 읽으면 전부 미등록으로 보여 재설치하게 되므로 여기서 멈춥니다.
	var st model.StatusResponse
	if err := c.Do("GET", "/api/status", nil, &st); err != nil {
		return fmt.Errorf("컨트롤러 등록 정보를 읽지 못했습니다: %w", err)
	}
	leases, err := dhcp.ReadLeases(getDHCPPaths().leases)
	if err != nil {
		return err
	}
	// DHCP 를 안 쓰는 환경: 호스트 목록 파일의 주소도 대상으로 (파일이 없으면 건너뜀)
	if r.hostsFile == "" {
		r.hostsFile = defaultAutoenrollHosts()
	}
	if _, err := os.Stat(r.hostsFile); err == nil {
		listed, err := readHostsFile(r.hostsFile)
		if err != nil {
			return err
		}
		leases = append(leases, listedLeases(listed, leases)...)
	}
	ignore, err := readIgnoreFile(*ignoreFile)
	if err != nil {
		return err
	}
	targets := autoenrollTargets(leases, st.Hosts, ignore, time.Now())
	// 지난 실행에서 등록을 확인한 대상(이름 없는 임대·IP 로 적은 호스트)은 다시 접속하지 않습니다.
	doneFile := filepath.Join(r.logDir, "enrolled")
	done := readDone(doneFile)
	targets = skipDone(targets, done, st.Hosts)
	if len(targets) == 0 {
		return nil
	}
	// 무인 실행이라 처음 보는 호스트 키는 기록하고 진행합니다. 바뀐 호스트 키는 ssh 가 계속 거부합니다.
	r.acceptNew = true
	if err := r.build(); err != nil {
		return err
	}
	if err := checkReadable(r.ssh.KeyFile, "SSH 키"); err != nil {
		return err
	}
	if *dryRun {
		// 설치는 하지 않고, 컨트롤러 키로 로그인되는지만 확인해서 보여 줍니다.
		names := map[keyState]string{keyOK: "키 확인 → 설치 대상", keyMissing: "키 대기", keyUnreachable: "접속 안 됨", keyError: "오류"}
		tw := newTable()
		fmt.Fprintln(tw, "IP\tMAC\t이름\t상태\t설명")
		for _, l := range targets {
			login, state, detail := pickClientLogin(&r.ssh, l.IP)
			if login != nil {
				detail = "접속: " + loginDesc(login)
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", l.IP, l.MAC, dash(l.Name), names[state], detail)
		}
		return tw.Flush()
	}
	bundle, err := remote.OpenBundle(r.bundleDir)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(r.logDir, 0o700); err != nil {
		return err
	}
	canaryToken, err := readEnrollToken(*canary)
	if err != nil {
		return err
	}
	groupToken, err := readEnrollToken(*group)
	if err != nil {
		return err
	}

	// 링 배정이 앞선 호스트의 결과에 달려 있어 한 대씩 처리합니다.
	hasCanary := canaryKernels(st.Hosts)
	registered := map[string]bool{}
	for _, h := range st.Hosts {
		registered[shortName(h.Hostname)] = true
	}
	waitFile := filepath.Join(r.logDir, "key-waiting")
	prevWaiting := readWaiting(waitFile)
	waiting := map[string]bool{}
	failed := 0
	for _, l := range targets {
		// 1. 컨트롤러 키·저장한 관리자 키로 로그인되는지 먼저 확인 (로그인되는 호스트만 설치)
		login, state, detail := pickClientLogin(&r.ssh, l.IP)
		switch state {
		case keyMissing, keyUnreachable:
			waiting[l.MAC] = true
			if !prevWaiting[l.MAC] {
				progress(l.IP, "키 대기: "+detail)
			}
			continue
		case keyError:
			failed++
			progress(l.IP, "실패: "+detail)
			continue
		}
		progress(l.IP, "로그인 확인 ("+loginDesc(login)+") → 설치 시작")

		s := &remote.Session{SSH: login, Target: l.IP, OnStep: progress}
		name, token := *group, groupToken
		err := func() error {
			defer saveLog(r.logDir, l.IP, "install", s)
			problems, warnings, err := s.Preflight(remote.PreflightOptions{
				ForInstall: true, Arch: bundle.Arch, Mirrors: bundle.Mirrors, ControllerURL: os.Getenv("KPCTL_URL"),
			})
			if err != nil {
				return err
			}
			for _, w := range warnings {
				progress(l.IP, "경고: "+w)
			}
			if s.Facts.Role == "infra" {
				progress(l.IP, "건너뜀: 컨트롤러 또는 빌드 서버")
				done[l.MAC] = doneInfra
				name = ""
				return nil
			}
			// 임대에 이름이 없으면 접속해 봐야 등록 여부를 알 수 있습니다.
			if registered[shortName(s.Facts.Hostname)] {
				done[l.MAC] = s.Facts.Hostname
				name = ""
				return nil
			}
			if len(problems) > 0 {
				return fmt.Errorf("점검 실패: %s", strings.Join(problems, "; "))
			}
			if !hasCanary[s.Facts.Kernel] {
				name, token = *canary, canaryToken
			}
			if err := s.Install(bundle, remote.InstallOptions{
				ControllerURL: os.Getenv("KPCTL_URL"), EnrollToken: token, CAFile: os.Getenv("KPCTL_CA"),
			}); err != nil {
				return err
			}
			_, err = waitRegistered(c, s.Facts.Hostname, time.Minute)
			return err
		}()
		if err != nil {
			failed++
			progress(l.IP, "실패: "+firstLine(err))
			continue
		}
		if name == "" {
			continue
		}
		registered[shortName(s.Facts.Hostname)] = true
		done[l.MAC] = s.Facts.Hostname
		if name == *canary {
			hasCanary[s.Facts.Kernel] = true
		}
		progress(l.IP, fmt.Sprintf("자동 등록 완료: %s, 커널 %s, 그룹 %s", s.Facts.Hostname, s.Facts.Kernel, name))
	}
	writeWaiting(waitFile, waiting)
	writeDone(doneFile, done)
	if failed > 0 {
		return fmt.Errorf("%d대 중 %d대 실패 (다음 실행 때 다시 시도)", len(targets), failed)
	}
	return nil
}

// ── 컨트롤러 키 확인 ──

type keyState int

const (
	keyOK          keyState = iota
	keyMissing              // 호스트가 컨트롤러 키를 받아 주지 않음 → 등록될 때까지 대기
	keyUnreachable          // 접속 자체가 안 됨 (부팅 중, sshd 아직 안 뜸 등) → 대기
	keyError                // 그 밖의 오류 (호스트 키 바뀜 등) → 실패로 보고
)

// probeKey 는 컨트롤러 키로 BatchMode 로그인을 해 봅니다.
func probeKey(ssh *remote.SSH, host string) (keyState, string) {
	probe := *ssh
	probe.Timeout = 30 * time.Second
	out, err := probe.Run(host, "true", "")
	if err == nil {
		return keyOK, ""
	}
	return classifyProbe(out, err)
}

// classifyProbe 는 ssh 실패 출력을 보고 대기할지 실패로 볼지 정합니다.
func classifyProbe(out string, err error) (keyState, string) {
	o := strings.ToLower(out)
	switch {
	case strings.Contains(o, "host identification has changed"), strings.Contains(o, "host key verification failed"):
		return keyError, "호스트 키가 known_hosts 와 다릅니다 (재설치한 서버면 ssh-keygen -R <IP> -f $KPCTL_SSH_KNOWN_HOSTS)"
	case strings.Contains(o, "permission denied"), strings.Contains(o, "too many authentication failures"):
		return keyMissing, "컨트롤러 키·저장한 키 모두 로그인 안 됨 (kpctl ssh-key add 로 관리자 키 저장, 또는 ssh-key copy 로 등록하면 자동 설치)"
	case strings.Contains(o, "connection refused"), strings.Contains(o, "timed out"), strings.Contains(o, "no route to host"),
		strings.Contains(o, "connection reset"), strings.Contains(o, "connection closed"), strings.Contains(o, "시간 초과"):
		return keyUnreachable, "SSH 접속 안 됨 (부팅 중이거나 sshd 가 아직 안 뜸)"
	}
	return keyError, firstLine(err) + " " + strings.TrimSpace(lastLine(out))
}

// readWaiting / writeWaiting 은 지난 실행에서 "키 대기" 였던 MAC 목록을 보관합니다 (안내를 한 번만 출력하려고).
func readWaiting(path string) map[string]bool {
	out := map[string]bool{}
	data, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	for _, l := range strings.Fields(string(data)) {
		out[l] = true
	}
	return out
}

func writeWaiting(path string, m map[string]bool) {
	var ls []string
	for k := range m {
		ls = append(ls, k)
	}
	sort.Strings(ls)
	data := strings.Join(ls, "\n")
	if data != "" {
		data += "\n"
	}
	_ = os.WriteFile(path, []byte(data), 0o600)
}

// autoenrollTargets 는 임대 중 설치 대상을 IP 순서로 돌려줍니다.
// 한 MAC 에 임대가 여러 줄이면 (IP 가 바뀐 경우) 가장 늦게 만료되는 것만 씁니다. 옛 IP 는 응답하지 않기 때문입니다.
func autoenrollTargets(leases []dhcp.Lease, hosts []*model.Host, ignore map[string]bool, now time.Time) []dhcp.Lease {
	newest := map[string]dhcp.Lease{}
	for _, l := range leases {
		if !l.Active(now) {
			continue
		}
		old, seen := newest[l.MAC]
		if !seen || l.Expires.IsZero() || (!old.Expires.IsZero() && l.Expires.After(old.Expires)) {
			newest[l.MAC] = l
		}
	}
	registered := map[string]bool{}
	for _, h := range hosts {
		registered[shortName(h.Hostname)] = true
	}
	var out []dhcp.Lease
	for _, l := range newest {
		name := shortName(l.Name)
		if ignore[l.IP] || ignore[l.MAC] || (name != "" && (ignore[name] || registered[name])) {
			continue
		}
		out = append(out, l)
	}
	sort.Slice(out, func(i, j int) bool { return ipLess(out[i].IP, out[j].IP) })
	return out
}

// canaryKernels 는 첫 번째 링(카나리) 호스트가 이미 있는 커널 목록입니다.
func canaryKernels(hosts []*model.Host) map[string]bool {
	first := 0
	for _, h := range hosts {
		if first == 0 || h.Ring < first {
			first = h.Ring
		}
	}
	out := map[string]bool{}
	for _, h := range hosts {
		if h.Ring == first {
			out[h.Status.Kernel] = true
		}
	}
	return out
}

// readIgnoreFile 은 제외 목록을 소문자로 읽습니다. 파일이 없으면 빈 목록입니다.
func readIgnoreFile(path string) (map[string]bool, error) {
	out := map[string]bool{}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return out, nil
	}
	lines, err := readHostsFile(path)
	if err != nil {
		return nil, err
	}
	for _, l := range lines {
		out[strings.ToLower(l)] = true
	}
	return out, nil
}

func readEnrollToken(group string) (string, error) {
	dir := os.Getenv("KPCTL_TOKEN_DIR")
	if dir == "" {
		dir = "/etc/kpctl/tokens"
	}
	path := filepath.Join(dir, "enroll-"+group+".token")
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("등록 토큰: %w", err)
	}
	token := strings.TrimSpace(string(data))
	if len(token) < 16 {
		return "", fmt.Errorf("등록 토큰이 너무 짧습니다 (%s)", path)
	}
	return token, nil
}

// defaultAutoenrollHosts 는 DHCP 를 안 쓰는 환경에서 자동 설치 대상을 적는 파일입니다 (KPCTL_AUTOENROLL_HOSTS 로 바꿈).
func defaultAutoenrollHosts() string {
	if p := os.Getenv("KPCTL_AUTOENROLL_HOSTS"); p != "" {
		return p
	}
	return "/etc/kpctl/autoenroll-hosts"
}

// listedLeases 는 호스트 목록 파일의 주소를 임대처럼 바꿉니다. 이미 DHCP 임대에 있는 IP 는 뺍니다.
// MAC 칸에는 "host:<주소>" 를 넣어 키 대기·등록 기록의 열쇠로 씁니다. 이름으로 적었으면 접속 전에 등록 여부를 압니다.
func listedLeases(listed []string, leases []dhcp.Lease) []dhcp.Lease {
	inDHCP := map[string]bool{}
	for _, l := range leases {
		inDHCP[l.IP] = true
	}
	var out []dhcp.Lease
	for _, a := range unique(listed) {
		if inDHCP[a] {
			continue
		}
		l := dhcp.Lease{MAC: "host:" + a, IP: a}
		if net.ParseIP(a) == nil {
			l.Name = a
		}
		out = append(out, l)
	}
	return out
}

// doneInfra 는 컨트롤러·빌드 서버라 설치하지 않는 대상의 표시입니다.
const doneInfra = "@infra"

// readDone / writeDone 은 "대상 열쇠(MAC 또는 host:주소) 호스트이름" 줄을 보관합니다.
func readDone(path string) map[string]string {
	out := map[string]string{}
	data, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(data), "\n") {
		if f := strings.Fields(line); len(f) == 2 {
			out[f[0]] = f[1]
		}
	}
	return out
}

func writeDone(path string, m map[string]string) {
	var ls []string
	for k, v := range m {
		ls = append(ls, k+" "+v)
	}
	sort.Strings(ls)
	data := strings.Join(ls, "\n")
	if data != "" {
		data += "\n"
	}
	_ = os.WriteFile(path, []byte(data), 0o600)
}

// skipDone 은 지난 실행에서 등록을 확인했고 지금도 등록돼 있는 대상, 인프라 서버로 확인한 대상을 뺍니다.
// 등록이 지워진 호스트(kpctl host delete)는 다시 대상이 됩니다.
func skipDone(targets []dhcp.Lease, done map[string]string, hosts []*model.Host) []dhcp.Lease {
	registered := map[string]bool{}
	for _, h := range hosts {
		registered[shortName(h.Hostname)] = true
	}
	var out []dhcp.Lease
	for _, l := range targets {
		if n := done[l.MAC]; n == doneInfra || (n != "" && registered[shortName(n)]) {
			continue
		}
		out = append(out, l)
	}
	return out
}
