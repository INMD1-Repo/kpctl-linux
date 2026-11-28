// 이 파일: 질문형 설치 — 터미널에서 kpctl install / install-builder 를 호스트 없이 실행하면 하나씩 물어봅니다.
//
// 답으로 명령줄 인자를 만들고 일반 설치와 같은 점검·설치 함수를 부릅니다.
// 순서: 질문 → 같은 명령줄 보여 주기 → 점검(-check) → (실패 시 SSH 키 등록 제안·재점검) → 확인 → 설치.
// 스크립트·타이머처럼 터미널이 아니면 질문하지 않고 예전처럼 동작합니다.
package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"kpctl/internal/client"
)

// prompter 는 한 줄씩 묻고 답을 읽습니다 (시험에서는 in/out 을 바꿔 끼움).
type prompter struct {
	in  *bufio.Reader
	out io.Writer
}

func newPrompter() *prompter { return &prompter{in: bufio.NewReader(os.Stdin), out: os.Stdout} }

// stdinIsTerminal 은 사람이 터미널에서 실행했는지 봅니다.
func stdinIsTerminal() bool {
	fi, err := os.Stdin.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// wantsWizard: 터미널이고 인자가 하나도 없으면 질문형으로 설치합니다.
func wantsWizard(args []string) bool { return len(args) == 0 && stdinIsTerminal() }

// ask 는 질문을 보여 주고 답을 돌려줍니다. 빈 답이면 def.
func (p *prompter) ask(question, def string) (string, error) {
	if def != "" {
		fmt.Fprintf(p.out, "%s [%s]: ", question, def)
	} else {
		fmt.Fprintf(p.out, "%s: ", question)
	}
	line, err := p.in.ReadString('\n')
	if err != nil && (err != io.EOF || line == "") {
		fmt.Fprintln(p.out)
		return "", fmt.Errorf("입력이 끝나 설치를 멈춥니다")
	}
	if line = strings.TrimSpace(line); line == "" {
		return def, nil
	}
	return line, nil
}

// need 는 빈 답을 받지 않고 다시 묻습니다.
func (p *prompter) need(question string) (string, error) {
	for {
		v, err := p.ask(question, "")
		if err != nil || v != "" {
			return v, err
		}
		fmt.Fprintln(p.out, "  값을 입력하세요.")
	}
}

// yes 는 예/아니오를 묻습니다.
func (p *prompter) yes(question string, def bool) (bool, error) {
	hint := "y/N"
	if def {
		hint = "Y/n"
	}
	for {
		fmt.Fprintf(p.out, "%s [%s]: ", question, hint)
		line, err := p.in.ReadString('\n')
		if err != nil && (err != io.EOF || line == "") {
			fmt.Fprintln(p.out)
			return false, fmt.Errorf("입력이 끝나 설치를 멈춥니다")
		}
		switch strings.ToLower(strings.TrimSpace(line)) {
		case "":
			return def, nil
		case "y", "yes", "예", "네":
			return true, nil
		case "n", "no", "아니오", "아니요":
			return false, nil
		}
		fmt.Fprintln(p.out, "  y 또는 n 으로 답하세요.")
	}
}

// pick 은 번호로 고르게 합니다. 돌려주는 값은 0부터 시작하는 순번입니다.
func (p *prompter) pick(question string, choices []string, def int) (int, error) {
	for i, c := range choices {
		fmt.Fprintf(p.out, "  %d) %s\n", i+1, c)
	}
	for {
		v, err := p.ask(question, fmt.Sprint(def+1))
		if err != nil {
			return 0, err
		}
		var n int
		if _, err := fmt.Sscan(v, &n); err == nil && n >= 1 && n <= len(choices) {
			return n - 1, nil
		}
		fmt.Fprintf(p.out, "  1~%d 중에서 고르세요.\n", len(choices))
	}
}

// shellJoin 은 다음에 그대로 붙여 넣을 수 있는 명령줄을 만듭니다.
func shellJoin(args []string) string {
	out := make([]string, len(args))
	for i, a := range args {
		if a != "" && strings.Trim(a, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_./:@=,") == "" {
			out[i] = a
		} else {
			out[i] = shQuote(a)
		}
	}
	return strings.Join(out, " ")
}

// accountHelp 는 "SSH 접속 계정" 질문 앞에 지금 시도할 계정·키를 알려 줍니다 (어떤 키로 들어가는지 헷갈리지 않게).
func accountHelp(p *prompter) {
	def := os.Getenv("KPCTL_SSH_USER")
	if def == "" {
		def = "(ssh 기본)"
	}
	fmt.Fprintf(p.out, "  엔터를 치면 컨트롤러 키(계정 %s) → 저장한 키 순서로 자동으로 시도합니다.\n", def)
	for _, k := range storedKeys() {
		fmt.Fprintf(p.out, "    저장한 키 %-16s 계정 %-14s 용도 %s\n", filepath.Base(k), showUser(keyUser(k)), roleDesc(k))
	}
	fmt.Fprintln(p.out, "  특정 계정으로만 접속하려면 그 계정 이름을 입력하세요 (예: root, ubuntu).")
}

// enrollGroups 는 토큰 디렉터리의 enroll-<그룹>.token 이름들입니다.
func enrollGroups() []string {
	dir := os.Getenv("KPCTL_TOKEN_DIR")
	if dir == "" {
		dir = "/etc/kpctl/tokens"
	}
	matches, _ := filepath.Glob(filepath.Join(dir, "enroll-*.token"))
	var out []string
	for _, m := range matches {
		out = append(out, strings.TrimSuffix(strings.TrimPrefix(filepath.Base(m), "enroll-"), ".token"))
	}
	sort.Strings(out)
	return out
}

// wizardPlan 은 질문으로 정한 설치 한 건입니다.
type wizardPlan struct {
	command string   // "install" | "install-builder"
	source  []string // 자동으로 대상을 읽는 옵션 (-from-dhcp 또는 -hosts-file 경로)
	flags   []string // 설치 옵션
	hosts   []string // 직접 지정한 호스트
	kernels []string // install-builder 대상 커널
	setup   []string // install-builder 의 "--" 뒤 setup-builder.sh 옵션
	user    string   // SSH 접속 계정 (키 등록 제안에 씀)
}

func (w *wizardPlan) args(check bool) []string {
	out := []string{}
	if check {
		out = append(out, "-check")
	}
	out = append(out, w.source...)
	out = append(out, w.flags...)
	out = append(out, w.hosts...)
	out = append(out, w.kernels...)
	if len(w.setup) > 0 {
		out = append(out, "--")
		out = append(out, w.setup...)
	}
	return out
}

// askAgentPlan 은 에이전트(클라이언트) 설치에 필요한 값을 묻습니다.
func askAgentPlan(p *prompter, dhcpAvailable bool) (*wizardPlan, error) {
	w := &wizardPlan{command: "install"}
	fmt.Fprintln(p.out, "■ 클라이언트(에이전트) 설치 — 질문에 답하면 점검 후 설치합니다. [ ] 안은 엔터를 쳤을 때 값입니다.")
	fmt.Fprintln(p.out)

	choices := []string{"호스트 주소를 직접 입력", "호스트 목록 파일 (한 줄에 하나)"}
	if dhcpAvailable {
		choices = append(choices, "관리망 DHCP에서 동적 IP를 받은 미등록 호스트 (고정 IP 제외)")
	}
	how, err := p.pick("설치할 호스트를 어떻게 정할까요", choices, 0)
	if err != nil {
		return nil, err
	}
	switch how {
	case 0:
		v, err := p.need("호스트 주소 (여러 대는 공백으로)")
		if err != nil {
			return nil, err
		}
		w.hosts = strings.Fields(v)
	case 1:
		v, err := p.need("호스트 목록 파일 경로")
		if err != nil {
			return nil, err
		}
		w.source = []string{"-hosts-file", v}
	case 2:
		w.source = []string{"-from-dhcp"}
	}

	fmt.Fprintln(p.out)
	accountHelp(p)
	if w.user, err = p.ask("SSH 접속 계정", ""); err != nil {
		return nil, err
	}
	if w.user != "" {
		w.flags = append(w.flags, "-ssh-user", w.user)
	}

	fmt.Fprintln(p.out)
	groups := enrollGroups()
	if len(groups) == 0 {
		return nil, fmt.Errorf("등록 토큰(enroll-<그룹>.token)이 없습니다. 컨트롤러 설치(setup-controller.sh)를 먼저 하세요")
	}
	def := 0
	for i, g := range groups {
		if g == "canary" {
			def = i
		}
	}
	descs := make([]string, len(groups))
	for i, g := range groups {
		descs[i] = g
		switch g {
		case "canary":
			descs[i] += "  (링 1: 새 패치를 먼저 받는 시험 호스트 — 처음엔 1~2대)"
		case "server":
			descs[i] += "  (링 2: 카나리 관찰 후 받는 나머지 호스트)"
		}
	}
	g, err := p.pick("등록 그룹", descs, def)
	if err != nil {
		return nil, err
	}
	w.flags = append(w.flags, "-group", groups[g])
	return w, nil
}

// askBuilderPlan 은 빌드 서버 설치에 필요한 값을 묻습니다.
func askBuilderPlan(p *prompter) (*wizardPlan, error) {
	w := &wizardPlan{command: "install-builder"}
	fmt.Fprintln(p.out, "■ 빌드 서버 설치 — 질문에 답하면 점검 후 설치합니다. [ ] 안은 엔터를 쳤을 때 값입니다.")
	fmt.Fprintln(p.out, "  빌드 서버는 패치할 호스트와 같은 Ubuntu 버전(예: 24.04)이어야 하고, 패치 대상 호스트와는 다른 서버여야 합니다.")
	fmt.Fprintln(p.out)

	v, err := p.need("빌드 서버 주소 (여러 대는 공백으로)")
	if err != nil {
		return nil, err
	}
	for _, h := range strings.Fields(v) {
		if why := nativeKernelProblem(h); why != "" {
			return nil, fmt.Errorf("%q 는 호스트 주소가 아닙니다. %s.\n%s", h, why, nativeBuilderHint)
		}
		if isKernelArg(h) || strings.HasPrefix(h, "-") {
			return nil, fmt.Errorf("%q 는 호스트 주소가 아닙니다 (커널 이름은 다음 질문에서 받습니다)", h)
		}
	}
	w.hosts = strings.Fields(v)

	fmt.Fprintln(p.out)
	accountHelp(p)
	if w.user, err = p.ask("SSH 접속 계정", ""); err != nil {
		return nil, err
	}
	if w.user != "" {
		w.flags = append(w.flags, "-ssh-user", w.user)
	}

	fmt.Fprintln(p.out)
	fmt.Fprintln(p.out, "  빌드 서비스 실행 계정: 빌드 서버 안에서 kpctl-builder 가 돌아갈 일반 계정입니다 (SSH 계정과 별개, 없으면 만듦).")
	for {
		u, err := p.ask("빌드 서비스 실행 계정", "kpbuild")
		if err != nil {
			return nil, err
		}
		if buildUserName.MatchString(u) && u != "root" {
			if u != "kpbuild" {
				w.flags = append(w.flags, "-build-user", u)
			}
			break
		}
		fmt.Fprintln(p.out, "  소문자·숫자·_·- 32자 이내, root 는 안 됩니다.")
	}

	fmt.Fprintln(p.out)
	fmt.Fprintln(p.out, "  대상 커널: 엔터를 치면 컨트롤러에 등록된 호스트 중 빌드 서버와 같은 시리즈의 커널을 자동으로 고릅니다.")
	for {
		k, err := p.ask("대상 커널 (예: 6.8.0-136-generic, 여러 개는 공백)", "")
		if err != nil {
			return nil, err
		}
		bad := ""
		for _, f := range strings.Fields(k) {
			// Debian/Rocky 커널은 다시 묻지 않고 CLI 와 같이 안내 후 중단합니다 (엔터로 Ubuntu 자동 선택에 빠지지 않도록)
			if why := nativeKernelProblem(f); why != "" {
				return nil, fmt.Errorf("%s.\n%s", why, nativeBuilderHint)
			}
			if !isKernelArg(f) {
				bad = f
			}
		}
		if bad == "" {
			w.kernels = strings.Fields(k)
			break
		}
		fmt.Fprintf(p.out, "  %q 는 커널 이름 형식이 아닙니다 (uname -r 값, 예: 6.8.0-136-generic).\n", bad)
	}

	fmt.Fprintln(p.out)
	for {
		m, err := p.ask("빌드 메모리 한도 MiB", "12288")
		if err != nil {
			return nil, err
		}
		var n int
		if _, err := fmt.Sscan(m, &n); err == nil && n >= 1024 {
			if n != 12288 {
				w.setup = append(w.setup, "--memory-mib", fmt.Sprint(n))
			}
			break
		}
		fmt.Fprintln(p.out, "  1024 이상의 숫자를 입력하세요.")
	}
	fmt.Fprintln(p.out, "  컴파일러 이미지는 snapshot.ubuntu.com 에서 수백 MB 를 받습니다. 저장소가 느린 곳이면 시간을 늘리세요.")
	for {
		m, err := p.ask("컴파일러 이미지 빌드 제한 시간(분)", "180")
		if err != nil {
			return nil, err
		}
		var n int
		if _, err := fmt.Sscan(m, &n); err == nil && n >= 10 && n <= 1440 {
			if n != 180 {
				w.setup = append(w.setup, "--image-timeout-minutes", fmt.Sprint(n))
			}
			break
		}
		fmt.Fprintln(p.out, "  10~1440 사이 숫자를 입력하세요.")
	}
	cache, err := p.yes("ccache(컴파일 캐시, 디스크 약 40 GiB)로 빌드를 빠르게 할까요", true)
	if err != nil {
		return nil, err
	}
	if !cache {
		w.setup = append(w.setup, "--no-cache")
	}

	fmt.Fprintln(p.out)
	upgrade, err := p.yes("이미 빌더가 설치된 서버를 다시 설치(업그레이드)하는 건가요", false)
	if err != nil {
		return nil, err
	}
	if upgrade {
		stop, err := p.yes("  실행 중인 빌더를 멈추고 진행할까요 (진행 중인 빌드는 실패로 끝남)", true)
		if err != nil {
			return nil, err
		}
		if stop {
			w.flags = append(w.flags, "-stop-running")
		}
		reset, err := p.yes("  기존 builder.json 을 버리고 이 컨트롤러 기준으로 새로 만들까요", false)
		if err != nil {
			return nil, err
		}
		if reset {
			w.flags = append(w.flags, "-reset-config")
		}
	}
	return w, nil
}

// runWizard 는 마지막 점검을 통과한 호스트를 확인받고 그 주소로 설치합니다.
func runWizard(c *client.Client, p *prompter, w *wizardPlan, run func(*client.Client, []string) ([]hostResult, error), sshKey func(*client.Client, []string) error) error {
	fmt.Fprintf(p.out, "\n입력한 조건으로 다시 실행할 명령:\n  sudo kpctl %s %s\n\n", w.command, shellJoin(w.args(false)))
	for {
		fmt.Fprintln(p.out, "■ 점검 (아무것도 바꾸지 않음)")
		results, err := run(c, w.args(true))
		if len(results) == 0 {
			return err
		}
		var passed []string
		for _, result := range results {
			if result.ok {
				passed = append(passed, result.target)
			}
		}
		if err != nil {
			fmt.Fprintf(p.out, "\n점검 실패: %v\n", err)
			fmt.Fprintln(p.out, "SSH 키가 없어 접속에 실패했다면 비밀번호로 로그인해 키를 등록할 수 있습니다.")
			if len(passed) > 0 {
				fmt.Fprintf(p.out, "N을 선택하면 점검을 통과한 %d대만 설치 대상으로 남습니다.\n", len(passed))
			}
			again, err := p.yes("SSH 키를 등록하고 다시 점검할까요", false)
			if err != nil {
				return err
			}
			if again {
				if err := sshKey(c, w.copyArgs()); err != nil {
					fmt.Fprintf(p.out, "키 등록 실패: %v\n", err)
				}
				continue
			}
		}
		if len(passed) == 0 {
			return fmt.Errorf("점검을 통과한 서버가 없어 설치하지 않았습니다")
		}
		fmt.Fprintf(p.out, "\n점검을 통과한 설치 대상 %d대: %s\n", len(passed), strings.Join(passed, " "))
		ok, err := p.yes("이 서버에 설치할까요", true)
		if err != nil {
			return err
		}
		if !ok {
			fmt.Fprintln(p.out, "설치하지 않았습니다.")
			return nil
		}
		install := *w
		install.source = nil
		install.hosts = passed
		_, err = run(c, install.args(false))
		return err
	}
}

// copyArgs 는 같은 대상·계정으로 kpctl ssh-key copy 를 부를 인자입니다 (커널 이름은 뺌).
func (w *wizardPlan) copyArgs() []string {
	out := []string{"copy"}
	if w.user != "" {
		out = append(out, "-ssh-user", w.user)
	}
	out = append(out, w.source...)
	return append(out, w.hosts...)
}

func agentWizard(c *client.Client) error {
	p := newPrompter()
	_, err := os.Stat(getDHCPPaths().leases)
	w, err := askAgentPlan(p, err == nil)
	if err != nil {
		return err
	}
	return runWizard(c, p, w, runAgentInstall, cmdSSHKey)
}

func builderWizard(c *client.Client) error {
	p := newPrompter()
	w, err := askBuilderPlan(p)
	if err != nil {
		return err
	}
	return runWizard(c, p, w, runBuilderInstall, cmdSSHKey)
}
