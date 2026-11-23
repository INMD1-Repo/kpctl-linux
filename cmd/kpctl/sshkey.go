// 이 파일: kpctl ssh-key — 컨트롤러 SSH 공개키를 호스트에 등록
//
//	kpctl ssh-key show              authorized_keys 에 넣을 줄 출력 (cloud-init, 기존 자동화용)
//	kpctl ssh-key copy <호스트...>   지금 쓰는 계정/비밀번호로 한 번 로그인해서 키 등록
//	kpctl ssh-key add | list | remove  관리자가 준 키를 컨트롤러에 저장 (keystore.go)
//
// 등록하는 줄에는 제한을 붙입니다:
//
//	from="컨트롤러IP"  이 IP 에서 온 접속만 허용 (KPCTL_SSH_FROM 또는 -from)
//	restrict          포트 포워딩, 에이전트 포워딩, X11, pty 금지 (설치에 필요 없음)
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"kpctl/internal/client"
)

const sshKeyUsage = `사용법:
  kpctl ssh-key show [-from IP]
  kpctl ssh-key copy [옵션] [계정] <호스트...>      (옵션은 맨 앞에)

  계정을 첫 인자로 주면 그 계정으로 로그인해서 그 계정의 authorized_keys 에 넣습니다.
    kpctl ssh-key copy root 10.0.0.10 10.0.0.11
    kpctl ssh-key copy -from-dhcp ubuntu
  첫 인자가 IP·점 있는 이름·DNS 로 풀리는 이름이면 호스트로 봅니다 (계정은 -ssh-user 또는 KPCTL_SSH_USER).
  기본 계정(KPCTL_SSH_USER)과 다른 계정으로 등록하면 그 계정을 기억해 두고, 설치·자동 등록 때 컨트롤러 키로 그 계정도 시도합니다.

  copy 는 호스트마다 비밀번호나 평소 쓰는 키로 한 번 로그인해서
  컨트롤러 공개키를 ~<사용자>/.ssh/authorized_keys 에 추가하고, 그 키로 로그인되는지 확인합니다.
  처음 접속하는 호스트는 호스트 키 지문을 물어봅니다. 확인한 지문은 kpctl 의 known_hosts 에 저장됩니다.

옵션:`

func cmdSSHKey(c *client.Client, args []string) error {
	if len(args) >= 1 && (args[0] == "add" || args[0] == "list" || args[0] == "remove") {
		return cmdKeyStore(args[0], args[1:])
	}
	if len(args) < 1 || (args[0] != "show" && args[0] != "copy") {
		return fmt.Errorf("kpctl ssh-key show | copy <호스트...> | add <개인키> | list | remove <이름>  (자세히: kpctl ssh-key add -h)")
	}
	action := args[0]

	fs := flag.NewFlagSet("ssh-key "+action, flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprintln(os.Stderr, sshKeyUsage); fs.PrintDefaults() }
	key := fs.String("key", os.Getenv("KPCTL_SSH_KEY"), "등록할 컨트롤러 개인키 (공개키는 같은 이름 + .pub)")
	from := fs.String("from", os.Getenv("KPCTL_SSH_FROM"), "이 키를 쓸 수 있는 접속 출발지 IP (기본: KPCTL_SSH_FROM)")
	var sf *sshFlags
	var loginKey *string
	if action == "copy" {
		sf = addSSHFlags(fs)
		loginKey = fs.String("login-key", "", "처음 로그인할 때 쓸 키 (기본: 평소 쓰는 ssh 키 또는 비밀번호)")
	}
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *key == "" {
		return fmt.Errorf("-key 가 필요합니다 (컨트롤러를 setup-controller.sh 로 만들었다면 sudo 로 실행)")
	}
	line, err := authorizedLine(*key+".pub", *from)
	if err != nil {
		return err
	}

	if action == "show" {
		fmt.Println(line)
		return nil
	}
	if u, ok := userArg(fs.Args(), sf.fromDHCP || sf.hostsFile != ""); ok {
		sf.ssh.User = u
		sf.skipArgs = 1
	}
	if sf.ssh.User != "" {
		fmt.Printf("접속 계정: %s\n", sf.ssh.User)
	}
	if ok, err := sf.loadDHCPTargets(c, fs); !ok {
		return err
	}
	return sshKeyCopy(sf, fs, *key, *loginKey, line)
}

// authorizedLine 은 authorized_keys 에 넣을 한 줄을 만듭니다.
func authorizedLine(pubFile, from string) (string, error) {
	data, err := os.ReadFile(pubFile)
	if err != nil {
		if os.IsPermission(err) {
			return "", fmt.Errorf("%s 를 읽을 권한이 없습니다 (sudo kpctl ... 로 실행하세요)", pubFile)
		}
		return "", err
	}
	pub := strings.TrimSpace(string(data))
	if !strings.HasPrefix(pub, "ssh-") {
		return "", fmt.Errorf("%s 는 OpenSSH 공개키가 아닙니다", pubFile)
	}
	opts := "restrict"
	if from != "" {
		if strings.ContainsAny(from, `" `) {
			return "", fmt.Errorf("-from 값이 이상합니다: %q", from)
		}
		opts = fmt.Sprintf(`from="%s",%s`, from, opts)
	}
	return opts + " " + pub, nil
}

// copyScript 는 원격에서 표준 입력으로 받은 줄을 authorized_keys 에 넣습니다 (같은 키가 이미 있으면 그대로 둠).
const copyScript = `umask 077
mkdir -p ~/.ssh && touch ~/.ssh/authorized_keys
read -r line
key=$(printf '%s\n' "$line" | awk '{for(i=1;i<=NF;i++) if ($i ~ /^ssh-/) {print $(i+1); exit}}')
if [ -n "$key" ] && grep -qF "$key" ~/.ssh/authorized_keys; then
  echo "이미 등록됨"
else
  printf '%s\n' "$line" >> ~/.ssh/authorized_keys && echo "등록함"
fi`

// sshKeyCopy 는 호스트를 하나씩 돌며 키를 등록합니다.
// 비밀번호를 물어볼 수 있으므로 병렬로 하지 않습니다.
func sshKeyCopy(sf *sshFlags, fs *flag.FlagSet, key, loginKey, line string) error {
	if err := sf.build(); err != nil {
		return err
	}
	targets, err := sf.targets(fs)
	if err != nil {
		return err
	}

	login := sf.ssh // 처음 로그인용: 사람이 비밀번호/지문을 입력할 수 있게
	login.Interactive = true
	login.KeyFile = loginKey

	verify := sf.ssh // 확인용: 컨트롤러 키만으로 BatchMode 로그인
	verify.KeyFile = key

	var failed []string
	for _, t := range targets {
		fmt.Printf("[%s] 키 등록 중...\n", t)
		out, err := login.Run(t, "sh -c "+shQuote(copyScript), line+"\n")
		if err != nil {
			fmt.Printf("[%s] 실패: %v\n%s\n", t, err, strings.TrimSpace(out))
			failed = append(failed, t)
			continue
		}
		result := strings.TrimSpace(lastLine(out))
		if _, err := verify.Run(t, "true", ""); err != nil {
			fmt.Printf("[%s] %s, 그러나 컨트롤러 키로 로그인 실패: %v\n", t, result, err)
			fmt.Printf("      (이미 등록된 키에 from= 제한이 다르거나, sshd 가 키 로그인을 막았는지 확인)\n")
			failed = append(failed, t)
			continue
		}
		fmt.Printf("[%s] %s, 컨트롤러 키로 로그인 확인\n", t, result)
	}
	if len(failed) > 0 {
		return fmt.Errorf("%d대 중 %d대 실패: %s", len(targets), len(failed), strings.Join(failed, " "))
	}
	if u := sf.ssh.User; u != "" && u != os.Getenv("KPCTL_SSH_USER") {
		if err := rememberUser(key, u); err != nil {
			fmt.Printf("경고: 계정 %s 를 기억하지 못했습니다 (%v). 설치 때 -ssh-user %s 를 주세요\n", u, err, u)
		} else {
			fmt.Printf("계정 %s 를 기억했습니다. 설치·자동 등록 때 컨트롤러 키로 이 계정도 시도합니다.\n", u)
		}
	}
	fmt.Printf("\n%d대 완료. 이제 kpctl install 을 쓸 수 있습니다.\n", len(targets))
	return nil
}

// userArg 는 첫 위치 인자가 계정 이름인지 판단합니다 (ssh-key copy <계정> <호스트...>).
// 계정으로 보는 조건: 계정 이름 형식이고, IP 가 아니고, 점이 없고, DNS 로 풀리지 않으며,
// 뒤에 호스트가 더 있거나 다른 곳(-from-dhcp, -hosts-file)에서 대상을 받을 때.
func userArg(args []string, otherTargets bool) (string, bool) {
	if len(args) == 0 || (len(args) < 2 && !otherTargets) {
		return "", false
	}
	a := args[0]
	if !userRe.MatchString(a) || strings.Contains(a, ".") || net.ParseIP(a) != nil {
		return "", false
	}
	if _, err := net.LookupHost(a); err == nil {
		return "", false // 이름이 풀리면 호스트
	}
	return a, true
}

// rememberUser 는 컨트롤러 키로 등록한 추가 계정을 <키 디렉터리>/users 에 적습니다.
func rememberUser(key, user string) error {
	path := filepath.Join(filepath.Dir(key), "users")
	for _, u := range rememberedUsers(key) {
		if u == user {
			return nil
		}
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintln(f, user)
	return err
}

// rememberedUsers 는 ssh-key copy 가 기억한 계정 목록입니다.
func rememberedUsers(key string) []string {
	if key == "" {
		return nil
	}
	data, err := os.ReadFile(filepath.Join(filepath.Dir(key), "users"))
	if err != nil {
		return nil
	}
	var out []string
	for _, l := range strings.Fields(string(data)) {
		if userRe.MatchString(l) {
			out = append(out, l)
		}
	}
	return out
}

func shQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

func lastLine(s string) string {
	ls := strings.Split(strings.TrimRight(s, "\n"), "\n")
	return ls[len(ls)-1]
}
