// 이 파일: SSH 접속 옵션 (install, uninstall, ssh-key copy 가 함께 씀)
//
// 기본값은 환경 변수에서 옵니다. 컨트롤러를 setup-controller.sh 로 만들었다면
// /etc/kpctl/kpctl.env 에 들어 있어서 따로 줄 필요가 없습니다.
//
//	KPCTL_SSH_KEY          개인키 (/etc/kpctl/ssh/id_ed25519)
//	KPCTL_SSH_KNOWN_HOSTS  호스트 키 기록 (/etc/kpctl/ssh/known_hosts)
//	KPCTL_SSH_USER         접속 사용자
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"kpctl/internal/client"
	"kpctl/internal/remote"
)

type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

type sshFlags struct {
	ssh        remote.SSH
	opts       stringList
	acceptNew  bool
	knownHosts string
	hostsFile  string
	fromDHCP   bool     // -from-dhcp: 관리망 DHCP 임대 중 아직 등록 안 된 호스트를 대상에 추가
	extra      []string // fromDHCP 로 찾은 대상 (명령이 채움)
	skipArgs   int      // 앞에서 몇 개의 위치 인자를 대상이 아닌 것으로 뺄지 (ssh-key copy <계정> ...)
}

// addSSHFlags 는 공통 SSH 옵션을 등록합니다. (-ssh-key 는 명령마다 뜻이 달라 각자 등록)
func addSSHFlags(fs *flag.FlagSet) *sshFlags {
	f := &sshFlags{}
	fs.StringVar(&f.ssh.User, "ssh-user", os.Getenv("KPCTL_SSH_USER"), "SSH 사용자 (기본: KPCTL_SSH_USER)")
	fs.IntVar(&f.ssh.Port, "ssh-port", 0, "SSH 포트 (기본: 22 또는 ~/.ssh/config)")
	fs.Var(&f.opts, "ssh-opt", "추가 ssh -o 옵션, 여러 번 가능 (예: -ssh-opt ProxyJump=bastion)")
	fs.BoolVar(&f.acceptNew, "accept-new-hostkey", false, "처음 접속하는 호스트의 키를 known_hosts 에 자동 추가")
	fs.StringVar(&f.knownHosts, "ssh-known-hosts", os.Getenv("KPCTL_SSH_KNOWN_HOSTS"),
		"known_hosts 파일 (기본: KPCTL_SSH_KNOWN_HOSTS, 비면 ~/.ssh/known_hosts)")
	fs.StringVar(&f.hostsFile, "hosts-file", "", "호스트 목록 파일 (한 줄에 하나, # 은 주석)")
	fs.BoolVar(&f.fromDHCP, "from-dhcp", false, "관리망 DHCP 에서 IP 를 받았지만 아직 컨트롤러에 등록 안 된 호스트 전부")
	return f
}

// loadDHCPTargets 는 -from-dhcp 일 때 DHCP 임대에서 대상을 찾아 extra 에 넣습니다.
// 찾은 대상이 없으면 ok=false (명령은 할 일이 없으므로 그냥 끝내면 됨).
func (f *sshFlags) loadDHCPTargets(c *client.Client, fs *flag.FlagSet) (ok bool, err error) {
	if !f.fromDHCP {
		return true, nil
	}
	targets, registered, err := dhcpInstallTargets(c)
	if err != nil {
		return false, err
	}
	fmt.Printf("관리망 DHCP: 대상 %d대 (이미 등록된 %d대 제외)\n", len(targets), registered)
	f.extra = targets
	if len(targets) == 0 && fs.NArg() <= f.skipArgs && f.hostsFile == "" {
		fmt.Println("새로 설치할 호스트가 없습니다.")
		return false, nil
	}
	return true, nil
}

// build 는 옵션을 ssh -o 목록으로 정리합니다.
// ssh 는 같은 옵션이 여러 번 오면 처음 것을 쓰므로, 사용자가 -ssh-opt 로 준 값을 맨 앞에 둡니다.
func (f *sshFlags) build() error {
	f.ssh.Options = append(f.ssh.Options, f.opts...)
	if f.knownHosts != "" {
		f.ssh.Options = append(f.ssh.Options, "UserKnownHostsFile="+f.knownHosts)
	}
	if f.acceptNew {
		f.ssh.Options = append(f.ssh.Options, "StrictHostKeyChecking=accept-new")
	}
	return nil
}

// targets 는 명령줄의 호스트와 -hosts-file 의 호스트를 합칩니다.
func (f *sshFlags) targets(fs *flag.FlagSet) ([]string, error) {
	targets := append([]string{}, fs.Args()[f.skipArgs:]...)
	if f.hostsFile != "" {
		fromFile, err := readHostsFile(f.hostsFile)
		if err != nil {
			return nil, err
		}
		targets = append(targets, fromFile...)
	}
	targets = unique(append(targets, f.extra...))
	for _, t := range targets {
		if strings.HasPrefix(t, "-") {
			return nil, fmt.Errorf("호스트 %q 가 옵션처럼 보입니다. 옵션은 호스트 이름보다 앞에 쓰세요", t)
		}
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("대상 호스트가 없습니다 (호스트 이름이나 -hosts-file 을 주세요)")
	}
	return targets, nil
}

// checkReadable 은 파일을 읽을 수 있는지 미리 확인합니다 (root 전용 파일을 일반 사용자로 읽으려 할 때 안내).
func checkReadable(path, what string) error {
	if path == "" {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		if os.IsPermission(err) {
			return fmt.Errorf("%s %s 를 읽을 권한이 없습니다 (sudo kpctl ... 로 실행하세요)", what, path)
		}
		return fmt.Errorf("%s: %w", what, err)
	}
	return f.Close()
}
