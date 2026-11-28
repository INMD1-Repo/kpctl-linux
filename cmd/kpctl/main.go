// kpctl: 관리자 CLI
//
// 환경 변수:
//
//	KPCTL_URL    컨트롤러 주소 (예: https://kpatch.internal:8443)
//	KPCTL_TOKEN  관리자 토큰
//	KPCTL_CA     (선택) 사설 CA 인증서 파일
//
// 환경 변수가 비어 있으면 /etc/kpctl/kpctl.env (KPCTL_ENV 로 다른 파일 지정 가능)에서 읽습니다.
// setup-controller.sh 가 이 파일을 만들어 주므로, 컨트롤러에서는 sudo kpctl ... 만으로 동작합니다.
//
// 새 명령을 추가하려면: commands 맵에 한 줄 추가하고, 함수 하나를 만드세요.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"kpctl/internal/client"
)

type command struct {
	usage string
	run   func(c *client.Client, args []string) error
}

var commands = map[string]command{
	"status":   {"status                                   전체 현황", cmdStatus},
	"jobs":     {"jobs                                     최근 빌드 작업", cmdJobs},
	"log":      {"log <작업번호>                            빌드 로그 보기", cmdLog},
	"approve":  {"approve <작업번호> [--prerelease]          빌드된 작업 승인 → 첫 번째 링 배포", cmdApprove},
	"submit":   {"submit -kernel K [-urgent] [-cve ..] [-title ..] <파일.patch>   수동 패치 제출", cmdSubmit},
	"build":    {"build -kernel K [-urgent] [--prerelease]  현재 활성 패치로 다시 빌드", cmdBuild},
	"patches":  {"patches -kernel K                        커널의 패치 목록", cmdPatches},
	"patch":    {"patch enable|disable <패치ID>             패치 켜기/끄기 (이후 build 필요)", cmdPatch},
	"promote":  {"promote -kernel K -ring N [-force] [--prerelease]   이전 링 버전을 링 N 에 배포", cmdPromote},
	"rollback": {"rollback -kernel K -version N [--prerelease]       모든 링을 버전 N 으로 (0 = 패치 전부 내림)", cmdRollback},
	"hosts":    {"hosts [mok-status|mok-password <호스트>]   호스트 목록·MOK 상태·콘솔 승인 비밀번호", cmdHosts},
	"signing":  {"signing init-key | list | rollout-cert      공통 모듈 서명 키 준비·상태·MOK 등록 예약", cmdSigning},
	"auto":     {"auto [pause|resume|hold K|clear K]       자동 배포 현황·일시 중지·재개", cmdAuto},
	"host":     {"host set|cordon|uncordon|reboot|delete <호스트> [...]   호스트 관리 (kpctl host 로 도움말)", cmdHost},

	// SSH 원격 설치 (install.go)
	"install":         {"install [-check] -group G <호스트...>               SSH 로 에이전트 설치 (인자 없이 = 질문형)", cmdInstall},
	"install-builder": {"install-builder [-check] <호스트...> [커널...]        SSH 로 빌드 서버 설치 (인자 없이 = 질문형)", cmdInstallBuilder},
	"uninstall":       {"uninstall [-remove-patches] <호스트...>            SSH 로 에이전트 제거 (kpctl uninstall -h)", cmdUninstall},
	"bootstrap":       {"bootstrap [-group G] [-cloud-init]                 VM 이 스스로 등록하는 스크립트 출력 (kpctl bootstrap -h)", cmdBootstrap},
	"ssh-key":         {"ssh-key show | copy | add | list | remove          SSH 키 등록·관리자 키 저장", cmdSSHKey},

	// DHCP 호스트 자동 등록 (autoenroll.go)
	"autoenroll": {"autoenroll [-dry-run]                             DHCP 를 받은 미등록 호스트에 자동 설치 (타이머가 실행)", cmdAutoenroll},

	// 관리망 DHCP (dhcp.go)
	"dhcp": {"dhcp leases | reserve | unreserve | restart        관리망 DHCP 임대 보기·IP 고정·재시작", cmdDHCP},
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd, ok := commands[os.Args[1]]
	if !ok {
		usage()
		os.Exit(2)
	}

	var c *client.Client
	local := os.Args[1] == "signing" && len(os.Args) > 2 && os.Args[2] == "init-key"
	if !local {
		c = adminClient()
	}
	if err := cmd.run(c, os.Args[2:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintln(os.Stderr, "오류:", err)
		os.Exit(1)
	}
}

func adminClient() *client.Client {
	envErr := loadEnvFile()
	url, token := os.Getenv("KPCTL_URL"), os.Getenv("KPCTL_TOKEN")
	if url == "" || token == "" {
		if envErr != nil {
			fmt.Fprintln(os.Stderr, "오류:", envErr)
		}
		fmt.Fprintln(os.Stderr, "KPCTL_URL 과 KPCTL_TOKEN 환경 변수를 설정하세요 (컨트롤러에서는 sudo kpctl ...)")
		os.Exit(2)
	}
	c, err := client.New(url, token, os.Getenv("KPCTL_CA"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "오류:", err)
		os.Exit(1)
	}
	return c
}

// loadEnvFile 은 KEY=VALUE 형식 파일을 읽어, 아직 설정되지 않은 환경 변수만 채웁니다.
// (명령줄에서 직접 준 환경 변수가 항상 우선)
func loadEnvFile() error {
	path := os.Getenv("KPCTL_ENV")
	if path == "" {
		path = "/etc/kpctl/kpctl.env"
	}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("%s 를 읽지 못했습니다: %w", path, err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.Trim(strings.TrimSpace(v), `"'`)
		if _, set := os.LookupEnv(k); !set {
			os.Setenv(k, v)
		}
	}
	return nil
}

func usage() {
	fmt.Fprintln(os.Stderr, "사용법: kpctl <명령> [옵션]\n\n명령:")
	names := make([]string, 0, len(commands))
	for n := range commands {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Fprintln(os.Stderr, "  kpctl "+commands[n].usage)
	}
}
