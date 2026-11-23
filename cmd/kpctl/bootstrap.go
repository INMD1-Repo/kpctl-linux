// 이 파일: kpctl bootstrap — VM 이 스스로 등록하는 스크립트 만들기
//
// 컨트롤러가 VM 에 들어가 설치하는 kpctl install 과 반대로, VM 이 컨트롤러에서 묶음을 받아 설치합니다.
// 그래서 VM 에 SSH 키가 없어도 되고, 스크립트를 넣은 VM 만 등록됩니다.
// 묶음을 주는 쪽은 컨트롤러의 GET /api/bootstrap/agent.tar.gz 입니다.
package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"kpctl/internal/client"
	"kpctl/internal/remote"
)

const bootstrapUsage = `사용법: kpctl bootstrap [옵션] > 파일

  VM 이 스스로 에이전트를 받아 컨트롤러에 등록하는 스크립트를 출력합니다.
  출력에 등록 토큰이 들어 있으니 비밀번호처럼 다루세요.

  예) kpctl bootstrap -group server > kpctl-server.sh                 지금 있는 VM 에서 root 로 실행
      kpctl bootstrap -group server -cloud-init > kpctl-server.yaml   새 VM 의 cloud-init 용

옵션:`

var (
	bootstrapURLRe   = regexp.MustCompile(`^https?://[A-Za-z0-9.:\[\]_-]+$`)
	bootstrapTokenRe = regexp.MustCompile(`^[A-Za-z0-9._-]+$`) // install-agent.sh 와 같은 규칙
)

func cmdBootstrap(c *client.Client, args []string) error {
	fs := flag.NewFlagSet("bootstrap", flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprintln(os.Stderr, bootstrapUsage); fs.PrintDefaults() }
	group := fs.String("group", "server", "등록 그룹 → KPCTL_TOKEN_DIR/enroll-<그룹>.token (새 VM 이 저절로 카나리가 되지 않도록 기본은 server)")
	tokenFile := fs.String("enroll-token-file", "", "등록 토큰 파일 (-group 대신 직접 지정)")
	cloudInit := fs.Bool("cloud-init", false, "cloud-init 설정(#cloud-config) 으로 출력")
	controllerURL := fs.String("controller-url", os.Getenv("KPCTL_URL"), "VM 이 접속할 컨트롤러 주소 (기본: KPCTL_URL)")
	caFile := fs.String("ca", os.Getenv("KPCTL_CA"), "컨트롤러 CA 인증서 파일 (기본: KPCTL_CA)")
	controllerIP := fs.String("controller-ip", os.Getenv("KPCTL_SSH_FROM"), "컨트롤러 이름이 VM 에서 안 풀릴 때 /etc/hosts 에 넣을 IP (기본: KPCTL_SSH_FROM)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("인자를 받지 않습니다: %s", strings.Join(fs.Args(), " "))
	}

	if *tokenFile == "" {
		*tokenFile = filepath.Join(os.Getenv("KPCTL_TOKEN_DIR"), "enroll-"+*group+".token")
	}
	raw, err := os.ReadFile(*tokenFile)
	if err != nil {
		return fmt.Errorf("등록 토큰을 읽지 못했습니다: %w", err)
	}
	token := strings.TrimSpace(string(raw))
	if !bootstrapTokenRe.MatchString(token) {
		return fmt.Errorf("%s: 등록 토큰에 영문/숫자/._- 외의 문자가 있습니다", *tokenFile)
	}
	if !bootstrapURLRe.MatchString(*controllerURL) {
		return fmt.Errorf("컨트롤러 주소가 잘못됐습니다: %q", *controllerURL)
	}
	if *controllerIP != "" && net.ParseIP(*controllerIP) == nil {
		return fmt.Errorf("IP 형식이 아닙니다: %s", *controllerIP)
	}
	var ca string
	if *caFile != "" {
		data, err := os.ReadFile(*caFile)
		if err != nil {
			return fmt.Errorf("CA 인증서를 읽지 못했습니다: %w", err)
		}
		if !strings.Contains(string(data), "BEGIN CERTIFICATE") {
			return fmt.Errorf("%s 는 PEM 인증서가 아닙니다", *caFile)
		}
		ca = string(data)
	}

	script, err := bootstrapScript(*controllerURL, token, ca, *controllerIP)
	if err != nil {
		return err
	}
	if *cloudInit {
		fmt.Print(bootstrapCloudInit(script))
	} else {
		fmt.Print(script)
	}
	fmt.Fprintln(os.Stderr, "출력에 등록 토큰이 들어 있습니다. 공유 저장소에 올리지 말고, 파일 권한을 제한하세요.")
	return nil
}

// bootstrapCloudInit 은 스크립트를 파일로 쓰고 한 번 실행한 뒤 지우는 cloud-init 설정입니다.
// base64 로 넣어 YAML 이스케이프 문제를 피합니다. /run 은 재부팅하면 비워집니다.
func bootstrapCloudInit(script string) string {
	return "#cloud-config\n" +
		"write_files:\n" +
		"  - path: /run/kpctl-bootstrap.sh\n" +
		"    permissions: '0700'\n" +
		"    encoding: b64\n" +
		"    content: " + base64.StdEncoding.EncodeToString([]byte(script)) + "\n" +
		"runcmd:\n" +
		"  - [sh, -c, 'bash /run/kpctl-bootstrap.sh; rm -f /run/kpctl-bootstrap.sh']\n"
}

// bootstrapScript 는 VM 에서 실행할 스크립트입니다. 넣는 값은 호출하는 쪽에서 형식을 검사했습니다.
func bootstrapScript(controllerURL, token, ca, controllerIP string) (string, error) {
	u, err := url.Parse(controllerURL)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, `#!/bin/bash
# kpctl 자동 등록 (kpctl bootstrap 이 생성). 등록 토큰이 들어 있으니 비밀번호처럼 다루세요.
set -euo pipefail

URL='%s'
HOST='%s'
IP='%s'

if [ -w /var/log ]; then exec > >(tee -a /var/log/kpctl-bootstrap.log) 2>&1; fi
echo "■ kpctl 자동 등록: $(hostname) → $URL"

# 컨트롤러·빌드 서버는 패치 대상이 아닙니다.
for f in /etc/kpctl/controller.json /etc/kpctl/builder.json; do
  if [ -e "$f" ]; then echo "!! 이 서버는 kpctl 컨트롤러 또는 빌드 서버입니다 ($f). 등록하지 않습니다"; exit 1; fi
done

# 같은 이름으로 등록하면 기존 호스트 기록을 대체하므로, 이미지 기본 이름으로는 등록하지 않습니다.
case "$(hostname)" in
  localhost|localhost.localdomain|ubuntu)
    echo "!! 호스트 이름이 '$(hostname)' 입니다. VM 마다 다른 이름을 정한 뒤 다시 실행하세요"; exit 1 ;;
esac

umask 077
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
cat > "$W/token" <<'KPCTL_EOF'
%s
KPCTL_EOF
`, controllerURL, u.Hostname(), controllerIP, token)

	if ca != "" {
		fmt.Fprintf(&b, "cat > \"$W/ca.crt\" <<'KPCTL_EOF'\n%s\nKPCTL_EOF\nCURL_CA=(--cacert \"$W/ca.crt\")\nINSTALL_CA=(\"$W/ca.crt\")\n",
			strings.TrimSpace(ca))
	} else {
		b.WriteString("CURL_CA=()\nINSTALL_CA=()\n")
	}

	b.WriteString(remote.PinHostsFunc)
	b.WriteString(`
# 관리망 DNS 를 쓰지 않는 VM 도 컨트롤러를 찾을 수 있도록 (cloud-init 이 /etc/hosts 를 다시 써도 남게)
if [ -n "$IP" ] && ! getent hosts "$HOST" >/dev/null; then
  kpctl_pin_host "$IP" "$HOST"
  echo "  /etc/hosts 에 $HOST → $IP 고정"
fi

# 부팅 직후에는 네트워크가 아직 없을 수 있어 5분간 다시 시도합니다.
echo "■ 에이전트 묶음 받기"
for i in $(seq 1 30); do
  if printf 'header = "Authorization: Bearer %s"\n' "$(cat "$W/token")" |
     curl -fsS --max-time 120 -K - ${CURL_CA[@]+"${CURL_CA[@]}"} -o "$W/agent.tgz" "$URL/api/bootstrap/agent.tar.gz"; then
    break
  fi
  if [ "$i" = 30 ]; then echo "!! 컨트롤러에서 묶음을 받지 못했습니다"; exit 1; fi
  echo "  다시 시도 ($i/30)"
  sleep 10
done

tar xzf "$W/agent.tgz" -C "$W"
bash "$W/agent/install-agent.sh" "$URL" "@$W/token" ${INSTALL_CA[@]+"${INSTALL_CA[@]}"}
`)
	return b.String(), nil
}
