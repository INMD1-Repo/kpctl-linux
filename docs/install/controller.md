# 컨트롤러 설치

[설치 순서](README.md)

`dist/controller/` 전체를 서버에 복사하고 root로 설치합니다. 가장 쉬운 방법은 인자 없이 터미널에서 실행하는 질문형입니다.

```sh
cd dist/controller
sudo ./setup-controller.sh
```

질문형은 이 서버의 IPv4 NIC를 보여 줍니다. 기본 경로가 아닌 사설망 NIC가 하나뿐이면 그 NIC를 관리망으로 제안하고, 도메인(`mgmt.internal`), 이름(`ctl.<도메인>`), 컨트롤러 IP, DHCP 범위의 기본값을 계산합니다. 설치 전에 같은 설치를 다시 할 수 있는 한 줄 명령을 보여 주고 확인을 받습니다. 관리망 NIC를 고르지 않으면 DHCP 없이 설치합니다.

옵션으로 바로 설치할 수도 있습니다. 아래 주소는 설명용입니다. 실제 값을 넣기 전에 `-D`로 계산 결과만 확인할 수 있으며, `-D`는 아무것도 바꾸지 않습니다.

```sh
sudo ./setup-controller.sh -N eno2 -D                                   # 관리망 NIC 하나로 IP·범위·이름 계산
sudo ./setup-controller.sh -n ctl.mgmt.example.test -i 192.0.2.10 -u ops -S -y   # 관리망 DHCP 없이
```

이미 설치한 컨트롤러에서 다시 실행하면 `/etc/kpctl/kpctl.env`의 이름·IP·SSH 계정을 그대로 씁니다. TLS 인증서와 호스트 설정이 어긋나지 않게 하기 위해서입니다. 바꾸려면 `-n`·`-i`·`-u`를 줍니다.

`-S`는 서비스 시작을 생략하고 `-y`는 SSH 키 선택 질문을 생략합니다. 준비한 설치용 개인키는 `-k`, 추가 관리자 키는 반복 가능한 `-b`로 지정합니다. 스크립트가 토큰·사설 CA·서버 인증서·설치용 SSH 키와 기본 설정을 만듭니다. 기존 설정과 키가 있으면 해당 생성 부분은 보존합니다.

## 초기 설정

<a id="module-signing-key"></a>

### 공통 라이브패치 모듈 서명 키 준비

설치 후 컨트롤러에서 한 번 실행합니다. 예시 키 ID는 `prod-2026`입니다. 기존 개인키·인증서나 외부 서명 명령을 운영 중이면 해당 설정을 계속 사용할 수 있습니다. 이미 배포한 키를 교체할 때는 [키 교체 순서](../operations/secure-boot.md#key-rotation)를 따릅니다.

```sh
# 처음에만 상위 디렉터리를 준비합니다. 이미 있으면 소유자와 권한을 확인합니다.
sudo mkdir -m 0700 /etc/kpctl/signing && sudo chown kpctl:kpctl /etc/kpctl/signing
sudo -u kpctl -- kpctl signing init-key prod-2026
sudo -u kpctl -- sha256sum /etc/kpctl/signing/prod-2026/module.der
sudo -u kpctl -- openssl x509 -inform DER -in /etc/kpctl/signing/prod-2026/module.der -noout -subject -enddate -fingerprint -sha256
```

`init-key`는 API 토큰 없이 로컬에서 RSA-3072 개인키와 유효기간 5년의 자체 서명 DER 인증서를 만듭니다. 키 ID별 디렉터리는 0700, 두 파일은 실행 계정 소유의 0600입니다. `-dir /절대/경로`로 기존의 보호된 상위 디렉터리를 지정할 수 있습니다. 명령은 두 파일을 함께 게시하고 이미 존재하는 ID에서는 중단합니다. 출력의 공개 DER SHA256을 보관해 콘솔의 인증서와 대조하세요. 개인키는 컨트롤러와 접근이 제한된 암호화 백업에만 보관하세요. 서비스의 무인 서명을 위해 개인키 파일 자체에는 암호가 걸려 있지 않습니다.

키 생성이 강제 종료되면 상위 디렉터리에 개인키를 담은 `.init-key-*`가 남을 수 있습니다. 먼저 생성 작업을 함께 수행하는 운영자와 점검 시간을 잡고 새 생성을 일시 중지하세요. 실행 중인 프로세스, 남은 디렉터리의 정확한 이름·소유자·권한·시각과 최종 키 ID 디렉터리를 확인합니다.

```sh
pgrep -af '[k]pctl signing init-key'
sudo -u kpctl -- find /etc/kpctl/signing -mindepth 1 -maxdepth 1 -type d -name '.init-key-*' -ls
sudo -u kpctl -- ls -ld /etc/kpctl/signing/prod-2026
```

사용 중인 작업이 없고 중단된 시도의 임시 디렉터리임을 확인한 경우에만, 목록에서 확인한 **정확한 이름 하나**로 `sudo -u kpctl -- rm -rI -- /etc/kpctl/signing/.init-key-정확한이름`을 실행합니다. 경로 확인에는 메타데이터만 사용하고 백업 범위에서도 버려진 임시 키를 확인하세요. 최종 디렉터리가 있으면 그 공개 DER의 지문을 확인하고 기존 키를 보존합니다.

Ubuntu shim의 모듈 전용 EKU `1.3.6.1.4.1.2312.16.1.2`와 codeSigning을 사용합니다. 부팅에는 Ubuntu가 배포한 서명된 shim·GRUB·GA 커널을 사용하고, kpctl은 승인된 `.ko` 사본에 서명합니다. [Ubuntu Secure Boot 문서](https://documentation.ubuntu.com/security/security-features/platform-protections/secure-boot/)

대상에서 `uname -r`과 `cat /proc/version_signature`로 GA 커널 릴리스를 확인합니다. 다음은 **컨트롤러에서** 실행하는 예시이며 `K`는 대상의 실제 릴리스로 바꿉니다. 대상 ABI마다 컨트롤러에서 실행 가능한 `sign-file`과 그 라이브러리가 필요합니다. 대상과 컨트롤러의 Ubuntu 시리즈가 달라 패키지가 현재 저장소에 없으면 관리자가 해당 ABI의 도구를 별도 경로에 준비해 서명 명령에 지정합니다.

```sh
K=6.8.0-85-generic
sudo apt-get install openssl "linux-headers-$K"
sudo -u kpctl -- openssl cms -help >/dev/null 2>&1 && echo "OpenSSL CMS 실행 확인"
sudo -u kpctl -- test -x "/usr/src/linux-headers-$K/scripts/sign-file"
sudo -u kpctl -- test -r /etc/kpctl/signing/prod-2026/module.priv
sudoedit /etc/kpctl/controller.json
```

초기 설치의 빈 최상위 `"sign_command": []` 항목을 제거하고 아래 예시의 `signing` 블록을 기존 설정에 병합합니다. 토큰, TLS와 다른 운영 설정은 설치 시 생성한 값을 사용하세요. 키 생성 CLI는 설정 파일을 편집하지 않습니다. 외부 래퍼·HSM 서명도 실제 서명자에 해당하는 DER 파일을 `cert`에 지정하세요. 컨트롤러 서비스의 PATH에서 OpenSSL CMS 검증을 실행할 수 있어야 승인됩니다. 경로의 `{kernel}`은 승인 작업의 대상 릴리스로 치환됩니다. [Linux 모듈 서명 도구](https://docs.kernel.org/admin-guide/module-signing.html)

<!-- config-example: controller -->
```json
{
  "listen": ":8443",
  "tls_cert": "/etc/kpctl/tls/server.crt",
  "tls_key": "/etc/kpctl/tls/server.key",
  "data_dir": "/var/lib/kpctl",
  "admin_tokens": {"ops": "replace-with-admin-token-0123456789"},
  "builder_token": "replace-with-builder-token-0123456789",
  "enroll_tokens": [
    {"name": "canary", "token": "replace-with-canary-token-0123456789", "ring": 1, "reboot_policy": "drain"},
    {"name": "server", "token": "replace-with-fleet-token-0123456789", "ring": 2, "reboot_policy": "drain"}
  ],
  "rings": [1, 2],
  "min_soak_minutes": {"2": 1440},
  "auto_rollout": {"enabled": false},
  "signing": {
    "mode": "always",
    "keys": [{
      "id": "prod-2026",
      "active": true,
      "cert": "/etc/kpctl/signing/prod-2026/module.der",
      "sign_command": ["/usr/src/linux-headers-{kernel}/scripts/sign-file", "sha256", "/etc/kpctl/signing/prod-2026/module.priv", "/etc/kpctl/signing/prod-2026/module.der", "{module}"]
    }]
  },
  "test_vm": {"enabled": false}
}
```

이 예시는 TLS·키 파일을 생성하지 않습니다. 서비스 사용자 `kpctl`이 필요한 키·인증서와 서명 도구를 읽거나 실행할 수 있어야 합니다. 인증서 ID와 DER 해시는 상태에 고정하므로 같은 ID의 인증서 본문을 교체하면 시작을 거부합니다. 새 인증서는 새 ID로 추가합니다.

외부 서명 명령을 사용하면 인자에는 파일 경로나 안전한 키 참조만 지정하세요. 개인키 본문·암호·PIN은 인자나 도구의 표준 출력·오류에 기록하지 않습니다. 공통 키를 읽을 수 있는 계정·프로세스는 그 키를 신뢰하는 모든 대상에 서명할 수 있으므로 서비스 계정 접근과 백업 복호화 권한을 제한하세요.

VM 검사는 위 예시에서 꺼져 있습니다. [고정 VM 예시](../../configs/testvm.example.json) 또는 [일회용 QEMU 예시](../../configs/testvm-qemu.example.json)의 `test_vm`을 환경에 맞춰 구성하세요. SSH 키·이미지·NVRAM 파일과 필요한 모드의 VM을 준비한 뒤 활성화합니다. 상세 조건은 [F22](../features/test-vm.md#f22)에 있습니다.

## 시작과 확인

```sh
sudo systemctl enable kpctl-controller
sudo systemctl restart kpctl-controller  # 시작 또는 변경한 설정 다시 읽기
sudo kpctl status
sudo kpctl signing list
```

CLI는 환경 변수 `KPCTL_URL`, `KPCTL_TOKEN`, `KPCTL_CA`를 우선 사용하고 비어 있으면 `/etc/kpctl/kpctl.env`에서 읽습니다. 관리자 웹은 같은 컨트롤러 주소로 접속합니다. Settings에서 변경한 운영 값은 재시작 후에도 `settings.json`으로 유지되며 설정 파일 값보다 우선합니다.

TLS 파일이 없으면 서버는 HTTP를 사용할 수 있지만 코드가 시험 용도로 경고합니다. 실제 설치에는 TLS와 CA를 구성하세요. 키 파일 오류, 중복 active 키, 충돌하는 서명 설정은 시작 또는 승인을 막습니다. [서명 운영](../operations/secure-boot.md)과 [문제 해결](../reference/troubleshooting.md)을 확인합니다.

근거: [설치 스크립트](../../deploy/setup-controller.sh), [설정](../../internal/controller/config.go)의 `LoadConfig`, [서비스](../../deploy/systemd/kpctl-controller.service), [서명](../../internal/controller/signing.go)의 `validateSigning`·`signingCerts`, [CLI 환경](../../cmd/kpctl/main.go)의 `loadEnvFile`.
