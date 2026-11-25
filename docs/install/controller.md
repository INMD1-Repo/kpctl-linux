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

설치 스크립트가 처음 만드는 설정에는 서명 명령이 비어 있습니다. 운영 서명 키를 준비한 다음 `/etc/kpctl/controller.json`을 편집하세요. 새 `signing` 블록을 사용할 때에는 기존 `sign_command` 항목을 제거해야 합니다.

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
      "cert": "/etc/kpctl/keys/prod-2026.der",
      "sign_command": ["/usr/src/linux-headers-{kernel}/scripts/sign-file", "sha512", "/etc/kpctl/keys/prod-2026.priv", "/etc/kpctl/keys/prod-2026.der", "{module}"]
    }]
  },
  "test_vm": {"enabled": false}
}
```

이 예시는 TLS·키 파일을 생성하지 않습니다. 서비스 사용자 `kpctl`이 필요한 키·인증서와 서명 도구를 읽거나 실행할 수 있어야 합니다. 인증서 ID와 DER 해시는 상태에 고정하므로 같은 ID의 인증서 본문을 교체하면 시작을 거부합니다. 새 인증서는 새 ID로 추가합니다.

VM 검사는 위 예시에서 꺼져 있습니다. [고정 VM 예시](../../configs/testvm.example.json) 또는 [일회용 QEMU 예시](../../configs/testvm-qemu.example.json)의 `test_vm`을 환경에 맞춰 구성하세요. SSH 키·이미지·NVRAM 파일과 필요한 모드의 VM을 준비한 뒤 활성화합니다. 상세 조건은 [F22](../features/test-vm.md#f22)에 있습니다.

## 시작과 확인

```sh
sudo systemctl enable --now kpctl-controller
sudo kpctl status
sudo kpctl signing list
```

CLI는 환경 변수 `KPCTL_URL`, `KPCTL_TOKEN`, `KPCTL_CA`를 우선 사용하고 비어 있으면 `/etc/kpctl/kpctl.env`에서 읽습니다. 관리자 웹은 같은 컨트롤러 주소로 접속합니다. Settings에서 변경한 운영 값은 재시작 후에도 `settings.json`으로 유지되며 설정 파일 값보다 우선합니다.

TLS 파일이 없으면 서버는 HTTP를 사용할 수 있지만 코드가 시험 용도로 경고합니다. 실제 설치에는 TLS와 CA를 구성하세요. 키 파일 오류, 중복 active 키, 충돌하는 서명 설정은 시작 또는 승인을 막습니다. [서명 운영](../operations/secure-boot.md)과 [문제 해결](../reference/troubleshooting.md)을 확인합니다.

근거: [설치 스크립트](../../deploy/setup-controller.sh), [설정](../../internal/controller/config.go)의 `LoadConfig`, [서비스](../../deploy/systemd/kpctl-controller.service), [서명](../../internal/controller/signing.go)의 `validateSigning`·`signingCerts`, [CLI 환경](../../cmd/kpctl/main.go)의 `loadEnvFile`.
