# 대상 에이전트 설치

[설치 순서](README.md)

실행 커널과 Ubuntu signature가 기본 GA 대상인지 먼저 확인합니다. 에이전트는 컨트롤러로 연결해 보고하며 호스트에서 수신 포트를 열지 않습니다. 모듈과 부팅 설정을 다루므로 서비스는 root로 실행합니다.

## SSH 설치

컨트롤러에 설치 묶음, 호스트 SSH 키와 신뢰할 호스트 키 기록을 준비합니다. 설치 명령은 먼저 점검 모드로 실행할 수 있습니다.

```sh
sudo kpctl install -check -group canary node-01
sudo kpctl install -group canary node-01
sudo kpctl hosts
```

터미널에서 인자 없이 `sudo kpctl install`만 실행하면 질문형으로 설치합니다. 호스트 지정 방법(직접 입력·목록 파일·DHCP 미등록 호스트), SSH 접속 계정, 등록 그룹을 묻고 점검 → 확인 → 설치 순서로 진행하며, 같은 설치를 다시 할 명령줄도 보여 줍니다. 그룹은 등록 토큰의 링과 재부팅 정책을 선택합니다. `kpctl install`은 접속·권한·커널 기능·컨트롤러 접근을 점검하고 설치 묶음을 보내 등록을 확인합니다. 추가 SSH 키 관리는 `kpctl ssh-key list`와 `kpctl ssh-key add`를 사용합니다. 실제 옵션은 [CLI 정의](../../cmd/kpctl/install.go)와 [SSH 옵션](../../cmd/kpctl/sshflags.go), [질문형 설치](../../cmd/kpctl/wizard.go)에 있습니다.

### 점검 항목

점검은 호스트를 바꾸지 않습니다. **문제**가 있으면 설치하지 않고(`-force`로 무시), **경고**는 알리기만 합니다. 판정 규칙은 [hostcheck.go](../../internal/remote/hostcheck.go) 한 곳에 있습니다. 실패 문구별 해결과 원인이 겹칠 때의 결과는 [설치·커널 준비 문제 해결](../operations/install-troubleshooting.md)에 있습니다.

| 구분 | 상황 | 대응 |
|---|---|---|
| 문제 | 컨테이너 안, systemd 아님, `CONFIG_LIVEPATCH` 없음 | VM·물리 서버의 livepatch 커널에 설치 |
| 문제 | `/lib/modules/<실행 커널>` 없음 (실행 중인 커널 패키지 삭제됨) | 설치된 커널로 재부팅 후 다시 설치 |
| 문제 | `/var` 여유 500MB 미만, 컨트롤러·빌드 서버 | 공간 확보, 다른 호스트 선택 |
| 경고 | 지원 LTS의 GA generic 커널이 아님 (HWE 등) | 패치 자동 빌드 안 됨 — 커널 점프로 GA 커널 준비 |
| 경고 | Secure Boot·커널 lockdown | 서명 인증서 MOK 등록 |
| 경고 | 다른 라이브패치(`kpctl_` 외)가 올라가 있음 | 재부팅 전까지 kpctl 패치 적용 안 됨 |
| 경고 | GRUB 아님, `/boot`가 LVM·RAID·ext 아님, 미러 목록 전체 접속 불가 | 다음 GA 커널 자동 준비 불가 — 수동 교체 |
| 경고 | 공식 저장소만 접속 불가 | 설치·커널 준비가 한국 미러(KAIST → 카카오)로 자동 전환. 순서는 [미러 목록](../operations/install-troubleshooting.md#mirrors) |
| 경고 | `/boot` 여유 300MB 미만 | `apt autoremove --purge` (다음 GA 커널 준비에 필요) |
| 경고 | 시계가 5분 넘게 어긋남 | `timedatectl set-ntp true` (TLS 검증 실패 방지) |
| 자동 | dpkg 중단 상태, python3 없음 | 설치 스크립트가 `dpkg --configure -a`, python3 설치 |

## 로컬 설치

호스트에 `dist/agent/`와 신뢰할 CA, 등록 토큰 파일을 전달한 뒤 실행합니다. `@파일`은 토큰을 프로세스 인자로 직접 넣지 않는 입력 형식입니다.

```sh
cd dist/agent
sudo ./install-agent.sh https://ctl.mgmt.example.test:8443 @/secure/enroll-canary.token /secure/ca.crt
```

선택 옵션 `--enroll-mok`를 뒤에 추가하면 서명이 필요하고 active 인증서가 미등록인 호스트에서 컨트롤러에 등록 예약을 요청합니다. 기본은 요청하지 않습니다. 예약은 재부팅을 실행하지 않으며 비밀번호 조회·콘솔 승인은 [Secure Boot 절차](../operations/secure-boot.md)를 따릅니다.

설치 스크립트는 kpatch 런타임을 설치하고 Canonical Livepatch 서비스와 커널 자동 갱신·자동 재부팅 정책을 조정합니다. 재실행 시 `agent.json`은 설치 인자로 다시 작성하므로 기존 수동 설정을 먼저 보관하세요. 등록 상태와 이미 적용한 모듈, 기존 재부팅 훅은 유지합니다.

## 직접 설정할 때

<!-- config-example: agent -->
```json
{
  "controller_url": "https://ctl.mgmt.example.test:8443",
  "enroll_token": "replace-with-canary-token-0123456789",
  "ca_file": "/etc/kpctl/ca.crt",
  "state_dir": "/var/lib/kpctl-agent",
  "interval_seconds": 60,
  "reboot_hook": "/etc/kpctl/reboot-hook.sh",
  "mok_auto_import": false
}
```

기본 보고 간격은 60초입니다. 적용 실패 뒤 같은 버전의 재시도는 10분 동안 기다릴 수 있으므로 보고 간격이 적용 완료 기한은 아닙니다. 보안 수집 실패는 경고로 분리하며 기존 상태를 `off`로 꾸미지 않습니다.

다음 커널 준비와 재부팅은 다른 작업입니다. `kpctl host reboot`는 이미 검증된 목표 커널을 지정해 1회 승인하며 VM과 boot ID 조건을 다시 검사합니다. 설치·MOK 예약만으로 재부팅이 승인되지 않습니다.

제거 시 `kpctl uninstall`은 기본으로 적용한 라이브패치를 유지합니다. `-remove-patches`를 명시하면 보호를 해제할 수 있습니다. 로컬 제거 스크립트도 기본으로 모듈을 유지하고 커널 hold와 재부팅 훅은 남깁니다.

근거: [설치](../../deploy/install-agent.sh), [제거](../../deploy/uninstall-agent.sh), [설정](../../internal/agent/config.go)의 `LoadConfig`, [보고·적용](../../internal/agent/agent.go)의 `cycle`·`apply`, [실행 전 승인 검사](../../internal/agent/reboot.go), [원격 설치](../../internal/remote/steps.go)의 `Preflight`·`Install`.
