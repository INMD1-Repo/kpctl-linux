# 업그레이드와 복구

<a id="upgrade"></a>

컨트롤러, CLI, 에이전트 설치 묶음, 빌더 바이너리와 외부 도우미는 같은 버전으로 맞춰 관리합니다. 프로그램 갱신 자체는 호스트 재부팅 승인을 만들지 않습니다. 운영 서버를 갱신하기 전에는 현재 설정·상태·적용 버전과 진행 중인 작업을 먼저 확인하세요.

> **외부 서명기 사용 시 주의**: 업그레이드 전에 실제 서명자에 대응하는 공개 DER가 설정되어 있는지 확인하세요. 검증할 DER를 찾을 수 없는 래퍼·HSM 명령 또는 `cert`가 없는 명시적 키는 업그레이드 직후부터 해당 키의 서명 승인이 차단됩니다. 시작 감사 로그와 `sudo kpctl signing list`에서 사유를 확인할 수 있습니다.

---

## 빠른 업데이트 (`kpctl update`)

<a id="git-update"></a>

컨트롤러나 빌더 서버에서 `kpctl update`를 실행하면 **현재 서버에 설치된 역할을 자동으로 감지**하고, Git에서 새 버전을 받아 빌드·교체·서비스 재시작까지 한 번에 진행합니다. API 토큰(`/etc/kpctl/kpctl.env`) 없이 로컬에서 바로 동작합니다.

### 1. 채널별 실행 방법

| 원하는 동작 | 명령 | 설명 |
| --- | --- | --- |
| 업데이트 여부만 확인 | `kpctl update -check` | 파일 변경·재시작 없이 현재 설치 버전, 감지된 역할, 새 커밋 목록만 출력 |
| 릴리즈 버전 업데이트 (기본) | `sudo kpctl update` | 원격 릴리즈(`origin/main`)와 현재 설치 버전을 비교해 최신 릴리즈로 갱신 |
| 개발 버전 업데이트 | `sudo kpctl update -dev` | 원격 개발 브랜치(`origin/Dev`)로 전환·pull 후 갱신 |
| 현재 브랜치 최신 커밋 반영 | `sudo kpctl update now` | 브랜치를 바꾸지 않고 현재 체크아웃된 자기 브랜치의 최신 커밋으로 갱신 (`-now`와 동일) |
| 강제 재빌드·재설치 | `sudo kpctl update -force` | 이미 같은 커밋이 설치되어 있어도 다시 빌드해 덮어씀 |
| 관리자 웹까지 다시 빌드 | `sudo kpctl update -web` | `npm`으로 React 관리자 웹을 다시 빌드해 컨트롤러 바이너리에 포함 |

> **팁**: `kpctl update now`는 원격에 같은 이름의 브랜치가 있으면 최신 커밋을 fast-forward로 가져오고, 로컬 브랜치가 원격보다 앞서 있거나 로컬 전용 브랜치이면 현재 브랜치의 최신 커밋으로 바로 빌드·설치합니다.

### 2. `git pull` 시 자동 업데이트 (Git `post-merge` 훅)

`kpctl update`를 한 번 실행하면 해당 저장소에 `post-merge` 훅이 자동으로 설치됩니다(생략하려면 `-no-hook`). 업데이트 없이 훅만 따로 관리할 수도 있습니다.

```sh
kpctl update -install-hook      # 저장소에 git pull 자동 업데이트 훅 설치
kpctl update -uninstall-hook    # 설치한 자동 업데이트 훅 제거
```

훅이 설치된 저장소에서 `git pull`을 실행하면 다음 순서로 자동 동작합니다.

1. `git pull`로 새 커밋이 병합되면 `post-merge` 훅이 `kpctl update -from-hook`을 호출합니다.
2. 설치된 역할이 없으면(예: 개발 PC) 오류 없이 조용히 건너뜁니다.
3. 컨트롤러나 빌더가 설치된 서버이고 커밋이 바뀌었으면 자동으로 빌드·설치·재시작합니다.

- 한 번만 자동 업데이트를 건너뛰려면 `KPCTL_SKIP_AUTO_UPDATE=1 git pull`을 사용하세요.
- 기존에 직접 만들어 둔 다른 `post-merge` 훅이 있으면 덮어쓰지 않고 안내 후 중단합니다.

### 3. 역할 자동 감지 및 갱신 범위

| 감지 역할 | 자동 감지 기준 | 갱신되는 파일 | 재시작 서비스 |
| --- | --- | --- | --- |
| 컨트롤러 | `kpctl-controller.service`, `/etc/kpctl/controller.json`, `/usr/local/bin/kpctl-controller` | `/usr/local/bin/{kpctl-controller,kpctl}`, `/usr/local/share/kpctl/{agent,builder}`, `/usr/local/libexec/kpctl-cve-inventory`, 컨트롤러 관련 systemd 유닛 | `kpctl-controller` |
| Ubuntu 빌더 | `kpctl-builder.service`, `/etc/kpctl/builder.json` | `/usr/local/bin/{kpctl-builder,kpctl}`, `/usr/local/sbin/kpctl-kernel-debug`, `/usr/local/libexec/kpctl-kernel-inputs`, sandbox 빌드 환경 도우미·레시피, `kpctl-builder.service` | `kpctl-builder` |
| Debian·Rocky 네이티브 빌더 | `kpctl-native-builder.{service,timer}`, `/etc/kpctl/native-builder/worker.json`, `/opt/kpctl/native-builder/kpctl-native-builder.py` | `/usr/local/bin/{kpctl-builder,kpctl}`, `/opt/kpctl/native-builder/*`, `kpctl-native-builder.{service,timer}` | `kpctl-native-builder.timer` |

- **보존되는 항목**: `/etc/kpctl/*.json` 설정, 토큰, TLS 인증서, 서명 키, SSH 키, `/var/lib/kpctl*` 데이터 디렉터리, 빌더 서비스의 커스텀 `User=`/`Group=`과 drop-in 설정(`*.service.d/`)은 건드리지 않습니다.
- **안전 장치**: 저장소에 커밋되지 않은 변경이 있으면 pull을 거부합니다. 네이티브 빌더는 진행 중인 커널 빌드를 끊지 않도록 타이머만 재시작합니다.
- **저장소 탐색 순서**: `-repo` → `KPCTL_REPO_DIR` → `/etc/kpctl/update.json`에 기록된 경로 → 현재 디렉터리의 Git 저장소 → `/opt/kpctl/src`(없으면 자동 복제).
- **유용한 보조 옵션**: `-role controller|builder|native-builder`(역할 수동 지정), `-branch <이름>`(특정 브랜치 지정), `-no-restart`(파일만 교체하고 재시작 생략).

---

<a id="backup"></a>

## 일관된 백업

큰 업그레이드 전에는 자동 진행을 멈추고 진행 중인 승인·VM 시험·빌드 결과 전송과 재부팅 승인을 정리한 뒤 서비스를 정상 중지해 백업합니다. 이미 적용된 에이전트 모듈은 컨트롤러 중지만으로 제거되지 않습니다.

| 서버 | 함께 보존할 자료 |
| --- | --- |
| 컨트롤러 | `/etc/kpctl/`의 설정·토큰·TLS·서명 키·SSH 자료, 전체 `data_dir`의 state/settings/patches/artifacts/logs/testlogs/coverage/audit |
| 빌더 | builder 설정·CA, 전체 `work_dir`, 명시한 원본 저장소·프로파일·입력 경로와 도우미 버전 |
| 에이전트 | agent 설정, `/var/lib/kpctl-agent/`의 등록·실행·MOK 결과·준비 기록, `/var/lib/kpatch/` 설치 사본, 수정한 재부팅 훅 |

서명 개인키가 설정 디렉터리 밖에 있으면 그 경로도 포함합니다. `.unsigned-*`와 `signed-<키>/`를 포함한 artifacts 전체가 원본 pin·키별 메타데이터와 한 시점이어야 하므로 숨김 파일을 제외하는 복사 명령을 사용하지 않습니다. 비밀번호 원문을 가진 state와 개인키·토큰 백업은 접근을 제한하고 안전한 위치에 보관합니다.

---

## 수동 업그레이드 절차

### 컨트롤러·CLI (배포 묶음 방식)

폐쇄망 등 서버에서 직접 `git pull`·빌드를 할 수 없는 환경에서는 빌드 머신에서 `make dist`로 만든 `dist/controller`를 복사해 수동으로 갱신합니다. 설치 스크립트는 기존 설정·키를 재사용하지만 변경점을 먼저 비교하세요.

```sh
sudo systemctl stop kpctl-controller
# dist/controller 의 파일 설치 (docs/install/controller.md 절차)
sudo systemctl daemon-reload
sudo systemctl start kpctl-controller
sudo journalctl -u kpctl-controller --since '-10 minutes'
sudo kpctl status
sudo kpctl signing list
```

명령 사이의 파일 설치는 [컨트롤러 설치](../install/controller.md)의 배포 묶음 절차를 따릅니다. 시작 중 인증서 ID의 DER pin이 다르다고 거부되면 상태 파일에서 pin을 지우지 말고 새 ID로 교체 절차를 진행하세요. 중단된 VM 시험은 시작 복구에서 정리되고 실패로 표시됩니다.

### 서명 필요 호스트의 업그레이드 점검

업그레이드 전에 `sudo kpctl hosts`와 `sudo kpctl signing list`로 서명 필요·상태 미확인 호스트와 현재 서명 설정을 대조합니다.

- 새 에이전트가 Secure Boot on, lockdown, 강제 서명 또는 보안 신호 `unknown`을 보고하면 서명 미설정 상태에서는 이후 누적본 배포가 `blocked_signing_disabled`로 제외됩니다. 서명 메타데이터가 없는 이전 승인 작업은 `blocked_artifact`가 될 수 있습니다. 기존 적용 모듈은 유지되지만 제외가 풀릴 때까지 새 CVE 패치는 적용되지 않습니다.
- 서명 명령을 쓰는 경우 컨트롤러의 OpenSSL CMS, 대상 ABI용 `sign-file`, 실제 서명자와 일치하는 공개 DER를 먼저 준비합니다. 래퍼 뒤에 인증서 경로가 숨겨져 있으면 기존 명령을 `signing.keys[].sign_command`로 옮기고 `id: default`, `active: true`, `cert`에 같은 인증서를 지정합니다.
- 시험 컨트롤러의 canary에서 새 누적본 승인·서명 SHA·실제 적용까지 확인한 뒤 운영 호스트를 갱신합니다. [등록과 적용 확인](secure-boot.md#mok-enrollment)

### 빌더와 에이전트

#### Ubuntu 빌더의 원격 바이너리 자동 갱신 (`self_update`)

컨트롤러가 갱신되면 `/usr/local/share/kpctl/builder/kpctl-builder`도 함께 바뀝니다. Ubuntu 빌더에 `self_update=true`와 서비스의 `KPCTL_BUILDER_UPDATE_PATH`가 켜져 있으면 빌더가 인증된 HTTPS로 새 바이너리의 SHA를 확인하고 `-h` 실행 시험 뒤 종료 코드 `75`로 재시작하며, systemd가 `kpbuild` 소유 단일 링크 일반 파일만 root로 설치합니다.

> **참고**: `self_update`는 `kpctl-builder` 실행 파일만 교체합니다. Python 도우미·컨테이너 레시피·systemd 유닛까지 함께 최신화하려면 빌더 서버에서 `sudo kpctl update`를 실행하거나 같은 배포본을 설치하세요.

업그레이드 전에는 진행 중인 빌드가 결과를 전송하도록 기다립니다. 새 빌더 설정은 다음 명령으로 미리 검사할 수 있습니다.

```sh
sudo -u kpbuild -H /usr/local/bin/kpctl-builder -config /etc/kpctl/builder.json -check-config
```

#### 에이전트 갱신

에이전트는 새 묶음을 사용하는 `kpctl install` 또는 호스트 설치 스크립트 재실행으로 갱신합니다. 등록 정보·적용 패치·기존 재부팅 훅은 보존되지만 `agent.json`을 새로 생성하므로 커스텀 설정은 미리 비교·백업하세요. MOK의 `awaiting_agent`가 지속되면 에이전트 갱신 후 최근 빈 목록 보고를 확인합니다. [MOK 예약 복구](secure-boot.md#mok-enrollment)

---

<a id="downgrade"></a>

## 이전 버전으로 복구

일반 추가 필드는 구 버전 JSON 읽기에 무시될 수 있어도 모든 상태 의미가 호환되는 것은 아닙니다. 특히 음수 출시 전 작업·링 overlay는 이전 컨트롤러에서 복구 호환을 보장하지 않습니다. 새 컨트롤러가 동작할 때 다음 순서로 정리하세요.

1. 출시 전 수집을 끄고, 대기·진행·built 음수 작업과 대상 호스트를 검토합니다. 운영 목표를 명시적인 정식 released 버전으로 되돌리고 overlay가 해제됐는지 확인합니다.
2. 호스트의 실제 정식 모듈 적용·전환 완료와 재부팅 요청 없음, MOK 예약 상태를 확인합니다. 원래 자료를 보존한 백업을 만듭니다.
3. 승인된 복구 시점의 실행 파일·설정·**전체 상태와 artifacts**를 일관되게 복원합니다. 새 메타데이터에 옛 artifacts만 섞거나 state만 과거로 덮지 않습니다.
4. 자동 진행을 멈춘 채 시작하여 링 목표·실제 버전·키별 사본·원본 pin·빌더 호환을 재확인한 뒤 운영자가 재개합니다.

원본 pin이 없는 과거 released 작업의 키 교체는 추정으로 허용하지 않으며 [키 교체](secure-boot.md#key-rotation)의 새 누적본 경로를 사용합니다.

근거: [상태 저장](../../internal/controller/state.go), [자동 업데이트 CLI](../../cmd/kpctl/update.go), [업데이트 엔진](../../internal/updater/updater.go), [빌더 갱신](../../internal/builder/selfupdate.go), [제공 바이너리](../../internal/controller/builder_update.go), [에이전트 재설치](../../deploy/install-agent.sh), [VM 복구](../../internal/controller/testvm.go).
