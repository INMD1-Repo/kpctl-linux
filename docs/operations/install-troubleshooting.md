# 설치·커널 준비 문제 해결

<a id="install-troubleshooting"></a>

[운영 안내](README.md) · [에이전트 설치](../install/agent.md) · [재부팅 승인](reboot-approval.md) · [Secure Boot 운영](secure-boot.md) · [증상별 확인 순서](../reference/troubleshooting.md)

에이전트 설치, 라이브패치 적용, 다음 GA 커널 준비 단계에서 표시되는 오류와 조치를 정리합니다.

## 1. 어디서 막혔는지 찾기

| 단계 | 실행 주체 | 실패가 보이는 곳 | 장 |
|---|---|---|---|
| 설치 전 점검 | `kpctl install`, 질문형 설치, `kpctl autoenroll`의 SSH 점검 | 결과 표의 "점검 실패"와 "경고:" 줄, 설치 로그 | [2](#preflight) |
| 설치 스크립트 | `install-agent.sh` (SSH 설치·부트스트랩·로컬 설치 공통) | "설치 실패"와 `!!` 줄 | [3](#script) |
| 등록 | `kpctl-agent -once` (설치 스크립트 마지막) | "설치 실패", 컨트롤러 감사 로그 | [4](#enroll) |
| 패치 적용 | 에이전트 주기 실행 | `kpctl hosts`의 오류·제외 사유, 웹 호스트 화면 | [5](#apply) |
| 다음 GA 커널 준비 | 에이전트 → `kpctl-prepare-kernel` | 웹 "공식 커널 준비 실패: …", `kernel_prepare.error` | [6](#prepare) |

DHCP 부트스트랩(`/api/bootstrap/agent.tar.gz`)은 SSH 점검을 거치지 않습니다. 이 경로에서는 3장의 스크립트 자체 검사만 적용됩니다. `/boot` 여유, 공식 저장소 접속, 시계, 외부 라이브패치는 설치 뒤 5·6장 증상으로 나타납니다.

<a id="preflight"></a>

## 2. 설치 전 점검

점검은 호스트를 바꾸지 않습니다. **문제**가 있으면 설치하지 않습니다(`-force`로 무시 가능). **경고**는 알리기만 합니다. 판정 규칙은 [hostcheck.go](../../internal/remote/hostcheck.go)의 `hostChecks`와 [steps.go](../../internal/remote/steps.go)의 `Preflight`에 있습니다.

| 구분 | 증상(표시 문구) | 원인 | 조치 |
|---|---|---|---|
| 접속 | `SSH 접속 실패` | 키·계정·호스트 키 기록 | 질문형 설치가 키 등록을 제안합니다. 수동으로는 `kpctl ssh-key add` |
| 문제 | `root 가 아니고 비밀번호 없는 sudo 도 안 됩니다` | 계정 권한 | root로 접속하거나 NOPASSWD sudo 설정 |
| 문제 | `아키텍처 불일치` | x86_64 묶음을 arm64에 설치하는 등 | 해당 아키텍처로 `make dist` |
| 문제 | 컨트롤러 접속 실패 (응답 `000`) | 방화벽·DNS·포트 | 이름을 못 찾더라도 SSH로 들어온 주소로 `/healthz`가 200이면 `/etc/hosts`에 `# kpctl` 줄을 자동으로 넣고 경고만 냅니다 |
| 경고 | `curl 이 없어 컨트롤러 접속을 미리 확인하지 못했습니다` | 최소 이미지 | 등록 단계(4장)에서 실제로 확인됩니다 |
| 문제 | `컨트롤러 또는 빌드 서버입니다` | `/etc/kpctl/controller.json`·`builder.json` 있음 | 패치 대상 호스트를 고르세요. auto-enroll은 조용히 건너뜁니다 |
| 문제 | `컨테이너(lxc) 안입니다` | LXC·Docker 등 | 라이브패치는 커널 모듈이므로 VM·물리 서버에만 설치 |
| 문제 | `systemd 로 부팅하지 않은 시스템입니다` | init이 systemd가 아님 | 지원하지 않음 |
| 문제 | `CONFIG_LIVEPATCH=y 가 없습니다` | 커널 기능 없음 | livepatch 커널로 부팅. `/boot/config-*`가 없는 이미지는 `/sys/kernel/livepatch`로 판정합니다 |
| 문제 | `/lib/modules/<커널> 가 없습니다` | 실행 중인 커널 패키지가 지워짐 | 설치된 커널로 재부팅한 뒤 다시 설치 |
| 문제 | `/var 여유 …MB` (500MB 미만) | 디스크 부족 | 공간 확보 |
| 경고 | `GA generic 커널이 아니어서 패치가 자동으로 빌드되지 않습니다` | HWE·파생 커널, 미지원 시리즈 | 7장 C3 |
| 경고 | `Secure Boot 켜짐` / `커널 lockdown(…)` | 서명 모듈만 올라감 | [Secure Boot 운영](secure-boot.md)대로 인증서 등록 |
| 경고 | `다른 라이브패치가 올라가 있습니다 (…)` | `kpctl_`로 시작하지 않는 라이브패치(Canonical `lkp_*` 등) | 7장 C5 |
| 경고 | `/boot/grub/grubenv 가 없어(GRUB 아님)` | systemd-boot 등 | 다음 GA 커널 자동 준비 불가 → 수동 커널 교체 |
| 경고 | `/boot 가 …(…)라 … 자동 준비를 할 수 없습니다` | `/boot`가 ext2/3/4가 아니거나 LVM(`/dev/dm-*`)·RAID(`/dev/md*`) | 자동 준비 불가 → 수동 커널 교체 |
| 경고 | `Ubuntu 공식 저장소에 접속하지 못해 kaist 미러를 씁니다` (또는 `kakao`) | 공식 저장소만 막힘 | 조치 불필요. 설치·커널 준비가 [미러 목록](#mirrors)의 다음 미러로 자동 전환됩니다 |
| 경고 | `mirrors.list 의 Ubuntu 미러에 모두 접속하지 못해` | 공식·KAIST·카카오 HTTP 모두 차단 | 목록의 미러 중 하나를 허용하거나, 사내 미러를 목록에 더하거나, 수동 교체 |
| 경고 | `/boot 여유 …MB` (300MB 미만) | 옛 커널이 쌓임 | `sudo apt autoremove --purge`. 도우미는 256MB 미만이면 거부합니다 |
| 경고 | `dpkg 가 설치 도중 멈춘 상태` | 이전 apt가 중단됨 | 설치 스크립트가 자동으로 복구합니다 (3장) |
| 경고 | `python3 가 없어 설치하며 함께 설치합니다` | 최소 이미지 | 자동 (3장) |
| 경고 | `호스트 시계가 컨트롤러와 … 어긋나` (5분 초과) | NTP 꺼짐 | `sudo timedatectl set-ntp true`. 7장 C9 |
| 경고 | `이미 설치되어 있어 재설치(업그레이드)합니다` | 재설치 | 등록·적용 패치·수정한 재부팅 훅은 유지됩니다. 7장 C12 |

<a id="script"></a>

## 3. 설치 스크립트

[install-agent.sh](../../deploy/install-agent.sh)는 다시 실행해도 안전합니다. 아래 표의 "자동" 행은 스크립트가 스스로 처리합니다.

| 증상 | 원인 | 처리 |
|---|---|---|
| `!! … CONFIG_LIVEPATCH 가 없습니다` / `/lib/modules/… 가 없습니다` / `systemd 로 부팅한 시스템이 아닙니다` / `컨테이너 안에서는…` | 2장과 같음. 부트스트랩·로컬 설치도 여기서 막힘 | 2장 조치 |
| `!! 이 서버는 kpctl 컨트롤러 또는 빌드 서버입니다` | 인프라 서버 | 다른 호스트 선택 |
| `등록 토큰에 영문/숫자/._- 외의 문자가 있습니다` | 토큰 복사 오류 | 토큰 파일 다시 생성 |
| 자동: `dpkg 복구 (dpkg --configure -a)` | dpkg 중단 상태 | 실패하면 `!! dpkg 복구 실패`로 멈춥니다. 출력에 나온 패키지를 직접 고친 뒤 다시 실행 |
| 자동: `저장소 실패 → kaist 미러(…)로 다시 시도` | 호스트 저장소 설정으로 색인을 받지 못함 (`apt-get update`가 경고만 내고 성공으로 끝나는 경우 포함) | [미러 목록](#mirrors)을 위에서부터 시도합니다. 별도 목록 디렉터리(`/var/cache/kpctl-apt-mirror`)에 색인을 받아 이후 설치를 그 미러에서 하고, 호스트의 `sources.list`와 목록은 바꾸지 않습니다 |
| `(mirrors.list 의 미러도 모두 실패: 기존 목록으로 계속)` | 목록의 미러 모두 접속 불가 | 계속 진행. 아래 행으로 이어질 수 있음 |
| 자동: python3 설치. 실패 시 `!! 경고: python3 설치 실패` | 오프라인·저장소 오류 | 설치는 계속됩니다. 패치 적용에는 지장 없고 커널 자동 준비만 안 됩니다. 나중에 `apt-get install python3` |
| `저장소에 kpatch 패키지가 없어 설치 묶음의 kpatch 를 씁니다` | 24.04처럼 패키지가 없는 시리즈, 또는 목록을 못 받음 | 묶음의 kpatch를 설치합니다. `readelf`가 없을 때만 binutils를 설치합니다 |
| `!! 저장소에 kpatch 패키지가 없고 설치 묶음에도 kpatch 가 없습니다` | 묶음 불완전 | `make dist`로 묶음 다시 만들기 |
| apt가 5분 기다린 뒤 실패 | 다른 apt·unattended-upgrades가 잠금을 쥠 | 끝난 뒤 다시 실행 |
| `!! 경고: kpctl-prepare-kernel.py 가 묶음에 없어…` | 오래된·손으로 만든 묶음 | 6장 첫 행. SSH 설치는 이제 이 파일이 없으면 시작 전에 거부합니다 |

<a id="enroll"></a>

## 4. 등록

설치 스크립트 마지막의 `kpctl-agent -once`가 실패하면 스크립트가 멈춥니다. 이때 바이너리와 설정은 설치되었지만 서비스는 켜지지 않은 상태입니다. 원인을 고친 뒤 같은 설치를 다시 실행하면 됩니다.

| 증상 | 원인 | 조치 |
|---|---|---|
| TLS `certificate has expired or is not yet valid` | 호스트 시계 어긋남 | `timedatectl set-ntp true` 후 재설치 |
| TLS `unknown authority` | CA 미지정·다른 CA | `-ca`로 컨트롤러 CA 지정 |
| 401/403 | 토큰이 틀렸거나 그룹 토큰이 교체됨 | 컨트롤러의 `enroll-<그룹>.token` 확인 |
| 접속 거부·시간 초과 | 컨트롤러 중지·방화벽·`/etc/hosts`의 옛 IP | 컨트롤러 상태 확인, `/etc/hosts`의 `# kpctl` 줄 확인 |

<a id="after-reboot"></a>

### 전부 재시작한 뒤 연결이 안 될 때

컨트롤러에서 `kpctl status`를 실행하고, 관리망 이름과 HTTPS 포트에 접근할 수 있는지 확인합니다. 컨트롤러가 한 번도 응답하지 않았다면 에이전트·빌더 설정의 URL과 CA 파일도 확인합니다.

| 증상 | 가능한 원인 | 조치 |
|---|---|---|
| `connection refused` | 컨트롤러 서비스가 부팅 후 시작되지 않음. 사용 중인 관리망 서비스나 타이머도 비활성일 수 있음 | `systemctl status kpctl-controller`와 `systemctl is-enabled kpctl-controller`를 확인합니다. 이 배포에서 사용하는 컨트롤러·관리망 서비스·타이머만 활성화합니다 |
| `lookup … no such host` | cloud-init이 부팅 중 `/etc/hosts`를 다시 작성함 | 사용하는 DNS 또는 `/etc/hosts`를 확인합니다. 호스트명 고정이 필요한 cloud-init 환경에서는 해당 템플릿에도 관리 주소를 유지합니다 |
| 빌더의 관리망 주소가 부팅마다 바뀜 | DHCP 클라이언트 ID가 달라지거나 고정 예약이 없음 | `kpctl dhcp reserve <IP>`로 MAC을 예약하고, DHCP 서버의 예약 정책을 확인합니다 |
| 웹에 빌드 서버가 `failed`로 표시됨 | 컨트롤러 재시작 중 연결이 끊겼거나 빌더 요청이 거부됨 | 빌더 로그와 `last_seen`을 확인합니다. 연결 거부·시간 초과·5xx는 재시도하고, 인증 오류 등 4xx는 실패로 표시합니다 |
| `unknown authority` | 접속하는 클라이언트가 컨트롤러의 사설 CA를 신뢰하지 않음 | 빌더·에이전트의 `ca_file` 또는 관리 장비의 신뢰 저장소에 이 배포의 CA 인증서를 설정합니다 |

<a id="apply"></a>

## 5. 패치 적용

| 증상 | 원인 | 조치 |
|---|---|---|
| `외부 라이브패치 … 가 활성 또는 전환 중이므로 atomic replace 를 실행하지 않습니다` | 다른 공급자의 패치가 올라가 있음. atomic replace가 그 패치를 지우기 때문에 막힘 | 재부팅해서 내려야 합니다. 7장 C5 |
| `… 라이브패치 전환이 끝나지 않아 새 패치를 적용하지 않습니다` / `전환 완료를 확인하지 못했습니다` | 패치된 함수 안에서 잠든 작업 | 다음 주기에 자동 재시도. 계속되면 `/sys/kernel/livepatch/*/transition`과 해당 프로세스 확인 |
| `모듈 해시 불일치` / `ELF 검사 실패` | 전송 손상·프록시 변조·산출물 문제 | 자동으로 적용하지 않습니다. 컨트롤러 산출물과 프록시 확인 |
| `blocked_mok_missing`, MOK pending, `blocked_artifact` | 서명·인증서 | [Secure Boot 운영](secure-boot.md), [증상별 확인 순서](../reference/troubleshooting.md) |
| 패치가 오지 않음 (HWE) | 자동 빌드 대상 아님 | 7장 C3 |

<a id="prepare"></a>

## 6. 다음 GA 커널 자동 준비

에이전트는 실패하면 6시간 뒤에 다시 시도합니다. 원인을 고쳤다면 웹의 **원인 해결 후 다시 준비** 버튼이나 `kpctl host prepare-kernel <호스트>`로 다시 요청하세요. 새 요청은 대기 시간을 한 번 건너뛰고 다음 보고 때 바로 실행됩니다. 같은 요청으로 반복 실행되지는 않습니다. 이 동작은 요청 시각을 기록해서 판단하므로 컨트롤러와 호스트의 시계가 달라도 같습니다.

| 오류 문구 (`kernel_prepare.error`) | 원인 | 조치 |
|---|---|---|
| `커널 준비 도우미 /usr/local/sbin/kpctl-prepare-kernel 가 없습니다` (이전 버전: `fork/exec …: no such file or directory`) | 이전 SSH 설치 묶음에 도우미가 빠져 있었음 | 새 묶음으로 `kpctl install <호스트>` 후 다시 요청. 급하면 `sudo install -m 0755 kpctl-prepare-kernel.py /usr/local/sbin/kpctl-prepare-kernel` |
| `/usr/bin/env: 'python3': No such file or directory` | python3 없음 | `apt-get install python3` 후 다시 요청 |
| `자동 커널 준비에는 boot_target_path가 state_dir/boot-target.json이어야 합니다` | 에이전트 설정 변경 | `agent.json`의 `boot_target_path` 기본값 복원 |
| `unconfigured packages require review before preparing a kernel` | 설치 뒤 dpkg가 중단됨 | `sudo dpkg --configure -a` 후 다시 요청 |
| `only the matching Ubuntu GA generic kernel is supported` | HWE·파생 커널, Ubuntu 아님 | 7장 C3 |
| `unsupported architecture` | amd64·arm64가 아님 | 지원하지 않음 |
| `no usable package mirror (official: …; kaist: …; kakao: …)` | [미러 목록](#mirrors)의 모든 미러가 색인을 받지 못했거나 GA 메타 패키지가 없음. 미러마다 이유가 붙습니다. 성공하면 출력의 `package mirror: <이름>`으로 어느 미러를 썼는지 알 수 있습니다 | 하나의 HTTP를 허용한 뒤 다시 요청. 허용할 수 없으면 수동 교체 |
| `/etc/kpctl/mirrors.list:<줄>: invalid mirror line` | 호스트의 미러 목록을 손으로 잘못 고침 | 컨트롤러 묶음의 `mirrors.list`로 재설치 |
| `no published package: …` / `ambiguous GA image dependency` | 저장소 색인이 일시적으로 불완전함 | 자동 재시도를 기다림 |
| `a newer GA ABI is not yet published` | 아직 새 커널이 없음 | 정상. 조치 불필요 |
| `insufficient /boot free space; existing kernels are retained` | `/boot` 256MB 미만 | `apt autoremove --purge` 후 다시 요청 |
| `one-shot GRUB fallback requires a verified plain ext2/3/4 boot filesystem` | `/boot`가 LVM·RAID·ext 아님 | 자동 준비 불가. 수동 교체 |
| `an existing next-boot selection must be reviewed first` | 누군가 `grub-reboot`으로 다음 부팅을 지정함 | `grub-editenv /boot/grub/grubenv list`로 확인. 의도한 게 아니면 `grub-editenv /boot/grub/grubenv unset next_entry` |
| `GRUB did not retain the explicitly saved fallback` | `/etc/default/grub`이 `GRUB_DEFAULT`를 덮어씀 | `/etc/default/grub.d/99-kpctl-boot.cfg`가 마지막에 적용되는지 확인 |
| `would change a non-kernel package` / `unsafe package plan` | 커널 외 패키지가 함께 바뀌는 계획(보류·깨진 의존성) | `apt-get check`, `apt-mark showhold` 확인 |
| `installed package version differs` / `prepared initrd could not be validated` / `new kernel modules were not prepared` | 설치 도중 실패, initramfs 생성 실패(디스크 부족 등) | 로그 끝부분 확인. 공간 확보 후 다시 요청 |
| `에이전트 재시작으로 커널 준비 완료를 확인하지 못했습니다` | 준비 중에 재설치·재시작함 | 다시 요청 |
| `context deadline exceeded` | 45분 넘게 걸림 (느린 미러) | 미러 상태 확인 후 다시 요청 |
| `…; 준비 기록·파일 검토 필요 (자동 갱신 중지)` | 실패 뒤 남은 준비 기록이 검증되지 않음 | 자동 재시도가 멈춥니다. 상태 디렉터리의 `boot-target.json`과 `/boot` 파일을 검토하고 정리한 뒤 다시 요청 |

<a id="mirrors"></a>

### 미러 목록

공식 저장소가 안 되면 쓸 미러는 [`deploy/mirrors.list`](../../deploy/mirrors.list) 한 파일에 있습니다. 설치 묶음에 들어가 호스트의 `/etc/kpctl/mirrors.list`로 설치되고, 설치 스크립트·커널 준비 도우미·설치 전 점검이 모두 이 파일을 위에서부터 씁니다. 지금 순서는 다음과 같습니다.

| 순서 | 이름 | amd64 | arm64 |
|---|---|---|---|
| 1 | official | `archive.ubuntu.com/ubuntu` (보안: `security.ubuntu.com`) | `ports.ubuntu.com/ubuntu-ports` |
| 2 | kaist | `ftp.kaist.ac.kr/ubuntu` | `ftp.kaist.ac.kr/ubuntu-ports` |
| 3 | kakao | `mirror.kakao.com/ubuntu` | 없음 |

KAIST·카카오는 Launchpad의 [Ubuntu 공식 미러 목록](https://launchpad.net/ubuntu/+archivemirrors)에 "Up to date"로 등록된 한국 미러입니다. 어느 미러에서 받든 공식과 같은 Ubuntu 서명 키(`ubuntu-archive-keyring.gpg`)로 검증하므로 신뢰 기준은 같습니다.

미러를 바꾸려면 이 파일만 고칩니다. 형식은 `이름 아키텍처 저장소-주소 [보안-주소]`이고 파일 머리말에 설명이 있습니다. 고친 뒤 `make dist`로 묶음을 만들거나, 운영 중인 컨트롤러에서는 `/usr/local/share/kpctl/agent/mirrors.list`를 직접 고칩니다. 그런 다음 `kpctl install`로 호스트에 다시 배포합니다. 형식이 틀리면 `kpctl install`이 설치를 시작하기 전에 줄 번호와 함께 거부합니다. 시험은 [mirrors_test.go](../../internal/remote/mirrors_test.go), [kernel_prepare_test.py](../../test/kernel_prepare_test.py), [install_agent_mirror_test.py](../../test/install_agent_mirror_test.py)가 이 실제 파일로 순서를 확인합니다.

<a id="combinations"></a>

## 7. 원인이 겹칠 때

각 요인이 영향을 주는 단계는 아래와 같습니다. 대부분은 서로 독립적이라 각 장의 조치를 차례로 적용하면 됩니다. 결과가 달라지는 조합만 C1–C20에 따로 정리했습니다.

| 요인 | 값 | 설치 | 패치 적용 | 커널 자동 준비 |
|---|---|---|---|---|
| 실행 환경 | VM·물리 / 컨테이너 | ✓ / ✗ | – | – |
| 저장소 접속 | 공식 됨 / 공식만 막힘 / 목록 전체 막힘 | ✓ / ✓ 한국 미러 / ✓ (C1·C2) | ✓ | ✓ / ✓ 한국 미러 / ✗ |
| kpatch 패키지 | 저장소에 있음 / 없음 | ✓ / 묶음 사용 | ✓ | – |
| 커널 | 지원 LTS GA / HWE·파생 | ✓ | ✓ / 빌드 안 됨 | ✓ / ✗ |
| 서명 | 불필요 / 필요+등록됨 / 필요+미등록 | ✓ | ✓ / ✓ / 제외 | ✓ |
| `/boot` | ext 충분 / 부족 / LVM·RAID·GRUB 아님 | ✓ | ✓ | ✓ / 정리 후 ✓ / ✗ |
| 외부 라이브패치 | 없음 / 있음 | ✓ | ✓ / 재부팅 전 ✗ | ✓ |
| dpkg | 정상 / 중단 | ✓ / 자동 복구 | ✓ | ✓ / ✗ |
| 설치 묶음 | 현재 / 도우미 빠진 이전 묶음 | ✓ | ✓ | ✓ / ✗ |

| # | 조합 | 결과 | 해결 |
|---|---|---|---|
| C1 | 미러 목록 전체 접속 불가 × kpatch 패키지 없는 시리즈 × `readelf` 없음 | binutils를 받지 못해 설치 실패 | 사내 미러를 쓰거나 binutils를 먼저 설치. `readelf`가 있으면 그냥 통과 |
| C2 | 미러 목록 전체 접속 불가 × python3 없음 | 설치 성공(경고), 패치 적용 정상. 커널 자동 준비는 python3·저장소 둘 다 없어 실패 | 저장소를 열 수 없으면 python3만 설치해도 소용이 없습니다. 이 호스트는 수동 커널 교체로 운영 |
| C3 | HWE·파생 커널 × (어떤 조합이든) | 패치 빌드·자동 준비 모두 안 됨. 컨트롤러가 수동 준비 요청도 거부합니다 | 같은 시리즈의 GA 커널(`linux-image-generic`)을 직접 설치하고 재부팅합니다. 그 뒤부터 자동 대상이 됩니다 |
| C4 | Secure Boot × MOK 미등록 × 커널 점프 재부팅 | 재부팅 한 번으로 둘 다 처리할 수 있습니다. 다만 MOK 등록은 콘솔 승인이 필요합니다. 무인 자동 점프로 재부팅하면 승인 화면을 지나쳐 계속 `blocked_mok_missing` 상태로 남습니다 | 콘솔 담당자가 있을 때 계획 재부팅으로 MOK 승인과 커널 점프를 함께 진행 |
| C5 | 외부 라이브패치 활성 × 설치 | 설치는 성공하고 Canonical Livepatch는 꺼집니다. 이미 올라간 패치 때문에 재부팅 전까지 kpctl 패치가 적용되지 않습니다 | 재부팅 한 번이 필요합니다. 다음 GA 커널 점프 재부팅과 묶으면 재부팅이 한 번으로 끝납니다. 에이전트는 외부 모듈을 자동으로 내리지 않습니다 |
| C6 | C5 × Secure Boot 미등록 | 재부팅이 두 가지 이유로 필요합니다 | C4와 같이 콘솔이 있는 계획 재부팅 한 번 |
| C7 | `/boot` 부족 × LVM·RAID | 공간을 정리해도 LVM 조건 때문에 계속 실패 | 자동 준비를 기대하지 말고 수동 교체. 공간 정리는 수동 교체에도 필요 |
| C8 | `/boot` 부족만 | 6시간마다 실패 | `apt autoremove --purge` → **원인 해결 후 다시 준비** |
| C9 | 시계 어긋남 × 새로 만든 CA·인증서 | 등록 단계에서 TLS 실패. 바이너리는 설치됐지만 서비스는 켜지지 않음 | 시계를 맞추고 설치를 다시 실행(멱등) |
| C10 | 컨트롤러 이름 미해결 × SSH 주소로는 접속됨 | `/etc/hosts`에 `# kpctl` 줄을 자동으로 넣고 설치 성공 | 나중에 컨트롤러 IP가 바뀌면 보고가 끊깁니다. 재설치하면 그 줄을 새 IP로 바꿉니다 |
| C11 | 이전 묶음으로 설치된 호스트 × 자동 준비 | `fork/exec … no such file or directory` 반복 | 새 묶음으로 재설치 → **원인 해결 후 다시 준비** |
| C12 | 재설치 × 커널 준비 진행 중 | 설치가 에이전트를 멈춰 준비가 실패로 기록됨 | 재설치는 준비가 끝난 뒤에 하는 게 좋습니다. 이미 겹쳤다면 다시 요청 |
| C13 | 설치 뒤 dpkg 중단 × 자동 준비 | 도우미가 거부(`unconfigured packages…`). 설치 때의 자동 복구는 다시 실행되지 않음 | `dpkg --configure -a` → 다시 요청 |
| C14 | 실행 커널 패키지 삭제 × 설치·준비 | 설치 점검에서 막힘. 이미 설치된 호스트는 패치 모듈 빌드·적용 대상 커널과 디스크가 어긋남 | 디스크에 있는 커널로 재부팅한 뒤 정상 절차 |
| C15 | DHCP 부트스트랩 × 2장의 경고 조건 | SSH 점검이 없어 경고 없이 설치됩니다 | 설치 뒤 `kpctl hosts`와 웹의 준비 실패 문구로 확인합니다. 미리 보려면 `kpctl install -check <호스트>` |
| C16 | 저장소 미러 IP 일부만 막힘 | apt는 다른 IP로 넘어가 성공합니다. 한 번만 시도하는 점검은 가끔 접속 불가로 오판했습니다 | 점검이 미러마다 세 번까지 시도하도록 고쳤습니다. 경고가 반복되면 실제로 막힌 것입니다 |
| C18 | 공식 저장소만 막힘 × 이전 색인이 남아 있음 | `apt-get update`가 `W: Some index files failed to download`만 내고 0으로 끝나 실패를 놓칠 수 있습니다 | 설치 스크립트가 출력의 `Failed to fetch`도 실패로 보고 다음 미러로 전환합니다. 가짜 apt로 이 경우를 자동 시험합니다. 도우미는 빈 목록에서 시작해 GA 메타 패키지까지 확인하므로 같은 문제가 없습니다 |
| C19 | arm64 호스트 × 공식 ports 막힘 | 카카오는 ports를 제공하지 않아 arm64는 공식 → KAIST 두 곳뿐입니다 | KAIST도 막히면 자동 준비 불가. 다른 ports 미러를 [미러 목록](#mirrors)에 더하세요 |
| C20 | 카카오로 전환 × 새 커널 발표 직후 | 카카오는 공식보다 몇 시간 늦게 동기화되어 새 GA 커널이 아직 없을 수 있습니다 | 도우미가 `a newer GA ABI is not yet published`로 끝나고 6시간 뒤 다시 시도합니다. 조치 불필요 |
| C17 | 관리자 수동 요청이 남은 채 실패 × 재설치 | 새 에이전트가 시작하자마자 그 요청으로 한 번 다시 시도합니다 (대기 건너뜀) | 의도한 동작입니다. 원치 않으면 재설치 전에 `kpctl host prepare-kernel <호스트> -cancel` |

근거: [점검 판정](../../internal/remote/hostcheck.go), [점검 스크립트](../../internal/remote/steps.go), [설치 스크립트](../../deploy/install-agent.sh), [준비 도우미](../../deploy/kpctl-prepare-kernel.py), [에이전트 준비](../../internal/agent/kernel_prepare.go), [외부 라이브패치 확인](../../internal/agent/kpatch.go), [준비 요청](../../internal/controller/handlers_agent.go).
