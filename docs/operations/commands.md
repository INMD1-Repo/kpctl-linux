# CLI 명령 모음

<a id="commands"></a>

`KPCTL_URL`, `KPCTL_TOKEN`, 선택적인 `KPCTL_CA`를 사용합니다. 비어 있는 변수는 `/etc/kpctl/kpctl.env`에서 채우며 `KPCTL_ENV`로 파일을 바꿀 수 있습니다. 관리자는 개인별 토큰을 쓰면 감사 기록에 각 이름이 남습니다.

<a id="inspect"></a>

```sh
kpctl status
kpctl jobs
kpctl hosts
kpctl log 12
kpctl patches -kernel 6.8.0-85-generic
kpctl signing list
kpctl auto
```

<a id="patch-rollout"></a>

커널 이름과 작업 번호는 실제 상태에서 고릅니다. 아래 번호는 문법 예시입니다. `build`, `submit`, `promote`, `rollback`, 설치 명령의 플래그는 위치 인자 앞에 씁니다. `approve`는 작업 번호 뒤의 `--prerelease`도 처리합니다.

```sh
kpctl submit -kernel 6.8.0-85-generic -cve CVE-2026-12345 -title '검토한 수정' fix.patch
kpctl patch disable p000012
kpctl patch enable p000012
kpctl build -kernel 6.8.0-85-generic
kpctl approve 12
kpctl promote -kernel 6.8.0-85-generic -ring 2
kpctl rollback -kernel 6.8.0-85-generic -version 2
```

패치 활성 상태 변경만으로 기존 모듈은 바뀌지 않습니다. 새 누적 빌드·승인이 필요합니다. `promote -force`는 관찰·호스트 건강 문제를 무시하는 관리자 조작이므로 문제를 검토한 경우에만 사용합니다. 서명·아티팩트 자격 조건은 호스트별로 계속 적용됩니다. `rollback -version 0`은 모든 링의 kpctl 패치를 제거하도록 지시합니다.

출시 전 작업은 정식 버전과 별도의 음수 버전입니다. 승인에는 켜진 VM 시험과 명시적인 옵션이 필요합니다. 승급·출시 전 버전으로의 롤백에도 옵션을 붙입니다.

```sh
kpctl build -kernel 6.8.0-85-generic --prerelease
kpctl approve 13 --prerelease
kpctl promote -kernel 6.8.0-85-generic -ring 2 --prerelease
kpctl rollback -kernel 6.8.0-85-generic -version -1 --prerelease
```

정식 버전으로 되돌릴 때는 일반 양수 버전 롤백을 사용합니다. 출시 전 배포 중에는 자동 승인·자동 승급과 호스트의 즉시 업데이트가 제한됩니다.

<a id="hosts"></a>

호스트 인자는 등록 ID 또는 정확한 호스트 이름입니다. 재부팅의 `-kernel`은 호스트가 보고한 검증된 준비 대상이어야 합니다. `prepare-kernel`은 준비 기록이 없을 때 다음 공식 GA 커널 설치만 요청하며 재부팅하지 않습니다([커널 점프](reboot-approval.md#web-jump)).

```sh
kpctl host set node-01 -ring 1 -policy drain
kpctl host prepare-kernel node-01
kpctl host cordon node-01
kpctl host reboot node-01 -kernel 6.8.0-86-generic
kpctl host cancel-reboot node-01
kpctl host uncordon node-01
kpctl signing rollout-cert prod-2026
kpctl hosts mok-password node-01
```

`host delete`는 컨트롤러 등록을 삭제하는 명령입니다. 원격 에이전트 제거는 `uninstall`을 사용합니다. MOK 예약과 재부팅 승인은 서로 별개입니다.

<a id="automation-install"></a>

```sh
kpctl auto pause
kpctl auto resume
kpctl auto hold 6.8.0-85-generic
kpctl auto clear 6.8.0-85-generic
kpctl install -check -group canary node-01
kpctl install -group canary node-01
kpctl install -group server -hosts-file hosts.txt
kpctl uninstall node-01
kpctl install-builder -check build-noble
kpctl install-builder build-noble
kpctl install-builder -stop-running build-noble 6.8.0-136-generic -- --memory-mib 16384
kpctl autoenroll -dry-run
kpctl dhcp leases
kpctl ssh-key list
kpctl ssh-key show -cloud-init > kpctl-client.yaml
```

기본 `uninstall`은 적용 중인 라이브패치를 보존합니다. `-remove-patches`를 붙이면 패치 제거도 요청합니다. `install`과 `install-builder`를 터미널에서 인자 없이 실행하면 필요한 값을 하나씩 묻는 질문형 설치가 됩니다. 인자를 주거나 스크립트·타이머에서 실행하면 질문하지 않습니다. `install-builder`는 빌드 서버를 SSH로 한 번에 설치합니다. 커널을 생략하면 등록 호스트 중 같은 시리즈의 GA 커널을 고르며, `--` 뒤 값은 `setup-builder.sh`에 그대로 넘깁니다. SSH 접속 계정은 `-ssh-user`, 빌드 서비스 계정은 `-build-user`로 고릅니다. 실행 중인 빌더는 `-stop-running` 없이는 바꾸지 않습니다. `install -h`, `install-builder -h`, `autoenroll -h`, `bootstrap -h`로 SSH·토큰·묶음 관련 선택지를 확인합니다. `bootstrap` 출력에는 등록 토큰이 있으므로 권한을 제한한 파일로 저장합니다. `ssh-key show -cloud-init`은 컨트롤러 공개키만 넣는 새 VM용 user-data를 출력합니다. 토큰이 없어 템플릿에 둬도 되며, 설치는 자동 등록이 SSH로 합니다.

근거: [명령 등록](../../cmd/kpctl/main.go), [배포·호스트 명령](../../cmd/kpctl/commands.go), [서명 명령](../../cmd/kpctl/signing.go), [설치 명령](../../cmd/kpctl/install.go), [빌더 설치 명령](../../cmd/kpctl/install_builder.go), [질문형 설치](../../cmd/kpctl/wizard.go).
