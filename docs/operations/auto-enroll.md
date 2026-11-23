# 클라이언트 자동 등록

<a id="auto-enroll"></a>

`kpctl autoenroll`은 미등록 호스트 중 **클라이언트 키로 들어가지는 호스트**에 질문 없이 에이전트를 설치하는 일회 명령입니다. 대상은 관리망 DHCP 임대와 `/etc/kpctl/autoenroll-hosts`(DHCP를 쓰지 않을 때, 한 줄에 IP 또는 이름)에 적은 호스트입니다. `kpctl-autoenroll.timer`는 부팅 후 1분, 이전 실행 종료 후 1분 간격으로 실행합니다. 컨트롤러를 관리망 DHCP(`-N`)나 미리 준비한 클라이언트 키(`-k`)로 설치하면 타이머가 켜지므로 운영 전 대상을 확인합니다.

```sh
echo 192.0.2.21 | sudo tee -a /etc/kpctl/autoenroll-hosts   # DHCP 없이 대상 추가
```

등록을 확인한 대상은 로그 디렉터리의 `enrolled` 기록에 남겨 매분 다시 접속하지 않습니다. 등록을 지운 호스트(`kpctl host delete`)는 다시 대상이 되므로, 일부러 에이전트를 뺀 호스트는 제외 파일에 적습니다.

```sh
sudo kpctl dhcp leases
sudo kpctl autoenroll -dry-run
sudo systemctl status kpctl-autoenroll.timer
sudo journalctl -u kpctl-autoenroll.service --since today
```

`-dry-run`도 실제 SSH 로그인 확인을 수행하지만 설치는 하지 않습니다. 컨트롤러의 등록 상태를 읽지 못하면 전체 임대를 미등록으로 가정하지 않고 중단합니다. 만료 임대·이미 등록한 호스트·제외 파일의 항목을 거릅니다.

<a id="access"></a>

컨트롤러 설치 키(`-k`로 넘긴 클라이언트 키)와 `kpctl ssh-key add`로 저장한 클라이언트 키 중 로그인 가능한 조합을 사용합니다. 빌드 서버 전용 키(`setup-controller.sh -b` 또는 `ssh-key add -role builder`)는 쓰지 않으므로, 빌더를 설치하기 전의 빌드 서버에 에이전트가 깔리지 않습니다. 이 구분이 생기기 전에 저장한 빌드 서버 키는 `sudo kpctl ssh-key add -role builder /etc/kpctl/ssh/keys/<이름>`으로 표시합니다. 로그인 권한이 없으면 키 대기로 건너뛰며 무작위 비밀번호를 시도하지 않습니다. 처음 보는 SSH 호스트 키는 기록하지만 바뀐 키는 SSH가 거부합니다. 변경된 키를 자동 삭제해서 통과시키지 않습니다.

```sh
sudo kpctl ssh-key list
sudo kpctl ssh-key copy node-01
sudo kpctl autoenroll -dry-run
```

추가 SSH 옵션과 저장 키 사용법은 해당 명령의 `-h`를 확인합니다. `/etc/kpctl/autoenroll-ignore`에는 제외할 IP·MAC·이름을 한 줄에 하나씩 적습니다. `/etc/kpctl/controller.json` 또는 `builder.json`이 있는 서버는 설치 전 점검에서도 제외합니다. 빌더·컨트롤러를 패치 대상 호스트로 함께 운영하지 않습니다.

<a id="groups"></a>

자동 등록은 기본적으로 커널별 첫 호스트를 `canary`, 나머지를 `server` 그룹에 넣습니다. 컨트롤러의 같은 이름 enroll token과 링 구성이 필요합니다. 이 선택은 실제 커널 확인 후 순차적으로 수행하므로 임의 병렬 설치로 바꾸지 않습니다. 기존 카나리의 상태·정책이 의도에 맞는지도 확인합니다.

자동 등록을 원하지 않는 구간에는 타이머를 중지하고, 대상·SSH 권한·그룹을 확인한 뒤 다시 켭니다.

```sh
sudo systemctl disable --now kpctl-autoenroll.timer
sudo kpctl install -check -group canary node-01
sudo kpctl install -group canary node-01
sudo systemctl enable --now kpctl-autoenroll.timer
```

기존 호스트의 명시적 업그레이드에는 `kpctl install`을 사용합니다. 이미 등록된 호스트를 자동 등록 타이머가 계속 재설치하지 않습니다. SSH가 없는 새 VM은 [에이전트 설치](../install/agent.md)의 bootstrap/cloud-init 경로를 사용할 수 있으며 출력 등록 토큰을 보호합니다. MOK 자동 예약은 별도 [선택 설정](secure-boot.md#mok-enrollment)입니다.

근거: [대상 선택·설치 흐름](../../cmd/kpctl/autoenroll.go), [타이머](../../deploy/systemd/kpctl-autoenroll.timer), [설치 방어](../../deploy/install-agent.sh).
