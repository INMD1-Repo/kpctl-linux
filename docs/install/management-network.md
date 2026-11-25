# 관리망 DHCP·DNS와 자동 등록

[설치 순서](README.md)

컨트롤러 설치 옵션 `-N`을 사용하면 지정한 NIC에서만 DHCP와 관리망 DNS를 제공하도록 dnsmasq를 구성합니다. 해당 NIC에 컨트롤러의 고정 IP를 먼저 설정해야 합니다. 다른 값은 그 NIC에서 계산합니다.

| 값 | 주지 않았을 때 |
|---|---|
| `-i` 컨트롤러 IP | NIC의 IPv4 주소 |
| `-r` 동적 범위 | NIC가 속한 /24의 `.100`~`.250`. 컨트롤러 IP가 그 안에 있으면 `.20`~`.99`. /24보다 좁은 망은 직접 지정해야 합니다 |
| `-d` 도메인 | `-n`에서 첫 칸을 뺀 값. `-n`도 없으면 `mgmt.internal` |
| `-n` 이름 | `ctl.<도메인>` |

```sh
sudo ./setup-controller.sh -N eno2 -D     # 계산 결과만 확인
sudo ./setup-controller.sh -N eno2
sudo ./setup-controller.sh -n ctl.mgmt.example.test -i 192.0.2.10 -u ops -N eno2 -r 192.0.2.100,192.0.2.200 -S -y
```

예시 주소와 NIC를 실제 관리망 값으로 바꾸세요. 설정은 관리망 도메인만 응답하고 외부 DNS로 전달하지 않습니다. DHCP는 기본 경로를 배포하지 않습니다. 호스트에서 관리망 DNS를 선택하는 구성은 [netplan 예시](../../configs/host-mgmt-netplan.example.yaml)를 환경에 맞춰 검토합니다.

## 임대와 예약

```sh
sudo kpctl dhcp leases
sudo kpctl autoenroll -dry-run
sudo kpctl dhcp reserve node-01   # 등록이 끝난 호스트의 IP 고정
sudo kpctl dhcp restart
```

`leases`는 유효 임대와 고정 예약을 에이전트 등록 상태와 함께 보여 줍니다. `reserve`는 예약 충돌을 검사하고 파일을 교체한 뒤 dnsmasq에 다시 읽도록 알립니다. `restart`는 설정 검사가 통과해야 서비스를 재시작하며 root 권한이 필요합니다.

설치할 때 관리망 옵션을 사용하면 자동 등록 타이머도 구성합니다. 자동 등록과 `-from-dhcp`는 활성 동적 임대에서 미등록 호스트를 찾습니다. 고정 예약된 MAC이나 IP, 무기한 임대는 건너뜁니다. 자동 등록은 제외 목록도 확인합니다. 무인 접속 키가 없으면 키 대기로 남으며 클라이언트 키로 들어가지는 대상에만 에이전트를 설치합니다(빌드 서버 전용 키는 쓰지 않음). DHCP 없이 미리 준비한 클라이언트 키(`-k`)만 줘도 타이머가 켜지며, 이때 대상은 `/etc/kpctl/autoenroll-hosts`에 적습니다. 새 VM에는 컨트롤러 공개키만 넣으면 됩니다. `sudo kpctl ssh-key show -cloud-init > kpctl-client.yaml`의 출력을 VM의 user-data로 쓰면, VM이 관리망 IP를 받은 뒤 1분 안에 에이전트가 설치됩니다. 이 설정에는 등록 토큰이 없으므로 VM 템플릿에 넣어 둬도 됩니다. root가 아닌 계정(`-user ops` 또는 `KPCTL_SSH_USER`)이면 비밀번호 없는 sudo 계정을 만듭니다. 운영자가 의도적으로 제거한 서버는 `/etc/kpctl/autoenroll-ignore`에 추가해야 재설치 대상이 되지 않습니다.

기본 동적 임대 시간은 24시간이며 고정 예약은 무기한으로 생성합니다. DHCP·DNS 서버 자체는 단일 컨트롤러이므로 이 설정만으로 관리망 서비스의 이중화가 제공되지는 않습니다.

근거: [dnsmasq 생성](../../deploy/setup-controller.sh), [임대·예약 파일](../../internal/dhcp/dhcp.go), [관리 CLI](../../cmd/kpctl/dhcp.go)의 `dhcpRestart`, [자동 등록](../../cmd/kpctl/autoenroll.go)의 `autoenrollTargets`·`classifyProbe`.
