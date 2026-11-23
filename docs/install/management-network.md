# 관리망 DHCP·DNS와 자동 등록

[설치 순서](README.md)

컨트롤러 설치 옵션 `-N`을 사용하면 지정한 NIC에서만 DHCP와 관리망 DNS를 제공하도록 dnsmasq를 구성합니다. 해당 NIC에 컨트롤러의 고정 IP를 먼저 설정해야 하며 동적 범위를 `-r`로 지정합니다.

```sh
sudo ./setup-controller.sh -n ctl.mgmt.example.test -i 192.0.2.10 -u ops -N eno2 -r 192.0.2.100,192.0.2.200 -S -y
```

예시 주소와 NIC를 실제 관리망 값으로 바꾸세요. 설정은 관리망 도메인만 응답하고 외부 DNS로 전달하지 않습니다. DHCP는 기본 경로를 배포하지 않습니다. 호스트에서 관리망 DNS를 선택하는 구성은 [netplan 예시](../../configs/host-mgmt-netplan.example.yaml)를 환경에 맞춰 검토합니다.

## 임대와 예약

```sh
sudo kpctl dhcp leases
sudo kpctl dhcp reserve -all
sudo kpctl dhcp restart
sudo kpctl autoenroll -dry-run
```

`leases`는 유효 임대와 고정 예약을 에이전트 등록 상태와 함께 보여 줍니다. `reserve`는 예약 충돌을 검사하고 파일을 교체한 뒤 dnsmasq에 다시 읽도록 알립니다. `restart`는 설정 검사가 통과해야 서비스를 재시작하며 root 권한이 필요합니다.

설치할 때 관리망 옵션을 사용하면 자동 등록 타이머도 구성합니다. 자동 등록은 임대 목록에서 이미 등록한 호스트와 제외 목록을 빼고 SSH 접근을 점검합니다. 무인 접속 키가 없으면 키 대기로 남으며 클라이언트 키로 들어가지는 대상에만 에이전트를 설치합니다(빌드 서버 전용 키는 쓰지 않음). DHCP 없이 미리 준비한 클라이언트 키(`-k`)만 줘도 타이머가 켜지며, 이때 대상은 `/etc/kpctl/autoenroll-hosts`에 적습니다. 운영자가 의도적으로 제거한 서버는 `/etc/kpctl/autoenroll-ignore`에 추가해야 재설치 대상이 되지 않습니다.

기본 동적 임대 시간은 24시간이며 고정 예약은 무기한으로 생성합니다. DHCP·DNS 서버 자체는 단일 컨트롤러이므로 이 설정만으로 관리망 서비스의 이중화가 제공되지는 않습니다.

근거: [dnsmasq 생성](../../deploy/setup-controller.sh), [임대·예약 파일](../../internal/dhcp/dhcp.go), [관리 CLI](../../cmd/kpctl/dhcp.go)의 `dhcpRestart`, [자동 등록](../../cmd/kpctl/autoenroll.go)의 `autoenrollTargets`·`classifyProbe`.
