# 에이전트 설치와 관리망

[기능 목차](README.md)

<a id="f15"></a>
## F15. SSH 설치·제거·bootstrap

`kpctl install`은 SSH 접속과 사전 점검을 거쳐 설치 묶음을 보내고 에이전트 설정·서비스를 준비합니다. `-check`는 설치 전 점검 경로입니다. `Session.Preflight`는 Ubuntu·커널·관리 접속·컨트롤러 연결과 충돌 조건을 보고하고, `Session.Install`이 실제 배치를 수행합니다. 기존 공급자의 라이브패치를 자동으로 제거해 전환하는 절차는 아닙니다.

등록 그룹은 컨트롤러의 enroll token으로 초기 링과 재부팅 정책을 정합니다. 등록 뒤에는 전용 호스트 토큰으로 보고합니다. 컨트롤러 자신을 호스트로 등록하는 동작은 기본 거부하며, 시험용 명시 설정으로만 허용합니다.

`kpctl bootstrap`은 새 호스트가 설치 묶음을 받을 스크립트 또는 cloud-init 출력을 생성합니다. 출력에는 등록에 필요한 비밀 정보가 있으므로 일반 공개 파일로 보관하지 않습니다. `kpctl uninstall`은 서비스와 에이전트 제거를 수행하며, 실행 패치 제거 여부는 명시 옵션으로 결정합니다.

직접 사용하는 `deploy/install-agent.sh --enroll-mok`는 새 설정에 `mok_auto_import=true`를 넣는 선택입니다. 기본은 꺼짐이며 에이전트가 active 인증서의 등록 예약을 요청하게 합니다. 등록 예약이나 설치 스크립트가 이 때문에 자동 재부팅하지 않습니다. 실제 등록과 콘솔 확인은 [서명 운영](../operations/secure-boot.md)에 따릅니다.

구현: [install.go](../../cmd/kpctl/install.go), [bootstrap.go](../../cmd/kpctl/bootstrap.go), [steps.go](../../internal/remote/steps.go)의 `Preflight`, `Install`, `Uninstall`; [install-agent.sh](../../deploy/install-agent.sh). 검증: [e2e.sh](../../test/e2e.sh), [signing_test.go](../../internal/agent/signing_test.go). 배포 순서는 [설치 목차](../install/README.md)에 있습니다.

<a id="f16"></a>
## F16. 관리자 키, DHCP와 자동 등록

관리자 키 저장소는 기본 `/etc/kpctl/ssh/keys`이며 `KPCTL_SSH_KEY_DIR`로 바꿀 수 있습니다. `kpctl ssh-key`는 공개키 복사와 저장소 추가·조회·제거를 제공합니다. 자동 설치는 후보 키·계정을 순서대로 점검하고 접속 가능한 조합을 고릅니다. 인증에 실패한 호스트를 이미 설치된 것으로 처리하지 않습니다.

DHCP는 dnsmasq의 임대와 예약 파일을 읽고 쓰는 별도 기능입니다. `kpctl dhcp leases`로 임대를 확인하고 reserve·unreserve로 예약을 관리합니다. 예약 충돌과 MAC·IPv4·이름 형식을 검증합니다. 서비스 재시작은 `kpctl dhcp restart`로 수행합니다.

`kpctl autoenroll`은 아직 등록되지 않은 유효한 DHCP 임대 중 설치 대상을 고르고, 필요한 키가 없으면 대기 상태를 남깁니다. 제공한 타이머는 부팅 후와 이전 실행 종료 뒤 약 1분 간격으로 실행합니다. 운영망·등록 그룹·무시 대상과 SSH 접근 권한을 먼저 준비해야 합니다.

관리망 DHCP 구성은 한 컨트롤러의 서비스입니다. 이 코드가 DHCP 고가용성이나 모든 네트워크 장비의 DNS·경로 구성을 관리하지는 않습니다. 관리망 설정 변경은 실제 호스트에서 기존 서비스망 연결과 함께 확인해야 합니다.

구현: [keystore.go](../../cmd/kpctl/keystore.go)의 `keyStoreAdd`, `loginCandidates`, `pickLogin`; [autoenroll.go](../../cmd/kpctl/autoenroll.go)의 `autoenrollTargets`, `classifyProbe`; [dhcp.go](../../internal/dhcp/dhcp.go)의 `CheckConflict`, `WriteReservations`; [CLI DHCP](../../cmd/kpctl/dhcp.go); [자동 등록 타이머](../../deploy/systemd/kpctl-autoenroll.timer). 검증: [autoenroll_test.go](../../cmd/kpctl/autoenroll_test.go), [dhcp_test.go](../../internal/dhcp/dhcp_test.go).
