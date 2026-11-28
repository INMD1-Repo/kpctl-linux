# 설치 순서

[목차](../README.md)

컨트롤러와 빌더는 운영 패치 대상과 분리해 준비합니다. 에이전트 설치 스크립트는 같은 머신에 컨트롤러·빌더 설정이 있으면 설치를 거부합니다.

1. 개발 환경에서 `make test`와 `make dist`를 실행해 설치 묶음을 만듭니다. 웹 재빌드에는 [web/package.json](../../web/package.json)에 맞는 Node.js/npm이 필요합니다.
2. `dist/controller/`를 [컨트롤러 서버](controller.md)에 설치하고 관리자·빌더·등록 토큰과 TLS 신뢰를 준비합니다.
3. 대상 LTS와 같은 Ubuntu 시리즈의 서버에 [빌더](builder.md)를 준비합니다. 컨트롤러에서 `sudo kpctl install-builder <빌드 서버>` 한 번으로 묶음 복사·설정·설치까지 끝나며, 직접 `dist/builder/ubuntu/`를 전달해 설치할 수도 있습니다. 기본 설치는 대상 GCC별 rootless sandbox입니다.
4. GA generic 커널을 실행하는 호스트에 `dist/agent/` 또는 관리자 CLI로 [에이전트](agent.md)를 설치합니다.
5. [서명과 MOK 상태](../operations/secure-boot.md), [승인 전 VM 검사](../features/test-vm.md#f22)를 구성한 뒤 카나리부터 승인합니다.

관리망 DHCP/DNS를 쓰는 경우에는 [관리망 설치](management-network.md)를 컨트롤러 단계에 함께 적용합니다.

## 준비할 정보

| 구성 요소 | 준비할 값 |
|---|---|
| 컨트롤러 | 호스트에서 해석 가능한 이름·IP, TLS 인증서, 상태 저장 디스크, 관리자 토큰 |
| 빌더 | 컨트롤러 주소·CA·빌더 토큰, 담당 시리즈, 대상 커널과 디버그 입력, 빌드 디스크·메모리 |
| 에이전트 | 컨트롤러 주소·CA·등록 그룹, 실행 커널과 Ubuntu signature, SSH 접근 또는 로컬 설치 권한 |
| 서명·시험 | 운영 서명 키와 DER 인증서, 대상 키 등록, 필요한 펌웨어 모드별 VM |

설정 예시는 로더가 허용하는 구조를 보여 줍니다. 예시의 토큰·주소·파일 경로는 설치 환경에 맞게 바꾸고 개인키는 별도로 준비해야 합니다. 설정의 오타는 무시되지 않고 시작 오류가 됩니다.

설치 스크립트는 서비스·APT 정책·파일을 변경합니다. 라이브패치 적용 시험, 커널 준비와 재부팅은 설치 성공 여부와 별도 검증 대상입니다. [제약](../reference/limitations.md)과 [시험 범위](../development/testing.md)를 함께 확인하세요.

근거: [배포 묶음](../../Makefile)의 `dist`, [컨트롤러 설치](../../deploy/setup-controller.sh), [빌더 설치](../../deploy/setup-builder.sh), [에이전트 설치](../../deploy/install-agent.sh).
