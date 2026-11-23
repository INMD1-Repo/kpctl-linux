# 기능 명세

[문서 목차](../README.md)

현재 구현의 입력, 판단, 상태 변화와 실패 처리를 설명합니다. 설정의 허용 필드와 기본값은 각 프로그램의 `ParseConfig`/`LoadConfig`, 관리 명령은 [CLI 정의](../../cmd/kpctl/main.go), HTTP 권한은 [routes](../../internal/controller/server.go)를 기준으로 합니다.

| 번호 | 기능 | 명세 |
|---|---|---|
| F01 | 실행 커널·GA 범위·정식 배포 상한 | [커널 수집](kernel-discovery.md#f01) |
| F02 | CVE 후보·의존성·시험 실패 검토 | [커널 수집](kernel-discovery.md#f02) |
| F03 | 도구 선택·소스·GCC 고정 환경 | [빌드](build-and-artifact.md#f03) |
| F04 | ELF·vermagic·심볼 CRC | [빌드](build-and-artifact.md#f04) |
| F05 | 누적 작업·대기열·결과 업로드 | [빌드](build-and-artifact.md#f05) |
| F06 | 승인·첫 링·승급 | [배포](rollout-and-agent.md#f06) |
| F07 | 호스트 보고·모듈 적용·부팅용 설치 | [에이전트](rollout-and-agent.md#f07) |
| F08 | 롤백·패치 제외·즉시 업데이트 | [배포 조작](rollout-and-agent.md#f08) |
| F09 | 자동 승인·승급·검토 보류 | [자동 배포](rollout-and-agent.md#f09) |
| F10 | 새 디스크 GA 커널 준비 | [커널 준비](reboot-and-uptime.md#f10) |
| F11 | 드레인·대상별 재부팅 승인 | [재부팅](reboot-and-uptime.md#f11) |
| F12 | 실제 부팅·기본 커널 확정·만료 정리 | [재부팅 결과](reboot-and-uptime.md#f12) |
| F13 | 독립 OSV 목록과 적용 범위 대조 | [CVE 현황](coverage-and-console.md#f13) |
| F14 | 웹·CLI에서 확인하는 결과 | [관리 화면](coverage-and-console.md#f14) |
| F15 | SSH 설치·제거·bootstrap | [설치](provisioning-and-network.md#f15) |
| F16 | 관리자 키·DHCP·자동 등록 | [관리망](provisioning-and-network.md#f16) |
| F17 | 설정·JSON 상태·원자 승인 저장 | [저장](settings-state-api.md#f17) |
| F18 | 인증 역할·API·감사 기록 | [권한](settings-state-api.md#f18) |
| F19 | 빌더 실행 파일 업데이트 | [업데이트](updates-and-validation.md#f19) |
| F20 | 자동 시험·전용 검증기·증명 범위 | [시험](updates-and-validation.md#f20) |
| F21 | 다중 서명 키·MOK·배포 자격 | [서명](signing.md#f21) |
| F22 | VM 보안·교체·롤백·smoke 검사 | [테스트 VM](test-vm.md#f22) |
| F23 | 선택적인 출시 전 수집·별도 배포 | [출시 전](prerelease-and-cna.md#f23) |
| F24 | 커널 CNA의 upstream 수정 ID 대조 | [CNA 매핑](prerelease-and-cna.md#f24) |

수집된 diff, 빌드 성공, VM 시험 통과, 실제 호스트 적용은 서로 다른 결과입니다. 라이브패치가 실행 중인 선택 함수를 바꾸더라도 디스크 커널이나 모든 CVE의 보호 상태가 함께 바뀌지는 않습니다. 설치는 [설치 목차](../install/README.md), 운영 절차는 [운영 목차](../operations/README.md), 구현 위치는 [코드 지도](../development/code-map.md)를 보세요.
