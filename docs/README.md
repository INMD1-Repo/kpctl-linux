# kpctl 문서

이 문서는 kpctl-linux의 설정, 설치·운영 절차, 구현과 시험 범위를 설명합니다.

| 읽을 내용 | 문서 |
|---|---|
| 프로그램 역할과 통신 | [구조](overview/architecture.md) |
| 누적 패치·링·재부팅 안전 조건 | [운영 규칙](overview/rules.md) |
| 기능과 입력·실패 처리 | [기능 명세](features/README.md) |
| 설치 준비와 순서 | [설치](install/README.md) |
| 컨트롤러 | [설치·초기 설정](install/controller.md) |
| LTS별 빌더 | [격리 빌드 환경](install/builder.md) |
| 대상 호스트 | [에이전트](install/agent.md) |
| 관리망 | [DHCP·DNS·자동 등록](install/management-network.md) |
| 서명 | [F21](features/signing.md#f21), [Secure Boot 운영](operations/secure-boot.md) |
| 승인 전 VM 검사 | [F22](features/test-vm.md#f22) |
| 출시 전 수정·CNA 매핑 | [F23](features/prerelease-and-cna.md#f23), [F24](features/prerelease-and-cna.md#f24) |
| 저장 파일·기본 경로 | [파일 위치](reference/files.md) |
| 장애 판단 | [문제 해결](reference/troubleshooting.md), [설치·커널 준비 문제 해결](operations/install-troubleshooting.md) |
| 지원·검증 범위 | [제약](reference/limitations.md) |
| 수정할 소스 | [코드 지도](development/code-map.md) |
| 시험·웹 개발 | [시험](development/testing.md), [웹](development/web.md) |

처음 설치할 때는 운영 규칙과 설치 문서를 먼저 읽고, 서명을 요구하는 호스트가 있으면 인증서 등록 상태를 확인한 다음 배포를 승인하세요. 현재 동작을 검토할 때는 각 문서 끝의 소스 링크와 설정 예시를 함께 확인합니다.

저장소 개요로 돌아가기: [README](../README.md).
