# 운영 안내

<a id="operations"></a>

컨트롤러가 배포할 누적 모듈을 정하고, 빌더가 모듈을 만들며, 에이전트가 실제 커널 상태를 확인하면서 적용합니다. `built`는 승인 대기 상태이고 `released`는 링의 목표가 정해진 상태입니다. 호스트의 실제 활성 모듈과 전환 완료까지 확인해야 적용을 판단할 수 있습니다.

| 작업 | 문서 |
| --- | --- |
| 매일 상태 확인·오류 대응 | [일상 점검](daily.md#daily) |
| CLI 명령 찾기 | [명령 모음](commands.md#commands) |
| 자동 승인·링 승급 관리 | [자동 배포](auto-rollout.md#auto-rollout) |
| DHCP 호스트 자동 등록 | [자동 등록](auto-enroll.md#auto-enroll) |
| 설치·커널 준비 실패와 조합별 해결 | [설치·커널 준비 문제 해결](install-troubleshooting.md#install-troubleshooting) |
| 디스크 커널 준비·재부팅 | [재부팅 승인](reboot-approval.md#reboot-approval) |
| 서명·MOK·키 교체 | [Secure Boot 운영](secure-boot.md#secure-boot) |
| 승인용 고정·일회 VM 준비와 복구 | [VM 시험](test-vm.md#test-vm) |
| 빌더 이전 | [빌더 이전](builder-migration.md#builder-migration) |
| 격리 이미지·컴파일러·캐시 | [빌드 환경](build-environment.md#build-environment) |
| 프로그램 갱신·복구 | [업그레이드](upgrade.md#upgrade) |
| CVE 현황의 해석 | [CVE 점검](cve-coverage.md#cve-coverage) |
| 관리자 화면 | [웹 운영](web.md#web) |

설정 파일은 [컨트롤러 예제](../../configs/controller.example.json), [빌더 예제](../../configs/builder.example.json), [에이전트 예제](../../configs/agent.example.json)와 각 구성 요소의 로더가 기준입니다. 구현 위치는 [코드 안내](../development/code-map.md)를 참고하세요.
