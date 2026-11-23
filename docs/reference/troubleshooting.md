# 증상별 확인 순서

[목차](../README.md) · [파일·로그 위치](files.md) · 설치·커널 준비 실패는 [설치·커널 준비 문제 해결](../operations/install-troubleshooting.md)

## 시작하지 않음

모르는 설정 키, `signing`과 `sign_command`의 동시 사용, active 키 수 오류는 로더에서 거부합니다. 명시한 DER를 읽지 못하거나 같은 키 ID의 DER 내용이 바뀌어도 시작을 막습니다. 설정 오류를 무시하는 옵션을 찾기보다 실제 필드와 키 ID를 확인하세요. 기존 `sign_command`에서 추정한 DER를 읽지 못하는 경우는 호환성을 위해 경고로 남습니다.

컨트롤러 journal과 [설정 예시](../../configs/controller.example.json)를 비교합니다. 빌더의 `-check-config`는 설정과 CA 검사에 사용할 수 있지만 실제 빌드·컨트롤러 연결 시험을 대신하지 않습니다.

## 재시작 뒤 연결 거부

빌더나 에이전트가 `connect: connection refused`나 `lookup … no such host`를 받으면 컨트롤러에서 `kpctl status`를 먼저 실행합니다. 재부팅 뒤 자동으로 켜지지 않을 유닛이 있으면 맨 위에 표시됩니다. cloud-init이 `/etc/hosts`를 다시 쓰는 문제와 DHCP 주소가 바뀌는 문제는 [전부 재시작한 뒤 연결이 안 될 때](../operations/install-troubleshooting.md#after-reboot)에 정리했습니다.

## 호스트가 패치를 받지 않음

`kpctl hosts`에서 실행 커널, 링 목표, 제외 사유와 보안 경고를 확인합니다.

| 표시·오류 | 확인할 것 |
|---|---|
| `blocked_mok_missing` | 현재 키가 명확히 미등록입니다. 인증서 예약과 다음 계획된 재부팅의 콘솔 승인을 확인합니다. |
| MOK pending | 예약이 실제 등록 완료는 아닙니다. 콘솔 승인 뒤 다음 호스트 보고에서 자격을 다시 계산합니다. |
| 등록 상태 미확인 | 도구·EFI·이전 에이전트 보고를 확인합니다. 미확인을 등록 완료나 서명 불필요로 취급하지 않습니다. |
| `blocked_artifact` | 필요한 키의 검증된 서명 사본이 없습니다. 이전 원본과 검증 조건을 갖춘 새 누적 작업을 준비합니다. |
| HWE 미지원 | 이름이 같은 GA 모듈을 억지로 배포하지 않습니다. 실행 커널 signature와 공식 GA 커널 전환 절차를 확인합니다. |
| 외부 라이브패치 활성·전환 | 다른 공급자의 보호 상태와 운영 전환 계획을 확인합니다. 에이전트는 외부 모듈을 자동으로 제거하지 않습니다. |

비밀번호는 `kpctl hosts mok-password`로 조회할 수 있으며 조회가 감사됩니다. 패치 제외 상태를 v0 롤백으로 바꾸면 기존 보호를 제거하므로 같은 조작으로 취급하면 안 됩니다.

## 빌드·승인이 멈춤

`kpctl log`와 빌더 journal을 읽고 실패 분류·원본 로그·대상 GCC·config·인증서·디버그 입력·심볼 CRC를 확인합니다. 누적 빌드 실패는 어느 보안 수정이 원인인지 확정한 결과가 아닙니다. 입력을 자동으로 빼거나 ABI 검사를 완화하지 않습니다.

VM의 "이미지 설정 오류"와 미서명 모듈이 허용되는 오류는 이미지·서명 강제 검증 문제입니다. 모듈 결함으로 바로 분류하지 마세요. Jobs/Patches의 단계 결과와 `testlogs`를 확인합니다. 새 WARNING·BUG·Call Trace도 실패할 수 있으며 고정 VM은 정리 실패까지 확인해야 합니다.

출시 전 승인에는 `kpctl approve`의 `--prerelease`와 켜진 VM 검사가 필요합니다. 정식 활성 입력이 바뀐 오래된 후보는 `kpctl build`에 `--prerelease`를 주어 다시 빌드합니다. 수동 승급·롤백에도 출시 전 플래그가 필요합니다.

서명 원본이나 pin을 찾지 못해 키 교체가 멈추면 보존·복구 상태를 먼저 확인합니다. 과거 서명 파일에서 원본을 추측하거나 상태 해시를 수동 변경하지 않습니다. 장기 실행 중의 만료 경고도 Settings, `kpctl signing list`와 감사 기록에서 확인합니다.

## 자동 배포·재부팅이 진행하지 않음

`kpctl auto`의 보류 사유와 관찰 시간을 먼저 봅니다. 나중 빌드가 성공하거나 호스트 오류가 사라져도 보류가 저절로 풀리지는 않습니다. 원인과 배포할 누적본을 검토한 뒤 `kpctl auto clear`로 해제합니다. 출시 전 overlay가 있으면 자동화가 해당 커널을 보류하는 것이 정상입니다.

재부팅은 cordon, 신선한 VM 0 확인, 검증한 목표, boot ID, 파일·잠금과 승인 만료 조건을 검사합니다. MOK 예약이나 디스크 커널 준비만으로 승인되지 않습니다. 지정 호스트 자동 점프는 정확한 ID 허용 목록과 추가 조건을 모두 요구합니다.

근거: [설정 검증](../../internal/controller/signing.go)의 `validateSigning`, [목표·서명 자격](../../internal/controller/rollout.go)의 `desired`·`rolloutEligibility`, [시험](../../internal/testvm/manager.go), [실패 분류](../../internal/buildlog/failure.go), [자동 보류](../../internal/controller/auto.go), [재부팅](../../internal/controller/reboot.go).
