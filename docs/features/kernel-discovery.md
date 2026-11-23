# 실행 커널과 CVE 후보 수집

[기능 목차](README.md)

<a id="f01"></a>
## F01. 실행 커널, GA 범위와 정식 상한

에이전트는 실행 ABI와 `/proc/version_signature`를 보고합니다. 빌더 설정의 `kernels`가 비어 있으면 컨트롤러의 호스트 커널 목록에서 자기 LTS 시리즈를 고릅니다. [SupportedLTS](../../internal/model/lts.go)에 정의된 기본 범위는 jammy의 5.15.0, noble의 6.8.0, resolute의 7.0.0이며 `-generic`을 대상으로 합니다.

자동 수집에서 최신 Git 태그의 정렬 결과만으로 배포 여부를 판단하지 않습니다. `publishedKernelVersion`은 APT가 신뢰하는 Ubuntu main의 정식·updates·security 색인을 읽고 GA 이미지의 linux 소스 버전을 비교합니다. `officialTargetTag`는 그 버전과 정확히 같은 Ubuntu 태그가 있는지 확인합니다. 색인·태그 확인 실패는 개발 태그로 대체하지 않습니다.

`max_kernels`의 기본값은 -1로 제한이 없습니다. 양수를 지정하면 최근 ABI 범위를 고르고 범위 밖 호스트를 별도 보고합니다. 설정 예시의 값은 로더 기본값과 다를 수 있습니다. 관리자가 `kernels[]`를 직접 지정하는 빌드 입력 경로도 있지만, 이것이 HWE나 파생 커널의 운영 배포 지원을 뜻하지는 않습니다.

GA와 같은 ABI 이름을 가진 HWE는 Ubuntu 버전 서명으로 가려 배포하지 않습니다. 버전 서명이 없는 이전 보고는 이 구분에 필요한 정보가 부족합니다. 해당 호스트의 에이전트를 갱신하고 실제 커널 패키지를 확인해야 합니다.

| 설정/입력 | 판단 위치 |
|---|---|
| `series`, `kernels[]`, `max_kernels` | [config.go](../../internal/builder/config.go), [kernels.go](../../internal/builder/kernels.go) |
| 정식 APT 버전·정확한 태그 | [published.go](../../internal/builder/published.go)의 `publishedKernelVersion`, `officialTargetTag` |
| GA/HWE 식별 | [lts.go](../../internal/model/lts.go)의 `LTSForKernel`, `HWEWithGAName` |
| 수집 준비·최신 정보 보고 | [discover.go](../../internal/builder/discover.go)의 `discoverWithForce`, `reportUpstream` |

검증: [published_test.go](../../internal/builder/published_test.go), [kernels_window_test.go](../../internal/builder/kernels_window_test.go), [lts_test.go](../../internal/model/lts_test.go).

<a id="f02"></a>
## F02. 후보 선택, 선행 수정과 검토 보류

기본 경로는 `kernel/`, `mm/`, `fs/`, `net/`, `security/`, `ipc/`, `io_uring/`, `crypto/`, `block/`, `lib/`, `arch/x86/`입니다. 전체 `drivers/`는 기본 목록에 없습니다. `paths`와 `kernels[].paths`로 범위를 지정할 수 있습니다. 기본 후보는 이 경로를 변경한 CVE 표기 커밋이며, 선택적인 [CNA 매핑](prerelease-and-cna.md#f24)을 켜면 명시적 upstream 수정 ID도 대조합니다.

`discoverRange`는 오래된 커밋부터 확인하고 이미 처리한 커밋과 관리자 제외를 조회합니다. `resolvePatchSet`은 필요한 선행 수정을 찾고, `independentPatchSet`은 현재 누적 입력과의 적용 문맥을 확인합니다. 기본 선행 수정 상한은 12개입니다. 단독 문맥이 맞지 않으면 이미 활성인 패치와 앞서 시험을 마친 후보를 포함해 재시험할 수 있습니다.

기본적으로 후보별 시험 빌드를 하고, 최종 누적 빌드도 별도로 수행합니다. 한 주기의 기본 시험 한도는 10개이며 나머지는 후속 주기에 이어집니다. 인증서·컴파일러·의존성·도구 제약·원인 미확인 실패는 원문과 입력을 남겨 검토를 기다립니다. 새 영구적인 ‘라이브패치 불가’ 판정을 만들어 보안 수정을 자동 제외하지 않습니다. 이미 시험한 앞부분을 등록할 수 있어도 전체 상한까지 수집했다고 보고하지 않습니다.

같은 실패 입력의 불필요한 재시험은 보류할 수 있습니다. 입력이 달라지거나 관리자가 다시 수집을 요청하면 재검토합니다. 커밋 제외는 사유와 현재 문제 참조를 요구하는 관리자 동작이며, 제외 취소나 나중 빌드 성공만으로 자동 배포 보류가 해제되지는 않습니다. 원인을 해결한 뒤 운영자가 `kpctl auto clear`로 해당 커널을 재개합니다.

`skip_trial_build=true`는 후보별 컴파일을 생략하는 명시적 선택입니다. 최종 누적 빌드와 산출물 검사는 계속 수행하며, 일부 검토된 수정본은 이 생략을 허용하지 않습니다. 후보 수집은 모든 CVE의 영향 판정이나 공격 차단 시험을 대신하지 않습니다.

구현: [filter.go](../../internal/builder/filter.go), [prereq.go](../../internal/builder/prereq.go), [trial_retry.go](../../internal/builder/trial_retry.go), [failure.go](../../internal/builder/failure.go), [commit_decisions.go](../../internal/controller/commit_decisions.go). 검증: [dependency_test.go](../../internal/builder/dependency_test.go), [trial_retry_test.go](../../internal/builder/trial_retry_test.go), [build_safety_test.go](../../internal/controller/build_safety_test.go).
