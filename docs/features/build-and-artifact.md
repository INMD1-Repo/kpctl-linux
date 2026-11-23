# 누적 빌드와 산출물

[기능 목차](README.md)

<a id="f03"></a>
## F03. 소스, 도구와 대상 GCC 환경

`build_tool=auto`는 대상 config에서 `CONFIG_KLP_BUILD=y`를 확인하면 native klp-build를 고르고, 아니면 kpatch-build를 사용합니다. 커널 버전 번호만으로 선택하지 않습니다. `kpatch` 또는 `klp`를 명시할 수도 있지만 대상 커널의 도구·구성 조건을 만족해야 합니다.

빌드는 정확한 기준 태그와 공식 config, vmlinux, 헤더·심볼 자료를 사용합니다. Ubuntu 인증서나 원래 config를 제거해 컴파일 실패를 우회하지 않습니다. 필요한 디버그 자료는 설정한 도우미로 준비하며, `controller_kernel_inputs`를 사용하면 컨트롤러가 제공하는 정확한 패키지 바이트·크기·SHA256을 확인합니다.

`sandbox`를 지정하면 대상 커널에 기록된 GCC에 맞는 프로파일과 고정 컨테이너 이미지로 격리 빌드합니다. 프로파일의 GCC가 다르거나 준비되지 않으면 준비·검토 단계에서 멈춥니다. 격리 빌드 실패를 호스트 빌드로 자동 우회하지 않습니다. `sandbox` 생략 시에는 기존 호스트 빌드 경로를 유지하므로 운영 배포 설정에서 실제 격리 환경 사용 여부를 확인해야 합니다.

native 경로의 `cumulativeKLPPatches`는 선택한 패치들을 비공개 Git index에 순서대로 적용해 하나의 누적 diff로 만듭니다. 운영 소스 checkout을 후보마다 임의 변경하는 방식이 아닙니다. 소스 무결성·잠금·기준 캐시도 빌드 입력의 일부로 관리합니다.

구현: [klp.go](../../internal/builder/klp.go)의 `buildTool`, `runBuild`, `runKLPBuild`; [cumulative.go](../../internal/builder/cumulative.go)의 `cumulativeKLPPatches`; [sandbox_profiles.go](../../internal/builder/sandbox_profiles.go)의 `sandboxProfile`; [sandbox_prepare.go](../../internal/builder/sandbox_prepare.go)의 `ensureSandboxProfile`; [integrity.go](../../internal/builder/integrity.go).

검증: [klp_test.go](../../internal/builder/klp_test.go), [cumulative_test.go](../../internal/builder/cumulative_test.go), [sandbox_profiles_test.go](../../internal/builder/sandbox_profiles_test.go), [sandbox_prepare_test.go](../../internal/builder/sandbox_prepare_test.go).

<a id="f04"></a>
## F04. ELF, vermagic와 심볼 CRC

빌더의 `verifyModule`은 컴파일러 종료 코드 외에 실제 모듈을 읽습니다. 재배치 가능한 ELF인지, 아키텍처·이름·실행 ABI·livepatch 표시가 맞는지 검사하고 공통 `klpcheck` 검사를 수행합니다. config의 vermagic 플래그를 대조하며, MODVERSIONS 대상은 공식 모듈의 전체 vermagic 및 대상 Module.symvers의 참조 심볼 CRC와 비교합니다.

인증서·헤더·ELF·vermagic·CRC가 맞지 않는 결과를 배포 가능한 모듈로 취급하지 않습니다. 이 검사는 실행 중 락 순서나 데이터 의미 변화까지 증명하지 않습니다. 실제 VM·호스트 시험은 별도 단계입니다.

컨트롤러는 신뢰한 빌더가 제출한 바이트를 저장합니다. 업로드에서 빌더의 전체 ABI 검사를 독립적으로 반복하지 않으므로 빌더 토큰은 신뢰 경계입니다. 에이전트는 받은 SHA256과 공통 ELF 검사를 확인한 뒤 load를 시도합니다. 부팅 시 kpatch.service의 일괄 로드는 에이전트의 다운로드 검사를 다시 실행하지 않습니다.

구현: [module.go](../../internal/builder/module.go)의 `verifyModule`, `verifyVermagicFlags`, `compareModuleVersions`; [klpcheck](../../internal/klpcheck/check.go); [agent.go](../../internal/agent/agent.go)의 `loadVersion`. 검증: [module_test.go](../../internal/builder/module_test.go), [빌드 안전 시험](../../internal/controller/build_safety_test.go).

<a id="f05"></a>
## F05. 누적 작업, 배정과 결과 저장

컨트롤러의 `createJobChannel`이 현재 활성 입력을 고정하고 버전 번호를 부여합니다. 정식 버전은 커널별 양수 카운터를 사용하며, 같은 채널의 이전 queued/running/built 작업은 새 누적본에 포함되므로 superseded가 됩니다. 출시 전 입력과 번호는 [별도 채널](prerelease-and-cna.md#f23)에 둡니다. 전체 작업 ID는 공통으로 유일합니다.

빌더는 선언한 시리즈·명시 커널 범위 안에서 긴급 작업을 먼저 받고, 같은 우선순위에서는 먼저 생성된 작업을 받습니다. 작업에는 고정된 패치 내용과 해시, 확인 가능한 대상 커널 정보가 들어갑니다. 빌더는 패치 묶음의 선행 커밋을 중복 제거하고 누적 모듈을 생성합니다.

기본 상태 흐름은 queued → running → built → released입니다. 빌드 실패는 failed로 남기고 입력을 보존합니다. VM 시험은 built 작업의 별도 `vm_test` 상태로 기록하며 시험 중이라고 배포 상태를 미리 바꾸지 않습니다. 오래 끊긴 running 작업은 하트비트와 기본 180분 제한을 기준으로 다시 대기열에 넣습니다.

성공한 업로드는 모듈과 `unsigned_sha256`을 저장합니다. 승인 때 보존한 서명 전 원본이 이 pin과 맞아야 합니다. 키별 서명 바이트의 해시와 VM 증거는 승인 결과에 추가합니다. 결과 전송 실패는 빌더에서 제한적으로 재시도하며, 실패한 누적 빌드가 보안 패치의 자동 제외로 이어지지 않습니다.

구현: [jobs.go](../../internal/controller/jobs.go)의 `createJobChannel`, `nextQueuedJob`; [handlers_builder.go](../../internal/controller/handlers_builder.go)의 `handleBuilderNext`, `handleBuilderResult`; [worker.go](../../internal/builder/worker.go)의 `BuildNext`, `sendResult`, `build`. 검증: [jobs_test.go](../../internal/controller/jobs_test.go), [task_test.go](../../internal/controller/task_test.go), [result_retry_test.go](../../internal/builder/result_retry_test.go).
