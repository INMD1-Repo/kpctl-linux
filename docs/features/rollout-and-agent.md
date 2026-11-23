# 승인, 링 배포와 호스트 적용

[기능 목차](README.md)

<a id="f06"></a>
## F06. 승인과 링 승급

`kpctl approve`는 built 작업의 상태를 확인하고 서명 사본을 준비합니다. VM 기능이 켜져 있으면 실제 배포 사본마다 모든 필요한 모드의 시험을 끝냅니다. 배포 직전에 작업 상태, 출시 전 동의, 현재 fleet 모드, 원본·산출물 해시를 다시 확인하고 첫 링의 목표를 갱신합니다. 서명 방식과 호스트별 자격은 [F21](signing.md#f21), VM 단계는 [F22](test-vm.md#f22)에 정의합니다.

승인은 `Store.UpdateAtomic`의 복제 상태에 적용하고 상태 파일 저장에 성공한 뒤 live 상태로 공개합니다. 서명 키 교체용 이전 사본도 이 승인에 함께 연결합니다. 승인되지 않은 키 사본은 다운로드 metadata gate를 통과하지 않습니다.

`kpctl promote`는 바로 이전 링의 목표를 다음 링으로 옮깁니다. 기본 검사는 관찰 시간, 보고 신선도, 오류, 목표 버전, 전환 종료와 실제 활성 모듈입니다. MOK·서명 사유로 제외된 호스트는 이 건강 검사에서 빼며 결과에 제외 수와 사유를 반환합니다. `-force`는 관리자가 관찰·건강 검사를 건너뛰는 별도 조작입니다. 출시 전 목표에는 추가 명시 동의가 필요합니다.

구현: [handlers_admin.go](../../internal/controller/handlers_admin.go)의 `approveJobWithPrerelease`, `promoteKernelWithPrerelease`; [rollout.go](../../internal/controller/rollout.go)의 `promoteProblems`; [state.go](../../internal/controller/state.go)의 `UpdateAtomic`. 검증: [rollout_test.go](../../internal/controller/rollout_test.go), [testvm_test.go](../../internal/controller/testvm_test.go), [state_atomic_test.go](../../internal/controller/state_atomic_test.go).

<a id="f07"></a>
## F07. 보고, 적용과 부팅용 설치

에이전트는 등록 토큰으로 전용 호스트 토큰을 받은 뒤 기본 60초 주기로 실행 커널, 로컬 버전, 활성·전환 모듈, 보안 신호와 준비 상태를 보고합니다. `module_sha256`은 현재 부팅용 설치 사본의 실제 해시입니다. 컨트롤러의 `desired`는 커널과 링의 목표, 즉시 업데이트 지정, 출시 전 목표와 서명 자격으로 보낼 사본을 고릅니다.

새 비영 버전 적용은 다운로드 전과 load 직전에 다른 공급자의 활성·전환 패치가 없는지 확인합니다. 새 파일의 SHA256과 ELF 검사를 마치고 kpatch load를 실행합니다. enabled=1이고 transition=0임을 확인한 뒤 부팅용 설치와 버전 기록을 수행하고 이전 kpctl 설치본을 정리합니다. 전환 확인 실패에는 이전 부팅용 설치본을 유지합니다. 전환 후 정리 실패도 오류로 보고하고 후속 사이클에서 다시 정리합니다.

`blocked=true`는 기존 보호를 유지하라는 응답입니다. 에이전트가 이를 v0 롤백으로 처리하지 않습니다. 같은 버전에서 active 키가 바뀌어도 현재 설치 해시와 등록 상태에 맞는 기존 서명 사본을 유지할 수 있습니다. 키 변경만으로 같은 이름의 설치 파일을 덮어써 해시 충돌을 만들지 않습니다.

다른 공급자의 모듈은 직접 내리지 않습니다. 또한 다운로드·전환·실패 재시도 시간은 보고 주기와 별개이므로 모든 적용을 60초 안에 끝낸다고 보장하지 않습니다.

구현: [agent.go](../../internal/agent/agent.go)의 `Cycle`, `apply`, `loadVersion`, `activateVersion`, `installVersion`; [kpatch.go](../../internal/agent/kpatch.go)의 `checkCanLoad`, `waitTransition`; [handlers_agent.go](../../internal/controller/handlers_agent.go)의 `handleReport`; [rollout.go](../../internal/controller/rollout.go)의 `desired`, `rolloutEligibility`. 검증: [agent_test.go](../../internal/agent/agent_test.go), [signing_identity_test.go](../../internal/controller/signing_identity_test.go).

<a id="f08"></a>
## F08. 롤백, 입력 제외와 즉시 업데이트

`kpctl rollback`은 모든 링을 지정한 기존 승인 버전으로 돌리고 호스트별 즉시 업데이트 지정을 해제합니다. 버전 0은 kpctl 모듈과 설치본 제거 요청입니다. 롤백은 자동 배포를 수동 보류로 남깁니다. 출시 전 음수 버전은 `--prerelease` 동의가 필요합니다.

`kpctl patch disable`은 다음 누적 빌드의 입력 상태를 바꿉니다. 이미 고정한 작업이나 실행 중인 모듈을 즉시 수정하지 않습니다. 제외를 반영하려면 새로 빌드·검토·승인해야 합니다.

호스트 즉시 업데이트 API는 최신 승인된 정식 누적본을 특정 호스트에 지정합니다. 링보다 앞설 수 있으므로 관리자 판단이 필요합니다. 출시 전 버전이나 출시 전 목표를 사용 중인 호스트에는 이 지름길을 적용하지 않습니다. 취소하면 링 목표를 따릅니다.

구현: [handlers_admin.go](../../internal/controller/handlers_admin.go)의 `handleRollback`, `handlePatchState`, `handleHostUpdateNow`. 검증: [auto_test.go](../../internal/controller/auto_test.go), [prerelease_integration_test.go](../../internal/controller/prerelease_integration_test.go).

<a id="f09"></a>
## F09. 자동 배포와 검토 보류

자동 배포는 기본 꺼짐입니다. 켜면 새로 추가한 입력이 자동 승인 대상인지 확인하고 관리자 승인과 같은 함수를 사용합니다. 새 수동 제출 입력이나 새 패치 없는 재빌드는 직접 승인 대상으로 남깁니다. 자동 승급도 실제 적용·신선도·관찰 시간을 확인하며 `approve_only`는 후속 링을 수동으로 남깁니다.

호스트 오류, 빌드 실패, 수집 검토 문제, 롤백은 자동화를 보류시킵니다. 문제가 해결돼 보이더라도 수동 검토 보류를 저절로 해제하지 않습니다. 전체 일시 중지는 `kpctl auto pause`, 재개는 `kpctl auto resume`, 커널별 검토 후 해제는 `kpctl auto clear`로 조작합니다. 출시 전 목표가 있으면 정식 자동 승인·승급도 보류해 운영자가 유지한 출시 전 보호를 자동으로 덮어쓰지 않습니다.

설정은 `auto_rollout`과 운영 `settings.json`의 자동 배포·관찰 값입니다. 기본 자동 관찰 시간은 1440분이며 링별 최소 관찰과 함께 적용합니다. 자동 확인 루프의 기본 주기는 60초입니다.

구현: [auto.go](../../internal/controller/auto.go)의 `planAuto`, `autoIneligible`, `planPromote`, `autoTick`, `holdResolved`; [settings.go](../../internal/controller/settings.go). 검증: [auto_test.go](../../internal/controller/auto_test.go), [settings_test.go](../../internal/controller/settings_test.go).
