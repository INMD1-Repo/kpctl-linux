# 디스크 커널 준비와 승인 재부팅

[기능 목차](README.md)

<a id="f10"></a>
## F10. 새 GA 커널 준비

라이브패치 적용은 실행 중인 ABI를 바꾸지 않습니다. 새 디스크 커널 준비는 이후 승인 재부팅에 쓸 이미지·initrd·config·GRUB 항목을 마련하는 작업입니다. 에이전트의 `maybePrepareKernel`은 컨트롤러의 준비 요청을 받아 별도 도우미를 실행하고 prepared 또는 실패·재시도 상태를 보고합니다.

준비 도우미는 신뢰한 APT 배포 범위에서 더 새로운 동일 계열 GA generic 커널을 선택하고 설치·부팅 구성을 확인합니다. 대상 ID에는 패키지 버전과 부팅 파일 해시 등이 묶입니다. 기록의 소유자·권한, 파일 해시, GRUB 항목과 현재 기본 부팅 항목이 맞지 않으면 준비된 대상으로 인정하지 않습니다. 준비만으로 재부팅하거나 새 커널을 실행 상태로 보고하지 않습니다.

`auto_prepare_kernel`은 기본 꺼짐입니다. 범위 밖 호스트에 대한 준비 요청과 `auto_jump_kernel_hosts`의 승인 대상 지정은 서로 다른 조건입니다. 일반 커스텀 커널 이미지의 설치·서명·부팅 경로는 이 기능에 포함되지 않습니다.

구현: [kernel_prepare.go](../../internal/agent/kernel_prepare.go)의 `maybePrepareKernel`; [kpctl-prepare-kernel.py](../../deploy/kpctl-prepare-kernel.py); [reboot.go](../../internal/agent/reboot.go)의 `bootTarget`; [kernel_jump.go](../../internal/controller/kernel_jump.go)의 `kernelRefreshTargetID`. 검증: [kernel_prepare_test.go](../../internal/agent/kernel_prepare_test.go), [kernel_prepare_test.py](../../test/kernel_prepare_test.py).

<a id="f11"></a>
## F11. 드레인과 한 번의 대상별 승인

승인에는 drain 정책, cordon 상태, 최근 확인한 VM 0대, 신선한 호스트 보고, 호스트 오류 없음과 유효한 준비 대상이 필요합니다. 컨트롤러는 스케줄러 명령이 있으면 VM 수를 다시 조회합니다. 없으면 에이전트의 명시적인 로컬 VM 수를 사용하며 미확인을 0으로 만들지 않습니다.

관리자가 승인한 정확한 대상 ID와 현재 boot ID를 5분 동안 유효한 일회성 승인에 고정합니다. 에이전트는 실행 직전에 승인 claim, VM 수, 실행 커널·부팅 ID, 파일·잠금·만료를 재확인하고 일회성 GRUB 항목을 준비한 뒤 재부팅 훅을 실행합니다. 단순한 이전 형식의 재부팅 번호만 내려 실행시키지 않습니다.

자동 점프는 `auto_jump_kernel_hosts`에 정확한 등록 ID를 지정한 호스트로 제한합니다. 자동 준비도 켜져 있어야 하며, 이미 cordon된 호스트가 정식 대상·신선도·VM 조건을 만족해야 합니다. 코드는 호스트를 임의로 드레인하거나 uncordon하지 않고, 다른 미완료 승인과의 순차 진행을 확인합니다. 실패한 같은 부팅·대상을 자동으로 반복 승인하지 않습니다.

`kpctl host cordon`, `kpctl host reboot`, `kpctl host uncordon`은 별개의 관리자 조작입니다. MOK 등록 예약은 이 승인 경로를 호출하지 않습니다. 상세 조작은 [Secure Boot 운영](../operations/secure-boot.md)을 함께 보세요.

구현: [controller/reboot.go](../../internal/controller/reboot.go)의 `rebootProblem`, `handleHostReboot`, `handleRebootClaim`; [drain.go](../../internal/controller/drain.go)의 `checkDrain`; [kernel_jump.go](../../internal/controller/kernel_jump.go)의 `maybeApproveKernelJump`; [agent/reboot.go](../../internal/agent/reboot.go)의 `maybeReboot`. 검증: [reboot_test.go](../../internal/controller/reboot_test.go), [kernel_jump_test.go](../../internal/controller/kernel_jump_test.go), [agent 재부팅 시험](../../internal/agent/reboot_test.go).

<a id="f12"></a>
## F12. 실제 부팅 확인과 선택 정리

컨트롤러의 `reconcileReboot`는 boot ID 변경만으로 성공 처리하지 않습니다. 승인 실행 기록, 정확한 대상 ABI·Ubuntu 패키지 버전이 일치해야 booted 결과를 남깁니다. 에이전트는 그 결과를 받은 뒤 준비 파일 해시를 다시 확인하고 새 GRUB 기본 항목을 확정해 확인 ID를 보고합니다.

승인 취소·만료와 실제 부팅 결과에 따라 에이전트는 자신이 설정한 일회성 항목만 정리합니다. 실행 전달 이후에는 취소보다 실제 결과 확인을 우선합니다. 에이전트 중단·전원 장애 동안 GRUB 자체가 승인 시간을 감시하는 것은 아니므로 설정된 다음 부팅 항목의 즉시 정리를 보장하지 않습니다.

실제 부팅을 마쳐도 호스트는 자동으로 uncordon되지 않습니다. 커널·서비스·작업 상태를 확인한 운영자가 복귀를 결정합니다. 라이브패치나 한 호스트의 재부팅 승인만으로 전체 서비스의 무중단을 보장하지 않습니다.

구현: [controller/reboot.go](../../internal/controller/reboot.go)의 `reconcileReboot`; [agent/reboot.go](../../internal/agent/reboot.go)의 `reconcileBootChoice`, `clearBootChoice`, `retireBootTarget`. 검증: [reboot_hook_test.py](../../test/reboot_hook_test.py), [reboot_test.go](../../internal/agent/reboot_test.go).
