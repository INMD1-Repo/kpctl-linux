# 승인 전에 실행하는 VM 검사

[기능 목차](README.md) · [서명 자격](signing.md#f21)

<a id="f22"></a>
## F22. 실제 산출물의 부팅·거부·교체·롤백 검증

`test_vm.enabled`의 기본값은 false입니다. 켜면 컨트롤러가 승인할 실제 서명 사본을 키별로 시험하고 SHA256·모드·단계를 작업에 남깁니다. 시험 VM 전용 키로 별도 바이트를 만들지 않습니다. 배포할 서명 바이트 그대로 시험해야 운영에서 제공할 파일과 시험 증거가 일치하기 때문입니다.

고정 VM은 `fixed`, 일회용 VM은 `images`에 커널·모드별로 지정합니다. 일회용 생성·삭제·콘솔·목록은 외부 명령 계약으로 연결하며 QEMU 스크립트는 그 구현 예입니다. 모드는 sb_on, sb_off, bios이고 auto는 해당 커널의 보고를 바탕으로 선택합니다. 펌웨어/SB 정보가 없거나 fleet가 비어 있으면 모든 모드를 요구합니다. 고정 VM별 직렬화와 전체 동시 실행 제한은 정리 단계까지 유지됩니다.

### 검사 단계

| 단계 | 성공 조건 |
|---|---|
| boot | 정확한 커널·펌웨어·SB·lockdown·sig_enforce 확인 |
| negative_signature | sb_on에서 서명 전 원본 load가 거부되고 잔존 모듈 없음 |
| load_previous | 이전 배포본이 있으면 같은 키 사본이 활성·전환 완료 |
| load_new | 새 모듈 enabled=1, transition=0 |
| replace | 이전 모듈이 제거됐거나 비활성·전환 완료 |
| smoke | 새 모듈이 활성인 동안 설정한 argv 명령이 0으로 종료 |
| rollback | 이전 모듈 재로드 후 활성·전환 완료, 새 모듈 비활성/제거 |
| cleanup | 시험 모듈·작업 디렉터리 제거, 다른 공급자 모듈 제거 없음 |
| kernel_log | 기준 이후의 새 커널 오류가 없음 |

sb_on은 Secure Boot on이면서 lockdown integrity/confidentiality 또는 sig_enforce on이어야 합니다. 이 조건이 없으면 모듈 결함으로 분류하지 않고 이미지 설정 오류로 실패합니다. unsigned 원본이 없으면 부정 시험을 성공으로 생략하지 않습니다. 원본이 로드되면 즉시 unload하고 서명 강제 미동작으로 실패합니다.

이전 누적본이 없으면 load_previous·replace·rollback은 사유와 함께 skipped입니다. 같은 키의 이전 사본이 없을 때는 [검증된 원본 기반 키 교체](signing.md#f21)로 준비할 수 있어야 하며, 준비·검증할 수 없는 경우 승인하지 않습니다. `smoke_cmd`는 인자 경계를 유지하고 기존 test_timeout 안에서 실행합니다.

### 로그와 정리

fixed와 disposable 모두 시험 전 boot ID와 전체 dmesg를 기준으로 잡습니다. 이후 로그에 그 prefix가 정확히 남아 있어야 하며 ring buffer 회전·삭제로 연속성을 확인하지 못하면 실패합니다. 고정 VM의 과거 WARNING/Oops 줄만으로 새 시험을 실패시키지 않습니다.

새 Oops, panic, BUG, WARNING, Call Trace, livepatch 실패는 거부합니다. sb_on의 module verification failed도 실패입니다. 일반 livepatch K taint는 허용하지만 sb_off/bios의 서명 검증 taint는 시험 대상 모듈에 귀속되는 줄만 허용합니다. 일회용 VM의 serial console panic도 실패로 남깁니다.

시험 셸의 EXIT trap과 독립된 후속 SSH 정리를 사용합니다. 실패·시간 초과에도 제공한 kpctl 모듈 이름만 정리하고 잔존을 확인합니다. 정리하지 못한 고정 VM은 실패와 수동 복구 필요 상태를 보고하며 자동 재부팅으로 숨기지 않습니다. 일회용 VM은 삭제하고 실패한 삭제·고아 기록은 시작 시 복구 대상에 남깁니다.

### 선택 설정

다음은 검사 옵션의 완전한 비활성 예제입니다. 실제 활성화에는 커널별 fixed/images, SSH 키와 일회용 외부 명령 등을 준비해야 합니다.

<!-- config-example: testvm -->
```json
{
  "enabled": false,
  "modes": "auto",
  "negative_sig_test": true,
  "smoke_cmd": ["/usr/bin/true"],
  "test_timeout": "5m"
}
```

negative_sig_test는 생략하면 true이며 sb_on에서만 수행합니다. false는 명시적 생략입니다. smoke_cmd는 생략 가능하고 빈 실행 파일·NUL 인자는 설정 오류입니다. 모르는 설정 키는 거부합니다. 완전한 구성 형태는 [고정/외부 VM 예시](../../configs/testvm.example.json), [QEMU 예시](../../configs/testvm-qemu.example.json)를 보세요.

구현: [manager.go](../../internal/testvm/manager.go)의 `RunWithArtifacts`, `runGuest`, `testModule`, `allowedKernelLog`, `checkKernelLog`; [config.go](../../internal/testvm/config.go)의 `Config.Validate`, `SelectModes`; [controller/testvm.go](../../internal/controller/testvm.go)의 `testModule`; [model/testvm.go](../../internal/model/testvm.go)의 `VMTestResult`, `VMTestStep`.

검증: [security_test.go](../../internal/testvm/security_test.go), [fixed_test.go](../../internal/testvm/fixed_test.go), [manager_test.go](../../internal/testvm/manager_test.go), [controller VM 시험](../../internal/controller/testvm_test.go), [QEMU 계약 시험](../../test/qemu_scripts_test.py). 가짜 도구·파일 기반 시험은 실제 커널·Secure Boot 하드웨어 실행 검증이 아닙니다.
