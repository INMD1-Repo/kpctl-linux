# 승인용 VM 시험 운영

<a id="test-vm"></a>

`test_vm.enabled=true`이면 일반 승인과 자동 승인 모두 VM 통과 후 배포합니다. 출시 전 승인에는 켜진 VM 시험이 필수입니다. 시험 대상은 운영에 제공할 동일 서명 사본이며, 다른 시험 키로 만든 모듈의 성공으로 대체하지 않습니다.

<a id="guests"></a>

## 게스트 준비

대상 `uname -r`가 정확히 일치하는 Ubuntu GA 게스트를 준비합니다. SSH 키 로그인, 비대화식 sudo, `kpatch`, sysfs와 커널 로그 읽기가 필요합니다. 게스트에는 다른 활성 라이브패치, 진행 중 전환, 운영 에이전트의 자동 적용 작업을 두지 않습니다. 사전 상태가 더러우면 시험을 중단합니다.

| 모드 | 확인하는 실제 부팅 상태 |
| --- | --- |
| `sb_on` | UEFI·Secure Boot on, lockdown integrity/confidentiality 또는 sig_enforce on |
| `sb_off` | UEFI·Secure Boot off |
| `bios` | BIOS·Secure Boot off |

`modes="auto"`는 같은 커널의 호스트 보고에서 필요한 모드를 합칩니다. 오래된 보고도 포함하고, 펌웨어·SB가 미확인이거나 호스트가 없으면 세 모드를 모두 선택합니다. 명시한 모드 배열은 그 배열을 사용하므로 실제 fleet의 모드를 빠뜨리지 않도록 검토합니다.

`sb_on` 게스트의 shim/MOK에는 시험할 운영 키를 등록합니다. 새 키·옛 키가 모두 필요한 승인에는 해당 키가 실제로 신뢰되는 게스트가 필요합니다. 부팅 커널 이미지의 신뢰와 `.ko` 서명은 별개입니다. 공식 서명된 GA 이미지를 사용하며, 별도 이미지 서명이 필요한 환경의 `sbsign` 작업을 kpctl이 대신 수행하지 않습니다. 사용자 제작 커널을 이 경로의 지원 기준으로 바꾸지 않습니다.

## 고정 VM과 일회 VM

[고정 VM 설정 예제](../../configs/testvm.example.json)의 `test_vm` 블록을 컨트롤러 설정에 넣고 실제 커널·모드별 SSH 주소와 키를 지정합니다. 고정 VM은 생성·삭제하지 않으며 모드별로 동시에 중복 사용하지 않게 잠급니다. 시험 후 모듈·임시 파일을 정리하고 원래 부팅 상태를 확인합니다.

[QEMU 설정 예제](../../configs/testvm-qemu.example.json)는 외부 명령 네 개로 일회 VM을 관리합니다. 예제 경로의 스크립트를 설치하고 컨트롤러 사용자에게 디스크·NVRAM 읽기, VM 작업 디렉터리 쓰기, `/dev/kvm` 접근 권한을 준비합니다. 게스트용 SSH 키와 QEMU·qemu-img·OVMF 등도 운영자가 준비합니다. 컨트롤러 설치 스크립트가 완성된 게스트 이미지를 자동 제작한다고 가정하지 않습니다.

예제의 `images`는 비워 두었습니다. 파일을 준비한 뒤 이 맵에 실제 커널 이름을 키로 넣고 그 안에 `sb_on`, `sb_off`, `bios`별 객체를 추가합니다. 각 객체의 `disk`는 존재하는 디스크 파일 경로이며 UEFI 두 모드는 `vars`도 필요합니다. 로더는 비활성 설정에 등록한 이미지도 실제 일반 파일인지 검사하므로, 없는 예제 경로를 넣어 두지 않습니다.

UEFI 디스크와 VARS 파일은 한 쌍입니다. `sb_on`과 `sb_off` 이미지는 각 실제 상태를 확인한 뒤 보존하고, BIOS에는 VARS를 지정하지 않습니다. QEMU helper는 원본 디스크를 덮는 대신 overlay와 NVRAM 사본을 만듭니다. 기본 SSH listen은 localhost, 동시 수는 2, 메모리는 4096 MiB, CPU는 2개입니다.

`allow_tcg=false`가 기본이며 KVM이 없으면 실패합니다. 명시적으로 TCG를 허용하면 boot timeout을 네 배로 늘리고 경고합니다. CPU 기능·속도가 운영 KVM과 다를 수 있으므로 이 결과를 같은 실행 환경으로 간주하지 않습니다. `seed_iso=true`를 선택할 때는 공개 SSH 키와 cloud-localds가 추가로 필요합니다.

<a id="evidence"></a>

## 승인과 증거

```sh
sudo kpctl log 12
sudo kpctl approve 12
sudo kpctl jobs
```

웹의 작업 상세에서 각 키·모드·단계와 SHA를 확인합니다. `negative_sig_test`는 생략 시 켜지며 `sb_on`에서 서명 전 원본 로드를 반드시 거부해야 합니다. 서명 강제가 실제로 꺼진 게스트는 이미지 설정 오류로 실패합니다.

| 단계 | 성공 증거 |
| --- | --- |
| boot | 정확한 커널·펌웨어·보안 상태 |
| negative_signature | unsigned 거부와 모듈 미잔류 |
| load_previous | 같은 키의 이전 누적본 활성·전환 완료 |
| load_new·replace | 새 누적본 활성·전환 완료, 이전본 비활성·전환 없음 |
| smoke | 설정한 `smoke_cmd`가 새 모듈 활성 중 성공 |
| rollback | 이전본 복원·전환 완료, 새 모듈 비활성 |
| cleanup·kernel_log | 정리 완료, 부팅 ID 불변, 시험 후 새 오류 로그 없음 |

최초 배포처럼 이전 누적본이 없거나 smoke 명령이 없으면 해당 단계는 skipped로 기록됩니다. 이전 모듈이 필요한데 같은 키 사본을 확인하지 못하면 다른 키를 대신 써서 rollback 성공으로 처리하지 않습니다. 새 키 bootstrap은 [pin 기반 이전 사본 절차](secure-boot.md#key-rotation)를 따릅니다.

컨트롤러는 현재·원본·이전 파일 SHA를 시험 전후 비교합니다. 모든 모드의 정리까지 끝난 뒤 승인하며, 도중 실패는 배포를 막고 자동 hold를 남깁니다. 성공한 시험 이후 fleet·작업·누적 입력이 바뀌었어도 최종 승인에서 다시 확인합니다.

<a id="recovery"></a>

## 실패·재시작 복구

기본 로그는 `data_dir/testlogs/kpctl-test-<작업>-<모드>-<키>.*`에 남습니다. console과 guest 단계 출력을 함께 보며, panic/oops뿐 아니라 새 BUG·WARNING·Call Trace·livepatch 실패도 검토합니다. 일반 livepatch taint와 시험 모듈에 한정한 허용 로그 외의 오류를 성공으로 덮지 않습니다.

일회 VM은 성공·실패·timeout 후 모두 삭제를 시도합니다. 컨트롤러 재시작 시 state의 기록과 외부 list 명령의 잔류 VM을 합쳐 정리합니다. 고정 VM 정리에 실패하면 시험을 계속 재사용하지 말고 연결·모듈·부팅 ID를 직접 복구합니다. 전체 VM 디렉터리나 무관한 프로세스를 PID 파일만 보고 제거하지 않습니다.

가짜 Runner를 쓰는 Go 시험은 명령 계약·실패 차단을 검증합니다. 실제 부팅·키 신뢰·커널 기능 검증은 위 조건을 충족한 VM에서 별도로 수행해야 합니다.

근거: [설정·모드 선택](../../internal/testvm/config.go), [시험·정리·로그 판정](../../internal/testvm/manager.go), [컨트롤러 승인 연결](../../internal/controller/testvm.go), [QEMU 생성 helper](../../deploy/testvm/qemu/create.sh), [기능 정의](../features/test-vm.md#f22).
