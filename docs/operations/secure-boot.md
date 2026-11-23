# Secure Boot·서명·MOK 운영

<a id="secure-boot"></a>

서명 필요 여부는 Secure Boot 스위치 하나로 결정하지 않습니다. 에이전트는 펌웨어, EFI SecureBoot 변수, 커널 lockdown, `module.sig_enforce`를 보고하고 컨트롤러도 같은 정책으로 판단합니다. 수집 실패는 에이전트 보고 주기를 중단시키지 않으며 `unknown`과 경고로 표시합니다.

<a id="policy-table"></a>

## 서명 필요 조건표

`*`는 해당 열의 모든 값을 뜻합니다. 위에서부터 처음 일치하는 행을 적용합니다. 첫 세 행은 신호를 읽지 못한 경우이고, 나머지 행은 세 보안 신호를 모두 읽은 경우입니다. 펌웨어는 `uefi`, `bios`, `unknown` 전체를 포함합니다. 따라서 표는 모든 조합을 포괄합니다.

| firmware | secure_boot | lockdown | sig_enforce | 서명 필요 | 경고 |
| --- | --- | --- | --- | --- | --- |
| * | unknown·누락·잘못된 값 | * | * | 예 | 읽지 못한 모든 신호를 명시 |
| * | on·off | unknown·누락·잘못된 값 | * | 예 | 읽지 못한 모든 신호를 명시 |
| * | on·off | none·integrity·confidentiality | unknown·누락·잘못된 값 | 예 | sig_enforce 미확인 |
| * | on | none·integrity·confidentiality | on·off | 예 | 신호 수집 경고 없음 |
| * | off | integrity·confidentiality | on·off | 예 | 신호 수집 경고 없음 |
| * | off | none | on | 예 | 신호 수집 경고 없음 |
| * | off | none | off | 아니요 | 신호 수집 경고 없음 |

호스트가 별도로 `signature_required=true`를 보고하면 컨트롤러는 표의 결과와 OR하여 서명을 요구합니다. 펌웨어 미확인만으로 서명이 필요해지는 것은 아니지만, 보안 신호가 빠졌다면 필요로 판단합니다. BIOS에서도 lockdown이나 강제 서명이 켜질 수 있습니다.

| 위 표의 서명 필요 | firmware | MOK 필요·지원 | 배포 결과 |
| --- | --- | --- | --- |
| 아니요 | * | 배포를 위한 MOK 등록 요구 없음 | 해당 작업 기본 사본 사용 |
| 예 | uefi | shim/MOK를 쓰는 환경에서는 신뢰할 인증서의 등록 필요 | 아래 모드·등록·사본 선택표 적용 |
| 예 | bios·unknown | 자동 MOK 미지원; 실제 커널 신뢰 키·등록 방법 별도 확인 | 아래 선택표 적용; unknown fallback은 신뢰 검증 완료를 뜻하지 않음 |

## 서명 모드와 승인 결과

| `signing.mode` | 새 누적본 생성 | 서명 필요 호스트·VM이 있는 경우 |
| --- | --- | --- |
| `always` | 필요한 키별 사본에 항상 서명 | 등록 상태와 사본에 따라 호스트별 선택 |
| `when_required` | 해당 커널의 호스트 또는 켜진 `sb_on` VM 시험이 요구하면 서명 | 이전 unsigned 사본을 그대로 서명 가능하다고 취급하지 않음 |
| `never` | 서명하지 않음 | 호스트는 `blocked_signing_disabled`; 켜진 VM 시험이 서명을 요구하면 승인 자체 거부 |

명시적인 `signing` 블록은 active 키가 정확히 하나여야 합니다. 기존 최상위 `sign_command`는 `signing`과 함께 쓸 수 없으며, 블록을 생략하면 기존 `always` 동작과 `default` 키 이름으로 해석됩니다. 예전 명령에 고정 `.der` 인자가 있으면 공개 인증서 경로를 추출합니다. 상세 구성은 [컨트롤러 설치](../install/controller.md)와 [실제 설정 예제](../../configs/controller.example.json)를 참고하세요.

## 호스트별 사본 선택

아래 표는 서명 필요 호스트를 기준으로 합니다. 서명 불필요 호스트에는 해당 작업의 기본 사본을 사용합니다. 동일 버전의 설치 SHA를 유지하는 규칙이 새 버전의 active 우선순위보다 먼저 적용됩니다.

| 상태 | 결과 |
| --- | --- |
| `mode=never` | `blocked_signing_disabled`; 기존 모듈 유지 |
| 같은 버전이고 설치 SHA와 일치하는 허용된 signed 사본이 있음 | 그 사본 유지; active 변경은 새 누적 버전부터 반영 |
| 등록된 키의 signed 사본이 있음 | 새 버전은 active 등록 키 우선, 그다음 등록된 다른 설정 키 선택 |
| 등록된 키의 사본이 없거나 명시적으로 unsigned임 | `blocked_artifact`; 재승인 또는 새 누적본 필요 |
| 모든 설정 키가 명시적으로 `not_enrolled`임 | `blocked_mok_missing`: “MOK 등록 필요” |
| 위 상태에서 MOK 예약도 확인됨 | 같은 제외 상태, “다음 계획된 재부팅 때 콘솔에서 MOK 승인 필요” |
| 설치 SHA·등록 보고가 모두 없는 이전 에이전트 | 처음 적용할 때부터 작업 기본 사본을 일관되게 제공하고 경고; 명시적 unsigned·누락 사본은 차단 |
| 새 에이전트가 등록 상태를 unknown으로 보고함 | active 사본과 경고 전달; 명시적 unsigned·누락 사본은 차단 |

보안 신호와 등록 상태의 unknown은 서로 다른 정보입니다. 이전 에이전트는 필드가 없으므로 서명 필요로 판단하면서 등록 미확인 경고를 붙입니다. 이전 형식의 메타데이터에는 기존 기본 URL 호환 경로가 남아 있으므로, unknown 경고가 실제 키 신뢰 검증의 완료를 뜻하지 않습니다.

같은 버전의 모듈은 서명만 달라져도 SHA가 다릅니다. 에이전트는 같은 이름의 설치 파일을 다른 SHA로 덮는 대신 실패하도록 되어 있습니다. 컨트롤러는 보고된 `module_sha256`과 맞는 아직 허용된 사본을 유지합니다. 맞는 사본이 없으면 기존 보호를 유지하고 새 누적본을 요구합니다. SHA와 등록 정보가 모두 없는 이전 에이전트에는 최초 적용부터 원래 작업 기본 사본을 일관되게 제공하며 경고합니다. active 변경 뒤 처음 합류해도 다음 보고에서 동일 버전의 SHA가 바뀌지 않습니다. 새 누적본의 기본 사본이 새 키로 생성되면 그 새 버전부터 키가 바뀝니다.

제외는 v0 롤백이 아닙니다. 새 에이전트는 `blocked` 지시에서 적용을 건너뜁니다. 이전 에이전트에는 확인 가능한 현재 released 버전을 다시 전달하여 기존 보호를 유지하고, 현재 버전 증거가 없으면 보고 요청을 거부하여 적용 전에 멈춥니다. 관리자가 명시한 `rollback -version 0`은 패치를 실제로 내립니다. 제외 호스트는 링 승급 검사에서 제외되고 사유가 표시됩니다.

<a id="mok-enrollment"></a>

## 인증서 등록 예약과 콘솔 승인

MOK 자동화는 **UEFI와 shim/MokManager를 사용하는 부팅 환경**을 전제로 합니다. BIOS에서 강제 서명이 켜졌다면 MOK 자동 등록은 `unsupported`입니다. 해당 커널이 실제로 신뢰하는 키링과 운영자가 승인한 키 배포 방법을 먼저 확인해야 합니다. BIOS에 `mokutil --import`를 실행하면 해결된다고 가정하지 않습니다.

1. 컨트롤러에 공개 DER 인증서와 서명 명령을 설정하고, 키 ID와 인증서 내용을 확인합니다. 같은 ID의 DER은 처음 확인한 SHA에 고정됩니다. 인증서 교체에는 새 ID를 씁니다.
2. 시험 VM의 신뢰 키는 운영자가 별도로 등록합니다. 다음 CLI는 컨트롤러에 등록된 대상 호스트에 인증서 예약을 전달하며, 고정·일회 시험 VM 이미지를 자동 변경하지 않습니다.

   ```sh
   sudo kpctl signing list
   sudo kpctl signing rollout-cert prod-2026
   sudo kpctl hosts mok-password node-01
   ```

3. 호스트의 `mok_import` 결과와 `mok_pending`을 확인합니다. 예약은 재부팅을 실행하지 않습니다. 다음 계획된 재부팅 때 콘솔에서 해당 인증서와 호스트별 비밀번호를 확인하고 MOK 등록을 승인합니다.
4. 부팅 후 새 보고의 `enrolled_certs[키ID]=enrolled`를 확인합니다. pending이나 명령 성공만으로 등록 완료 처리하지 않습니다.

`rollout-cert`는 이미 등록된 호스트를 건너뛰고 나머지에 요청합니다. 비 UEFI·미확인 펌웨어에는 경고를 표시합니다. 실패·unsupported 요청은 원인을 해결한 뒤 명시적으로 다시 예약할 수 있습니다. 같은 키·인증서의 진행 중 요청을 반복 실행해 비밀번호를 계속 바꾸지 않습니다.

설치 묶음의 `install-agent.sh`에는 선택적인 `--enroll-mok`가 있습니다. 기본값은 꺼짐이며, 켜면 에이전트가 서명 필요·active 인증서 미등록 조건에서 예약을 요청합니다. 이미 설치한 에이전트는 `mok_auto_import` 설정으로 같은 동작을 선택할 수 있습니다. 일반 `kpctl install` 명령에 이 플래그가 있다고 가정하지 말고 직접 설치 스크립트 또는 설정 파일을 사용합니다.

컨트롤러는 무작위 호스트별 비밀번호 원문을 권한 0600의 `state.json`에 보관하고, OpenSSL의 SHA512-crypt 해시만 에이전트로 보냅니다. 비밀번호 조회는 감사 로그에 남으며 일반 상태 API에는 원문이 없습니다. 에이전트는 DER·X.509·SHA256을 확인한 뒤 `mokutil --import <DER> --hash-file <임시파일>`로 예약하고 해시 임시 파일을 지웁니다. 원문·해시는 에이전트 로컬 상태에 보존하지 않습니다.

`mokutil`이 없거나 `--hash-file`을 지원하지 않으면 실패·unsupported 안내를 확인합니다. UEFI/shim 호스트에서는 승인한 공개 DER로 `sudo mokutil --import /경로/인증서.der`를 수동 실행하고 다음 계획 재부팅의 콘솔 승인을 사용할 수 있습니다. 실제 `--test-key` 출력과 종료 코드를 함께 확인하며 pending·차단된 키를 enrolled로 오인하지 않습니다.

MOK import를 처리하는 주기에는 패치 적용·재부팅 경로로 진행하지 않습니다. 결과가 컨트롤러에 보고된 뒤의 후속 주기는 별도로 승인된 재부팅을 처리할 수 있습니다. kpctl의 재부팅 승인은 [정확한 새 GA 대상·드레인·5분 일회 승인](reboot-approval.md#reboot-approval) 조건을 그대로 적용합니다. MOK 등록을 위해 이 조건을 우회하지 않습니다.

<a id="key-rotation"></a>

## 키 교체

새 키를 이전 키 ID에 덮어쓰지 않습니다. 먼저 현재 키가 유효한 동안, 현재 컨트롤러로 업로드·승인한 pin 보유 누적본과 정상 VM 시험을 확보합니다. 인증서 만료 임박 전에 다음 순서로 진행합니다.

1. 새 ID를 inactive로 추가하고 기존 키를 active로 유지합니다. 서명 명령과 공개 DER, VM의 신뢰 키를 준비합니다. 새 키를 실제 필요한 호스트에 등록하고 enrolled 보고를 확인합니다.
2. VM 시험을 켠 상태로 새 누적본을 빌드·승인합니다. active 키와 서명 필요 호스트에 등록된 추가 키의 사본이 생성됩니다. 새 키 사본이 이전 배포 버전에 없으면, 보존된 이전 `.unsigned-<모듈>.ko`와 저장된 `unsigned_sha256`이 모두 존재하고 일치해야 합니다.
3. 컨트롤러는 이전 원본으로 **비공개 이전 버전 사본**을 새 키로 서명합니다. 현재 사본과 함께 모든 선택 모드에서 이전 로드→새 사본 replace→이전 버전 rollback을 시험하고 전후 SHA를 확인합니다.
4. 모든 키·모드 시험과 최종 상태·fleet 재검사가 성공하면 `UpdateAtomic` 최종 승인에서 검증된 이전 사본을 게시하고 이전 released 작업에 키별 메타데이터를 추가합니다. 기본 SHA·기본 URL의 바이트·active 키·정식 버전은 바꾸지 않습니다. 실패한 승인에서는 이전 키별 메타데이터를 게시하지 않습니다.
5. 양쪽 사본과 호스트 등록 상태를 확인한 후 새 키를 active로 전환하고 컨트롤러를 재시작합니다. 같은 버전을 이미 적용한 호스트는 허용된 설치 서명을 유지하며, 다음 누적 버전부터 새 active를 우선 사용합니다. 충분한 적용·롤백 관찰 뒤 기존 키를 제거합니다.

과거 released 작업에 unsigned pin이나 원본이 없으면 현재 서명 파일에서 원본을 추정하지 않습니다. 기존 키를 active로 유지한 채 먼저 **새 누적본을 현 컨트롤러로 업로드·승인**하여 원본과 pin을 확보한 다음 교체합니다. missing·corrupted 원본을 숨기거나 `.unsigned` 파일을 수작업으로 만들어 bootstrap을 통과시키지 않습니다.

`when_required`에서 이전 버전이 명시적으로 unsigned였으면 VM의 서명 강제 환경에서 이전 사본을 시험하기 위해서만 비공개 재서명합니다. 이 사본은 운영용 이전 variant로 게시하지 않고 기존 unsigned 사본·기본 alias를 보존합니다. 그 이전 버전으로의 운영 롤백은 서명 필요 호스트에서 차단될 수 있으므로, 필요한 롤백 기준을 signed 누적본으로 먼저 확보합니다.

키 제거 시 설정에 남은 enrolled 키가 없는 호스트는 경고합니다. 인증서 만료가 30일 이내이면 CLI·설정 화면에 경고하며 자동 배포의 켜짐 여부와 무관하게 컨트롤러 확인 루프에서도 감사합니다. 동일 경고는 반복을 줄이지만 재시작 시 다시 기록될 수 있습니다. 경고가 키 회수나 자동 교체를 실행하지는 않습니다.

<a id="vm-evidence"></a>

## VM 증거와 혼재 운영

VM에는 운영에 제공할 **동일한 서명 바이트**를 전달합니다. `sb_on`의 unsigned 거부 시험은 서명 전 원본을 쓰며 별도 시험 키로 생산 사본을 대체하지 않습니다. 모드별 boot, negative_signature, load_previous, load_new, replace, smoke, rollback, cleanup, kernel_log 결과와 키별 SHA를 확인합니다. `sb_on`은 SB on뿐 아니라 lockdown integrity/confidentiality 또는 sig_enforce on도 확인합니다.

고정 VM은 시험 후 정리하며, 일회 VM은 삭제합니다. 정리·새 커널 로그·예기치 않은 재부팅 실패도 승인 실패입니다. 실제 커널·펌웨어 신뢰와 패치 기능 검증은 운영 환경의 VM·호스트 시험이 필요하며 가짜 도구 단위 시험이 이를 대신하지 않습니다.

새 필드를 모르는 이전 에이전트에는 기존 URL·SHA 경로와 unknown 경고를 유지합니다. MOK 자동 예약·등록 보고·설치 SHA 선택 기능은 새 에이전트에서 사용합니다. 이전 빌더는 출시 전 capability가 없으므로 음수 작업을 받지 않습니다. 출시 전 상태가 있는 컨트롤러를 이전 버전으로 되돌리는 복구 호환은 보장하지 않습니다. [업그레이드·복구](upgrade.md#downgrade)에서 overlay 정리와 일관된 백업을 먼저 수행합니다.

근거: [공통 정책](../../internal/model/signing.go), [수집](../../internal/agent/security.go), [MOK 처리](../../internal/agent/signing.go), [배포 선택](../../internal/controller/rollout.go), [서명·이전 variant 검증](../../internal/controller/signing.go), [최종 승인](../../internal/controller/handlers_admin.go), [키 상태·예약](../../internal/controller/signing_admin.go), [VM 실행](../../internal/testvm/manager.go).
