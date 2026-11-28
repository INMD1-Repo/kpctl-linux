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
| 보안·서명 상태를 보고한 호스트에 서명이 필요하고 서명 키·명령이 없음 | `blocked_signing_disabled`. 컨트롤러의 키를 설정하고 새 누적본 승인 |
| 위 호스트에서 이전 작업의 서명 사본 메타데이터가 없음 | `blocked_artifact`. 원래 승인 작업의 기본 URL로 대체하지 않음 |
| 같은 버전이고 설치 SHA와 일치하는 허용된 signed 사본이 있음 | 그 사본 유지; active 변경은 새 누적 버전부터 반영 |
| 등록된 키의 signed 사본이 있음 | 새 버전은 active 등록 키 우선, 그다음 등록된 다른 설정 키 선택 |
| 등록된 키의 사본이 없거나 명시적으로 unsigned임 | `blocked_artifact`; 재승인 또는 새 누적본 필요 |
| 모든 설정 키가 명시적으로 `not_enrolled`임 | `blocked_mok_missing`: “MOK 등록 필요” |
| 위 상태에서 MOK 예약도 확인됨 | 같은 제외 상태, “다음 계획된 재부팅 때 콘솔에서 MOK 승인 필요” |
| 보안·서명 필드가 전혀 없는 이전 에이전트 | 작업 기본 사본과 미확인 경고. 서명 미설정의 익명 사본과 이전 형식의 기본 URL 호환 유지 |
| 새 에이전트가 등록 상태를 unknown으로 보고함 | active 사본과 경고 전달; 명시적 unsigned·누락 사본은 차단 |

`mokutil --test-key <DER> --ignore-keyring`에서 MokListRT 등록을 확인한 경우에만 에이전트가 `enrolled`로 보고합니다. UEFI db에서 일치하면 `in_db`로 보고하며 확인된 등록 수에 포함하지 않습니다. 이는 shim/MOK 목록에 대한 관찰입니다. 대상 Ubuntu GA 커널이 어느 키링에서 모듈 서명을 신뢰하는지는 해당 부팅에서 확인해야 합니다. db 일치만 관찰하면 등록 미확인 정책에 따라 경고와 함께 서명 사본을 제공할 수 있습니다.

보안 신호와 등록 상태의 unknown은 서로 다른 정보입니다. 이전 에이전트는 필드가 없으므로 서명 필요로 판단하면서 등록 미확인 경고를 붙입니다. 이전 형식의 메타데이터에는 기존 기본 URL 호환 경로가 남아 있으므로, unknown 경고가 실제 키 신뢰 검증의 완료를 뜻하지 않습니다.

같은 버전의 모듈은 서명만 달라져도 SHA가 다릅니다. 에이전트는 같은 이름의 설치 파일을 다른 SHA로 덮는 대신 실패하도록 되어 있습니다. 컨트롤러는 보고된 `module_sha256`과 맞는 아직 허용된 사본을 유지합니다. 맞는 사본이 없으면 기존 보호를 유지하고 새 누적본을 요구합니다. SHA와 등록 정보가 모두 없는 이전 에이전트에는 최초 적용부터 원래 작업 기본 사본을 일관되게 제공하며 경고합니다. active 변경 뒤 처음 합류해도 다음 보고에서 동일 버전의 SHA가 바뀌지 않습니다. 새 누적본의 기본 사본이 새 키로 생성되면 그 새 버전부터 키가 바뀝니다.

제외는 v0 롤백이 아닙니다. 새 에이전트는 `blocked` 지시에서 적용을 건너뜁니다. 이전 에이전트에는 확인 가능한 현재 released 버전을 다시 전달하여 기존 보호를 유지하고, 현재 버전 증거가 없으면 보고 요청을 거부하여 적용 전에 멈춥니다. 관리자가 명시한 `rollback -version 0`은 패치를 실제로 내립니다. 제외 호스트는 링 승급 검사에서 제외되고 사유가 표시됩니다.

<a id="mok-enrollment"></a>

## 인증서 등록 예약과 콘솔 승인

MOK 자동화는 **UEFI와 shim/MokManager를 사용하는 부팅 환경**을 전제로 합니다. BIOS에서 강제 서명이 켜졌다면 MOK 자동 등록은 `unsupported`입니다. 해당 커널이 실제로 신뢰하는 키링과 운영자가 승인한 키 배포 방법을 먼저 확인해야 합니다. BIOS에 `mokutil --import`를 실행하면 해결된다고 가정하지 않습니다.

1. [컨트롤러 설치·공통 키 준비](../install/controller.md#module-signing-key)에서 `sudo -u kpctl -- kpctl signing init-key prod-2026`를 실행하고, 서명 명령·공개 DER를 설정한 뒤 서비스를 재시작합니다. 대상은 UEFI/shim, Secure Boot on, 지원 Ubuntu GA 커널과 재부팅 중 접근 가능한 콘솔을 갖춰야 합니다. 대상에서 `mokutil --sb-state`, `uname -r`, `cat /proc/version_signature`를 확인합니다. `mokutil`이 없으면 대상에서 `sudo apt-get install mokutil`로 준비하세요.
2. **첫 시험은 `-host node-01`로 canary 한 대를 지정하세요.** 정확한 호스트 이름 또는 ID를 사용하며, 중복된 이름은 ID로 다시 지정합니다. `-host`를 생략한 기존 명령은 이 컨트롤러에 등록된 모든 호스트 중 인증서 미등록·미확인 대상에 예약합니다. 고정·일회 시험 VM 이미지의 신뢰 키는 운영자가 별도로 등록합니다.

   ```sh
   sudo kpctl install -check -group canary node-01
   sudo kpctl install -group canary node-01
   sudo kpctl signing list
   sudo kpctl hosts mok-status node-01
   # 이 호스트 한 대에만 예약합니다.
   sudo kpctl signing rollout-cert -host node-01 prod-2026
   sudo kpctl hosts mok-status node-01
   ```

3. 에이전트의 다음 보고 뒤 `mok-status`에서 해당 키의 예약 결과를 확인합니다. `pending`이면 콘솔 조작자가 비공개 터미널에서 `sudo kpctl hosts mok-password node-01`로 조회합니다. `awaiting_agent`는 다음 보고를 기다립니다. `pending_existing`이면 기존 예약과 비밀번호가 유지되므로 최초 예약자에게 콘솔 비밀번호를 확인합니다. 도구가 일반 경고를 출력한 뒤 인증서 대기가 확인되면 `pending`과 경고를 함께 보고합니다. 해석할 수 없는 출력을 반환하면 `pending_uncertain`에서 해당 요청의 후보 비밀번호를 조회할 수 있습니다. 경고가 있으면 최초 예약자와 값을 대조하세요. 구 에이전트의 `pending`은 출처가 불분명해 조회된 값이 콘솔 비밀번호와 다를 수 있습니다. 다음 계획된 재부팅 때 VM 콘솔의 MokManager에서 **Enroll MOK → View key**로 키 ID·지문을 대조한 뒤 Continue → Yes, 호스트별 비밀번호를 입력하고 부팅합니다. 지문이 SHA1 형식이면 컨트롤러에서 같은 DER에 `openssl x509 -inform DER -in 파일.der -noout -fingerprint -sha1`을 실행해 같은 형식으로 대조합니다.
4. 부팅 후 `mokutil --sb-state`가 enabled인지 다시 확인합니다. 컨트롤러에서 `sudo kpctl hosts mok-status node-01`의 보고 시각이 재부팅 후이고 `prod-2026: enrolled`인지 확인합니다. 마지막 예약 기록은 여전히 pending일 수 있습니다. 대상에서 직접 확인하려면 에이전트 기본 경로 `/var/lib/kpctl-agent/certs/<DER의 SHA256>.der`를 사용해 `sudo mokutil --test-key /해당/공개.der --ignore-keyring`을 실행합니다. mokutil 버전에 따라 정상 질의의 0·1 종료 규약이 다릅니다. 에이전트는 인증서 경로와 결과 문구를 함께 검사합니다. `unknown`이면 해당 DER, 지원 옵션, EFI 변수 접근과 부팅 경로를 확인합니다. [mokutil 0.6.0 소스](https://github.com/lcp/mokutil/blob/0.6.0/src/mokutil.c) · [현재 mokutil 소스](https://github.com/lcp/mokutil/blob/master/src/mokutil.c)

`rollout-cert`는 이미 등록된 호스트를 건너뛰고 나머지에 요청합니다. 비 UEFI·미확인 펌웨어에는 경고를 표시합니다. 실패·unsupported 요청은 원인을 해결한 뒤 같은 키로 명시적으로 다시 예약할 수 있습니다. 이때 컨트롤러가 저장한 콘솔 비밀번호는 그대로 두고 에이전트 작업 ID만 갱신합니다. 같은 키·인증서의 진행 중 요청을 반복 실행해 비밀번호를 계속 바꾸지 않습니다.

다른 키의 요청이 있으면 수동·자동 예약 모두 기존 처리 결과와 대기 보고를 확인합니다. 미지원(`unsupported`)은 import 실행 전 결과입니다. 이전 키가 등록됐거나 미지원으로 끝나고 대기 보고가 없으면 새 키를 예약할 수 있습니다. 실패(`failed`) 직후 호스트가 MOK 대기를 보고하면 관리자 조회에서 해당 요청의 후보 비밀번호를 확인할 수 있습니다. 대기가 해당 DER인지와 최초 예약자를 대조하세요. 실패는 펌웨어 쓰기 후에도 발생할 수 있어 동일 요청 결과와 최근의 **빈 MokNew** 보고가 있어야 다른 키로 넘어갑니다. 같은 키를 자동으로 반복 재시도하지 않습니다. 실제 import 직전에도 에이전트는 해당 공개 DER와 호스트 전체 대기 목록을 다시 확인합니다.

**같은 키를 다시 요청했는데 예약 수가 0일 때**에는 경고에 표시된 호스트·요청 ID와 `sudo kpctl hosts mok-status node-01`의 마지막 보고를 확인하세요. 전체 예약 응답의 `scheduled_hosts`는 요청 ID를 새로 발급한 호스트 수입니다. 기존 요청을 보존한 호스트는 경고에 표시하며, 단일 호스트의 같은 요청은 HTTP 409로 이유를 반환합니다. 실제 대기가 있으면 최초 예약자의 콘솔 승인을 진행하세요. 최근 보고에서 키가 `not_enrolled`이고 MokNew가 비었는데 이전 처리 결과가 남았다면 경고에 표시된 `-host`와 정확한 `-replace-request` 명령으로 같은 키를 재예약할 수 있습니다. 이때 기존 비밀번호와 해시를 유지하고 요청 ID를 갱신합니다.

**퇴역 키 또는 같은 키의 이전 요청이 계속 표시될 때**에는 대상 콘솔에서 `sudo mokutil --list-new`를 확인하세요. 대기 중이면 최초 예약자와 기존 콘솔 승인을 먼저 처리합니다. 운영자가 콘솔 처리를 마쳤거나 별도 절차로 대기를 정리했는데 컨트롤러에 `pending`·`pending_existing`·`pending_uncertain`만 남은 경우 아래 명령으로 **컨트롤러 요청**을 교체할 수 있습니다. 콘솔에서 다른 도구로 예약하는 작업과 시간을 겹치지 않게 하세요.

```sh
sudo kpctl hosts mok-status node-01
# 최근 보고에서 'MokNew 빈 목록 확인: true'와 처리된 컨트롤러 요청 ID를 읽습니다.
read -r -p '교체할 기존 MOK 요청 ID: ' REQ
# 같은 키 재시도는 기존 키 ID, 퇴역 키 교체는 새 키 ID를 지정합니다.
sudo kpctl signing rollout-cert -host node-01 -replace-request "$REQ" prod-2026
sudo kpctl hosts mok-status node-01
```

복구는 요청 ID가 일치하고 처리 결과가 저장되어 있으며 마지막 보고가 최신이고 MokNew가 비었다는 명시적 증거가 있는 경우에만 실행됩니다. `mok_pending: false`만 보고한 구 에이전트는 갱신 후 새 보고를 기다리세요. 대기와 빈 목록 모두 확인되지 않으면 CLI는 `미보고/확인 불가`를 표시합니다. 대상의 UEFI·mokutil과 에이전트 버전을 확인하세요. 키 제거만으로 미완료 요청을 취소하지 않습니다. 조회 중 도착한 다른 요청, 처리 중인 요청, 실제 대기는 기존 비밀번호와 함께 보존합니다. 복구 성공은 관리자·대상·키·이전 요청 ID와 함께 감사됩니다. 이 명령에는 펌웨어 요청 취소나 재부팅 단계가 없습니다.

**`awaiting_agent`가 지속될 때**에는 `mok-status`의 마지막 보고 시각과 호스트의 `systemctl status kpctl-agent`, `journalctl -u kpctl-agent -b`로 에이전트 실행·컨트롤러 연결을 확인하세요. MOK 요청을 처리하지 않는 구 에이전트는 같은 배포본으로 갱신해 기존 요청부터 처리하게 합니다. 퇴역 키의 인증서가 없어 `failed`를 보고한 경우에는 최신 빈 MokNew 보고 뒤 새 키 예약을 다시 시도하세요. 에이전트를 복구할 수 없으면 해당 호스트의 교체를 보류합니다. 호스트를 실제로 폐기·재구축해 재등록하는 경우 새 호스트 ID로 시작하므로 기존 MOK 대기의 최초 예약자와 콘솔 접근 가능 여부를 먼저 확인하고 호스트 링·정책을 다시 점검하세요. 컨트롤러 등록을 삭제해도 펌웨어 대기는 취소되지 않습니다.

관리자 API는 전체 예약에 `POST /api/signing/{key}/rollout-cert`, 한 대 예약에 `POST /api/signing/{key}/hosts/{host}/rollout-cert`를 사용합니다. 두 요청의 본문은 비우거나 빈 JSON 객체 `{}`를 보냅니다. 단일 호스트 경로에만 `?replace_request=<기존 요청 ID>`를 지정할 수 있습니다. 구 컨트롤러가 단일 호스트 경로를 지원하지 않으면 CLI가 오류를 반환합니다. 전체 예약으로 재시도하지 않습니다.

설치 묶음의 `install-agent.sh`에는 선택적인 `--enroll-mok`가 있습니다. 기본값은 꺼짐이며, 켜면 에이전트가 서명 필요·active 인증서 미등록 조건에서 예약을 요청합니다. 이미 설치한 에이전트는 `mok_auto_import` 설정으로 같은 동작을 선택할 수 있습니다. 일반 `kpctl install` 명령에 이 플래그가 있다고 가정하지 말고 직접 설치 스크립트 또는 설정 파일을 사용합니다.

컨트롤러는 무작위 호스트별 비밀번호 원문을 권한 0600의 `state.json`에 보관하고, OpenSSL의 SHA512-crypt 해시만 에이전트로 보냅니다. 비밀번호 조회는 감사 로그에 남으며 일반 상태 API에는 원문이 없습니다. 에이전트는 DER·X.509·SHA256을 확인한 뒤 `mokutil --import <DER> --hash-file <임시파일>`로 예약하고 해시 임시 파일을 지웁니다. 원문·해시는 에이전트 로컬 상태에 보존하지 않습니다.

`mokutil`이 없거나 `--hash-file`을 지원하지 않으면 실패·unsupported 안내를 확인합니다. UEFI/shim 호스트에서는 승인한 공개 DER로 `sudo mokutil --import /경로/인증서.der`를 수동 실행하고 다음 계획 재부팅의 콘솔 승인을 사용할 수 있습니다. 실제 `--test-key` 출력과 종료 코드를 함께 확인하며 pending·차단된 키를 enrolled로 오인하지 않습니다.

MOK import를 처리하는 주기에는 패치 적용·재부팅 경로로 진행하지 않습니다. 결과가 컨트롤러에 보고된 뒤의 후속 주기는 별도로 승인된 재부팅을 처리할 수 있습니다. kpctl의 재부팅 승인은 [정확한 새 GA 대상·드레인·5분 일회 승인](reboot-approval.md#reboot-approval) 조건을 그대로 적용합니다. MOK 등록을 위해 이 조건을 우회하지 않습니다.

<a id="verify-signed-module"></a>

## 첫 서명 패치 적용 확인

해당 Ubuntu 시리즈의 [빌더](../install/builder.md)가 준비되어 있고 대상 GA ABI의 검토 가능한 활성 패치가 있어야 합니다. 첫 시험에서는 자동 승인을 끄고 canary의 재부팅 후 등록 보고를 기다립니다. 별도 `test_vm` 검사를 사용하는 경우 동일 ABI로 부팅하는 시험 VM에도 같은 **공개 DER**를 미리 등록하세요. `sb_on` 시험은 그 VM에서 미서명 원본 거부와 실제 배포 사본의 로드·교체·롤백을 검사합니다.

```sh
# 컨트롤러에서 K에 canary의 uname -r 값을 넣습니다.
K=6.8.0-85-generic
sudo kpctl patches -kernel "$K"
sudo kpctl build -kernel "$K"
sudo kpctl jobs
# 생성된 작업이 승인대기이고 diff와 빌드 로그를 검토한 뒤 실행합니다.
read -r -p '승인할 작업 번호: ' JOB
sudo kpctl log "$JOB"
sudo kpctl approve "$JOB"
sudo kpctl hosts
```

canary의 적용/목표 버전이 같고 오류·전환 대기가 사라지면, 대상 콘솔에서 아래 값을 확인합니다. `MOD`에는 해당 승인 작업의 실제 모듈 이름을 넣습니다. 단일 키 설치에서는 컨트롤러에서 `sudo sha256sum "/var/lib/kpctl/artifacts/$K/signed-prod-2026/$MOD.ko"`로 배포 사본의 SHA256을 읽어 설치 사본과 대조합니다. VM 시험을 사용했다면 관리자 웹의 작업 상세에 기록된 키별 SHA256도 확인합니다.

```sh
sudo kpatch list
read -r -p '승인된 모듈 이름 (.ko 제외): ' MOD
KO="/var/lib/kpatch/$(uname -r)/$MOD.ko"
sudo sha256sum "$KO"
sudo modinfo -F signer "$KO"
cat "/sys/kernel/livepatch/$MOD/enabled"       # 1
cat "/sys/kernel/livepatch/$MOD/transition"    # 0
sudo journalctl -k -b --no-pager | tail -100
```

컨트롤러는 Linux trailer·서명 길이, 원본 SHA256, CMS 서명자 한 명 및 분리 서명을 검사합니다. OpenSSL CMS는 실제 배포하는 DER로 원본 바이트의 서명을 확인합니다. 검증 실패 때는 서비스 계정의 OpenSSL CMS 실행 여부, 래퍼 출력 형식, 설정 DER와 서명자 지문을 대조하세요. 부팅 후 Secure Boot 상태, 해당 키의 등록 보고, 승인 SHA와 실제 로드·활성 상태까지 일치해야 대상 검증이 끝납니다. 서명 도구가 없으면 컨트롤러의 대상 헤더·실행 권한을 확인합니다. `Key was rejected by service` 또는 `Required key not available`이면 대상의 DER 지문·shim 부팅·등록 보고와 커널 로그를 확인합니다. `invalid module format`이면 `uname -r`과 `modinfo -F vermagic "$KO"`를 비교합니다. 로드가 실패해 설치 파일이 없으면 같은 진단에 에이전트가 다운로드한 `/var/lib/kpctl-agent/modules/$MOD.ko`를 사용합니다.

<a id="key-rotation"></a>

## 키 교체

새 ID용 키는 예를 들어 컨트롤러에서 `sudo -u kpctl -- kpctl signing init-key prod-next`로 준비합니다. 기존 키 디렉터리와 DER pin, 배포 상태 및 산출물을 일관되게 백업하고 수명·지문을 기록합니다. VM이나 빌더에서 개인키를 회수하거나 이들에게 개인키 백업을 복사하지 않습니다.

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
