# 서명 키, MOK와 호스트별 배포 자격

[기능 목차](README.md) · [운영 절차](../operations/secure-boot.md)

<a id="f21"></a>
## F21. 여러 서명 키와 혼합 보안 상태

공통 `model.SignaturePolicy`는 Secure Boot on, lockdown integrity/confidentiality, sig_enforce on 중 하나라도 있으면 서명이 필요하다고 판단합니다. 세 신호 중 누락·unknown·예상하지 못한 값도 서명 필요와 경고로 처리합니다. BIOS라도 lockdown 또는 서명 강제가 켜질 수 있습니다.

컨트롤러는 키 ID, 공개 DER와 그 SHA256을 에이전트에 전달합니다. 에이전트는 DER 무결성과 X.509 형식을 확인하고 `mokutil --test-key`의 확인된 출력과 종료 결과로 enrolled/not_enrolled/in_db/unknown을 보고합니다. UEFI db 일치만 관찰한 in_db는 MOK 등록 수에서 제외하고 미확인 경고를 표시합니다. 등록 대기는 `--list-new`와 키별 pending 결과로 확인합니다. mokutil 없음·비 EFI·수집 실패를 등록됨으로 추정하지 않으며, 이 수집 실패 자체로 에이전트 사이클을 중단하지 않습니다.

### 설정과 이전 구성

`kpctl signing init-key prod-2026`는 컨트롤러의 서비스 계정으로 실행하는 로컬 명령입니다. RSA 개인키와 Ubuntu shim 모듈 전용 EKU가 있는 DER 인증서를 한 디렉터리에 생성합니다. 호스트와 시험 VM에는 공개 DER만 제공합니다. [권한·설치·설정 명령](../install/controller.md#module-signing-key)

`signing`을 사용하면 키 ID가 유일해야 하고 active 키는 정확히 하나여야 합니다. mode 기본값은 always입니다. always는 서명 명령으로 사본을 만들고, when_required는 호스트나 선택한 VM 모드가 요구할 때 서명합니다. never는 서명 필요 호스트를 제외합니다. 모든 키의 명령 인자는 셸 없이 실행하며 `{module}`과 `{kernel}`을 치환합니다.

<!-- config-example: controller -->
```json
{
  "admin_tokens": {"operator": "example-admin-token-0123456789"},
  "builder_token": "example-builder-token-0123456789",
  "rings": [1, 2],
  "signing": {
    "mode": "always",
    "keys": [{
      "id": "prod-2026",
      "active": true,
      "cert": "/etc/kpctl/signing/prod-2026/module.der",
      "sign_command": [
        "/usr/src/linux-headers-{kernel}/scripts/sign-file",
        "sha256",
        "/etc/kpctl/signing/prod-2026/module.priv",
        "/etc/kpctl/signing/prod-2026/module.der",
        "{module}"
      ]
    }]
  }
}
```

운영에서는 실제 키·인증서를 준비하고 호스트와 시험 VM에 필요한 신뢰를 구성해야 합니다. 이 설정 예제의 검증 통과가 해당 파일 존재·서명 성공·MOK 등록을 검증하는 것은 아닙니다.

기존 `sign_command`만 있으면 always 모드의 default active 키 하나로 해석하고 정적인 `.der` 인자에서 인증서를 추정합니다. 추정 인증서를 읽지 못했다고 기존 구성의 시작 조건을 새로 강화하지는 않습니다. `signing`과 `sign_command`를 함께 주면 오류입니다. 서명 명령 자체가 없던 이전 구성은 하위 호환 경로를 유지하므로 always라는 이름만으로 운영 키가 자동 준비되지는 않습니다.

### 사본 선택과 기존 보호 유지

서명 승인에는 컨트롤러에서 실행 가능한 `openssl cms`와 해당 키의 공개 DER가 필요합니다. 컨트롤러는 Linux 모듈 trailer·PKCS#7 길이와 서명 앞 원본의 SHA256을 검사한 뒤, 설정한 DER만 서명자 후보로 사용해 단일 서명자의 분리 CMS 서명을 검증합니다. Linux의 모듈 서명 형식에 맞춰 signed attributes가 있는 CMS도 거부합니다. 외부 래퍼가 정적 DER 인자를 노출하지 않으면 `signing.keys[].cert`에 명시합니다. 대상 부팅 키링과 커널 로드는 실기에서 별도로 확인합니다. [Linux 모듈 PKCS#7 검사](https://github.com/torvalds/linux/blob/v6.8/crypto/asymmetric_keys/pkcs7_verify.c) · [OpenSSL CMS 검증 옵션](https://docs.openssl.org/3.0/man1/openssl-cms/)

승인은 서명 전 원본을 `unsigned_sha256`으로 고정하고 매번 그 원본에서 사본을 만듭니다. active 사본과, 서명 필요 호스트가 등록했다고 보고한 다른 키의 사본을 준비합니다. 호스트에는 선택한 사본의 SHA256과 URL을 전달합니다.

| 판단 | 결과 |
|---|---|
| 서명 불필요 | 승인 작업의 기본 사본 |
| 서명 필요 보고·컨트롤러 서명 명령 없음 | blocked_signing_disabled, 서명 키·명령 설정 필요 |
| 서명 필요·등록된 키와 검증된 사본 존재 | 등록된 키 선택, 새 적용에서는 active 우선 |
| 모든 현재 키가 not_enrolled | blocked_mok_missing, MOK 등록 필요 |
| 위 경우에 mok_pending | 다음 계획된 재부팅의 콘솔 승인 필요 |
| 새 에이전트의 등록 상태 unknown | active 서명 사본과 경고 |
| 보안·서명 필드가 전혀 없는 이전 에이전트 | 처음부터 승인 작업 기본 사본을 일관되게 제공하고 경고. 서명 설정을 생략한 익명 미서명 사본도 이 호환 경로에서만 허용 |
| 필요한 서명 사본 없음·이전 unsigned 사본만 존재 | blocked_artifact, 새 누적 빌드·승인 필요 |
| mode=never·서명 필요 | blocked_signing_disabled와 경고 |

같은 버전의 호스트는 `module_sha256`이 일치하는 기존 서명 사본을 유지할 수 있습니다. 이전 에이전트는 처음 적용할 때부터 승인 작업의 기본 사본을 일관되게 제공받습니다. active 변경은 다음 누적 버전에서 반영하며 같은 모듈 이름의 설치 바이트를 덮어쓰지 않습니다. 맞는 사본을 유지할 수 없으면 제외 응답으로 멈춥니다. 제외는 기존 보호를 v0로 제거하는 요청이 아닙니다.

제외 호스트는 건강한 다른 호스트의 링 승급을 막지 않습니다. CLI·Hosts·promote 응답에 이유를 표시하고 다음 보고에서 다시 판정합니다. 등록을 마친 호스트는 자격을 회복하면 현재 목표를 받을 수 있습니다.

### 키 교체와 이전 누적본

키 ID는 DER 내용의 지속적인 식별자입니다. 컨트롤러는 삭제한 ID의 pin도 보존하므로 같은 ID를 다른 인증서에 재사용하지 않습니다. 새 키를 추가하고 `kpctl signing rollout-cert -host node-01 prod-next`로 canary부터 예약한 뒤, 호스트와 시험 VM에서 새 키 신뢰를 준비합니다. 기존 키를 유지한 상태에서 새 누적본을 빌드·승인하고 이후 active를 바꾸는 순서로 진행합니다.

VM 검사를 사용하는 환경에서 이전 누적본에 새 키 사본이 없으면, 컨트롤러는 pin된 이전 unsigned 원본으로 비공개 서명 사본을 준비합니다. 그 사본과 새 누적본으로 모든 키·모드의 교체·롤백 시험을 통과하고 해시를 다시 확인한 경우에만 최종 원자 승인에서 이전 작업의 검증된 variant를 추가합니다. 이전 작업의 기본 SHA256·active ID·기본 URL 바이트는 유지합니다. 기존 unsigned variant의 시험용 재서명은 비공개로 사용하고 기존 운영 바이트·metadata를 덮어쓰지 않습니다.

이전 released 작업에 unsigned pin이 없거나 원본이 없어 확인할 수 없으면 자동 추정하지 않습니다. 키 추가에 앞서 기존 설정으로 새 누적본을 한 번 빌드·승인해 원본 pin을 준비해야 합니다. active를 바꾼 뒤에도 새 누적본 적용을 확인하기 전에 옛 키를 제거하지 않습니다. 옛 키만 등록된 호스트가 남으면 제거 경고가 발생합니다.

### 예약, 비밀번호와 만료

MOK 예약은 호스트별 임의 비밀번호를 컨트롤러 상태에만 저장합니다. 에이전트에는 해시를 전달하고 임시 파일을 통해 `mokutil --import ... --hash-file ...`을 실행한 뒤 등록 대기를 다시 확인합니다. 지원하지 않는 환경은 unsupported와 수동 절차를 보고합니다. 이 경로는 재부팅 함수를 호출하지 않습니다.

`kpctl hosts mok-status node-01`에서 마지막 보고 시각, 키별 등록 결과와 마지막 예약 결과를 확인합니다. `mok-status`는 컨트롤러 요청 ID와 상태, 마지막 에이전트 결과, 비밀번호 없이 확인한 빈 MokNew 여부를 보여줍니다. 퇴역 키 요청은 최근 빈 목록 보고와 처리 완료 증거가 있는 경우에만 단일 호스트의 요청 ID를 지정해 복구합니다. [요청 교체 조건](../operations/secure-boot.md#mok-enrollment)

`pending_existing`은 이전 예약자가 설정한 비밀번호가 필요합니다. 이때 `mok-password`는 새 요청의 비밀번호를 표시하지 않습니다. 구 에이전트의 출처 미확인 `pending`에는 조회된 값이 기존 비밀번호와 다를 수 있다는 경고가 붙습니다. `mok_pending`은 호스트 전체의 대기 신호입니다. 키별 `enrolled` 판정에는 해당 DER에 대한 명시적인 조회 결과가 필요합니다.

`kpctl hosts mok-password`는 관리자 조회이며 감사됩니다. 만료 30일 이내 경고는 `kpctl signing list`와 Settings에 표시합니다. 시작 시와 기본 60초 자동 확인 루프에서 새 만료·제거 경고를 감사하며 자동 배포를 꺼도 이 확인은 실행합니다.

구현: [model/signing.go](../../internal/model/signing.go)의 `SignaturePolicy`; [controller/signing.go](../../internal/controller/signing.go)의 `signingConfig`, `pinnedUnsignedArtifact`, `prepareSigningArtifactsWithRotations`, `publishSigningRotationsLocked`; [rollout.go](../../internal/controller/rollout.go)의 `rolloutEligibility`; [signing_admin.go](../../internal/controller/signing_admin.go)의 `scheduleMOK`, `auditSigningWarnings`; [agent/signing.go](../../internal/agent/signing.go)의 `mokTestResult`, `enrollmentStatus`, `importMOK`.

검증: [signing_test.go](../../internal/controller/signing_test.go), [signing_identity_test.go](../../internal/controller/signing_identity_test.go), [signing_rotation_test.go](../../internal/controller/signing_rotation_test.go), [signing_rotation_retention_test.go](../../internal/controller/signing_rotation_retention_test.go), [에이전트 MOK 시험](../../internal/agent/signing_test.go). 실제 펌웨어·콘솔 등록 시험과 구분합니다.
