# CVE 대조와 관리 화면

[기능 목차](README.md)

<a id="f13"></a>
## F13. 독립 OSV 목록과 적용 범위

`kpctl-cve-inventory.py`는 Canonical의 전체 OSV 아카이브를 받아 Ubuntu 24.04·26.04 GA용 목록으로 축약합니다. 입력의 형식·건수·릴리스 자료를 검증하고 기존 목록의 비정상 축소를 차단합니다. 이 목록은 빌더가 수집한 커밋 목록에서 역으로 만드는 자료가 아닙니다.

컨트롤러는 Ubuntu 패키지 버전을 Debian 버전 비교로 대조해 affected, base_fixed, outside_range 또는 unknown을 구분합니다. 공식 수정 버전이 확인되지 않거나 범위 자료가 불완전하면 임의로 영향 없음으로 바꾸지 않습니다. 수집·활성 입력·승인 작업과, 호스트의 실제 버전·활성 모듈 상태를 함께 대조해 미수집, 처리 대기, 포함, 일부 포함, 관리자 제외 등을 표시합니다.

`included`는 해당 자료와 선택된 누적본에서 확인한 포함 상태입니다. 목록 전체의 공격 차단·실행 안전성이나 라이브패치 불가 커밋이 모두 해결됐다는 증명이 아닙니다. 빌더의 [CNA 수정 ID 매핑](prerelease-and-cna.md#f24)은 후보 발견 경로이며 이 독립 OSV 대조를 대체하지 않습니다.

입력 파일은 컨트롤러 data_dir의 `coverage/vendor.json`입니다. 갱신 서비스·타이머, 원본 자료 시각, 목록 상태와 unknown 행을 함께 확인해야 합니다.

구현: [kpctl-cve-inventory.py](../../deploy/kpctl-cve-inventory.py)의 `compact`; [coverage.go](../../internal/controller/coverage.go)의 `coverageBase`, `assessBase`, `handleCoverage`; [lts.go](../../internal/model/lts.go)의 `SignatureVersion`. 검증: [inventory_test.py](../../test/inventory_test.py), [coverage_test.go](../../internal/controller/coverage_test.go).

<a id="f14"></a>
## F14. 웹·CLI에서 볼 수 있는 결과

React 웹은 Go 컨트롤러에 포함한 번들로 제공됩니다. API 인증 후 현황, 빌드 작업·빌더, 호스트, 패치, CVE 대조, 설정과 감사 기록을 봅니다. 빌드 작업 검토에서는 diff·로그·승인 상태, 키·모드별 VM 단계와 출시 전 표시를 확인할 수 있습니다. Hosts는 실행 커널·보안 신호·서명 자격·등록 상태·경고와 제외 사유를 보여줍니다. Settings의 서명 현황에는 ID·active·만료·등록 호스트 수·경고만 포함하며 키 파일 경로나 개인키·서명 명령을 내려주지 않습니다.

서버의 승인·승급·재부팅 조건은 화면 버튼의 표시 여부와 별개로 API에서 다시 검사합니다. 출시 전 승인은 관리자 동의가 필요하며 즉시 업데이트에서는 제외합니다. 화면에서 검토해도 실제 커널 안전성 검증이 완료됐다는 뜻은 아닙니다.

CLI는 `kpctl status`, `kpctl hosts`, `kpctl jobs`, `kpctl patches`, `kpctl log`, `kpctl signing list`로 같은 운영 상태를 확인합니다. `kpctl hosts mok-password`는 감사되는 별도 민감 정보 조회입니다. 모든 관리 작업에는 관리자 토큰이 필요합니다.

UI 개발 서버의 가상 호스트·CVE·VM 결과는 실제 운영 결과로 사용하지 않습니다. `web/dev`는 독립된 가상 상태를 제공하며 문구에도 이를 표시합니다. 소스 변경 후에는 번들을 다시 만들고 소스·내장 번들 일치를 확인합니다.

구현: [App.jsx](../../web/src/App.jsx), [Hosts.jsx](../../web/src/pages/Hosts.jsx), [Jobs.jsx](../../web/src/pages/Jobs.jsx), [dialogs.jsx](../../web/src/dialogs.jsx), [Settings.jsx](../../web/src/pages/Settings.jsx), [status.go](../../cmd/kpctl/status.go), [signing.go](../../cmd/kpctl/signing.go). 검증: [app.test.jsx](../../web/src/test/app.test.jsx), [demo.test.js](../../web/src/test/demo.test.js). 개발 방법은 [웹 개발](../development/web.md)에 있습니다.
