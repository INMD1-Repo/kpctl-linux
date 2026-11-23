# 시험과 증거 범위

[개발 안내](README.md) · [기능 F20](../features/updates-and-validation.md#f20)

개발 검증은 저장소 루트에서 실행합니다. [Makefile](../../Makefile)의 `make test`는 Go 형식·정적 검사, Go 회귀시험, Python 시험, 가짜 도구 e2e, 문서 검사, 내부 패키지 race, QEMU 셸 검사와 웹 시험·번들 일치를 묶습니다. 관련 파일을 고친 뒤 다음 명령도 사용합니다.

```bash
make test
make docs-check
go test -race ./internal/...
make lint-scripts
make test-web
```

Go 백엔드와 문서 도구는 표준 라이브러리를 사용합니다. Go race 검사는 CGO와 C 컴파일러가 필요하고, 웹 검사는 Node.js/npm 및 lockfile의 개발 의존성을 사용합니다. `lint-scripts`의 현재 대상은 QEMU adapter 셸입니다. 테스트의 임시 HTTP 서버는 로컬 포트를 열어야 합니다. Go 시험 옵션이 필요하면 `GO_TEST_FLAGS`를 넘길 수 있습니다.

| 계층 | 실행과 근거 | 입증 범위 |
|---|---|---|
| Go | [내부 패키지](../../internal/)와 [CLI](../../cmd/kpctl/) | 상태·서명 정책·배정·승인·실패 복구·정확한 해시와 전환 규칙 |
| VM 셸 계약 | [security_test.go](../../internal/testvm/security_test.go) | 실제 guest 스크립트를 임시 sysfs·가짜 kpatch로 실행한 거부·교체·롤백·smoke·정리 순서 |
| Python | [test](../../test/)의 `_test.py` | 패키지 입력·커널 준비·설치 훅·자료 수집·VM adapter 계약 |
| e2e | [e2e.sh](../../test/e2e.sh) | 가짜 빌드·서명·kpatch로 등록부터 누적 배포·롤백·보류까지 |
| 웹 | [React 시험](../../web/src/test/) | jsdom UI와 가상 API, 이전 응답 호환, 비밀 경로 미표시 |
| 운영 번들 | [check-build.mjs](../../web/scripts/check-build.mjs) | React 소스 재빌드 결과와 Go 내장 파일의 바이트 일치, 개발 데이터 제외 |
| 문서 | [docscheck](../../internal/docscheck/) | 실제 parser의 예제, 실제 CLI dispatch, 상대 파일·앵커와 선언 위치 |

이 시험들의 성공은 특정 실제 Ubuntu 커널에서 모듈이 로드되거나 CVE 공격이 차단됐다는 증거가 아닙니다. 실제 커널·VM·펌웨어 검증은 별도 격리 환경에서 수행하고 커널·모듈 SHA256·모드·단계·부팅 ID·결과를 함께 기록합니다.

## 선택 검증

```bash
make test-web-browser
make test-web-demo
KPCTL_TEST_CVE_FEED_REPO=/absolute/path/to/vulns go test ./internal/builder -run '^TestSystemCVEFeedCloneParser$' -count=1 -v
```

실제 CNA clone 검사는 공개 수정 ID 파서와 Git snapshot을 확인합니다. 커널 모듈 실행 검사가 아닙니다. 기본 Go 시험에서는 해당 외부 clone 의존 검사를 건너뜁니다. 실제 Chromium 검사는 Playwright 브라우저 설치가 필요하며, [브라우저 시험](../../web/tests/)은 가짜 API 또는 가상 개발 데이터를 사용합니다.

[전용 수용 검증기](../../test/acceptance.py)는 manifest로 고정한 호스트·작업·해시를 관찰합니다. 일반 `make test`가 실제 호스트에 연결하거나 실제 승인·재부팅을 실행하는 절차로 쓰이지 않도록 격리합니다.

## 문서 검사 계약

HTML 주석 `config-example: controller`, `builder`, `agent`, `testvm`이 붙은 JSON 블록은 전체 설정 또는 testvm wrapper여야 합니다. 검사기는 실제 `ParseConfig`/VM 검증을 사용하고 운영 디렉터리를 만들지 않습니다. `configs/*.example.json`도 같은 기준으로 검사합니다.

CLI 참조는 [commands 등록](../../cmd/kpctl/main.go)과 각 dispatch 함수의 AST에서 읽습니다. [검사 회귀](../../internal/docscheck/check_test.go)는 일부러 틀린 예제·하위 명령·앵커·선언 위치를 넣어 실패하는 것을 확인합니다.
