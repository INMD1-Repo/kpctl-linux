# 관리자 웹 개발

[개발 안내](README.md) · [운영 화면](../operations/web.md)

[web/package.json](../../web/package.json)의 Node.js 범위와 lockfile을 사용합니다. React/Vite 소스는 `web/src/`, 개발용 데이터와 API는 `web/dev/`에 있습니다. 운영 제공 파일은 `internal/controller/web/`이며 [web.go](../../internal/controller/web.go)가 Go에 내장합니다.

```bash
make dev-web
make web
make test-web
```

개발 서버는 기본 `/ui/` 경로의 가상 환경을 제공합니다. 실제 운영 API로 개발할 때는 [Vite 설정](../../web/vite.config.js)과 인증·CA 구성을 확인합니다. 가상 서버가 운영 서버로 자동 전환되는 구조로 사용하지 않습니다.

| 파일 | 책임 |
|---|---|
| [store.jsx](../../web/src/store.jsx) | 인증·상태 갱신·resource와 mutation 수명 |
| [selectors.js](../../web/src/selectors.js) | 정식/출시 전 목표, 이전 보안 보고의 보수적 표시 |
| [Hosts](../../web/src/pages/Hosts.jsx) | 보안 신호·MOK·키 등록·배포 제외와 호스트 조작 |
| [Jobs](../../web/src/pages/Jobs.jsx), [Patches](../../web/src/pages/Patches.jsx) | 출시 전 표시·검토·VM 단계 증거 |
| [Settings](../../web/src/pages/Settings.jsx) | 설정 폼과 공개 키 목록·만료 경고 |
| [ui.jsx](../../web/src/ui.jsx), [dialogs.jsx](../../web/src/dialogs.jsx) | 공통 표·dialog·VMTestEvidence·명시 승인과 승급 결과 |
| [가상 API](../../web/dev/store.js), [데이터](../../web/dev/data.js) | 호스트·서명·VM 결과·출시 전 제약을 재현하는 개발 fixture |

서명 필요·키 자격의 실제 결정은 Go 컨트롤러가 합니다. 웹의 fallback은 이전 보고를 안전하게 표시하는 역할입니다. Settings는 공개 필드만 렌더링하며 개인키·인증서 파일 경로와 서명 명령을 다루지 않습니다. VM 단계의 `detail`과 오류는 텍스트로 표시합니다.

출시 전 승인은 별도 동의와 API 플래그를 요구합니다. 출시 전 목표가 있는 호스트를 정식 즉시 업데이트의 후보로 섞지 않습니다. 승급 결과의 제외 대수·사유는 성공 안내에 남깁니다.

운영 번들을 바꾸면 `make web` 이후 `make test-web`로 실제 출력 바이트가 저장된 내장 파일과 같은지 확인합니다. 운영 산출물에 데모 토큰·`/api/dev/`·가상 CVE 표식이 들어가면 [검사 스크립트](../../web/scripts/check-build.mjs)가 실패합니다. 테스트·가상 데이터만 바꾼 경우도 웹 시험으로 정책 흐름을 확인합니다.
