# 설정, JSON 저장과 API 권한

[기능 목차](README.md)

<a id="f17"></a>
## F17. 설정 로더와 상태 저장

컨트롤러·빌더·에이전트는 `ParseConfig`에서 JSON 해석, 기본값과 검증을 공유합니다. `LoadConfig`는 파일을 읽고 필요한 디렉터리를 준비하는 운영 진입점입니다. 알 수 없는 설정 키는 거부합니다. 빌더의 폐기된 `min_kernels` 키만 명시적인 이전 설정 호환 예외입니다.

컨트롤러의 운영 설정은 controller.json을 기본으로 하고 data_dir의 `settings.json`을 덮어씁니다. 웹에서 변경 가능한 항목은 자동 배포·관찰·보고 신선도·작업 제한으로 제한됩니다. 서명 키 파일이나 비밀 명령을 Settings API의 편집 대상으로 노출하지 않습니다. CLI의 환경 변수는 설정 env 파일보다 우선합니다.

`state.json`에는 작업·입력·커널별 목표·호스트·빌더·일회성 승인·MOK 예약과 인증서 pin이 들어갑니다. 모듈·diff·로그는 별도 파일입니다. 하나의 Store mutex로 접근을 직렬화하며 동일 data_dir의 다중 컨트롤러를 지원하는 DB는 아닙니다.

일반 `Update`는 callback 뒤 임시 파일 기록, 파일 fsync, rename과 directory fsync를 수행합니다. callback이나 저장 오류의 모든 메모리 변경을 자동 rollback하는 일반 트랜잭션은 아닙니다. 승인 경로는 `UpdateAtomic`을 사용합니다. JSON 깊은 복제본에 승인·키 사본 metadata를 적용하고 저장 성공 뒤에만 live 상태를 바꿉니다. rename 뒤 directory fsync 실패에는 이전 inode로 복구를 시도합니다. 복구 자체가 실패하거나 복구 fsync도 실패하면 백업·디스크 상태 또는 지속성 미확인을 명시하며 전원 장애·영구 I/O 오류의 복구 완료를 보장하지 않습니다.

백업은 state.json뿐 아니라 설정, 원본 diff, 서명 전 원본, 키별 산출물과 운영 키를 일관된 시점으로 보관해야 합니다. state.json에는 컨트롤러에서만 보관하는 MOK 비밀번호 원문도 있으므로 파일 권한 0600과 관리 디렉터리 권한을 유지합니다.

구현: [controller/config.go](../../internal/controller/config.go), [builder/config.go](../../internal/builder/config.go), [agent/config.go](../../internal/agent/config.go), [settings.go](../../internal/controller/settings.go), [state.go](../../internal/controller/state.go)의 `Update`, `UpdateAtomic`, `persistAtomicState`; [CLI 환경 로더](../../cmd/kpctl/main.go)의 `loadEnvFile`. 검증: [settings_test.go](../../internal/controller/settings_test.go), [state_atomic_test.go](../../internal/controller/state_atomic_test.go).

<a id="f18"></a>
## F18. API 역할과 감사

| 주체 | 인증과 허용 범위 |
|---|---|
| 관리자 | 이름별 Bearer 토큰으로 상태·설정·승인·호스트·재부팅·서명 관리 |
| 빌더 | builder Bearer 토큰으로 작업 배정, 커밋 수집·결과·하트비트·실행 파일 업데이트 |
| 신규 호스트 | 본문의 그룹 등록 토큰으로 최초 등록·설치 묶음 취득 |
| 등록 호스트 | 전용 Bearer 토큰으로 자기 보고와 재부팅 claim |
| 산출물 조회 | 관리자 또는 유효 호스트 토큰. 키별 query는 승인 metadata와 실제 파일 SHA를 확인 |
| 공개 | healthz와 로그인·정적 웹. 관리 데이터는 관리자 인증 필요 |

호스트 토큰은 컨트롤러 상태에 해시로 저장합니다. TLS 클라이언트는 설정한 CA로 서버를 검증합니다. 운영 토큰의 자동 만료·개별 빌더별 권한 분리·다중 인증을 이 API가 제공하는 것은 아닙니다. 호스트 토큰의 산출물 조회는 해당 호스트의 목표 파일만 허용하는 파일별 권한 모델도 아닙니다.

주요 경로는 `/api/agent/report`, `/api/builder/next`, `/api/jobs/{id}/approve`, `/api/kernels/{kernel}/promote`, `/api/signing`, `/api/settings`입니다. 각 메서드·역할·본문은 [routes](../../internal/controller/server.go)와 [model](../../internal/model/model.go)을 기준으로 확인합니다. MOK 비밀번호는 별도 관리자 조회이며 no-store 응답과 감사 기록을 남깁니다.

`audit.log`는 조작자와 승인·승급·롤백·키 예약·비밀번호 조회 등을 기록합니다. 만료 30일 경계와 제거된 키 경고는 시작 시와 자동 확인 루프에서 새 경고를 감사하고 동일 경고의 반복 기록을 줄입니다. 호스트 오류, 빌드·VM 로그와 수집 검토 문제는 각각의 상태·로그에도 남습니다. 보존·회전·외부 감사 전송은 별도 운영 책임입니다.

구현: [server.go](../../internal/controller/server.go)의 `routes`, `admin`, `builder`, `agent`, `audit`; [client.go](../../internal/client/client.go); [signing_admin.go](../../internal/controller/signing_admin.go)의 `handleMOKPassword`, `auditSigningWarnings`; [handlers_agent.go](../../internal/controller/handlers_agent.go)의 `handleArtifact`. 검증: [auto_test.go](../../internal/controller/auto_test.go), [signing_admin_test.go](../../internal/controller/signing_admin_test.go), [signing_rotation_test.go](../../internal/controller/signing_rotation_test.go).
