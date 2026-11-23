# 실행 파일 업데이트와 검증 범위

[기능 목차](README.md)

<a id="f19"></a>
## F19. 빌더 실행 파일 업데이트

`self_update`의 기본값은 true입니다. 실제 업데이트는 systemd가 마련한 `KPCTL_BUILDER_UPDATE_PATH`와 현재 실행 파일의 SHA256을 확인할 수 있을 때만 사용합니다. 이전 서비스처럼 설치 경로가 없으면 다운로드·재시작 반복을 시작하지 않습니다.

메인 루프는 시작 시와 약 10분마다 작업 사이에서 컨트롤러의 빌더 해시를 확인합니다. 다르면 임시 파일로 받고 SHA256을 검증하며, 빌더 사용자 권한으로 받은 프로그램의 `-h` 실행을 제한 시간 안에 확인합니다. 성공한 파일을 업데이트 경로로 옮긴 뒤 종료 코드 75로 재시작을 요청합니다.

제공한 systemd 서비스의 root 사전 단계는 정해진 파일의 소유자·형식·링크 조건을 확인하고 설치 경로로 복사합니다. 받은 프로그램의 사전 실행을 root로 수행하지 않습니다. 서비스 본체는 빌더 사용자로 다시 실행합니다. 확인·다운로드·해시·실행 시험 실패 시 기존 프로그램으로 계속합니다.

이 경로는 빌더 바이너리용입니다. 컨트롤러·에이전트·운영 커널의 자동 업데이트를 의미하지 않으며 `-h` 성공만으로 업무 정확성을 검증하지도 않습니다. 운영 업그레이드 때는 컨트롤러가 제공하는 배포 파일과 빌더 설치 파일의 순서를 함께 관리해야 합니다.

구현: [selfupdate.go](../../internal/builder/selfupdate.go)의 `updatePath`, `CheckUpdate`, `fetchUpdate`; [worker.go](../../internal/builder/worker.go)의 `Run`; [builder_update.go](../../internal/controller/builder_update.go); [서비스](../../deploy/systemd/kpctl-builder.service). 검증: [selfupdate_test.go](../../internal/builder/selfupdate_test.go).

<a id="f20"></a>
## F20. 개발 시험과 전용 호스트 검증

| 시험 | 확인 범위 | 남는 한계 |
|---|---|---|
| Go 단위·회귀 | 입력·태그·해시·상태·권한·실패·승급·저장 규칙 | 실제 커널과 하드웨어 실행을 대신하지 않음 |
| Python·셸·e2e | 설치·준비·QEMU 계약과 가짜 도구의 전체 흐름 | 실제 ELF 생성·취약점 차단을 보장하지 않음 |
| guest 셸 + 가짜 sysfs/kpatch | 실제 시험 스크립트의 교체·rollback·오류·정리 순서 | 실제 livepatch 전환·Secure Boot 검증은 아님 |
| React·개발 데이터 시험 | 경고·명시 동의·민감 정보 비노출·가상 API 상태 | 실제 호스트 배포·콘솔 MOK 승인 검증은 아님 |
| 브라우저 시험 | 내장 번들·CSP·화면 조작 | 가짜 API를 쓰는 경우 운영 결과가 아님 |
| 지정 커널·호스트 실측 | 고정한 바이트·구성·부하·회귀 | 시험하지 않은 커널·CVE·기종 전체로 일반화하지 않음 |

기본 확인은 `make test`이며 문서 계약은 `make docs-check`, 웹 단독 확인은 `make test-web`입니다. 브라우저·개발 서버 시험은 `make test-web-browser`, `make test-web-demo`로 실행합니다. race와 셸 정적 검사도 [시험 안내](../development/testing.md)의 명령으로 확인합니다. 명령이 있다는 것과 실제 장비에서 실행했다는 사실을 구분합니다.

`test/acceptance.py`는 일반 승인마다 자동 실행하는 코드가 아니라 고정 manifest의 대상·버전·해시를 검증하는 별도 시험기입니다. acceptance 모드는 최소 24시간과 운영 관찰 시간 중 긴 값을 적용하고, 신선한 보고·부팅 불변·서비스·VM 수·로그·부하를 관찰한 뒤 정해진 승급·회귀·롤백·복구를 수행합니다. 중단 뒤 실행 단계를 무조건 재생하지 않습니다.

observe 모드는 이미 지정한 배포를 관찰하며 관리 API의 GET만 허용합니다. 승인·승급·롤백·재부팅은 수행하지 않고 긴 보고 공백이 있는 과거 실행을 자동 재사용하지 않습니다. 공개 `validation-state.json`은 허용한 진행 정보만 제공하며 개인 manifest와 원본 증거를 그대로 웹에 보내지 않습니다.

실제 커널 시험은 대상 커널과 산출물 해시, 시험 범위, 완료 결과를 기록합니다.

구현: [Makefile](../../Makefile), [acceptance.py](../../test/acceptance.py), [coverage.go](../../internal/controller/coverage.go)의 `validationStatus`; [service](../../deploy/systemd/kpctl-acceptance@.service). 검증: [acceptance_test.py](../../test/acceptance_test.py), [VM 셸 시험](../../internal/testvm/security_test.go), [React 시험](../../web/src/test/app.test.jsx).
