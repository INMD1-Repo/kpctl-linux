# 파일과 상태 위치

[목차](../README.md)

아래 경로는 기본 설정과 설치 스크립트 기준입니다. 프로그램 설정에서 바꿀 수 있는 경로는 실제 설치값을 확인하세요.

| 구성 요소 | 경로 | 용도 |
|---|---|---|
| 컨트롤러 | `/etc/kpctl/controller.json` | 토큰·링·서명·VM 등 프로그램 설정 |
| 컨트롤러 | `/etc/kpctl/kpctl.env` | 관리자 CLI의 주소·토큰·CA와 SSH 기본값 |
| 컨트롤러 | `/etc/kpctl/tls/` | 사설 CA와 서버 인증서·키 |
| 컨트롤러 | `/etc/kpctl/tokens/` | 설치 스크립트가 만든 관리자·빌더·그룹 등록 토큰 |
| 컨트롤러 | `/var/lib/kpctl/state.json` | 작업·패치·호스트·번호·링 목표·인증서 pin·MOK 예약 |
| 컨트롤러 | `/var/lib/kpctl/settings.json` | 웹에서 바꾼 운영 값 |
| 컨트롤러 | `/var/lib/kpctl/patches/` | 등록한 패치 본문 |
| 컨트롤러 | `/var/lib/kpctl/artifacts/` | 커널별 모듈, 보존 원본과 키별 서명 사본 |
| 컨트롤러 | `/var/lib/kpctl/logs/`, `/var/lib/kpctl/testlogs/` | 누적 빌드·승인 전 VM 로그 |
| 컨트롤러 | `/var/lib/kpctl/audit.log` | 관리자 조작·자동 처리·MOK 비밀번호 조회 기록 |
| 빌더 | `/etc/kpctl/builder.json` | 접속·담당 커널·sandbox·선택 수집 설정 |
| 빌더 | `/var/lib/kpctl-builder/` | 작업 공간과 시험 실패·출시 전·CNA 캐시 |
| 빌더 | `/srv/ubuntu-<series>` | 자동 모드 Ubuntu 커널 Git |
| 빌더 | `/usr/lib/debug/boot/` | 대상 vmlinux 입력 |
| 에이전트 | `/etc/kpctl/agent.json`, `/etc/kpctl/ca.crt` | 로컬 설치 시 접속 설정과 CA |
| 에이전트 | `/var/lib/kpctl-agent/state.json` | 호스트 토큰·적용·설치·승인·공개 인증서 결과 |
| 에이전트 | `/var/lib/kpctl-agent/modules/` | 다운로드한 모듈 |
| 에이전트 | `/var/lib/kpatch/` | 커널별 부팅용 모듈 설치본 |
| 에이전트 | `/etc/kpctl/reboot-hook.sh` | 승인 검사 뒤 실행할 재부팅 훅 |
| 에이전트 | `/etc/kpctl/mirrors.list` | 공식 저장소가 안 될 때 쓸 Ubuntu 미러 순서. 설치 묶음의 [mirrors.list](../../deploy/mirrors.list)를 설치하며 재설치하면 덮어씁니다 |

서명 개인키와 DER의 위치는 `signing.keys` 또는 기존 `sign_command`가 정합니다. 키 파일을 state 디렉터리에 자동 생성하는 기능은 없습니다. Settings와 공개 키 목록은 그 경로·개인키를 응답하지 않습니다.

## 보관과 복구

컨트롤러 상태에는 호스트별 MOK 원문 비밀번호가 들어갑니다. 일반 상태 API에 이 예약 저장소를 그대로 공개하지 않으며 전용 관리자 조회에는 감사 기록과 `no-store`를 적용합니다. 토큰·개인키·상태 백업은 같은 민감도로 취급합니다.

모듈 원본과 `UnsignedSHA256`, 인증서 ID별 DER pin은 키 교체 검증에 필요합니다. 상태 파일만 복구하고 원본을 잃으면 과거 배포본의 새 키 사본을 안전하게 만들 수 없어 승인을 거부할 수 있습니다. 서명 전 원본이나 pin을 임의로 재생성해 이 검사를 우회하지 마세요.

에이전트 로컬 상태는 0600으로 저장하며 공개 DER와 등록 결과를 보관하지만 MOK 원문 비밀번호·해시는 저장하지 않습니다. 삭제하면 다음 실행에서 다시 등록해야 합니다. 제거 스크립트는 로컬 상태를 삭제해도 적용 중인 모듈은 기본으로 유지합니다.

실행 로그는 systemd journal과 위 파일 로그를 함께 확인합니다. 운영 로그 회전과 상태·관련 파일을 한 시점으로 맞춘 백업은 별도 운영 작업입니다.

근거: [상태 저장](../../internal/controller/state.go), [경로·감사](../../internal/controller/server.go), [서명 원본](../../internal/controller/signing.go)의 `pinnedUnsignedArtifact`, [MOK 저장](../../internal/controller/signing_admin.go)의 `MOKEnrollment`, [에이전트 상태](../../internal/agent/state.go).
