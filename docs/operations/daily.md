# 일상 점검

<a id="daily"></a>

먼저 목표 링 버전과 실제 호스트 상태를 함께 확인합니다. 컨트롤러에서 설치한 CLI는 `/etc/kpctl/kpctl.env`를 읽으며, 이미 설정한 환경 변수가 파일보다 우선합니다.

```sh
sudo kpctl status
sudo kpctl jobs
sudo kpctl hosts
sudo kpctl auto
sudo kpctl signing list
```

호스트가 목표 버전을 보고하는 것만으로 완료 처리하지 않습니다. 최근 보고, 오류 없음, 해당 모듈의 `enabled=1`, `transition=0`을 확인합니다. 서명 때문에 제외된 호스트는 기존 보호를 유지할 수 있으므로, 전체 배포가 진행됐어도 제외 사유를 별도로 처리합니다.

<a id="symptoms"></a>

| 보이는 상태 | 확인할 증거와 다음 행동 |
| --- | --- |
| 작업 `pending` | 해당 Ubuntu 시리즈의 빌더 연결·활동과 작업 대기열을 확인합니다. |
| 작업 `building`이 오래 지속 | 빌더 서비스 로그, 자원 한도, 입력 취득 상태를 확인합니다. 제한 시간이 지나면 작업이 다시 대기열에 들어갈 수 있습니다. |
| 작업 `built` | 빌드 로그와 포함 패치, 서명·VM 시험 설정을 확인한 뒤 승인합니다. |
| VM 시험 실패 | `data_dir/testlogs/`의 해당 작업·모드·키 로그와 단계 결과를 확인합니다. 정리 실패한 고정 VM은 복구 후 다시 시험합니다. |
| 호스트 오류·전환 중 | 에이전트 로그와 `/sys/kernel/livepatch/`를 확인합니다. 강제 언로드로 전환 검사를 우회하지 않습니다. |
| `blocked_mok_missing` | [인증서 등록](secure-boot.md#mok-enrollment)을 진행합니다. 예약만으로 등록이 완료되지 않습니다. |
| `blocked_artifact` | 등록된 키의 사본, 기존 설치 SHA, 원본 보존 여부를 확인하고 새 누적본 또는 재승인을 준비합니다. |
| 서명 상태 `unknown` | 보안 파일·`mokutil` 접근을 복구합니다. unknown은 서명 불필요를 뜻하지 않습니다. |
| 수집 검토·자동 보류 | 실패 커밋과 입력·프로파일·원본 로그를 먼저 확인합니다. 원인 해결 또는 명시적인 관리자 판단 뒤 보류를 해제합니다. |
| 빌더 지원 범위 밖 | 기존 모듈의 보호 범위와 새 공식 GA 커널을 확인하고 [준비·승인 절차](reboot-approval.md#prepare)를 진행합니다. |

```sh
sudo kpctl log 12
sudo journalctl -u kpctl-controller --since today
sudo journalctl -u kpctl-builder --since today
sudo journalctl -u kpctl-agent --since today
```

각 `journalctl` 명령은 해당 서비스가 설치된 서버에서 실행합니다. 빌드 서버의 `work_dir/job-<번호>/`와 `trial-<커밋>/build.log`, 출시 전 시험의 `prerelease-trial-<커밋>/build.log`는 로컬 증거입니다. 컨트롤러의 기본 `data_dir`는 `/var/lib/kpctl`이며, 작업 로그는 `logs/`, VM 로그는 `testlogs/`, 관리자 조작은 `audit.log`에 남습니다.

<a id="incident"></a>

오류 조사 중에는 `kpctl auto hold <커널>`로 해당 커널의 자동 진행을 멈추거나 `kpctl auto pause`로 전체 자동 진행을 멈춥니다. 이 명령은 이미 정해진 호스트 목표를 롤백하지 않습니다. 롤백은 [별도 명령](commands.md#patch-rollout)이며 `-version 0`은 모든 kpctl 패치를 내리는 실제 조작입니다.

다른 공급자의 활성·전환 중 라이브패치가 있으면 atomic replace가 거부됩니다. Canonical Livepatch 등과의 동시 운영을 허용하려고 접두사나 검사 코드를 바꾸지 않습니다. 설치 스크립트는 Canonical Livepatch를 비활성화하지만, 실행 중인 상태도 직접 확인해야 합니다.

복구 전후의 상태, 작업 번호, 커널 패키지 버전, 로그를 보존합니다. 상태 파일만 따로 복사한 백업은 서명 원본·키별 사본과 어긋날 수 있으므로 [일관된 백업](upgrade.md#backup)을 사용합니다.

근거: [배포 판단](../../internal/controller/rollout.go), [에이전트 적용 전 검사](../../internal/agent/kpatch.go), [자동 진행](../../internal/controller/auto.go).
