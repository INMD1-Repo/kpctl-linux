# 업그레이드와 복구

<a id="upgrade"></a>

컨트롤러, CLI, 에이전트 설치 묶음, 빌더 바이너리와 외부 도우미를 같은 배포본으로 관리합니다. 프로그램 갱신은 호스트 재부팅 승인을 만들지 않습니다. 배포 전 현재 설정·상태·적용 버전과 진행 작업을 기록합니다.

<a id="backup"></a>

## 일관된 백업

자동 진행을 멈추고 진행 중인 승인·VM 시험·빌드 결과 전송과 재부팅 승인을 정리한 뒤 서비스를 정상 중지해 백업합니다. 에이전트의 이미 적용한 모듈은 컨트롤러 중지만으로 제거되지 않습니다.

| 서버 | 함께 보존할 자료 |
| --- | --- |
| 컨트롤러 | `/etc/kpctl/`의 설정·토큰·TLS·서명 키·SSH 자료, 전체 `data_dir`의 state/settings/patches/artifacts/logs/testlogs/coverage/audit |
| 빌더 | builder 설정·CA, 전체 `work_dir`, 명시한 원본 저장소·프로파일·입력 경로와 도우미 버전 |
| 에이전트 | agent 설정, `/var/lib/kpctl-agent/`의 등록·실행·MOK 결과·준비 기록, `/var/lib/kpatch/` 설치 사본, 수정한 재부팅 훅 |

서명 개인키가 설정 디렉터리 밖에 있으면 그 경로도 포함합니다. `.unsigned-*`와 `signed-<키>/`를 포함한 artifacts 전체가 원본 pin·키별 메타데이터와 한 시점이어야 합니다. 숨김 파일을 제외하는 복사 명령을 사용하지 않습니다. 비밀번호 원문을 가진 state와 개인키·토큰 백업은 접근을 제한하고 별도 안전한 위치에 보관합니다.

## 컨트롤러·CLI

새 `dist/controller`의 설치 스크립트는 기존 설정·키를 재사용하는 경로가 있지만 변경점을 먼저 비교합니다. 서비스를 중지한 상태에서 실행 파일·내장 웹·에이전트 묶음·빌더 제공 파일·도우미를 함께 갱신하고 설정 로더 오류가 없는지 시작 로그를 확인합니다. 웹의 `settings.json` override도 유지되는지 확인합니다.

```sh
sudo systemctl stop kpctl-controller
sudo systemctl daemon-reload
sudo systemctl start kpctl-controller
sudo journalctl -u kpctl-controller --since '-10 minutes'
sudo kpctl status
sudo kpctl signing list
```

명령 사이의 파일 설치는 [컨트롤러 설치](../install/controller.md)의 배포 묶음 절차를 따릅니다. 시작 중 인증서 ID의 DER pin이 다르다고 거부되면 새 ID로 교체 절차를 설계합니다. 상태 파일에서 pin을 지워 통과시키지 않습니다. 중단된 VM 시험은 시작 복구에서 정리되고 실패로 표시됩니다.

## 빌더와 에이전트

빌더 자동 갱신은 `self_update=true`, 제공 바이너리 존재, 서비스의 `KPCTL_BUILDER_UPDATE_PATH`가 모두 필요합니다. 빌더는 인증된 HTTPS로 받은 SHA를 확인하고 `-h` 실행 시험 후 staging 파일을 남겨 종료 코드 75로 재시작합니다. 서비스는 `kpbuild` 소유 단일 링크 일반 파일만 root 설치 대상으로 허용합니다. 이 경로는 Python 도우미·컨테이너 레시피·서비스 설정을 자동 갱신하지 않으므로 별도로 같은 배포본을 설치합니다.

업그레이드 전에 진행 중인 빌드가 결과를 전송하도록 기다립니다. 새 컨트롤러는 성공·실패·보류 결과 모두에서 빌더 이름과 배정 시각을 확인합니다. 빌더를 먼저 갱신하거나 컨트롤러와 빌더를 함께 갱신합니다. 새 빌더가 추가한 결과 필드는 구 컨트롤러에서도 수신할 수 있습니다. 자동 갱신을 사용하면 컨트롤러가 제공하는 빌더 파일도 같은 버전으로 교체합니다.

새 빌더 설정은 먼저 다음과 같이 검사합니다.

```sh
sudo -u kpbuild -H /usr/local/bin/kpctl-builder -config /etc/kpctl/builder.json -check-config
```

에이전트는 새 묶음을 사용하는 `kpctl install` 또는 호스트 설치 스크립트 재실행으로 갱신합니다. 설치는 등록 정보·적용 패치·기존 재부팅 훅을 보존하지만 `agent.json`을 생성하므로 커스텀 설정을 사전에 비교·백업합니다. 갱신 후 security·enrollment·설치 SHA 보고와 실제 활성 상태를 확인합니다. MOK 자동 예약은 명시적인 선택이며 재부팅을 뜻하지 않습니다.

<a id="downgrade"></a>

## 이전 버전으로 복구

일반 추가 필드는 구 버전 JSON 읽기에 무시될 수 있어도 모든 상태 의미가 호환되는 것은 아닙니다. 특히 음수 출시 전 작업·링 overlay는 이전 컨트롤러에서 복구 호환을 보장하지 않습니다. 새 컨트롤러가 동작할 때 다음 순서로 정리합니다.

1. 출시 전 수집을 끄고, 대기·진행·built 음수 작업과 대상 호스트를 검토합니다. 운영 목표를 명시적인 정식 released 버전으로 되돌리고 overlay가 해제됐는지 확인합니다.
2. 호스트의 실제 정식 모듈 적용·전환 완료와 재부팅 요청 없음, MOK 예약 상태를 확인합니다. 원래 자료를 보존한 백업을 만듭니다.
3. 승인된 복구 시점의 실행 파일·설정·**전체 상태와 artifacts**를 일관되게 복원합니다. 새 메타데이터에 옛 artifacts만 섞거나 state만 과거로 덮지 않습니다.
4. 자동 진행을 멈춘 채 시작하여 링 목표·실제 버전·키별 사본·원본 pin·빌더 호환을 재확인합니다. 그 뒤 운영자가 재개합니다.

이미 새 버전이 적용된 호스트와 오래된 컨트롤러 백업 사이의 차이는 운영자가 조정해야 합니다. 원본 pin이 없는 과거 released 작업의 키 교체를 추정으로 허용하지 않으며 [키 교체](secure-boot.md#key-rotation)의 새 누적본 경로를 사용합니다. MOK를 등록했다는 사실과 이전 컨트롤러가 그 등록 상태를 이해하는지는 구분합니다.

근거: [상태 저장](../../internal/controller/state.go), [빌더 갱신](../../internal/builder/selfupdate.go), [제공 바이너리](../../internal/controller/builder_update.go), [에이전트 재설치](../../deploy/install-agent.sh), [VM 복구](../../internal/controller/testvm.go).
