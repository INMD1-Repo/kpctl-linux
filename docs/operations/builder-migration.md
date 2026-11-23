# 빌더 이전

<a id="builder-migration"></a>

이전 대상은 실행 파일만이 아닙니다. 대상 시리즈, controller 접속 정보·CA, `work_dir`, 커널 원본·태그, 디버그 입력, 격리 프로파일·레시피, 진행 작업과 로컬 실패 증거를 함께 다룹니다. 컨트롤러의 작업·패치·배포 상태는 컨트롤러에 보존합니다.

<a id="migration-plan"></a>

## 이전 전

1. `kpctl status`, `jobs`, 웹의 빌더 활동에서 현재 작업과 대상 커널·시리즈를 기록합니다. 자동 승인 영향이 있으면 해당 커널을 hold합니다.
2. 진행 중인 빌드·결과 업로드를 완료하고 구 빌더 서비스를 정상 중지합니다. 서비스는 종료에 긴 유예를 주므로 SIGKILL로 중단하지 않습니다. 중단된 작업은 컨트롤러 제한 시간 뒤 재배정될 수 있습니다.
3. `/etc/kpctl/builder.json`, CA, 사용자·서비스 한도, `work_dir`와 로그·프로파일을 백업합니다. 토큰이 있는 백업은 권한을 제한합니다. 컨트롤러 상태 백업이 필요하면 [전체 백업 절차](upgrade.md#backup)를 따릅니다.

```sh
sudo systemctl stop kpctl-builder
sudo systemctl is-active kpctl-builder
```

새 서버에서는 [빌더 설치](../install/builder.md)로 `kpbuild`, rootless 런타임, 대상 커널 입력과 현재 릴리스 도우미를 준비합니다. 호스트 OS가 다르면 기존 프로파일의 이미지·도구를 검증하고, 대상 컴파일러가 맞는 환경을 다시 준비합니다. 이전 호스트의 기본 GCC를 새 빌더에서 그대로 대신 쓰지 않습니다.

## 자료 배치와 재시작

경로를 유지하면 `git_dir`, `vmlinux`, `profiles_dir` 등 참조가 단순해집니다. 경로를 바꾸면 설정과 프로파일 참조를 함께 점검합니다. 복원 파일은 `kpbuild`가 필요한 작업 경로를 읽고 쓸 수 있어야 하며, root 설치 바이너리·도우미는 서비스 사용자가 교체할 수 없도록 유지합니다. 손상됐거나 출처를 확인할 수 없는 캐시는 새 환경에서 재생성합니다.

```sh
sudo -u kpbuild -H /usr/local/bin/kpctl-builder -config /etc/kpctl/builder.json -check-config
sudo systemctl daemon-reload
sudo systemctl enable --now kpctl-builder
sudo journalctl -u kpctl-builder -f
```

`-check-config`는 JSON·기본값·CA 읽기를 확인하며 컨트롤러 접속이나 실제 빌드를 대신하지 않습니다. 시작 후 빌더 heartbeat, 대상 시리즈, 공식 상한 태그, 준비 프로파일, 실제 누적 빌드와 업로드를 확인합니다. 구 서비스는 자동 재시작되지 않도록 비활성화한 뒤 새 서버를 정상 운영 대상으로 확정합니다.

<a id="new-channels"></a>

## 출시 전·CNA feed 설정이 있는 경우

출시 전 수집은 명시한 `kernels[].prerelease`별로 수행합니다. 기본 꺼짐이며 branch 기본값은 `master-next`, poll 기본값은 30분입니다. 정식 APT 배포 상한과 그 뒤의 고정 tip 사이만 수집하고 정식 collected/latest 기록을 바꾸지 않습니다. 새로운 서버에서도 공식 APT·정확 태그·선형 관계를 확인할 수 있어야 합니다.

`work_dir/prerelease/<커널>.json`의 범위·tip·실패 기록과 `trial-failures/prerelease/`는 재검토 증거입니다. 이 기록을 이전했다고 새 서버의 환경 검증이 생략되지는 않습니다. `cve_feed`가 켜졌으면 첫 수집에서 원격 갱신이 가능해야 하며, 복사한 오래된 cache만으로 갱신 성공을 가정하지 않습니다.

이전 빌더는 capability가 없어 출시 전 작업을 받지 않습니다. 새 설정 필드를 모르는 구 빌더로 되돌릴 때는 [컨트롤러·상태 복구](upgrade.md#downgrade)와 함께 구성 호환을 검토합니다. 진행 중인 음수 작업을 일반 양수 작업으로 수동 변경하지 않습니다.

근거: [빌더 실행과 결과 전송](../../internal/builder/worker.go), [서비스 종료·업데이트](../../deploy/systemd/kpctl-builder.service), [독립 출시 전 수집](../../internal/builder/prerelease.go), [CNA cache](../../internal/builder/cve_feed.go).
