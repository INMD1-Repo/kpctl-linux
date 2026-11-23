# LTS별 빌더 설치

[설치 순서](README.md)

대상 커널의 시리즈와 빌더 OS를 맞춥니다. 기본 설치 경로는 rootless 컨테이너와 대상 GCC 프로파일을 준비합니다. `--host-mode`는 호스트에 직접 빌드 의존성을 설치하는 명시적인 별도 모드입니다.

## 컨트롤러에서 한 번에 설치 (권장)

컨트롤러에 SSH 키가 등록된 빌드 서버라면 컨트롤러에서 명령 하나로 설치합니다. `kpctl install-builder`는 사전 점검(sudo·아키텍처·지원 시리즈·컨트롤러 접속·실행 중인 빌더) → `/usr/local/share/kpctl/builder` 묶음 복사 → 컨트롤러 주소·`/etc/kpctl/tokens/builder.token`·CA로 `builder.json` 작성 → `setup-builder.sh` 실행 → 컨트롤러에 빌더 보고 확인까지 진행합니다. 토큰은 명령줄이 아닌 표준 입력으로 전달되고 임시 디렉터리는 끝나면 지웁니다.

헷갈리면 터미널에서 인자 없이 `sudo kpctl install-builder`만 실행합니다. 빌드 서버 주소, SSH 접속 계정(저장한 키와 계정을 보여 줌), 빌드 서비스 계정, 대상 커널, 메모리, ccache, 재설치 여부를 차례로 묻습니다. 그다음 같은 설치를 다시 할 수 있는 명령줄을 보여 주고, 점검 → 설치 확인 → 설치 순서로 진행합니다. 점검에서 접속에 실패하면 그 자리에서 `ssh-key copy`로 키를 등록하고 다시 점검할 수 있습니다.

```sh
sudo kpctl install-builder                           # 질문형
sudo kpctl ssh-key copy build-noble                  # 키가 아직 없을 때 한 번
sudo kpctl install-builder -check build-noble        # 점검만
sudo kpctl install-builder build-noble               # 설치
sudo kpctl install-builder build-jammy 5.15.0-160-generic -- --memory-mib 16384 --no-cache
```

대상 커널을 생략하면 컨트롤러에 등록된 호스트 중 빌드 서버와 같은 시리즈의 GA 커널을 고릅니다. 등록 호스트가 없으면 커널을 직접 지정해야 합니다. `--` 뒤 값은 `setup-builder.sh` 옵션으로 그대로 전달되며 `--config`·`--ca-file`·`--plan`은 명령이 직접 정합니다. 호스트에 `builder.json`이 이미 있으면 유지하고, 이 컨트롤러 기준으로 새로 만들려면 `-reset-config`를 붙입니다. 계정은 둘 다 고를 수 있습니다. SSH로 접속할 계정은 `-ssh-user`(또는 `user@호스트`)이고, 빌드 서비스를 실행할 계정은 `-build-user`입니다. 빌드 계정을 생략하면 `kpbuild`를 쓰고, 재설치 때는 기존 서비스 계정을 유지합니다. 실행 중인 빌더는 `-stop-running`을 줄 때만 멈추고 다시 설치합니다. 에이전트가 설치된 운영 호스트에는 `-force` 없이 설치하지 않습니다. 호스트별 상세 로그는 `kpctl-install-logs/<호스트>.install-builder.log`에 남습니다.

설치 중 가장 오래 걸리는 단계는 대상 GCC 컴파일러 이미지 빌드입니다. 서명 스냅샷 저장소(snapshot.ubuntu.com)에서 커널 빌드 의존성 수백 MB를 받습니다. 이 저장소는 위치에 따라 매우 느릴 수 있습니다(실측 80 kB/s). 이미지 빌드 제한 시간은 기본 180분입니다. 시간이 넘으면 podman을 SIGTERM으로 멈춰 컨테이너 안의 apt까지 끝내고, 이번 빌드가 남긴 작업 컨테이너를 지운 뒤 마지막 다운로드 속도를 오류에 보여 줍니다. 저장소가 느린 곳에서는 `-- --image-timeout-minutes 360`처럼 늘려 다시 실행합니다. 이미지 빌드 로그는 빌드 서버의 `/var/lib/kpctl-builder/environments/<시리즈>/compiler-*/image-build.log`입니다.

## 접속 설정과 직접 설치

다음은 24.04 `noble` 빌더용 완전한 설정 예시입니다. 시리즈·주소·토큰·CA 경로를 실제 환경 값으로 바꿉니다.

<!-- config-example: builder -->
```json
{
  "controller_url": "https://ctl.mgmt.example.test:8443",
  "token": "replace-with-builder-token-0123456789",
  "ca_file": "/etc/kpctl/tls/ca.crt",
  "series": "noble",
  "controller_kernel_inputs": true,
  "work_dir": "/var/lib/kpctl-builder",
  "git_root": "/srv",
  "discover_minutes": 60,
  "update_check_minutes": 5,
  "max_kernels": 2,
  "sandbox": {
    "profiles_dir": "/var/lib/kpctl-builder/environments/noble",
    "auto_prepare": true,
    "retry_clean": true,
    "prepare": {"memory_mib": 12288, "pids": 4096, "min_free_gib": 60, "cache_gib": 20, "cache_total_gib": 40, "snapshot": "auto"}
  },
  "cve_feed": {"enabled": false}
}
```

`dist/builder/` 전체가 필요합니다. 실행 파일만 복사하면 디버그 입력·격리 환경 도우미가 빠집니다. 아래 커널 번호는 설치 명령의 형식 예시이며 최신 배포 버전을 뜻하지 않습니다.

```sh
cd dist/builder
sudo ./setup-builder.sh --config /secure/builder.json --ca-file /secure/ca.crt --no-start 6.8.0-136-generic
sudo -u kpbuild -H /usr/local/bin/kpctl-builder -config /etc/kpctl/builder.json -check-config
sudo systemctl enable --now kpctl-builder
```

빌드 서비스 계정은 `--user NAME`으로 바꿀 수 있습니다(기본 `kpbuild`). 사용자 생성, sudoers, 작업·Git·설정 디렉터리 소유자, rootless 런타임(subuid·linger), 서비스의 `User=`/`Group=`과 자동 업데이트 소유자 검사에 같은 계정이 적용됩니다. 이미 다른 계정으로 설치된 빌더에 다른 계정을 지정하면 파일 소유자가 갈라지므로 거부합니다. 이 문서의 `sudo -u kpbuild` 예시는 바꾼 계정 이름으로 읽습니다. 설치 스크립트는 실행 중인 빌더가 있으면 중단을 요구합니다. 대상 커널 인자는 기본 sandbox 준비에 필요하며 설치 후 `kernels`가 비어 있으면 등록 호스트의 해당 GA 시리즈를 자동으로 선택합니다. `--plan`으로 설치 모드·호스트 패키지·캐시 계획을 읽을 수 있습니다. `-check-config`는 설정과 CA를 읽는 검사이며 컨트롤러에 접속해 작업을 검증하는 명령은 아닙니다.

## 운영 시 기본값

작업 확인은 기본 30초, 전체 수집은 60분, 정식 배포 상한 확인은 5분입니다. 상한 변경을 확인하면 전체 수집 주기 전에 수집합니다. 수집 주기를 0으로 끌 수 있으며 출시 전 수집은 해당 커널 설정의 별도 주기로 동작합니다.

로더에서 `max_kernels`를 생략하면 제한이 없습니다. 저장소 예시와 위 설치 예시는 최근 2개 ABI로 제한합니다. 메모리·디스크·캐시 값은 설치 옵션과 프로파일에서 정하며 여유 공간 부족은 빌드 보류 사유입니다. 설정된 sandbox가 실패해도 호스트 컴파일로 대체하지 않습니다.

자동 모드와 출시 전 수집을 켠 직접 지정 커널은 정식 APT 상한을 사용합니다. 기존 `kernels` 직접 지정 모드에서 출시 전 기능을 끈 경우에는 `tag_glob`의 최신 태그를 선택하는 경로가 유지됩니다. 이 경우 운영자가 Git 범위를 직접 관리해야 하며 자동 모드의 정식 배포 판정을 받는 설정으로 해석하면 안 됩니다.

빌더 자동 업데이트는 기본 설정과 systemd의 업데이트 경로가 함께 있을 때 사용합니다. 컨트롤러가 제공한 파일의 SHA256을 확인하고 비권한 사용자로 실행 가능성을 검사한 뒤 재시작 시 설치합니다.

출시 전 브랜치와 CNA 매핑은 [F23·F24](../features/prerelease-and-cna.md#f23)를 따릅니다. 자동 수집의 정식 상한, 개별 시험·최종 누적 빌드와 GCC/config/ABI 검사를 생략하는 성능 튜닝은 기본 설치가 아닙니다. `skip_trial_build`를 켠 결과를 개별 수정의 검증 완료로 보고해서는 안 됩니다.

근거: [원격 설치 명령](../../cmd/kpctl/install_builder.go), [원격 설치 단계](../../internal/remote/builder.go), [설치 옵션](../../deploy/setup-builder.sh), [설정](../../internal/builder/config.go)의 `LoadConfig`, [입력 준비](../../internal/builder/task.go)의 `resolveTaskKernel`, [APT 상한](../../internal/builder/published.go)의 `officialTargetTag`, [빌드 검사](../../internal/builder/klp.go)의 `runBuild`, [서비스](../../deploy/systemd/kpctl-builder.service).
