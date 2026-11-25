# 빌드 환경과 캐시

<a id="build-environment"></a>

빌드는 실행 호스트의 커널 버전이 아니라 **대상 커널의 원본·설정·컴파일러·심볼**에 맞아야 합니다. 기본 설치는 `kpbuild` 사용자와 rootless 컨테이너를 사용하고, 대상 커널별 프로파일로 GCC와 입력을 고정합니다. 격리 환경 오류가 생겨도 호스트 빌드로 자동 전환하지 않습니다.

<a id="prepare-environment"></a>

## 설치와 준비

배포 묶음 `dist/builder`에서 실제 대상 커널을 지정합니다. `--plan`은 계획을 출력하고, `--no-start`는 서비스 시작을 보류합니다.

```sh
sudo ./setup-builder.sh --plan --no-cache 6.8.0-85-generic
sudo ./setup-builder.sh --config /안전한/경로/builder.json --no-start 6.8.0-85-generic
sudo -u kpbuild -H /usr/local/bin/kpctl-builder -config /etc/kpctl/builder.json -check-config
sudo systemctl enable --now kpctl-builder
```

기본 메모리 한도는 12288 MiB, PID 한도 4096, 시작 최소 여유 60 GiB, 커널별 기준 캐시 20 GiB, 전체 봉인 캐시 40 GiB입니다. 실제 자원에 맞게 명시하되 서비스의 `MemoryMax`·`TasksMax`와 프로파일 한도를 함께 확인합니다. `--cache-gib 0` 또는 `--no-cache`로 캐시를 끌 수 있습니다. 캐시 사용 여부가 산출물 검사를 바꾸지 않습니다.

기존 빌더에 런타임만 추가하는 `setup-build-environment.sh`는 설치된 호스트 패키지의 업그레이드·제거가 필요한 계획을 거부합니다. 필요한 경우 계획을 검토하여 별도로 런타임을 설치합니다. 도우미·레시피·kpatch 수정 묶음도 같은 릴리스로 설치해야 합니다.

<a id="pins"></a>

## 고정되는 입력

프로파일은 digest로 고정한 기본 이미지, 대상 헤더가 기록한 컴파일러, APT 서명 검증과 필요한 고정 패키지, kpatch 레시피를 사용합니다. `snapshot=auto`는 대상 컴파일러를 취득할 수 있는 서명 스냅샷을 찾습니다. `none`은 명시한 저장소를 쓰는 선택이며 서명 검증을 끄는 옵션이 아닙니다.

원본 `BaseTag`와 config/vmlinux/headers/Module.symvers·심볼 CRC·ELF·vermagic 등의 검사는 누적 빌드, 단독 시험, 출시 전 빌드에 공통 적용됩니다. `CONFIG_KLP_BUILD` 커널은 `build_tool=auto`에서 `klp-build`를 선택하고 그 외에는 `kpatch-build`를 사용합니다. 경로 허용 목록이나 변환 규칙을 넓혀 빌드 실패를 성공으로 바꾸지 않습니다.

`controller_kernel_inputs=true`면 컨트롤러의 인증된 캐시에서 패키지 입력을 가져오며 새 컨트롤러와 해당 도우미가 필요합니다. 기본 직접 취득 경로와 구분합니다. 네트워크·저장소·도구 누락은 패치 자체의 라이브패치 불가 증거가 아닙니다.

<a id="cache-and-failure"></a>

## 캐시·실패 조사

기준 빌드 캐시는 입력·프로파일별로 봉인되어 읽기 전용으로 재사용됩니다. 각 시험은 독립 작업 디렉터리에서 실행하고 네트워크·메모리·PID·디스크 한도를 적용합니다. 캐시 정합성 실패나 clean 재시도 결과도 로그에 남습니다. 손상 캐시를 원본 검증 없이 신뢰하도록 바꾸지 않습니다.

`build_timeout_minutes`(기본 180)는 단계마다 따로 적용됩니다. 커널마다 처음 한 번 하는 패치 없는 기준 빌드(ccache 준비)와 그 뒤의 실제 빌드가 각각 이 시간을 씁니다. 예전에는 둘이 한 시간을 나눠 써서 캐시가 없는 첫 빌드가 끝나지 못했습니다. 2026-11-23 실측(14코어, Ubuntu 26.04 `7.0.0-43`)은 기준 빌드 2시간 6분, 캐시를 쓴 klp-build 72분입니다. 빌더는 도우미 전체를 `2 × build_timeout_minutes + 15분`까지 기다립니다. 중단된 빌드 컨테이너는 다음 실행이 시작할 때 최대 10분 동안 지웁니다. 수십 GiB를 지우는 데 25초 제한은 짧아서, 지우지 못한 컨테이너 때문에 이후 실행이 모두 시작 단계에서 실패했습니다.

```sh
sudo journalctl -u kpctl-builder --since today
sudo -u kpbuild -H /usr/local/libexec/kpctl-build-environment kernel-inventory --profiles-dir /var/lib/kpctl-builder/environments/noble
```

`work_dir/job-<번호>/`, `trial-<커밋>/build.log`, `prerelease-trial-<커밋>/build.log`, 프로파일의 이미지·패키지 증거를 함께 확인합니다. 일반 환경 오류는 같은 입력으로 제한 재시도 후 보류합니다. 원인 미확인·산출물 검증 실패를 패치 자동 제외로 처리하지 않습니다. 관리자가 제외를 결정하면 이유·입력·로그와 미해결 CVE를 보존합니다.

자동 정리는 활성 커널·진행 작업·공유 캐시 참조와 여유 공간을 확인합니다. 인벤토리를 확인하지 못했을 때 수작업으로 커널 자료 전체를 삭제하지 않습니다. `kernel_cleanup_free_gib=-1`은 외부 정리·보류 검사를 끄지만 격리 도우미의 자원 검사는 유지됩니다. 배포 안전성을 위해 기본값에서 벗어나는 설정은 근거를 남깁니다.

근거: [빌더 설정](../../internal/builder/config.go), [설치](../../deploy/setup-builder.sh), [환경 도우미](../../deploy/kpctl-build-environment.py), [실패 분류](../../internal/builder/failure.go), [실제 예제](../../configs/builder.example.json).
