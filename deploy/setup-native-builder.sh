#!/bin/bash
# Debian 12·Rocky 9·10 AMD64 네이티브 빌더 설치. dist/builder 에서 root 로 실행합니다 (보통 kpctl install-builder 가 SSH 로 실행).
#
# 빌더 호스트는 대상과 같은 배포판·릴리스의 전용 VM 입니다. 이 스크립트는 그 VM 에
#   배포판 공식 빌드 도구 → (Debian 12·Rocky 9) 고정 kpatch → 전용 계정·디렉터리 → 공식 패키징 Git
#   → 대상 커널마다 discover 계획(base.json)·prepare 영수증(base-proof.json) → worker.json·토큰·CA
#   → kpctl-native-builder.timer (kpctl-native-builder.py work 를 1분마다, flock 직렬화, systemd 샌드박스)
# 를 준비합니다. 다시 실행해도 안전해야 합니다 (기존 계정·Git·캐시·설정 재사용).
#
# 하지 않는 것 (보안 경계, docs/operations/distribution-kernels.md):
#   - 컨트롤러 승인 핀(distribution-proofs/<track>.json) 작성: 빌더와 독립된 환경에서 운영자가 합니다.
#   - 수정 후보 수집(collect): 사람이 경로·제목·CVE 를 검토해 실행합니다.
#
# 설치 경로
#   /opt/kpctl/native-builder/             kpctl-native-builder.py, native_inputs.py, kpctl-native-work.sh (root 0755)
#   /usr/local/bin/kpctl-builder           -verify-distribution-module 용 (root 0755)
#   /etc/kpctl/native-builder/worker.json  controller_url, ca_file, token_file, builder (root:<계정> 0640)
#   /etc/kpctl/native-builder/token        빌더 토큰 (root:<계정> 0640)
#   /etc/kpctl/tls/ca.crt                  컨트롤러 CA (선택)
#   /var/lib/kpctl-native/                 <계정> 0700
#     inputs/<debian-linux|rocky-kernel>   공식 패키징 Git (--no-checkout, 태그·원격 브랜치 포함, shallow 금지)
#     cache/  work/                        서명 인덱스·패키지 캐시, 작업마다 새 하위 디렉터리
#     tracks/<track>/base.json             대상 커널 계획 (discover 결과 중 abi·version 이 맞는 한 줄)
#     tracks/<track>/base-proof.json       prepare --fetch 영수증 (track 에 실행 커널 build ID 포함)
#   /etc/systemd/system/kpctl-native-builder.{service,timer}
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
START=1 PLAN=0 WORKER_INPUT="" TOKEN_INPUT="" CA_INPUT="" JOBS="" BUILD_USER="" BUILD_USER_GIVEN=0
TARGETS=()   # "ABI" 또는 "ABI=TRACK"
KPATCH_REF="${KPATCH_REF:-e0a8f7c681964e9128449446a34f7f3e631a8621}"  # setup-builder.sh 와 같은 고정 kpatch
ROOT_DIR=/var/lib/kpctl-native ETC_DIR=/etc/kpctl/native-builder OPT_DIR=/opt/kpctl/native-builder

usage() {
  cat <<'HELP'
사용법: sudo ./setup-native-builder.sh [옵션] --target <ABI[=TRACK]> [--target ...]
  --target ABI[=TRACK] 대상 커널 uname -r (반복). TRACK 을 주면 prepare 영수증의 track 과 정확히 같아야 합니다
  --worker FILE        worker.json (controller_url, ca_file, token_file, builder). 없으면 기존 설정 유지
  --token-file FILE    빌더 토큰 (--worker 와 함께)
  --ca-file FILE       CA 를 /etc/kpctl/tls/ca.crt 로 설치
  --jobs N             컴파일 병렬 수 (기본 CPU 수)
  --user NAME          빌드 실행 계정 (기본 kpbuild, 재설치 때는 기존 서비스 계정)
  --no-start           설치·설정만 하고 타이머 시작 생략
  --plan               점검 결과·설치할 패키지·대상을 JSON 으로 표시하고 아무것도 바꾸지 않음
  --help               도움말
HELP
}

# TODO(codex): 옵션 해석. setup-builder.sh 와 같은 형식 (값 누락·알 수 없는 옵션은 exit 2).
#   --target 값: ABI 는 Debian 12 ^6\.1\.0-[0-9]+-amd64$, Rocky 9·10 은 model/distribution.go 의 profiles 와 같은 정규식.
#   TRACK 은 ^native__(debian__12|rocky__9|rocky__10)__amd64__<ABI>__[^_]+(_t[^_]+)*__[0-9a-f]{40}$ 이고 그 안의 ABI 가 같아야 함.
#   --jobs 는 양의 정수, --user 는 ^[a-z_][a-z0-9_-]{0,31}$ 이고 root 불가. 설치된 서비스의 User= 와 다르면 거부.
#   --worker 를 주면 --token-file 필수 (반대도). 대상이 하나도 없으면 exit 2.
parse_args() {
  echo "!! setup-native-builder.sh: 아직 구현되지 않았습니다" >&2
  exit 2
}

# ■ 1. 점검: root, /etc/os-release 가 Debian 12(bookworm) 또는 Rocky 9·10 stable, x86_64, systemd,
#   컨테이너 아님(systemd-detect-virt --container), Rocky 10 이면 x86-64-v3, /var 여유 40 GiB 이상,
#   모든 --target 이 이 호스트와 같은 배포판·주 릴리스인지. 하나라도 어긋나면 "!! 이유" 출력 후 exit 1.
#   (Go 의 NativeBuilderHardBlock·nativeBuilderChecks 와 같은 기준. kpctl 을 거치지 않고 직접 실행해도 지켜야 함)
check_host() { :; }

# ■ 2. 배포판 패키지: 공식 저장소만 씁니다 (서드파티 저장소 추가 금지).
#   Debian 12: apt-get install git python3 dpkg-dev gpgv gcc make binutils kmod libelf-dev libssl-dev bc bison flex cpio
#              xz-utils zstd dwarves debian-archive-keyring rsync elfutils patchutils + linux 의 Build-Depends (apt-get build-dep 는
#              deb-src 가 필요하므로, 대상 버전 dsc 의 Build-Depends 를 prepare 이후 확인해 설치하거나 문서의 목록 사용)
#   Rocky 9·10: dnf -y install dnf-plugins-core rpm-build rpmdevtools cpio git gnupg2 gcc make elfutils-libelf-devel kmod python3
#              patchutils; dnf config-manager --set-enabled crb; Rocky 10 은 xxhash-libs xxhash-devel(devel 저장소, 0.8 이상).
#              대상 버전마다 `dnf download --source kernel-<version>` 으로 SRPM 을 받아 rpm -K 로 서명 확인 후 `dnf builddep` 실행
#              (native_inputs.discover 의 source-only prepare 가 rpmbuild -bp 를 쓰므로 discover 전에 필요).
install_packages() { :; }

# ■ 3. 고정 kpatch (Debian 12·Rocky 9 만. Rocky 10 은 정식 klp-build): $KPATCH_REF 를 공식 저장소에서 받아
#   bash "$HERE/kpctl-kpatch-fixes.sh" <소스> 로 수정본을 적용하고 make && make install. 이미 같은 ref 로 설치돼 있으면 건너뜀
#   (/usr/local/share/kpctl/kpatch-ref 같은 표식 파일로 판정). setup-builder.sh 의 kpatch 설치 부분을 참고.
install_kpatch() { :; }

# ■ 4. 계정·디렉터리·프로그램: 시스템 계정(로그인 셸 없음), 위 "설치 경로" 의 소유자·권한. kpctl-builder 는 /usr/local/bin 에.
setup_user_and_files() { :; }

# ■ 5. 공식 패키징 Git: Debian https://salsa.debian.org/kernel-team/linux.git, Rocky https://git.rockylinux.org/staging/rpms/kernel.git
#   (native_inputs.SALSA·ROCKY 와 같아야 함). 계정 권한으로 git clone --no-checkout, 이후 git fetch --tags origin
#   +refs/heads/*:refs/remotes/origin/*. 이미 있으면 origin URL 이 같은지 확인 후 fetch 만.
prepare_git() { :; }

# ■ 6. 대상 커널 계획: suite.json = {distro, release, suite, git, keyring} 로 계정 권한에서
#   python3 kpctl-native-builder.py discover --plan suite.json --cache ... --work-dir ... --fetch [--limit N] 를 실행하고
#   출력 JSON 줄 중 abi(와 Debian 은 version 도 TRACK 이 있으면 그 값) 이 대상과 같은 것을 tracks/<임시>/base.json 으로 저장.
#   Debian 은 suite bookworm-security 를 먼저, 없으면 bookworm. Rocky suite 는 BaseOS, keyring 은 /etc/pki/rpm-gpg/RPM-GPG-KEY-Rocky-<rel>.
#   못 찾으면 "!! <ABI>: 공식 서명 릴리스·Git 태그를 찾지 못했습니다" 로 실패. base.json 에 jobs 를 넣음.
plan_targets() { :; }

# ■ 7. 공식 패키지·영수증: 대상마다 계정 권한에서 prepare --plan base.json --cache --work-dir --fetch > base-proof.json.
#   TRACK 을 받았으면 영수증 .track 과 정확히 같아야 함 (다르면 "!! 빌드 ID 불일치" 로 실패, 디렉터리 남기지 않음).
#   성공하면 tracks/<영수증 track>/ 로 옮김. 목록에 없는 기존 tracks/ 하위 디렉터리는 지우지 않고 경고만 (운영자 판단).
prepare_targets() { :; }

# ■ 8. 설정·서비스: --worker/--token-file 이 있으면 원자적으로(임시 파일 → mv) 설치, 없으면 기존 파일이 있어야 함.
#   --ca-file → /etc/kpctl/tls/ca.crt. $HERE/kpctl-native-builder.{service,timer} 를 /etc/systemd/system 에 설치하고
#   서비스의 User=/Group= 을 계정으로 맞춤. systemctl daemon-reload. 설치 후 계정 권한으로 worker.json·토큰·CA 를 읽을 수 있는지 확인.
install_config_and_units() { :; }

# ■ 9. 시작: --no-start 가 아니면 systemctl enable --now kpctl-native-builder.timer 후 서비스 1회 시작(--no-block)
start_timer() { :; }

# --plan: 1 의 점검 결과·2 의 패키지 목록·대상을 JSON 으로 출력하고 종료 (아무것도 바꾸지 않음)
show_plan() { :; }

parse_args "$@"
check_host
if [ "$PLAN" = 1 ]; then show_plan; exit 0; fi
install_packages
install_kpatch
setup_user_and_files
prepare_git
plan_targets
prepare_targets
install_config_and_units
start_timer
