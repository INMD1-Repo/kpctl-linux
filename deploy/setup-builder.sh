#!/bin/bash
# 새 Ubuntu LTS 빌더 설치. dist/builder에서 root로 실행합니다.
# 기본: 호스트 입력 + rootless 런타임 + 대상 GCC 이미지 + 설정·서비스.
# 호스트 컴파일 도구 설치는 --host-mode에서만 수행합니다.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
HOST_MODE=0 START=1 PLAN=0 CONFIG_INPUT="" CA_INPUT="" SOURCES=""
MEMORY_MIB=12288 CACHE_GIB=20 MIN_FREE_GIB=60 JOBS="" IMAGE_TIMEOUT_MINUTES=180 SNAPSHOT_TIMEOUT_MINUTES=20
CACHE_TOTAL_GIB=40 SNAPSHOT=auto CACHE_SELECTED=0 ALLOW_LIVE_FALLBACK=0
BUILD_USER="" BUILD_USER_GIVEN=0
KERNELS=() EXTRA_PACKAGES=()
usage() {
  cat <<'HELP'
사용법: sudo ./setup-builder.sh [옵션] <대상 커널> [커널 ...]
  --config FILE       controller_url/token/ca_file이 있는 builder.json
  --ca-file FILE      CA를 /etc/kpctl/tls/ca.crt로 설치
  --memory-mib N      서비스·컨테이너 메모리 한도 (기본 12288)
  --jobs N            컴파일 병렬 수 (기본 CPU·메모리에서 계산)
  --cache-gib N       ccache 사용량 한도 (기본 20 GiB, 0은 끔; 지정 시 질문 생략)
  --no-cache          ccache 끄기 (--cache-gib 0과 같음)
  --cache-total-gib N sandbox 공통 봉인 캐시 전체 한도 (기본 40 GiB)
  --snapshot ID       GCC용 서명 스냅샷 (기본 auto, none은 지정 저장소)
  --allow-live-fallback 이번 설치에서 자동 스냅샷 서버 장애 시 Ubuntu 일반 저장소의 서명·정확한 GCC 버전 검증 허용
  --snapshot-timeout-minutes N
                      스냅샷 후보 한 개의 GCC 패키지 확인 제한 시간 (기본 20분)
  --min-free-gib N    빌드 시작 여유 공간 (기본 60)
  --image-timeout-minutes N
                      컴파일러 이미지 빌드 제한 시간 (기본 180분, 저장소가 느리면 늘림)
  --sources FILE      이미지용 서명 검증 APT deb822 저장소
  --package NAME=VER  이미지 추가 고정 패키지 (반복 가능)
  --user NAME         빌드 서비스 실행 계정 (기본 kpbuild, 재설치 때는 기존 서비스 계정)
  --host-mode         호스트에 build-dep/kpatch/ccache 설치
  --no-start          설치·설정만 하고 서비스 시작 생략
  --plan              모드·패키지·캐시 계획을 질문 없이 JSON으로 표시
  --help              도움말
HELP
}
while [ $# -gt 0 ]; do
  case "$1" in
    --host-mode) HOST_MODE=1; shift ;;
    --no-start) START=0; shift ;;
    --plan) PLAN=1; shift ;;
    --no-cache) CACHE_GIB=0; CACHE_SELECTED=1; shift ;;
    --allow-live-fallback) ALLOW_LIVE_FALLBACK=1; shift ;;
    --config|--ca-file|--memory-mib|--jobs|--cache-gib|--cache-total-gib|--snapshot|--min-free-gib|--sources|--package|--user|--image-timeout-minutes|--snapshot-timeout-minutes)
      [ $# -ge 2 ] || { echo "$1 값이 필요합니다" >&2; exit 2; }
      case "$1" in
        --config) CONFIG_INPUT=$2 ;; --ca-file) CA_INPUT=$2 ;;
        --memory-mib) MEMORY_MIB=$2 ;; --jobs) JOBS=$2 ;;
        --cache-gib) CACHE_GIB=$2; CACHE_SELECTED=1 ;; --min-free-gib) MIN_FREE_GIB=$2 ;;
        --cache-total-gib) CACHE_TOTAL_GIB=$2 ;; --snapshot) SNAPSHOT=$2 ;;
        --sources) SOURCES=$2 ;; --package) EXTRA_PACKAGES+=("$2") ;;
        --user) BUILD_USER=$2; BUILD_USER_GIVEN=1 ;;
        --image-timeout-minutes) IMAGE_TIMEOUT_MINUTES=$2 ;;
        --snapshot-timeout-minutes) SNAPSHOT_TIMEOUT_MINUTES=$2 ;;
      esac
      shift 2 ;;
    --help|-h) usage; exit 0 ;;
    -*) echo "알 수 없는 옵션: $1" >&2; exit 2 ;;
    *) [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+-[0-9]+-[A-Za-z0-9_-]+$ ]] || { echo "잘못된 커널: $1" >&2; exit 2; }
       KERNELS+=("$1"); shift ;;
  esac
done
if [[ "$ALLOW_LIVE_FALLBACK" = 1 && ( "$HOST_MODE" = 1 || -n "$SOURCES" || "$SNAPSHOT" != auto ) ]]; then
  echo '--allow-live-fallback은 --snapshot auto를 쓰는 기본 sandbox 저장소에서만 사용할 수 있습니다' >&2
  exit 2
fi
for value in "$MEMORY_MIB" "$CACHE_GIB" "$MIN_FREE_GIB" "$CACHE_TOTAL_GIB" "$IMAGE_TIMEOUT_MINUTES" "$SNAPSHOT_TIMEOUT_MINUTES"; do
  [[ "$value" =~ ^[0-9]+$ ]] || { echo '자원 한도는 정수여야 합니다' >&2; exit 2; }
done
# 빌드 계정: 지정값 → 이미 설치된 서비스의 User= → kpbuild. 설치된 계정과 다르면 거부 (파일 소유자가 갈라지므로).
installed_user=$(sed -n 's/^User=//p' /etc/systemd/system/kpctl-builder.service 2>/dev/null | head -1 || true)
if [ -z "$BUILD_USER" ]; then BUILD_USER=${installed_user:-kpbuild}; fi
[[ "$BUILD_USER" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || { echo "잘못된 계정 이름: $BUILD_USER (소문자·숫자·_·- 32자 이내)" >&2; exit 2; }
[ "$BUILD_USER" != root ] || { echo '빌드 계정으로 root 는 쓸 수 없습니다' >&2; exit 2; }
if [ "$BUILD_USER_GIVEN" = 1 ] && [ -n "$installed_user" ] && [ "$installed_user" != "$BUILD_USER" ]; then
  echo "이미 계정 $installed_user 로 설치된 빌더입니다. 계정을 바꾸려면 서비스를 지우고 /var/lib/kpctl-builder 소유자를 정리한 뒤 다시 설치하세요" >&2; exit 2
fi
[[ -z "$JOBS" || "$JOBS" =~ ^[1-9][0-9]*$ ]] || { echo '--jobs는 1 이상이어야 합니다' >&2; exit 2; }
(( MEMORY_MIB >= 1024 && MEMORY_MIB <= 1048576 && CACHE_GIB <= 1024 && MIN_FREE_GIB >= 8 && MIN_FREE_GIB <= 65536 )) || { echo '잘못된 자원 한도' >&2; exit 2; }
(( IMAGE_TIMEOUT_MINUTES >= 10 && IMAGE_TIMEOUT_MINUTES <= 1440 )) || { echo '--image-timeout-minutes 는 10~1440 이어야 합니다' >&2; exit 2; }
(( 10#$SNAPSHOT_TIMEOUT_MINUTES >= 1 && 10#$SNAPSHOT_TIMEOUT_MINUTES <= 1440 )) || { echo '--snapshot-timeout-minutes 는 1~1440 이어야 합니다' >&2; exit 2; }
(( CACHE_TOTAL_GIB <= 4096 && (HOST_MODE == 1 || CACHE_TOTAL_GIB >= CACHE_GIB) )) || { echo '공통 캐시 한도가 잘못됐습니다' >&2; exit 2; }
if [ "$PLAN" = 0 ] && [ "$CACHE_SELECTED" = 0 ] && [ -t 0 ]; then
  if [ "$HOST_MODE" = 1 ]; then
    echo "호스트 ccache: 일반 컴파일 캐시를 최대 ${CACHE_GIB} GiB까지 사용합니다."
  else
    echo "sandbox ccache: 패치 없는 기준 빌드 캐시를 준비하고 읽기 전용으로 재사용합니다 (기준 ${CACHE_GIB} GiB, 전체 ${CACHE_TOTAL_GIB} GiB)."
  fi
  while true; do
    answer=""
    read -r -p 'ccache를 사용하시겠습니까? [Y/n] ' answer || true
    case "$answer" in
      ""|[Yy]|[Yy][Ee][Ss]) break ;;
      [Nn]|[Nn][Oo]) CACHE_GIB=0; break ;;
      *) echo 'y 또는 n으로 답하세요.' >&2 ;;
    esac
  done
fi
cache_service_settings=()
if [ "$HOST_MODE" = 1 ]; then
  if (( CACHE_GIB > 0 )); then
    cache_service_settings=("Environment=CCACHE_NODISABLE=1 CCACHE_MAXSIZE=${CACHE_GIB}Gi" "UnsetEnvironment=CCACHE_DISABLE")
  else
    cache_service_settings=("Environment=CCACHE_DISABLE=1" "UnsetEnvironment=CCACHE_NODISABLE CCACHE_MAXSIZE")
  fi
else
  # Discard a previous host-mode override. The container's sealed-cache
  # profile controls sandbox caching independently of the host environment.
  cache_service_settings=("UnsetEnvironment=CCACHE_DISABLE CCACHE_NODISABLE CCACHE_MAXSIZE")
fi
host_packages=(ca-certificates git python3 sudo curl kmod ubuntu-dbgsym-keyring)
if [ "$HOST_MODE" = 1 ]; then
  host_packages+=(build-essential dpkg-dev devscripts ccache gawk libelf-dev elfutils patchutils bison flex libssl-dev bc rsync libxxhash-dev)
fi
if [ "$PLAN" = 1 ]; then
  python3 - "$HOST_MODE" "$CACHE_GIB" "$CACHE_TOTAL_GIB" "$(printf '%s\n' "${cache_service_settings[@]}")" "${host_packages[@]}" <<'PLANPY'
import json, sys
host = sys.argv[1] == '1'
print(json.dumps({'mode': 'host' if host else 'sandbox', 'host_packages': sys.argv[5:],
                  'runtime_packages': [] if host else ['podman', 'uidmap', 'slirp4netns'],
                  'host_build_dep_linux': host,
                  'cache': {'enabled': int(sys.argv[2]) > 0,
                            'mode': 'host_writable' if host else 'sandbox_sealed',
                            'max_gib': int(sys.argv[2]),
                            'total_gib': None if host else int(sys.argv[3])},
                  'ccache_service_settings': sys.argv[4].splitlines()}))
PLANPY
  exit 0
fi
(. /etc/os-release && [ "$ID" = ubuntu ]) || { echo "Debian/Rocky 빌더는 kpctl-native-builder.py 및 distribution-kernels.md를 사용하세요" >&2; exit 2; }
KPATCH_REF="${KPATCH_REF:-e0a8f7c681964e9128449446a34f7f3e631a8621}"
GIT_ROOT="${GIT_ROOT:-/srv}"
SUPPORTED_LTS="jammy noble resolute"  # internal/model/lts.go 의 SupportedLTS 와 같게 유지
[ "$(id -u)" = 0 ] || { echo "root 로 실행하세요"; exit 1; }
if [ "$HOST_MODE" = 0 ] && [ "${#KERNELS[@]}" = 0 ]; then
  echo 'sandbox 준비에는 대상 커널이 필요합니다 (예: 6.8.0-136-generic)' >&2; exit 2
fi
if [ "$HOST_MODE" = 0 ]; then
  # 빌드 시작 여유(min_free) + 공통 캐시 + 이미지·커널 Git·디버그 심볼(약 30 GiB)은 권장 추정치입니다.
  # 실제 빌드 보류 기준은 활성 프로파일의 disk_free_mib 이며, 그보다 부족하면 빌더가 빌드를 보류하고 웹에 알립니다.
  disk_dir=/var/lib; [ -d /var/lib/kpctl-builder ] && disk_dir=/var/lib/kpctl-builder
  disk_cache=$CACHE_TOTAL_GIB; (( CACHE_GIB > 0 )) || disk_cache=0
  disk_need=$(( MIN_FREE_GIB + disk_cache + 30 ))
  disk_free=$(( $(df -Pk "$disk_dir" | awk 'NR==2 {print $4}') / 1048576 ))
  if (( disk_free < disk_need )); then
    echo "경고: $disk_dir 여유 ${disk_free} GiB < 필요 약 ${disk_need} GiB (시작 여유 ${MIN_FREE_GIB} + 캐시 ${disk_cache} + 이미지·Git 30)." >&2
    echo "      빌드가 자주 디스크 부족으로 보류되거나 캐시 정리가 잦을 수 있습니다. 디스크를 늘리거나 --min-free-gib·--cache-total-gib 를 낮추세요." >&2
  fi
fi
for input in "$CONFIG_INPUT" "$CA_INPUT" "$SOURCES"; do
  [ -z "$input" ] || [ -f "$input" ] || { echo "입력 파일 없음: $input" >&2; exit 2; }
done
[ -x "$HERE/kpctl-builder" ] || { echo 'make dist로 만든 dist/builder에서 실행하세요' >&2; exit 2; }
[ -f "$HERE/kpctl-kernel-debug.sh" ] || { echo 'kpctl-kernel-debug.sh가 없습니다. make dist로 만든 전체 dist/builder 묶음을 사용하세요' >&2; exit 2; }
[ -f "$HERE/kpctl-kernel-inputs.py" ] || { echo 'kpctl-kernel-inputs.py가 없습니다. 전체 dist/builder 묶음을 사용하세요' >&2; exit 2; }
if systemctl is-active --quiet kpctl-builder; then
  echo '실행 중인 빌더가 있습니다. 새 설치 스크립트이므로 작업 종료 뒤 중지하고 실행하세요.' >&2; exit 1
fi
. /etc/os-release
CODENAME="$VERSION_CODENAME"
case " $SUPPORTED_LTS " in
  *" $CODENAME "*) echo "시리즈: $CODENAME ($VERSION_ID) — 이 시리즈의 GA 커널을 자동으로 맡습니다" ;;
  *) echo "지원하지 않는 Ubuntu 시리즈: $CODENAME" >&2; exit 2 ;;
esac

echo "■ 호스트 입력·ddebs (deb-src는 호스트 모드만)"
apt-get update -q
apt-get install -y -q --no-install-recommends "${host_packages[@]}"
cat > /etc/apt/sources.list.d/ddebs.list <<EOF
deb http://ddebs.ubuntu.com ${CODENAME} main restricted universe multiverse
deb http://ddebs.ubuntu.com ${CODENAME}-updates main restricted universe multiverse
EOF
if [ "$HOST_MODE" = 1 ] && [ -f /etc/apt/sources.list.d/ubuntu.sources ]; then
  sed -i 's/^Types: deb$/Types: deb deb-src/' /etc/apt/sources.list.d/ubuntu.sources   # 24.04 이후
fi
if [ "$HOST_MODE" = 1 ] && [ -f /etc/apt/sources.list ]; then
  sed -i 's/^# *deb-src /deb-src /' /etc/apt/sources.list                             # 22.04
fi
apt-get update -q

if [ "$HOST_MODE" = 1 ]; then
  apt-get build-dep -y -q linux
  echo "■ 호스트 kpatch ($KPATCH_REF)"
  if [ ! -d /opt/kpatch ]; then
    git clone https://github.com/dynup/kpatch.git /opt/kpatch
  fi
  git -C /opt/kpatch fetch -q origin
  git -C /opt/kpatch checkout -q "$KPATCH_REF"
  bash "$HERE/kpctl-kpatch-fixes.sh" /opt/kpatch
  make -C /opt/kpatch -j"$(nproc)"
  python3 "$HERE/kpctl-kpatch-cold-test.py" /opt/kpatch/kpatch-build/create-diff-object
  make -C /opt/kpatch install
  echo "kpatch 커밋: $(git -C /opt/kpatch rev-parse HEAD)"
fi

echo "■ 커널별 디버그 심볼"
[ "${#KERNELS[@]}" -ge 1 ] || echo "  (커널을 주지 않아 건너뜀. 빌드 서버 로그에 '디버그 심볼 없음' 이 보이면 그 커널로 다시 실행하세요)"
for K in "${KERNELS[@]}"; do
  # 운영 중 자동 설치와 같은 경로로 이미지·헤더·모듈·심볼을 준비합니다 (APT → Launchpad).
  bash "$HERE/kpctl-kernel-debug.sh" "$K" \
    || { echo "!! ${K} 입력 패키지를 준비하지 못했습니다. 위 APT·Launchpad 오류를 확인하세요." >&2; exit 1; }
  test -f "/usr/lib/debug/boot/vmlinux-${K}" || { echo "!! vmlinux-${K} 없음"; exit 1; }
  if grep -q '^CONFIG_X86_KERNEL_IBT=y' "/boot/config-${K}" 2>/dev/null \
     || grep -q '^CONFIG_X86_KERNEL_IBT=y' "/usr/src/linux-headers-${K}/.config" 2>/dev/null; then
    echo "!! ${K}: CONFIG_X86_KERNEL_IBT=y — kpatch-build 가 이 커널을 거부합니다"
  fi
  echo "  ${K}: 커널을 빌드한 컴파일러 → $(grep -ho 'gcc[^)]*' /usr/src/linux-headers-${K}/include/generated/compile.h 2>/dev/null || echo '확인 불가')"
done
if [ "$HOST_MODE" = 1 ]; then gcc --version | head -1; fi

echo "■ 빌드 사용자"
echo "  계정: $BUILD_USER"
id "$BUILD_USER" >/dev/null 2>&1 || useradd -m -s /bin/bash "$BUILD_USER"
BUILD_GROUP=$(id -gn "$BUILD_USER")
install -d -o "$BUILD_USER" -g "$BUILD_GROUP" /var/lib/kpctl-builder
# 호스트가 오래된 커널을 써도 사람 손 없이 빌드하도록, kpctl-builder 가 그 커널의 디버그 심볼을 직접 설치합니다.
# 빌드 계정에게는 이 도우미 하나만 root 로 실행하게 허용합니다 (도우미가 커널 이름·버전 형식을 검사).
if [ -f "$HERE/kpctl-kernel-debug.sh" ]; then
  install -m 0755 -o root -g root "$HERE/kpctl-kernel-debug.sh" /usr/local/sbin/kpctl-kernel-debug
  install -d -m 0755 -o root -g root /usr/local/libexec
  install -m 0755 -o root -g root "$HERE/kpctl-kernel-inputs.py" /usr/local/libexec/kpctl-kernel-inputs
  SUDOERS=$(mktemp)
  echo "$BUILD_USER ALL=(root) NOPASSWD: /usr/local/sbin/kpctl-kernel-debug" > "$SUDOERS"
  if visudo -cqf "$SUDOERS"; then
    install -m 0440 -o root -g root "$SUDOERS" /etc/sudoers.d/kpctl-builder
    echo "  디버그 심볼 자동 설치: /usr/local/sbin/kpctl-kernel-debug (+ /etc/sudoers.d/kpctl-builder)"
  else
    echo "!! sudoers 규칙 검사 실패 — 디버그 심볼 자동 설치를 끕니다"
  fi
  rm -f "$SUDOERS"
else
  echo "  (kpctl-kernel-debug.sh 가 없어 디버그 심볼 자동 설치를 건너뜀)"
fi

echo "■ Ubuntu 커널 git ($CODENAME)"
GIT_DIR="$GIT_ROOT/ubuntu-$CODENAME"
(
  builder_git() { sudo -u "$BUILD_USER" -H sh -c 'cd "$HOME" && exec git "$@"' sh "$@"; }
  valid_worktree() {
    local top
    top=$(builder_git -C "$1" rev-parse --show-toplevel 2>/dev/null) &&
      [[ "$1" -ef "$top" ]] && builder_git -C "$1" rev-parse --verify --quiet 'HEAD^{commit}' >/dev/null
  }
  use_existing() {
    if valid_worktree "$GIT_DIR"; then
      echo "  이미 있음: $GIT_DIR"
      return 0
    fi
    echo "!! $GIT_DIR 에서 빌드 사용자가 유효한 git 체크아웃과 HEAD를 확인할 수 없습니다. 기존 경로를 복구하거나 다른 위치로 옮긴 뒤 재시도하세요." >&2
    return 1
  }
  if [ -e "$GIT_DIR" ] || [ -L "$GIT_DIR" ]; then
    use_existing
    exit
  fi
  mkdir -p -- "$GIT_ROOT"
  stage=$(mktemp -d -- "$GIT_ROOT/.ubuntu-$CODENAME.clone.XXXXXXXX")
  trap 'rm -rf -- "$stage"' EXIT
  trap 'exit 129' HUP
  trap 'exit 130' INT
  trap 'exit 143' TERM
  chmod 0711 "$stage"
  # Launchpad 의 HTTPS 앞단은 큰 저장소에서 "Path translation timed out" / 504 를 자주 냅니다 (서버 측 일시 오류).
  # 몇 번 다시 시도하고, 그래도 안 되면 HTTP 앞단을 거치지 않는 git:// 로 받습니다.
  # origin 은 마지막에 https 로 맞춰 두어, 이후 fetch 는 방화벽에서 막히기 쉬운 9418 포트를 쓰지 않습니다.
  LP_PATH="git.launchpad.net/~ubuntu-kernel/ubuntu/+source/linux/+git/${CODENAME}"
  urls=("https://$LP_PATH" "https://$LP_PATH" "https://$LP_PATH" "git://$LP_PATH" "git://$LP_PATH")
  for index in "${!urls[@]}"; do
    url=${urls[index]}
    checkout="$stage/checkout"
    install -d -o "$BUILD_USER" -g "$BUILD_GROUP" "$checkout"
    echo "  clone: $url"
    if builder_git clone "$url" "$checkout" && valid_worktree "$checkout"; then
      builder_git -C "$checkout" remote set-url origin "https://$LP_PATH"
      if ! mv -nT -- "$checkout" "$GIT_DIR"; then
        [ -e "$GIT_DIR" ] || [ -L "$GIT_DIR" ] || exit 1
      fi
      # mv -n 은 다른 설치가 경로를 먼저 만들었을 때도 성공을 반환할 수 있습니다.
      if [ -e "$checkout" ]; then use_existing; fi
      exit 0
    fi
    rm -rf -- "$checkout"
    if (( index + 1 < ${#urls[@]} )); then
      echo "  !! 실패. 30초 뒤 다시 시도합니다"
      sleep 30
    fi
  done
  echo "!! 커널 git clone 실패 (Launchpad 일시 장애일 수 있음). 나중에 이 스크립트를 다시 실행하세요" >&2
  exit 1
)

profiles="/var/lib/kpctl-builder/environments/$CODENAME"
if [ "$HOST_MODE" = 0 ]; then
  echo '■ rootless 런타임·대상 컴파일러 프로파일'
  bash "$HERE/setup-build-environment.sh" --fresh-install --user "$BUILD_USER"
  prepare=(/usr/local/libexec/kpctl-build-environment prepare --profiles-dir "$profiles"
           --base-image "docker.io/library/ubuntu:$VERSION_ID" --memory-mib "$MEMORY_MIB"
           --pids 4096 --min-free-gib "$MIN_FREE_GIB" --cache-gib "$CACHE_GIB"
           --cache-total-gib "$CACHE_TOTAL_GIB" --snapshot "$SNAPSHOT" --git-dir "$GIT_DIR"
           --snapshot-timeout-minutes "$SNAPSHOT_TIMEOUT_MINUTES" --image-timeout-minutes "$IMAGE_TIMEOUT_MINUTES")
  if [ "$ALLOW_LIVE_FALLBACK" = 1 ]; then prepare+=(--allow-live-fallback); fi
  source_copy=""
  if [ -n "$SOURCES" ]; then
    source_copy=$(mktemp /var/lib/kpctl-builder/environments/.sources.XXXXXXXX)
    install -m 0400 -o "$BUILD_USER" -g "$BUILD_GROUP" "$SOURCES" "$source_copy"
    prepare+=(--sources "$source_copy")
    trap 'rm -f "$source_copy"' EXIT
  fi
  for package in "${EXTRA_PACKAGES[@]}"; do prepare+=(--package "$package"); done
  for kernel in "${KERNELS[@]}"; do
    sudo -u "$BUILD_USER" -H sh -c 'cd "$HOME"; exec "$@"' sh "${prepare[@]}" --kernel "$kernel"
  done
  [ -z "$source_copy" ] || rm -f "$source_copy"
fi

echo '■ 바이너리·설정·서비스'
base_for_config=""
if [ "$HOST_MODE" = 0 ]; then
  base_for_config=$(python3 - "$profiles/base-image.json" <<'PY'
import json,sys
print(json.load(open(sys.argv[1]))['base_image'])
PY
  )
fi
install -m 0755 -o root -g root "$HERE/kpctl-builder" /usr/local/bin/kpctl-builder
install -d -m 0750 -o root -g "$BUILD_GROUP" /etc/kpctl
source_for_config=""
if [ "$HOST_MODE" = 0 ] && [ -n "$SOURCES" ]; then
  source_for_config=/etc/kpctl/build-environment.sources
  install -m 0640 -o root -g "$BUILD_GROUP" "$SOURCES" "$source_for_config"
fi
if [ -n "$CA_INPUT" ]; then
  install -d -m 0755 /etc/kpctl/tls
  install -m 0644 -o root -g root "$CA_INPUT" /etc/kpctl/tls/ca.crt
fi
config_source="$CONFIG_INPUT"
if [ -z "$config_source" ]; then
  if [ -f /etc/kpctl/builder.json ]; then config_source=/etc/kpctl/builder.json
  else config_source="$HERE/builder.example.json"; START=0
  fi
fi
if [ -z "$JOBS" ]; then
  JOBS=$(( MEMORY_MIB / 1536 )); (( JOBS > 0 )) || JOBS=1
  cpus=$(nproc); (( JOBS <= cpus )) || JOBS=$cpus
fi
python3 - "$config_source" "$HOST_MODE" "$profiles" "$CODENAME" "$GIT_ROOT" "$JOBS" "$CA_INPUT" "$MEMORY_MIB" "$CACHE_GIB" "$CACHE_TOTAL_GIB" "$MIN_FREE_GIB" "$SNAPSHOT" \
  "$SNAPSHOT_TIMEOUT_MINUTES" "$IMAGE_TIMEOUT_MINUTES" "$source_for_config" "$base_for_config" "$BUILD_GROUP" "${EXTRA_PACKAGES[@]}" <<'PY'
import json
import os
from pathlib import Path
import grp
import sys
import tempfile

(source, host, profiles, series, git_root, jobs, ca, memory, cache, total, minimum, snapshot,
 snapshot_timeout, image_timeout, sources, base, group, *packages) = sys.argv[1:]
config = json.loads(Path(source).read_text())
if config.get("series") not in (None, "", series):
    raise SystemExit("설정의 series가 설치할 Ubuntu 시리즈와 다릅니다")
config["series"] = series
config["git_root"] = git_root
config["jobs"] = int(jobs)
if ca:
    config["ca_file"] = "/etc/kpctl/tls/ca.crt"
if host == "1":
    config.pop("sandbox", None)
else:
    config["sandbox"] = {"profiles_dir": profiles, "retry_clean": True, "auto_prepare": True,
                         "prepare": {"base_image": base, "memory_mib": int(memory), "pids": 4096, "min_free_gib": int(minimum),
                                     "cache_gib": int(cache), "cache_total_gib": int(total), "snapshot": snapshot,
                                     "snapshot_timeout_minutes": int(snapshot_timeout), "image_timeout_minutes": int(image_timeout),
                                     "sources": sources, "packages": packages}}
target = Path("/etc/kpctl/builder.json")
fd, name = tempfile.mkstemp(prefix=".builder-", dir=target.parent)
with os.fdopen(fd, "w") as output:
    os.fchmod(output.fileno(), 0o640)
    os.fchown(output.fileno(), 0, grp.getgrnam(group).gr_gid)
    json.dump(config, output, ensure_ascii=False, indent=2)
    output.write("\n")
    output.flush()
    os.fsync(output.fileno())
os.replace(name, target)
PY
service="$HERE/kpctl-builder.service"
[ -f "$service" ] || service="$HERE/systemd/kpctl-builder.service"
# 서비스 파일의 계정(User=/Group=, 자동 업데이트 소유자 검사)을 빌드 계정으로 맞춤
unit=$(mktemp)
sed -e "s/^User=kpbuild\$/User=$BUILD_USER/" -e "s/^Group=kpbuild\$/Group=$BUILD_GROUP/" \
    -e "s/= kpbuild:1 ]/= $BUILD_USER:1 ]/" -e "s/~kpbuild/~$BUILD_USER/; s/# kpbuild 소유/# $BUILD_USER 소유/" "$service" > "$unit"
grep -q "^User=$BUILD_USER\$" "$unit" && grep -q "= $BUILD_USER:1 ]" "$unit" || { echo '!! 서비스 파일 계정 치환 실패' >&2; rm -f "$unit"; exit 1; }
install -m 0644 -o root -g root "$unit" /etc/systemd/system/kpctl-builder.service
rm -f "$unit"
install -d -m 0755 /etc/systemd/system/kpctl-builder.service.d
cat > /etc/systemd/system/kpctl-builder.service.d/20-resources.conf <<EOF
[Service]
MemoryMax=${MEMORY_MIB}M
TasksMax=4096
EOF
printf '%s\n' '[Service]' "${cache_service_settings[@]}" > /etc/systemd/system/kpctl-builder.service.d/30-ccache.conf
systemctl daemon-reload
if [ "$START" = 1 ]; then
  sudo -u "$BUILD_USER" -H /usr/local/bin/kpctl-builder -config /etc/kpctl/builder.json -check-config
  systemctl enable --now kpctl-builder
else
  echo "설치 완료 (빌드 계정 $BUILD_USER). builder.json의 접속 정보·CA를 확인한 뒤 systemctl enable --now kpctl-builder를 실행하세요."
fi
