#!/bin/bash
# kpctl-kernel-debug: 호스트 커널의 디버그 심볼(vmlinux)·이미지·헤더를 빌드 서버에 설치합니다.
#
#   sudo /usr/local/sbin/kpctl-kernel-debug [--controller] <커널> [패키지버전]
#   예: sudo /usr/local/sbin/kpctl-kernel-debug 7.0.0-28-generic 7.0.0-28.28
#
# kpctl-builder(빌드 계정, 기본 kpbuild)가 디버그 심볼이 없는 호스트 커널을 만나면 이 스크립트를 sudo 로 부릅니다.
# sudoers 에는 이 스크립트 하나만 허용합니다 (/etc/sudoers.d/kpctl-builder, setup-builder.sh 가 만듦).
# 그래서 인자를 엄격히 검사하고, 정해진 패키지 이름만 설치합니다.
#
# 1) apt (ddebs 포함) 로 설치
# 2) 저장소에서 이미 빠진 오래된 버전이면 Launchpad 빌드 기록에서 받아 dpkg 로 설치
#    패키지 버전을 생략하면 같은 Ubuntu 시리즈·아키텍처의 정식 배포 기록에서 조회
#
# 설치한 오래된 커널 이미지는 부팅 기본값을 바꾸지 않습니다 (grub 은 가장 높은 버전으로 부팅).
set -euo pipefail

installed() { [ "$(dpkg-query -W -f='${db:Status-Status}' "$1" 2>/dev/null || true)" = installed ]; }

# --remove <커널>: 빌드 서버의 최근 커널 범위 밖 커널 자료(디버그 심볼·이미지·헤더) 삭제.
# 실행 중인 커널·가장 높은 설치 커널은 지우지 않고, apt 시뮬레이션 결과가 정확히 그 커널 패키지만일 때만 지웁니다.
if [ "${1:-}" = "--remove" ]; then
  K="${2:-}"
  [[ "$K" =~ ^[0-9]+\.[0-9]+\.[0-9]+-[0-9]+-generic$ ]] || { echo "커널 이름이 이상합니다: '$K'" >&2; exit 2; }
  [ "$(id -u)" = 0 ] || { echo "root 로 실행해야 합니다" >&2; exit 1; }
  [ "$K" != "$(uname -r)" ] || { echo "실행 중인 커널은 지우지 않습니다: $K" >&2; exit 4; }
  newest=$(ls /boot/vmlinuz-*-generic 2>/dev/null | sed 's|^/boot/vmlinuz-||' | sort -V | tail -1)
  [ "$K" != "$newest" ] || { echo "가장 높은 설치 커널(부팅 기본값)은 지우지 않습니다: $K" >&2; exit 4; }
  ABI="${K%-generic}"
  pkgs=()
  for p in "linux-image-$K" "linux-image-unsigned-$K" "linux-modules-$K" "linux-modules-extra-$K" \
           "linux-headers-$K" "linux-image-$K-dbgsym" "linux-image-unsigned-$K-dbgsym"; do
    installed "$p" && pkgs+=("$p")
  done
  # 공통 헤더는 같은 ABI 의 다른 변형 헤더가 없을 때만
  others=$(dpkg-query -W -f='${Package} ${db:Status-Status}\n' "linux-headers-$ABI-*" 2>/dev/null | awk -v k="linux-headers-$K" '$2=="installed" && $1!=k' || true)
  [ -z "$others" ] && installed "linux-headers-$ABI" && pkgs+=("linux-headers-$ABI")
  VMLINUX="/usr/lib/debug/boot/vmlinux-$K"
  if [ ${#pkgs[@]} -gt 0 ]; then
    export DEBIAN_FRONTEND=noninteractive
    sim=$(apt-get -s -o DPkg::Lock::Timeout=300 purge "${pkgs[@]}" 2>&1) || { echo "apt 시뮬레이션 실패: $(echo "$sim" | tail -2)" >&2; exit 5; }
    while read -r verb name _; do
      case "$verb" in Remv|Purg) ;; *) continue ;; esac
      case " ${pkgs[*]} " in *" $name "*) ;; *) echo "다른 패키지($name)까지 지워지므로 중단합니다" >&2; exit 5 ;; esac
    done <<< "$sim"
    apt-get -y -q -o DPkg::Lock::Timeout=300 purge "${pkgs[@]}" >/dev/null
  fi
  [ -f "$VMLINUX" ] && [ ! -L "$VMLINUX" ] && rm -f "$VMLINUX"
  echo "커널 패키지 ${#pkgs[@]}개 삭제: $K"
  exit 0
fi

INPUT_MODE=""
if [ "${1:-}" = --controller ]; then INPUT_MODE=--controller; shift; fi
K="${1:-}" V="${2:-}"
[ "$#" -le 2 ] || { echo '지원하지 않는 입력 전달 옵션' >&2; exit 2; }
if [ "$INPUT_MODE" = --controller ] && [ -z "$V" ]; then
  echo '컨트롤러 입력 전달에는 정확한 패키지 버전이 필요합니다' >&2; exit 2
fi
[[ "$K" =~ ^[0-9]+\.[0-9]+\.[0-9]+-[0-9]+-generic$ ]] || { echo "커널 이름이 이상합니다: '$K' (예: 7.0.0-28-generic)" >&2; exit 2; }
ABI="${K%-generic}"
if [ -n "$V" ]; then
  [[ "$V" =~ ^${ABI//./\\.}\.[0-9]+$ ]] || { echo "패키지 버전이 이상합니다: '$V' (예: ${ABI}.NN)" >&2; exit 2; }
fi
[ "$(id -u)" = 0 ] || { echo "root 로 실행해야 합니다" >&2; exit 1; }

VMLINUX="/usr/lib/debug/boot/vmlinux-$K"
ready() {
  [ -f "$VMLINUX" ] && installed "linux-headers-$K" && installed "linux-modules-$K" \
    && { installed "linux-image-$K" || installed "linux-image-unsigned-$K"; } || return 1
  if [ "$INPUT_MODE" = --controller ]; then
    for package in "linux-headers-$K" "linux-headers-$ABI" "linux-modules-$K"; do
      at_version "$package" || return 1
    done
    { at_version "linux-image-$K" || at_version "linux-image-unsigned-$K"; } || return 1
    { at_version "linux-image-$K-dbgsym" || at_version "linux-image-unsigned-$K-dbgsym"; } || return 1
  fi
}
at_version() { installed "$1" && [ "$(dpkg-query -W -f='${Version}' "$1" 2>/dev/null)" = "$V" ]; }
if ready; then echo "이미 있음: $VMLINUX (이미지·헤더·모듈 설치됨)"; exit 0; fi

# 이미 설치한 이미지 종류를 유지하여 signed/unsigned 간 패키지 충돌을 피합니다.
IMAGE="linux-image-$K"
if installed "linux-image-unsigned-$K"; then IMAGE="linux-image-unsigned-$K"; fi
export DEBIAN_FRONTEND=noninteractive
APT=(apt-get -y -q -o DPkg::Lock::Timeout=300 -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold)
pin() { [ -n "$V" ] && echo "=$V" || true; }

install_inputs() {
  if ! dpkg -i "${got[@]}"; then
    "${APT[@]}" -f install 2>&1 | tail -6 \
      || { echo "커널 입력 패키지 의존성 복구 실패: $K ($V)" >&2; exit 3; }
  fi
  ready || { echo "커널 입력 패키지 설치 미완료: $VMLINUX 및 이미지·헤더·모듈을 확인하세요" >&2; exit 3; }
  echo "설치 완료: $VMLINUX"
}

if [ "$INPUT_MODE" = --controller ]; then
  helper=/usr/local/libexec/kpctl-kernel-inputs
  [ -f "$helper" ] || { echo "컨트롤러 입력 도우미가 없습니다: $helper (새 dist/builder 묶음으로 설치하세요)" >&2; exit 3; }
  TMP=$(mktemp -d /tmp/kpctl-kernel-debug.XXXXXX)
  trap 'rm -rf "$TMP"' EXIT
  echo "■ 컨트롤러에서 입력 패키지 받기: $K ($V)"
  keep_image=()
  if installed "$IMAGE"; then keep_image=(--keep-image); fi
  python3 "$helper" "$K" "$V" "$TMP" "$IMAGE" "${keep_image[@]}" > "$TMP/files" \
    || { echo '컨트롤러 입력 전달 실패 (직접 다운로드로 우회하지 않음)' >&2; exit 3; }
  mapfile -t got < "$TMP/files"
  [ "${#got[@]}" -eq 5 ] || { echo '컨트롤러 입력 파일이 부족합니다' >&2; exit 3; }
  install_inputs
  exit 0
fi

echo "■ apt 로 설치 시도: $K $(pin)"
apt-get update -q >/dev/null 2>&1 || true
for debug in "linux-image-unsigned-$K-dbgsym" "linux-image-$K-dbgsym"; do
  if "${APT[@]}" install "$IMAGE$(pin)" "$debug$(pin)" \
       "linux-headers-$K$(pin)" "linux-modules-$K$(pin)" 2>&1 | tail -6; then
    ready && { echo "설치 완료: $VMLINUX"; exit 0; }
  fi
done

# 저장소에서 빠진 버전: Launchpad 빌드 기록 (primary archive 의 +files)
ARCH=$(dpkg --print-architecture)
LP="https://launchpad.net/ubuntu/+archive/primary/+files"
TMP=$(mktemp -d /tmp/kpctl-kernel-debug.XXXXXX)
trap 'rm -rf "$TMP"' EXIT
if [ -z "$V" ]; then
  . /etc/os-release
  series="${VERSION_CODENAME:-}"
  [[ "$series" =~ ^[a-z]+$ ]] || { echo 'Ubuntu 시리즈를 확인할 수 없습니다' >&2; exit 3; }
  echo "■ Launchpad 패키지 버전 조회: $K ($series/$ARCH)"
  if ! curl -fsSG --retry 3 --connect-timeout 15 --max-time 120 \
      'https://api.launchpad.net/1.0/ubuntu/+archive/primary' \
      --data-urlencode 'ws.op=getPublishedBinaries' \
      --data-urlencode "binary_name=linux-image-unsigned-$K" \
      --data-urlencode 'exact_match=true' --data-urlencode 'order_by_date=true' \
      --data-urlencode "distro_arch_series=https://api.launchpad.net/1.0/ubuntu/$series/$ARCH" \
      --data-urlencode 'ws.size=300' -o "$TMP/publications.json"; then
    echo "Launchpad 패키지 버전 조회 실패: $K ($series/$ARCH)" >&2; exit 3
  fi
  if ! V=$(python3 - "$TMP/publications.json" "$ABI" "$K" "$series" "$ARCH" <<'PY'
import json
import re
import sys

path, abi, kernel, series, arch = sys.argv[1:]
with open(path) as source:
    entries = json.load(source)["entries"]
versions = {
    entry["binary_package_version"] for entry in entries
    if entry.get("binary_package_name") == "linux-image-unsigned-" + kernel
    and entry.get("distro_arch_series_link") == f"https://api.launchpad.net/1.0/ubuntu/{series}/{arch}"
    and entry.get("pocket") in ("Release", "Updates", "Security")
    and entry.get("date_published")
    and re.fullmatch(re.escape(abi) + r"\.[0-9]+", entry.get("binary_package_version", ""))
}
if not versions:
    raise SystemExit("일치하는 GA 커널의 정식 배포 패키지 버전이 없습니다")
print(max(versions, key=lambda version: int(version.rsplit(".", 1)[1])))
PY
  ); then
    echo "Launchpad에서 $K 의 정확한 패키지 버전을 확인하지 못했습니다" >&2; exit 3
  fi
fi
echo "■ Launchpad 에서 받기: $V ($ARCH)"
got=()
download() {
  local f="$1"
  if curl -fsSL --retry 3 --connect-timeout 15 --max-time 1800 -o "$TMP/$f" "$LP/$f"; then
    echo "  받음: $f"; got+=("$TMP/$f")
  else
    echo "  다운로드 실패: $f" >&2; return 1
  fi
}
# 새 입력은 signed 이미지를 우선하고, 공급되지 않으면 unsigned 이미지를 시도합니다.
if ! download "${IMAGE}_${V}_${ARCH}.deb"; then
  if [ "$IMAGE" != "linux-image-$K" ] || installed "$IMAGE"; then
    echo "Launchpad 커널 이미지 다운로드 실패: $IMAGE ($V)" >&2; exit 3
  fi
  download "linux-image-unsigned-${K}_${V}_${ARCH}.deb" \
    || { echo "Launchpad 커널 이미지 다운로드 실패: $K ($V)" >&2; exit 3; }
fi
for f in \
  "linux-modules-${K}_${V}_${ARCH}.deb" \
  "linux-headers-${K}_${V}_${ARCH}.deb" \
  "linux-headers-${ABI}_${V}_all.deb" \
  "linux-image-unsigned-${K}-dbgsym_${V}_${ARCH}.ddeb"; do
  download "$f" || { echo "Launchpad 필수 입력 패키지 다운로드 실패: $f" >&2; exit 3; }
done
# 의존성이 빠진 것은 apt 가 채움
install_inputs
