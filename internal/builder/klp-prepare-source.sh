#!/bin/bash
# 커널 소스 준비 (kpatch-build -s, klp-build 공용): klp-prepare-source.sh <커널> <소스 디렉터리> [커널 git 디렉터리 태그 [도구를 합친 트리]]
#
# klp-build 는 실행 중인 커널과 같은 소스와 .config 가 있는 트리에서 돌아야 합니다.
# kpatch-build 가 Ubuntu 에서 하는 준비와 같습니다.
set -euo pipefail

# Ubuntu 패키징은 태그에 들어 있는 공개 인증서를 이 두 파일로 합칩니다.
# 커널 보안 설정을 비우지 않고 동일한 공식 make 대상만 실행합니다.
prepare_certificates() {
  local targets=() key target
  [ -f .config ] || { echo "커널 소스에 .config 가 없습니다"; return 1; }
  for key in SYSTEM_TRUSTED_KEYS SYSTEM_REVOCATION_KEYS; do
    case "$key" in
      SYSTEM_TRUSTED_KEYS) target=debian/canonical-certs.pem ;;
      SYSTEM_REVOCATION_KEYS) target=debian/canonical-revoked-certs.pem ;;
    esac
    if grep -qx "CONFIG_${key}=\"${target}\"" .config && [ ! -s "$target" ]; then
      targets+=("$target")
    fi
  done
  if [ "${#targets[@]}" -gt 0 ]; then
    [ -f debian/rules ] || { echo "Ubuntu 공개 인증서 생성에 필요한 debian/rules 가 없습니다"; return 1; }
    make -s -f debian/rules "${targets[@]}"
    for target in "${targets[@]}"; do
      [ -s "$target" ] || { echo "Ubuntu 공개 인증서 생성 결과가 비어 있습니다: $target"; return 1; }
    done
  fi
}

# 예전 준비 코드가 만든 캐시도 다시 압축을 풀지 않고 누락된 인증서만 준비합니다.
if [ "${1:-}" = "--certificates-only" ]; then
  cd "${2:?소스 디렉터리}"
  prepare_certificates
  exit
fi

KERNEL="${1:?커널}"
SRC="${2:?소스 디렉터리}"
GITDIR="${3:-}"
TAG="${4:-}"
TREE="${5:-}"
CONFIG="${KPCTL_BOOT_DIR:-/boot}/config-$KERNEL"
URL="http://archive.ubuntu.com/ubuntu/pool/main/l"

[ -f "$CONFIG" ] || { echo "$CONFIG 없음 → sudo apt install linux-image-$KERNEL"; exit 1; }

TMP=$(mktemp -d "$(dirname "$SRC")/prepare.XXXXXX")
trap 'rm -rf "$TMP"' EXIT
if [ -n "$GITDIR" ] && [ -n "$TAG" ]; then
  # 빌드 서버의 Ubuntu 커널 git 에서 그 커널의 태그를 꺼냄.
  # Ubuntu 저장소(pool)는 오래된 버전의 소스를 지우므로, 오래된 호스트 커널도 빌드하려면 git 이 필요합니다.
  git -C "$GITDIR" rev-parse -q --verify "refs/tags/$TAG" >/dev/null || { echo "커널 git 에 태그 $TAG 가 없습니다 (git fetch --tags 확인)"; exit 1; }
  mkdir "$TMP/src"
  # TREE: 기준 태그에 검증된 빌드 도구(objtool·klp-build)만 바꿔 넣은 트리 (klptools.go). 커널 코드는 기준 태그 그대로.
  git -C "$GITDIR" archive --format=tar "${TREE:-$TAG}" | tar -x -C "$TMP/src"
  mv "$TMP/src" "$SRC"
else
  PKG=$(dpkg-query -W -f='${Source}' "linux-image-$KERNEL" | sed s/-signed//)
  VER=$(dpkg-query -W -f='${Version}' "linux-image-$KERNEL")
  [ -n "$PKG" ] && [ -n "$VER" ] || { echo "linux-image-$KERNEL 패키지 정보 없음"; exit 1; }
  cd "$TMP"
  dget -u "$URL/$PKG/${PKG}_${VER}.dsc"
  mv "$PKG-${KERNEL%%-*}" "$SRC"
fi

cd "$SRC"
# Ubuntu 는 upstream SUBLEVEL 을 유지하고 make KERNELRELEASE 로 ABI 이름을 정합니다.
# SUBLEVEL 을 0 으로 바꾸면 LINUX_VERSION_CODE 까지 달라집니다.
cp "$CONFIG" .config
# 배포판 패치로 추가된 스크립트는 실행 권한이 빠져 있습니다.
for d in scripts tools; do
  [ -d "$d" ] && find "$d" -type f ! -perm -u+x -exec grep -lZ -m1 '^#!' {} + | xargs -0 -r chmod +x
done
prepare_certificates
echo "ubuntu-build-v2" > .kpctl-source-format
echo "${TAG:-dsc}${TREE:+ tools=$TREE}" > .kpctl-ready
