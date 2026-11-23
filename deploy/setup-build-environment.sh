#!/bin/bash
# Add the rootless runtime to an existing kpctl builder. Does not restart builds.
set -euo pipefail
export LC_ALL=C
fresh=0
# 빌드 계정: --user → 설치된 kpctl-builder 서비스의 User= → kpbuild
BUILD_USER=$(sed -n 's/^User=//p' /etc/systemd/system/kpctl-builder.service 2>/dev/null | head -1 || true)
BUILD_USER=${BUILD_USER:-kpbuild}
while [ $# -gt 0 ]; do
  case "$1" in
    --fresh-install) fresh=1; shift ;;
    --user) [ $# -ge 2 ] || { echo '--user 값이 필요합니다' >&2; exit 2; }; BUILD_USER=$2; shift 2 ;;
    *) echo '사용법: setup-build-environment.sh [--fresh-install] [--user NAME]' >&2; exit 2 ;;
  esac
done
[[ "$BUILD_USER" =~ ^[a-z_][a-z0-9_-]{0,31}$ && "$BUILD_USER" != root ]] || { echo "잘못된 빌드 계정: $BUILD_USER" >&2; exit 2; }
[ "$(id -u)" = 0 ] || { echo 'root로 실행하세요'; exit 1; }
HERE=$(cd "$(dirname "$0")" && pwd)
id "$BUILD_USER" >/dev/null 2>&1 || { echo "먼저 setup-builder.sh로 빌드 계정 $BUILD_USER 와 대상 커널 입력을 준비하세요"; exit 1; }
BUILD_GROUP=$(id -gn "$BUILD_USER")
simulation=$(mktemp)
trap 'rm -f "$simulation"' EXIT
apt-get update -q
if [ "$fresh" = 1 ]; then
  apt-get install -y -q --no-install-recommends podman uidmap slirp4netns
else
  apt-get -s install --no-install-recommends --no-upgrade podman uidmap slirp4netns > "$simulation"
  # Refuse upgrades/removals of any installed host package, including dependencies.
  if awk '/^Remv / { bad=1 } /^Inst / && $3 ~ /^\[/ { bad=1 } END { exit !bad }' "$simulation"; then
    cat "$simulation"
    echo '호스트 패키지 교체가 필요합니다. APT 계획을 검토한 뒤 런타임을 별도로 설치하세요.'
    exit 1
  fi
  apt-get install -y -q --no-install-recommends --no-upgrade podman uidmap slirp4netns
fi
for map in /etc/subuid /etc/subgid; do
  allocation=$(python3 - "$map" "$BUILD_USER" <<'PY'
from pathlib import Path
import sys

path, user = Path(sys.argv[1]), sys.argv[2]
entries = []
for line in path.read_text().splitlines() if path.exists() else []:
    if not line.strip() or line.startswith("#"):
        continue
    owner, start, count = line.split(":")
    entries.append((owner, int(start), int(start) + int(count)))
mine = [(start, end) for owner, start, end in entries if owner == user and end - start >= 65536]
if mine:
    for start, end in mine:
        if any(owner != user and start < other_end and other_start < end
               for owner, other_start, other_end in entries):
            raise SystemExit(user + " subordinate ID 범위가 다른 사용자와 겹칩니다: " + str(path))
else:
    start = max([100000] + [end for _, _, end in entries])
    if start + 65536 > 2**32 - 1:
        raise SystemExit("subordinate ID 범위가 부족합니다")
    print(str(start) + "-" + str(start + 65535))
PY
)
  if [ -n "$allocation" ]; then
    case "$map" in
      /etc/subuid) usermod --add-subuids "$allocation" "$BUILD_USER" ;;
      /etc/subgid) usermod --add-subgids "$allocation" "$BUILD_USER" ;;
    esac
  fi
done
loginctl enable-linger "$BUILD_USER"
build_uid=$(id -u "$BUILD_USER")
systemctl start "user@${build_uid}.service"
install -d -m 0755 /usr/local/libexec /usr/local/share/kpctl/build-environment/kpatch-fixes
install -m 0755 "$HERE/kpctl-build-environment.py" /usr/local/libexec/kpctl-build-environment
for asset in Containerfile install-packages.sh configure-apt.sh toolchain-pins.sh; do
  install -m 0644 "$HERE/build-environment/$asset" /usr/local/share/kpctl/build-environment/
done
install -m 0644 "$HERE/kpctl-kpatch-fixes.sh" "$HERE/kpctl-kpatch-cold-test.py" /usr/local/share/kpctl/build-environment/
cp -R "$HERE/kpatch-fixes/." /usr/local/share/kpctl/build-environment/kpatch-fixes/
install -d -o "$BUILD_USER" -g "$BUILD_GROUP" -m 0700 /var/lib/kpctl-builder/environments
sudo -u "$BUILD_USER" -H sh -c 'cd "$HOME"; podman info --format "rootless={{.Host.Security.Rootless}} runtime={{.Host.OCIRuntime.Name}}"'
echo 'rootless 런타임 설치 완료. 대상 헤더를 기준으로 prepare --kernel을 실행합니다.'
