#!/bin/bash
# Pin the native C/C++ family, plus every already-installed binary from the
# same GCC source. Do not install unrelated Ada/Fortran/cross compilers.
set -euo pipefail
compiler=${1:?compiler package}
cxx=${2:?C++ package}
name=${compiler%%=*}; version=${compiler#*=}; major=${name#gcc-}
[[ "$name" =~ ^gcc-[0-9]+$ && "$compiler" = *=* && "$version" =~ ^[A-Za-z0-9.+:~_-]+$ ]] || exit 2
pins=()
for component in "gcc-$major" "g++-$major" "cpp-$major" "gcc-$major-base" "libgcc-$major-dev" "libstdc++-$major-dev"; do
  apt-cache show "$component=$version" > /tmp/kpctl-package-metadata 2>/dev/null || {
    echo "정확한 GCC 구성 패키지가 없습니다: $component=$version" >&2; exit 3;
  }
  grep -q '^Package:' /tmp/kpctl-package-metadata || { echo "패키지 버전 없음: $component=$version" >&2; exit 3; }
  pins+=("$component=$version")
done
case "$(dpkg --print-architecture)" in
  amd64) triplet=x86-64-linux-gnu ;;
  arm64) triplet=aarch64-linux-gnu ;;
  *) triplet= ;;
esac
if [ -n "$triplet" ]; then
  for component in "gcc-$major-$triplet" "g++-$major-$triplet" "cpp-$major-$triplet"; do
    if apt-cache show "$component=$version" > /tmp/kpctl-package-metadata 2>/dev/null && grep -q '^Package:' /tmp/kpctl-package-metadata; then
      pins+=("$component=$version")
    fi
  done
fi
while IFS=$'\t' read -r binary source; do
  if [ "$source" = "gcc-$major" ]; then pins+=("$binary=$version"); fi
done < <(dpkg-query -W -f='${binary:Package}\t${source:Package}\n')
printf '%s\n' "${pins[@]}" "$cxx" | LC_ALL=C sort -u
