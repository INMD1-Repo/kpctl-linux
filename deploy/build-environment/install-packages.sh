#!/bin/bash
set -euo pipefail
export LC_ALL=C
locked=${1:?locked mode}
compiler=${2:?compiler package}
cxx=${3:?C++ package}
bash /tmp/environment/configure-apt.sh "${4:-}"
apt-get update -q
if [ "$locked" = 1 ]; then
  # Unchanged base packages are already supplied by the immutable base image.
  # Reinstall every added/changed package and verify the FULL manifest below.
  # This avoids requiring newer base packages in an older compiler snapshot.
  comm -23 /tmp/environment/packages.lock /tmp/environment/base-packages.lock > /tmp/kpctl-delta.lock
  xargs -r apt-get install -y -q --no-install-recommends --allow-downgrades --reinstall < /tmp/kpctl-delta.lock
else
  apt-get install -y -q --allow-downgrades --no-install-recommends ca-certificates git python3 build-essential dpkg-dev \
    devscripts ccache gawk libelf-dev elfutils patchutils bison flex libssl-dev bc \
    rsync libxxhash-dev kmod xz-utils zstd
  apt-get build-dep -y -q --allow-downgrades linux
  bash /tmp/environment/toolchain-pins.sh "$compiler" "$cxx" > /tmp/kpctl-toolchain.lock
  mapfile -t toolchain < /tmp/kpctl-toolchain.lock
  apt-get install -y -q --no-install-recommends --allow-downgrades "${toolchain[@]}"
  mkdir -p /usr/local/share
  cp /tmp/kpctl-toolchain.lock /usr/local/share/kpctl-toolchain.lock
  if [ -s /tmp/environment/extra-packages ]; then
    xargs -r apt-get install -y -q --no-install-recommends --allow-downgrades < /tmp/environment/extra-packages
  fi
fi
python3 - "$compiler" <<'PY'
import subprocess
import sys

package, version = sys.argv[1].split("=", 1)
metadata = subprocess.check_output(["apt-cache", "show", sys.argv[1]], text=True)
source = next((line[8:].split()[0] for line in metadata.splitlines() if line.startswith("Source: ")), package)
rows = subprocess.check_output(["dpkg-query", "-W", "-f=${binary:Package}\t${source:Package}\t${source:Version}\n"], text=True)
for row in rows.splitlines():
    binary, origin, installed = row.split("\t")
    if origin == source and installed != version:
        raise SystemExit("GCC source package version mismatch: " + binary + "=" + installed + " != " + version)
PY
# Select the compiler requested by the target kernel, even when the image's
# distribution default is a different GCC major. Never use the host compiler.
compiler_name=${compiler%%=*}
compiler_major=${compiler_name#gcc-}
for tool in gcc g++ cc c++; do
  case "$tool" in g++|c++) target="g++-$compiler_major" ;; *) target="gcc-$compiler_major" ;; esac
  test -x "/usr/bin/$target"
  ln -sf "/usr/bin/$target" "/usr/local/bin/$tool"
done
mkdir -p /usr/local/share/kpctl
dpkg-query -W -f='${binary:Package}=${Version}\n' | LC_ALL=C sort > /usr/local/share/kpctl/packages.lock
if [ "$locked" = 1 ]; then
  cmp /usr/local/share/kpctl/packages.lock /tmp/environment/packages.lock
fi
apt-get clean
rm -f /etc/apt/apt.conf.d/49kpctl-bootstrap-ca
