#!/bin/bash
# Image preparation only. Snapshot selection never changes the build host APT.
set -euo pipefail
snapshot=${1:-}
if [ -n "$snapshot" ] && [[ ! "$snapshot" =~ ^[0-9]{8}T[0-9]{6}Z$ ]]; then
  echo '잘못된 Ubuntu snapshot ID' >&2; exit 2
fi
if [ -s /tmp/environment/ca-certificates.crt ]; then
  echo 'Acquire::https::CaInfo "/tmp/environment/ca-certificates.crt";' > /etc/apt/apt.conf.d/49kpctl-bootstrap-ca
fi
if [ -n "$snapshot" ] && [ ! -s /tmp/environment/sources ]; then
  . /etc/os-release
  rm -f /etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources
  cat > /etc/apt/sources.list.d/ubuntu.sources <<EOF
Types: deb deb-src
URIs: https://snapshot.ubuntu.com/ubuntu/$snapshot/
Suites: $VERSION_CODENAME $VERSION_CODENAME-updates $VERSION_CODENAME-security
Components: main restricted universe multiverse
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
Snapshot: no
Check-Valid-Until: no
EOF
  # The URI already fixes the historical date. Only freshness expiration is
  # disabled; archive signatures and every package SHA-256 remain mandatory.
  rm -f /etc/apt/apt.conf.d/50kpctl-snapshot
  cat > /etc/apt/preferences.d/kpctl-snapshot <<'EOF'
Package: *
Pin: origin "snapshot.ubuntu.com"
Pin-Priority: 1001
EOF
  exit 0
fi
if [ -s /tmp/environment/sources ]; then
  rm -f /etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources
  cp /tmp/environment/sources /etc/apt/sources.list.d/ubuntu.sources
fi
if [ -f /etc/apt/sources.list.d/ubuntu.sources ]; then
  sed -i 's/^Types: deb$/Types: deb deb-src/' /etc/apt/sources.list.d/ubuntu.sources
  if [ -n "$snapshot" ]; then
    awk -v id="$snapshot" '
      /^Snapshot:/ { next }
      /^$/ { if (block) print "Snapshot: " id; print; block=0; next }
      { print; if ($0 !~ /^#/) block=1 }
      END { if (block) print "Snapshot: " id }
    ' /etc/apt/sources.list.d/ubuntu.sources > /tmp/environment-sources.new
    cp /tmp/environment-sources.new /etc/apt/sources.list.d/ubuntu.sources
  fi
else
  awk -v id="$snapshot" '
    /^deb / {
      if (id != "") {
        if ($0 ~ /^deb \[/) sub(/^deb \[/,"deb [snapshot=" id " ")
        else sub(/^deb /,"deb [snapshot=" id "] ")
      }
      print; sub(/^deb /,"deb-src "); print; next
    }
    { print }
  ' /etc/apt/sources.list > /tmp/environment-sources.new
  cp /tmp/environment-sources.new /etc/apt/sources.list
fi
if [ -n "$snapshot" ]; then
  printf 'APT::Snapshot "%s";\n' "$snapshot" > /etc/apt/apt.conf.d/50kpctl-snapshot
fi
