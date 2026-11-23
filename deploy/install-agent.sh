#!/bin/bash
# 호스트에 에이전트 설치 (root 로 실행, kpctl-agent 바이너리와 같은 디렉터리에서)
#
#   sudo ./install-agent.sh https://kpatch.internal:8443 <등록토큰> [ca.crt]
#   sudo ./install-agent.sh https://kpatch.internal:8443 @/경로/토큰파일 [ca.crt]
#   sudo ./install-agent.sh https://kpatch.internal:8443 @/경로/토큰파일 [ca.crt] --enroll-mok
#
# 토큰 자리에 @파일경로 를 주면 파일에서 읽습니다 (kpctl install 이 이 방식을 씀: ps 에 토큰이 안 보이도록).
# 다시 실행해도 됩니다(재설치·업그레이드). 등록 정보와 적용 중인 패치, 수정한 재부팅 훅은 유지됩니다.
#
# 하는 일:
#   1. kpatch 런타임 설치 (kpatch 명령 + kpatch.service)
#   2. Canonical Livepatch 끄기 (같이 쓰면 서로 패치를 덮어씀)
#   3. 커널 자동 업그레이드/자동 재부팅 막기 (재부팅은 컨트롤러가 결정)
#   4. 에이전트 설치, 설정, 서비스 시작
set -euo pipefail

URL="${1:?컨트롤러 주소}"
TOKEN="${2:?등록 토큰}"
shift 2
CA=""
MOK_LINE=""
for arg in "$@"; do
  case "$arg" in
    --enroll-mok) MOK_LINE='"mok_auto_import": true,' ;;
    --*) echo "알 수 없는 옵션: $arg"; exit 1 ;;
    *) [ -z "$CA" ] || { echo "CA 파일은 하나만 지정하세요"; exit 1; }; CA="$arg" ;;
  esac
done
HERE=$(cd "$(dirname "$0")" && pwd)
[ "$(id -u)" = 0 ] || { echo "root 로 실행하세요"; exit 1; }
# 커널 고정 같은 변경을 하기 전에 막습니다. 컨트롤러·빌드 서버는 패치 대상이 아닙니다.
for f in /etc/kpctl/controller.json /etc/kpctl/builder.json; do
  [ ! -e "$f" ] || { echo "!! 이 서버는 kpctl 컨트롤러 또는 빌드 서버입니다 ($f). 에이전트를 설치하지 않습니다"; exit 1; }
done
export DEBIAN_FRONTEND=noninteractive   # SSH 로 실행할 때 apt 가 질문하지 않도록

if [ "${TOKEN#@}" != "$TOKEN" ]; then
  TOKEN=$(cat "${TOKEN#@}")
fi
[ -n "$TOKEN" ] || { echo "등록 토큰이 비어 있습니다"; exit 1; }
# JSON 에 그대로 넣으므로 안전한 문자만 허용 (openssl rand -hex 로 만든 토큰이면 통과)
[[ "$TOKEN" =~ ^[A-Za-z0-9._-]+$ ]] || { echo "등록 토큰에 영문/숫자/._- 외의 문자가 있습니다"; exit 1; }

echo "■ 커널 확인"
K=$(uname -r)
[ -d /sys/kernel/livepatch ] || grep -qs '^CONFIG_LIVEPATCH=y' "/boot/config-$K" || { echo "!! $K 커널에 CONFIG_LIVEPATCH 가 없습니다"; exit 1; }
[ -d "/lib/modules/$K" ] || { echo "!! /lib/modules/$K 가 없습니다 (실행 중인 커널 패키지가 지워짐). 설치된 커널로 재부팅한 뒤 다시 실행하세요"; exit 1; }
[ -d /run/systemd/system ] || { echo "!! systemd 로 부팅한 시스템이 아닙니다"; exit 1; }
VIRT=$(systemd-detect-virt --container 2>/dev/null) || true
if [ "${VIRT:-none}" != none ]; then echo "!! 컨테이너 안에서는 커널 모듈을 올릴 수 없습니다"; exit 1; fi
echo "  $K: CONFIG_LIVEPATCH=y"
echo "  Secure Boot: $(mokutil --sb-state 2>/dev/null || echo '확인 불가')"

echo "■ 1. kpatch 런타임"
APT=(-y -q -o DPkg::Lock::Timeout=300)
# 이전 apt 가 도중에 끊겨 dpkg 가 멈춰 있으면 어떤 설치도 실패하므로 먼저 복구
if [ -n "$(dpkg --audit 2>/dev/null)" ]; then
  echo "  dpkg 복구 (dpkg --configure -a)"
  dpkg --configure -a || { echo "!! dpkg 복구 실패. 'sudo dpkg --configure -a' 출력을 확인하세요"; exit 1; }
fi
# >>> apt-mirror (test/install_agent_mirror_test.py 가 이 구간만 꺼내 시험합니다)
APT_SRC=()      # 미러를 바꾸면 apt-get·apt-cache 에 함께 붙는 옵션
MIRRORS_LIST="$HERE/mirrors.list"
# apt-get update 는 색인을 못 받아도 경고만 내고 0 으로 끝나는 경우가 있어 출력도 봅니다
apt_update_ok() {
  local out rc=0
  out=$(apt-get update -q -o DPkg::Lock::Timeout=300 -o APT::Update::Error-Mode=any "$@" 2>&1) || rc=$?
  printf '%s\n' "$out" | grep -v '^\(Get\|Hit\|Ign\):' || true
  [ $rc = 0 ] && ! printf '%s' "$out" | grep -q 'Failed to fetch\|Some index files failed'
}
APT_UPDATED=""
# 먼저 호스트의 저장소 설정으로 받고, 안 되면 mirrors.list 의 미러를 위에서부터 시도합니다.
# 미러 색인은 별도 디렉터리에 받으므로 호스트의 sources.list 와 목록은 바꾸지 않습니다. 같은 Ubuntu 서명 키로 검증합니다.
apt_update() {
  [ -z "$APT_UPDATED" ] || return 0
  APT_UPDATED=1
  apt_update_ok && return 0
  [ -f "$MIRRORS_LIST" ] || { echo "  (apt-get update 실패, mirrors.list 없음: 기존 목록으로 계속)"; return 0; }
  local d=${KPCTL_APT_MIRROR_DIR:-/var/cache/kpctl-apt-mirror} code darch name arch url sec
  code=$(. /etc/os-release; echo "$VERSION_CODENAME"); darch=$(dpkg --print-architecture)
  while read -r name arch url sec; do
    case "$name" in ""|"#"*) continue ;; esac
    [ "$arch" = "$darch" ] || continue
    echo "  저장소 실패 → $name 미러($url)로 다시 시도"
    rm -rf "$d"; mkdir -p "$d/lists/partial" "$d/empty"
    printf 'deb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] %s %s main universe\n' \
      "$url" "$code" "$url" "$code-updates" "${sec:-$url}" "$code-security" > "$d/sources.list"
    local opts=(-o "Dir::Etc::sourcelist=$d/sources.list" -o "Dir::Etc::sourceparts=$d/empty" -o "Dir::State::lists=$d/lists")
    if apt_update_ok "${opts[@]}"; then
      APT_SRC=("${opts[@]}"); APT+=("${opts[@]}")
      return 0
    fi
  done < "$MIRRORS_LIST"
  echo "  (mirrors.list 의 미러도 모두 실패: 기존 목록으로 계속)"
}
# <<< apt-mirror
if ! command -v python3 >/dev/null; then  # 커널 준비 도우미(kpctl-prepare-kernel)에만 필요: 실패해도 패치 적용은 됨
  apt_update; apt-get install "${APT[@]}" python3 || echo "!! 경고: python3 설치 실패. 설치 후에야 다음 GA 커널 자동 준비가 동작합니다" >&2
fi
if ! command -v kpatch >/dev/null; then
  apt_update
  if apt-cache ${APT_SRC[@]+"${APT_SRC[@]}"} policy kpatch | grep -q 'Candidate: [^(]'; then
    apt-get install "${APT[@]}" kpatch
  elif [ -f "$HERE/kpatch" ] && [ -f "$HERE/kpatch.service" ]; then
    # 24.04 처럼 저장소에 패키지가 없는 시리즈: 묶음에 든 kpatch 사용 (readelf 가 필요해서 binutils 도 설치)
    echo "  저장소에 kpatch 패키지가 없어 설치 묶음의 kpatch 를 씁니다"
    command -v readelf >/dev/null || apt-get install "${APT[@]}" binutils
    install -m 0755 "$HERE/kpatch" /usr/local/sbin/kpatch
    install -m 0644 "$HERE/kpatch.service" /etc/systemd/system/kpatch.service
    systemctl daemon-reload
  else
    echo "!! 저장소에 kpatch 패키지가 없고 설치 묶음에도 kpatch 가 없습니다"; exit 1
  fi
fi
systemctl enable kpatch.service

echo "■ 2. Canonical Livepatch 끄기"
if command -v canonical-livepatch >/dev/null; then canonical-livepatch disable || true; fi

echo "■ 3. 커널 고정, 자동 재부팅 끄기"
apt-mark hold linux-image-generic linux-headers-generic "linux-image-$K" "linux-modules-$K" >/dev/null 2>&1 || true
mkdir -p /etc/apt/apt.conf.d
cat > /etc/apt/apt.conf.d/99kpctl-no-reboot <<'EOF'
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Automatic-Reboot-WithUsers "false";
APT::Periodic::Unattended-Upgrade "0";
EOF
if [ -d /etc/needrestart/conf.d ]; then
  printf '%s\n' '$nrconf{kernelhints} = 0;' '$nrconf{restart} = "l";' > /etc/needrestart/conf.d/99kpctl.conf
fi

echo "■ 4. 에이전트"
systemctl stop kpctl-agent 2>/dev/null || true          # 재설치: 실행 중인 에이전트 먼저 멈춤
install -m 0755 "$HERE/kpctl-agent" "/usr/local/bin/kpctl-agent.new.$$"
mv -f "/usr/local/bin/kpctl-agent.new.$$" /usr/local/bin/kpctl-agent   # 실행 중인 파일을 안전하게 교체
install -d -m 0755 /etc/kpctl
CA_LINE=""
if [ -n "$CA" ]; then install -m 0644 "$CA" /etc/kpctl/ca.crt; CA_LINE='"ca_file": "/etc/kpctl/ca.crt",'; fi
( umask 077
  cat > /etc/kpctl/agent.json <<EOF
{
  "controller_url": "$URL",
  "enroll_token": "$TOKEN",
  $CA_LINE
  $MOK_LINE
  "interval_seconds": 60,
  "reboot_hook": "/etc/kpctl/reboot-hook.sh"
}
EOF
)
[ -f /etc/kpctl/reboot-hook.sh ] || install -m 0700 "$HERE/reboot-hook.example.sh" /etc/kpctl/reboot-hook.sh
# 커널 준비 도우미가 읽는 미러 순서 (공식 → 한국 미러)
if [ -f "$HERE/mirrors.list" ]; then install -m 0644 "$HERE/mirrors.list" /etc/kpctl/mirrors.list; fi
if [ -f "$HERE/kpctl-prepare-kernel.py" ]; then
  install -m 0755 "$HERE/kpctl-prepare-kernel.py" /usr/local/sbin/kpctl-prepare-kernel
else
  echo "!! 경고: kpctl-prepare-kernel.py 가 묶음에 없어 자동 커널 준비(커널 점프 1단계)가 실패합니다" >&2
fi
install -m 0644 "$HERE/kpctl-agent.service" /etc/systemd/system/kpctl-agent.service
systemctl daemon-reload
/usr/local/bin/kpctl-agent -config /etc/kpctl/agent.json -once   # 등록 + 첫 보고
systemctl enable kpctl-agent
systemctl restart kpctl-agent

echo "완료. 컨트롤러에서 kpctl hosts 로 확인하세요."
echo "Secure Boot 사용 시: mokutil --import <서명 인증서.der> 후 재부팅 때 콘솔에서 승인 필요"
if [ -n "$MOK_LINE" ]; then
  echo "MOK 등록 예약을 컨트롤러에 요청했습니다. 비밀번호는 kpctl hosts mok-password <호스트>로 조회하세요."
  echo "서명 필요·active 인증서 미등록인 경우에만 예약하며 재부팅은 실행하지 않습니다."
fi
