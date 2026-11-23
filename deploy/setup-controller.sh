#!/bin/bash
# 컨트롤러 서버 구축 (Ubuntu, root 로 실행, make dist 결과의 dist/controller 디렉터리에서)
#
#   sudo ./setup-controller.sh -n kpatch.internal -i 10.0.0.5
#
#   -n 이름   호스트들이 컨트롤러에 접속할 DNS 이름 (TLS 인증서에 들어감, 필수)
#   -i IP     컨트롤러 IP (인증서에 추가 + SSH 키를 이 IP 에서만 쓰게 제한)
#   -u 사용자 호스트에 SSH 로 접속할 사용자 (기본 root)
#   -p 포트   컨트롤러 포트 (기본 8443)
#   -S        서비스를 시작하지 않음
#   -k 파일   미리 준비한 클라이언트(호스트) 개인키. 주면 새로 만들지 않고 이 키를 설치용 키로 쓰고,
#             이 키로 들어가지는 미등록 호스트에 질문 없이 에이전트를 자동 설치합니다 (kpctl-autoenroll.timer).
#             대상: 관리망 DHCP(-N) 임대 + /etc/kpctl/autoenroll-hosts 에 적은 호스트
#   -b 파일   빌드 서버 개인키 (여러 번 가능). /etc/kpctl/ssh/keys 에 빌드 서버 전용으로 저장
#             (install-builder 만 사용. 자동 설치·kpctl install 은 이 키로 들어가지 않음)
#   -y        묻지 않음 (-k 가 없으면 키를 새로 만듦)
#   (-k, -b, -y 를 안 주고 터미널에서 실행하면 미리 준비한 키가 있는지 물어봅니다)
#
# 관리망 DHCP + DNS (선택, dnsmasq):
#   -N NIC    관리망 NIC 이름 (이 NIC 에만 DHCP/DNS 를 냄. 이 NIC 에 -i 의 고정 IP 가 있어야 함)
#   -r 범위   동적 IP 범위 "시작,끝"  예: 10.0.0.100,10.0.0.250
#   -d 도메인 관리망 DNS 도메인 (기본: -n 에서 첫 칸을 뺀 것. 예: -n ctl.mgmt.internal → mgmt.internal)
#   -l 시간   동적 임대 시간 (기본 24h. 고정 예약한 호스트는 무기한)
#
#   예) sudo ./setup-controller.sh -n ctl.mgmt.internal -i 10.0.0.1 -u ops -N eno2 -r 10.0.0.100,10.0.0.250
#
# 한 번에 만드는 것 (이미 있으면 그대로 두므로 다시 실행해도 안전):
#   /etc/kpctl/ssh/id_ed25519     호스트 설치용 SSH 키 (kpctl install 이 기본으로 사용. -k 를 주면 그 키 사본)
#   /etc/kpctl/ssh/keys/          빌드 서버 등 추가 키 (-b)
#   /etc/kpctl/ssh/known_hosts    호스트 키 기록
#   /etc/kpctl/tokens/*.token     관리자·빌드 서버·등록(canary, server) 토큰
#   /etc/kpctl/tls/               사설 CA + 컨트롤러 서버 인증서
#   /etc/kpctl/controller.json    컨트롤러 설정
#   /etc/kpctl/kpctl.env          kpctl 기본값 (sudo kpctl ... 만으로 동작)
#   (-N 일 때) /etc/kpctl/dnsmasq.conf, /etc/kpctl/dhcp-hosts, kpctl-dnsmasq 서비스
set -euo pipefail

NAME="" IP="" SSH_USER="root" PORT=8443 START=1
NIC="" RANGE="" DOMAIN="" LEASE=24h
CLIENT_KEY="" BUILDER_KEYS=() ASK=1 USER_GIVEN=0
usage() { sed -n '2,28p' "$0" | sed 's/^# \{0,1\}//'; exit 1; }
while getopts "n:i:u:p:Sk:b:yN:r:d:l:h" o; do
  case "$o" in
    n) NAME="$OPTARG" ;; i) IP="$OPTARG" ;; u) SSH_USER="$OPTARG"; USER_GIVEN=1 ;;
    p) PORT="$OPTARG" ;; S) START=0 ;;
    k) CLIENT_KEY="$OPTARG"; ASK=0 ;; b) BUILDER_KEYS+=("$OPTARG"); ASK=0 ;; y) ASK=0 ;;
    N) NIC="$OPTARG" ;; r) RANGE="$OPTARG" ;; d) DOMAIN="$OPTARG" ;; l) LEASE="$OPTARG" ;;
    *) usage ;;
  esac
done
[ -n "$NAME" ] || usage
[ "$(id -u)" = 0 ] || { echo "root 로 실행하세요"; exit 1; }
valid_ip() {  # IPv4 (각 칸 0~255) 또는 IPv6 (':' 포함, 16진수)
  if [[ "$1" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]]; then
    for o in "${BASH_REMATCH[@]:1}"; do [ "$o" -le 255 ] || return 1; done
  else
    [[ "$1" == *:* && "$1" =~ ^[0-9A-Fa-f:.]+$ ]]
  fi
}
[ -z "$IP" ] || valid_ip "$IP" || { echo "-i $IP 는 IP 주소가 아닙니다"; exit 1; }

# 관리망 DHCP 옵션 검사 (뭔가 바꾸기 전에)
if [ -n "$NIC" ]; then
  [ -n "$IP" ] && [ -n "$RANGE" ] || { echo "-N 을 쓰려면 -i (컨트롤러 관리망 IP) 와 -r (범위) 가 필요합니다"; exit 1; }
  [[ "$RANGE" =~ ^[0-9.]+,[0-9.]+$ ]] || { echo "-r 형식: 시작IP,끝IP  예: 10.0.0.100,10.0.0.250"; exit 1; }
  DOMAIN="${DOMAIN:-${NAME#*.}}"
  case "$DOMAIN" in *.*) ;; *) echo "관리망 도메인 '$DOMAIN' 은 점이 하나 이상 있어야 합니다. 예: -n ctl.mgmt.internal 또는 -d mgmt.internal"; exit 1 ;; esac
  case "$NAME" in *."$DOMAIN") ;; *)
    echo "-n $NAME 은 관리망 도메인 $DOMAIN 안의 이름이어야 합니다 (호스트가 관리망 DNS 로 컨트롤러를 찾도록)"; exit 1 ;;
  esac
  command -v ip >/dev/null || { echo "ip 명령이 필요합니다 (apt install iproute2)"; exit 1; }
  ip link show "$NIC" >/dev/null 2>&1 || { echo "NIC $NIC 이 없습니다"; exit 1; }
  ip -4 -o addr show dev "$NIC" | grep -q " $IP/" \
    || { echo "NIC $NIC 에 $IP 가 없습니다. 관리망 NIC 에 고정 IP 를 먼저 설정하세요 (netplan)"; exit 1; }
fi
for c in openssl ssh-keygen; do command -v $c >/dev/null || { echo "$c 가 필요합니다 (apt install openssl openssh-client)"; exit 1; }; done

# ── 미리 준비한 SSH 키 ──
# check_key: 무인 설치에 쓸 수 있는 개인키인지 확인 (암호 없음). 공개키를 표준 출력으로 냄.
check_key() {
  [ -f "$1" ] || { echo "!! 파일이 없습니다: $1" >&2; return 1; }
  grep -q 'PRIVATE KEY-----' "$1" 2>/dev/null || { echo "!! 개인키가 아닙니다 (.pub 가 아니라 개인키를 주세요): $1" >&2; return 1; }
  ssh-keygen -y -P '' -f "$1" 2>/dev/null || { echo "!! 암호가 걸렸거나 읽을 수 없는 키입니다 (무인 설치에는 암호 없는 키가 필요): $1" >&2; return 1; }
}
BUILDER_USER="root"
# 설치용 키가 아직 없고 터미널에서 실행했으면 물어봄 (다시 실행할 때는 묻지 않음)
if [ "$ASK" = 1 ] && [ -t 0 ] && [ ! -s /etc/kpctl/ssh/id_ed25519 ]; then
  echo "■ 미리 준비한 SSH 키"
  echo "  호스트(클라이언트)에 이미 넣어 둔 관리자 키가 있으면 그 개인키를 설치용 키로 씁니다."
  while :; do
    read -r -p "  클라이언트 개인키 경로 (엔터 = 새로 생성): " CLIENT_KEY
    [ -z "$CLIENT_KEY" ] && break
    CLIENT_KEY="${CLIENT_KEY/#\~/$HOME}"
    check_key "$CLIENT_KEY" >/dev/null && break
  done
  if [ -n "$CLIENT_KEY" ] && [ "$USER_GIVEN" = 0 ]; then
    read -r -p "  이 키로 접속할 호스트 계정 [$SSH_USER]: " a; SSH_USER="${a:-$SSH_USER}"
  fi
  while :; do
    read -r -p "  빌드 서버 개인키 경로 (여러 개는 공백으로, 엔터 = 없음): " a
    [ -z "$a" ] && break
    ok=1
    for k in $a; do k="${k/#\~/$HOME}"; check_key "$k" >/dev/null || ok=0; done
    if [ "$ok" = 1 ]; then for k in $a; do BUILDER_KEYS+=("${k/#\~/$HOME}"); done; break; fi
  done
  if [ ${#BUILDER_KEYS[@]} -gt 0 ]; then
    read -r -p "  빌드 서버 접속 계정 [$BUILDER_USER]: " a; BUILDER_USER="${a:-$BUILDER_USER}"
  fi
fi
# 옵션으로 받은 키도 바뀌기 전에 미리 검사
[ -z "$CLIENT_KEY" ] || check_key "$CLIENT_KEY" >/dev/null || exit 1
for k in "${BUILDER_KEYS[@]}"; do check_key "$k" >/dev/null || exit 1; done

HERE=$(cd "$(dirname "$0")" && pwd)
ETC=/etc/kpctl
DATA=/var/lib/kpctl
URL="https://$NAME:$PORT"
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT

echo "■ 1. 사용자, 디렉터리"
id kpctl >/dev/null 2>&1 || useradd -r -s /usr/sbin/nologin -d "$DATA" kpctl
install -d -m 0755 "$ETC"
install -d -m 0700 "$ETC/tokens" "$ETC/ssh"
install -d -m 0750 -o root -g kpctl "$ETC/tls"
install -d -m 0750 -o kpctl -g kpctl "$DATA"

echo "■ 2. 토큰"
token() {   # 토큰 파일이 없으면 만들고, 내용을 출력
  local f="$ETC/tokens/$1.token"
  [ -s "$f" ] || (umask 077; openssl rand -hex 32 > "$f")
  cat "$f"
}
ADMIN=$(token admin)
BUILDER=$(token builder)
CANARY=$(token enroll-canary)
SERVER=$(token enroll-server)
echo "  $ETC/tokens/ (admin, builder, enroll-canary, enroll-server)"

echo "■ 3. TLS (사설 CA + 서버 인증서)"
if [ ! -s "$ETC/tls/ca.crt" ]; then
  cat > "$TMP/ca.cnf" <<EOF
[req]
distinguished_name = dn
prompt = no
[dn]
CN = kpctl CA ($NAME)
[v3_ca]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
EOF
  (umask 077; openssl req -x509 -config "$TMP/ca.cnf" -extensions v3_ca \
     -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 \
     -keyout "$ETC/tls/ca.key" -out "$ETC/tls/ca.crt" 2>/dev/null)
  echo "  CA 생성: $ETC/tls/ca.crt"
else
  echo "  CA 있음 (그대로 사용)"
fi
if [ ! -s "$ETC/tls/server.crt" ]; then
  SAN="DNS:$NAME"; [ -n "$IP" ] && SAN="$SAN,IP:$IP"
  printf 'subjectAltName=%s\nextendedKeyUsage=serverAuth\nkeyUsage=critical,digitalSignature\n' "$SAN" > "$TMP/ext"
  (umask 077; openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
     -subj "/CN=$NAME" -keyout "$ETC/tls/server.key" -out "$TMP/server.csr" 2>/dev/null)
  openssl x509 -req -in "$TMP/server.csr" -CA "$ETC/tls/ca.crt" -CAkey "$ETC/tls/ca.key" \
     -CAcreateserial -CAserial "$ETC/tls/ca.srl" -days 825 -extfile "$TMP/ext" -out "$ETC/tls/server.crt" 2>/dev/null
  echo "  서버 인증서 생성: $SAN"
else
  echo "  서버 인증서 있음 (그대로 사용)"
fi
chmod 0600 "$ETC/tls/ca.key"
chown root:kpctl "$ETC/tls/server.key"; chmod 0640 "$ETC/tls/server.key"
chmod 0644 "$ETC/tls/ca.crt" "$ETC/tls/server.crt"

echo "■ 4. SSH 키 (호스트 설치용)"
if [ -s "$ETC/ssh/id_ed25519" ]; then
  echo "  있음 (그대로 사용): $ETC/ssh/id_ed25519"
  [ -z "$CLIENT_KEY" ] || echo "  !! -k $CLIENT_KEY 는 무시했습니다. 바꾸려면 $ETC/ssh/id_ed25519* 를 지우고 다시 실행하세요"
elif [ -n "$CLIENT_KEY" ]; then
  # 파일 이름은 id_ed25519 로 고정 (kpctl.env 가 이 경로를 가리킴). RSA 등 다른 형식이어도 ssh 는 내용을 보고 씁니다.
  install -m 0600 "$CLIENT_KEY" "$ETC/ssh/id_ed25519"
  check_key "$ETC/ssh/id_ed25519" > "$ETC/ssh/id_ed25519.pub"
  echo "  미리 준비한 키 사용: $CLIENT_KEY → $ETC/ssh/id_ed25519 (접속 계정 $SSH_USER)"
else
  ssh-keygen -q -t ed25519 -N '' -C "kpctl@$NAME" -f "$ETC/ssh/id_ed25519"
  echo "  생성: $ETC/ssh/id_ed25519"
fi
touch "$ETC/ssh/known_hosts"
chmod 0600 "$ETC/ssh/id_ed25519" "$ETC/ssh/known_hosts"
# 빌드 서버 키: kpctl ssh-key add 와 같은 형식으로 저장 (<이름>, <이름>.pub, <이름>.user)
for k in "${BUILDER_KEYS[@]}"; do
  install -d -m 0700 "$ETC/ssh/keys"
  n=$(basename "$k"); n="${n%.pem}"
  dst="$ETC/ssh/keys/$n"
  if [ -e "$dst" ] && ! cmp -s "$k" "$dst"; then n="builder-$n"; dst="$ETC/ssh/keys/$n"; fi
  install -m 0600 "$k" "$dst"
  check_key "$dst" > "$dst.pub"; chmod 0644 "$dst.pub"
  echo "$BUILDER_USER" > "$dst.user"; chmod 0644 "$dst.user"
  echo builder > "$dst.role"; chmod 0644 "$dst.role"   # 빌드 서버 전용: 클라이언트 자동 설치에 쓰지 않음
  echo "  빌드 서버 키 저장: $k → $dst (접속 계정 $BUILDER_USER, 빌드 서버 전용)"
done

echo "■ 5. 설정 파일"
if [ ! -s "$ETC/controller.json" ]; then
  cat > "$ETC/controller.json" <<EOF
{
  "listen": ":$PORT",
  "tls_cert": "$ETC/tls/server.crt",
  "tls_key": "$ETC/tls/server.key",
  "data_dir": "$DATA",

  "admin_tokens": { "admin": "$ADMIN" },
  "builder_token": "$BUILDER",
  "enroll_tokens": [
    { "name": "canary", "token": "$CANARY", "ring": 1, "reboot_policy": "drain" },
    { "name": "server", "token": "$SERVER", "ring": 2, "reboot_policy": "drain" }
  ],

  "rings": [1, 2],
  "min_soak_minutes": { "2": 1440 },

  "sign_command": [],
  "scheduler": { "cordon_command": [], "uncordon_command": [], "vm_count_command": [] }
}
EOF
  echo "  생성: $ETC/controller.json"
else
  echo "  있음 (그대로 사용): $ETC/controller.json"
fi
chown root:kpctl "$ETC/controller.json"; chmod 0640 "$ETC/controller.json"

if [ ! -s "$ETC/kpctl.env" ]; then
  (umask 077; echo "# kpctl 기본값. kpctl 은 환경 변수가 비어 있으면 이 파일을 읽습니다 (그래서 sudo kpctl ... 만으로 동작)." > "$ETC/kpctl.env")
  echo "  생성: $ETC/kpctl.env"
fi
envset() {   # 키가 없을 때만 추가 (이미 있는 값은 그대로 둠)
  grep -q "^$1=" "$ETC/kpctl.env" || echo "$1=$2" >> "$ETC/kpctl.env"
}
envset KPCTL_URL "$URL"
envset KPCTL_TOKEN "$ADMIN"
envset KPCTL_CA "$ETC/tls/ca.crt"
envset KPCTL_SSH_KEY "$ETC/ssh/id_ed25519"
envset KPCTL_SSH_KNOWN_HOSTS "$ETC/ssh/known_hosts"
envset KPCTL_SSH_USER "$SSH_USER"
envset KPCTL_SSH_FROM "$IP"
envset KPCTL_TOKEN_DIR "$ETC/tokens"
if [ -n "$NIC" ]; then
  envset KPCTL_DHCP_LEASES "$DATA/dnsmasq.leases"
  envset KPCTL_DHCP_HOSTS "$ETC/dhcp-hosts"
  envset KPCTL_DNSMASQ_PID /run/kpctl-dnsmasq.pid
fi

if [ -n "$NIC" ]; then
  echo "■ 5-1. 관리망 DHCP + DNS ($NIC, 도메인 $DOMAIN)"
  command -v dnsmasq >/dev/null || DEBIAN_FRONTEND=noninteractive apt-get install -y -q dnsmasq-base
  # dnsmasq 는 시작 후 이 사용자로 권한을 낮춤 (dnsmasq-base 패키지가 보통 만들어 둠)
  id dnsmasq >/dev/null 2>&1 || useradd -r -s /usr/sbin/nologin -d /nonexistent -g nogroup dnsmasq
  [ -f "$ETC/dhcp-hosts" ] || printf '# kpctl 관리망 고정 IP 예약 (dnsmasq dhcp-hostsfile)\n# 형식: MAC,IP,이름,infinite   — kpctl dhcp reserve / unreserve 로 관리합니다.\n' > "$ETC/dhcp-hosts"
  chmod 0644 "$ETC/dhcp-hosts"
  if [ ! -s "$ETC/dnsmasq.conf" ]; then
    cat > "$ETC/dnsmasq.conf" <<EOF
# kpctl 관리망 DHCP + DNS — setup-controller.sh 가 생성
# 고친 뒤: systemctl restart kpctl-dnsmasq   (고정 예약은 kpctl dhcp reserve 로)

# 관리망 NIC 에서만 동작 (서비스망·VM 망에는 절대 DHCP 를 내지 않음)
interface=$NIC
except-interface=lo
bind-interfaces
user=dnsmasq

# DNS: 관리망 도메인($DOMAIN)만 답하고, 다른 이름은 밖으로 넘기지 않음
no-resolv
no-hosts
domain=$DOMAIN
local=/$DOMAIN/
host-record=$NAME,$IP

# DHCP
dhcp-authoritative
# 같은 VM 이 부팅마다 다른 클라이언트 ID(DUID)를 보내도 MAC 으로만 구분해 같은 주소를 줌
dhcp-ignore-clid
dhcp-range=$RANGE,$LEASE
# 기본 경로(router)를 주지 않음 — 관리망 DHCP 가 호스트의 서비스망 경로를 바꾸지 않도록
dhcp-option=option:router
dhcp-hostsfile=$ETC/dhcp-hosts
dhcp-leasefile=$DATA/dnsmasq.leases
pid-file=/run/kpctl-dnsmasq.pid
log-dhcp
EOF
    echo "  생성: $ETC/dnsmasq.conf"
  else
    echo "  있음 (그대로 사용. 컨트롤러 이름 줄만 아래에서 맞춤. 다른 값은 직접 고친 뒤 systemctl restart kpctl-dnsmasq): $ETC/dnsmasq.conf"
  fi
  dnsmasq --test --conf-file="$ETC/dnsmasq.conf" >/dev/null 2>&1 \
    || { dnsmasq --test --conf-file="$ETC/dnsmasq.conf"; echo "!! dnsmasq 설정 오류"; exit 1; }
  if [ -f "$HERE/kpctl-dnsmasq.service" ]; then
    install -m 0644 "$HERE/kpctl-dnsmasq.service" /etc/systemd/system/
  fi
fi

# 관리망 DNS 에 컨트롤러 이름 맞추기
# dnsmasq.conf 는 직접 고친 내용을 지키려고 덮어쓰지 않습니다. 그런데 -n 을 바꿔 다시 설치하면
# host-record 가 옛 이름에 남아 호스트가 새 이름을 DNS 로 찾지 못하므로, 이 줄만 고칩니다.
# -N 없이 다시 실행해도 적용합니다 (dnsmasq.conf 가 있으면 관리망 DNS 를 쓰는 중이므로).
# 옛 이름의 host-record 는 그 이름을 쓰는 빌드 서버가 있을 수 있어 지우지 않습니다.
DNSMASQ_CHANGED=0
if [ -n "$IP" ] && [ -s "$ETC/dnsmasq.conf" ] && ! grep -qxF "host-record=$NAME,$IP" "$ETC/dnsmasq.conf"; then
  CONF_BAK="$ETC/dnsmasq.conf.bak-$(date +%Y%m%d%H%M%S)"
  cp -p "$ETC/dnsmasq.conf" "$CONF_BAK"
  # 같은 이름의 host-record 가 있으면 그 줄을 바꾸고(여러 줄이면 하나로), 없으면 마지막 host-record 뒤(없으면 끝)에 넣음
  awk -v key="host-record=$NAME" -v want="host-record=$NAME,$IP" '
    { line[NR] = $0; split($0, f, ","); if (f[1] == key) { hit[NR] = 1; nhit++ } if ($0 ~ /^host-record=/) last = NR }
    END {
      found = nhit > 0; done = 0
      for (i = 1; i <= NR; i++) {
        if (hit[i]) { if (!done) print want; done = 1; continue }
        print line[i]
        if (!found && i == last) { print want; done = 1 }
      }
      if (!done) print want
    }' "$CONF_BAK" > "$ETC/dnsmasq.conf.new"
  cat "$ETC/dnsmasq.conf.new" > "$ETC/dnsmasq.conf" && rm -f "$ETC/dnsmasq.conf.new"   # 덮어쓰기: 권한·소유자 유지
  if command -v dnsmasq >/dev/null && ! dnsmasq --test --conf-file="$ETC/dnsmasq.conf" >/dev/null 2>&1; then
    dnsmasq --test --conf-file="$ETC/dnsmasq.conf"
    cat "$CONF_BAK" > "$ETC/dnsmasq.conf"
    echo "!! 관리망 DNS 에 $NAME 을 넣으니 dnsmasq 설정 오류가 나서 되돌렸습니다 ($CONF_BAK)"; exit 1
  fi
  DNSMASQ_CHANGED=1
  echo "  관리망 DNS: host-record=$NAME,$IP 로 맞춤 (이전 파일: $CONF_BAK)"
fi

# 컨트롤러 자신은 관리망 dnsmasq 에 묻지 않으므로 이름을 /etc/hosts 에 고정합니다. cloud-init(manage_etc_hosts)이
# 부팅마다 /etc/hosts 를 다시 쓰는 VM 에서는 그 템플릿에도 넣어야 재부팅 뒤 kpctl·autoenroll 이 이름을 찾습니다.
# (internal/remote 의 PinHostsFunc 와 같은 동작)
if [ -n "$IP" ]; then
  for f in /etc/hosts /etc/cloud/templates/hosts.*.tmpl; do
    [ -f "$f" ] || continue
    grep -v "[[:space:]]$NAME[[:space:]]*# kpctl\$" "$f" > "$f.kpctl-new" || true
    echo "$IP $NAME # kpctl" >> "$f.kpctl-new"
    cat "$f.kpctl-new" > "$f"; rm -f "$f.kpctl-new"
  done
  echo "  /etc/hosts 에 $NAME → $IP 고정 (컨트롤러 자신이 이 이름을 찾도록)"
fi

echo "■ 6. 프로그램 설치"
if [ -x "$HERE/kpctl-controller" ]; then
  install -m 0755 "$HERE/kpctl-controller" "$HERE/kpctl" /usr/local/bin/
  if [ -d "$HERE/agent" ]; then
    install -d /usr/local/share/kpctl
    rm -rf /usr/local/share/kpctl/agent && cp -r "$HERE/agent" /usr/local/share/kpctl/agent
  fi
  # 빌드 서버 묶음: kpctl install-builder 가 SSH 로 보내고, kpctl-builder 는 빌드 서버 자동 업데이트에도 씁니다
  if [ -x "$HERE/builder/kpctl-builder" ]; then
    install -d /usr/local/share/kpctl
    rm -rf /usr/local/share/kpctl/builder && cp -r "$HERE/builder" /usr/local/share/kpctl/builder
  fi
  install -m 0644 "$HERE/kpctl-controller.service" /etc/systemd/system/
  if [ -f "$HERE/kpctl-cve-inventory.py" ]; then
    install -d -m 0755 /usr/local/libexec
    install -d -o kpctl -g kpctl -m 0750 "$DATA/coverage"
    install -m 0755 "$HERE/kpctl-cve-inventory.py" /usr/local/libexec/kpctl-cve-inventory
    install -m 0644 "$HERE/kpctl-cve-inventory.service" "$HERE/kpctl-cve-inventory.timer" /etc/systemd/system/
  fi
  # DHCP 자동 등록: 컨트롤러 SSH 키를 등록한 호스트에만 설치하므로, 관리망 DHCP(-N)를 쓸 때 기본으로 켭니다.
  if [ -f "$HERE/kpctl-autoenroll.timer" ]; then
    install -m 0644 "$HERE/kpctl-autoenroll.service" "$HERE/kpctl-autoenroll.timer" /etc/systemd/system/
    [ -e "$ETC/autoenroll-ignore" ] || printf '# kpctl autoenroll 제외 목록 (IP, MAC, 이름). 일부러 에이전트를 지운 호스트는 여기에 적으세요.\n' > "$ETC/autoenroll-ignore"
    [ -e "$ETC/autoenroll-hosts" ] || printf '%s\n' '# kpctl autoenroll 대상 (DHCP 를 안 쓸 때). 한 줄에 IP 또는 이름 하나.' \
      '# 클라이언트 키로 들어가지는 미등록 호스트에 1분 안에 질문 없이 설치합니다.' > "$ETC/autoenroll-hosts"
  fi
  echo "  /usr/local/bin/kpctl-controller, kpctl, /usr/local/share/kpctl/{agent,builder}"
else
  echo "  이 디렉터리에 kpctl-controller 가 없어 건너뜀 (make dist 의 dist/controller 에서 실행하세요)"
fi
if [ $START = 1 ] && [ -x /usr/local/bin/kpctl-controller ]; then
  systemctl daemon-reload
  systemctl enable kpctl-controller
  systemctl restart kpctl-controller
  if [ -f /etc/systemd/system/kpctl-cve-inventory.timer ]; then
    systemctl enable --now kpctl-cve-inventory.timer
    systemctl start --no-block kpctl-cve-inventory.service
  fi
  echo "  kpctl-controller 시작"
  if [ -n "$NIC" ] && [ -f /etc/systemd/system/kpctl-dnsmasq.service ]; then
    systemctl enable kpctl-dnsmasq
    systemctl restart kpctl-dnsmasq
    echo "  kpctl-dnsmasq 시작 ($NIC 에서 DHCP/DNS)"
  fi
  # 자동 설치: 관리망 DHCP(-N)를 쓰거나 미리 준비한 클라이언트 키(-k)를 줬으면 켬 (질문 없이 키로 들어가지는 호스트에 설치)
  if { [ -n "$NIC" ] || [ -n "$CLIENT_KEY" ]; } && [ -f /etc/systemd/system/kpctl-autoenroll.timer ]; then
    systemctl enable --now kpctl-autoenroll.timer
    echo "  kpctl-autoenroll.timer 시작 (클라이언트 키로 들어가지는 새 호스트에 1분 안에 자동 설치. 끄기: systemctl disable --now kpctl-autoenroll.timer)"
  fi
fi

# -N 으로 실행했으면 위에서 이미 재시작함. -N 없이 다시 실행해 이름만 바뀐 경우 돌고 있는 dnsmasq 에 반영
if [ $DNSMASQ_CHANGED = 1 ] && [ -z "$NIC" ]; then
  if systemctl is-active --quiet kpctl-dnsmasq 2>/dev/null; then
    systemctl restart kpctl-dnsmasq
    echo "  kpctl-dnsmasq 재시작 (관리망 DNS 에 $NAME 반영)"
  else
    echo "  kpctl-dnsmasq 가 꺼져 있어 다음에 시작할 때 $NAME 이 반영됩니다"
  fi
fi

PUB=$(cat "$ETC/ssh/id_ed25519.pub")
FROM=""; [ -n "$IP" ] && FROM="from=\"$IP\","
cat <<EOF

완료.
  컨트롤러 주소    $URL   (호스트·빌드 서버에서 $NAME 이 이 서버로 풀려야 합니다)
  관리자 웹        $URL/   (로그인 토큰: $ETC/tokens/admin.token)
  CA 인증서        $ETC/tls/ca.crt   (kpctl install-builder 가 빌드 서버에 복사)
  빌드 서버 토큰    $ETC/tokens/builder.token
  SSH 공개키       ${FROM}restrict $PUB

EOF
if [ -n "$NIC" ]; then cat <<EOF
  관리망 DHCP       $NIC, 범위 $RANGE, 도메인 $DOMAIN (호스트는 <이름>.$DOMAIN 으로 등록됨)
  방화벽            $NIC 에서 UDP 67(DHCP), UDP/TCP 53(DNS), TCP $PORT 를 허용하세요
  호스트 NIC 설정    host-mgmt-netplan.example.yaml 참고 (기본 경로·일반 DNS 를 바꾸지 않게)

EOF
fi
cat <<EOF
다음 단계:
  0) (DHCP 사용 시) 호스트가 IP 를 받으면 고정:  sudo kpctl dhcp leases → sudo kpctl dhcp reserve -all
  1) 호스트에 SSH 공개키 등록 (지금 쓰는 계정/비밀번호로 한 번만. 미리 준비한 키를 썼다면 이미 들어 있는 호스트는 생략)
       sudo kpctl ssh-key copy server-01 server-02 ...
       sudo kpctl ssh-key copy root server-01 server-02 ...   (첫 인자로 계정 지정)
     또는 cloud-init / 기존 자동화로 위 "SSH 공개키" 줄을 ~$SSH_USER/.ssh/authorized_keys 에 추가
  자동 설치: 클라이언트 키(-k)를 줬거나 관리망 DHCP(-N)를 쓰면, 클라이언트 키로 들어가지는 미등록 호스트에
     1분 안에 질문 없이 설치됩니다. DHCP 를 안 쓰면 대상 호스트를 $ETC/autoenroll-hosts 에 한 줄씩 적으세요.
       sudo kpctl autoenroll -dry-run      (대상·키 확인만)
  2) 수동 점검 → 설치 (헷갈리면 인자 없이 sudo kpctl install → 질문형)
       sudo kpctl install -check -hosts-file hosts.txt
       sudo kpctl install -group canary server-01
       sudo kpctl install -group server -hosts-file hosts.txt
     (DHCP 사용 시 -hosts-file 대신 -from-dhcp: 관리망에서 IP 를 받았지만 아직 등록 안 된 호스트 전부)
  3) 빌드 서버 설치 (대상 LTS 와 같은 Ubuntu 서버)
       sudo kpctl install-builder                         (질문형: 하나씩 묻고 점검 후 설치)
       sudo kpctl install-builder -check build-noble
       sudo kpctl install-builder build-noble            (커널 생략 시 등록 호스트 기준 자동 선택)
EOF
