#!/bin/bash
# 관리망 DHCP + DNS 통합 테스트 — 실제 dnsmasq, 실제 DHCP 클라이언트(busybox udhcpc), 실제 sshd
#
#   sudo ./test/dhcp.sh
#
# 구성: 브리지 kpbr0(10.77.0.1, 컨트롤러 관리망 NIC 역할) 에 네트워크 네임스페이스 2개(gpu-01, gpu-02)를
#       veth 로 붙여 GPU 호스트 2대처럼 씁니다. 각 호스트는 자기 이름·sshd·에이전트 상태 디렉터리를 따로 가집니다.
# 확인: setup-controller.sh -N → DHCP 임대(기본 경로 없음) → DNS → 고정 예약 → ssh-key copy/install -from-dhcp
# 주의: /etc/kpctl, /etc/hosts 등을 만들었다가 지웁니다. 테스트용 VM/컨테이너에서만 실행하세요.
set -euo pipefail

[ "$(id -u)" = 0 ] || { echo "root 로 실행하세요"; exit 1; }
[ ! -e /etc/kpctl ] || { echo "/etc/kpctl 가 이미 있어 중단합니다 (운영 컨트롤러일 수 있음)"; exit 1; }
for c in ip dnsmasq busybox dig curl openssl unshare; do command -v $c >/dev/null || { echo "$c 가 필요합니다"; exit 1; }; done

ROOT=$(cd "$(dirname "$0")/.." && pwd)
W=$(mktemp -d); chmod 755 "$W"
PORT=18446 NET=10.77.0 BR=kpbr0 DOM=mgmt.test CTL=ctl.mgmt.test
KCFG="/boot/config-$(uname -r)"
STUBS=(apt-get apt-mark systemctl kpatch)
CREATED_KCFG=0 CREATED_AGENTDIR=0 CTRL_PID="" DNSMASQ_PID=""

cleanup() {
  set +e
  for n in 1 2; do [ -f "$W/sshd-gpu$n.pid" ] && kill "$(cat "$W/sshd-gpu$n.pid")"; ip netns del kp-gpu$n 2>/dev/null; rm -rf /etc/netns/kp-gpu$n; done
  [ -n "$CTRL_PID" ] && kill "$CTRL_PID"
  [ -n "$DNSMASQ_PID" ] && kill "$DNSMASQ_PID"
  ip link del $BR 2>/dev/null
  for s in "${STUBS[@]}"; do grep -qs KPCTL-TEST-STUB "/usr/local/sbin/$s" && rm -f "/usr/local/sbin/$s"; done
  [ $CREATED_KCFG = 1 ] && rm -f "$KCFG"
  [ $CREATED_AGENTDIR = 1 ] && rm -rf /var/lib/kpctl-agent
  sed -i '/# kpctl$/d' /etc/hosts
  rm -f /etc/sudoers.d/kpctl-test
  userdel -r kpdeploy >/dev/null 2>&1; userdel kpctl >/dev/null 2>&1
  rm -rf /etc/kpctl /var/lib/kpctl /usr/local/share/kpctl /run/kpctl-dnsmasq.pid \
         /usr/local/bin/kpctl-controller /usr/local/bin/kpctl /usr/local/bin/kpctl-agent \
         /etc/systemd/system/kpctl-controller.service /etc/systemd/system/kpctl-dnsmasq.service \
         /etc/systemd/system/kpctl-agent.service /etc/apt/apt.conf.d/99kpctl-no-reboot
  if [ "${KEEP:-}" = "1" ]; then echo "작업 디렉터리 유지: $W"; else rm -rf "$W"; fi
}
trap cleanup EXIT

pass() { echo "  ✔ $*"; }
die()  { echo "  ✘ $*"; echo "--- 마지막 출력 ---"; tail -25 "$W/out" 2>/dev/null; exit 1; }
check() { local msg="$1"; shift; if "$@"; then pass "$msg"; else die "$msg"; fi; }
unset KPCTL_URL KPCTL_TOKEN KPCTL_CA KPCTL_BUNDLE KPCTL_SSH_KEY KPCTL_SSH_USER

echo "■ 준비"
D="$W/dist/controller"; mkdir -p "$D/agent" "$W/bin"
(cd "$ROOT" && CGO_ENABLED=0 go build -o "$W/bin" ./cmd/...)
# 관리망은 내부망: 이 셸에 외부용 프록시가 있어도 curl 이 프록시로 보내지 않도록
# (kpctl 자체는 프록시 설정을 무시하므로 이것은 curl 용입니다)
unset HTTPS_PROXY HTTP_PROXY https_proxy http_proxy ALL_PROXY all_proxy
cp "$W/bin/kpctl-agent" "$ROOT"/deploy/install-agent.sh "$ROOT"/deploy/uninstall-agent.sh \
   "$ROOT"/deploy/systemd/kpctl-agent.service "$ROOT"/configs/reboot-hook.example.sh "$ROOT"/deploy/kpctl-prepare-kernel.py "$ROOT"/deploy/mirrors.list "$D/agent/"
cp "$W/bin/kpctl-controller" "$W/bin/kpctl" "$ROOT"/deploy/setup-controller.sh \
   "$ROOT"/deploy/systemd/kpctl-controller.service "$ROOT"/deploy/systemd/kpctl-dnsmasq.service "$D/"
for s in "${STUBS[@]}"; do
  [ -e "/usr/local/sbin/$s" ] && ! grep -qs KPCTL-TEST-STUB "/usr/local/sbin/$s" && { echo "/usr/local/sbin/$s 가 이미 있어 중단"; exit 1; }
  printf '#!/bin/sh\n# KPCTL-TEST-STUB\necho "%s $*" >> %s/calls.log\n' "$s" "$W" > "/usr/local/sbin/$s"
  chmod +x "/usr/local/sbin/$s"
done
if [ ! -e "$KCFG" ]; then echo CONFIG_LIVEPATCH=y > "$KCFG"; CREATED_KCFG=1; fi
[ -e /var/lib/kpctl-agent ] || { mkdir -p /var/lib/kpctl-agent; CREATED_AGENTDIR=1; }   # 호스트별 bind mount 자리

ip link add $BR type bridge && ip addr add $NET.1/24 dev $BR && ip link set $BR up
pass "관리망 브리지 $BR ($NET.1/24)"

echo "■ 1. setup-controller.sh 의 DHCP 옵션 검사 (아무것도 만들지 않아야 함)"
S=(bash "$D/setup-controller.sh" -i $NET.1 -u kpdeploy -p $PORT -S)
if "${S[@]}" -n $CTL -N $BR >"$W/out" 2>&1; then die "-r 없이 통과"; fi
check "-r 없으면 거부" grep -q '\-r (범위) 가 필요' "$W/out"
if "${S[@]}" -n kpatch.internal -N $BR -r $NET.100,$NET.150 >"$W/out" 2>&1; then die "점 없는 도메인 통과"; fi
check "도메인에 점이 없으면 거부 (-n kpatch.internal → internal)" grep -q "점이 하나 이상" "$W/out"
if "${S[@]}" -n ctl.other.test -d $DOM -N $BR -r $NET.100,$NET.150 >"$W/out" 2>&1; then die "도메인 밖 이름 통과"; fi
check "-n 이 관리망 도메인 밖이면 거부" grep -q "도메인 $DOM 안의 이름" "$W/out"
if bash "$D/setup-controller.sh" -n $CTL -i 10.99.0.1 -N $BR -r $NET.100,$NET.150 -S >"$W/out" 2>&1; then die "NIC 에 없는 IP 통과"; fi
check "NIC 에 -i 고정 IP 가 없으면 거부" grep -q "NIC $BR 에 10.99.0.1 가 없습니다" "$W/out"
check "검사 실패 시 /etc/kpctl 안 만듦" test ! -e /etc/kpctl

echo "■ 2. setup-controller.sh -N"
"${S[@]}" -n $CTL -N $BR -r $NET.100,$NET.150 -l 2h >"$W/out" 2>&1 || die "setup 실패"
check "dnsmasq.conf: 관리망 NIC 만" grep -qx "interface=$BR" /etc/kpctl/dnsmasq.conf
check "dnsmasq.conf: 기본 경로 안 줌" grep -qx "dhcp-option=option:router" /etc/kpctl/dnsmasq.conf
check "kpctl.env 에 DHCP 경로" grep -q '^KPCTL_DHCP_LEASES=/var/lib/kpctl/dnsmasq.leases' /etc/kpctl/kpctl.env
check "/etc/hosts 에 $CTL" grep -q "^$NET.1 $CTL  # kpctl" /etc/hosts
check "설치 안내에 방화벽 포트" grep -q 'UDP 67(DHCP)' "$W/out"
echo "# 손으로 쓴 주석" >> /etc/kpctl/dhcp-hosts
"${S[@]}" -n $CTL -N $BR -r $NET.100,$NET.150 -l 2h >"$W/out" 2>&1 || die "재실행 실패"
check "다시 실행해도 예약 파일·hosts 줄 유지" bash -c "grep -q '손으로 쓴 주석' /etc/kpctl/dhcp-hosts && [ \$(grep -c '# kpctl\$' /etc/hosts) = 1 ]"

# systemd 대신 서비스 유닛과 같은 명령으로 직접 실행
/usr/sbin/dnsmasq --keep-in-foreground --log-facility=- --conf-file=/etc/kpctl/dnsmasq.conf >"$W/dnsmasq.log" 2>&1 &
DNSMASQ_PID=$!
runuser -u kpctl -- /usr/local/bin/kpctl-controller -config /etc/kpctl/controller.json >"$W/controller.log" 2>&1 &
CTRL_PID=$!
for _ in $(seq 50); do curl -sf --cacert /etc/kpctl/tls/ca.crt "https://$CTL:$PORT/healthz" >/dev/null && break; sleep 0.1; done
check "컨트롤러가 이름($CTL)으로 HTTPS 응답" curl -sf --cacert /etc/kpctl/tls/ca.crt "https://$CTL:$PORT/healthz" -o /dev/null
check "dnsmasq 실행 중 (dnsmasq 사용자로 권한 낮춤)" bash -c "sleep 0.5; [ \"\$(ps -o user= -p $DNSMASQ_PID)\" = dnsmasq ]"

echo "■ 3. GPU 호스트 2대가 DHCP 받기"
cat > "$W/udhcpc.sh" <<'EOF'
#!/bin/sh
# busybox udhcpc 스크립트: 받은 값을 기록하고 IP 를 적용
case "$1" in
  deconfig) ip addr flush dev "$interface" ;;
  bound|renew)
    ip addr flush dev "$interface"
    ip addr add "$ip/$mask" dev "$interface"
    { echo "ip=$ip"; echo "router=$router"; echo "dns=$dns"; echo "domain=$domain"; } > "$OUT"
    ;;
esac
EOF
chmod +x "$W/udhcpc.sh"
dhcp_get() {   # dhcp_get <번호> <이름>
  OUT="$W/lease-$2.env" ip netns exec kp-gpu$1 busybox udhcpc -i eth0 -x hostname:$2 -n -q -t 5 -T 1 -s "$W/udhcpc.sh" >>"$W/udhcpc.log" 2>&1
}
for n in 1 2; do
  ip netns add kp-gpu$n
  ip link add kpv$n type veth peer name eth0 netns kp-gpu$n
  ip link set kpv$n master $BR up
  ip netns exec kp-gpu$n ip link set lo up
  ip netns exec kp-gpu$n ip link set eth0 up
  dhcp_get $n gpu-0$n || die "gpu-0$n DHCP 실패"
done
. "$W/lease-gpu-01.env"
check "gpu-01 이 동적 범위에서 IP 받음 ($ip)" bash -c "[[ $ip == $NET.1[0-5][0-9] ]]"
check "기본 경로(router) 를 받지 않음" test -z "$router"
check "DNS 서버 = 컨트롤러, 도메인 = $DOM" test "$dns" = "$NET.1" -a "$domain" = "$DOM"
check "netns 에 기본 경로 없음" test -z "$(ip netns exec kp-gpu1 ip route show default)"
IP1=$ip; IP2=$(. "$W/lease-gpu-02.env"; echo $ip)

echo "■ 4. 관리망 DNS"
check "gpu-01.$DOM → $IP1"  test "$(dig +short @$NET.1 gpu-01.$DOM)" = "$IP1"
check "$CTL → $NET.1"      test "$(dig +short @$NET.1 $CTL)" = "$NET.1"
check "관리망 밖 이름은 답하지 않음 (밖으로 넘기지 않음)" test -z "$(dig +short +time=1 +tries=1 @$NET.1 example.com)"

echo "■ 5. kpctl dhcp"
kpctl dhcp leases >"$W/out" 2>&1 || die "leases 실패"
check "임대 2건, 아직 예약·등록 없음" bash -c "grep -q '^$IP1 .*gpu-01 .*남은' '$W/out' && grep -q '^$IP2 .*gpu-02' '$W/out'"
kpctl dhcp reserve gpu-01 >"$W/out" 2>&1 || die "reserve 실패"
check "예약 저장 + dnsmasq 반영" bash -c "grep -q \",$IP1,gpu-01,infinite\" /etc/kpctl/dhcp-hosts && grep -q 'dnsmasq 에 반영' '$W/out'"
dhcp_get 1 gpu-01
check "다시 받으면 같은 IP, 무기한 임대" bash -c ". '$W/lease-gpu-01.env'; [ \"\$ip\" = $IP1 ] && kpctl dhcp leases | grep -q '^$IP1 .*고정(무기한) *예'"
kpctl dhcp reserve -ip $NET.20 gpu-02 >"$W/out" 2>&1 || die "reserve -ip 실패"
dhcp_get 2 gpu-02
check "-ip 로 정한 IP($NET.20) 를 다음 임대부터 받음" bash -c ". '$W/lease-gpu-02.env'; [ \"\$ip\" = $NET.20 ]"
IP2=$NET.20
if kpctl dhcp reserve -ip $NET.20 -name other gpu-01 >"$W/out" 2>&1; then die "중복 예약 통과"; fi
check "이미 예약된 MAC/IP 중복 거부" grep -q '이미' "$W/out"
kpctl dhcp unreserve gpu-02 >/dev/null && kpctl dhcp reserve -all >"$W/out" 2>&1 || die "unreserve/-all 실패"
check "unreserve 후 reserve -all 이 지금 IP 로 다시 고정" grep -q "고정: .* → $NET.20 gpu-02" "$W/out"
check "손으로 쓴 주석은 그대로" grep -q '손으로 쓴 주석' /etc/kpctl/dhcp-hosts

echo "■ 6. 호스트별 sshd (자기 이름, 자기 /etc/kpctl·에이전트 상태)"
useradd -m -s /bin/bash kpdeploy; usermod -p '*' kpdeploy
echo 'kpdeploy ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/kpctl-test; chmod 440 /etc/sudoers.d/kpctl-test
ssh-keygen -q -t ed25519 -N '' -f "$W/admin_id"; ssh-keygen -q -t ed25519 -N '' -f "$W/hostkey"
mkdir -p "$W/keys" /run/sshd; cp "$W/admin_id.pub" "$W/keys/kpdeploy"; chmod 644 "$W/keys/kpdeploy"
cat > "$W/sshd_config" <<EOF
HostKey $W/hostkey
AuthorizedKeysFile .ssh/authorized_keys $W/keys/%u
PasswordAuthentication no
StrictModes no
UsePAM no
Subsystem sftp /usr/lib/openssh/sftp-server
EOF
for n in 1 2; do
  mkdir -p /etc/netns/kp-gpu$n "$W/gpu$n/etc" "$W/gpu$n/state"
  printf 'nameserver %s\nsearch %s\n' $NET.1 $DOM > /etc/netns/kp-gpu$n/resolv.conf   # 호스트가 관리망 DNS 를 씀
  ip netns exec kp-gpu$n unshare --uts --mount sh -c "
    hostname gpu-0$n
    mount --bind $W/gpu$n/etc /etc/kpctl
    mount --bind $W/gpu$n/state /var/lib/kpctl-agent
    exec /usr/sbin/sshd -f $W/sshd_config -o PidFile=$W/sshd-gpu$n.pid -E $W/sshd-gpu$n.log"
done
sleep 0.5
pass "sshd 2대 ($IP1, $IP2)"

echo "■ 7. -from-dhcp 로 키 등록 → 점검 → 설치"
kpctl ssh-key copy -from-dhcp -accept-new-hostkey -login-key "$W/admin_id" >"$W/out" 2>&1 || die "ssh-key copy -from-dhcp 실패"
check "DHCP 대상 2대 키 등록·로그인 확인" bash -c "grep -q '대상 2대' '$W/out' && [ \$(grep -c '컨트롤러 키로 로그인 확인' '$W/out') = 2 ]"
kpctl install -check -from-dhcp >"$W/out" 2>&1 || die "점검 실패"
check "2대 점검 통과 (호스트가 $CTL 을 관리망 DNS 로 찾아 접속)" grep -q '2대 모두 성공' "$W/out"
kpctl install -group server -from-dhcp -parallel 2 -log-dir "$W/logs" >"$W/out" 2>&1 || die "설치 실패"
check "2대 동시 설치 완료" bash -c "[ \$(grep -c '설치 완료' '$W/out') = 2 ]"
check "컨트롤러에 gpu-01, gpu-02 등록 (링 2)" bash -c "kpctl hosts | grep -q '^gpu-01 .* 2 ' && kpctl hosts | grep -q '^gpu-02 .* 2 '"
check "에이전트가 이름으로 컨트롤러 접속" grep -q "\"controller_url\": \"https://$CTL:$PORT\"" "$W/gpu1/etc/agent.json"
check "dhcp leases 에 등록 상태 표시" bash -c "kpctl dhcp leases | grep '^$IP1' | grep -q '등록 (링 2'"
kpctl install -check -from-dhcp >"$W/out" 2>&1 || die "재점검 오류"
check "모두 등록되면 -from-dhcp 대상 없음" grep -q '새로 설치할 호스트가 없습니다' "$W/out"
if kpctl uninstall -from-dhcp >"$W/out" 2>&1; then die "uninstall -from-dhcp 통과"; fi
check "uninstall 에는 -from-dhcp 금지" grep -q '쓸 수 없습니다' "$W/out"

echo
echo "모든 DHCP 테스트 통과"
