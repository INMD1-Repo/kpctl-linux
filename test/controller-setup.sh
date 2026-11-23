#!/bin/bash
# 컨트롤러 구축 → SSH 키 등록 → 원격 설치 통합 테스트
#
#   sudo ./test/controller-setup.sh
#
# setup-controller.sh 로 이 머신을 컨트롤러로 만들고(키·토큰·TLS 생성), 127.0.0.1:2222 sshd 를
# "GPU 호스트"로 써서 ssh-key copy → install → uninstall 을 확인합니다.
# 주의: /etc/kpctl 등을 실제로 만들었다가 지웁니다. 테스트용 VM/컨테이너에서만 실행하세요.
set -euo pipefail

[ "$(id -u)" = 0 ] || { echo "root 로 실행하세요"; exit 1; }
[ ! -e /etc/kpctl ] || { echo "/etc/kpctl 가 이미 있어 중단합니다 (운영 컨트롤러일 수 있음)"; exit 1; }

ROOT=$(cd "$(dirname "$0")/.." && pwd)
W=$(mktemp -d); chmod 755 "$W"
PORT=18445 SSHPORT=2222
KCFG="/boot/config-$(uname -r)"
STUBS=(apt-get apt-mark systemctl kpatch)
CREATED_KCFG=0 CTRL_PID=""

cleanup() {
  set +e
  [ -n "$CTRL_PID" ] && kill "$CTRL_PID" 2>/dev/null
  [ -f "$W/sshd.pid" ] && kill "$(cat "$W/sshd.pid")" 2>/dev/null
  for s in "${STUBS[@]}"; do grep -qs KPCTL-TEST-STUB "/usr/local/sbin/$s" && rm -f "/usr/local/sbin/$s"; done
  [ $CREATED_KCFG = 1 ] && rm -f "$KCFG"
  rm -f /etc/sudoers.d/kpctl-test
  userdel -r kpdeploy >/dev/null 2>&1; userdel kpctl >/dev/null 2>&1
  rm -rf /etc/kpctl /var/lib/kpctl /var/lib/kpctl-agent /usr/local/share/kpctl \
         /usr/local/bin/kpctl-controller /usr/local/bin/kpctl /usr/local/bin/kpctl-agent \
         /etc/systemd/system/kpctl-controller.service /etc/systemd/system/kpctl-agent.service \
         /etc/apt/apt.conf.d/99kpctl-no-reboot
  if [ "${KEEP:-}" = "1" ]; then echo "작업 디렉터리 유지: $W"; else rm -rf "$W"; fi
}
trap cleanup EXIT

pass() { echo "  ✔ $*"; }
die()  { echo "  ✘ $*"; echo "--- 마지막 출력 ---"; tail -25 "$W/out" 2>/dev/null; exit 1; }
check() { local msg="$1"; shift; if "$@"; then pass "$msg"; else die "$msg"; fi; }
perm() { stat -c '%a %U:%G' "$1"; }

# 사람이 쓰는 환경처럼: KPCTL_* 환경 변수 없이 /etc/kpctl/kpctl.env 만으로 동작해야 함
unset KPCTL_URL KPCTL_TOKEN KPCTL_CA KPCTL_BUNDLE KPCTL_SSH_KEY KPCTL_SSH_USER

echo "■ 준비: make dist 와 같은 dist/controller 묶음"
D="$W/dist/controller"; mkdir -p "$D/agent" "$W/bin"
(cd "$ROOT" && CGO_ENABLED=0 go build -o "$W/bin" ./cmd/...)
cp "$W/bin/kpctl-agent" "$ROOT"/deploy/install-agent.sh "$ROOT"/deploy/uninstall-agent.sh \
   "$ROOT"/deploy/systemd/kpctl-agent.service "$ROOT"/configs/reboot-hook.example.sh "$ROOT"/deploy/kpctl-prepare-kernel.py "$ROOT"/deploy/mirrors.list "$D/agent/"
cp "$W/bin/kpctl-controller" "$W/bin/kpctl" "$ROOT"/deploy/setup-controller.sh \
   "$ROOT"/deploy/systemd/kpctl-controller.service "$D/"
for s in "${STUBS[@]}"; do
  [ -e "/usr/local/sbin/$s" ] && ! grep -qs KPCTL-TEST-STUB "/usr/local/sbin/$s" && { echo "/usr/local/sbin/$s 가 이미 있어 중단"; exit 1; }
done
for s in apt-get apt-mark systemctl kpatch; do
  printf '#!/bin/sh\n# KPCTL-TEST-STUB\necho "%s $*" >> %s/calls.log\n' "$s" "$W" > "/usr/local/sbin/$s"
  chmod +x "/usr/local/sbin/$s"
done
if [ ! -e "$KCFG" ]; then echo CONFIG_LIVEPATCH=y > "$KCFG"; CREATED_KCFG=1; fi
pass "묶음, 가짜 apt/systemctl/kpatch"

echo "■ 1. setup-controller.sh"
bash "$D/setup-controller.sh" -n localhost -i 127.0.0.1 -u kpdeploy -p $PORT >"$W/out" 2>&1 || die "setup 실패"
check "SSH 키 생성 (600)"        test "$(perm /etc/kpctl/ssh/id_ed25519)" = "600 root:root"
check "공개키 생성"              grep -q '^ssh-ed25519 .* kpctl@localhost$' /etc/kpctl/ssh/id_ed25519.pub
check "토큰 4개 (600)"           bash -c 'for t in admin builder enroll-canary enroll-server; do [ "$(stat -c %a /etc/kpctl/tokens/$t.token)" = 600 ] || exit 1; done'
check "CA 키 root 전용 (600)"     test "$(perm /etc/kpctl/tls/ca.key)" = "600 root:root"
check "서버 키 kpctl 그룹 읽기 (640)" test "$(perm /etc/kpctl/tls/server.key)" = "640 root:kpctl"
check "서버 인증서 SAN"           bash -c "openssl x509 -in /etc/kpctl/tls/server.crt -noout -ext subjectAltName | grep -q 'DNS:localhost, IP Address:127.0.0.1'"
check "서버 인증서가 CA 로 검증됨"  bash -c "openssl verify -CAfile /etc/kpctl/tls/ca.crt /etc/kpctl/tls/server.crt >/dev/null"
check "kpctl.env (600)"          test "$(perm /etc/kpctl/kpctl.env)" = "600 root:root"
check "프로그램 설치"            test -x /usr/local/bin/kpctl -a -x /usr/local/share/kpctl/agent/kpctl-agent
check "공개키 안내 (from=, restrict)" grep -q 'from="127.0.0.1",restrict ssh-ed25519' "$W/out"

FP1=$(ssh-keygen -lf /etc/kpctl/ssh/id_ed25519.pub); TOK1=$(cat /etc/kpctl/tokens/admin.token)
bash "$D/setup-controller.sh" -n localhost -i 127.0.0.1 -u kpdeploy -p $PORT >"$W/out" 2>&1 || die "재실행 실패"
check "다시 실행해도 키·토큰 그대로" test "$(ssh-keygen -lf /etc/kpctl/ssh/id_ed25519.pub)" = "$FP1" -a "$(cat /etc/kpctl/tokens/admin.token)" = "$TOK1"

echo "■ 2. 컨트롤러를 kpctl 사용자로 실행 (HTTPS)"
runuser -u kpctl -- /usr/local/bin/kpctl-controller -config /etc/kpctl/controller.json >"$W/controller.log" 2>&1 &
CTRL_PID=$!
for _ in $(seq 50); do curl -sf --cacert /etc/kpctl/tls/ca.crt "https://localhost:$PORT/healthz" >/dev/null && break; sleep 0.1; done
check "CA 로 검증된 HTTPS 응답" curl -sf --cacert /etc/kpctl/tls/ca.crt "https://localhost:$PORT/healthz" -o /dev/null
kpctl status >"$W/out" 2>&1 || die "kpctl status 실패"
check "환경 변수 없이 kpctl.env 로 kpctl 동작" grep -q '등록된 호스트 없음' "$W/out"

echo "■ 3. 호스트 역할 sshd (관리자가 원래 쓰던 키만 등록된 상태)"
useradd -m -s /bin/bash kpdeploy; usermod -p '*' kpdeploy
echo 'kpdeploy ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/kpctl-test; chmod 440 /etc/sudoers.d/kpctl-test
ssh-keygen -q -t ed25519 -N '' -f "$W/admin_id"      # 관리자 개인 키 (비밀번호 로그인 대신)
ssh-keygen -q -t ed25519 -N '' -f "$W/hostkey"
mkdir -p "$W/keys" /run/sshd; cp "$W/admin_id.pub" "$W/keys/kpdeploy"; chmod 644 "$W/keys/kpdeploy"
cat > "$W/sshd_config" <<EOF
Port $SSHPORT
ListenAddress 127.0.0.1
HostKey $W/hostkey
PidFile $W/sshd.pid
AuthorizedKeysFile .ssh/authorized_keys $W/keys/%u
PasswordAuthentication no
StrictModes no
UsePAM no
Subsystem sftp /usr/lib/openssh/sftp-server
EOF
/usr/sbin/sshd -f "$W/sshd_config" -E "$W/sshd.log"
pass "sshd 127.0.0.1:$SSHPORT, 사용자 kpdeploy"

if kpctl install -check -accept-new-hostkey -ssh-port $SSHPORT 127.0.0.1 >"$W/out" 2>&1; then die "키 등록 전인데 접속됨"; fi
check "키 등록 전에는 컨트롤러 키로 접속 불가" grep -q '접속 실패' "$W/out"

echo "■ 4. kpctl ssh-key"
kpctl ssh-key show >"$W/out" 2>&1
check "show: from=\"127.0.0.1\",restrict 줄" grep -q '^from="127.0.0.1",restrict ssh-ed25519 ' "$W/out"
: > /etc/kpctl/ssh/known_hosts
kpctl ssh-key copy -ssh-port $SSHPORT -accept-new-hostkey -login-key "$W/admin_id" 127.0.0.1 >"$W/out" 2>&1 || die "ssh-key copy 실패"
check "copy: 등록 + 컨트롤러 키 로그인 확인" grep -q '등록함, 컨트롤러 키로 로그인 확인' "$W/out"
check "authorized_keys 에 제한 붙어 들어감" grep -q '^from="127.0.0.1",restrict ssh-ed25519' ~kpdeploy/.ssh/authorized_keys
check "호스트 키가 kpctl known_hosts 에 기록" test -s /etc/kpctl/ssh/known_hosts
kpctl ssh-key copy -ssh-port $SSHPORT -login-key "$W/admin_id" 127.0.0.1 >"$W/out" 2>&1 || die "두 번째 copy 실패"
check "다시 copy 하면 '이미 등록됨' (중복 추가 안 함)" bash -c "grep -q '이미 등록됨' '$W/out' && [ \$(grep -c kpctl@localhost ~kpdeploy/.ssh/authorized_keys) = 1 ]"

echo "■ 5. 컨트롤러 자신에는 설치하지 않음 (옵션 기본값으로 설치하는 경로는 test/dhcp.sh 에서 확인)"
kpctl install -check -ssh-port $SSHPORT 127.0.0.1 >"$W/out" 2>&1 || die "점검 실패"
check "점검 통과 (호스트 키 재확인 없이)" grep -q '점검 통과' "$W/out"
if kpctl install -group canary -ssh-port $SSHPORT -log-dir "$W/logs" 127.0.0.1 >"$W/out" 2>&1; then die "컨트롤러에 설치됨"; fi
check "컨트롤러에는 설치 거부" grep -rq '컨트롤러 또는 빌드 서버' "$W/logs"
check "에이전트 파일과 커널 고정 없음" test ! -e /etc/kpctl/agent.json -a ! -e /usr/local/bin/kpctl-agent
check "컨트롤러 파일은 그대로" test -s /etc/kpctl/controller.json -a -s /etc/kpctl/kpctl.env
if kpctl install -group nosuch -ssh-port $SSHPORT 127.0.0.1 >"$W/out" 2>&1; then die "없는 그룹으로 설치됨"; fi
check "없는 그룹은 거부" grep -q 'enroll-nosuch.token' "$W/out"

echo
echo "모든 컨트롤러 구축 테스트 통과"
