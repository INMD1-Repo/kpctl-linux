#!/bin/bash
# kpctl install / uninstall 테스트 — 실제 sshd 를 127.0.0.1:2222 에 띄워 이 머신 자체를 "GPU 호스트"로 씁니다.
#
#   sudo ./test/ssh-install.sh
#
# 주의: root 와 openssh-server, sudo 가 필요하고, 이 머신에 실제로 파일을 설치했다가 지웁니다.
#       apt-get, apt-mark, systemctl 은 /usr/local/sbin 에 가짜를 잠깐 두고 테스트가 끝나면 지웁니다.
#       테스트용 컨테이너/VM 에서만 실행하세요.
set -euo pipefail

[ "$(id -u)" = 0 ] || { echo "root 로 실행하세요"; exit 1; }
for c in sshd ssh scp sudo curl; do command -v $c >/dev/null || [ -x /usr/sbin/$c ] || { echo "$c 가 필요합니다"; exit 1; }; done

ROOT=$(cd "$(dirname "$0")/.." && pwd)
W=$(mktemp -d)
chmod 755 "$W"
BIN="$W/bin"
PORT=18444
SSHPORT=2222
ADMIN=admin-token-0123456789
KCFG="/boot/config-$(uname -r)"
STUBS=(apt-get apt-mark systemctl kpatch)
CREATED_KCFG=0
CTRL_PID="" SSHD_PID=""

cleanup() {
  set +e
  [ -n "$CTRL_PID" ] && kill "$CTRL_PID" 2>/dev/null
  [ -f "$W/sshd.pid" ] && kill "$(cat "$W/sshd.pid")" 2>/dev/null
  for s in "${STUBS[@]}"; do grep -qs KPCTL-TEST-STUB "/usr/local/sbin/$s" && rm -f "/usr/local/sbin/$s"; done
  [ $CREATED_KCFG = 1 ] && rm -f "$KCFG"
  rm -f /etc/sudoers.d/kpctl-test
  userdel -r kpdeploy >/dev/null 2>&1
  rm -rf /etc/kpctl /var/lib/kpctl-agent /usr/local/bin/kpctl-agent /etc/systemd/system/kpctl-agent.service \
         /etc/apt/apt.conf.d/99kpctl-no-reboot
  if [ "${KEEP:-}" = "1" ]; then echo "작업 디렉터리 유지: $W"; else rm -rf "$W"; fi
}
trap cleanup EXIT

pass() { echo "  ✔ $*"; }
die()  { echo "  ✘ $*"; echo "--- 마지막 출력 ---"; tail -25 "$W/out" 2>/dev/null; exit 1; }
check() { local msg="$1"; shift; if "$@"; then pass "$msg"; else die "$msg"; fi; }

echo "■ 준비"
mkdir -p "$BIN"
(cd "$ROOT" && CGO_ENABLED=0 go build -o "$BIN" ./cmd/...)
export PATH="$BIN:$PATH" KPCTL_URL="http://127.0.0.1:$PORT" KPCTL_TOKEN="$ADMIN"

# 설치 묶음 (make dist 의 dist/controller/agent 와 같은 구성)
B="$W/bundle"; mkdir -p "$B"
cp "$BIN/kpctl-agent" "$ROOT"/deploy/install-agent.sh "$ROOT"/deploy/uninstall-agent.sh \
   "$ROOT"/deploy/systemd/kpctl-agent.service "$ROOT"/configs/reboot-hook.example.sh "$ROOT"/deploy/kpctl-prepare-kernel.py "$ROOT"/deploy/mirrors.list "$B/"
export KPCTL_BUNDLE="$B"
echo enroll-canary-0123456789 > "$W/canary.token"
echo enroll-fleet-01234567890 > "$W/fleet.token"

# 가짜 시스템 명령 (호출 기록만 남김)
for s in "${STUBS[@]}"; do
  [ -e "/usr/local/sbin/$s" ] && ! grep -qs KPCTL-TEST-STUB "/usr/local/sbin/$s" && { echo "/usr/local/sbin/$s 가 이미 있어 중단"; exit 1; }
done
for s in apt-get apt-mark systemctl; do
  printf '#!/bin/sh\n# KPCTL-TEST-STUB\necho "%s $*" >> %s/calls.log\n' "$s" "$W" > "/usr/local/sbin/$s"
done
# apt-get install kpatch 를 부르면 가짜 kpatch 가 생기게
cat >> /usr/local/sbin/apt-get <<EOF
case "\$*" in *install*kpatch*) printf '#!/bin/sh\n# KPCTL-TEST-STUB\nexit 0\n' > /usr/local/sbin/kpatch; chmod +x /usr/local/sbin/kpatch;; esac
EOF
chmod +x /usr/local/sbin/apt-get /usr/local/sbin/apt-mark /usr/local/sbin/systemctl
if [ ! -e "$KCFG" ]; then echo CONFIG_LIVEPATCH=y > "$KCFG"; CREATED_KCFG=1; fi
pass "바이너리, 설치 묶음, 가짜 apt/systemctl"

cat > "$W/controller.json" <<EOF
{
  "listen": "127.0.0.1:$PORT", "data_dir": "$W/ctl-data",
  "admin_tokens": {"tester": "$ADMIN"}, "builder_token": "builder-token-0123456789",
  "allow_self_enroll": true,
  "enroll_tokens": [
    {"name": "canary", "token": "enroll-canary-0123456789", "ring": 1, "reboot_policy": "drain"},
    {"name": "fleet",  "token": "enroll-fleet-01234567890", "ring": 2, "reboot_policy": "drain"}
  ],
  "rings": [1, 2]
}
EOF
kpctl-controller -config "$W/controller.json" >"$W/controller.log" 2>&1 &
CTRL_PID=$!
for _ in $(seq 50); do curl -sf "$KPCTL_URL/healthz" >/dev/null && break; sleep 0.1; done
pass "컨트롤러"

# sshd: root(키) + 일반 사용자 kpdeploy(키, 처음엔 sudo 없음)
useradd -m -s /bin/bash kpdeploy
usermod -p '*' kpdeploy        # 비밀번호 없음 (잠금 계정이면 sshd 가 키 로그인도 거부)
grep -q '^root:!' /etc/shadow && usermod -p '*' root
ssh-keygen -q -t ed25519 -N '' -f "$W/id"
ssh-keygen -q -t ed25519 -N '' -f "$W/hostkey"
mkdir -p "$W/keys" /run/sshd
cp "$W/id.pub" "$W/keys/root"; cp "$W/id.pub" "$W/keys/kpdeploy"; chmod 644 "$W/keys"/*
cat > "$W/sshd_config" <<EOF
Port $SSHPORT
ListenAddress 127.0.0.1
HostKey $W/hostkey
PidFile $W/sshd.pid
AuthorizedKeysFile $W/keys/%u
PermitRootLogin prohibit-password
PasswordAuthentication no
StrictModes no
UsePAM no
Subsystem sftp /usr/lib/openssh/sftp-server
EOF
/usr/sbin/sshd -f "$W/sshd_config" -E "$W/sshd.log"
SSH=(-ssh-port $SSHPORT -ssh-key "$W/id" -ssh-opt "UserKnownHostsFile=$W/known_hosts")
pass "sshd 127.0.0.1:$SSHPORT"

echo "■ 1. 처음 보는 호스트 키 → 거부, -accept-new-hostkey → 통과"
if kpctl install -check "${SSH[@]}" root@127.0.0.1 >"$W/out" 2>&1; then die "호스트 키 확인 없이 접속됨"; fi
check "known_hosts 에 없으면 접속 실패" grep -q '접속 실패' "$W/out"
kpctl install -check -accept-new-hostkey "${SSH[@]}" root@127.0.0.1 >"$W/out" 2>&1 || die "점검 실패"
check "점검 통과" grep -q '점검 통과' "$W/out"
check "점검은 아무것도 바꾸지 않음" test ! -e /usr/local/bin/kpctl-agent -a ! -e "$W/calls.log"

echo "■ 2. 점검 실패 케이스"
if kpctl install -check "${SSH[@]}" kpdeploy@127.0.0.1 >"$W/out" 2>&1; then die "sudo 없는 사용자 점검 통과"; fi
check "sudo 없는 일반 사용자 거부" grep -q '비밀번호 없는 sudo' "$W/out"
if kpctl install -check -controller-url http://127.0.0.1:1 "${SSH[@]}" root@127.0.0.1 >"$W/out" 2>&1; then die "컨트롤러 접속 불가인데 통과"; fi
check "호스트→컨트롤러 접속 불가 감지" grep -q '컨트롤러 http://127.0.0.1:1 에 접속하지 못했습니다' "$W/out"
mkdir -p "$W/bundle-arm"; cp "$B"/* "$W/bundle-arm/"
(cd "$ROOT" && CGO_ENABLED=0 GOARCH=arm64 go build -o "$W/bundle-arm/kpctl-agent" ./cmd/kpctl-agent)
if kpctl install -check -bundle "$W/bundle-arm" "${SSH[@]}" root@127.0.0.1 >"$W/out" 2>&1; then die "아키텍처 불일치인데 통과"; fi
check "아키텍처 불일치 감지 (arm64 에이전트 → x86_64 호스트)" grep -q '아키텍처 불일치' "$W/out"
if kpctl install "${SSH[@]}" root@127.0.0.1 >"$W/out" 2>&1; then die "토큰 없이 설치됨"; fi
check "등록 토큰 없으면 설치 거부" grep -q 'enroll-token-file 이 필요' "$W/out"

echo "■ 3. 설치 (root, hosts 파일)"
printf '# 카나리\nroot@127.0.0.1   # 주석\n\n' > "$W/hosts.txt"
kpctl install -enroll-token-file "$W/canary.token" -log-dir "$W/logs" "${SSH[@]}" -hosts-file "$W/hosts.txt" >"$W/out" 2>&1 || die "설치 실패"
check "설치 완료 + 등록 확인" grep -q '설치 완료' "$W/out"
check "링 1(카나리 토큰)으로 등록" bash -c "kpctl hosts | grep -q \"^$(hostname) .* 1 \""
check "apt 로 kpatch 설치" grep -q 'apt-get install -y -q kpatch' "$W/calls.log"
check "커널 고정(apt-mark hold)" grep -q 'apt-mark hold' "$W/calls.log"
check "agent.json 권한 600" test "$(stat -c %a /etc/kpctl/agent.json)" = 600
check "원격 임시 디렉터리(토큰 파일) 삭제" bash -c "! ls -d /tmp/kpctl-install.* 2>/dev/null"
check "로그에 토큰이 남지 않음" bash -c "! grep -rq enroll-canary '$W/logs'"
ID1=$(kpctl hosts | awk -v h="$(hostname)" '$1==h {print $2}')

echo "■ 4. 재설치 (sudo 사용자, 다른 토큰) — 등록 유지"
echo 'kpdeploy ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/kpctl-test; chmod 440 /etc/sudoers.d/kpctl-test
: > "$W/calls.log"
kpctl install -enroll-token-file "$W/fleet.token" -log-dir "$W/logs" "${SSH[@]}" kpdeploy@127.0.0.1 >"$W/out" 2>&1 || die "재설치 실패"
check "sudo 로 재설치 완료" grep -q '설치 완료' "$W/out"
check "이미 설치됨 경고" grep -q '이미 설치되어 있어 재설치' "$W/out"
check "kpatch 가 있으면 apt 설치 생략" bash -c "! grep -q 'apt-get install' '$W/calls.log'"
check "에이전트 재시작" grep -q 'systemctl restart kpctl-agent' "$W/calls.log"
ID2=$(kpctl hosts | awk -v h="$(hostname)" '$1==h {print $2}')
check "같은 호스트 ID 유지 ($ID1)" test "$ID1" = "$ID2"
check "링도 그대로 1" bash -c "kpctl hosts | grep -q \"^$(hostname) .* 1 \""

echo "■ 5. 여러 대 병렬 점검"
kpctl install -check -parallel 2 "${SSH[@]}" root@127.0.0.1 kpdeploy@127.0.0.1 >"$W/out" 2>&1 || die "병렬 점검 실패"
check "2대 모두 통과" grep -q '2대 모두 성공' "$W/out"

echo "■ 6. 제거 (패치 유지 기본값)"
kpctl uninstall -log-dir "$W/logs" "${SSH[@]}" kpdeploy@127.0.0.1 >"$W/out" 2>&1 || die "제거 실패"
check "제거 완료, 패치 유지, 등록 삭제" grep -q '패치 유지, 등록 삭제' "$W/out"
check "에이전트 파일 삭제" test ! -e /usr/local/bin/kpctl-agent -a ! -e /etc/kpctl/agent.json -a ! -e /var/lib/kpctl-agent
check "재부팅 훅은 남김" test -e /etc/kpctl/reboot-hook.sh
check "컨트롤러 등록 삭제" bash -c "kpctl hosts | grep -q '등록된 호스트 없음'"

echo
echo "모든 SSH 설치 테스트 통과"
