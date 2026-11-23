#!/bin/bash
# 전체 흐름 테스트 (가짜 kpatch 사용, root 불필요)
#
#   ./test/e2e.sh
#
# 확인하는 것:
#   자동 수집(경로 필터, 시험 실패 검토) → 빌드 → 승인(서명) → 링 1 → promote 검사 → 링 2
#   → 긴급 수동 패치 → 빌드 실패 시 패치 보존·관리자 제외 → 롤백 → cordon/드레인/재부팅 → 재시작 후 상태 유지
#   → LTS 시리즈별 빌드 서버 (자동 대상 커널, 작업 배정, HWE 호스트 제외)
#   → 자동 배포 (롤백 뒤 멈춤, 재개, 자동 승인·승급, 일시 중지) → 관리자 웹 → 자동 등록 스크립트
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
FAKE="$ROOT/test/fake"
W=$(mktemp -d)
BIN="$W/bin"
PORT=18443
KERNEL=6.8.0-85-generic
ADMIN=admin-token-0123456789
BUILDER=builder-token-0123456789
CTRL_PID=""

cleanup() {
  [ -n "$CTRL_PID" ] && kill "$CTRL_PID" 2>/dev/null || true
  if [ "${KEEP:-}" = "1" ]; then echo "작업 디렉터리 유지: $W"; else rm -rf "$W"; fi
}
trap cleanup EXIT

pass() { echo "  ✔ $*"; }
die()  { echo "  ✘ $*"; echo "--- 컨트롤러 로그 ---"; tail -30 "$W/controller.log"; exit 1; }
check() { local msg="$1"; shift; if "$@"; then pass "$msg"; else die "$msg"; fi; }

export KPCTL_URL="http://127.0.0.1:$PORT" KPCTL_TOKEN="$ADMIN"
export KPCTL_ENV="$W/no-env" KPCTL_CA="" KPCTL_SSH_FROM=""
export GIT_AUTHOR_NAME=test GIT_AUTHOR_EMAIL=t@t GIT_COMMITTER_NAME=test GIT_COMMITTER_EMAIL=t@t
export FAKE_SCHED="$W/sched"
mkdir -p "$FAKE_SCHED"
chmod +x "$FAKE"/*

echo "■ 빌드"
mkdir -p "$BIN"
(cd "$ROOT" && go build -o "$BIN" ./cmd/...)
export PATH="$BIN:$FAKE:$PATH"   # 실제 APT 상태와 격리한 가짜 배포 색인도 사용
pass "바이너리 4개"

echo "■ 가짜 Ubuntu 커널 git 준비"
U="$W/upstream"
mkdir -p "$U"/{arch/x86/kvm,virt/kvm,fs/ext4,drivers/vfio}
printf 'VERSION = 6\nPATCHLEVEL = 8\nSUBLEVEL = 0\n' > "$U/Makefile"
git -C "$U" init -q
for f in arch/x86/kvm/x86.c virt/kvm/kvm_main.c fs/ext4/inode.c drivers/vfio/pci.c; do echo "int x;" > "$U/$f"; done
git -C "$U" add -A && git -C "$U" commit -qm "initial"
git -C "$U" tag Ubuntu-6.8.0-85.85
echo "int bounds_check;" >> "$U/arch/x86/kvm/x86.c"
git -C "$U" commit -qam $'KVM: x86: fix bounds check\n\nCVE-2026-1111'
echo "int ext4_fix;" >> "$U/fs/ext4/inode.c"
git -C "$U" commit -qam $'ext4: fix overflow\n\nCVE-2026-2222'
echo "int FAIL_BUILD;" >> "$U/virt/kvm/kvm_main.c"
git -C "$U" commit -qam $'KVM: change struct layout\n\nCVE-2026-3333'
echo "int vfio_cleanup;" >> "$U/drivers/vfio/pci.c"
git -C "$U" commit -qam "vfio: cleanup (CVE 없음)"
git -C "$U" tag Ubuntu-6.8.0-86.86
mkdir -p "$W/src" "$W/debug" "$W/boot"
echo 'CONFIG_LIVEPATCH=y' > "$W/boot/config-$KERNEL"
git clone -q "$U" "$W/src/ubuntu-noble"
echo "fake vmlinux" > "$W/debug/vmlinux-$KERNEL"
export KPCTL_TEST_APT_SERIES=noble KPCTL_TEST_APT_PACKAGES="$W/Packages"
cat > "$W/Packages" <<EOF
Package: linux-image-unsigned-6.8.0-86-generic
Architecture: $(dpkg --print-architecture)
Source: linux
Version: 6.8.0-86.86

EOF
pass "태그 85.85 → 86.86, 커밋 4개"

echo "■ 설정 파일"
cat > "$W/controller.json" <<EOF
{
  "listen": "127.0.0.1:$PORT",
  "data_dir": "$W/ctl-data",
  "admin_tokens": {"tester": "$ADMIN"},
  "builder_token": "$BUILDER",
  "enroll_tokens": [
    {"name": "canary", "token": "enroll-canary-0123456789", "ring": 1, "reboot_policy": "drain"},
    {"name": "fleet",  "token": "enroll-fleet-01234567890", "ring": 2, "reboot_policy": "drain"}
  ],
  "rings": [1, 2],
  "sign_command": ["$FAKE/sign-file", "{module}"],
  "scheduler": {"vm_count_command": ["$FAKE/vm-count", "{host}"]},
  "drain_check_seconds": 1
}
EOF
# 가짜 빌드는 수 KB만 쓰므로 실제 커널용 60 GiB 디스크 기준을 적용하지 않습니다.
cat > "$W/builder.json" <<EOF
{
  "controller_url": "$KPCTL_URL",
  "token": "$BUILDER",
  "work_dir": "$W/build", "kernel_cleanup_free_gib": -1,
  "kpatch_build": "$FAKE/kpatch-build",
  "series": "noble",
  "paths": ["arch/x86/kvm", "virt/kvm", "drivers/vfio", "net/"],
  "git_root": "$W/src",
  "debug_dir": "$W/debug",
  "boot_dir": "$W/boot"
}
EOF
# make_host 이름 등록토큰 커널 version_signature
make_host() {
  local h=$1 tok=$2 kernel=$3 sig=$4
  local R="$W/host-$h"; mkdir -p "$R/proc"
  echo "$kernel" > "$R/proc/osrelease"; echo "$sig" > "$R/proc/version_signature"; echo 32768 > "$R/proc/tainted"
  printf '#!/bin/sh\ntouch %s/rebooted\n' "$R" > "$R/reboot-hook.sh"
  python3 "$FAKE/prepare-boot.py" "$R" "$kernel"
  cat > "$W/agent-$h.json" <<EOF
{
  "controller_url": "$KPCTL_URL", "enroll_token": "$tok", "hostname": "$h",
  "state_dir": "$R/state", "kpatch_bin": "$FAKE/kpatch", "kpatch_install_dir": "$R/installed", "reboot_hook": "$R/reboot-hook.sh",
  "livepatch_sysfs": "$R/sys/livepatch", "module_sysfs": "$R/sys/module",
  "tainted_path": "$R/proc/tainted", "osrelease_path": "$R/proc/osrelease",
  "signature_path": "$R/proc/version_signature", "boot_id_path": "$R/proc/boot_id", "proc_dir": "$R/proc",
  "boot_dir": "$R/boot", "grub_config": "$R/boot/grub.cfg", "grub_env": "$R/grubenv",
  "grub_reboot_bin": "$R/grub-reboot", "grub_editenv_bin": "$R/grub-editenv", "kernel_prepare_lock": "$R/prepare.lock", "package_locks": [],
  "grub_set_default_bin": "$R/grub-set-default"
}
EOF
}
make_host gpu-01 enroll-canary-0123456789 $KERNEL "Ubuntu 6.8.0-85.85-generic 6.8.12"
make_host gpu-02 enroll-fleet-01234567890 $KERNEL "Ubuntu 6.8.0-85.85-generic 6.8.12"
agent() { FAKE_ROOT="$W/host-$1" "$BIN/kpctl-agent" -config "$W/agent-$1.json" -once 2>>"$W/agent.log"; }
lp() { echo "$W/host-$1/sys/livepatch"; }
modname() { echo "kpctl_6_8_0_85_generic_v$1"; }

start_controller() {
  "$BIN/kpctl-controller" -config "$W/controller.json" >>"$W/controller.log" 2>&1 &
  CTRL_PID=$!
  for _ in $(seq 50); do curl -sf "$KPCTL_URL/healthz" >/dev/null && return; sleep 0.1; done
  die "컨트롤러가 뜨지 않음"
}
start_controller
pass "컨트롤러 시작"

echo "■ 1. 호스트 등록"
agent gpu-01; agent gpu-02
check "호스트 2대 등록" test "$(kpctl hosts | grep -c gpu-)" = 2

echo "■ 2. 자동 수집 + 빌드"
"$BIN/kpctl-builder" -config "$W/builder.json" -once 2>"$W/builder.log"
check "자동 모드: 기준 태그를 version_signature 에서 (Ubuntu-6.8.0-85.85)" grep -q "Ubuntu-6.8.0-85.85..Ubuntu-6.8.0-86.86" "$W/builder.log"
kpctl patches -kernel $KERNEL > "$W/out"
check "KVM CVE-2026-1111 만 패치로 수집" grep -q CVE-2026-1111 "$W/out"
check "경로 밖 CVE-2026-2222(ext4) 제외" bash -c "! grep -q CVE-2026-2222 '$W/out' && ! kpctl status | grep -q CVE-2026-2222"
kpctl status > "$W/out"
curl -sf -H "Authorization: Bearer $ADMIN" "$KPCTL_URL/api/status" > "$W/status.json"
check "시험 실패는 CVE 검토 상태로 남고 영구 불가로 자동 제외하지 않음" python3 - "$W/status.json" "$KERNEL" <<'PY'
import json,sys
s=json.load(open(sys.argv[1]));u=s['upstream'][sys.argv[2]]
assert u['problem_failure']['cves']==['CVE-2026-3333'],u
assert not s.get('unpatchable'),s.get('unpatchable')
assert not u.get('collected_tag'),u
PY
check "job 1 승인대기" grep -qE '^1 .*승인대기' "$W/out"
# 이 시험에서는 실패 원인을 확인한 관리자가 해당 커밋을 제외한 뒤 계속합니다.
python3 - "$W/status.json" "$KERNEL" "$W/exclude.json" "$W/exclude-commit" <<'PY'
import json,sys
u=json.load(open(sys.argv[1]))['upstream'][sys.argv[2]]
json.dump({'reason':'가짜 빌드의 자료 변경 제약을 확인하고 별도 조치','problem_ref':u['problem_at']},open(sys.argv[3],'w'))
open(sys.argv[4],'w').write(u['problem_failure']['commit'])
PY
FAILED_COMMIT=$(cat "$W/exclude-commit")
curl -sf -X POST -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
  --data-binary @"$W/exclude.json" "$KPCTL_URL/api/kernels/$KERNEL/commits/$FAILED_COMMIT/exclude" >/dev/null
kpctl auto clear "$KERNEL" >/dev/null

echo "■ 3. 승인 → 링 1"
kpctl approve 1 >/dev/null
check "서명 명령 실행됨" grep -q '~SIGNED~' "$W/ctl-data/artifacts/$KERNEL/$(modname 1).ko"
if kpctl promote -kernel $KERNEL -ring 2 >"$W/out" 2>&1; then die "적용 전 promote 가 통과됨"; fi
check "카나리 미적용 상태에서 promote 차단" grep -q '아직 v0' "$W/out"
agent gpu-01; agent gpu-02
check "gpu-01(링1) v1 적용" test "$(cat "$(lp gpu-01)/$(modname 1)/enabled")" = 1
check "gpu-02(링2) 아직 미적용" test ! -e "$(lp gpu-02)/$(modname 1)"

echo "■ 4. promote → 링 2"
kpctl promote -kernel $KERNEL -ring 2 >/dev/null
agent gpu-02
check "gpu-02 v1 적용" test -e "$(lp gpu-02)/$(modname 1)"

echo "■ 5. 긴급 수동 패치"
cat > "$W/manual.patch" <<'EOF'
--- a/drivers/vfio/pci.c
+++ b/drivers/vfio/pci.c
@@ -1 +1,2 @@
 int x;
+int zero_day_fix;
EOF
kpctl submit -kernel $KERNEL -urgent -cve CVE-2026-9999 -title "0-day 긴급" "$W/manual.patch" >/dev/null
"$BIN/kpctl-builder" -config "$W/builder.json" -once 2>>"$W/builder.log"
check "v2 는 v1 패치 + 수동 패치 누적" bash -c "grep -q bounds_check '$W/ctl-data/artifacts/$KERNEL/$(modname 2).ko' && grep -q zero_day_fix '$W/ctl-data/artifacts/$KERNEL/$(modname 2).ko'"
kpctl approve 2 >/dev/null
agent gpu-01
check "gpu-01 v2 적용" test -e "$(lp gpu-01)/$(modname 2)"
check "gpu-01 v1 모듈 내려짐" test ! -e "$W/host-gpu-01/sys/module/$(modname 1)"
check "gpu-01 v1 설치본 삭제" test ! -e "$W/host-gpu-01/installed/$KERNEL/$(modname 1).ko"

echo "■ 6. 빌드 실패 패치 보존 → 검토 후 관리자 제외"
sed 's/zero_day_fix/FAIL_BUILD/' "$W/manual.patch" > "$W/bad.patch"
kpctl submit -kernel $KERNEL -title "깨진 패치" "$W/bad.patch" >/dev/null
"$BIN/kpctl-builder" -config "$W/builder.json" -once 2>>"$W/builder.log"
check "job 3 실패" bash -c "kpctl jobs | grep -qE '^3 .*실패'"
check "빌드 실패만으로 패치를 자동 제외하지 않음" bash -c "kpctl patches -kernel $KERNEL | grep '깨진' | grep -q active"
check "빌드 실패 커널의 자동 배포 중단" bash -c "curl -sf -H 'Authorization: Bearer $ADMIN' '$KPCTL_URL/api/status' | grep -q '누적 빌드 실패'"
check "실패 로그 조회" bash -c "kpctl log 3 | grep -q 'changed data section'"
BADPATCH=$(kpctl patches -kernel $KERNEL | awk '/깨진 패치/ {print $1}')
kpctl patch disable "$BADPATCH" >/dev/null
kpctl build -kernel $KERNEL >/dev/null
"$BIN/kpctl-builder" -config "$W/builder.json" -once 2>>"$W/builder.log"
check "다음 빌드(job 4)는 깨진 패치 없이 성공" bash -c "kpctl jobs | grep -qE '^4 .*승인대기'"

echo "■ 7. 롤백"
kpctl rollback -kernel $KERNEL -version 1 >/dev/null
agent gpu-01
check "gpu-01 v1 으로 복귀" test -e "$(lp gpu-01)/$(modname 1)"
check "gpu-01 v2 내려짐" test ! -e "$W/host-gpu-01/sys/module/$(modname 2)"

echo "■ 8. 드레인 → 재부팅"
if kpctl host reboot gpu-02 -kernel 6.8.0-86-generic >"$W/out" 2>&1; then die "cordon 없이 재부팅 승인됨"; fi
check "cordon 전 재부팅 거부" grep -q 'cordon 상태가 아닙니다' "$W/out"
echo 2 > "$FAKE_SCHED/vmcount-gpu-02"
kpctl host cordon gpu-02 >/dev/null; sleep 2
if kpctl host reboot gpu-02 -kernel 6.8.0-86-generic >"$W/out" 2>&1; then die "VM 이 남았는데 재부팅 승인됨"; fi
check "VM 2대 남아 재부팅 거부" grep -q 'VM 이 2 대' "$W/out"
echo 0 > "$FAKE_SCHED/vmcount-gpu-02"; sleep 2
check "드레인 완료 표시" bash -c "kpctl hosts | grep gpu-02 | grep -q '재부팅 가능'"
kpctl host reboot gpu-02 -kernel 6.8.0-86-generic >/dev/null
agent gpu-02
check "재부팅 훅 실행" test -e "$W/host-gpu-02/rebooted"
rm "$W/host-gpu-02/rebooted"
echo 6.8.0-86-generic > "$W/host-gpu-02/proc/osrelease"   # 새 커널로 올라온 것처럼
echo boot-after > "$W/host-gpu-02/proc/boot_id"
echo "Ubuntu 6.8.0-86.86-generic 6.8.12" > "$W/host-gpu-02/proc/version_signature"
agent gpu-02
check "같은 재부팅 요청은 반복 실행 안 함" test ! -e "$W/host-gpu-02/rebooted"
check "재부팅 요청 정리됨" bash -c "! kpctl hosts | grep gpu-02 | grep -q '재부팅 승인됨'"
check "새 커널(86)은 트랙 없음 → 우리 패치 전부 내림" test -z "$(ls "$(lp gpu-02)")"
kpctl host uncordon gpu-02 >/dev/null

echo "■ 9. 컨트롤러 재시작 후 상태 유지"
kill "$CTRL_PID"; wait "$CTRL_PID" 2>/dev/null || true
start_controller
check "배포 상태 유지 (링1 v1, 링2 v1)" bash -c "kpctl status | grep -qE '^$KERNEL +v1 +v1'"
check "감사 로그 기록" grep -q '승인 job 1' "$W/ctl-data/audit.log"

echo "■ 10. LTS 시리즈별 빌드 서버"
JAMMY=5.15.0-125-generic
echo 'CONFIG_LIVEPATCH=y' > "$W/boot/config-$JAMMY"
make_host gpu-03 enroll-fleet-01234567890 $JAMMY "Ubuntu 5.15.0-125.135-generic 5.15.167"
make_host gpu-04 enroll-fleet-01234567890 $KERNEL "Ubuntu 6.8.0-85.85~22.04.1-generic 6.8.12"   # 22.04 HWE
agent gpu-03; agent gpu-04
check "22.04 HWE 호스트에는 24.04 GA 용 모듈을 주지 않음" test -z "$(ls "$(lp gpu-04)" 2>/dev/null)"
check "HWE 호스트는 목표 v0, 'HWE 미지원' 표시" bash -c "kpctl hosts | grep gpu-04 | grep -q 'v0/v0.*HWE 미지원'"
kpctl submit -kernel $JAMMY -title "jammy 수동 패치" "$W/manual.patch" >/dev/null
JOB=$(kpctl jobs | awk -v k=$JAMMY '$0 ~ k {print $1; exit}')
"$BIN/kpctl-builder" -config "$W/builder.json" -once 2>"$W/builder.log"
check "noble 빌드 서버는 jammy 작업을 가져가지 않음" bash -c "kpctl jobs | grep -qE '^$JOB .*대기'"
check "새 커널(86) 디버그 심볼 없음 안내" grep -q '6.8.0-86-generic.*디버그 심볼 없음' "$W/builder.log"
check "HWE 커널은 자동 수집 대상 아님" grep -q 'HWE 커널' "$W/builder.log"
sed 's/"noble"/"jammy"/' "$W/builder.json" > "$W/builder-jammy.json"
"$BIN/kpctl-builder" -config "$W/builder-jammy.json" -once 2>"$W/builder-jammy.log"
check "정확한 jammy 입력 없이 빌드하지 않음" bash -c "kpctl jobs | grep -qE '^$JOB .*실패'"
check "jammy git 이 없으면 clone 명령 안내" grep -q 'git clone .*+git/jammy' "$W/builder-jammy.log"
J="$W/src/ubuntu-jammy"
mkdir -p "$J/drivers/vfio"
printf 'VERSION = 5\nPATCHLEVEL = 15\nSUBLEVEL = 0\n' > "$J/Makefile"
echo 'int x;' > "$J/drivers/vfio/pci.c"
git -C "$J" init -q
git -C "$J" add -A && git -C "$J" commit -qm 'jammy fixture'
git -C "$J" tag Ubuntu-5.15.0-125.135
echo 'fake vmlinux' > "$W/debug/vmlinux-$JAMMY"
kpctl build -kernel "$JAMMY" >/dev/null
JOB=$(kpctl jobs | awk -v k=$JAMMY '$0 ~ k {print $1; exit}')
"$BIN/kpctl-builder" -config "$W/builder-jammy.json" -once 2>>"$W/builder-jammy.log"
check "정확한 jammy 기준 입력을 준비하면 작업 빌드" bash -c "kpctl jobs | grep -qE '^$JOB .*승인대기'"

echo "■ 11. 자동 배포"
kill "$CTRL_PID"; wait "$CTRL_PID" 2>/dev/null || true
sed -i 's/"rings": \[1, 2\],/"rings": [1, 2],\n  "auto_rollout": {"enabled": true, "soak_minutes": 0, "check_seconds": 1},/' "$W/controller.json"
start_controller
echo "int auto_fix;" >> "$U/arch/x86/kvm/x86.c"
git -C "$U" commit -qam $'KVM: x86: auto rollout fix\n\nCVE-2026-7777'
git -C "$U" tag Ubuntu-6.8.0-87.87
# Git 태그만으로는 수집하지 않습니다. 정식 APT 색인에도 87이 공개된 상황으로 진행합니다.
sed -i -e 's/6.8.0-86-generic/6.8.0-87-generic/' -e 's/6.8.0-86.86/6.8.0-87.87/' "$W/Packages"
"$BIN/kpctl-builder" -config "$W/builder.json" -once 2>"$W/builder-auto.log"
AUTOJOB=$(kpctl jobs | awk -v k=$KERNEL '$0 ~ k && /승인대기/ {print $1; exit}')
test -n "$AUTOJOB" || die "새 Ubuntu 패치 빌드 작업이 없음"
sleep 2
check "롤백한 커널은 자동 승인하지 않고 멈춤" bash -c "kpctl jobs | grep -qE '^$AUTOJOB .*승인대기' && kpctl auto | grep -q '자동 배포 멈춤'"
kpctl auto pause >/dev/null
kpctl auto clear $KERNEL >/dev/null
sleep 2
check "일시 중지 중에는 재개해도 승인하지 않음" bash -c "kpctl jobs | grep -qE '^$AUTOJOB .*승인대기' && kpctl auto | grep -q '일시 중지'"
kpctl auto resume >/dev/null
sleep 2
check "재개하면 사람 없이 승인되고 링 1 배포" bash -c "kpctl jobs | grep -E '^$AUTOJOB ' | grep -q 'auto'"
check "자동 승인도 서명 명령을 거침" bash -c "grep -l auto_fix '$W/ctl-data/artifacts/$KERNEL/'*.ko | xargs grep -q '~SIGNED~'"
AUTOVER=$(kpctl jobs | awk -v j=$AUTOJOB '$1 == j {print $3}')
check "카나리 적용 전에는 링 2 로 넘어가지 않음" bash -c "! kpctl status | grep -qE '^$KERNEL +$AUTOVER +$AUTOVER'"
agent gpu-01
sleep 2
check "카나리 적용 뒤 링 2 로 자동 승급" bash -c "kpctl status | grep -qE '^$KERNEL +$AUTOVER +$AUTOVER'"
check "감사 로그에 auto 로 남음" grep -qP '\tauto\t승인 job '"$AUTOJOB" "$W/ctl-data/audit.log"
kpctl submit -kernel $KERNEL -title "자동 승인 금지 확인" "$W/manual.patch" >/dev/null
MANUALJOB=$(kpctl jobs | awk 'NR==2 {print $1}')
"$BIN/kpctl-builder" -config "$W/builder.json" -once 2>>"$W/builder-auto.log"
sleep 2
check "수동 제출 패치는 자동 승인하지 않음" bash -c "kpctl jobs | grep -qE '^$MANUALJOB .*승인대기' && kpctl auto | grep -q '직접 승인'"

echo "■ 12. 관리자 웹"
check "화면은 토큰 없이 열림" bash -c "curl -sf '$KPCTL_URL/' | grep -q 'kpctl 관리자'"
check "스크립트 제한 헤더" bash -c "curl -sfI '$KPCTL_URL/' | grep -qi \"content-security-policy: .*script-src 'self'\""
check "데이터 API 는 토큰 필요" test "$(curl -s -o /dev/null -w '%{http_code}' "$KPCTL_URL/api/status")" = 401
check "감사 로그 API" bash -c "curl -sf -H 'Authorization: Bearer $ADMIN' '$KPCTL_URL/api/audit' | grep -q '승인 job'"

echo "■ 13. 자동 등록"
mkdir -p "$W/bundle" "$W/tokens"
cp "$BIN/kpctl-agent" "$W/bundle/"
# 실제 install-agent.sh 는 시스템을 바꾸므로, 받은 인자와 토큰을 기록하는 가짜를 묶음에 넣습니다.
cat > "$W/bundle/install-agent.sh" <<EOF
#!/bin/bash
{ echo "url=\$1"; echo "token=\$(cat "\${2#@}")"; echo "from=\$(basename "\$(dirname "\$0")")"; } > "$W/bootstrap.out"
EOF
chmod +x "$W/bundle/install-agent.sh"
ln -s /etc/passwd "$W/bundle/leak"
kill "$CTRL_PID"; wait "$CTRL_PID" 2>/dev/null || true
sed -i "s|\"rings\": \\[1, 2\\],|\"rings\": [1, 2],\n  \"agent_bundle_dir\": \"$W/bundle\",|" "$W/controller.json"
start_controller
echo enroll-fleet-01234567890 > "$W/tokens/enroll-fleet.token"
export KPCTL_TOKEN_DIR="$W/tokens"
if kpctl bootstrap -group nope >"$W/out" 2>&1; then die "없는 그룹 통과"; fi
check "없는 그룹은 거부" grep -q 'enroll-nope.token' "$W/out"
kpctl bootstrap -group fleet > "$W/bootstrap.sh"
check "스크립트 문법" bash -n "$W/bootstrap.sh"
kpctl bootstrap -group fleet -cloud-init > "$W/bootstrap.yaml"
check "cloud-init 형식" bash -c "head -1 '$W/bootstrap.yaml' | grep -qx '#cloud-config'"
check "cloud-init 안의 스크립트가 같음" bash -c "grep -A1 'encoding: b64' '$W/bootstrap.yaml' >/dev/null; awk '/content:/ {print \$2}' '$W/bootstrap.yaml' | base64 -d | cmp - '$W/bootstrap.sh'"
check "묶음은 토큰 필요" test "$(curl -s -o /dev/null -w '%{http_code}' "$KPCTL_URL/api/bootstrap/agent.tar.gz")" = 401
check "관리자 토큰으로는 묶음 못 받음" test "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $ADMIN" "$KPCTL_URL/api/bootstrap/agent.tar.gz")" = 401
curl -sf -H 'Authorization: Bearer enroll-fleet-01234567890' "$KPCTL_URL/api/bootstrap/agent.tar.gz" | tar tz > "$W/out"
check "묶음에 에이전트 포함, 심볼릭 링크 제외" bash -c "grep -qx agent/kpctl-agent '$W/out' && ! grep -q leak '$W/out'"
# 실행 머신의 실제 컨트롤러 설정·로그를 건드리지 않도록 절대 경로만 임시 경로로 바꿉니다.
mkdir -p "$W/bootstrap-root/etc/kpctl"
sed -e "s|/etc/kpctl/|$W/bootstrap-root/etc/kpctl/|g" \
    -e "s|/var/log|$W/bootstrap-root/var/log|g" \
    -e "s|/etc/hosts|$W/bootstrap-root/etc/hosts|g" "$W/bootstrap.sh" > "$W/bootstrap-test.sh"
touch "$W/bootstrap-root/etc/hosts"
touch "$W/bootstrap-root/etc/kpctl/controller.json"
if bash "$W/bootstrap-test.sh" >"$W/out" 2>&1; then die "컨트롤러 자동 등록을 허용함"; fi
check "컨트롤러 자동 등록 차단" grep -q '등록하지 않습니다' "$W/out"
rm "$W/bootstrap-root/etc/kpctl/controller.json"
bash "$W/bootstrap-test.sh" >"$W/out" 2>&1 || die "자동 등록 스크립트 실패"
check "스크립트가 묶음을 받아 설치 스크립트를 토큰과 함께 실행" bash -c "grep -qx 'url=$KPCTL_URL' '$W/bootstrap.out' && grep -qx 'token=enroll-fleet-01234567890' '$W/bootstrap.out' && grep -qx 'from=agent' '$W/bootstrap.out'"
check "묶음 전달 감사 로그" grep -q '에이전트 묶음 전달' "$W/ctl-data/audit.log"
unset KPCTL_TOKEN_DIR

echo
echo "모든 테스트 통과"; echo; echo "--- kpctl status 예시 ---"; kpctl status
