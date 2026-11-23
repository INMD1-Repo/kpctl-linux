#!/bin/bash
# 호스트에서 에이전트 제거 (root 로 실행)
#
#   sudo ./uninstall-agent.sh                  에이전트만 제거. 적용 중인 라이브패치는 그대로 둠
#   sudo ./uninstall-agent.sh --remove-patches 우리(kpctl_) 라이브패치도 내리고 설치본 삭제
#
# 기본값이 "패치 유지"인 이유: 패치를 내리면 막아 둔 CVE 가 다시 열리고,
# 실행 중인 커널을 바꾸는 작업이기도 하기 때문입니다.
#
# 그대로 두는 것: kpatch 패키지, 커널 고정(apt-mark hold), /etc/kpctl/reboot-hook.sh
set -uo pipefail

REMOVE_PATCHES=0
[ "${1:-}" = "--remove-patches" ] && REMOVE_PATCHES=1
[ "$(id -u)" = 0 ] || { echo "root 로 실행하세요"; exit 1; }

echo "■ 에이전트 중지"
systemctl disable --now kpctl-agent 2>/dev/null || true

if [ $REMOVE_PATCHES = 1 ]; then
  echo "■ kpctl_ 라이브패치 내리기"
  for d in /sys/kernel/livepatch/kpctl_* /sys/module/kpctl_*; do
    [ -e "$d" ] || continue
    n=$(basename "$d")
    [ -e "/sys/module/$n" ] || continue   # 이미 내려감
    if kpatch unload "$n" >/dev/null 2>&1 || rmmod "$n" 2>/dev/null; then
      echo "  내림: $n"
    else
      echo "  !! $n 내리기 실패 (kpatch list 로 확인하세요)"
    fi
  done
  rm -fv /var/lib/kpatch/*/kpctl_*.ko
else
  echo "■ 라이브패치는 유지합니다 (내리려면 --remove-patches)"
  ls /sys/kernel/livepatch/ 2>/dev/null | grep '^kpctl_' | sed 's/^/  적용 중: /' || true
fi

echo "■ 파일 삭제"
rm -fv /usr/local/bin/kpctl-agent \
       /etc/systemd/system/kpctl-agent.service \
       /etc/kpctl/agent.json /etc/kpctl/ca.crt /etc/kpctl/mirrors.list \
       /usr/local/sbin/kpctl-prepare-kernel \
       /etc/apt/apt.conf.d/99kpctl-no-reboot \
       /etc/needrestart/conf.d/99kpctl.conf
rm -rf /var/lib/kpctl-agent /var/cache/kpctl-apt-mirror
systemctl daemon-reload 2>/dev/null || true
# kpctl install 이 컨트롤러 이름을 못 찾을 때 넣은 줄 ("IP 이름 # kpctl"). cloud-init 템플릿에 넣은 줄도 지웁니다
for f in /etc/hosts /etc/cloud/templates/hosts.*.tmpl; do
  if [ -f "$f" ] && grep -q '# kpctl$' "$f"; then
    grep -v '# kpctl$' "$f" > "$f.kpctl-new"; cat "$f.kpctl-new" > "$f"
    rm -f "$f.kpctl-new"
    echo "$f 에서 kpctl 컨트롤러 줄 삭제"
  fi
done

echo "완료."
echo "그대로 둔 것: kpatch 패키지, /etc/kpctl/reboot-hook.sh, 커널 고정:"
apt-mark showhold 2>/dev/null | sed 's/^/  hold: /' || true
echo "커널 고정을 풀려면: apt-mark unhold <패키지>"
