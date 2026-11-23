#!/bin/sh
# 재부팅 훅 예시 — 에이전트가 관리자 재부팅 승인(kpctl host reboot)을 받으면 실행합니다.
# 컨트롤러는 cordon 상태 + VM 0대일 때만 승인을 내주지만, 여기서 한 번 더 확인하는 것을 권합니다.
#
# 이 예시: 부트로더가 선택한 디스크 커널로 정상 재부팅합니다.
# 새 커널 패키지와 부트로더 기본 항목은 승인 전에 확인하세요.
set -eu

[ "${KPCTL_REBOOT_APPROVED:-}" = 1 ] && [ -n "${KPCTL_REBOOT_ID:-}" ] && \
  [ -n "${KPCTL_TARGET_KERNEL:-}" ] && [ -n "${KPCTL_TARGET_ID:-}" ] || {
  echo "관리자 승인을 재확인한 에이전트만 재부팅할 수 있습니다" >&2
  exit 1
}

# (권장) 이 호스트에 VM 이 정말 없는지 로컬에서 한 번 더 확인
# 자체 VM 시스템에 맞게 바꾸세요. 예: QEMU 프로세스 수 확인
# pgrep 의 기본 comm 은 15자로 잘립니다. 전체 qemu-system-x86_64 를
# 정확히 비교하면 실행 중인 QEMU 를 놓칩니다. 긴 이름은 접두사로 확인합니다.
if pgrep -x 'qemu-system-.*|qemu-kvm|kvm|firecracker|cloud-hypervis.*|crosvm|bhyve|lxc-start|conmon|containerd-shim.*' >/dev/null 2>&1; then
  echo "VM 또는 컨테이너 프로세스가 남아 있어 재부팅하지 않습니다" >&2
  exit 1
else
  status=$?
  if [ "$status" != 1 ]; then
    echo "VM 프로세스 확인에 실패해 재부팅하지 않습니다" >&2
    exit 1
  fi
fi

# 새 커널 패키지는 미리 설치해 두어야 합니다 (apt-mark hold 해제 → 설치 → 다시 hold)
systemctl reboot
