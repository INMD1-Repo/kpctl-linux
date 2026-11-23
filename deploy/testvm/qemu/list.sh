#!/usr/bin/env bash
set -euo pipefail
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=deploy/testvm/qemu/common.sh
source "$script_dir/common.sh"
[[ $# -eq 0 ]] || fail 'usage: list.sh'
init_root
lock_root
# Include failed/stale directories as well, so startup recovery can clean them.
for vm_dir in "$vm_root"/kpctl-test-*; do
    [[ -d $vm_dir && ! -L $vm_dir ]] || continue
    vm_id=${vm_dir##*/}
    validate_id "$vm_id"
    printf '%s\n' "$vm_id"
done
