#!/usr/bin/env bash
set -euo pipefail
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=deploy/testvm/qemu/common.sh
source "$script_dir/common.sh"
[[ $# -eq 1 ]] || fail 'usage: delete.sh ID'
init_root
vm_id=$1
vm_directory "$vm_id"
lock_root
[[ -d $vm_dir ]] || exit 0
pid=
if [[ -r $vm_dir/pid ]]; then pid=$(cat -- "$vm_dir/pid"); fi
# A failed/partial daemon startup may leave a QMP socket without its PID file.
# Always request a graceful quit; PID ownership is required only for signals.
qmp_quit "$vm_dir/qmp.sock"
if pid_matches "$pid" "$vm_id"; then
    deadline=$((SECONDS + 10))
    while (( SECONDS < deadline )); do
        if ! pid_matches "$pid" "$vm_id"; then break; fi
        sleep 0.1
    done
    if pid_matches "$pid" "$vm_id"; then
        kill -TERM -- "$pid" 2>/dev/null || true
        deadline=$((SECONDS + 2))
        while (( SECONDS < deadline )); do
            if ! pid_matches "$pid" "$vm_id"; then break; fi
            sleep 0.1
        done
        if pid_matches "$pid" "$vm_id"; then
            kill -KILL -- "$pid" 2>/dev/null || true
        fi
    fi
fi
rm -rf -- "$vm_dir"
