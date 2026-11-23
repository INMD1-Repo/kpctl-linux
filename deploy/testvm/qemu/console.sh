#!/usr/bin/env bash
set -euo pipefail
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=deploy/testvm/qemu/common.sh
source "$script_dir/common.sh"
[[ $# -eq 1 ]] || fail 'usage: console.sh ID'
init_root
vm_directory "$1"
lock_root
if [[ -f $vm_dir/console.log ]]; then cat -- "$vm_dir/console.log"; fi
