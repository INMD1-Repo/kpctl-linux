#!/usr/bin/env bash
set -euo pipefail
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=deploy/testvm/qemu/common.sh
source "$script_dir/common.sh"

[[ $# -eq 6 ]] || fail 'usage: create.sh NAME DISK VARS FIRMWARE MEMORY CPUS'
vm_id=$1
disk=$2
vars=$3
firmware=$4
memory=$5
cpus=$6
validate_id "$vm_id"
[[ $memory =~ ^[1-9][0-9]*$ && $cpus =~ ^[1-9][0-9]*$ ]] || fail 'memory and cpus must be positive integers'
[[ -f $disk && -r $disk ]] || fail "disk image does not exist or is unreadable: $disk"
disk=$(realpath -- "$disk")
case "$firmware" in
    sb_on) code=/usr/share/OVMF/OVMF_CODE_4M.secboot.fd ;;
    sb_off) code=/usr/share/OVMF/OVMF_CODE_4M.fd ;;
    bios) code= ;;
    *) fail "unknown firmware: $firmware" ;;
esac
if [[ $firmware = bios ]]; then
    [[ -z $vars ]] || fail 'bios must not specify VARS'
else
    [[ -f $code && -r $code ]] || fail "OVMF firmware missing: $code (install Ubuntu ovmf)"
    [[ -n $vars && -f $vars && -r $vars ]] || fail "UEFI VARS image missing or unreadable: $vars"
    vars=$(realpath -- "$vars")
fi

for binary in qemu-system-x86_64 qemu-img python3 flock realpath; do
    command -v "$binary" >/dev/null || fail "required command missing: $binary"
done
cpu_args=(-enable-kvm -cpu host)
if [[ ! -c /dev/kvm || ! -r /dev/kvm || ! -w /dev/kvm ]]; then
    [[ ${KPCTL_TESTVM_ALLOW_TCG:-false} = true ]] || fail '/dev/kvm is unavailable; enable nested KVM or use a dedicated test node (TCG requires allow_tcg=true)'
    cpu_args=(-accel tcg -cpu max)
    printf 'testvm: WARNING: using TCG; controller must multiply boot_timeout by four; CPU features can differ\n' >&2
fi

listen_addr=${KPCTL_TESTVM_LISTEN_ADDR:-127.0.0.1}
port_range=${KPCTL_TESTVM_PORT_RANGE:-2200-2299}
max_concurrent=${KPCTL_TESTVM_MAX_CONCURRENT:-2}
[[ $port_range =~ ^([0-9]+)-([0-9]+)$ ]] || fail 'port_range must look like 2200-2299'
port_first=${BASH_REMATCH[1]}
port_last=${BASH_REMATCH[2]}
[[ $max_concurrent =~ ^[1-9][0-9]*$ ]] || fail 'max_concurrent must be a positive integer'
python3 - "$listen_addr" "$port_first" "$port_last" <<'PY'
import ipaddress, sys
ipaddress.ip_address(sys.argv[1])
if not 1 <= int(sys.argv[2]) <= int(sys.argv[3]) <= 65535:
    raise SystemExit('testvm: port_range must be within 1-65535')
PY

if [[ ${KPCTL_TESTVM_SEED_ISO:-false} = true ]]; then
    command -v cloud-localds >/dev/null || fail 'seed_iso requires cloud-localds (cloud-image-utils)'
    [[ -f ${KPCTL_TESTVM_SSH_PUBLIC_KEY:-} ]] || fail 'seed_iso requires KPCTL_TESTVM_SSH_PUBLIC_KEY pointing to a public-key file'
fi

init_root
vm_directory "$vm_id"
[[ ${#vm_dir} -lt 90 ]] || fail 'VM directory path is too long for the QMP Unix socket'
# Serialize allocation through QEMU startup so another creator cannot claim the
# same port before QEMU has bound it. Drop the lock while waiting for capacity.
while true; do
    lock_root
    [[ ! -e $vm_dir ]] || fail "VM directory already exists: $vm_dir"
    running=0
    for other_dir in "$vm_root"/kpctl-test-*; do
        [[ -d $other_dir && ! -L $other_dir && -r $other_dir/pid ]] || continue
        other_id=${other_dir##*/}
        other_pid=$(cat -- "$other_dir/pid")
        if pid_matches "$other_pid" "$other_id"; then
            running=$((running + 1))
        fi
    done
    if (( running < max_concurrent )); then break; fi
    flock -u 9
    exec 9>&-
    sleep 1
done

port=$(python3 - "$vm_root" "$listen_addr" "$port_first" "$port_last" <<'PY'
import ipaddress, pathlib, socket, sys
root, address, first, last = sys.argv[1:]
reserved = set()
for path in pathlib.Path(root).glob('kpctl-test-*/port'):
    try:
        reserved.add(int(path.read_text().strip()))
    except (OSError, ValueError):
        pass
family = socket.AF_INET6 if ipaddress.ip_address(address).version == 6 else socket.AF_INET
for port in range(int(first), int(last) + 1):
    if port in reserved:
        continue
    try:
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.bind((address, port))
        print(port)
        break
    except OSError:
        continue
else:
    raise SystemExit('testvm: no free SSH port in port_range')
PY
)
mkdir -- "$vm_dir"
cleanup_failure() {
    status=$?
    trap - EXIT HUP INT TERM
    flock -u 9
    exec 9>&-
    if (( status != 0 )); then
        "$script_dir/delete.sh" "$vm_id" || true
    fi
    exit "$status"
}
trap cleanup_failure EXIT
trap 'exit 130' INT
trap 'exit 143' HUP TERM
printf '%s\n' "$port" >"$vm_dir/port"
qemu-img create -f qcow2 -F qcow2 -b "$disk" "$vm_dir/overlay.qcow2" >&2

firmware_args=(-machine q35)
if [[ $firmware != bios ]]; then
    cp -- "$vars" "$vm_dir/vars.fd"
    firmware_args+=(-drive "if=pflash,format=raw,unit=0,readonly=on,file=$(qemu_path "$code")"
                    -drive "if=pflash,format=raw,unit=1,file=$(qemu_path "$vm_dir/vars.fd")")
    if [[ $firmware = sb_on ]]; then
        firmware_args[1]=q35,smm=on
        firmware_args+=(-global 'driver=cfi.pflash01,property=secure,value=on')
    fi
fi

seed_args=()
if [[ ${KPCTL_TESTVM_SEED_ISO:-false} = true ]]; then
    python3 - "$vm_dir" "$vm_id" "${KPCTL_TESTVM_SSH_USER:-ubuntu}" "$KPCTL_TESTVM_SSH_PUBLIC_KEY" <<'PY'
import json, pathlib, re, sys
directory, vm_id, username, keyfile = sys.argv[1:]
if not re.fullmatch(r'[a-z_][a-z0-9_-]*', username):
    raise SystemExit('testvm: invalid SSH user')
key = pathlib.Path(keyfile).read_text().strip()
if '\n' in key or not key.startswith(('ssh-', 'ecdsa-', 'sk-')):
    raise SystemExit('testvm: expected one SSH public key')
root = pathlib.Path(directory)
# JSON is valid YAML. cloud-init accepts a cloud-config document in this format.
config = {'users': [{'name': username, 'groups': ['sudo'],
                    'sudo': 'ALL=(ALL) NOPASSWD:ALL', 'shell': '/bin/bash',
                    'lock_passwd': True, 'ssh_authorized_keys': [key]}],
          'ssh_pwauth': False, 'disable_root': True}
(root / 'user-data').write_text('#cloud-config\n' + json.dumps(config) + '\n')
(root / 'meta-data').write_text(json.dumps({'instance-id': vm_id, 'local-hostname': vm_id}) + '\n')
PY
    cloud-localds "$vm_dir/seed.iso" "$vm_dir/user-data" "$vm_dir/meta-data" >&2
    seed_args=(-drive "file=$(qemu_path "$vm_dir/seed.iso"),format=raw,media=cdrom,readonly=on")
fi
forward_addr=$listen_addr
if [[ $forward_addr = *:* ]]; then forward_addr="[$forward_addr]"; fi
qemu-system-x86_64 -name "$vm_id" "${firmware_args[@]}" "${cpu_args[@]}" \
    -m "$memory" -smp "$cpus" \
    -drive "if=virtio,format=qcow2,file=$(qemu_path "$vm_dir/overlay.qcow2")" \
    "${seed_args[@]}" \
    -netdev "user,id=n0,hostfwd=tcp:$forward_addr:$port-:22" -device virtio-net-pci,netdev=n0 \
    -daemonize -pidfile "$vm_dir/pid" -display none -serial "file:$(qemu_path "$vm_dir/console.log")" \
    -qmp "unix:$(qemu_path "$vm_dir/qmp.sock"),server,nowait" 9>&-
python3 - "$listen_addr" "$port" "$vm_id" <<'PY'
import json, sys
host, port, vm_id = sys.argv[1:]
print(json.dumps({'host': host, 'port': int(port), 'id': vm_id}))
PY
