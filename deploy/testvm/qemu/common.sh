#!/usr/bin/env bash
# Shared local-only helpers. The controller talks only to the four command scripts.
set -euo pipefail
umask 077

fail() { printf 'testvm: %s\n' "$*" >&2; exit 1; }

init_root() {
    vm_root=${KPCTL_TESTVM_ROOT:-/var/lib/kpctl/testvm}
    [[ $vm_root = /* && $vm_root != / ]] || fail 'KPCTL_TESTVM_ROOT must be an absolute directory other than /'
    mkdir -p -- "$vm_root"
    vm_root=$(realpath -- "$vm_root")
}

validate_id() {
    [[ ${1:-} =~ ^kpctl-test-[A-Za-z0-9_.-]+$ && ${#1} -le 128 ]] || fail 'invalid VM ID (expected kpctl-test-...)'
}

vm_directory() {
    validate_id "$1"
    vm_dir=$vm_root/$1
    [[ ! -L $vm_dir ]] || fail "refusing symlink VM directory: $vm_dir"
}

lock_root() {
    exec 9>"$vm_root/.lock"
    flock -x 9
}

# A PID file alone must never authorize killing a process after PID reuse.
pid_matches() {
    python3 - "$1" "$2" <<'PY'
import pathlib, sys
pid, vm_id = sys.argv[1:]
if not pid.isdecimal() or int(pid) <= 1:
    sys.exit(1)
try:
    cmd = pathlib.Path('/proc', pid, 'cmdline').read_bytes().split(b'\0')
except OSError:
    sys.exit(1)
# create.sh sets the VM ID as the exact value following -name.
sys.exit(0 if any(cmd[i] == b'-name' and cmd[i + 1] == vm_id.encode()
                  for i in range(len(cmd) - 1)) else 1)
PY
}

# QMP quit is best effort; process verification and bounded termination follow it.
qmp_quit() {
    python3 - "$1" <<'PY'
import json, socket, sys
try:
    with socket.socket(socket.AF_UNIX) as conn:
        conn.settimeout(1)
        conn.connect(sys.argv[1])
        stream = conn.makefile('rwb', buffering=0)
        def response():
            while True:
                data = json.loads(stream.readline())
                if 'return' in data or 'error' in data:
                    return data
        json.loads(stream.readline())  # QMP greeting
        stream.write(b'{"execute":"qmp_capabilities"}\r\n')
        response()
        stream.write(b'{"execute":"quit"}\r\n')
except (OSError, ValueError):
    pass
PY
}

# QEMU uses a doubled comma to escape commas inside option values.
qemu_path() { printf '%s' "${1//,/,,}"; }
