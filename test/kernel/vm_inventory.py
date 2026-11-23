#!/usr/bin/env python3
"""Conservative local workload inventory used by dedicated test-host reboots."""
import os
import sys


def count_workloads(proc="/proc"):
    found = set()
    exact = {"qemu-kvm", "kvm", "firecracker", "cloud-hypervisor", "crosvm", "bhyve", "lxc-start", "conmon"}
    for pid in os.listdir(proc):
        if not pid.isdigit():
            continue
        try:
            with open(os.path.join(proc, pid, "cmdline"), "rb") as handle:
                argv0 = handle.read(4096).split(b"\0", 1)[0].decode(errors="replace")
            if not argv0:  # kernel thread
                continue
            executable = os.readlink(os.path.join(proc, pid, "exe"))
        except FileNotFoundError:  # process exited while taking inventory
            continue
        names = {os.path.basename(argv0), os.path.basename(executable).removesuffix(" (deleted)")}
        if any(name in exact or name.startswith(("qemu-system-", "containerd-shim")) for name in names):
            found.add(pid)
    return len(found)


if __name__ == "__main__":
    try:
        print(count_workloads())
    except (OSError, ValueError) as error:
        print("workload inventory incomplete: " + str(error), file=sys.stderr)
        sys.exit(2)
