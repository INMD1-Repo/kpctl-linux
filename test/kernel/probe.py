#!/usr/bin/env python3
"""Read-only health and boot-persistence evidence for livepatch acceptance."""
import hashlib
import json
from pathlib import Path
import subprocess


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def probe():
    kernel = Path("/proc/sys/kernel/osrelease").read_text().strip()
    patches = []
    for directory in sorted(Path("/sys/kernel/livepatch").iterdir()):
        patches.append({"name": directory.name,
                        "enabled": (directory / "enabled").read_text().strip(),
                        "transition": (directory / "transition").read_text().strip()})
    installed = {p.name: digest(p) for p in Path("/var/lib/kpatch", kernel).glob("*.ko")}
    units = {}
    for unit in ["kpatch.service", "kpctl-agent.service", "ssh.service"]:
        raw = subprocess.check_output(["systemctl", "show", unit, "-p", "ActiveState,Result,ExecMainStatus,ExecMainStartTimestampMonotonic"], text=True)
        units[unit] = dict(line.split("=", 1) for line in raw.splitlines() if "=" in line)
    return {"kernel": kernel, "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
            "boot_loader_enabled": subprocess.run(["systemctl", "is-enabled", "--quiet", "kpatch.service"]).returncode == 0,
            "tainted": int(Path("/proc/sys/kernel/tainted").read_text()),
            "boot_files": {p.name: digest(p) for p in [Path("/boot/vmlinuz-"+kernel), Path("/boot/initrd.img-"+kernel), Path("/boot/config-"+kernel)]},
            "patches": patches, "installed": installed, "units": units}


if __name__ == "__main__":
    print(json.dumps(probe(), sort_keys=True))
