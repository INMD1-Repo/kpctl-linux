#!/usr/bin/env python3
"""Isolated disk/GRUB fixture: never runs any real bootloader or reboot tool."""
import hashlib
import json
from pathlib import Path
import sys

root, kernel = Path(sys.argv[1]), sys.argv[2]
branch, abi, _ = kernel.rsplit("-", 2)
target = f"{branch}-{int(abi)+1}-generic"
boot = root/"boot"
boot.mkdir(exist_ok=True)
entry = f"gnulinux-advanced-abc>gnulinux-{target}-advanced-abc"
files = {"image_sha256": boot/("vmlinuz-"+target), "initrd_sha256": boot/("initrd.img-"+target),
         "config_sha256": boot/("config-"+target), "grub_sha256": boot/"grub.cfg"}
for key, path in files.items():
    path.write_text(key if key != "grub_sha256" else 'set default="${saved_entry}" ${next_entry} \'gnulinux-advanced-abc\' \''+entry.split(">",1)[1]+"'\n")
fallback=f"gnulinux-advanced-abc>gnulinux-{kernel}-advanced-abc"
result = dict(kernel=target, package_version=f"{branch}-{int(abi)+1}.{int(abi)+1}", entry=entry,fallback_entry=fallback,
              **{key:hashlib.sha256(path.read_bytes()).hexdigest() for key,path in files.items()})
state = root/"state"
state.mkdir(exist_ok=True)
manifest = state/"boot-target.json"
manifest.write_text(json.dumps(result))
manifest.chmod(0o600)
(root/"proc/boot_id").write_text("boot-before")
(root/"grubenv").write_text("")
(root/"saved").write_text(fallback)
for name, script in {
    "grub-reboot": '#!/bin/sh\nprintf "%s" "$2" > "'+str(root/'grubenv')+'"\n',
    "grub-set-default": '#!/bin/sh\nprintf "%s" "$2" > "'+str(root/'saved')+'"\n',
    "grub-editenv": '#!/bin/sh\nif [ "$2" = list ]; then printf "saved_entry="; cat "'+str(root/'saved')+'"; printf "\\nnext_entry="; cat "$1"; else : > "$1"; fi\n',
}.items():
    path = root/name
    path.write_text(script)
    path.chmod(0o755)
