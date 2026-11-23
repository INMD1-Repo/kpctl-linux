#!/usr/bin/env python3
"""Opt-in real create-diff-object regression; never loads a kernel module."""
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile


def run(*args, cwd=None):
    return subprocess.check_output(args, cwd=cwd, stderr=subprocess.STDOUT)


def verify(tool):
    tool = str(Path(tool).resolve())
    with tempfile.TemporaryDirectory(prefix="kpctl-cold-") as temporary:
        root = Path(temporary)
        flags = ["-O2", "-ffunction-sections", "-fdata-sections", "-fno-pie", "-fno-pic",
                 "-mcmodel=kernel", "-fsanitize=bool", "-fno-asynchronous-unwind-tables",
                 "-fno-unwind-tables", "-fno-omit-frame-pointer", "-fno-optimize-sibling-calls"]

        def build(name, profile=False, added=False, line=100, value=7):
            directory = root / name
            directory.mkdir()
            extra = "__attribute__((noinline)) int added(void) { return input; }\n" if added else ""
            text = ("_Bool input;\n" + extra + f'#line {line} "unit.c"\n' +
                    f"__attribute__((noinline)) int parent(void) {{ return input ? {value} : 9; }}\n")
            (directory / "unit.c").write_text(text)
            run(os.environ.get("CC", "gcc"), *flags, *(["-pg", "-mfentry"] if profile else []),
                "-c", "unit.c", "-o", "unit.o", cwd=directory)
            return directory / "unit.o"

        exports = root / "Module.symvers"
        exports.write_text("0x00000001\t__fentry__\tvmlinux\tEXPORT_SYMBOL_GPL\n"
                           "0x00000002\t__ubsan_handle_load_invalid_value\tvmlinux\tEXPORT_SYMBOL_GPL\n")

        def compare(original, patched, name, expected):
            symbols = root / (name + ".symtab")
            symbols.write_bytes(run("readelf", "--wide", "--symbols", str(original)))
            result = subprocess.run([tool, str(original), str(patched), "vmlinux", str(symbols),
                                     str(exports), "kpctl_cold_test", str(root / (name + ".o"))],
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            output = result.stdout.decode()
            if (result.returncode == 0) != expected:
                raise AssertionError(f"{name}: exit={result.returncode}\n{output}")
            if not expected and "doesn't have patchable function entry" not in output:
                raise AssertionError(f"{name}: failed for unexpected reason\n{output}")
            return output

        original = build("original")
        patched = build("renumbered", added=True)
        # Verify this compiler produced the exact relocation-only cold case.
        for label, path in [("original", original), ("renumbered", patched)]:
            run("objcopy", "--dump-section", f".text.unlikely.parent={root / (label + '.cold')}", str(path))
        if (root / "original.cold").read_bytes() != (root / "renumbered.cold").read_bytes():
            raise AssertionError("fixture does not have identical cold instructions")
        output = compare(original, patched, "equal-metadata-no-entry", True)
        if "changed function: parent" in output:
            raise AssertionError("unchanged parent was unnecessarily included")
        compare(original, build("different-line", added=True, line=101), "different-source-location", False)
        compare(original, build("different-code", added=True, value=8), "real-instruction-change", False)

        changed_type = build("different-type", added=True)
        sections = run("readelf", "--wide", "--section-headers", str(changed_type)).decode()
        metadata = re.search(r"\.data\.\.Lubsan_type\d+", sections).group()
        payload = root / "type.data"
        run("objcopy", "--dump-section", f"{metadata}={payload}", str(changed_type))
        contents = bytearray(payload.read_bytes())
        contents[-2] ^= 1
        payload.write_bytes(contents)
        run("objcopy", "--update-section", f"{metadata}={payload}", str(changed_type))
        compare(original, changed_type, "different-type-description", False)

        profiled_original = build("profiled-original", profile=True)
        profiled_patched = build("profiled-changed", profile=True, added=True, line=101)
        output = compare(profiled_original, profiled_patched, "changed-cold-needs-profiled-parent", True)
        if "changed function: parent" not in output:
            raise AssertionError("changed cold relocations did not include their profiled parent")
        print("PASS: 5 cold/UBSAN ELF cases; real metadata/code changes still require fentry")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: python3 kpctl-kpatch-cold-test.py /path/to/create-diff-object")
    verify(sys.argv[1])
