#!/usr/bin/env python3
"""Check upstream test summaries as well as exit codes (ioam6.sh exits 0 on failures)."""
import json
from pathlib import Path
import re
import subprocess
import sys


def execute(command, directory):
    result = subprocess.run(command, cwd=directory, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=240)
    print(result.stdout, end="", flush=True)
    if result.returncode:
        raise RuntimeError("kernel selftest failed: "+command[0])
    return result.stdout


def run(root, kernel):
    if kernel.startswith("6.8."):
        result = json.loads(execute([str(root/"waitid-regression"), "1024"], root))
        if result["stale_noevent_results"] or result["normal_child_results"] != 1024:
            raise RuntimeError("waitid result regression")
        output = execute(["bash", "./ioam6.sh"], root/"ioam")
        if not re.search(r"^- Tests passed: 88$", output, re.M) or not re.search(r"^- Tests failed: 0$", output, re.M):
            raise RuntimeError("IOAM test summary missing, skipped or failed")
    elif kernel.startswith("7.0."):
        for name, count in [("scm_rights", 40), ("scm_inq", 3)]:
            output = execute([str(root/"unix"/name)], root/"unix")
            if f"# Totals: pass:{count} fail:0 xfail:0 xpass:0 skip:0 error:0" not in output:
                raise RuntimeError("UNIX test summary missing, skipped or failed")
    else:
        raise ValueError("acceptance suite has no tests for this kernel")


if __name__ == "__main__":
    run(Path(sys.argv[1]).resolve(), Path("/proc/sys/kernel/osrelease").read_text().strip())
