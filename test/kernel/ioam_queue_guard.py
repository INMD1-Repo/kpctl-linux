#!/usr/bin/env python3
"""Post-patch-only IOAM queue boundary check using the matching upstream selftest.

Never run against an unpatched kernel. The separately built parser adds a
Beta-node bit6 == IOAM6_U32_UNAVAILABLE assertion; the stock parser skips it.
Network configuration is confined to the selftest's new network namespaces.
"""
import hashlib
import os
from pathlib import Path
import re
import subprocess
import sys


def main(directory, module, expected_sha, parser_sha):
    kernel = Path("/proc/sys/kernel/osrelease").read_text().strip()
    live = Path("/sys/kernel/livepatch", module)
    if (live/"enabled").read_text().strip() != "1" or (live/"transition").read_text().strip() != "0":
        raise ValueError("required livepatch is not active")
    binary = Path("/var/lib/kpatch", kernel, module+".ko")
    if hashlib.sha256(binary.read_bytes()).hexdigest() != expected_sha:
        raise ValueError("required patch digest differs")
    if hashlib.sha256((directory/"ioam6_parser").read_bytes()).hexdigest() != parser_sha:
        raise ValueError("queue assertion parser digest differs")
    script = (directory/"ioam6.sh").read_text().split("\nnpassed=0\n")[0]
    old = "ip link add name ioam-veth-alpha netns $ioam_node_alpha type veth \\\n         peer name ioam-veth-betaL netns $ioam_node_beta"
    new = "ip link add name ioam-veth-alpha numtxqueues 8 numrxqueues 8 netns $ioam_node_alpha type veth \\\n         peer name ioam-veth-betaL numtxqueues 8 numrxqueues 8 netns $ioam_node_beta"
    if script.count(old) != 1:
        raise ValueError("unexpected upstream selftest layout")
    script = script.replace(old, new)
    script += '''
npassed=0; nfailed=0
trap 'cleanup >/dev/null 2>&1' EXIT
setup
ip netns exec "$ioam_node_alpha" tc qdisc add dev veth0 clsact || exit 1
ip netns exec "$ioam_node_alpha" tc filter add dev veth0 egress matchall action skbedit queue_mapping 7 || exit 1
ip -netns "$ioam_node_beta" -details link show veth0
ip -netns "$ioam_node_beta" -details link show veth1
fwd_full_supp_trace inline
ip netns exec "$ioam_node_alpha" tc -s filter show dev veth0 egress
log_results
test "$npassed" = 1 && test "$nfailed" = 0
'''
    env = dict(os.environ, KPCTL_QUEUE_GUARD="1")
    result = subprocess.run(["bash"], input=script, cwd=directory, env=env, text=True, timeout=60, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    print(result.stdout, end="", flush=True)
    if result.returncode or not re.search(r"^- Tests passed: 1$", result.stdout, re.M) or not re.search(r"^- Tests failed: 0$", result.stdout, re.M):
        raise RuntimeError("queue boundary assertion missing or failed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(Path(sys.argv[1]).resolve(), sys.argv[2], sys.argv[3], sys.argv[4]))
