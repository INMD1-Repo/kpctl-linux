#!/usr/bin/env python3
"""Opt-in rootless image smoke test; uses only a temporary C source and cache."""

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def manifest(root):
    return {
        str(path.relative_to(root)): (digest(path), path.stat().st_mtime_ns)
        for path in root.rglob("*")
        if path.is_file()
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    args = parser.parse_args()
    if os.geteuid() == 0:
        raise SystemExit("run as the rootless builder account")
    with tempfile.TemporaryDirectory(
        prefix="kpctl-readonly-cache-review-"
    ) as temporary:
        root = Path(temporary)
        os.chdir(root)
        cache, work, inputs = [root / name for name in ("cache", "work", "inputs")]
        for path in (cache, work, work / "tmp", inputs):
            path.mkdir()
        source = inputs / "probe.c"
        source.write_text("int cache_probe(int x) { return x + 1; }\n")
        (inputs / "ccache.conf").write_text("")
        base = [
            "podman",
            "--cgroup-manager=cgroupfs",
            "run",
            "--cgroups=disabled",
            "--rm",
            "--pull=never",
            "--network=none",
            "--http-proxy=false",
            "--read-only",
            "--cap-drop=all",
            "--security-opt=no-new-privileges",
            "--userns=keep-id",
            "--user",
            f"{os.getuid()}:{os.getgid()}",
            "--tmpfs=/tmp:rw,nosuid,nodev,size=64m",
            "--workdir=/var/lib/kpctl-builder",
            "--volume",
            f"{work}:/var/lib/kpctl-builder:rw",
            "--volume",
            f"{inputs}:/inputs:ro",
            "--env=PATH=/usr/lib/ccache:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "--env=CCACHE_DIR=/ccache",
            "--env=CCACHE_CONFIGPATH=/inputs/ccache.conf",
            "--env=CCACHE_TEMPDIR=/var/lib/kpctl-builder/tmp",
            "--env=CCACHE_COMPILERCHECK=content",
            "--env=CCACHE_STATS=1",
            "--env=CCACHE_STATSLOG=/var/lib/kpctl-builder/stats.log",
            "--env=CCACHE_NOHARDLINK=1",
            "--env=CCACHE_SLOPPINESS=",
            "--env=CCACHE_LOGFILE=/var/lib/kpctl-builder/cache.log",
            "--entrypoint=gcc",
        ]

        def compile(readonly):
            command = base + [
                "--volume",
                f"{cache}:/ccache:" + ("ro" if readonly else "rw"),
            ]
            if readonly:
                command += ["--env=CCACHE_READONLY=1"]
            command += [
                args.image,
                "-g",
                "-c",
                "/inputs/probe.c",
                "-o",
                "/var/lib/kpctl-builder/probe.o",
            ]
            result = subprocess.run(command, text=True, capture_output=True, timeout=30)
            if result.returncode:
                raise RuntimeError(result.stderr[-4000:])
            return digest(work / "probe.o")

        try:
            first = compile(False)
            before = manifest(cache)
            for path in cache.rglob("*"):
                path.chmod(0o500 if path.is_dir() else 0o400)
            cache.chmod(0o500)
            (work / "cache.log").write_text("")
            second = compile(True)
            counts = Counter(
                line
                for line in (work / "stats.log").read_text().splitlines()
                if not line.startswith("#")
            )
            measured_hits = (
                counts["direct_cache_hit"] + counts["preprocessed_cache_hit"]
            )
            if measured_hits < 1 or counts["cache_miss"] < 1:
                raise RuntimeError(
                    "separate stats log did not record baseline miss and readonly hit"
                )
            log = (work / "cache.log").read_text()
            hit = (
                "Succeeded getting cached result" in log
                or "cache_hit" in log
                or "cache hit" in log.lower()
            )
            if first != second or not hit or manifest(cache) != before:
                raise RuntimeError("readonly cache hit failed:\n" + log[-4000:])
            source.write_text("int cache_probe(int x) { return x + 2; }\n")
            third = compile(True)
            if third == second or manifest(cache) != before:
                raise RuntimeError(
                    "changed source reused a stale object or mutated the cache"
                )
            print(
                json.dumps(
                    {
                        "image": args.image,
                        "cache_hit": hit,
                        "identical_unpatched_object": first == second,
                        "changed_source_compiled": third != second,
                        "readonly_cache_unchanged": manifest(cache) == before,
                        "cache_files": len(before),
                        "measured_hits": measured_hits,
                        "measured_misses": counts["cache_miss"],
                    },
                    sort_keys=True,
                )
            )
        finally:
            cache.chmod(0o700)
            for path in cache.rglob("*"):
                path.chmod(0o700 if path.is_dir() else 0o600)


if __name__ == "__main__":
    main()
