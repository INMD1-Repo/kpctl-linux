#!/usr/bin/env python3
"""Bounded CPU, memory, file and UNIX-socket load for dedicated canaries."""
import array
import hashlib
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import threading
import time


def run(directory, seconds):
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    available = int(next(line.split()[1] for line in Path("/proc/meminfo").read_text().splitlines() if line.startswith("MemAvailable:"))) * 1024
    memory = bytearray(b"k") * min(256 * 1024 * 1024, max(16 * 1024 * 1024, available // 8))
    expected = hashlib.sha256(memory).digest()
    stop, errors = threading.Event(), []
    counts = {"hashes": 0, "file_rounds": 0, "socket_rounds": 0, "rights_cycles": 0}
    started = time.monotonic()

    def guarded(fn):
        try:
            fn()
        except Exception as error:
            errors.append(str(error))
            stop.set()

    def cpu():
        while not stop.is_set():
            if hashlib.sha256(memory).digest() != expected:
                raise RuntimeError("memory checksum changed")
            counts["hashes"] += 1

    def files():
        payload = b"kpctl-acceptance" * 4096
        with tempfile.TemporaryFile(dir=directory) as handle:
            while not stop.is_set():
                handle.seek(0); handle.write(payload); handle.flush(); os.fsync(handle.fileno())
                handle.seek(0)
                if handle.read(len(payload)) != payload:
                    raise RuntimeError("file data mismatch")
                counts["file_rounds"] += 1
                stop.wait(.5)

    def sockets():
        payload = b"canary" * 1024
        while not stop.is_set():
            a, b = socket.socketpair()
            try:
                a.sendall(payload)
                received = bytearray()
                while len(received) < len(payload):
                    received += b.recv(len(payload)-len(received))
                if received != payload:
                    raise RuntimeError("socket data mismatch")
                counts["socket_rounds"] += 1
            finally:
                a.close(); b.close()
            # Only our descriptors are passed; the unread self-reference exercises UNIX GC.
            a, b = socket.socketpair()
            try:
                a.sendmsg([b"x"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [b.fileno()]))])
                counts["rights_cycles"] += 1
            finally:
                a.close(); b.close()
            stop.wait(.025)

    threads = [threading.Thread(target=guarded, args=(fn,)) for fn in [cpu, cpu, files, sockets]]
    for thread in threads:
        thread.start()
    try:
        while time.monotonic()-started < seconds and not errors:
            stop.wait(min(5, max(0, seconds-(time.monotonic()-started))))
    finally:
        stop.set()
        for thread in threads:
            thread.join(timeout=15)
    result = {"complete": not errors and all(not t.is_alive() for t in threads), "seconds": time.monotonic()-started,
              "memory_bytes": len(memory), "counts": counts, "errors": errors}
    (directory / "workload.json").write_text(json.dumps(result, indent=2)+"\n")
    print(json.dumps(result), flush=True)
    return 0 if result["complete"] and all(counts.values()) else 1


if __name__ == "__main__":
    duration = int(sys.argv[2])
    if not 1 <= duration <= 86400:
        raise SystemExit("duration outside validation limits")
    raise SystemExit(run(Path(sys.argv[1]), duration))
