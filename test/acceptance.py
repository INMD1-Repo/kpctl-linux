#!/usr/bin/env python3
"""Pinned, fail-closed acceptance continuation for the dedicated four-host lab.

Never enables global automatic rollout, clears holds, shortens soak policy,
uses force, or selects a newer build. Credentials stay in the existing root
configuration. A failed run requires investigation before a new run.
"""
import datetime as dt
import grp
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import time
import urllib.error
import urllib.request
import ssl
import http.client
import signal


UTC = dt.timezone.utc
ERRORS = re.compile(r"BUG:|Oops:|Kernel panic|WARNING: CPU:|general protection fault|KASAN:|KCSAN:|soft lockup|hard LOCKUP|rcu[^\n]*stall", re.I)
TRANSIENT = (RuntimeError, urllib.error.URLError, TimeoutError, subprocess.TimeoutExpired, http.client.HTTPException)


def stamp():
    return dt.datetime.now(UTC).isoformat()


def elapsed(start, now):
    return (now-dt.datetime.fromisoformat(start)).total_seconds()


def check_host(host, expected, now):
    override = expected.get("update_now_version", 0)
    if override and (override != expected["version"] or expected.get("update_now_kernel") != expected["kernel"]):
        raise ValueError(expected["hostname"]+": pinned override differs from the release")
    if (host["hostname"] != expected["hostname"] or host["ring"] != expected["ring"] or host.get("cordoned") or host.get("reboot_request_id")
            or (host.get("update_now_version") or 0) != override
            or (host.get("update_now_kernel") or "") != expected.get("update_now_kernel", "")):
        raise ValueError(host["hostname"]+": host policy changed")
    if host["status"]["kernel"] != expected["kernel"] or host["status"]["version"] != expected["version"]:
        raise ValueError(host["hostname"]+": kernel/version changed")
    age = elapsed(host["last_seen"].replace("Z", "+00:00"), now)
    if not -30 <= age <= 120 or host["status"].get("error"):
        raise ValueError(host["hostname"]+": stale/error report")
    loaded = host["status"].get("loaded") or []
    confirmed = not loaded if expected["version"] == 0 else len(loaded) == 1 and loaded[0]["name"] == expected["module"] and loaded[0]["enabled"] and not loaded[0]["transition"]
    if not confirmed:
        raise ValueError(host["hostname"]+": active module not confirmed")
    if host["status"]["tainted"] & ~expected["tainted"]:
        raise ValueError(host["hostname"]+": new kernel taint")


def eligible(start, now, minimum_minutes):
    # Keep the original 24-hour acceptance floor even if settings are lowered.
    return elapsed(start, now) >= max(86400, minimum_minutes*60)


class Run:
    def __init__(self, manifest):
        self.manifest = json.loads(manifest.read_text())
        self.root = Path(self.manifest["evidence_dir"])
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.state_path = self.root / "state.json"
        self.state = json.loads(self.state_path.read_text()) if self.state_path.exists() else {}
        self.controller = json.loads(Path(self.manifest["controller_config"]).read_text())
        self.tls = ssl.create_default_context(cafile=self.manifest["ca_file"])

    def api(self, path, body=None):
        req = urllib.request.Request(self.manifest["controller_url"]+path,
            data=None if body is None else json.dumps(body).encode(),
            headers={"Authorization": "Bearer "+next(iter(self.controller["admin_tokens"].values())), "Content-Type": "application/json"},
            method="GET" if body is None else "POST")
        try:
            with urllib.request.urlopen(req, context=self.tls, timeout=20) as response:
                return json.load(response)
        except urllib.error.HTTPError as error:
            raise RuntimeError("controller rejected "+path+": "+str(error.code)) from None

    def remote(self, host, command, timeout=35):
        out = subprocess.run(["ssh", "-i", self.manifest["ssh_key"], "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", "-o",
            "UserKnownHostsFile="+self.manifest["known_hosts"], "root@"+host["address"], command], capture_output=True, text=True, timeout=timeout)
        if out.returncode:
            raise RuntimeError(host["hostname"]+": SSH check failed")
        return out.stdout

    def save(self, phase, **updates):
        self.state.update(updates, phase=phase, updated_at=stamp())
        for path, data in [(self.state_path, self.state), (Path(self.manifest["public_status"]),
            {k: v for k, v in self.state.items() if k in ["phase", "started_at", "eligible_after", "updated_at", "completed_at", "error", "checks", "last_action", "targets"]})]:
            temp = path.with_suffix(".tmp")
            with temp.open("w") as handle:
                json.dump(data, handle, indent=2); handle.write("\n"); handle.flush(); os.fsync(handle.fileno())
            os.chown(temp, 0, grp.getgrnam("kpctl").gr_gid)
            temp.chmod(0o640)
            os.replace(temp, path)

    def health(self, rings):
        status = self.api("/api/status")
        if status.get("auto", {}).get("paused"):
            raise ValueError("rollouts were paused; manual review required")
        now = dt.datetime.now(UTC)
        for expected in self.manifest["hosts"]:
            if expected["ring"] not in rings:
                continue
            host = next(h for h in status["hosts"] if h["id"] == expected["id"])
            check_host(host, expected, now)
        for pin in self.manifest["releases"]:
            job = next(j for j in status["jobs"] if j["id"] == pin["job"])
            if job["status"] != "released" or job["module_name"] != pin["module"] or job["sha256"] != pin["sha256"]:
                raise ValueError("pinned release changed")
            track = next(t for t in status["tracks"] if t["kernel"] == pin["kernel"])
            if track["ring_versions"].get("1") != pin["version"]:
                raise ValueError("canary target changed")
        return status

    def node_checks(self, rings, unpatched=False):
        if unpatched:
            status = self.api("/api/status")
        for host in self.manifest["hosts"]:
            if host["ring"] not in rings:
                continue
            if unpatched:
                expected = dict(host, version=0, tainted=host["baseline_tainted"])
                reported = next(h for h in status["hosts"] if h["id"] == host["id"])
                check_host(reported, expected, dt.datetime.now(UTC))
                track = next(t for t in status["tracks"] if t["kernel"] == host["kernel"])
                if track["ring_versions"].get(str(host["ring"]), 0) != 0:
                    raise ValueError(host["hostname"]+": staging target changed before validation")
            info = json.loads(self.remote(host, "python3 /usr/local/libexec/kpctl-acceptance-probe.py"))
            if info["boot_id"] != host["boot_id"] or info["boot_files"] != host["boot_files"]:
                raise ValueError(host["hostname"]+": unexpected reboot or disk kernel change")
            installed = {} if unpatched else {host["module"]+".ko": host["sha256"]}
            patches = [] if unpatched else [{"name": host["module"], "enabled": "1", "transition": "0"}]
            allowed_taint = host["baseline_tainted"] if unpatched else host["tainted"]
            if info["kernel"] != host["kernel"] or info["installed"] != installed:
                raise ValueError(host["hostname"]+": boot installation differs")
            if info["patches"] != patches or info["tainted"] & ~allowed_taint:
                raise ValueError(host["hostname"]+": direct kernel check differs from the healthy report")
            if any((unit["ActiveState"] != "active" and not (name == "kpatch.service" and host["ring"] == 2 and unit["ActiveState"] == "inactive"))
                   or unit["Result"] != "success" or unit["ExecMainStatus"] != "0" for name, unit in info["units"].items()) or not info["boot_loader_enabled"]:
                raise ValueError(host["hostname"]+": required service unhealthy")
            count = self.remote(host, "python3 /usr/local/libexec/kpctl-validation-vm-inventory.py").strip()
            if count != "0":
                raise ValueError(host["hostname"]+": workloads changed during dedicated-host validation")
            logs = self.remote(host, "journalctl -k -b --no-pager -o cat --since "+shlex.quote(self.state["journal_since"]))
            if ERRORS.search(logs):
                (self.root/(host["id"]+"-kernel-error.log")).write_text(logs)
                raise ValueError(host["hostname"]+": kernel error observed")
            if host["ring"] == 1:
                name = host.get("load_unit", "kpctl-soak-20261102.service")
                unit = dict(line.split("=", 1) for line in self.remote(host,
                    "systemctl show "+shlex.quote(name)+" -p ActiveState -p Result -p ExecMainStatus").splitlines())
                if unit["Result"] != "success" or unit["ExecMainStatus"] != "0" or unit["ActiveState"] not in ["active", "inactive"]:
                    raise ValueError(host["hostname"]+": load worker failed")

    def regressions(self, rings, label):
        for host in self.manifest["hosts"]:
            if host["ring"] in rings:
                for index, command in enumerate(host["regressions"]):
                    out = self.remote(host, command, timeout=600)
                    (self.root/(label+"-"+host["id"]+"-"+str(index)+".log")).write_text(out)

    def wait_applied(self, rings, version=2, kernel=None):
        deadline = time.monotonic()+600
        while time.monotonic() < deadline:
            status = self.api("/api/status")
            expected = [x for x in self.manifest["hosts"] if x["ring"] in rings and (kernel is None or x["kernel"] == kernel)]
            selected = [h for h in status["hosts"] if any(h["id"] == x["id"] for x in expected)]
            if len(selected) == len(expected):
                if version == 0:
                    if all(h["status"]["version"] == 0 and not h["status"].get("loaded") and not h["status"].get("error")
                           and -30 <= elapsed(h["last_seen"].replace("Z", "+00:00"), dt.datetime.now(UTC)) <= 120 for h in selected):
                        return
                else:
                    try:
                        self.health(rings)
                        return
                    except ValueError:
                        pass
            time.sleep(10)
        raise RuntimeError("deployment did not settle before the validation deadline")

    def action(self, path, body):
        phase = self.state["phase"]
        self.save(phase, last_action={"path": path, "request": body, "state": "requested", "at": stamp()})
        self.api(path, body)
        record = {"path": path, "request": body, "state": "acknowledged", "at": stamp()}
        self.state.setdefault("actions", []).append(record)
        self.save(phase, last_action=record)

    def rollback_one(self, pin):
        self.node_checks([1, 2])
        path = "/api/kernels/"+pin["kernel"]+"/rollback"
        try:
            self.action(path, {"version": 0})
            self.wait_applied([1, 2], 0, pin["kernel"])
            for host in self.manifest["hosts"]:
                if host["kernel"] != pin["kernel"]:
                    continue
                info = json.loads(self.remote(host, "python3 /usr/local/libexec/kpctl-acceptance-probe.py"))
                if info["patches"] or info["installed"]:
                    raise ValueError(host["hostname"]+": rollback left a loaded or boot-installed patch")
        finally:
            # Restore the already validated target even if a rollback check
            # fails. The agent's own transition/integrity guards still apply.
            for attempt in range(3):
                try:
                    self.action(path, {"version": pin["version"]})
                    break
                except TRANSIENT:
                    if attempt == 2:
                        raise
                    time.sleep(10)
        self.wait_applied([1, 2])

    def run(self):
        if self.state.get("phase") == "complete":
            return
        if self.state.get("phase") == "failed":
            raise ValueError("failed validation requires review; refusing automatic replay")
        if self.state.get("phase") not in [None, "soaking"]:
            raise ValueError("interrupted deployment requires review; refusing automatic replay")
        now = dt.datetime.now(UTC)
        self.state.setdefault("journal_since", self.state.get("started_at", stamp()))
        if "started_at" not in self.state or elapsed(self.state.get("updated_at", stamp()), now) > 120:
            self.state["started_at"] = stamp()  # observation gaps restart the full safety window
        self.health([1])
        self.node_checks([1])
        failures, last_nodes = 0, 0
        minimum = 1440
        while True:
            try:
                settings = self.api("/api/settings")["current"]
                if settings["auto_enabled"]:
                    raise ValueError("rollout policy changed; manual review required")
                minimum = int(settings["min_soak_minutes"].get("2", 0))
                self.health([1])
                if time.monotonic()-last_nodes >= 300:
                    self.node_checks([1]); last_nodes = time.monotonic()
                failures = 0
            except TRANSIENT:
                failures += 1
                if failures >= 3:
                    raise
            deadline = dt.datetime.fromisoformat(self.state["started_at"])+dt.timedelta(seconds=max(86400, minimum*60))
            self.save("soaking", eligible_after=deadline.isoformat(), checks=self.manifest["checks"])
            if failures == 0 and eligible(self.state["started_at"], dt.datetime.now(UTC), minimum):
                break
            time.sleep(30)
        for host in self.manifest["hosts"]:
            if host["ring"] == 1:
                work = json.loads(self.remote(host, "cat /var/lib/kpctl-agent/acceptance-20261102/workload/workload.json"))
                if not work["complete"] or work["errors"] or work["seconds"] < 86395 or not all(work["counts"].values()):
                    raise ValueError("24-hour load test did not complete")
        self.node_checks([2], unpatched=True)
        self.health([1])
        self.save("promoting")
        for pin in self.manifest["releases"]:
            self.action("/api/kernels/"+pin["kernel"]+"/promote", {"ring": 2, "force": False})
        self.wait_applied([1, 2]); self.node_checks([1, 2])
        self.regressions([2], "ring2")
        self.save("rollback_test")
        for pin in self.manifest["releases"]:
            self.rollback_one(pin)
        self.wait_applied([1, 2]); self.node_checks([1, 2])
        self.regressions([1, 2], "restored")
        self.save("complete", completed_at=stamp())


class ObserveRun(Run):
    """Observe already deployed, pinned releases; never promote or roll back."""

    def api(self, path, body=None):
        if body is not None or path not in ("/api/status", "/api/settings"):
            raise ValueError("observation permits status/settings reads only")
        return super().api(path)

    def action(self, path, body):
        raise ValueError("observation cannot change deployments")

    def health(self, rings):
        status = super().health(rings)
        for pin in self.manifest["targets"]:
            track = next(t for t in status["tracks"] if t["kernel"] == pin["kernel"])
            if track["ring_versions"] != pin["ring_versions"]:
                raise ValueError("observation ring targets changed: "+pin["kernel"])
        return status

    def run(self):
        if self.state.get("phase") == "complete":
            return
        if self.state.get("phase") not in (None, "soaking"):
            raise ValueError("failed/interrupted observation requires a new reviewed run")
        now = dt.datetime.now(UTC)
        if self.state and elapsed(self.state["updated_at"], now) > 120:
            raise ValueError("observation gap exceeded 120 seconds; start a new reviewed run")
        self.state.setdefault("started_at", stamp())
        self.state.setdefault("journal_since", self.manifest["journal_since"])
        self.health([1, 2])
        self.node_checks([1, 2])
        failures, last_nodes, minimum = 0, time.monotonic(), 1440
        while True:
            try:
                settings = self.api("/api/settings")["current"]
                if settings["auto_enabled"]:
                    raise ValueError("rollout policy changed; manual review required")
                minimum = int(settings["min_soak_minutes"].get("2", 0))
                self.health([1, 2])
                if time.monotonic()-last_nodes >= 300:
                    self.node_checks([1, 2]); last_nodes = time.monotonic()
                failures = 0
            except TRANSIENT:
                failures += 1
                if failures >= 3:
                    raise
            deadline = dt.datetime.fromisoformat(self.state["started_at"])+dt.timedelta(seconds=max(86400, minimum*60))
            self.save("soaking", eligible_after=deadline.isoformat(),
                      checks=self.manifest["checks"], targets=self.manifest["targets"])
            if failures == 0 and eligible(self.state["started_at"], dt.datetime.now(UTC), minimum):
                break
            time.sleep(30)
        self.health([1, 2])
        self.node_checks([1, 2])
        for host in self.manifest["hosts"]:
            if host["ring"] != 1:
                continue
            work = json.loads(self.remote(host, "cat "+shlex.quote(host["load_result"])))
            if not work["complete"] or work["errors"] or work["seconds"] < 86395 or not all(work["counts"].get(k, 0) > 0
                    for k in ("hashes", "file_rounds", "socket_rounds", "rights_cycles")):
                raise ValueError(host["hostname"]+": 24-hour load test did not complete")
        self.save("complete", completed_at=stamp())


if __name__ == "__main__":
    def interrupted(signum, frame):
        raise KeyboardInterrupt("validation service interrupted")
    signal.signal(signal.SIGTERM, interrupted)
    manifest = Path(sys.argv[1])
    mode = json.loads(manifest.read_text()).get("mode", "acceptance")
    if mode not in ("acceptance", "observe"):
        raise SystemExit("unknown validation mode")
    run = (ObserveRun if mode == "observe" else Run)(manifest)
    try:
        run.run()
    except BaseException as error:
        if isinstance(error, KeyboardInterrupt) and run.state.get("phase") == "soaking":
            run.save("soaking", stopped_at=stamp())
            raise SystemExit(0)
        try:
            run.state["targets"] = [{"kernel": t["kernel"], "ring_versions": t["ring_versions"]} for t in run.api("/api/status")["tracks"]]
        except Exception:
            pass
        run.save("failed", error=str(error))
        raise
