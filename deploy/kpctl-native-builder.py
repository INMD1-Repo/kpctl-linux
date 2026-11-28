#!/usr/bin/env python3
"""Release-specific, unprivileged builder for Debian and Rocky Linux AMD64."""
import argparse
import base64
from contextlib import contextmanager, nullcontext
from datetime import datetime, timezone
import difflib
import filecmp
from functools import cmp_to_key
import hashlib
import json
import os
from pathlib import Path
import re
import ssl
import shutil
import subprocess
import sys
import tempfile
import threading
import urllib.request

from native_inputs import digest, discover, DEBIAN, KEYS, ROCKY, SALSA, NoRedirect, public_module_cert, git, native_environment, prepare, require, run


def require_build_target(plan):
    require((plan["distro"], plan["release"]) != ("debian", "13"),
            "Debian 13 stock: identification and source research only (IBT=y, no CONFIG_KLP_BUILD). Install the official trixie-security linux-image-amd64 update and schedule a reboot.")


def candidate(base, fixed, paths):
    """All selected changes from two post-patch package trees, with normal Git -p1 paths."""
    rows = []
    for rel in sorted(set(paths)):
        require(re.fullmatch(r"(?:[\w-]+/)+[\w.-]+\.[chS]", rel) and ".." not in rel.split("/"),
                "select relative kernel C, header or assembly files")
        require(not rel.startswith("arch/") or rel.startswith("arch/x86/"), "change targets a different architecture")
        files = []
        labels = []
        modes = []
        for tree, prefix in ((base, "a/"), (fixed, "b/")):
            p = tree / rel
            require(p.resolve() == tree.resolve() / rel, f"source path resolves through a link: {rel}")
            if not p.exists():
                files.append([])
                labels.append("/dev/null")
                modes.append(None)
                continue
            require(p.is_file(), f"expected source file: {rel}")
            data = p.read_text()
            require(not data or data.endswith("\n"), f"missing final newline: {rel}")
            files.append(data.splitlines(keepends=True))
            labels.append(prefix + rel)
            modes.append("100755" if p.stat().st_mode & 0o111 else "100644")
        delta = list(difflib.unified_diff(*files, fromfile=labels[0], tofile=labels[1]))
        require(delta, f"no source changes: {rel}")
        rows.append(f"diff --git a/{rel} b/{rel}\n")
        if modes[0] is None:
            rows.append(f"new file mode {modes[1]}\n")
        elif modes[1] is None:
            rows.append(f"deleted file mode {modes[0]}\n")
        else:
            require(modes[0] == modes[1], f"source mode changed: {rel}")
        rows.extend(delta)
    return "".join(rows)


def changed_sources(base, fixed):
    """List package-tree changes, including paths needing manual review."""
    def paths(tree):
        found = set()
        for root, dirs, files in os.walk(tree):
            dirs[:] = [d for d in dirs if d not in (".pc", ".git", "debian") and not (Path(root)/d).is_symlink()]
            if Path(root) == tree / "arch":
                dirs[:] = [d for d in dirs if d == "x86"]
            for name in files:
                p = Path(root) / name
                relevant = p.suffix in (".c", ".h", ".S") or name.startswith(("Kconfig", "Makefile")) or name == "Kbuild"
                if relevant and not p.is_symlink():
                    found.add(p.relative_to(tree))
        return found
    old, new = paths(base), paths(fixed)
    for p in sorted(old | new):
        if p not in old:
            yield "added", p
        elif p not in new:
            yield "removed", p
        elif not filecmp.cmp(base/p, fixed/p, shallow=False):
            yield "modified", p


def tool_env(plan, inputs):
    native_environment(plan)
    config = inputs["config"].read_text()
    expected = re.search(r'^CONFIG_CC_VERSION_TEXT="([^"]+)"$', config, re.M)
    require(expected, "compiler identity missing from official config")
    version = expected[1]
    compiler = version.split()[0]
    require(re.fullmatch(r"[\w.-]+", compiler) and run(compiler, "--version").splitlines()[0] == version, "matching compiler required: " + version)
    # kpatch-build uses gcc to check the kernel's compiler. The native environment
    # must supply the corresponding default gcc as well as any versioned alias.
    require(run("gcc", "--version").splitlines()[0].partition(" ")[2] == version.partition(" ")[2], "default gcc differs from target compiler build")
    return {**os.environ, "LC_ALL": "C", "MAKEFLAGS": "KERNELRELEASE=" + plan["abi"], "CC": compiler}


def verify_build_config(expected, actual):
    def options(lines):
        result = {}
        for line in lines:
            if line.startswith("CONFIG_") and "=" in line:
                name, value = line.split("=", 1)
                # Debian invokes the same compiler under gcc and gcc-N. The
                # vendor, build/revision and all codegen options still match.
                if name == "CONFIG_CC_VERSION_TEXT":
                    value = value.partition(" ")[2]
                result[name] = value
        return result
    original, built = options(expected), options(actual.read_text().splitlines())
    changed = sorted(k for k in original.keys() | built.keys() if original.get(k) != built.get(k))
    require(not changed, "effective Kconfig differs from signed build: " + ", ".join(changed[:12]))


def bounded_directories(source, patches, directories):
    # A directory target cannot account for a header edit or for a .c file
    # included as a fragment by a translation unit in another directory.
    files = set()
    for data in patches:
        lines = data.decode().splitlines()
        old = [line[6:] for line in lines if line.startswith("--- a/")]
        new = [line[6:] for line in lines if line.startswith("+++ b/")]
        headers = [line for line in lines if line.startswith("diff --git ")]
        require(old and old == new and headers == [f"diff --git a/{p} b/{p}" for p in old]
                and not any(line.startswith(("rename ", "copy ", "new file ", "deleted file ",
                                             "GIT binary patch", "--- /dev/null", "+++ /dev/null")) for line in lines),
                "bounded builds require complete edits to existing C files")
        for path in old:
            file = source / path
            require(re.fullmatch(r"(?:[\w-]+/)+[\w.-]+\.c", path)
                    and file.resolve() == source.resolve() / path and file.is_file(), "invalid bounded source path")
            files.add(Path(path))
    touched = {str(path.parent) for path in files}
    require(isinstance(directories, list) and set(directories) == touched, "build_dirs must cover exactly the changed C files")
    names = b"|".join(re.escape(os.fsencode(file.name)) for file in files)
    include = re.compile(rb'^\s*#\s*include\s*[<"](?:[^>"\n]*/)?(?:' + names + rb')[>"]', re.M)
    for root, dirs, entries in os.walk(source):
        dirs[:] = [d for d in dirs if d not in (".git", ".pc", "debian")]
        for entry in entries:
            p = Path(root, entry)
            if p.suffix in (".c", ".h", ".S", ".inc") and not p.is_symlink() and include.search(p.read_bytes()):
                raise ValueError(f"changed C file is also included by {p.relative_to(source)}; use a full build")
    return touched


def compile_module(plan, inputs, version, patches, work):
    require_build_target(plan)
    env = tool_env(plan, inputs)
    work.mkdir()
    out = work / "output"
    out.mkdir()
    # A private cache prevents trials and builds for equal ABIs sharing a baseline.
    env["HOME"] = str(work)
    env["CACHEDIR"] = str(work / "cache")
    env["KPATCH_CACHE_DIR"] = str(work / "cache")
    source = work / "source"
    subprocess.run(["cp", "-a", "--reflink=auto", inputs["source"], source], check=True)
    track = inputs["proof"]["track"]
    name = "kpctl_" + hashlib.sha256(track.encode()).hexdigest()[:24] + "_v" + str(version)
    jobs = plan.get("jobs", 2)
    require(type(jobs) is int and 1 <= jobs <= 256, "invalid CPU budget")
    module = out / (name + ".ko")
    config = inputs["config"].read_text().splitlines()
    in_tree = "CONFIG_KLP_BUILD=y" in config
    dirs = plan.get("build_dirs", [])
    vendor_certificate = None
    if (in_tree or not dirs) and 'CONFIG_MODULE_SIG_KEY="certs/signing_key.pem"' in config:
        # The default Kbuild target generates a new key. Supply the exact public
        # certificate as a build input instead; .config and the running system
        # keep the vendor key policy. No modules_install is performed.
        vendor_certificate = source / "output/kpctl-vendor.pem"
        trusted = source/"certs/rhel.pem" if 'CONFIG_SYSTEM_TRUSTED_KEYS="certs/rhel.pem"' in config else None
        public_module_cert(inputs["debug"], vendor_certificate, trusted)
        env["MAKEFLAGS"] += " CONFIG_MODULE_SIG_KEY=output/kpctl-vendor.pem"
    if in_tree:
        tool = source / "scripts/livepatch/klp-build"
        require(tool.is_file(), "official kernel lacks configured klp-build tool")
        shutil.copyfile(inputs["config"], source / ".config")
        args = [tool, "-j", str(jobs), "-o", module]
    else:
        args = ["kpatch-build", "-j", str(jobs), "-s", source, "-a", plan["abi"], "-c", inputs["config"], "-v", inputs["debug"], "-n", name, "-o", out]
        if not dirs and plan["distro"] == "debian" and 'CONFIG_MODULE_SIG_KEY="output/signing_key.pem"' in config:
            # vmlinux's certs target reads this public certificate. No private
            # key, modules_install, signing bypass or boot image is needed.
            vendor_certificate = source / "output/signing_key.pem"
            public_module_cert(inputs["debug"], vendor_certificate)
        if dirs:
            touched = bounded_directories(source, patches, dirs)
            shutil.copyfile(inputs["symvers"], source / "Module.symvers")
            args.extend(["-t", "modules_prepare"])
            for directory in sorted(touched):
                args.extend(["-t", directory + "/"])
    for i, data in enumerate(patches):
        file = work / f"input-{i}.patch"
        file.write_bytes(data)
        args.append(file)
    with (work / "build.log").open("wb") as log:
        completed = subprocess.run(args, cwd=source, env=env, stdout=log, stderr=subprocess.STDOUT)
    if completed.returncode:
        tails = []
        for path in [work / "build.log", work / "cache/build.log"]:
            if path.is_file():
                with path.open("rb") as log:
                    problems = []
                    for line in log:
                        if re.search(rb"(?:fatal error:|error:|ERROR:|No rule to make target)", line):
                            problems.append(line[:1024].decode(errors="replace").strip())
                            if len(problems) == 6:
                                break
                    tails.extend(problems)
                    log.seek(max(0, path.stat().st_size - 8192))
                    tails.append(log.read().decode(errors="replace"))
        raise ValueError("livepatch build failed\n" + "\n".join(tails))
    verify_build_config(config, source/".config")
    if vendor_certificate:
        der = subprocess.check_output(["openssl", "x509", "-in", vendor_certificate, "-outform", "DER"])
        require((source/"certs/signing_key.x509").read_bytes() == der, "baseline used a different module signing certificate")
    subprocess.run(["kpctl-builder", "-verify-distribution-module", track, str(version), module, inputs["config"], inputs["symvers"], inputs["reference"]], env=env, check=True)
    return name, module


class Controller:
    def __init__(self, config):
        self.url = config["controller_url"].rstrip("/")
        require(self.url.startswith("https://"), "builder controller requires HTTPS")
        self.token = Path(config["token_file"]).read_text().strip()
        self.opener = urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=config.get("ca_file"))))

    def request(self, path, payload=None):
        data = None if payload is None else json.dumps(payload).encode()
        req = urllib.request.Request(self.url + path, data=data, headers={"Authorization": "Bearer " + self.token, "Content-Type": "application/json"})
        with self.opener.open(req, timeout=8 if path == "/api/builder/heartbeat" else 180) as resp:
            return json.load(resp) if resp.status != 204 else None


def assigned_patches(task):
    job = task["job"]
    supplied = task["patches"]
    require([p["id"] for p in supplied] == job["patch_ids"] and supplied, "invalid cumulative patch order")
    result = []
    for p in supplied:
        data = p["content"].encode()
        require(p["filename"] == p["id"] + ".patch" and p["size"] == len(data) and p["sha256"] == hashlib.sha256(data).hexdigest(), "corrupt task patch")
        result.append(data)
    return result


class NativeMonitor:
    limit = 256 * 1024  # model.BuilderLogLimit

    def __init__(self, client, claim, jobs, work):
        self.client, self.claim = client, claim
        self.jobs, self.disk = jobs, work.parent
        self.activity = {"kernel": claim["native_track"], "phase": "idle", "message": "다음 작업 조회 대기"}
        self.compile_dir = None
        self.log = ""
        self.truncated = False
        self.lock = threading.Lock()

    def read_log(self):
        if self.compile_dir is None:
            return
        # kpatch-build writes detailed compiler output under CACHEDIR on Debian 12 and Rocky 9.
        tails = []
        truncated = False
        for name in ("build.log", "cache/build.log"):
            try:
                with (self.compile_dir / name).open("rb") as stream:
                    end = stream.seek(0, os.SEEK_END)
                    stream.seek(max(0, end - self.limit))
                    chunk = stream.read(self.limit)
            except OSError:
                continue  # Files appear during compilation and disappear at cleanup.
            if chunk:
                tails.append(chunk)
                truncated |= end > self.limit
        if tails:
            data = b"\n".join(tails).decode(errors="replace").encode()
            self.log = data[-self.limit:].decode(errors="ignore")
            self.truncated = truncated or len(data) > self.limit

    def send(self):
        with self.lock:
            try:
                self.read_log()
                mem = {}
                for line in Path("/proc/meminfo").read_text().splitlines():
                    key, _, value = line.partition(":")
                    if key in ("MemTotal", "MemAvailable"):
                        mem[key] = int(value.split()[0]) * 1024
                disk = shutil.disk_usage(self.disk)
                activity = self.activity.copy()
                activity["message"] = activity["message"].encode()[:4000].decode(errors="ignore")
                log = self.log
                truncated = self.truncated
                if activity["phase"] == "failed":
                    data = (log + "\n" + activity["message"]).encode()
                    log = data[-self.limit:].decode(errors="ignore")
                    truncated = truncated or len(data) > self.limit
                self.client.request("/api/builder/heartbeat", dict(
                    self.claim, activity=activity, environment="distribution", log=log,
                    job_log=log if activity.get("job_id") else "", log_truncated=truncated,
                    resources=dict(cpus=os.cpu_count() or 1, jobs=self.jobs, load1=os.getloadavg()[0],
                                   memory_total=mem["MemTotal"], memory_available=mem["MemAvailable"],
                                   disk_total=disk.total, disk_available=disk.free)))
            except (OSError, ValueError, KeyError) as err:
                print("builder heartbeat:", err, file=sys.stderr)

    @contextmanager
    def running(self, phase, message, job=None):
        self.activity.update(phase=phase, message=message, started_at=datetime.now(timezone.utc).isoformat())
        if job:
            self.activity.update(job_id=job["id"], job_started_at=job["started_at"], version=job["version"])
        self.send()
        stop = threading.Event()
        def repeat():
            while not stop.wait(10):
                self.send()
        thread = threading.Thread(target=repeat, daemon=True)
        thread.start()
        try:
            yield
        except Exception as err:
            self.activity = dict(kernel=self.claim["native_track"], phase="failed",
                                 message=str(err).encode()[-4000:].decode(errors="ignore"))
            raise
        else:
            self.activity = dict(kernel=self.claim["native_track"], phase="idle", message="다음 작업 조회 대기")
        finally:
            stop.set()
            thread.join()
            self.send()

    @contextmanager
    def compiler(self, work, message):
        previous = self.activity
        with self.lock:
            self.activity = dict(previous, phase="building" if previous.get("job_id") else "trial", message=message)
            self.compile_dir = work
            self.log, self.truncated = "", False
        self.send()
        try:
            yield
        finally:
            with self.lock:
                self.read_log()
                self.compile_dir = None
                self.activity = previous


def work_once(client, plan, inputs, name, work, prepare_target=None, can_collect=False, collect=None):
    require_build_target(plan)
    track = inputs["proof"]["track"]
    claim = {"builder": name, "series": plan["distro"] + plan["release"], "native_track": track, "kernels": [track]}
    verifier = shutil.which("kpctl-builder")
    if verifier:
        try:
            claim["binary_sha256"] = digest(Path(verifier))
        except OSError as err:
            print("module verifier fingerprint:", err, file=sys.stderr)
    if can_collect:
        claim["can_collect_reviewed"] = True
        claim["can_auto_discover"] = True
    monitor = NativeMonitor(client, claim, plan.get("jobs", 2), work)
    task = client.request("/api/builder/next", claim)
    if not task:
        monitor.send()
        return
    if task.get("reviewed_candidates") or task.get("auto_discover"):
        require(can_collect and not task.get("job", {}).get("id"), "unexpected collection task")
        items = task.get("reviewed_candidates") or {"auto_discover": True}
        if collect is None:
            return items
        with monitor.running("discovering", "배포판 릴리스와 후보 확인 중"):
            collect(items, monitor)
        return
    job = task["job"]
    result = {"builder": name, "job_started_at": job["started_at"]}
    with monitor.running("building", "서명 패키지와 커널 빌드 입력 확인 중", job):
        try:
            require(job["kernel"] == track and job["version"] > 0 and not job.get("prerelease"), "wrong distro, package, build ID or channel")
            if prepare_target:
                expected = inputs["proof"]
                inputs = prepare_target()
                require(inputs["proof"] == expected, "prepared packages differ from the scheduled receipt")
            with monitor.compiler(work, "누적 모듈 컴파일 및 검증 중"):
                module, file = compile_module(plan, inputs, job["version"], assigned_patches(task), work)
            result.update(success=True, module_name=module, module_base64=base64.b64encode(file.read_bytes()).decode(),
                          distribution_proof=inputs["proof"], log=(monitor.log + "\n" + json.dumps(inputs["proof"])).strip())
        except (OSError, ValueError, subprocess.SubprocessError) as err:
            result.update(success=False, error=str(err), log=(monitor.log + "\n" + str(err)).strip())
        reply = client.request(f"/api/builder/jobs/{job['id']}/result", result)
        require(reply.get("result") == "ok", "controller no longer owns this build attempt")
        require(result["success"], result.get("error", ""))


def newer_version(distro, previous, fixed):
    # Call only after validating both package versions against the profile.
    if distro == "debian":
        return subprocess.run(["dpkg", "--compare-versions", previous, "lt", fixed]).returncode == 0
    expression = '%{lua:print(rpm.vercmp("' + previous + '","' + fixed + '"))}'
    return run("rpm", "--eval", expression) == "-1"


def process_release(action, plan, base, fixed, *, work, cache, fetch, paths, cves, title,
                    prior=None, parent=None, client=None, reviewed=None, monitor=None):
    distro = plan["distro"]
    preview = action in ("candidate", "changes", "fixed-proof")
    inputs = {"source": base[0]} if preview else base
    require(all(fixed[k] == plan[k] for k in ("distro", "release", "git")) and fixed["revision"] != plan["revision"], "wrong fixed release")
    git(plan, "merge-base", "--is-ancestor", plan["revision"], fixed["revision"])
    tree, proof = prepare(fixed, work / "fixed", cache, fetch, source_only=True)
    require(newer_version(distro, plan["version"], fixed["version"]), "fixed package must be newer than target")
    fixed_receipt = {**proof, "abi": fixed["abi"], "version": fixed["version"]}
    if action == "fixed-proof":
        print(json.dumps(fixed_receipt, indent=2))
        return
    if action == "changes":
        for state, path in changed_sources(inputs["source"], tree):
            print(state, path, sep="\t")
        return
    parent_id = ""
    start = inputs["source"]
    require(bool(prior) == bool(parent), "incremental delta requires previous release and parent pin")
    if prior:
        require(all(prior[k] == plan[k] for k in ("distro", "release", "git"))
                and prior["revision"] not in (plan["revision"], fixed["revision"]), "invalid predecessor")
        git(plan, "merge-base", "--is-ancestor", plan["revision"], prior["revision"])
        git(plan, "merge-base", "--is-ancestor", prior["revision"], fixed["revision"])
        start, receipt = prepare(prior, work / "previous", cache, fetch, source_only=True)
        prior_release = dict(receipt, abi=prior["abi"], version=prior["version"])
        require(parent["fixed"] == prior_release and sorted(set(paths)) == parent["paths"],
                "previous signed release or paths differ from parent pin")
        if preview:
            # Source-only review has authenticated every base field except the live image build ID.
            expected_base = dict(base[1], track=parent["base"]["track"])
        else:
            expected_base = inputs["proof"]
        require(parent["base"] == expected_base, "parent base mismatch")
        require(newer_version(distro, plan["version"], prior["version"])
                and newer_version(distro, prior["version"], fixed["version"]),
                "previous package must be newer than base and older than fixed")
        parent_id = parent["candidate_id"]
        require(re.fullmatch(re.escape(prior["revision"]) + r"/[0-9a-f]{64}", parent_id)
                and parent_id.endswith("/" + parent["sha256"]), "invalid parent candidate ID")
    patch = candidate(start, tree, paths)
    checksum = hashlib.sha256(patch.encode()).hexdigest()
    candidate_id = fixed["revision"] + "/" + checksum
    require(all(re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,}", c) for c in cves), "invalid reviewed CVE")
    if action == "candidate-proof" or reviewed is not None:
        receipt = dict(base=inputs["proof"], fixed=fixed_receipt, paths=sorted(set(paths)),
                       cves=sorted(set(cves)), parent_candidate=parent_id, sha256=checksum, candidate_id=candidate_id)
        if action == "candidate-proof":
            if title:
                receipt["title"] = title
            print(json.dumps(receipt, indent=2))
            return
        require(all(receipt[k] == reviewed[k] for k in receipt), "reconstructed candidate differs from independent review")
    if action == "candidate":
        sys.stdout.write(patch)
        return
    require(title, "reviewed title required")
    path = "/api/builder/kernels/" + inputs["proof"]["track"]
    known = client.request(path + "/known")
    active_rows=known.get("active_patches") or []
    if candidate_id in (known.get("commits") or []) or fixed["revision"] in (known.get("commits") or []):
        return
    active_ids=[]
    for row in active_rows:
        expected=row["commit"]+"/"+hashlib.sha256(row["content"].encode()).hexdigest()
        require(expected==row.get("candidate_id"), "active candidate hash mismatch or missing legacy receipt")
        active_ids.append(expected)
    if parent_id:
        require(parent_id in active_ids, "parent is no longer active")
    active = [p["content"].encode() for p in active_rows]
    trial = work / "trial"
    with monitor.compiler(trial, title) if monitor else nullcontext():
        compile_module(plan, inputs, 1, active + [patch.encode()], trial)
    added = dict(parent_candidate=parent_id, fixed_release=fixed_receipt, commit=fixed["revision"], title=title, cves=cves, content=patch)
    request = {"expected_active": active_ids, "patches": [added]}
    if reviewed is not None:
        request["reviewed_base"] = inputs["proof"]
    print(json.dumps(client.request(path + "/discovered", request)))


def reviewed_plan(base, fixed):
    suite = "BaseOS"
    if base["distro"] == "debian":
        stable = DEBIAN[base["release"]][0]
        suite = next((s for s in (stable, stable + "-security") if fixed["signer"] in KEYS[s]), None)
        require(suite, "no matching Debian suite for the reviewed signer")
    require(re.fullmatch(r"[0-9a-f]{40}", fixed["revision"]), "invalid fixed revision")
    return dict(base, suite=suite, **{k: fixed[k] for k in ("version", "abi", "revision")})


def collect_reviewed(client, plan, base_proof, items, cache, work, monitor=None):
    origin = SALSA if plan["distro"] == "debian" else ROCKY
    require(git(plan, "remote", "get-url", "origin") == origin, "wrong packaging Git origin")
    subprocess.run(["git", "-C", plan["git"], "fetch", "--tags", "origin", "+refs/heads/*:refs/remotes/origin/*"],
                   env={**os.environ, "GIT_ALLOW_PROTOCOL": "https", "GIT_TERMINAL_PROMPT": "0"}, check=True)
    failures = []
    for item in items:
        pin = item["pin"]
        try:
            require(pin["base"] == base_proof, "independent base receipt differs from installed track")
            parent = item.get("previous")
            require((parent["candidate_id"] if parent else "") == pin["parent_candidate"], "wrong reviewed predecessor")
            fixed = reviewed_plan(plan, pin["fixed"])
            prior = reviewed_plan(plan, parent["fixed"]) if parent else None
            with tempfile.TemporaryDirectory(dir=work) as tmp:
                scratch = Path(tmp)
                base = prepare(plan, scratch / "base", cache, True)
                title = pin.get("title") or f"{fixed['version']} ({', '.join(pin['paths'])})"
                process_release("collect", plan, base, fixed, work=scratch, cache=cache, fetch=True,
                                paths=pin["paths"], cves=pin["cves"], title=title, prior=prior, parent=parent,
                                client=client, reviewed=pin, monitor=monitor)
            break  # Give the resulting cumulative job priority on the next poll.
        except (OSError, ValueError, KeyError, subprocess.SubprocessError) as err:
            print(f"{pin['candidate_id']}: {err}", file=sys.stderr)
            failures.append(pin["candidate_id"])
    require(not failures, "reviewed collection failed: " + ", ".join(failures))


def _patch_paths(content):
    paths = []
    for line in content.splitlines():
        if line.startswith("diff --git "):
            parts = line.split()
            if len(parts) == 4 and parts[2].startswith("a/"):
                paths.append(parts[2][2:])
    return paths


def _load_auto_tried(state_path):
    if not state_path or not state_path.is_file():
        return {}
    try:
        data = json.loads(state_path.read_text())
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_auto_tried(state_path, data):
    if not state_path:
        return
    tmp = state_path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    os.replace(tmp, state_path)


def _discover_newer_releases(plan, cache, work):
    distro = plan["distro"]
    found = {}
    if distro == "rocky":
        # Rocky 는 공식 Git 태그를 먼저 필터링해 현재 기준보다 확실히 새 릴리스가 있을 때만 SRPM 을 받습니다.
        rel = plan["release"]
        prefix = f"patched/r{rel}/kernel-"
        tags = git(plan, "tag", "--merged", f"refs/remotes/origin/r{rel}",
                   "--sort=-version:refname", "-l", prefix + "*").splitlines()
        for tag in tags[:16]:
            ver = tag.removeprefix(prefix)
            if not newer_version(distro, plan["version"], ver):
                continue
            try:
                rev = git(plan, "rev-parse", f"refs/tags/{tag}^{{commit}}")
            except subprocess.SubprocessError:
                continue
            if not rev or rev == plan["revision"]:
                continue
            try:
                git(plan, "merge-base", "--is-ancestor", plan["revision"], rev)
            except subprocess.SubprocessError:
                continue
            found.setdefault(rev, dict(plan, suite="BaseOS", abi=ver + ".x86_64", version=ver, revision=rev))
    else:
        stable = DEBIAN[plan["release"]][0]
        for suite in (stable + "-security", stable):
            suite_plan = {k: plan[k] for k in ("distro", "release", "git", "keyring")}
            suite_plan["suite"] = suite
            try:
                releases = discover(suite_plan, cache, work, True, limit=8)
            except (OSError, ValueError, subprocess.SubprocessError) as err:
                print(f"[auto-discover] {suite} 조회 건너뜀: {err}", file=sys.stderr)
                continue
            for item in releases:
                rev = item.get("revision", "")
                ver = item.get("version", "")
                if not rev or rev == plan["revision"]:
                    continue
                if not newer_version(distro, plan["version"], ver):
                    continue
                try:
                    git(plan, "merge-base", "--is-ancestor", plan["revision"], rev)
                except subprocess.SubprocessError:
                    continue
                found.setdefault(rev, dict(plan, **item))
    def cmp_rel(a, b):
        if a["version"] == b["version"]:
            return 0
        return -1 if newer_version(distro, a["version"], b["version"]) else 1
    return sorted(found.values(), key=cmp_to_key(cmp_rel))


def auto_discover_and_collect(client, plan, base_proof, cache, work, state_path=None, monitor=None):
    """공식 서명 릴리스에서 새 커널 수정(.c)을 자동 탐색·시험 컴파일해 컨트롤러에 자동 핀 등록합니다."""
    origin = SALSA if plan["distro"] == "debian" else ROCKY
    require(git(plan, "remote", "get-url", "origin") == origin, "wrong packaging Git origin")
    subprocess.run(["git", "-C", plan["git"], "fetch", "--tags", "origin", "+refs/heads/*:refs/remotes/origin/*"],
                   env={**os.environ, "GIT_ALLOW_PROTOCOL": "https", "GIT_TERMINAL_PROMPT": "0"}, check=True)

    newer = _discover_newer_releases(plan, cache, work)
    if not newer:
        return False

    track = base_proof["track"]
    api_base = "/api/builder/kernels/" + track
    known = client.request(api_base + "/known") or {}
    known_commits = set(known.get("commits") or [])
    active_rows = known.get("active_patches") or []
    active_ids = []
    active_bytes = []
    latest_by_path = {}
    for row in active_rows:
        content = row["content"]
        cid = row["commit"] + "/" + hashlib.sha256(content.encode()).hexdigest()
        require(cid == row.get("candidate_id"), "active candidate hash mismatch")
        active_ids.append(cid)
        active_bytes.append(content.encode())
        for rel in _patch_paths(content):
            latest_by_path[rel] = (cid, row.get("fixed_release"))

    tried = _load_auto_tried(state_path)
    base_inputs = None
    prev_trees = {}

    for idx, fixed in enumerate(newer):
        if fixed["revision"] in known_commits:
            continue
        with tempfile.TemporaryDirectory(dir=work) as tmp:
            scratch = Path(tmp)
            if base_inputs is None:
                base_inputs = prepare(plan, work / "auto-base", cache, True)
                require(base_inputs["proof"] == base_proof, "prepared base differs from track receipt")
            try:
                fixed_tree, fixed_proof = prepare(fixed, scratch / f"fixed-{idx}", cache, True, source_only=True)
            except (OSError, ValueError, subprocess.SubprocessError) as err:
                print(f"[auto-discover] {fixed['version']} 소스 준비 건너뜀: {err}", file=sys.stderr)
                continue
            fixed_receipt = {**fixed_proof, "abi": fixed["abi"], "version": fixed["version"]}
            changed_c = [
                str(rel) for status, rel in changed_sources(base_inputs["source"], fixed_tree)
                if status in ("modified", "added") and rel.suffix == ".c"
                and (not str(rel).startswith("arch/") or str(rel).startswith("arch/x86/"))
            ]
            for cidx, rel in enumerate(changed_c):
                parent_id = ""
                start_tree = base_inputs["source"]
                if rel in latest_by_path:
                    parent_id, prev_fixed = latest_by_path[rel]
                    if not prev_fixed or not newer_version(plan["distro"], prev_fixed["version"], fixed["version"]):
                        continue
                    try:
                        git(plan, "merge-base", "--is-ancestor", prev_fixed["revision"], fixed["revision"])
                    except subprocess.SubprocessError:
                        continue
                    prev_rev = prev_fixed["revision"]
                    if prev_rev not in prev_trees:
                        prev_plan = reviewed_plan(plan, prev_fixed)
                        prev_tree, _ = prepare(prev_plan, work / f"prev-{prev_rev[:12]}", cache, True, source_only=True)
                        prev_trees[prev_rev] = prev_tree
                    start_tree = prev_trees[prev_rev]
                try:
                    patch = candidate(start_tree, fixed_tree, [rel])
                except ValueError:
                    continue
                checksum = hashlib.sha256(patch.encode()).hexdigest()
                candidate_id = fixed["revision"] + "/" + checksum
                if candidate_id in known_commits or candidate_id in tried:
                    continue
                try:
                    trial = scratch / f"trial-{cidx}"
                    with monitor.compiler(trial, f"{fixed['version']} {rel}") if monitor else nullcontext():
                        compile_module(plan, base_inputs, 1, active_bytes + [patch.encode()], trial)
                except (OSError, ValueError, subprocess.SubprocessError) as err:
                    print(f"[auto-discover] {fixed['version']} {rel} 시험 빌드 건너뜀: {err}", file=sys.stderr)
                    tried[candidate_id] = str(err)[:400]
                    _save_auto_tried(state_path, tried)
                    continue
                added = dict(
                    parent_candidate=parent_id,
                    fixed_release=fixed_receipt,
                    commit=fixed["revision"],
                    title=f"{fixed['version']} ({rel})",
                    cves=[],
                    content=patch,
                )
                req = {
                    "expected_active": active_ids,
                    "reviewed_base": base_proof,
                    "auto_pin": True,
                    "patches": [added],
                }
                print(json.dumps(client.request(api_base + "/discovered", req)))
                return True
    return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["discover", "history", "inspect", "candidate-proof", "prepare", "fixed-proof", "changes", "candidate", "collect", "work"])
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--cache", type=Path)
    parser.add_argument("--work-dir", type=Path, help="private scratch parent with room for extracted debug packages and baseline")
    parser.add_argument("--fetch", action="store_true", help="download missing inputs from official archive hosts")
    parser.add_argument("--proof", type=Path, help="verified prepare receipt for cheap work polling")
    parser.add_argument("--controller", type=Path, help="controller_url, ca_file, token_file, builder")
    parser.add_argument("--fixed", type=Path, help="later signed distribution release plan")
    parser.add_argument("--path", action="append", default=[])
    parser.add_argument("--title")
    parser.add_argument("--previous", type=Path, help="previous signed fixed release plan for an incremental delta")
    parser.add_argument("--parent-pin", type=Path, help="independent candidate-proof for the previous delta on exactly these paths")
    parser.add_argument("--limit", type=int, default=4, help="number of Rocky release tags to inspect")
    parser.add_argument("--cve", action="append", default=[])
    opts = parser.parse_args()
    if opts.proof and opts.action != "work":
        parser.error("--proof is only used for work")
    plan = json.loads(opts.plan.read_text())
    distro, rel = plan["distro"], plan["release"]
    if opts.action in ("prepare","collect", "work", "candidate-proof"):
        require_build_target(plan)
    if opts.action in ("collect", "work") and not opts.controller:
        parser.error("collect and work require --controller worker.json")
    if opts.action == "history":
        if distro == "debian":
            suite, series = DEBIAN[rel]
            require(plan["suite"] in (suite, suite + "-security"), "unsupported Debian suite")
            branch = f"debian/{series}/{plan['suite']}"
        else:
            require(distro == "rocky" and rel in ("9", "10") and plan["suite"] == "BaseOS", "unsupported Rocky release")
            branch = "r" + rel
        require(git(plan, "remote", "get-url", "origin") == (SALSA if distro == "debian" else ROCKY), "wrong Git origin")
        print(git(plan, "log", "-80", "--format=%H %s %D", "refs/remotes/origin/" + branch))
        return
    require(opts.cache and opts.work_dir, "--cache and --work-dir required")
    with tempfile.TemporaryDirectory(dir=opts.work_dir) as scratch:
        work = Path(scratch).resolve()
        if opts.action == "discover":
            require(1 <= opts.limit <= 100, "invalid tag limit")
            count = 0
            for released in discover(plan, opts.cache.resolve(), work, opts.fetch, opts.limit):
                print(json.dumps(released),flush=True)
                count += 1
            require(count, "no signed releases matched available official Git refs and package archives")
            return
        preview = opts.action in ("candidate", "changes", "fixed-proof")
        def target_inputs():
            return prepare(plan, work / "base", opts.cache.resolve(), opts.fetch, source_only=preview)
        if opts.action == "work":
            config = json.loads(opts.controller.read_text())
            if opts.proof:
                receipt = json.loads(opts.proof.read_text())
                require(receipt["revision"] == plan["revision"], "wrong polling receipt for plan")
                client = Controller(config)
                def collect(items, monitor):
                    if isinstance(items, dict) and items.get("auto_discover"):
                        auto_discover_and_collect(client, plan, receipt, opts.cache.resolve(), work,
                                                  state_path=opts.proof.parent / "auto-tried.json", monitor=monitor)
                    else:
                        collect_reviewed(client, plan, receipt, items, opts.cache.resolve(), work, monitor)
                work_once(client, plan, {"proof": receipt}, config["builder"], work / "build", target_inputs,
                          can_collect=opts.fetch, collect=collect)
            else:
                work_once(Controller(config), plan, target_inputs(), config["builder"], work / "build")
            return
        base = target_inputs()
        if opts.action in ("inspect","prepare"):
            print(json.dumps(base["proof"], indent=2))
            return
        require(opts.fixed and (opts.action in ("changes", "fixed-proof") or opts.path), "supply a later signed --fixed plan and every reviewed --path")
        fixed = json.loads(opts.fixed.read_text())
        client = Controller(json.loads(opts.controller.read_text())) if opts.action == "collect" else None
        prior = json.loads(opts.previous.read_text()) if opts.previous else None
        parent = json.loads(opts.parent_pin.read_text()) if opts.parent_pin else None
        process_release(opts.action, plan, base, fixed, work=work, cache=opts.cache.resolve(), fetch=opts.fetch,
                        paths=opts.path, cves=opts.cve, title=opts.title, prior=prior, parent=parent, client=client)



if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as e:
        sys.exit(str(e))
