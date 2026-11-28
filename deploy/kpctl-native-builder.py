#!/usr/bin/env python3
"""Release-specific, unprivileged builder for Debian and Rocky Linux AMD64."""
import argparse
import base64
import difflib
import filecmp
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

from native_inputs import discover, DEBIAN, KEYS, ROCKY, SALSA, NoRedirect, public_module_cert, git, native_environment, prepare, require, run


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
        with self.opener.open(req, timeout=180) as resp:
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


def heartbeat(client, claim, job, stop):
    activity = dict(phase="build", job_id=job["id"], kernel=job["kernel"], job_started_at=job["started_at"])
    while not stop.wait(30):
        try:
            client.request("/api/builder/heartbeat", {**claim, "activity": activity, "environment": "distribution"})
        except (OSError, ValueError) as err:
            print("builder heartbeat:", err, file=sys.stderr)


def work_once(client, plan, inputs, name, work, prepare_target=None, can_collect=False):
    require_build_target(plan)
    track = inputs["proof"]["track"]
    claim = {"builder": name, "series": plan["distro"] + plan["release"], "native_track": track, "kernels": [track]}
    if can_collect:
        claim["can_collect_reviewed"] = True
    task = client.request("/api/builder/next", claim)
    if not task:
        return
    if task.get("reviewed_candidates"):
        require(can_collect and not task["job"].get("id"), "unexpected collection task")
        return task["reviewed_candidates"]
    job = task["job"]
    result = {"builder": name, "job_started_at": job["started_at"]}
    stop = threading.Event()
    thread = threading.Thread(target=heartbeat, args=(client, claim, job, stop), daemon=True)
    thread.start()
    try:
        require(job["kernel"] == track and job["version"] > 0 and not job.get("prerelease"), "wrong distro, package, build ID or channel")
        if prepare_target:
            expected = inputs["proof"]
            inputs = prepare_target()
            require(inputs["proof"] == expected, "prepared packages differ from the scheduled receipt")
        module, file = compile_module(plan, inputs, job["version"], assigned_patches(task), work)
        result.update(success=True, module_name=module, module_base64=base64.b64encode(file.read_bytes()).decode(), distribution_proof=inputs["proof"], log=json.dumps(inputs["proof"]))
    except (OSError, ValueError, subprocess.SubprocessError) as err:
        result.update(success=False, error=str(err), log=str(err))
    finally:
        stop.set()
        thread.join()
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
                    prior=None, parent=None, client=None, reviewed=None):
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
    compile_module(plan, inputs, 1, active + [patch.encode()], work / "trial")
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


def collect_reviewed(client, plan, base_proof, items, cache, work):
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
                                client=client, reviewed=pin)
            break  # Give the resulting cumulative job priority on the next poll.
        except (OSError, ValueError, KeyError, subprocess.SubprocessError) as err:
            print(f"{pin['candidate_id']}: {err}", file=sys.stderr)
            failures.append(pin["candidate_id"])
    require(not failures, "reviewed collection failed: " + ", ".join(failures))


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
                items = work_once(client, plan, {"proof": receipt}, config["builder"], work / "build", target_inputs,
                                  can_collect=opts.fetch)
                if items:
                    collect_reviewed(client, plan, receipt, items, opts.cache.resolve(), work)
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
