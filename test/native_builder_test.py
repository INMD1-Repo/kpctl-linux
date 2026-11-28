"""Offline fixtures for archive verification, Git pinning, native compilation and dispatch."""
import base64
import datetime
import hashlib
import io
import importlib.util
import json
import lzma
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

DEPLOY = Path(__file__).resolve().parents[1] / "deploy"
sys.path.insert(0, str(DEPLOY))
import native_inputs as ni
spec = importlib.util.spec_from_file_location("native_builder", DEPLOY / "kpctl-native-builder.py")
nb = importlib.util.module_from_spec(spec)
spec.loader.exec_module(nb)

CASES = [("debian", "12", "bookworm-security", "6.1.0-57-amd64", "6.1.192-3"),
         ("debian", "13", "trixie-security", "6.12.118+deb13-amd64", "6.12.118-1"),
         ("rocky", "9", "BaseOS", "5.14.0-741.27.1.el9_9.x86_64", "5.14.0-741.27.1.el9_9"),
         ("rocky", "10", "BaseOS", "6.12.0-264.21.1.el10_3.x86_64", "6.12.0-264.21.1.el10_3")]


class NativeFixtures(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)

    def test_timer_collects_only_reproduced_review_then_builds_job(self):
        plan = dict(distro="debian", release="12", suite="bookworm", git="repo",
                    abi="6.1.0-50-amd64", version="6.1.176-1", revision="1"*40)
        track = "__".join(["native", "debian", "12", "amd64", plan["abi"], plan["version"], "a"*40])
        base = dict(track=track, revision=plan["revision"])
        fixed = dict(abi="6.1.0-57-amd64", version="6.1.192-3", revision="2"*40,
                     signer=next(iter(ni.KEYS["bookworm-security"])), source_sha256="3"*64, package_sha256="4"*64)
        rel = "fs/change.c"
        old, new = self.root/"old", self.root/"new"
        for tree, value in ((old, 1), (new, 2)):
            (tree/"fs").mkdir(parents=True)
            (tree/rel).write_text(f"int value = {value};\n")
        delta = nb.candidate(old, new, [rel])
        checksum = hashlib.sha256(delta.encode()).hexdigest()
        pin = dict(base=base, fixed=fixed, paths=[rel], cves=[], parent_candidate="", sha256=checksum,
                   candidate_id=fixed["revision"]+"/"+checksum, title="Reviewed change")
        for name, payload in (("base", plan), ("proof", base), ("worker", {"builder": "native"})):
            (self.root/name).write_text(json.dumps(payload))
        module = self.root/"fixture.ko"
        module.write_bytes(b"fixture")
        compiled, submitted, results = [], [], []
        def prepare(selected, work, cache, fetch, source_only=False):
            self.assertTrue(fetch)
            if source_only:
                self.assertEqual(selected["suite"], "bookworm-security")
                return new, {k: fixed[k] for k in ("revision", "signer", "source_sha256", "package_sha256")}
            return dict(source=old, proof=base)
        def compile_module(plan, inputs, version, patches, work):
            self.assertEqual(patches, [delta.encode()])
            compiled.append(work.name)
            return "fixture", module
        def request(path, payload=None):
            if path.endswith("/next"):
                self.assertTrue(payload["can_collect_reviewed"])
                if not submitted:
                    return {"job": {}, "reviewed_candidates": [{"pin": pin}]}
                return {"job": dict(id=1, started_at="now", kernel=track, patch_ids=["p1"], version=1),
                        "patches": [dict(id="p1", filename="p1.patch", content=delta, size=len(delta), sha256=checksum)]}
            if path.endswith("/known"):
                return {}
            if path.endswith("/discovered"):
                submitted.append(payload)
                return {"added_patches": 1}
            self.assertEqual(path, "/api/builder/jobs/1/result")
            results.append(payload)
            return {"result": "ok"}
        args = ["driver", "work", "--plan", str(self.root/"base"), "--proof", str(self.root/"proof"),
                "--controller", str(self.root/"worker"), "--cache", str(self.root), "--work-dir", str(self.root), "--fetch"]
        fetch = self.root/"git"
        fetch.write_text('#!/bin/sh\n[ "$GIT_ALLOW_PROTOCOL" = https ] && '
                         '[ "$*" = "-C repo fetch --tags origin +refs/heads/*:refs/remotes/origin/*" ]\n')
        fetch.chmod(0o755)
        with patch.dict(os.environ, PATH=f"{self.root}:{os.environ['PATH']}"), \
                patch.object(sys, "argv", args), patch.object(nb, "prepare", side_effect=prepare), \
                patch.object(nb, "git", return_value=ni.SALSA), patch.object(nb, "Controller") as client, \
                patch.object(nb, "compile_module", side_effect=compile_module) as build:
            client.return_value.request.side_effect = request
            with patch.dict(pin, sha256="0"*64), self.assertRaisesRegex(ValueError, "reviewed collection failed"):
                nb.main()
            self.assertEqual((compiled, submitted), ([], []))
            build.side_effect = ValueError("trial failed")
            with self.assertRaisesRegex(ValueError, "reviewed collection failed"):
                nb.main()
            self.assertEqual(submitted, [])
            build.side_effect = compile_module
            nb.main()
            nb.main()
        self.assertEqual(compiled, ["trial", "build"])
        self.assertEqual(submitted[0]["reviewed_base"], base)
        self.assertEqual(submitted[0]["patches"][0]["title"], pin["title"])
        self.assertEqual(results[0]["distribution_proof"], base)
        self.assertTrue(results[0]["success"])

    def test_git_packaging_trials_and_job_transport(self):
        for d, r, suite, abi, version in CASES:
            with self.subTest(d=d, r=r):
                root = self.root / (d + r)
                root.mkdir()
                git = root / "git"
                ni.run("git", "init", "--quiet", git)
                origin = ni.SALSA if d == "debian" else ni.ROCKY
                ni.run("git", "-C", git, "remote", "add", "origin", origin)
                plan = dict(distro=d, release=r, suite=suite, abi=abi, version=version, git=git)
                tree = subprocess.check_output(["git", "-C", git, "mktree"], input=b"").decode().strip()
                rev = ni.git(plan, "-c", "user.name=fixture", "-c", "user.email=fixture@localhost", "commit-tree", tree, "-m", "synthetic package")
                plan["revision"] = rev
                branch = "debian/" + ni.DEBIAN[r][1] + "/" + suite if d == "debian" else "r" + r
                tag = "debian/" + version if d == "debian" else f"patched/r{r}/kernel-{version}"
                ni.git(plan, "update-ref", "refs/remotes/origin/" + branch, rev)
                ni.git(plan, "update-ref", "refs/tags/" + tag, rev)
                ni.pin(plan, origin, branch, tag)
                with self.assertRaises(ValueError):
                    ni.pin({**plan, "revision": "0"*40}, origin, branch, tag)
                source = root / "source"
                fixed = root / "fixed"
                for path, value in [(source, "1"), (fixed, "2")]:
                    (path / "fs/x").mkdir(parents=True)
                    (path / "fs/x/main.c").write_text(f"int value(void) {{ return {value}; }}\n")
                p = nb.candidate(source, fixed, ["fs/x/main.c"])
                subprocess.run(["git", "apply", "--check", "-"], input=p.encode(), cwd=source, check=True)
                target = "__".join(["native", d, r, "amd64", abi, version, "1"*40])
                proof = {"track": target, "revision": rev}
                config = root / "config"
                config.write_text("CONFIG_LIVEPATCH=y\n" + ("CONFIG_KLP_BUILD=y\n" if r=="10" else ""))
                data = dict(source=source, config=config, proof=proof, debug=root/"vmlinux", reference=root/"ref.ko", symvers=root/"Module.symvers")
                bins = root / "bin"
                bins.mkdir()
                # Exercise the normal subprocess boundary without compiling or loading kernel code.
                tool = source / "scripts/livepatch/klp-build" if r=="10" else bins/"kpatch-build"
                tool.parent.mkdir(parents=True, exist_ok=True)
                tool.write_text('#!/usr/bin/env python3\nimport pathlib,sys,shutil\na=sys.argv\nif "-c" in a: shutil.copyfile(a[a.index("-c")+1],pathlib.Path(a[a.index("-s")+1])/".config")\nout=pathlib.Path(a[a.index("-o")+1]);out=out if "-n" not in a else out/(a[a.index("-n")+1]+".ko");out.write_bytes(b"fixture-module")\n')
                tool.chmod(0o755)
                verify = bins/"kpctl-builder"
                verify.write_text('#!/bin/sh\ntest "$1" = -verify-distribution-module && test -s "$4"\n')
                verify.chmod(0o755)
                result = {}
                class FixtureAPI:
                    def request(self, path, payload):
                        if path.endswith("/next"):
                            self_test.assertEqual(payload["native_track"], target)
                            return {"job":dict(id=7, kernel=target, version=1, patch_ids=["p1"], started_at="now"),
                                    "patches":[dict(id="p1", filename="p1.patch", content=p, size=len(p.encode()), sha256=hashlib.sha256(p.encode()).hexdigest())]}
                        self_test.assertEqual(path, "/api/builder/jobs/7/result")
                        result.update(payload)
                        return {"result": "ok"}
                self_test = self
                with patch.object(nb, "tool_env", return_value={**os.environ, "PATH":str(bins)+":"+os.environ["PATH"]}):
                    if r=="13":
                        with self.assertRaisesRegex(ValueError,"IBT"):
                            nb.work_once(FixtureAPI(),plan,data,"fixture",root/"build")
                        self.assertFalse(result)
                        continue
                    nb.work_once(FixtureAPI(), plan, data, "fixture", root/"build")
                self.assertTrue(result["success"])
                self.assertEqual(result["distribution_proof"], proof)

                # Drive the collection entry point against locally materialized signed-input
                # fixtures. Certificate and RPM verification are exercised separately below.
                fixed_rev = ni.git(plan, "-c", "user.name=fixture", "-c", "user.email=fixture@localhost",
                                   "commit-tree", tree, "-p", rev, "-m", "later package")
                version2 = version.replace(".1.el", ".2.el") if d == "rocky" else version + "+deb" + r + "u1"
                next_plan = {**plan, "version":version2, "revision":fixed_rev}
                if d == "rocky":
                    next_plan["abi"] = version2 + ".x86_64"
                for file, body in [("base.json",plan),("fixed.json",next_plan),("worker.json",{"builder":"fixture"})]:
                    (root/file).write_text(json.dumps(body,default=str))
                receipt = dict(revision=fixed_rev, source_sha256="a"*64,package_sha256="b"*64,signer="fixture")
                def fake_prepare(selected, path, cache, fetch, source_only=False):
                    self.assertFalse(fetch)
                    return (fixed, receipt) if source_only else data
                class Collector:
                    def request(self, path, payload=None):
                        if path.endswith("/known"):
                            return {"commits":[], "active_patches":[]}
                        self_test.assertTrue(path.endswith("/"+target+"/discovered"))
                        added = payload["patches"][0]
                        self_test.assertEqual(added["content"], p)
                        self_test.assertEqual(added["commit"], fixed_rev)
                        self_test.assertEqual(added["fixed_release"]["source_sha256"], receipt["source_sha256"])
                        return {"added_patches":1}
                args = ["driver","collect","--plan",str(root/"base.json"),"--fixed",str(root/"fixed.json"),
                        "--cache",str(root),"--work-dir",str(root),"--controller",str(root/"worker.json"),
                        "--path","fs/x/main.c","--title","fixture"]
                with patch.object(nb,"prepare",side_effect=fake_prepare), patch.object(nb,"Controller",return_value=Collector()), \
                        patch.object(nb,"tool_env",return_value={**os.environ,"PATH":str(bins)+":"+os.environ["PATH"]}), \
                        patch.object(sys,"argv",args):
                    nb.main()

    @unittest.skipUnless(shutil.which("gpgv") and shutil.which("gpg"), "needs GnuPG")
    def test_signed_debian_index_chain_and_tampering(self):
        home = self.root/"gnupg"
        home.mkdir(mode=0o700)
        gpg = ["gpg","--homedir",home,"--batch","--pinentry-mode","loopback","--passphrase",""]
        ni.run(*gpg, "--quick-generate-key","fixture <archive@localhost>","ed25519","sign","1d")
        fpr = next(l.split(":")[9] for l in ni.run(*gpg,"--with-colons","--list-keys").splitlines() if l.startswith("fpr:"))
        keyring = self.root/"keyring.gpg"
        keyring.write_bytes(subprocess.check_output([*gpg,"--export"]))
        for suite in ("bookworm-security","trixie-security"):
            dist = self.root/"dists"/suite
            lines=[]
            for rel in ["main/binary-amd64/Packages.xz", "main/source/Sources.xz"]:
                p=dist/rel
                p.parent.mkdir(parents=True)
                p.write_bytes(lzma.compress(b"Package: linux\n"))
                lines.append(f" {ni.digest(p)} {p.stat().st_size} {rel}")
            content=dist/"Release"
            content.write_text(f"Origin: Debian\nCodename: {suite}\nValid-Until: Thu, 01 Jan 2099 00:00:00 UTC\nSHA256:\n"+"\n".join(lines)+"\n")
            ni.run(*gpg,"--output",dist/"InRelease","--clearsign",content)
            archive=ni.Archive(self.root,"",False)
            with patch.dict(ni.KEYS,{suite:{fpr}}):
                for attempt in ("ok","bad-index","expired","bad-release"):
                    work=self.root/(suite+attempt)
                    work.mkdir()
                    if attempt=="ok":
                        self.assertEqual(ni.signed_indices({"keyring":keyring},archive,suite,work)[0],fpr)
                    else:
                        if attempt=="bad-index": p.write_bytes(b"tampered")
                        elif attempt=="expired":
                            content.write_text(content.read_text().replace("2099", "2001"))
                            ni.run(*gpg, "--yes", "--output",dist/"InRelease","--clearsign",content)
                            with self.assertRaisesRegex(ValueError, "expired"):
                                ni.signed_indices({"keyring":keyring},archive,suite,work)
                            continue
                        else:
                            f=dist/"InRelease";f.write_bytes(f.read_bytes().replace(b"Origin: Debian",b"Origin: Mirror"))
                        with self.assertRaises((ValueError,subprocess.CalledProcessError)):
                            ni.signed_indices({"keyring":keyring},archive,suite,work)

    def test_reject_unsupported_targets(self):
        for i,(d,r,abi) in enumerate([("debian","11","6.1.0-57-amd64"),("debian","12","6.12.118+deb12-amd64"),
                                       ("debian","13","6.12.118+deb13-rt-amd64"),("rocky","10","6.12.0-264.21.1.el10_3.aarch64")]):
            with self.assertRaisesRegex(ValueError,"unsupported"):
                ni.prepare(dict(distro=d,release=r,abi=abi,version="1"),self.root/str(i),self.root)

    def test_native_installer_uses_only_distribution_packages(self):
        script = (DEPLOY / "install-agent.sh").read_text()
        block = script.split("else\n  # Native targets", 1)[1].split('\nfi\necho "■ 4.', 1)[0]
        block = block[block.index("\n") + 1:]
        for distro, package_tool in (("debian", "apt-get"), ("rocky", "dnf")):
            with self.subTest(distro=distro):
                # Run the same commands as the installer without package or system access.
                stub = """
set -eu
compgen() { return 1; }
apt-get() { echo apt-get "$@"; }
dnf() { echo dnf "$@"; }
kpatch() { return 0; }
"""
                got = subprocess.check_output(["bash", "-c", stub + block],
                                              env={"ID": distro, "K": "fixture", "PATH":"/usr/bin:/bin"}, text=True)
                self.assertEqual(len(got.splitlines()), 1)
                self.assertTrue(got.startswith(package_tool + " "))
                self.assertIn("binutils kmod mokutil", got)
                self.assertNotIn("ubuntu", got.lower())

    @unittest.skipUnless(shutil.which("bwrap"), "rootless installer namespace required")
    def test_full_native_install_and_cleanup_in_namespace(self):
        probe = subprocess.run(["bwrap", "--unshare-all", "--ro-bind", "/usr", "/usr", "--symlink", "usr/lib", "/lib",
                                "--symlink", "usr/lib64", "/lib64", "--", "/usr/bin/true"], capture_output=True)
        if probe.returncode:
            self.skipTest("cannot create unprivileged mount/network namespace")
        for distro, release, suite, abi, _ in CASES:
            with self.subTest(distro=distro, release=release):
                root = self.root / (distro+release)
                for directory in ("etc/systemd/system", "run/systemd/system", "var/lib", "local/bin", "local/sbin",
                                  "sys/kernel/livepatch", "modules/"+abi, "tools", "bundle"):
                    (root/directory).mkdir(parents=True)
                (root/"etc/os-release").write_text(f"ID={distro}\nVERSION_ID={release}\n")
                (root/"etc/hosts").write_text("127.0.0.1 localhost\n")
                def stub(path, body):
                    path.write_text("#!/bin/sh\n"+body+"\n")
                    path.chmod(0o755)
                for name in ("systemctl", "apt-get", "dnf", "mokutil", "apt-mark", "reboot", "modprobe", "kpatch"):
                    stub(root/"tools"/name, f'echo "{name} $*" >> /work/calls')
                stub(root/"tools/uname", f"echo {abi}")
                stub(root/"tools/systemd-detect-virt", "echo none")
                stub(root/"bundle/kpctl-agent", 'echo "agent $*" >> /work/calls')
                shutil.copy(DEPLOY/"install-agent.sh", root/"bundle")
                shutil.copy(DEPLOY/"uninstall-agent.sh", root/"bundle")
                shutil.copy(DEPLOY/"systemd/kpctl-agent.service", root/"bundle")
                args = ["bwrap", "--unshare-all", "--uid", "0", "--gid", "0", "--ro-bind", "/usr", "/usr",
                        "--symlink", "usr/lib", "/lib", "--symlink", "usr/lib64", "/lib64", "--symlink", "usr/bin", "/bin",
                        "--symlink", "usr/sbin", "/sbin", "--dev", "/dev", "--proc", "/proc",
                        "--bind", str(root/"etc"), "/etc", "--bind", str(root/"var"), "/var", "--bind", str(root/"local"), "/usr/local",
                        "--ro-bind", str(root/"sys"), "/sys", "--ro-bind", str(root/"run"), "/run",
                        "--ro-bind", str(root/"modules"), "/usr/lib/modules", "--bind", str(root), "/work",
                        "--setenv", "PATH", "/work/tools:/usr/bin:/usr/sbin", "--"]
                subprocess.run([*args, "bash", "/work/bundle/install-agent.sh", "https://localhost", "test-fixture"], check=True, stdout=subprocess.DEVNULL)
                self.assertTrue((root/"local/bin/kpctl-agent").is_file())
                self.assertTrue((root/"etc/systemd/system/kpctl-agent.service").is_file())
                self.assertFalse((root/"etc/kpctl/reboot-hook.sh").exists())
                self.assertNotIn("reboot_hook", json.loads((root/"etc/kpctl/agent.json").read_text()))
                self.assertFalse((root/"etc/apt").exists())
                subprocess.run([*args, "bash", "/work/bundle/uninstall-agent.sh"], check=True, stdout=subprocess.DEVNULL)
                self.assertFalse((root/"local/bin/kpctl-agent").exists())
                calls = (root/"calls").read_text()
                self.assertIn("agent -identify", calls)
                self.assertIn("systemctl enable kpctl-agent", calls)
                self.assertIn("systemctl disable --now kpctl-agent", calls)
                self.assertIn("apt-get install" if distro=="debian" else "dnf -y", calls)
                for forbidden in ("apt-mark", "reboot", "modprobe", "canonical", "kpatch.service",
                                  "dnf " if distro=="debian" else "apt-get"):
                    self.assertNotIn(forbidden, calls)

    def test_complete_source_additions_and_removals(self):
        a, b = self.root/"old", self.root/"new"
        for root in (a,b):
            (root/"fs").mkdir(parents=True)
        (a/"fs/retired.h").write_text("#define X 1\n")
        (b/"fs/fixed.h").write_text("#define X 2\n")
        delta = nb.candidate(a,b,["fs/fixed.h","fs/retired.h"])
        subprocess.run(["git","apply","--check","-"],cwd=a,input=delta.encode(),check=True)
        with self.assertRaisesRegex(ValueError, "complete edits"):
            nb.bounded_directories(a,[delta.encode()],["fs"])
        (a/"fs/link.h").symlink_to("retired.h")
        with self.assertRaisesRegex(ValueError, "through a link"):
            nb.candidate(a,b,["fs/link.h"])

    def test_signed_configuration_preserves_security_options(self):
        official = ['CONFIG_CC_VERSION_TEXT="gcc-12 (Debian fixture)"', 'CONFIG_SYSTEM_TRUSTED_KEYS="certs/rhel.pem"']
        conf = self.root / "config"
        conf.write_text("\n".join(official).replace("gcc-12 ", "gcc "))
        nb.verify_build_config(official, conf)
        conf.write_text("\n".join(official).replace("certs/rhel.pem", ""))
        with self.assertRaisesRegex(ValueError, "CONFIG_SYSTEM_TRUSTED_KEYS"):
            nb.verify_build_config(official, conf)

    def test_restore_rocky_packaged_trust_policy(self):
        source, work = self.root/"source", self.root/"work"
        (source/"configs").mkdir(parents=True)
        (source/"certs").mkdir()
        work.mkdir()
        policy = 'CONFIG_SYSTEM_TRUSTED_KEYS="certs/rhel.pem"'
        vendor = source/"configs/kernel-6.12.0-x86_64.config"
        vendor.write_text(policy+"\n")
        (source/"certs/rhel.pem").write_text("signed SRPM fixture")
        spec = self.root/"kernel.spec"
        spec.write_text("# The kernel was built with")
        packaged = self.root/"packaged-config"
        packaged.write_text('# The kernel was built with\n# '+policy+'\n# We are resetting this value to facilitate local builds\nCONFIG_SYSTEM_TRUSTED_KEYS=""\n')
        actual = ni.rocky_build_config(packaged,source,spec,"6.12.0-264.21.1.el10_3",work)
        self.assertEqual(actual.read_text(), policy+"\n")
        packaged.write_text('CONFIG_SYSTEM_TRUSTED_KEYS=""\n')
        with self.assertRaisesRegex(ValueError, "unrecorded Rocky trust"):
            ni.rocky_build_config(packaged,source,spec,"6.12.0-264.21.1.el10_3",work)
        packaged.write_text('# The kernel was built with\n# '+policy+'\n# We are resetting this value to facilitate local builds\nCONFIG_SYSTEM_TRUSTED_KEYS=""\n')
        vendor.write_text('CONFIG_SYSTEM_TRUSTED_KEYS=""\n')
        with self.assertRaisesRegex(ValueError, "original trusted keys"):
            ni.rocky_build_config(packaged,source,spec,"6.12.0-264.21.1.el10_3",work)

    def test_bounded_build_covers_all_translation_units(self):
        old, new = self.root / "old", self.root / "new"
        for tree, n in ((old, 1), (new, 2)):
            (tree/"fs/proc").mkdir(parents=True)
            (tree/"fs/proc/x.c").write_text(f"int x = {n};\n")
        delta = nb.candidate(old, new, ["fs/proc/x.c"]).encode()
        self.assertEqual(nb.bounded_directories(old, [delta], ["fs/proc"]), {"fs/proc"})
        with self.assertRaisesRegex(ValueError, "exactly"):
            nb.bounded_directories(old, [delta], ["kernel"])
        with self.assertRaisesRegex(ValueError, "complete edits"):
            nb.bounded_directories(old, [delta.replace(b"diff --git a/fs/proc/x.c", b"diff --git a/kernel/y.c")], ["fs/proc"])
        (old/"fs/other.c").write_text('#include "proc/x.c"\n')
        with self.assertRaisesRegex(ValueError, "also included"):
            nb.bounded_directories(old, [delta], ["fs/proc"])

    def test_incremental_candidate_pin_binds_parent_and_signed_paths(self):
        root=self.root
        versions=["6.1.192-1","6.1.192-2","6.1.192-3"]
        receipts=[]
        plans=[]
        for index, version in enumerate(versions):
            source=root/str(index)/"fs"
            source.mkdir(parents=True)
            (source/"x.c").write_text(f"int example = {index};\n")
            (source/"side.c").write_text("int other;\n")
            plan=dict(distro="debian",release="12",suite="bookworm-security",git="offline",abi=f"6.1.0-{55+index}-amd64",
                      version=version, revision=str(index+1)*40)
            plans.append(plan)
            (root/(str(index)+".json")).write_text(json.dumps(plan))
            receipts.append(dict(source_sha256=str(index+3)*64,package_sha256=str(index+5)*64,signer="fixture",revision=plan["revision"]))
        base=dict(receipts[0], track="native__debian__12__amd64__6.1.0-55-amd64__6.1.192-1__"+"1"*40)
        def prepare(plan,work,cache,fetch,source_only=False):
            idx=plans.index(plan)
            return (root/str(idx),receipts[idx]) if source_only else dict(source=root/str(idx),proof=base)
        def command(action,fixed,extra=()):
            argv=["driver",action,"--plan",str(root/"0.json"),"--fixed",str(root/f"{fixed}.json"),"--cache",str(root),
                  "--work-dir",str(root),"--path","fs/x.c",*extra]
            with patch.object(nb,"prepare",side_effect=prepare),patch.object(nb,"git",return_value=""),patch.object(sys,"argv",argv),patch("sys.stdout",new_callable=io.StringIO) as output:
                nb.main()
                return output.getvalue()
        first=command("candidate",1)
        first_pin=json.loads(command("candidate-proof",1))
        parent=root/"parent.json"
        parent.write_text(json.dumps(first_pin))
        flags=["--previous",str(root/"1.json"),"--parent-pin",str(parent)]
        second=command("candidate",2,flags)
        second_pin=json.loads(command("candidate-proof",2,flags))
        self.assertEqual(second_pin["parent_candidate"], first_pin["candidate_id"])
        self.assertEqual(second_pin["sha256"], hashlib.sha256(second.encode()).hexdigest())
        for diff in (first,second):
            subprocess.run(["git","apply","-"],input=diff.encode(),cwd=root/"0",check=True)
        self.assertEqual((root/"0/fs/x.c").read_bytes(), (root/"2/fs/x.c").read_bytes())
        self.assertEqual((root/"0/fs/side.c").read_bytes(),b"int other;\n")
        parent.write_text(json.dumps(dict(first_pin, paths=["fs/side.c"])))
        with self.assertRaisesRegex(ValueError,"paths"):
            command("candidate-proof",2,flags)

    def test_cache_recovery_requires_verified_replacement(self):
        source=self.root/"official"
        cache=self.root/"cache"
        source.mkdir()
        cache.mkdir()
        (cache/"signed").write_bytes(b"expired")
        (source/"signed").write_bytes(b"bad signature")
        def verify(path):
            ni.require(path.read_bytes()==b"verified","invalid signature")
            return "verified"
        with self.assertRaisesRegex(ValueError,"--fetch"):
            ni.Archive(cache,source.as_uri(),False).authenticated("signed",verify)
        archive=ni.Archive(cache,source.as_uri(),True)
        with self.assertRaisesRegex(ValueError,"signature"):
            archive.authenticated("signed",verify)
        self.assertEqual((cache/"signed").read_bytes(),b"expired")
        (source/"new").write_bytes(b"invalid")
        with self.assertRaisesRegex(ValueError, "fresh archive input rejected"):
            archive.authenticated("new", verify)
        self.assertFalse((cache/"new").exists())
        (source/"signed").write_bytes(b"verified")
        path,result=archive.authenticated("signed",verify)
        self.assertEqual((path.read_bytes(),result),(b"verified","verified"))

    def test_changes_lists_every_reviewable_path(self):
        base, fixed = self.root / "old", self.root / "new"
        for d in (base, fixed):
            (d/"fs").mkdir(parents=True)
            (d/"fs/a.c").write_text("same")
        (base/"fs/old.h").write_text("old")
        (fixed/"fs/new.h").write_text("new")
        (fixed/"fs/a.c").write_text("diff")
        self.assertEqual([(k,str(p)) for k,p in nb.changed_sources(base,fixed)],
                         [("modified","fs/a.c"),("added","fs/new.h"),("removed","fs/old.h")])

    @unittest.skipUnless(all(shutil.which(x) for x in ("rpmbuild","rpmsign","rpmkeys","gpg")), "needs RPM signing tools")
    def test_signed_rpm_archive_and_corruption(self):
        home = self.root / "gnupg"
        home.mkdir(mode=0o700)
        gpg = ["gpg","--homedir",str(home),"--batch"]
        ni.run(*gpg,"--passphrase","","--quick-generate-key","archive-test <fixture@localhost>","rsa2048","sign","1d")
        fpr = next(l.split(":")[9] for l in ni.run(*gpg,"--with-colons","--list-keys").splitlines() if l.startswith("fpr:"))
        key = self.root / "test-key"
        key.write_bytes(subprocess.check_output([*gpg,"--armor","--export"]))
        db = self.root / "rpmdb"
        ni.run("rpmkeys","--dbpath",db,"--import",key)
        # 다른 키도 같은 rpmdb 에 들여옵니다: 그 키의 정상 서명은 고정 키 서명으로 인정하지 않아야 합니다
        ni.run(*gpg,"--passphrase","","--quick-generate-key","other-signer <other@localhost>","rsa2048","sign","1d")
        other = next(l.split(":")[9] for l in ni.run(*gpg,"--with-colons","--list-keys","other@localhost").splitlines() if l.startswith("fpr:"))
        other_key = self.root / "other-key"
        other_key.write_bytes(subprocess.check_output([*gpg,"--armor","--export",other]))
        ni.run("rpmkeys","--dbpath",db,"--import",other_key)
        keys = ni.openpgp_keys(key) + ni.openpgp_keys(other_key)
        ni.run(*gpg,"--passphrase","","--quick-generate-key","stranger <stranger@localhost>","rsa2048","sign","1d")
        stranger = next(l.split(":")[9] for l in ni.run(*gpg,"--with-colons","--list-keys","stranger@localhost").splitlines() if l.startswith("fpr:"))
        for major in ("9","10"):
            with self.subTest(major=major):
                spec = self.root / "kernel.spec"
                spec.write_text("Name: kernel-core\nVersion: 1\nRelease: 1.el"+major+
                                "\nSummary: Offline archive fixture\nLicense: MIT\nBuildArch: noarch\n"
                                "%description\nOnly signed archive transport is under test.\n"
                                "%install\nmkdir -p %{buildroot}/fixture\necho test > %{buildroot}/fixture/payload\n"
                                "%files\n/fixture/payload\n")
                ni.run("rpmbuild","-bb","--define",f"_topdir {self.root}",spec)
                rpm = next((self.root/"RPMS").rglob(f"kernel-core-1-1.el{major}.noarch.rpm"))
                with self.assertRaises((ValueError,subprocess.CalledProcessError)):
                    ni.verify_rpm(rpm,db,fpr,keys)
                unsigned = rpm.read_bytes()
                ni.run("rpmsign","--define",f"_gpg_path {home}","--define",f"_gpg_name {other}",
                       "--define",f"_openpgp_sign_id {other}","--addsign",rpm)
                ni.verify_rpm(rpm,db,other,keys)  # 그 키를 고정했다면 통과
                with self.assertRaisesRegex(ValueError,"pinned release key"):
                    ni.verify_rpm(rpm,db,fpr,keys)
                rpm.write_bytes(unsigned)
                # 들여오지 않은 키의 서명(NOKEY)이 함께 있어도 고정 키 서명이 유효하면 통과 (rpmkeys 는 1 로 끝남)
                ni.run("rpmsign","--define",f"_gpg_path {home}","--define",f"_gpg_name {stranger}",
                       "--define",f"_openpgp_sign_id {stranger}","--addsign",rpm)
                with self.assertRaisesRegex(ValueError,"pinned release key|rpmkeys exited"):
                    ni.verify_rpm(rpm,db,fpr,keys)
                ni.run("rpmsign","--define",f"_gpg_path {home}","--define",f"_gpg_name {fpr}",
                       "--define",f"_openpgp_sign_id {fpr}","--addsign",rpm)
                ni.verify_rpm(rpm,db,fpr,keys)
                blob = bytearray(rpm.read_bytes())
                blob[-8] ^= 1
                rpm.write_bytes(blob)
                with self.assertRaises((ValueError,subprocess.CalledProcessError)):
                    ni.verify_rpm(rpm,db,fpr,keys)

    def test_rpm_signature_must_name_pinned_key(self):
        # Rocky 10 의 rpm 4.19 출력(짧은 key ID)과 rpm 6 출력(전체 지문·16자리 key ID)
        pin = "FC226859C0860BF0DDB95B085B106C736FEDFC85"
        v6 = "AB" * 32
        keys = [(4, pin, True), (6, v6, True)]
        ok419 = "    V4 RSA/SHA256 Signature, key ID 6fedfc85: OK\n"
        ok6 = "    Header OpenPGP V4 RSA/SHA512 signature, key fingerprint: " + pin.lower() + ": OK\n"
        v6sig = "    Header OpenPGP V6 ML-DSA-65+Ed25519/SHA512 signature, key fingerprint: " + v6.lower() + ": OK\n"
        payload = "    Payload SHA256 digest: OK\n"
        def check(body, rc=0, key_list=keys):
            out = subprocess.CompletedProcess([], rc, ("x.rpm:\n" + body).encode(), b"")
            with patch.object(ni.subprocess, "run", return_value=out):
                ni.verify_rpm(Path("x.rpm"), Path("db"), pin, key_list)
        check("    Header V4 RSA/SHA256 Signature, key ID 6fedfc85: OK\n    Header SHA256 digest: OK\n" + payload + ok419)
        check(ok6 + payload)
        check(v6sig + ok6 + payload)  # Rocky 10.3 의 v4·v6 이중 서명, 두 키 모두 들여온 경우
        check("    Header OpenPGP V6 signature, key ID abababababababab: NOKEY\n" + ok6 + payload, rc=1)
        for body, rc, key_list, reason in [
            (v6sig + payload, 0, keys, "pinned release key"),
            (ok419, 0, keys, "payload"),
            (ok6 + payload.replace("OK", "BAD"), 1, keys, "verification failed"),
            (ok6.replace("OK", "BAD") + ok6 + payload, 1, keys, "verification failed"),
            ("    Header OpenPGP V4 signature, key ID 5b106c736fedfc85: NOKEY\n" + payload, 1, keys, "pinned release key"),
            (ok6 + payload, 1, keys, "rpmkeys exited"),
            ("    Header OpenPGP V6 signature, key ID abababababababab: NOKEY\n" + ok6 + payload, -9, keys, "rpmkeys exited"),
            # 여러 단어 결과(BAD (Expected …))도 실패로 봄
            ("    Header OpenPGP V6 signature, key ID abababababababab: NOKEY\n" + ok6 + payload +
             "    Payload SHA512 digest: BAD (Expected 1111 != 2222)\n", 1, keys, "verification failed"),
            (ok6 + payload + "    Header SHA256 digest: NOKEY\n", 0, keys, "NOKEY on a digest"),
            # 줄인 지문은 전체 지문으로 인정하지 않음
            ("    Header OpenPGP V4 RSA/SHA512 signature, key fingerprint: 5b106c736fedfc85: OK\n" + payload, 0, keys, "pinned release key"),
            # v6 key ID 는 지문 앞 64비트: 그 끝이 고정 키의 짧은 ID 와 겹치면 고정 키라고 단정하지 않음
            (ok419 + payload, 0, keys + [(6, "00000000" + "6FEDFC85" + "0" * 48, True)], "pinned release key"),
            (ok419 + payload, 0, keys + [(4, "0" * 32 + "6FEDFC85", True)], "pinned release key"),
        ]:
            with self.subTest(body=body, keys=len(key_list)), self.assertRaisesRegex(ValueError, reason):
                check(body, rc, key_list)

    @unittest.skipUnless(shutil.which("gpg"), "needs GnuPG")
    def test_release_key_file_with_v6_key(self):
        # Rocky 10.3 의 RPM-GPG-KEY-Rocky-10 처럼 v4 고정 키 옆에 RFC 9580 v6 키가 있는 파일
        home = self.root / "gnupg6"
        home.mkdir(mode=0o700)
        gpg = ["gpg","--homedir",str(home),"--batch"]
        ni.run(*gpg,"--passphrase","","--quick-generate-key","release <release@localhost>","rsa2048","sign","1d")
        fpr = next(l.split(":")[9] for l in ni.run(*gpg,"--with-colons","--list-keys").splitlines() if l.startswith("fpr:"))
        v4 = subprocess.check_output([*gpg,"--export"])
        v6_body = bytes([6]) + (1767225600).to_bytes(4,"big") + bytes([27]) + (32).to_bytes(4,"big") + bytes(range(32))
        v6_packet = bytes([0xC0 | 6, len(v6_body)]) + v6_body
        def armor(data):
            b64 = base64.b64encode(data).decode()
            lines = "\n".join(b64[i:i+64] for i in range(0, len(b64), 64))
            crc = base64.b64encode(hashlib.sha256(data).digest()[:3]).decode()  # 틀린 CRC 라도 거부하지 않음 (RFC 9580 §6.1)
            return f"-----BEGIN PGP PUBLIC KEY BLOCK-----\nVersion: fixture\n\n{lines}\n={crc}\n-----END PGP PUBLIC KEY BLOCK-----\n"
        expected_v6 = hashlib.sha256(b"\x9b" + len(v6_body).to_bytes(4,"big") + v6_body).hexdigest().upper()
        for name, content in (("one-block", armor(v4 + v6_packet)), ("two-blocks", armor(v4) + armor(v6_packet)), ("binary", v4 + v6_packet)):
            with self.subTest(name):
                key = self.root / name
                key.write_bytes(content if isinstance(content, bytes) else content.encode())
                signer, keys = ni.pinned_signer(key, {fpr})
                self.assertEqual(signer, fpr)
                self.assertIn((6, expected_v6, True), keys)
                with self.assertRaisesRegex(ValueError, "pinned release signing key"):
                    ni.pinned_signer(key, {"0"*40})
        # GnuPG 2.4 는 이 파일을 통째로 거부합니다 (설치 실패의 원인)
        bad = subprocess.run([*gpg,"--with-colons","--show-keys",self.root/"one-block"], capture_output=True)
        if bad.returncode == 0:
            self.assertIn(fpr, bad.stdout.decode())
        spaced = armor(v4).splitlines()
        spaced[3] = " ".join(spaced[3][k:k+16] for k in range(0, len(spaced[3]), 16)) + "  "
        (self.root / "spaced").write_text("\n".join(spaced) + "\n")
        self.assertEqual(ni.pinned_signer(self.root / "spaced", {fpr})[0], fpr)
        # base64 패딩 "==" 만 따로 한 줄에 있어도 CRC 줄로 오인하지 않음
        b64 = base64.b64encode(v4).decode()
        while not b64.endswith("=="):
            v4 += b"\xb4\x00"  # 빈 user ID 패킷(무시됨)으로 길이를 맞춰 패딩 "==" 를 만듦
            b64 = base64.b64encode(v4).decode()
        (self.root / "padding").write_text("-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n" + b64[:-2] + "\n==\n=AAAA\n-----END PGP PUBLIC KEY BLOCK-----\n")
        self.assertEqual(ni.pinned_signer(self.root / "padding", {fpr})[0], fpr)
        # 바이너리 키의 user ID 에 armor 머리글 문자열이 있어도 바이너리로 읽음
        uid = b"-----BEGIN PGP PUBLIC KEY BLOCK-----"
        (self.root / "uid").write_bytes(v4 + bytes([0xC0 | 13, len(uid)]) + uid)
        self.assertEqual(ni.pinned_signer(self.root / "uid", {fpr})[0], fpr)
        for name, blob in (("header", v4 + b"\xc6"), ("length", v4 + b"\xc6\xff\x00"), ("body", v4 + b"\xc6\x05\x04")):
            with self.subTest(truncated=name):
                (self.root / name).write_bytes(blob)
                with self.assertRaisesRegex(ValueError, "truncated"):
                    ni.pinned_signer(self.root / name, {fpr})
