"""Build tiny local package archives and Git releases and replay the native input reader.

The ELF payload is a userspace fixture with DWARF. No kernel or module is built
or loaded by these tests. Trial compiler invocation and deployment have their
own subprocess and HTTP fixtures.
"""
import lzma
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "deploy"))
import native_inputs as ni


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data.encode() if isinstance(data, str) else data)
    return path


def subprocess_ok(*args, cwd=None):
    # Keep successful package build output quiet; display diagnostics on failure.
    result = subprocess.run(args, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if result.returncode:
        raise AssertionError(result.stdout.decode(errors="replace")[-6000:])
    return result.stdout.decode().strip()


class NativeArchive(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.keyhome = self.root / "keys"
        self.keyhome.mkdir(mode=0o700)
        self.gpg = ["gpg", "--homedir", self.keyhome, "--batch", "--pinentry-mode", "loopback", "--passphrase", ""]
        subprocess_ok(*self.gpg, "--quick-generate-key", "local package fixture <test@localhost>", "rsa2048", "sign", "1d")
        keys = subprocess_ok(*self.gpg, "--with-colons", "--list-keys")
        self.fpr = next(row.split(":")[9] for row in keys.splitlines() if row.startswith("fpr:"))
        self.keyring = write(self.root/"keyring.gpg", subprocess.check_output([*self.gpg, "--export"]))
        self.elf = self.root/"fixture.elf"
        subprocess_ok("cc", "-g", "-Wl,--build-id=sha1", "-o", self.elf, write(self.root/"sample.c", "int main(void) { return 0; }\n"))

    def git_release(self, directory, plan, origin, tag, branch):
        subprocess_ok("git", "init", "-q", directory)
        subprocess_ok("git", "-C", directory, "remote", "add", "origin", origin)
        subprocess_ok("git", "-C", directory, "add", ".")
        tree = subprocess_ok("git", "-C", directory, "write-tree")
        rev = subprocess_ok("git", "-C", directory, "-c", "user.name=fixture", "-c",
                            "user.email=fixture@localhost", "commit-tree", tree, "-m", "offline signed release")
        for ref in ("refs/tags/"+tag, "refs/remotes/origin/"+branch):
            subprocess_ok("git", "-C", directory, "update-ref", ref, rev)
        plan.update(git=str(directory), revision=rev)

    def source_tree(self, tree):
        write(tree/"init/main.c", "int sample = 0;\n")
        write(tree/"Kbuild", "# fixture\n")
        write(tree/"scripts/extract-vmlinux", '#!/bin/sh\ncat "$1"\n')

    @unittest.skipUnless(all(shutil.which(t) for t in ("gpg", "cc", "openssl", "readelf")), "ELF and certificate tools required")
    def test_public_certificate_from_debian_elf(self):
        der = self.root/"public.der"
        subprocess_ok("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=fixture",
                      "-keyout", self.root/"temporary.key", "-outform", "DER", "-out", der)
        for length in (der.stat().st_size, 0):
            asm = write(self.root/"fixture.S", f'.section .rodata\n__module_cert_start:\n.incbin "{der}"\n__module_cert_end:\n.balign 8\n.globl module_cert_size\nmodule_cert_size: .quad {length}\n')
            image = self.root / "fixture.o"
            subprocess_ok("cc", "-c", "-o", image, asm)
            dest = self.root / "output/signing_key.pem"
            if length:
                ni.public_module_cert(image, dest)
                self.assertEqual(der.read_bytes(), subprocess.check_output(["openssl", "x509", "-in", dest, "-outform", "DER"]))
            else:
                with self.assertRaisesRegex(ValueError, "certificate length"):
                    ni.public_module_cert(image, dest)

    @unittest.skipUnless(all(shutil.which(t) for t in ("gpg", "gpgv", "cc", "dpkg-source", "dpkg-deb")), "Debian archive tools required")
    def test_debian_signed_packages_quilt_and_git(self):
        for rel, suite, abi, version in (
            ("12", "bookworm-security", "6.1.0-57-amd64", "6.1.192-3"),
            ("13", "trixie-security", "6.12.115+deb13.1-amd64", "6.12.115-1"),
        ):
            with self.subTest(suite=suite):
                root = self.root / rel
                upstream = version.split("-")[0]
                top = root / ("linux-"+upstream)
                self.source_tree(top)
                subprocess_ok("tar", "-C", root, "-cJf", root/f"linux_{upstream}.orig.tar.xz", top.name)
                packaging = top/"debian"
                write(packaging/"source/format", "3.0 (quilt)\n")
                write(packaging/"control", "Source: linux\nSection: kernel\nPriority: optional\nMaintainer: Test <test@localhost>\nStandards-Version: 4.6.2\n\nPackage: linux-test\nArchitecture: amd64\nDescription: test fixture\n")
                write(packaging/"changelog", f"linux ({version}) unstable; urgency=medium\n\n  * fixture\n\n -- Test <test@localhost>  Thu, 01 Jan 2026 00:00:00 +0000\n")
                write(packaging/"rules", "#!/usr/bin/make -f\n").chmod(0o755)
                write(packaging/"patches/series", "fixture.patch\n")
                write(packaging/"patches/fixture.patch", "--- a/init/main.c\n+++ b/init/main.c\n@@ -1 +1 @@\n-int sample = 0;\n+int sample = 1;\n")
                subprocess_ok("dpkg-source", "--before-build", top)
                subprocess_ok("dpkg-source", "-b", top, cwd=root)
                plan = dict(distro="debian", release=rel, suite=suite, abi=abi, version=version, keyring=str(self.keyring))
                repo = root/"git"
                shutil.copytree(packaging, repo/"debian")
                branch = f"debian/{ni.DEBIAN[rel][1]}/{suite}"
                self.git_release(repo, plan, ni.SALSA, "debian/"+version, branch)
                archive = root/"cache"/suite
                pool = archive/"pool"
                pool.mkdir(parents=True)
                source_entries = []
                for f in sorted(root.glob("linux_*")):
                    shutil.copy(f, pool)
                    source_entries.append(f" {ni.digest(f)} {f.stat().st_size} {f.name}")
                sources = f"Package: linux\nVersion: {version}\nFormat: 3.0 (quilt)\nDirectory: pool\nChecksums-Sha256:\n" + "\n".join(source_entries)+"\n"
                packages = []
                for name, payload in (
                    ("linux-image-"+abi, {"boot/vmlinuz-"+abi: self.elf.read_bytes(), "lib/modules/"+abi+"/test.ko": b"reference fixture"}),
                    ("linux-headers-"+abi, {"usr/src/linux-headers-"+abi+"/.config": b"CONFIG_LIVEPATCH=y\n", "usr/src/linux-headers-"+abi+"/Module.symvers": b"fixture\n"}),
                    ("linux-image-"+abi+"-dbg", {"usr/lib/debug/boot/vmlinux-"+abi: self.elf.read_bytes()}),
                ):
                    pkg = root/name
                    src = "linux-signed-amd64" if name == "linux-image-"+abi else "linux"
                    ctl = f"Package: {name}\nVersion: {version}\nArchitecture: amd64\nSource: {src}\nMaintainer: Test <test@localhost>\nDescription: test\n"
                    if src == "linux-signed-amd64":
                        ctl += f"Built-Using: linux (= {version})\n"
                    write(pkg/"DEBIAN/control", ctl)
                    for path, blob in payload.items():
                        write(pkg/path, blob)
                    deb = pool/(name+".deb")
                    subprocess_ok("dpkg-deb", "--build", pkg, deb)
                    packages.append(ctl + f"Filename: pool/{deb.name}\nSHA256: {ni.digest(deb)}\n")
                dist = archive/"dists"/suite
                hashes = []
                for path, content in (("main/binary-amd64/Packages.xz", "\n".join(packages)), ("main/source/Sources.xz", sources)):
                    f = write(dist/path, lzma.compress(content.encode()))
                    hashes.append(f" {ni.digest(f)} {f.stat().st_size} {path}")
                release = write(dist/"Release", f"Origin: Debian\nCodename: {suite}\nValid-Until: Thu, 01 Jan 2099 00:00:00 UTC\nSHA256:\n"+"\n".join(hashes)+"\n")
                subprocess_ok(*self.gpg, "--output", dist/"InRelease", "--clearsign", release)
                with patch.dict(ni.KEYS, {suite: {self.fpr}}):
                    profile={k:v for k,v in plan.items() if k not in ("revision","version","abi")}
                    scan=root/"discovery"
                    scan.mkdir()
                    self.assertEqual(list(ni.discover(profile,root/"cache",scan,False,4)), [plan])
                    inputs = ni.prepare(plan, root/"inputs", root/"cache")
                self.assertEqual((inputs["source"]/"init/main.c").read_text(), "int sample = 1;\n")
                self.assertEqual(inputs["proof"]["signer"], self.fpr)
                self.assertEqual(inputs["proof"]["revision"], plan["revision"])
                self.assertIn(f"__{abi}__{version}__", inputs["proof"]["track"])

    @unittest.skipUnless(all(shutil.which(t) for t in ("gpg", "cc", "rpmbuild", "rpmkeys", "cpio", "rpm2cpio", "rpmsign")), "RPM archive tools required")
    def test_rocky_signed_srpm_spec_lookaside_and_packages(self):
        for rel, base, release in (("9", "5.14.0", "741.27.1.el9_9"), ("10", "6.12.0", "264.21.1.el10_3")):
            with self.subTest(release=rel):
                ver = base+"-"+release
                abi = ver+".x86_64"
                root = self.root/rel
                src = root/"kernel-src"
                self.source_tree(src)
                write(src/f"configs/kernel-{base}-x86_64.config", 'CONFIG_SYSTEM_TRUSTED_KEYS=""\n')
                shutil.copy(self.elf, src/"sample.elf")
                sources = root/"SOURCES"
                sources.mkdir()
                tarball = sources/"fixture.tar.xz"
                subprocess_ok("tar", "-C", root, "-cJf", tarball, src.name)
                spec = root/"SPECS/kernel.spec"
                header = f"""Name: kernel
Version: {base}
Release: {release.split('.el')[0]}%{{?dist}}
Summary: Local fixture
License: MIT
Source0: fixture.tar.xz
%description
Archive verification fixture.
"""
                files = {
                    "kernel-core": [(f"/lib/modules/{abi}/vmlinuz", "sample.elf")],
                    "kernel-devel": [(f"/usr/src/kernels/{abi}/Module.symvers", "Kbuild")],
                    "kernel-modules-core": [(f"/lib/modules/{abi}/config", "config"), (f"/lib/modules/{abi}/test.ko", "sample.elf")],
                    "kernel-debuginfo": [(f"/usr/lib/debug/lib/modules/{abi}/vmlinux", "sample.elf")],
                }
                ctl = header
                for name in files:
                    ctl += f"\n%package -n {name}\nSummary: Offline fixture\n%description -n {name}\nOnly a package fixture.\n"
                ctl += '\n%prep\n%setup -q -n kernel-src\nsed -i s/0/1/g init/main.c\n%install\necho CONFIG_LIVEPATCH=y > config\n'
                ctl += "cat configs/kernel-"+base+"-x86_64.config >> config\n"
                for paths in files.values():
                    for name, file in paths:
                        ctl += f"install -Dm644 {file} %{{buildroot}}{name}\n"
                for name, paths in files.items():
                    ctl += f"\n%files -n {name}\n"+"\n".join(path for path, _ in paths)+"\n"
                write(spec, ctl)
                dist = ".el"+release.split(".el")[1]
                subprocess_ok("rpmbuild", "-ba", "--define", "_topdir "+str(root), "--define", "dist "+dist,
                              "--define", "debug_package %{nil}", "--define", "__os_install_post %{nil}", spec)
                repo = root/"git"
                write(repo/"SPECS/kernel.spec", spec.read_bytes())
                write(repo/".kernel.metadata", ni.digest(tarball)+"  SOURCES/fixture.tar.xz\n")
                key = write(root/"key.asc", subprocess.check_output([*self.gpg, "--armor", "--export"]))
                plan = dict(distro="rocky", release=rel, suite="BaseOS", abi=abi, version=ver, keyring=str(key))
                self.git_release(repo, plan, ni.ROCKY, f"patched/r{rel}/kernel-{ver}", "r"+rel)
                cache = root/"cache"/("rocky"+rel)
                routes = {"kernel": "BaseOS/source/tree", "kernel-core": "BaseOS/x86_64/os",
                          "kernel-modules-core": "BaseOS/x86_64/os", "kernel-devel": "AppStream/x86_64/os",
                          "kernel-debuginfo": "BaseOS/x86_64/debug/tree"}
                for name, route in routes.items():
                    f = root/"SRPMS"/f"kernel-{ver}.src.rpm" if name == "kernel" else root/"RPMS/x86_64"/f"{name}-{abi}.rpm"
                    subprocess_ok("rpmsign", "--define", "_gpg_path "+str(self.keyhome), "--define", "_gpg_name "+self.fpr,
                                  "--define", "_openpgp_sign_id "+self.fpr, "--addsign", f)
                    write(cache/route/"Packages/k"/f.name, f.read_bytes())
                # RPM commands, signatures, tag and source extraction are real.
                # CI is allowed to run the miniature spec outside a Rocky OS.
                with patch.dict(ni.KEYS, {rel:{self.fpr}}), patch.object(ni, "native_environment"):
                    profile={k:v for k,v in plan.items() if k not in ("revision","version","abi")}
                    scan=root/"discovery"
                    scan.mkdir()
                    self.assertEqual(list(ni.discover(profile,root/"cache",scan,False,4)), [plan])
                    inputs = ni.prepare(plan, root/"inputs", root/"cache")
                self.assertEqual((inputs["source"]/"init/main.c").read_text(), "int sample = 1;\n")
                self.assertEqual(inputs["proof"]["signer"], self.fpr)
                self.assertEqual(inputs["proof"]["revision"], plan["revision"])
                self.assertIn(f"__{abi}__{ver}__", inputs["proof"]["track"])
