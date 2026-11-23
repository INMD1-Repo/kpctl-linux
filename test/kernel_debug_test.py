import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[1]
KERNEL = "6.8.0-51-generic"
VERSION = "6.8.0-51.52"


class KernelDebugInstall(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.debug = self.root / "debug" / ("vmlinux-" + KERNEL)
        self.debug.parent.mkdir()
        (self.root / "os-release").write_text("VERSION_CODENAME=noble\n")
        self.config = {
            "apt_symbol": "unsigned",
            "entries": [self.publication()],
        }
        self.write_config()
        (self.root / "installed.json").write_text("[]")
        self.script = self.root / "kpctl-kernel-debug.sh"
        self.script.write_text(
            (REPO / "deploy/kpctl-kernel-debug.sh")
            .read_text()
            .replace("/usr/lib/debug/boot", str(self.debug.parent))
            .replace("/etc/os-release", str(self.root / "os-release"))
        )
        bin_dir = self.root / "bin"
        bin_dir.mkdir()
        command = bin_dir / "mock-command"
        command.write_text(
            f"#!{sys.executable}\n"
            + r'''
import json
import os
from pathlib import Path
import sys

root = Path(os.environ["KERNEL_DEBUG_TEST_ROOT"])
config = json.loads((root / "config.json").read_text())
command, args = Path(sys.argv[0]).name, sys.argv[1:]
with (root / "commands.jsonl").open("a") as output:
    output.write(json.dumps([command, args]) + "\n")
state = root / "installed.json"
installed = set(json.loads(state.read_text()))

def install(packages):
    installed.update(packages)
    if config.get("omit_headers"):
        installed.discard("linux-headers-6.8.0-51-generic")
    state.write_text(json.dumps(sorted(installed)))
    if any(package.endswith("-dbgsym") for package in installed):
        (root / "debug/vmlinux-6.8.0-51-generic").write_text("vmlinux")

if command == "id":
    print(0)
elif command == "dpkg-query":
    if args[-1] not in installed:
        sys.exit(1)
    print("installed")
elif command == "apt-get":
    if "update" in args:
        sys.exit(0)
    if "-f" in args:
        sys.exit(100 if config.get("fix_failure") else 0)
    packages = [arg.split("=", 1)[0] for arg in args if arg.startswith("linux-")]
    symbol = "unsigned" if any("unsigned" in p and p.endswith("-dbgsym") for p in packages) else "signed"
    if symbol != config.get("apt_symbol"):
        print("E: Unable to locate package", file=sys.stderr)
        sys.exit(100)
    install(packages)
elif command == "dpkg":
    if args == ["--print-architecture"]:
        print("amd64")
    else:
        install([Path(arg).name.split("_", 1)[0] for arg in args[1:]])
        sys.exit(1 if config.get("dpkg_failure") else 0)
elif command == "curl":
    destination = Path(args[args.index("-o") + 1])
    if any(arg.startswith("https://api.launchpad.net/") for arg in args):
        if config.get("api_failure"):
            print("curl: Launchpad metadata unavailable", file=sys.stderr)
            sys.exit(22)
        destination.write_text(json.dumps({"entries": config["entries"]}))
    else:
        if destination.name.startswith(config.get("missing", "never-match")):
            sys.exit(22)
        destination.write_text("package")
else:
    raise SystemExit("unexpected command: " + command)
'''
        )
        command.chmod(0o755)
        for name in ("id", "dpkg-query", "apt-get", "dpkg", "curl"):
            (bin_dir / name).symlink_to(command.name)
        self.environ = dict(
            os.environ,
            PATH=str(bin_dir) + os.pathsep + os.environ["PATH"],
            KERNEL_DEBUG_TEST_ROOT=str(self.root),
        )

    def publication(self, **changes):
        entry = {
            "binary_package_name": "linux-image-unsigned-" + KERNEL,
            "binary_package_version": VERSION,
            "distro_arch_series_link": "https://api.launchpad.net/1.0/ubuntu/noble/amd64",
            "pocket": "Updates",
            "date_published": "2024-12-16T13:36:19Z",
            "status": "Deleted",
        }
        return dict(entry, **changes)

    def write_config(self):
        (self.root / "config.json").write_text(json.dumps(self.config))

    def run_helper(self, version=None, kernel=KERNEL):
        self.write_config()
        return subprocess.run(
            ["bash", str(self.script), kernel, *([version] if version else [])],
            env=self.environ,
            capture_output=True,
            text=True,
            timeout=15,
        )

    def commands(self, name):
        return [
            args
            for command, args in map(
                json.loads, (self.root / "commands.jsonl").read_text().splitlines()
            )
            if command == name
        ]

    def test_apt_unsigned_symbols_include_all_kernel_inputs(self):
        result = self.run_helper(VERSION)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        attempts = [args for args in self.commands("apt-get") if "install" in args]
        self.assertEqual(len(attempts), 1)
        for package in (
            "linux-image-" + KERNEL,
            "linux-image-unsigned-" + KERNEL + "-dbgsym",
            "linux-headers-" + KERNEL,
            "linux-modules-" + KERNEL,
        ):
            self.assertIn(package + "=" + VERSION, attempts[0])
        self.assertFalse(self.commands("curl"))

    def test_apt_retries_signed_symbol_package(self):
        self.config["apt_symbol"] = "signed"
        result = self.run_helper()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        attempts = [args for args in self.commands("apt-get") if "install" in args]
        self.assertEqual(len(attempts), 2)
        self.assertIn("linux-image-" + KERNEL + "-dbgsym", attempts[1])
        self.assertFalse(self.commands("curl"))

    def test_symbols_alone_do_not_skip_missing_headers_and_modules(self):
        self.debug.write_text("existing vmlinux")
        result = self.run_helper()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(self.commands("apt-get"))

    def test_complete_install_skips_package_and_network_operations(self):
        self.debug.write_text("existing vmlinux")
        (self.root / "installed.json").write_text(
            json.dumps(["linux-" + part + "-" + KERNEL for part in ("image", "headers", "modules")])
        )
        result = self.run_helper()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(self.commands("apt-get"))
        self.assertFalse(self.commands("curl"))

    def test_pinned_launchpad_download_uses_exact_version_and_signed_image(self):
        self.config["apt_symbol"] = None
        result = self.run_helper(VERSION)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        downloads = self.commands("curl")
        self.assertEqual(len(downloads), 5)
        self.assertTrue(downloads[0][-1].endswith(f"linux-image-{KERNEL}_{VERSION}_amd64.deb"))
        self.assertTrue(all(f"_{VERSION}_" in args[-1] for args in downloads))
        self.assertEqual(len(self.commands("dpkg")[-1]), 6)

    def test_existing_unsigned_image_is_preserved(self):
        image = "linux-image-unsigned-" + KERNEL
        (self.root / "installed.json").write_text(json.dumps([image]))
        self.config["apt_symbol"] = None
        result = self.run_helper(VERSION)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        attempts = [args for args in self.commands("apt-get") if "install" in args]
        self.assertTrue(all(image + "=" + VERSION in args for args in attempts))
        self.assertTrue(self.commands("curl")[0][-1].endswith(f"{image}_{VERSION}_amd64.deb"))

    def test_missing_signed_image_uses_unsigned_for_new_inputs(self):
        self.config.update(apt_symbol=None, missing="linux-image-" + KERNEL + "_")
        result = self.run_helper(VERSION)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(self.commands("curl")[1][-1].endswith(
            f"linux-image-unsigned-{KERNEL}_{VERSION}_amd64.deb"
        ))

    def test_unpinned_launchpad_ignores_other_series_arch_hwe_and_proposed(self):
        self.config["apt_symbol"] = None
        self.config["entries"] += [
            self.publication(binary_package_version="6.8.0-51.9"),
            self.publication(binary_package_version="6.8.0-51.999", pocket="Proposed"),
            self.publication(binary_package_version="6.8.0-51.52~22.04.1"),
            self.publication(binary_package_version="6.8.0-51.999", date_published=None),
            self.publication(binary_package_version="6.8.0-51.999", distro_arch_series_link="https://api.launchpad.net/1.0/ubuntu/noble/arm64"),
            self.publication(binary_package_version="6.8.0-51.999", distro_arch_series_link="https://api.launchpad.net/1.0/ubuntu/jammy/amd64"),
            self.publication(binary_package_name="linux-image-unsigned-6.8.0-52-generic"),
        ]
        result = self.run_helper()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        metadata, *downloads = self.commands("curl")
        self.assertIn("distro_arch_series=https://api.launchpad.net/1.0/ubuntu/noble/amd64", metadata)
        self.assertTrue(all(f"_{VERSION}_" in args[-1] for args in downloads))

    def test_metadata_failure_is_reported_without_installing_packages(self):
        self.config.update(apt_symbol=None, api_failure=True)
        result = self.run_helper()
        self.assertEqual(result.returncode, 3)
        self.assertIn("버전 조회 실패", result.stderr)
        self.assertFalse(any("-i" in args for args in self.commands("dpkg")))

    def test_no_matching_publication_does_not_guess_a_version(self):
        self.config.update(apt_symbol=None, entries=[self.publication(pocket="Proposed")])
        result = self.run_helper()
        self.assertEqual(result.returncode, 3)
        self.assertIn("정확한 패키지 버전", result.stderr)
        self.assertEqual(len(self.commands("curl")), 1)

    def test_required_download_failure_stops_before_dpkg(self):
        self.config.update(apt_symbol=None, missing="linux-modules-")
        result = self.run_helper(VERSION)
        self.assertEqual(result.returncode, 3)
        self.assertIn("필수 입력 패키지 다운로드 실패", result.stderr)
        self.assertFalse(any("-i" in args for args in self.commands("dpkg")))

    def test_dependency_repair_failure_is_not_reported_as_success(self):
        self.config.update(apt_symbol=None, dpkg_failure=True, fix_failure=True)
        result = self.run_helper(VERSION)
        self.assertEqual(result.returncode, 3)
        self.assertIn("의존성 복구 실패", result.stderr)
        self.assertNotIn("설치 완료:", result.stdout)

    def test_missing_headers_after_install_is_not_reported_as_success(self):
        self.config.update(apt_symbol=None, omit_headers=True)
        result = self.run_helper(VERSION)
        self.assertEqual(result.returncode, 3)
        self.assertTrue(self.debug.exists())
        self.assertIn("설치 미완료", result.stderr)

    def test_fresh_setup_uses_helper_and_propagates_failure(self):
        setup = (REPO / "deploy/setup-builder.sh").read_text()
        section = setup.split('echo "■ 커널별 디버그 심볼"', 1)[1].split('echo "■ 빌드 사용자"', 1)[0]
        section = section.replace("/usr/lib/debug/boot", str(self.debug.parent))
        for failure in (False, True):
            with self.subTest(failure=failure):
                self.config.update(apt_symbol=None, api_failure=failure)
                self.write_config()
                (self.root / "installed.json").write_text("[]")
                if self.debug.exists():
                    self.debug.unlink()
                result = subprocess.run(
                    [
                        "bash", "-euo", "pipefail", "-c",
                        'HERE=$1; KERNELS=("$2"); HOST_MODE=0\n' + section,
                        "setup-kernel-stage", str(self.root), KERNEL,
                    ],
                    env=self.environ, capture_output=True, text=True, timeout=15,
                )
                self.assertEqual(result.returncode, 1 if failure else 0, result.stdout + result.stderr)
                if failure:
                    self.assertIn("위 APT·Launchpad 오류", result.stderr)
                else:
                    self.assertIn("Launchpad 에서 받기", result.stdout)


if __name__ == "__main__":
    unittest.main()
