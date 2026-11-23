import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import urllib.error


REPO = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("kernel_inputs", REPO / "deploy/kpctl-kernel-inputs.py")
inputs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inputs)
KERNEL, VERSION = "6.8.0-51-generic", "6.8.0-51.52"
IMAGE = "linux-image-" + KERNEL


class Response(io.BytesIO):
    def __init__(self, data, **headers):
        super().__init__(data)
        self.headers = {"Content-Length": str(len(data)), "X-Checksum-Sha256": hashlib.sha256(data).hexdigest(), **headers}


class Opener:
    def __init__(self, missing=()):
        self.requests = []
        self.missing = missing
        self.headers = {}

    def open(self, request, timeout):
        self.requests.append(request)
        filename = request.full_url.rsplit("/", 1)[1]
        if any(filename.startswith(prefix) for prefix in self.missing):
            raise urllib.error.HTTPError(request.full_url, 404, "missing", {}, None)
        return Response(filename.encode(), **self.headers)


def package_fields(args, text):
    name = Path(args[2]).name.removesuffix(".partial")
    package, version, architecture = name.rsplit("_", 2)
    arch = architecture.split(".", 1)[0]
    return f"Package: {package}\nVersion: {version}\nArchitecture: {arch}\n"


class ControllerKernelInputs(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.opener = Opener()
        patch = mock.patch.object(inputs.subprocess, "check_output", side_effect=package_fields)
        patch.start()
        self.addCleanup(patch.stop)

    def download(self, **kwargs):
        return inputs.download_inputs(KERNEL, VERSION, "amd64", self.root, IMAGE,
                                      ("https://controller.example", "private-builder-token", self.opener), **kwargs)

    def test_downloads_real_bytes_for_all_five_inputs_through_controller(self):
        paths = self.download()
        self.assertEqual(len(paths), 5)
        self.assertTrue(any(path.name.endswith("_all.deb") for path in paths))
        self.assertTrue(any(path.name.endswith(".ddeb") for path in paths))
        for path, request in zip(paths, self.opener.requests):
            self.assertEqual(path.read_bytes(), path.name.encode())
            self.assertTrue(request.full_url.startswith(f"https://controller.example/api/builder/kernel-inputs/{KERNEL}/{VERSION}/amd64/"))
            self.assertEqual(request.get_header("Authorization"), "Bearer private-builder-token")
        self.assertFalse(list(self.root.glob("*.partial")))

    def test_unsigned_image_fallback_only_on_missing_signed_image(self):
        self.opener.missing = (IMAGE + "_",)
        paths = self.download()
        self.assertTrue(paths[0].name.startswith("linux-image-unsigned-"))
        self.assertEqual(len(self.opener.requests), 6)

    def test_existing_image_type_never_changes(self):
        self.opener.missing = (IMAGE + "_",)
        with self.assertRaises(urllib.error.HTTPError):
            self.download(keep_image=True)
        self.assertEqual(len(self.opener.requests), 1)

    def test_missing_unsigned_symbols_can_use_signed_symbols(self):
        self.opener.missing = ("linux-image-unsigned-" + KERNEL + "-dbgsym",)
        paths = self.download()
        self.assertTrue(paths[-1].name.startswith(IMAGE + "-dbgsym"))

    def test_corrupt_or_incomplete_files_are_never_installed(self):
        for headers in ({"X-Checksum-Sha256": "0" * 64}, {"X-Checksum-Sha256": ""},
                        {"Content-Length": "1"}, {"Content-Length": str(inputs.LIMIT + 1)}):
            with self.subTest(headers=headers):
                self.opener.headers = headers
                with self.assertRaises(RuntimeError):
                    self.download()
                self.assertFalse(list(self.root.iterdir()))

    def test_wrong_package_identity_rejected_even_with_valid_digest(self):
        with mock.patch.object(inputs.subprocess, "check_output", return_value="Package: wrong\nVersion: 1\nArchitecture: amd64\n"):
            with self.assertRaisesRegex(RuntimeError, "패키지"):
                self.download()
        self.assertFalse(list(self.root.iterdir()))

    def test_network_failure_does_not_fallback_to_external_download(self):
        with mock.patch.object(self.opener, "open", side_effect=urllib.error.HTTPError("https://controller.example", 502, "failed", {}, None)):
            with self.assertRaises(urllib.error.HTTPError):
                self.download()
        self.assertFalse(list(self.root.iterdir()))

    def test_version_and_filename_arguments_cannot_select_other_files(self):
        for kernel, version, arch, image in (("../escape", VERSION, "amd64", IMAGE),
                                             (KERNEL, "6.8.0-52.52", "amd64", IMAGE),
                                             (KERNEL, VERSION, "../escape", IMAGE),
                                             (KERNEL, VERSION, "amd64", "../../escape")):
            with self.subTest(kernel=kernel, version=version, arch=arch, image=image):
                with self.assertRaises(RuntimeError):
                    inputs.download_inputs(kernel, version, arch, self.root, image, ("https://controller.example", "token", self.opener))
        self.assertFalse(self.opener.requests)

    def test_connection_requires_trusted_root_config_and_https(self):
        config = self.root / "builder.json"
        config.write_text(json.dumps({"controller_url": "http://controller.example", "token": "private-token"}))
        config.chmod(0o600)
        with mock.patch.object(inputs.os, "stat", return_value=type("Stat", (), {"st_mode": 0o100600, "st_uid": 0})()):
            with self.assertRaisesRegex(RuntimeError, "HTTPS"):
                inputs.load_connection(config)
        with mock.patch.object(inputs.os, "stat", return_value=type("Stat", (), {"st_mode": 0o100660, "st_uid": 0})()):
            with self.assertRaisesRegex(RuntimeError, "root"):
                inputs.load_connection(config)

    def test_redirect_does_not_forward_token(self):
        with self.assertRaisesRegex(RuntimeError, "리디렉션"):
            inputs.NoRedirect().redirect_request(None, None, 302, "", {}, "https://other.example")


class ControllerDebugHelper(unittest.TestCase):
    def test_controller_mode_installs_transferred_files_without_direct_download(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            debug = root / "debug"
            debug.mkdir()
            helper = root / "download.py"
            helper.write_text(
                "from pathlib import Path\nimport sys\n"
                "kernel, version, directory, image = sys.argv[1:5]\n"
                "for name in (image, 'linux-modules-'+kernel, 'linux-headers-'+kernel, 'linux-headers-'+kernel.removesuffix('-generic'), 'linux-image-unsigned-'+kernel+'-dbgsym'):\n"
                "    path = Path(directory) / (name + '_' + version + '_amd64.deb')\n"
                "    path.write_text('transferred bytes')\n    print(path)\n"
            )
            script = root / "debug.sh"
            script.write_text((REPO / "deploy/kpctl-kernel-debug.sh").read_text()
                              .replace("/usr/local/libexec/kpctl-kernel-inputs", str(helper))
                              .replace("/usr/lib/debug/boot", str(debug)))
            bin_dir = root / "bin"
            bin_dir.mkdir()
            mock_cmd = bin_dir / "command"
            mock_cmd.write_text(f"#!{sys.executable}\n" + r'''
import os
from pathlib import Path
import sys
root = Path(os.environ['INPUT_TEST_ROOT'])
command = Path(sys.argv[0]).name
if command == 'id':
    print(0)
elif command == 'dpkg-query':
    if not (root / 'installed').exists(): sys.exit(1)
    print('6.8.0-51.52' if '-f=${Version}' in sys.argv else 'installed')
elif command == 'dpkg':
    assert sys.argv[1] == '-i' and len(sys.argv) == 7, sys.argv
    assert all(Path(p).read_text() == 'transferred bytes' for p in sys.argv[2:])
    (root / 'installed').touch()
    (root / 'debug/vmlinux-6.8.0-51-generic').touch()
else:
    raise SystemExit('unexpected direct network/package operation: ' + command)
''')
            mock_cmd.chmod(0o755)
            for command in ("id", "dpkg-query", "dpkg", "apt-get", "curl"):
                (bin_dir / command).symlink_to(mock_cmd.name)
            result = subprocess.run(["bash", str(script), "--controller", KERNEL, VERSION],
                                    env=dict(os.environ, PATH=str(bin_dir) + os.pathsep + os.environ["PATH"], INPUT_TEST_ROOT=str(root)),
                                    text=True, capture_output=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertTrue((root / "installed").exists())


if __name__ == "__main__":
    unittest.main()
