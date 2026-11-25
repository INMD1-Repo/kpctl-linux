import contextlib
import concurrent.futures
import errno
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import importlib.util
import io
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "build_environment",
    Path(__file__).resolve().parents[1] / "deploy/kpctl-build-environment.py",
)
env = importlib.util.module_from_spec(spec)
spec.loader.exec_module(env)
real_require_limits = env.require_limits
real_require_space = env.require_space
real_user_build_lock = env.user_build_lock


class DisposableBuildEnvironment(unittest.TestCase):
    def setUp(self):
        mocked = patch.object(
            env, "require_limits", return_value={"memory.max": 4096, "pids.max": 128}
        )
        mocked.start()
        self.addCleanup(mocked.stop)
        for name in ("require_space", "user_build_lock"):
            mocked = patch.object(env, name)
            mocked.start()
            self.addCleanup(mocked.stop)

    def test_image_build_timeout_terminates_its_process_group(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = """
import os, signal, sys, time
from pathlib import Path

child = os.fork()
def stop(*_):
    if child:
        os.waitpid(child, 0)
    (Path(sys.argv[1]) / ("parent" if child else "child")).touch()
    sys.exit(0)

signal.signal(signal.SIGTERM, stop)
time.sleep(5)
"""
            with patch.object(env.subprocess, "run") as other_command, open(os.devnull, "w") as log:
                with self.assertRaises(subprocess.TimeoutExpired):
                    env.run_podman_build([sys.executable, "-c", script, tmp], log, 0.5)
            self.assertEqual({entry.name for entry in Path(tmp).iterdir()}, {"parent", "child"})
            other_command.assert_not_called()

    def test_image_build_interrupt_keeps_original_error_when_cleanup_fails(self):
        for error, grace in (
            (env.BuildCancelled("build cancelled"), 20),
            (KeyboardInterrupt(), 20),
            (subprocess.TimeoutExpired(["podman", "build"], 60), 120),
        ):
            with (
                self.subTest(error=type(error).__name__),
                patch.object(env.subprocess, "Popen") as spawn,
                patch.object(env, "stop_podman_build", side_effect=OSError("signal failed")) as stop,
                contextlib.redirect_stderr(io.StringIO()) as diagnostics,
            ):
                spawn.return_value.wait.side_effect = error
                with self.assertRaises(type(error)) as caught:
                    env.run_podman_build(["podman", "build"], None, 60)
                self.assertIs(caught.exception, error)
                self.assertTrue(spawn.call_args.kwargs["start_new_session"])
                stop.assert_called_once_with(spawn.return_value, grace)
                self.assertIn("signal failed", diagnostics.getvalue())

    def test_image_build_unresponsive_to_sigterm_is_killed_and_reaped(self):
        command = [
            sys.executable,
            "-c",
            "import signal, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); "
            "print('ready', flush=True); time.sleep(30)",
        ]
        with subprocess.Popen(command, start_new_session=True, stdout=subprocess.PIPE) as process:
            self.assertEqual(process.stdout.readline(), b"ready\n")
            with contextlib.redirect_stderr(io.StringIO()) as diagnostics:
                env.stop_podman_build(process, grace=0)
            self.assertEqual(process.returncode, -signal.SIGKILL)
            self.assertIn("SIGTERM", diagnostics.getvalue())

    def test_image_build_failure_keeps_exit_code(self):
        with open(os.devnull, "w") as log:
            with self.assertRaises(subprocess.CalledProcessError) as caught:
                env.run_podman_build([sys.executable, "-c", "exit(3)"], log, 10)
        self.assertEqual(caught.exception.returncode, 3)

    def test_effective_limits_include_stricter_ancestor(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "service/child").mkdir(parents=True)
            (root / "group").write_text("0::/service/child\n")
            (root / "service/memory.max").write_text("4096")
            (root / "service/pids.max").write_text("128")
            (root / "service/child/memory.max").write_text("8192")
            (root / "service/child/pids.max").write_text("max")
            self.assertEqual(
                env.inherited_limits(root / "group", root),
                {"memory.max": 4096, "pids.max": 128},
            )
            (root / "group").write_text("1:memory:/service/child\n")
            with self.assertRaisesRegex(ValueError, "cgroup v2"):
                env.inherited_limits(root / "group", root)

    def test_unlimited_or_too_large_resource_limits_fail_closed(self):
        profile = {"limits": {"memory_mib": 1024, "pids": 4096}}
        for memory, pids in [
            (None, 4096),
            (2 * 1024**3, 4096),
            (1024**3, None),
            (1024**3, 8192),
        ]:
            with patch.object(
                env,
                "inherited_limits",
                return_value={"memory.max": memory, "pids.max": pids},
            ):
                with self.assertRaisesRegex(ValueError, "MemoryMax and TasksMax"):
                    real_require_limits(profile)
        with patch.object(
            env,
            "inherited_limits",
            return_value={"memory.max": 1024**3, "pids.max": 4096},
        ):
            self.assertEqual(real_require_limits(profile)["pids.max"], 4096)

    def test_disk_space_is_checked_before_build_and_never_retried(self):
        with patch.object(
            env.shutil, "disk_usage", return_value=SimpleNamespace(free=4 * 1024**3)
        ):
            with self.assertRaisesRegex(env.DiskSpaceError, "insufficient disk space"):
                real_require_space(Path("/unused"), 5120)
        self.assertFalse(
            env.retryable({"kind": "environment", "error": "insufficient disk space"})
        )
        self.assertFalse(
            env.retryable(
                {"kind": "environment", "error": "write error. Out of diskspace"}
            )
        )

    def test_profiles_share_the_build_account_lock(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(
            Path, "home", return_value=Path(directory)
        ):
            with real_user_build_lock():
                with self.assertRaisesRegex(env.BuildBusy, "another kernel build"):
                    with real_user_build_lock(timeout=0):
                        self.fail("concurrent build admitted")
            with real_user_build_lock():
                pass

    def test_lock_waits_until_the_other_build_finishes(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(
            Path, "home", return_value=Path(directory)
        ), concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            acquired = threading.Event()
            started = threading.Event()

            def wait():
                started.set()
                with real_user_build_lock(timeout=1):
                    acquired.set()

            with real_user_build_lock():
                future = pool.submit(wait)
                self.assertTrue(started.wait(1))
                self.assertFalse(acquired.wait(0.02))
            future.result(timeout=2)
            self.assertTrue(acquired.is_set())

    def test_output_is_drained_and_disk_pressure_stops_client(self):
        with contextlib.redirect_stdout(
            io.StringIO()
        ) as live, contextlib.redirect_stderr(io.StringIO()) as errors:
            result = env.run_limited(
                [
                    sys.executable,
                    "-c",
                    "import sys;print('x'*200000);print('e'*200000,file=sys.stderr)",
                ],
                Path("."),
                5,
            )
        self.assertEqual(live.getvalue(), result.stdout)
        self.assertEqual(errors.getvalue(), result.stderr)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(len(result.stdout), 200001)
        self.assertEqual(len(result.stderr), 200001)
        real_popen = subprocess.Popen
        processes = []

        def create(*args, **kwargs):
            process = real_popen(*args, **kwargs)
            processes.append(process)
            return process

        with patch.object(env.subprocess, "Popen", side_effect=create), patch.object(
            env,
            "require_space",
            side_effect=env.DiskSpaceError("insufficient disk space"),
        ):
            with self.assertRaises(env.DiskSpaceError):
                env.run_limited(
                    [sys.executable, "-c", "import time;time.sleep(60)"],
                    Path("."),
                    0.05,
                )
        self.assertIsNotNone(processes[0].poll())

    def test_compiler_output_is_forwarded_before_process_exit(self):
        started = threading.Event()

        class LiveOutput(io.StringIO):
            def write(self, text):
                result = super().write(text)
                if "compiler ready" in self.getvalue():
                    started.set()
                return result

        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "continue"
            program = "import pathlib,sys,time; print('compiler ready',flush=True)\nwhile not pathlib.Path(sys.argv[1]).exists():time.sleep(0.01)\nprint('finished',flush=True)"
            with contextlib.redirect_stdout(
                LiveOutput()
            ) as live, concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(
                    env.run_limited,
                    [sys.executable, "-c", program, str(marker)],
                    Path(directory),
                    5,
                )
                try:
                    self.assertTrue(
                        started.wait(3), "compiler output was buffered until exit"
                    )
                    self.assertFalse(future.done())
                finally:
                    marker.write_text("go")
                result = future.result(timeout=3)
                self.assertEqual(result.returncode, 0)
                self.assertIn("finished", live.getvalue())

    def test_changed_recipe_or_rebuilt_toolchain_cannot_be_used(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            recipe = root / "recipe"
            recipe.mkdir()
            packages = "gcc-13=1.0\n"
            (recipe / "packages.lock").write_text(packages)
            (recipe / "Containerfile").write_text("FROM pinned\n")
            profile = {
                "schema": 1,
                "image": "sha256:" + "a" * 64,
                "settings": {},
                "limits": {"memory_mib": 4096, "pids": 4096},
                "tools": {"gcc": "original compiler"},
                "packages_sha256": env.sha(packages.encode()),
                "recipe_sha256": env.recipe_hash(recipe),
            }
            path = root / "profile.json"
            path.write_text(json.dumps(profile))
            with patch.object(
                env, "command", return_value=json.dumps([{"Id": profile["image"]}])
            ):
                self.assertEqual(env.load_profile(path)[1]["image"], profile["image"])
                with patch.object(
                    env,
                    "build_image",
                    return_value=(
                        "sha256:" + "b" * 64,
                        {"gcc": "different compiler"},
                        packages,
                    ),
                ), patch.object(env, "atomic") as publish:
                    with self.assertRaisesRegex(
                        ValueError, "changed locked packages/toolchain"
                    ):
                        env.rebuild(path)
                    publish.assert_not_called()
                (recipe / "Containerfile").write_text("FROM changed\n")
                with self.assertRaisesRegex(
                    ValueError, "recipe or package lock changed"
                ):
                    env.load_profile(path)

    def test_retry_is_environment_only(self):
        for response in [
            {"kind": "environment", "error": "file truncated"},
            {"kind": "build", "error": "ld: object: file format not recognized"},
            {"kind": "unknown", "error": "ld: object: file format not recognized"},
        ]:
            self.assertTrue(env.retryable(response))
        for kind, error in [
            ("build", "Found a static call in module"),
            ("build", "patch does not apply"),
            ("build", "Version disagreement for symbol foo"),
            ("validation", "file truncated"),
            ("artifact", "file truncated"),
            ("unsupported", "unexpected klp reloc for new symbol"),
            ("preflight", "gcc not installed"),
            ("environment", "no space left on device"),
            ("environment", "permission denied"),
            ("environment", "deadline exceeded"),
            ("environment", "rustc version mismatch"),
        ]:
            self.assertFalse(
                env.retryable({"kind": kind, "error": error}), (kind, error)
            )

    def test_guest_output_never_follows_links_or_reads_special_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "out").mkdir()
            (root / "out/module.ko").write_bytes(b"ELF-test")
            self.assertEqual(env.read_guest(root, "out/module.ko", 8), b"ELF-test")
            with self.assertRaises(ValueError):
                env.read_guest(root, "out/module.ko", 7)
            self.assertEqual(
                env.read_guest(root, "out/module.ko", 4, tail=True), b"test"
            )
            (root / "out/module.ko").unlink()
            (root / "out/module.ko").symlink_to("/etc/passwd")
            with self.assertRaises(OSError):
                env.read_guest(root, "out/module.ko", 1024)
            (root / "parent").symlink_to(root / "out", target_is_directory=True)
            with self.assertRaises(OSError):
                env.read_guest(root, "parent/module.ko", 1024)
            os.mkfifo(root / "pipe")
            with self.assertRaises(ValueError):
                env.read_guest(root, "pipe", 1024)
            with self.assertRaises(ValueError):
                env.read_guest(root, "../etc/passwd", 1024)

    def request(self, root):
        return {
            "kernel": {
                "kernel": "6.8.0-136-generic",
                "git_dir": "/repo",
                "base_tag": "Ubuntu-6.8.0-136.136",
                "tag_glob": "Ubuntu-6.8.0-*",
                "vmlinux": "/vmlinux",
                "paths": None,
            },
            "base_commit": "a" * 40,
            "name": "isolated_test",
            "work_dir": str(root),
            "out_dir": str(root / "out"),
            "boot_dir": "/boot",
            "patch_files": [],
            "build_tool": "kpatch",
            "jobs": 2,
            "timeout_minutes": 1,
        }

    def test_disk_shortage_defers_preflight_warmup_and_build(self):
        for stage in ("preflight", "warmup", "build"):
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                req = self.request(root)
                req["boot_dir"] = str(root)
                (root / ("config-" + req["kernel"]["kernel"])).write_text("CONFIG_LIVEPATCH=y\n")
                args = SimpleNamespace(worker=root / "worker", retry_clean=True)
                args.worker.write_text("worker")
                profile = {
                    "image": "image",
                    "packages_sha256": "p",
                    "recipe_sha256": "r",
                    "cache": {"max_gib": 1 if stage == "warmup" else 0},
                }
                out = Path(req["out_dir"])
                out.mkdir()
                shortage = env.DiskSpaceError("4 GiB free; need 5 GiB")
                with patch.object(env, "require_space", side_effect=shortage if stage == "preflight" else None), patch.object(
                    env, "container_args", return_value=[]
                ), patch.object(env, "run_limited", side_effect=shortage) as run:
                    status = env.run_locked(args, root / "profile.json", profile, req, out, {})
                self.assertEqual(status, 1)
                self.assertEqual(run.call_count, 0 if stage == "preflight" else 1)
                result = json.loads((out / "environment-result.json").read_text())
                self.assertEqual(result["kind"], "disk_space")
                self.assertEqual(result["error"], str(shortage))
                self.assertFalse(result["success"])
                self.assertFalse(list(out.glob("*.ko")))
                self.assertFalse(list((root / "runs").iterdir()))
                if stage == "warmup":
                    self.assertFalse(any(path.is_dir() for path in (root / "cache").iterdir()))

    def test_exactly_one_retry_same_image_and_fresh_workspace(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            worker = root / "worker"
            worker.write_bytes(b"offline worker")
            request = root / "request.json"
            request.write_text(json.dumps(self.request(root)))
            profile = {
                "image": "sha256:" + "b" * 64,
                "packages_sha256": "p",
                "recipe_sha256": "r",
            }
            attempts = []

            cache_used = []

            def attempt(req, profile, worker, work, timeout, cache=None):
                self.assertEqual(list(work.iterdir()), [])
                self.assertGreater(timeout, 0)
                attempts.append(work)
                cache_used.append(cache)
                (work / "corrupt-file").write_text("left by this attempt")
                return {
                    "success": False,
                    "kind": "environment",
                    "error": "file truncated",
                    "log": "error",
                }, None

            args = SimpleNamespace(
                profile=str(root / "profile.json"),
                request=str(request),
                worker=str(worker),
                retry_clean=True,
            )
            with patch.object(env, "engine"), patch.object(
                env, "load_profile", return_value=(root / "profile.json", profile)
            ), patch.object(
                env, "rebuild", return_value=profile
            ) as rebuild, patch.object(
                env,
                "prepare_cache",
                return_value=(Path("/sealed"), {"key": "baseline"}),
            ), patch.object(
                env, "attempt", side_effect=attempt
            ), contextlib.redirect_stdout(
                io.StringIO()
            ):
                self.assertEqual(env.run_build(args), 1)
                rebuild.assert_not_called()
            self.assertEqual(len(attempts), 2)
            self.assertNotEqual(attempts[0], attempts[1])
            self.assertEqual(cache_used, [Path("/sealed"), None])
            self.assertEqual(list((root / "runs").iterdir()), [])
            result = json.loads((root / "out/environment-result.json").read_text())
            self.assertFalse(result["success"])
            self.assertIn('"attempt": 2', result["log"])

    def run_with_clock(self, cache_info, baseline_seconds):
        """기준 빌드가 baseline_seconds 를 쓴 뒤 실제 빌드가 받는 제한 시간을 돌려줍니다 (가짜 시계)."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "worker").write_bytes(b"worker")
            request = root / "request.json"
            req = self.request(root)
            req["timeout_minutes"] = 180
            request.write_text(json.dumps(req))
            profile = {"image": "sha256:" + "c" * 64, "packages_sha256": "p", "recipe_sha256": "r"}
            clock = [1000.0]
            given = []

            def prepare(args, path, profile, req, state, deadline, logs):
                given.append(deadline - clock[0])
                clock[0] += baseline_seconds
                return Path("/sealed"), cache_info

            def attempt(req, profile, worker, work, timeout, cache=None):
                given.append(timeout)
                return {"success": False, "kind": "build", "error": "x", "log": ""}, None

            args = SimpleNamespace(profile=str(root / "profile.json"), request=str(request),
                                   worker=str(root / "worker"), retry_clean=False)
            with patch.object(env, "engine"), patch.object(
                env, "load_profile", return_value=(root / "profile.json", profile)
            ), patch.object(env, "prepare_cache", side_effect=prepare), patch.object(
                env, "attempt", side_effect=attempt
            ), patch.object(env.time, "monotonic", side_effect=lambda: clock[0]), contextlib.redirect_stdout(io.StringIO()):
                env.run_build(args)
            return given

    def test_cold_baseline_does_not_eat_the_build_time_limit(self):
        # 실제 환경: 기준 빌드 2시간 6분 뒤 klp-build 가 남은 54분 안에 못 끝나 취소됐습니다.
        baseline, build = self.run_with_clock({"key": "k", "warmup": True}, 126 * 60)
        self.assertEqual(baseline, 180 * 60)
        self.assertEqual(build, 180 * 60)

    def test_reused_cache_keeps_one_shared_limit(self):
        # 이미 봉인된 캐시를 쓰는 경우(기준 빌드 없음)는 제한을 다시 주지 않습니다.
        _, build = self.run_with_clock({"key": "k", "warmup": False}, 60)
        self.assertEqual(build, 180 * 60 - 60)

    def test_stale_container_removal_waits_long_enough(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "container-name").write_text("kpctl-build-" + "a" * 32)
            with patch.object(env.subprocess, "run") as run:
                env.cleanup_container(root)
            self.assertGreaterEqual(run.call_args.kwargs["timeout"], 600)
            self.assertFalse((root / "container-name").exists())

    def test_content_failure_does_not_reinstall_packages(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            request = root / "request.json"
            request.write_text(json.dumps(self.request(root)))
            worker = root / "worker"
            worker.write_bytes(b"worker")
            profile = {
                "image": "sha256:" + "a" * 64,
                "packages_sha256": "p",
                "recipe_sha256": "r",
            }
            args = SimpleNamespace(
                profile=str(root / "profile.json"),
                request=str(request),
                worker=str(worker),
                retry_clean=True,
            )
            with patch.object(env, "engine"), patch.object(
                env, "load_profile", return_value=(root / "profile.json", profile)
            ), patch.object(env, "rebuild") as rebuild, patch.object(
                env,
                "attempt",
                return_value=(
                    {
                        "success": False,
                        "kind": "build",
                        "error": "static call unsupported",
                    },
                    None,
                ),
            ) as attempt:
                self.assertEqual(env.run_build(args), 1)
                rebuild.assert_not_called()
                self.assertEqual(attempt.call_count, 1)

    def test_no_credentials_in_worker_protocol(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            req = self.request(root)
            req["token"] = "secret"
            request = root / "request.json"
            request.write_text(json.dumps(req))
            args = SimpleNamespace(
                profile=str(root / "profile.json"), request=str(request)
            )
            with patch.object(env, "engine"), patch.object(
                env, "load_profile", return_value=(root / "profile.json", {})
            ):
                with self.assertRaisesRegex(ValueError, "build inputs only"):
                    env.run_build(args)

    def test_container_always_removed_even_on_timeout(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            worker = root / "worker"
            worker.write_bytes(b"worker")
            boot = root / "boot"
            boot.mkdir()
            (boot / "config-6.8.0-136-generic").write_text("CONFIG_LIVEPATCH=y\n")
            req = self.request(root)
            req["boot_dir"] = str(boot)
            calls = []

            def run(argv, **kwargs):
                calls.append(argv)
                if argv[2] == "run":
                    raise subprocess.TimeoutExpired(argv, 1)
                return SimpleNamespace(returncode=0)

            with patch.object(
                env,
                "mount",
                side_effect=lambda a, b, mode="ro": [
                    "--volume",
                    str(a) + ":" + b + ":" + mode,
                ],
            ), patch.object(
                env, "run_limited", side_effect=lambda argv, root, timeout: run(argv)
            ), patch.object(
                env.subprocess, "run", side_effect=run
            ):
                response, artifact = env.attempt(
                    req,
                    {
                        "image": "sha256:" + "a" * 64,
                        "limits": {"memory_mib": 4096, "pids": 4096},
                    },
                    worker,
                    root / "attempt",
                    1,
                )
                self.assertIsNone(artifact)
                self.assertEqual(response["error"], "build timed out")
                self.assertFalse(env.retryable(response))
            self.assertIn("--network=none", calls[0])
            self.assertIn("--read-only", calls[0])
            self.assertIn("--cap-drop=all", calls[0])
            self.assertNotIn("--privileged", calls[0])
            headers_path = "/usr/src/linux-headers-" + req["kernel"]["kernel"]
            self.assertIn(f"{headers_path}:{headers_path}:ro", calls[0])
            self.assertNotIn("/usr/src:/usr/src:ro", calls[0])
            self.assertEqual(
                calls[1][0:5],
                ["podman", "--cgroup-manager=cgroupfs", "rm", "--force", "--ignore"],
            )
            self.assertFalse((root / "attempt/container-name").exists())

    def test_kernel_header_mounts_leave_image_tool_sources_visible(self):
        with tempfile.TemporaryDirectory() as directory:
            headers = Path(directory).resolve()
            kernel = "7.0.0-43-generic"
            flavored = headers / ("linux-headers-" + kernel)
            common = headers / "linux-headers-7.0.0-43"
            rust = headers / ("linux-lib-rust-" + kernel)
            for path in (
                flavored,
                common,
                headers / "linux-headers-7.0.0-42-generic",
                headers / "rustc-1.93.1",
            ):
                path.mkdir()
            expected = [f"{path}:/usr/src/{path.name}:ro" for path in (flavored, common)]
            self.assertEqual(env.kernel_header_mounts(kernel, headers)[1::2], expected)

            rust.mkdir()
            expected.append(f"{rust}:/usr/src/{rust.name}:ro")
            self.assertEqual(env.kernel_header_mounts(kernel, headers)[1::2], expected)

    def test_cleanup_failure_preserves_build_failure_and_blocks_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            worker = root / "worker"
            worker.write_bytes(b"worker")
            req = self.request(root)
            req["boot_dir"] = str(root)
            config = root / ("config-" + req["kernel"]["kernel"])
            config.write_text("CONFIG_LIVEPATCH=y\n")
            profile = {
                "image": "sha256:" + "a" * 64,
                "limits": {"memory_mib": 4096, "pids": 4096},
            }
            for outcome in ("failed", "successful", "timed out"):
                with self.subTest(outcome=outcome):
                    attempt_root = root / outcome

                    def run(argv, work, timeout):
                        if outcome == "timed out":
                            logfile = work / "home/.kpatch/build.log"
                            logfile.parent.mkdir()
                            logfile.write_text("interrupted compiler output")
                            raise subprocess.TimeoutExpired(argv, timeout)
                        success = outcome == "successful"
                        result = {"success": success, "log": "original compiler output"}
                        if success:
                            artifact = work / ("work/out/" + req["name"] + ".ko")
                            artifact.parent.mkdir()
                            artifact.write_bytes(b"module")
                        else:
                            result.update(error="compiler failed", kind="build")
                        (work / "work/result.json").write_text(json.dumps(result))
                        return SimpleNamespace(returncode=int(not success))

                    with patch.object(env, "mount", return_value=[]), patch.object(
                        env, "run_limited", side_effect=run
                    ), patch.object(
                        env.subprocess,
                        "run",
                        side_effect=subprocess.TimeoutExpired("podman rm", 25),
                    ) as cleanup:
                        response, artifact = env.attempt(
                            req, profile, worker, attempt_root, 1
                        )
                    cleanup.assert_called_once()
                    self.assertTrue((attempt_root / "container-name").exists())
                    self.assertFalse(response["success"])
                    self.assertIsNone(artifact)
                    self.assertFalse(env.retryable(response))
                    self.assertIn("container cleanup failed", response["log"])
                    if outcome == "timed out":
                        self.assertEqual(response["error"], "build timed out")
                        self.assertIn("interrupted compiler output", response["log"])
                    else:
                        self.assertIn("original compiler output", response["log"])
                        if outcome == "failed":
                            self.assertEqual(response["error"], "compiler failed")
                            self.assertEqual(response["kind"], "build")
                        else:
                            self.assertIn("container cleanup failed", response["error"])
                            self.assertEqual(response["kind"], "environment")

    def test_unwritable_workspace_cleanup_does_not_follow_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "work"
            root.mkdir()
            outside = Path(directory) / "outside"
            outside.mkdir()
            (outside / "keep").touch()
            (root / "link").symlink_to(outside, target_is_directory=True)
            (root / "child").mkdir(mode=0o500)
            root.chmod(0o500)
            env.remove_worktree(root)
            self.assertTrue((outside / "keep").exists())

    def test_cleanup_recovers_runtime_mapped_ownership(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "attempt"
            root.mkdir()
            with patch.object(
                env,
                "remove_owned_worktree",
                side_effect=[PermissionError("mapped UID"), None],
            ) as remove, patch.object(env.subprocess, "run") as run:
                env.remove_worktree(root)
                self.assertEqual(remove.call_count, 2)
                self.assertEqual(
                    run.call_args.args[0],
                    ["podman", "unshare", "chown", "-hR", "0:0", str(root)],
                )

    def test_cancel_exception_is_not_swallowed_as_a_retryable_syscall(self):
        # Exercise main's real signal registration while subprocess.communicate
        # is waiting. InterruptedError would be swallowed and leave it hanging.
        program = r"""
import importlib.util,subprocess,sys
spec=importlib.util.spec_from_file_location("signal_test",sys.argv[1])
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
def run(args):
    try:subprocess.run([sys.executable,"-c","import time;print('ready',flush=True);time.sleep(60)"],stderr=subprocess.PIPE)
    except m.BuildCancelled:
        print("cancelled",flush=True)
        return 17
    return 1
m.run_build=run
sys.argv=["helper","run","--profile","/p","--request","/r","--worker","/w"]
sys.exit(m.main())
"""
        process = subprocess.Popen(
            [sys.executable, "-c", program, spec.origin],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        try:
            with selectors.DefaultSelector() as ready:
                ready.register(process.stdout, selectors.EVENT_READ)
                self.assertTrue(ready.select(5), "signal test did not start")
                self.assertEqual(process.stdout.readline().strip(), "ready")
            process.send_signal(signal.SIGTERM)
            stdout, stderr = process.communicate(timeout=3)
            self.assertEqual(process.returncode, 17, stderr)
            self.assertIn("cancelled", stdout)
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
            process.communicate(timeout=3)


class BaselineCache(unittest.TestCase):
    def setUp(self):
        mocked = patch.object(env, "require_space")
        mocked.start()
        self.addCleanup(mocked.stop)

    def test_pressure_eviction_does_not_force_cache_recreation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            req = DisposableBuildEnvironment.request(self, root)
            req["boot_dir"] = str(root)
            (root / ("config-" + req["kernel"]["kernel"])).write_text("config")
            profile = {"image": "image", "cache": {"max_gib": 1}}
            with patch.object(env, "kernel_compiler", return_value={"compiler_identity":"gcc"}), patch.object(
                env, "require_space", side_effect=env.DiskSpaceError("low space")
            ), patch.object(env, "attempt") as attempt:
                cache, info = env.prepare_cache(SimpleNamespace(worker=root/"worker"),
                    root/"profile.json", profile, req, root/"runs", 10, [])
            self.assertIsNone(cache)
            self.assertFalse(info["enabled"])
            self.assertIn("일반 빌드", info["warning"])
            attempt.assert_not_called()

    def test_compiler_comes_from_target_headers(self):
        for version, major in [
            ("11.4.0-1ubuntu1~22.04.2", "11"),
            ("13.3.0-6ubuntu2~24.04", "13"),
            ("13.3.0-6ubuntu2~24.04.1", "13"),
            ("15.2.0-16ubuntu1", "15"),
        ]:
            with self.subTest(
                version=version
            ), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                kernel = "6.8.0-136-generic"
                header = (
                    root / ("linux-headers-" + kernel) / "include/generated/compile.h"
                )
                header.parent.mkdir(parents=True)
                upstream = version.split("-")[0]
                header.write_text(
                    '#define LINUX_COMPILER "x86_64-linux-gnu-gcc-'
                    + major
                    + " (Ubuntu "
                    + version
                    + ") "
                    + upstream
                    + '"\n'
                )
                with patch.object(
                    env,
                    "command",
                    side_effect=AssertionError("host compiler must not be queried"),
                ):
                    compiler = env.kernel_compiler(kernel, root)
                self.assertEqual(
                    compiler["compiler_package"], "gcc-" + major + "=" + version
                )
                self.assertEqual(
                    compiler["cxx_package"], "g++-" + major + "=" + version
                )
                header.write_text('#define LINUX_COMPILER "clang version 21"\n')
                with self.assertRaisesRegex(ValueError, "GCC"):
                    env.kernel_compiler(kernel, root)

    def test_cache_is_warmed_without_patches_sealed_reused_and_invalidated(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            request = DisposableBuildEnvironment.request(self, root)
            request["boot_dir"] = str(root)
            request["patch_files"] = ["/security.patch"]
            (root / ("config-" + request["kernel"]["kernel"])).write_text(
                "CONFIG_LIVEPATCH=y\n"
            )
            worker = root / "worker"
            worker.write_bytes(b"worker")
            args = SimpleNamespace(worker=worker)
            profile = {
                "image": "sha256:" + "a" * 64,
                "recipe_sha256": "r",
                "packages_sha256": "p",
                "cache": {"max_gib": 1},
            }
            state = root / "runs"
            state.mkdir()

            def baseline(req, profile, worker, attempt, timeout, *, cache, warmup):
                self.assertTrue(warmup)
                self.assertEqual(req["patch_files"], [])
                self.assertGreater(timeout, 0)
                (cache / "abR").write_bytes(b"object result")
                return {
                    "success": True,
                    "log": "baseline complete",
                    "cache": {"hits": 0, "misses": 100, "build_seconds": 12.5},
                }, None

            with patch.object(
                env,
                "kernel_compiler",
                return_value={"compiler_identity": "target compiler"},
            ), patch.object(env, "attempt", side_effect=baseline) as attempt:
                cache, first = env.prepare_cache(
                    args,
                    root / "profile.json",
                    profile,
                    request,
                    state,
                    env.time.monotonic() + 10,
                    [],
                )
                self.assertTrue(first["warmup"])
                self.assertEqual(cache.stat().st_mode & 0o777, 0o500)
                self.assertEqual((cache / "abR").stat().st_mode & 0o777, 0o400)
                request["patch_files"] = ["/different-security.patch"]
                same, second = env.prepare_cache(
                    args,
                    root / "profile.json",
                    profile,
                    request,
                    state,
                    env.time.monotonic() + 10,
                    [],
                )
                self.assertEqual(same, cache)
                self.assertFalse(second["warmup"])
                self.assertEqual(second["baseline_seconds"], 12.5)
                self.assertEqual(second["baseline_stats"]["misses"], 100)
                self.assertEqual(attempt.call_count, 1)
                (root / ("config-" + request["kernel"]["kernel"])).write_text(
                    "CONFIG_OTHER=y\n"
                )
                changed, third = env.prepare_cache(
                    args,
                    root / "profile.json",
                    profile,
                    request,
                    state,
                    env.time.monotonic() + 10,
                    [],
                )
                self.assertNotEqual(changed, cache)
                self.assertEqual(attempt.call_count, 2)
                self.assertTrue(cache.exists())
                (changed / "abR").chmod(0o600)
                (changed / "abR").write_bytes(b"corrupt")
                with self.assertRaisesRegex(
                    ValueError, "sealed baseline cache changed"
                ):
                    env.prepare_cache(
                        args,
                        root / "profile.json",
                        profile,
                        request,
                        state,
                        env.time.monotonic() + 10,
                        [],
                    )
                self.assertEqual(attempt.call_count, 2)

    def test_cache_rejects_links_and_special_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            outside = root / "outside"
            outside.write_bytes(b"keep")
            cache = root / "ccache"
            cache.mkdir()
            for kind in ("symlink", "hardlink", "fifo"):
                entry = cache / "abR"
                if kind == "symlink":
                    entry.symlink_to(outside)
                elif kind == "hardlink":
                    os.link(outside, entry)
                else:
                    os.mkfifo(entry)
                with self.assertRaises((ValueError, OSError)):
                    env.cache_manifest(cache, 1024)
                entry.unlink()
            self.assertEqual(outside.read_bytes(), b"keep")

    def test_trials_mount_cache_readonly_and_baseline_alone_can_write(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            worker = root / "worker"
            worker.write_bytes(b"worker")
            kernel = "6.8.0-136-generic"
            (root / ("config-" + kernel)).write_text("CONFIG_LIVEPATCH=y\n")
            security = root / "security.patch"
            security.write_text("CVE patch")
            req = DisposableBuildEnvironment.request(self, root)
            req.update(boot_dir=str(root), patch_files=[str(security)])
            profile = {
                "image": "sha256:" + "a" * 64,
                "limits": {"memory_mib": 4096, "pids": 4096},
                "cache": {"max_gib": 1},
            }
            for warmup in (False, True):
                attempt = root / str(warmup)

                def run(argv, work, timeout):
                    local = json.loads((work / "inputs/request.json").read_text())
                    self.assertEqual(bool(local.get("cache_warmup")), warmup)
                    self.assertEqual(len(local["patch_files"]), 0 if warmup else 1)
                    self.assertIn("/sealed:/ccache:" + ("rw" if warmup else "ro"), argv)
                    self.assertEqual("--env=CCACHE_READONLY=1" in argv, not warmup)
                    self.assertIn("--env=CCACHE_STATS=1", argv)
                    self.assertNotIn("--env=CCACHE_NOSTATS=1", argv)
                    self.assertIn(
                        "--env=CCACHE_STATSLOG=" + env.WORK + "/ccache-stats.log", argv
                    )
                    self.assertIn("--env=CCACHE_TEMPDIR=" + env.WORK + "/tmp", argv)
                    (work / "work/result.json").write_text(
                        '{"success":true,"log":"compiled"}'
                    )
                    (work / "work/ccache-stats.log").write_text(
                        "# probe.c\ndirect_cache_hit\nlocal_storage_hit\ncache_miss\n"
                    )
                    (work / "work/out").mkdir()
                    (work / "work/out/isolated_test.ko").write_bytes(b"module")
                    return SimpleNamespace(returncode=0, stdout="", stderr="")

                with patch.object(
                    env,
                    "mount",
                    side_effect=lambda src, dst, mode="ro": [
                        "--volume",
                        str(src) + ":" + dst + ":" + mode,
                    ],
                ), patch.object(env, "run_limited", side_effect=run), patch.object(
                    env.subprocess, "run"
                ):
                    response, artifact = env.attempt(
                        req,
                        profile,
                        worker,
                        attempt,
                        10,
                        cache=Path("/sealed"),
                        warmup=warmup,
                    )
                self.assertTrue(response["success"])
                self.assertEqual(response["cache"]["hits"], 1)
                self.assertEqual(response["cache"]["misses"], 1)
                self.assertEqual(artifact, None if warmup else b"module")

    def test_cache_key_changes_with_every_build_identity_input(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            req = DisposableBuildEnvironment.request(self, root)
            req["boot_dir"] = str(root)
            (root / ("config-" + req["kernel"]["kernel"])).write_text("config")
            worker = root / "worker"
            worker.write_bytes(b"worker")
            profile = {
                "image": "sha256:original",
                "recipe_sha256": "r",
                "packages_sha256": "p",
            }
            with patch.object(
                env, "kernel_compiler", return_value={"compiler_identity": "compiler"}
            ):
                before = env.cache_identity(req, profile, worker)
                for key in ("image",):
                    self.assertNotEqual(
                        before,
                        env.cache_identity(
                            req, dict(profile, **{key: "changed"}), worker
                        ),
                    )
                for key in ("build_tool",):
                    self.assertNotEqual(
                        before,
                        env.cache_identity(
                            dict(req, **{key: "changed"}), profile, worker
                        ),
                    )
                worker.write_bytes(b"new worker")
                self.assertEqual(before, env.cache_identity(req, profile, worker))
                self.assertEqual(
                    before,
                    env.cache_identity(
                        dict(req, base_commit="b" * 40), profile, worker
                    ),
                )


class FreshBuilderInstall(unittest.TestCase):
    def test_default_is_sandbox_and_host_tools_require_explicit_option(self):
        script = Path(__file__).resolve().parents[1] / "deploy/setup-builder.sh"
        for option, host in [((), False), (("--host-mode",), True)]:
            result = subprocess.run(
                ["bash", str(script), "--plan", *option],
                check=True,
                text=True,
                capture_output=True,
            )
            plan = json.loads(result.stdout)
            self.assertEqual(plan["mode"], "host" if host else "sandbox")
            self.assertEqual(plan["host_build_dep_linux"], host)
            for package in ("build-essential", "ccache", "devscripts", "libelf-dev"):
                self.assertEqual(package in plan["host_packages"], host)
            self.assertEqual("podman" in plan["runtime_packages"], not host)
        for args in [("--jobs", "0"), ("--memory-mib", "bad"), ("bad-kernel",)]:
            result = subprocess.run(
                ["bash", str(script), "--plan", *args], text=True, capture_output=True
            )
            self.assertNotEqual(result.returncode, 0)


class CacheObservability(unittest.TestCase):
    def test_per_attempt_stats_do_not_double_count_internal_lookups(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "ccache-stats.log").write_text(
                "# file.c\ndirect_cache_miss\nlocal_storage_miss\ncache_miss\ndirect_cache_hit\npreprocessed_cache_hit\ncalled_for_link\n"
            )
            report = env.read_cache_stats(root, True, False, 12.5)
            self.assertEqual((report["hits"], report["misses"]), (2, 1))
            self.assertAlmostEqual(report["hit_rate"], 2 / 3, places=5)
            self.assertIn("70%", report["warning"])
            self.assertNotIn("warning", env.read_cache_stats(root, True, True, 12.5))
            (root / "ccache-stats.log").write_text(
                "direct_cache_hit\n" * 8 + "cache_miss\n" * 2
            )
            self.assertNotIn("warning", env.read_cache_stats(root, True, False, 1))
            (root / "ccache-stats.log").write_text("called_for_link\n")
            self.assertIsNone(env.read_cache_stats(root, True, False, 1)["hit_rate"])
            self.assertIn("warning", env.read_cache_stats(root, True, False, 1))

    def entry(self, root, name, kernel, size, used):
        entry = root / (name * 64)
        cache = entry / "ccache"
        cache.mkdir(parents=True)
        with (cache / "abR").open("wb") as output:
            output.truncate(size)
        env.atomic(
            entry / "sealed.json",
            {"inputs": {"schema": 2, "kernel": kernel, "image": "image"}},
        )
        env.atomic(entry / "state.json", {"last_used_at": used})
        return entry

    def test_shared_budget_prunes_inactive_lru_and_keeps_active_kernels(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            old = self.entry(root, "a", "old", 600 * 1024**2, 1)
            active = self.entry(root, "b", "current", 300 * 1024**2, 0)
            profile = {"image": "image", "cache": {"max_gib": 1, "total_gib": 1}}
            self.assertTrue(
                env.cache_room(root, profile, {"current"}, reserve=300 * 1024**2)
            )
            self.assertFalse(old.exists())
            self.assertTrue(active.exists())
            self.assertFalse(
                env.cache_room(root, profile, {"current"}, reserve=1024**3)
            )
            self.assertTrue(
                active.exists(),
                "active kernel cache must not be thrashed by repeated warmups",
            )

    def test_disk_pressure_reuses_inactive_first_lru_and_can_drop_active_cache(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            old = self.entry(root, "a", "old", 4096, 20)
            active = self.entry(root, "b", "current", 4096, 1)
            profile = {"cache": {"max_gib": 1, "total_gib": 1}}
            removed = []
            real_remove = env.remove_worktree

            def remove(path):
                removed.append(path)
                real_remove(path)

            # Ample cache budget, but the work filesystem is full. Reuse the
            # existing LRU: inactive first, then reproducible active caches.
            with patch.object(env, "remove_worktree", side_effect=remove), patch.object(
                env.shutil, "disk_usage",
                side_effect=lambda _: SimpleNamespace(free=2 * 1024**3 if not active.exists() else 0),
            ):
                self.assertTrue(env.cache_room(root, profile, {"current"},
                    min_free_bytes=1024**3, space_path=root))
            self.assertEqual(removed, [old, active])
            self.assertTrue((root / ".policy.json").is_file())

    def test_fast_metadata_verification_and_full_audit_are_distinct(self):
        with tempfile.TemporaryDirectory() as directory:
            entry = Path(directory)
            cache = entry / "ccache"
            cache.mkdir()
            (cache / "abR").write_bytes(b"compiler output")
            original = env.cache_manifest(cache, 8192)
            env.seal_cache(cache)
            files = env.cache_manifest(cache, 8192, hash_content=False)
            files["abR"]["sha256"] = original["abR"]["sha256"]
            env.atomic(entry / "sealed.json", {"inputs": {"schema": 2}, "files": files})
            env.atomic(entry / "state.json", {"verified_at": env.time.time()})
            with patch.object(
                env.hashlib,
                "sha256",
                side_effect=AssertionError("normal reuse must not hash contents"),
            ):
                env.verify_cache(entry, 8192)
            sealed = json.loads((entry / "sealed.json").read_text())
            sealed["files"]["abR"]["sha256"] = "0" * 64
            env.atomic(entry / "sealed.json", sealed)
            with self.assertRaisesRegex(ValueError, "sealed baseline cache changed"):
                env.verify_cache(entry, 8192, full=True)


class ArchiveAcquisition(unittest.TestCase):
    fetch_error = "E: Failed to fetch https://snapshot.ubuntu.com/ubuntu/pool/p.deb  503  Service Unavailable"
    fetch_summary = "E: Unable to fetch some archives, maybe run apt update or try with --fix-missing?"

    def test_cancelled_snapshot_indexes_need_confirmed_outage_on_their_own_origin(self):
        uri = "https://snapshot.ubuntu.com/ubuntu/20261120T122658Z"
        err = f"Err:17 {uri} resolute-security/main amd64 Packages\n"
        blank = f"E: Failed to fetch {uri}/dists/resolute-security/main/binary-amd64/Packages  \n"
        outage = f"E: Failed to fetch {uri}/dists/resolute/multiverse/source/Sources  503  Service Unavailable\n"
        summary = "E: Some index files failed to download. They have been ignored, or old ones used instead."
        self.assertTrue(env.transient_archive_failure(err + blank + blank.replace("/main/", "/universe/")
                                                     + outage + summary))
        self.assertTrue(env.transient_archive_failure(blank.replace(".com/", ".com:443/") + outage))
        for other_origin in ("https://example.com", "http://snapshot.ubuntu.com", "https://snapshot.ubuntu.com:444"):
            with self.subTest(other_origin=other_origin):
                self.assertFalse(env.transient_archive_failure(blank.replace("https://snapshot.ubuntu.com", other_origin) + outage))
                self.assertFalse(env.transient_archive_failure(err.replace("https://snapshot.ubuntu.com", other_origin) + blank + outage))
        self.assertFalse(env.transient_archive_failure(err + blank + summary))
        for detail in ("Hash Sum mismatch", "The following signatures were invalid: BADSIG", "404  Not Found",
                       "Certificate verification failed", "Connection timed out"):
            with self.subTest(detail=detail):
                self.assertFalse(env.transient_archive_failure(err + "  " + detail + "\n" + blank + outage))
                self.assertFalse(env.transient_archive_failure(blank + "  " + detail + "\n" + outage))
        # APT may try another encoding that returns 404 before a status-bearing final error.
        self.assertTrue(env.transient_archive_failure(err + "  404  NOT FOUND [IP: 192.0.2.12 443]\n" + outage))
        self.assertFalse(env.transient_archive_failure(err + "  Hash Sum mismatch\n" + outage))

    def test_only_failing_apt_download_in_image_can_switch_archives(self):
        output = f"KPCTL_IMAGE_APT_BEGIN\n{self.fetch_error}\n{self.fetch_summary}\n"
        self.assertIn("503", env.image_archive_error(output + "KPCTL_IMAGE_APT_FAILED 100\n"))
        for ending in (
            "error building kpatch", "KPCTL_IMAGE_APT_FAILED 1",
            "E: Failed to fetch https://mirror/pkg  Hash Sum mismatch\nKPCTL_IMAGE_APT_FAILED 100",
            "E: The repository is not signed.\nKPCTL_IMAGE_APT_FAILED 100",
            "dpkg: error processing package p\nKPCTL_IMAGE_APT_FAILED 100",
        ):
            with self.subTest(ending=ending):
                self.assertFalse(env.image_archive_error(output + ending))

        def interrupted(argv, log, timeout):
            log.write(output + "KPCTL_IMAGE_APT_FAILED 100\n")
            raise subprocess.CalledProcessError(125, argv)

        locked = dict(base="ubuntu", compiler_package="gcc-15=1", cxx_package="g++-15=1",
                      snapshot_id="20261120T122658Z")
        with tempfile.TemporaryDirectory() as directory, patch.object(env, "run_podman_build", side_effect=interrupted):
            with self.assertRaises(subprocess.CalledProcessError):
                env.build_image(Path(directory), locked, True)

    def test_initial_image_503_rechecks_pins_and_shares_image_deadline(self):
        snapshot = "20261120T122658Z"
        gcc, cxx = "gcc-15=15.2.0-16ubuntu1", "g++-15=15.2.0-16ubuntu1"
        settings = {
            "base": "ubuntu@sha256:" + "a" * 64, "compiler_identity": "(Ubuntu 15.2.0-16ubuntu1) 15.2.0",
            "compiler_package": gcc, "cxx_package": cxx,
            "snapshot_id": snapshot, "snapshot_time_basis": {"kind": "kernel_package_publication_time", "tag": "Ubuntu-tag"},
        }
        args = SimpleNamespace(snapshot="auto", sources=None, allow_live_fallback=True,
                               image_timeout_minutes=10, snapshot_timeout_minutes=2)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "recipe").mkdir()
            recipe = Path(env.__file__).parent / "build-environment/install-packages.sh"
            # Only the network/guest configuration calls are stubbed. Run the actual APT failure trap.
            script = recipe.read_text().replace('bash /tmp/environment/configure-apt.sh "${4:-}"', ':')
            fake_apt = root / "apt-get"
            fake_apt.write_text('#!/bin/sh\n[ "$1" != update ] || exit 0\necho "$FETCH_ERROR" >&2\nexit 100\n')
            fake_apt.chmod(0o755)
            builds = []
            clock = [50.0]

            def build(argv, log, timeout):
                builds.append((next(a for a in argv if a.startswith("SNAPSHOT_ID=")), timeout))
                if len(builds) == 1:
                    result = subprocess.run(["bash", "-ec", script, "install", "0", gcc, cxx, snapshot],
                                            stdout=log, stderr=subprocess.STDOUT,
                                            env=dict(os.environ, PATH=f"{root}:{os.environ['PATH']}",
                                                     FETCH_ERROR=self.fetch_error + "\n" + self.fetch_summary))
                    self.assertEqual(result.returncode, 100)
                    clock[0] += 120.25
                    raise subprocess.CalledProcessError(125, argv)
                (root / "image.iid").write_text("sha256:" + "b" * 64)
                print("live image build", file=log)

            pins = "KPCTL_TOOLCHAIN_PIN " + gcc + "\nKPCTL_TOOLCHAIN_PIN " + cxx
            def recheck(argv, name, archive, log_path, timeout_minutes, timeout_option):
                self.assertEqual(timeout_minutes, 2)
                self.assertEqual(timeout_option, "--snapshot-timeout-minutes")
                clock[0] += 61.5
                return 0, pins

            with patch.object(env, "run_podman_build", side_effect=build), patch.object(
                env, "run_snapshot_probe", side_effect=recheck
            ) as probe, patch.object(env.time, "monotonic", side_effect=lambda: clock[0]), patch.object(
                env, "image_probe", return_value={"gcc": "gcc " + settings["compiler_identity"]}
            ), patch.object(env, "image_packages", return_value=gcc + "\n"), patch.object(env, "remember_image"):
                env.build_initial_image(args, root, settings)
            self.assertEqual(builds, [("SNAPSHOT_ID=" + snapshot, 600), ("SNAPSHOT_ID=", 418.25)])
            self.assertEqual(probe.call_args.args[0][-3:], ["", gcc, cxx])
            self.assertEqual(settings["snapshot_id"], "")
            self.assertEqual(settings["compiler_family"], [gcc, cxx])
            basis = settings["snapshot_time_basis"]
            self.assertEqual((basis["kind"], basis["failed_stage"], basis["tag"]),
                             ("live_archive_fallback", "image_build", "Ubuntu-tag"))
            self.assertEqual(basis["unavailable_snapshots"], [snapshot])
            self.assertIn(self.fetch_error, (root / basis["failed_log"]).read_text())
            self.assertIn("live image build", (root / "image-build.log").read_text())

    def test_image_deadline_stops_fallback_before_another_container_starts(self):
        for first_build_seconds in (599.75, 600):
            with self.subTest(first_build_seconds=first_build_seconds), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root / "recipe").mkdir()
                args = SimpleNamespace(snapshot="auto", sources=None, allow_live_fallback=True, image_timeout_minutes=10)
                settings = dict(base="ubuntu", snapshot_id="20261120T122658Z", snapshot_time_basis={},
                                compiler_package="gcc-15=1", cxx_package="g++-15=1")
                clock = [50.0]

                def first_build(*_):
                    (root / "image-build.log").write_text("snapshot returned 503")
                    clock[0] += first_build_seconds
                    raise env.ArchiveUnavailable("503")

                def recheck(argv, **options):
                    self.assertEqual(options["timeout"], 0.25)
                    log = options["stdout"]
                    log.write("KPCTL_TOOLCHAIN_PIN gcc-15=1\nKPCTL_TOOLCHAIN_PIN g++-15=1\n")
                    clock[0] += 0.25
                    return subprocess.CompletedProcess(argv, 0)

                with (
                    patch.object(env.time, "monotonic", side_effect=lambda: clock[0]),
                    patch.object(env, "build_image", side_effect=first_build) as build,
                    patch.object(env.subprocess, "run", side_effect=recheck) as probe,
                ):
                    with self.assertRaisesRegex(ValueError, "--image-timeout-minutes"):
                        env.build_initial_image(args, root, settings)
                build.assert_called_once()
                if first_build_seconds < 600:
                    probe.assert_called_once()
                    self.assertIn("KPCTL_TOOLCHAIN_PIN", (root / "snapshot-probe.log").read_text())
                else:
                    probe.assert_not_called()
                self.assertEqual(settings["snapshot_id"], "20261120T122658Z")
                failed_log, = root.glob("image-build-*.log")
                self.assertEqual(failed_log.read_text(), "snapshot returned 503")

    def test_image_outage_without_permission_or_after_live_selection_stops(self):
        for allowed, snapshot in ((False, "20261120T122658Z"), (True, "")):
            args = SimpleNamespace(snapshot="auto", sources=None, allow_live_fallback=allowed)
            with patch.object(env, "build_image", side_effect=env.ArchiveUnavailable("503")) as build:
                with self.assertRaisesRegex(env.ArchiveUnavailable, "503"):
                    env.build_initial_image(args, Path("/unused"), {"snapshot_id": snapshot})
                self.assertEqual(build.call_count, 1)

    @unittest.skipUnless(Path("/usr/lib/apt/apt-helper").is_file(), "requires Ubuntu APT")
    def test_snapshot_503_retry_preserves_expected_hash(self):
        payload = b"archive fixture\n"
        requests = []

        class Archive(BaseHTTPRequestHandler):
            def do_GET(self):
                requests.append(self.path)
                status = 503 if requests.count(self.path) <= 2 else 200
                self.send_response(status)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args):
                pass

        try:
            server = HTTPServer(("127.0.0.1", 0), Archive)
        except PermissionError:
            self.skipTest("sandbox does not permit loopback sockets")
        self.addCleanup(server.server_close)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.shutdown)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for subdir in ("apt.conf.d", "sources.list.d", "preferences.d"):
                (root / subdir).mkdir()
            (root / "os-release").write_text("VERSION_CODENAME=resolute\n")
            configure = Path(env.__file__).parent / "build-environment/configure-apt.sh"
            script = configure.read_text().replace("/etc/apt/", directory + "/").replace(
                "/tmp/environment/", directory + "/environment/"
            ).replace("/etc/os-release", str(root / "os-release"))
            subprocess.run(["bash", "-ec", script, "probe", "20261120T122658Z"], check=True)
            options = [
                "-c", str(root / "apt.conf.d/99kpctl-archive"),
                "-o", "Acquire::http::Proxy::127.0.0.1=DIRECT",
                "-o", "Acquire::Retries::Delay=false", "-o", "APT::Sandbox::User=root",
            ]
            config = subprocess.check_output(["apt-config", *options, "dump"], text=True)
            self.assertIn('APT::Update::Error-Mode "any";', config)
            url = f"http://127.0.0.1:{server.server_port}"
            for name, digest in (("index", hashlib.sha256(payload).hexdigest()), ("corrupt", "0" * 64)):
                path = root / name
                result = subprocess.run(
                    ["/usr/lib/apt/apt-helper", *options, "download-file", url + "/" + name,
                     str(path), "SHA256:" + digest],
                    capture_output=True, timeout=15,
                )
                self.assertGreaterEqual(requests.count("/" + name), 3)
                if name == "index":
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(path.read_bytes(), payload)
                else:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse(path.exists())


class SnapshotSelection(unittest.TestCase):
    candidates = ["20260701T000000Z", "20260702T000000Z", "20260630T000000Z"]
    settings = {
        "base": "ubuntu@sha256:" + "a" * 64,
        "compiler_package": "gcc-13=13.3.0-6ubuntu2~24.04.1",
        "cxx_package": "g++-13=13.3.0-6ubuntu2~24.04.1",
    }

    def select_with_probes(self, root, probe, **options):
        args = {"snapshot": "auto", "sources": None, "allow_live_fallback": False, **options}
        with patch.object(
            env, "snapshot_candidates", return_value=(self.candidates.copy(), {"kind": "test"})
        ), patch.object(env.subprocess, "run", side_effect=probe):
            return env.select_snapshot(SimpleNamespace(**args), root, self.settings)

    @staticmethod
    def probe_result(argv, log, code, *lines):
        # Write through the descriptor just as the child process does.
        os.write(log.fileno(), ("\n".join(lines) + "\n").encode())
        return subprocess.CompletedProcess(argv, code)

    def run_probes(self, attempts, responses, **options):
        def probe(argv, **kwargs):
            attempts.append(argv[-3])
            status, output = responses[len(attempts) - 1]
            return self.probe_result(argv, kwargs["stdout"], status, output)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "recipe").mkdir()
            return self.select_with_probes(root, probe, **options)

    def update_failure(self, reason, *other_errors):
        uri = f"https://snapshot.ubuntu.com/ubuntu/{self.candidates[0]}/dists/resolute-security/InRelease"
        return 100, "\n".join((
            "== apt-get update (binary package indexes) ==",
            "Ign:1 " + uri, "  404  NOT FOUND [IP: 192.0.2.11 443]",
            "E: Failed to fetch " + uri + "  " + reason + " [IP: 192.0.2.12 443]",
            *other_errors,
            "E: Some index files failed to download. They have been ignored, or old ones used instead.",
        ))

    def test_auto_outage_tries_one_other_snapshot(self):
        pins = [self.settings["compiler_package"], self.settings["cxx_package"]]
        ready = (0, "\n".join("KPCTL_TOOLCHAIN_PIN " + pin for pin in pins))
        for reason in ("503  Service Unavailable", "429  Too Many Requests"):
            with self.subTest(reason=reason):
                attempts = []
                selected = self.run_probes(attempts, [self.update_failure(reason), ready])
                self.assertEqual(attempts, self.candidates[:2])
                self.assertEqual(selected["snapshot_id"], self.candidates[1])
                self.assertEqual(selected["snapshot_time_basis"]["unavailable_snapshots"], self.candidates[:1])

        unavailable = self.update_failure("503  Service Unavailable")
        attempts = []
        with self.assertRaises(env.ArchiveUnavailable) as caught:
            self.run_probes(attempts, [unavailable, unavailable])
        self.assertEqual(attempts, self.candidates[:2])
        self.assertIn("503", str(caught.exception))
        self.assertNotIn("exact GCC packages unavailable", str(caught.exception))

    def test_opt_in_live_fallback_requires_exact_pins(self):
        failed = self.update_failure("503  Service Unavailable")
        pins = [self.settings["compiler_package"], self.settings["cxx_package"]]
        exact = (0, "\n".join("KPCTL_TOOLCHAIN_PIN " + pin for pin in pins))
        attempts = []
        selected = self.run_probes(attempts, [failed, exact], allow_live_fallback=True)
        self.assertEqual(attempts, [self.candidates[0], ""])
        self.assertEqual(selected["snapshot_id"], "")
        self.assertEqual(selected["compiler_family"], pins)
        self.assertEqual(selected["snapshot_time_basis"]["kind"], "live_archive_fallback")
        self.assertEqual(selected["snapshot_time_basis"]["unavailable_snapshots"], self.candidates[:1])
        self.assertNotIn("allow_live_fallback", json.dumps(selected))

        attempts = []
        with self.assertRaises(ValueError):
            self.run_probes(attempts, [failed, (0, "KPCTL_TOOLCHAIN_PIN " + pins[0])],
                            allow_live_fallback=True)
        self.assertEqual(attempts, [self.candidates[0], ""])

        attempts = []
        missing = (3, "required package unavailable")
        with self.assertRaisesRegex(ValueError, "no compiler substitution"):
            self.run_probes(attempts, [missing] * len(self.candidates), allow_live_fallback=True)
        self.assertEqual(attempts, self.candidates)

    def test_503_does_not_override_explicit_sources_or_other_errors(self):
        failed = self.update_failure("503  Service Unavailable")
        cases = [
            ({"snapshot": self.candidates[0]}, failed),
            ({"sources": "/custom.sources"}, failed),
            ({}, self.update_failure("404  Not Found")),
            ({}, self.update_failure("503  Service Unavailable", "E: Failed to fetch https://mirror/Packages  Hash Sum mismatch")),
            ({}, self.update_failure("503  Service Unavailable", "E: The repository 'https://mirror/ stable InRelease' is not signed.")),
            ({}, self.update_failure("503  Service Unavailable", "E: Failed to fetch https://mirror/Packages  404  Not Found")),
        ]
        for options, response in cases:
            with self.subTest(options=options, output=response[1]):
                attempts = []
                with self.assertRaises(ValueError) as caught:
                    self.run_probes(attempts, [response], allow_live_fallback=True, **options)
                self.assertEqual(isinstance(caught.exception, env.ArchiveUnavailable), bool(options))
                self.assertEqual(attempts, self.candidates[:1])

    def test_unchecked_candidate_keeps_outage_retryable(self):
        missing = (3, "exact pins unavailable here")
        with self.assertRaisesRegex(env.ArchiveUnavailable, self.candidates[0]):
            self.run_probes([], [self.update_failure("503  Service Unavailable"), missing, missing])

    def test_helper_reports_only_known_temporary_conditions_with_reserved_exit_codes(self):
        for error, code in (
            (env.ArchiveUnavailable("HTTP 503"), 69),
            (env.DiskSpaceError("4 GiB free"), 73),
            (OSError(errno.EDQUOT, "quota exceeded while writing result"), 73),
            (OSError(errno.ENOSPC, "no space left while writing result"), 73),
            (OSError(errno.EACCES, "permission denied"), 1),
            (env.BuildBusy("locked"), 75),
            (ValueError("Hash Sum mismatch"), 1),
        ):
            with self.subTest(error=error), patch.object(env, "main", side_effect=error), \
                    contextlib.redirect_stderr(io.StringIO()) as diagnostic:
                self.assertEqual(env.cli(), code)
                self.assertIn(str(error), diagnostic.getvalue())

    def test_kernel_package_tag_time_selects_bounded_snapshot_candidates(self):
        args = SimpleNamespace(
            snapshot="auto",
            sources=None,
            kernel="6.8.0-136-generic",
            git_dir="/kernel",
            base_tag=None,
        )
        with patch.object(
            env, "command", side_effect=["6.8.0-136.136", "2026-07-01T22:48:01+03:00"]
        ) as command, patch.object(
            env, "kernel_publication_time", side_effect=OSError("metadata unavailable")
        ):
            candidates, basis = env.snapshot_candidates(args)
        self.assertEqual(candidates[0], "20260701T194801Z")
        self.assertLessEqual(len(candidates), 6)
        self.assertEqual(basis["kind"], "kernel_package_tag_time")
        self.assertNotIn("gcc", command.call_args_list[0].args[0])
        args.snapshot = "not-a-date"
        with self.assertRaises(ValueError):
            env.snapshot_candidates(args)

    def test_kernel_publication_uses_matching_series_arch_version_and_stable_pocket(self):
        entry = {
            "binary_package_name": "linux-headers-6.8.0-51-generic",
            "binary_package_version": "6.8.0-51.52",
            "distro_arch_series_link": "https://api.launchpad.net/1.0/ubuntu/noble/amd64",
            "pocket": "Updates",
            "status": "Deleted",
            "date_published": "2024-12-16T13:36:19+00:00",
        }
        earlier = "2024-09-01T00:00:00+00:00"
        entries = [
            dict(entry, pocket="Proposed", date_published=earlier),
            dict(entry, binary_package_version="6.8.0-51.52~22.04.1", date_published=earlier),
            dict(entry, binary_package_name="linux-headers-6.8.0-52-generic", date_published=earlier),
            dict(entry, distro_arch_series_link="https://api.launchpad.net/1.0/ubuntu/jammy/amd64", date_published=earlier),
            dict(entry, distro_arch_series_link="https://api.launchpad.net/1.0/ubuntu/noble/arm64", date_published=earlier),
            dict(entry, pocket="Security", date_published="2024-12-16T22:56:02+00:00"),
            entry,
        ]
        response = io.BytesIO(json.dumps({"entries": entries}).encode())
        with patch.object(env, "command", return_value="amd64\n"), patch.object(
            env.urllib.request, "urlopen", return_value=response
        ) as request:
            published = env.kernel_publication_time("6.8.0-51-generic", "6.8.0-51.52", "noble")
        self.assertEqual(published.isoformat(), entry["date_published"])
        query = env.urllib.parse.parse_qs(env.urllib.parse.urlsplit(request.call_args.args[0]).query)
        self.assertEqual(query["version"], ["6.8.0-51.52"])
        self.assertEqual(query["distro_arch_series"], [entry["distro_arch_series_link"]])

    def test_kernel_released_after_gcc_migration_selects_available_exact_compiler(self):
        args = SimpleNamespace(
            snapshot="auto", sources=None, kernel="6.8.0-51-generic",
            git_dir="/kernel", base_tag=None,
        )
        settings = {
            "base": "ubuntu@sha256:" + "a" * 64,
            "compiler_package": "gcc-13=13.3.0-6ubuntu2~24.04",
            "cxx_package": "g++-13=13.3.0-6ubuntu2~24.04",
        }

        def probe(argv, **kwargs):
            snapshot = argv[-3]
            if snapshot < "20241212T151524Z":
                return self.probe_result(argv, kwargs["stdout"], 3, "package version unavailable")
            return self.probe_result(
                argv, kwargs["stdout"], 0,
                "KPCTL_TOOLCHAIN_PIN " + settings["compiler_package"],
                "KPCTL_TOOLCHAIN_PIN " + settings["cxx_package"],
            )

        published = env.dt.datetime(2024, 12, 16, 13, 36, 19, tzinfo=env.dt.timezone.utc)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "recipe").mkdir()
            with patch.object(
                env, "command", side_effect=["6.8.0-51.52", "2024-11-30T18:21:46+00:00"]
            ), patch.object(
                env, "kernel_publication_time", return_value=published
            ), patch.object(env.subprocess, "run", side_effect=probe) as run:
                selected = env.select_snapshot(args, root, settings)
        self.assertEqual(selected["snapshot_id"], "20241217T133619Z")
        self.assertEqual(selected["snapshot_time_basis"]["kind"], "kernel_package_publication_time")
        self.assertEqual(selected["compiler_family"], [settings["compiler_package"], settings["cxx_package"]])
        self.assertEqual(run.call_count, 1)

    def test_explicit_snapshot_and_custom_sources_do_not_query_publication(self):
        args = SimpleNamespace(snapshot="20241217T000000Z", sources=None)
        with patch.object(env, "kernel_publication_time") as publication:
            candidates, basis = env.snapshot_candidates(args)
            self.assertEqual(candidates, [args.snapshot])
            self.assertEqual(basis["kind"], "explicit_snapshot")
            with tempfile.TemporaryDirectory() as directory:
                sources = Path(directory) / "sources"
                sources.write_text("Snapshot: 20241218T000000Z\n")
                args.snapshot, args.sources = "auto", str(sources)
                candidates, basis = env.snapshot_candidates(args)
                self.assertEqual(candidates, ["20241218T000000Z"])
                self.assertEqual(basis["kind"], "custom_snapshot")
            publication.assert_not_called()

    def test_snapshot_probe_accepts_only_successful_exact_package_plan(self):
        pins = [self.settings["compiler_package"], self.settings["cxx_package"]]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "recipe").mkdir()

            def unavailable(argv, **kwargs):
                return self.probe_result(argv, kwargs["stdout"], 3, "package version unavailable")

            def second_date_has_pins(argv, **kwargs):
                if argv[-3] == self.candidates[0]:
                    return unavailable(argv, **kwargs)
                return self.probe_result(
                    argv, kwargs["stdout"], 0,
                    "KPCTL_TOOLCHAIN_PIN " + pins[0], "KPCTL_TOOLCHAIN_PIN " + pins[1],
                )

            selected = self.select_with_probes(root, second_date_has_pins)
            self.assertEqual(selected["snapshot_id"], self.candidates[1])
            self.assertEqual(selected["compiler_family"], pins)
            with self.assertRaisesRegex(ValueError, "no compiler substitution"):
                self.select_with_probes(root, unavailable)

            def missing_cxx(argv, **kwargs):
                return self.probe_result(argv, kwargs["stdout"], 0, "KPCTL_TOOLCHAIN_PIN " + pins[0])

            # A previous successful run has both pins in the same on-disk log.
            with self.assertRaises(ValueError):
                self.select_with_probes(root, missing_cxx)

    def test_apt_update_failure_reports_apt_error_without_trying_other_dates(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "recipe").mkdir()
            attempts = []
            failure = "E: Failed to fetch InRelease: Connection timed out"
            run = subprocess.run

            def failed_update(argv, **kwargs):
                attempts.append(argv[-3])
                # Run the guest script, substituting only the tools that configure
                # /etc/apt or contact a repository.
                setup = 'bash() { :; }\napt-get() { printf "%s\\n" "$@"; echo "$APT_ERROR" >&2; return 100; }\n'
                script = argv[argv.index("-ec") + 1]
                return run(
                    ["bash", "-ec", setup + script, *argv[-4:]],
                    env=dict(os.environ, APT_ERROR=failure), **kwargs,
                )

            with self.assertRaises(ValueError) as caught:
                self.select_with_probes(root, failed_update)
            self.assertEqual(attempts, self.candidates[:1])
            log = root / "snapshot-probe.log"
            for expected in (failure, self.candidates[0], str(log)):
                self.assertIn(expected, str(caught.exception))
            output = log.read_text()
            for expected in (
                failure,
                "Acquire::IndexTargets::deb-src::Sources::DefaultEnabled=false", "Acquire::Languages=none",
            ):
                self.assertIn(expected, output)

    def test_partial_probe_output_survives_timeout_and_named_container_is_removed(self):
        for options, minutes in (({}, 20), ({"snapshot_timeout_minutes": 45}, 45)):
            with self.subTest(options=options), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "recipe").mkdir()
                calls = []
                last_line = "Get:5 https://snapshot.ubuntu.com/ubuntu/ resolute/main amd64 Packages"

                def timeout(argv, **kwargs):
                    calls.append(argv)
                    if "rm" in argv:
                        return subprocess.CompletedProcess(argv, 0)
                    self.assertEqual(kwargs["timeout"], minutes * 60)
                    self.assertEqual(kwargs["stderr"], subprocess.STDOUT)
                    os.write(kwargs["stdout"].fileno(), (last_line + "\n").encode())
                    raise subprocess.TimeoutExpired(argv, kwargs["timeout"])

                with self.assertRaises(ValueError) as caught:
                    self.select_with_probes(root, timeout, **options)
                attempt, cleanup = calls
                self.assertEqual(attempt[-3], self.candidates[0])
                name = attempt[attempt.index("--name") + 1]
                self.assertEqual(cleanup[cleanup.index("rm"):], ["rm", "--force", "--ignore", name])
                log = root / "snapshot-probe.log"
                self.assertIn(last_line, log.read_text())
                for expected in (last_line, self.candidates[0], str(log)):
                    self.assertIn(expected, str(caught.exception))
                self.assertNotIn("mapfile -t", str(caught.exception))

    def test_cancelled_probe_removes_its_container_and_propagates_cancellation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "recipe").mkdir()
            calls = []

            def interrupted(argv, **kwargs):
                calls.append(argv)
                if "run" in argv:
                    raise env.BuildCancelled("service stopped")
                return subprocess.CompletedProcess(argv, 0)

            with self.assertRaisesRegex(env.BuildCancelled, "service stopped"):
                self.select_with_probes(root, interrupted)
            attempt, cleanup = calls
            self.assertEqual(cleanup[-1], attempt[attempt.index("--name") + 1])
            self.assertIn("rm", cleanup)


class EnvironmentRetention(unittest.TestCase):
    def test_rebuild_publishes_verified_image_before_retiring_old_images(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            root = directory / ("compiler-" + "1" * 20)
            root.mkdir()
            old, new = "sha256:" + "1" * 64, "sha256:" + "2" * 64
            tools = {"gcc": "exact compiler"}
            packages = "gcc-13=1.0\n"
            profile = {
                "image": old,
                "settings": {},
                "tools": tools,
                "packages_sha256": env.sha(packages.encode()),
            }
            env.atomic(root / "profile.json", profile)

            def cleanup(path, keep, references):
                self.assertEqual(
                    json.loads((root / "profile.json").read_text())["image"], new
                )
                self.assertEqual(keep, {new})
                self.assertIn(new, references)

            with patch.object(
                env, "load_profile", return_value=(root / "profile.json", profile)
            ), patch.object(
                env, "build_image", return_value=(new, tools, packages)
            ), patch.object(
                env, "cleanup_images", side_effect=cleanup
            ) as retired:
                self.assertEqual(env.rebuild(root / "profile.json")["image"], new)
                retired.assert_called_once()

    def fixture(self, directory, number):
        root = directory / ("compiler-" + str(number) * 20)
        root.mkdir()
        image = "sha256:" + str(number) * 64
        env.atomic(root / "profile.json", {"image": image})
        env.remember_image(root, image)
        state = env.lifecycle(root)
        state.update(last_used_at=1, inactive_since=1)
        env.atomic(root / "lifecycle.json", state)
        cache = directory / "cache" / (str(number) * 64)
        cache.mkdir(parents=True)
        env.atomic(cache / "sealed.json", {"inputs": {"image": image}})
        (cache / "object").write_bytes(b"cached object")
        return root, image, cache

    def test_expired_only_gc_protects_active_and_locked_and_removes_exact_image_cache(
        self,
    ):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            active, _, active_cache = self.fixture(directory, 1)
            locked, _, locked_cache = self.fixture(directory, 2)
            expired, image, expired_cache = self.fixture(directory, 3)
            removed = []

            def podman(args, **kwargs):
                if "inspect" in args:
                    owner = env.sha(str(expired.resolve()).encode())
                    return SimpleNamespace(
                        returncode=0,
                        stdout=json.dumps(
                            [{"Config": {"Labels": {"io.kpctl.profile": owner}}}]
                        ),
                    )
                self.assertEqual(args[-4:], ["image", "rm", "--no-prune", image])
                self.assertNotIn("--force", args)
                removed.append(args[-1])
                return SimpleNamespace(returncode=0, stdout="", stderr="")

            with env.profile_lock(locked / "profile.json"), patch.object(
                env.subprocess, "run", side_effect=podman
            ):
                env.gc_locked(directory, {active.name}, 14)
            self.assertEqual(removed, [image])
            self.assertTrue(active.exists() and active_cache.exists())
            self.assertTrue(locked.exists() and locked_cache.exists())
            self.assertFalse(expired.exists() or expired_cache.exists())
            self.assertEqual(len(list((directory / "retired").iterdir())), 1)

    def test_gc_delete_failure_keeps_profile_and_cache_and_unknown_headers_prevent_gc(
        self,
    ):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            root, image, cache = self.fixture(directory, 1)
            owner = env.sha(str(root.resolve()).encode())
            inspected = SimpleNamespace(
                returncode=0,
                stdout=json.dumps(
                    [{"Config": {"Labels": {"io.kpctl.profile": owner}}}]
                ),
            )
            refused = SimpleNamespace(returncode=2, stderr="image used by container")
            with patch.object(env.subprocess, "run", side_effect=[inspected, refused]):
                env.gc_locked(directory, set(), 14)
            self.assertTrue(root.exists() and cache.exists())
            args = SimpleNamespace(
                profiles_dir=directory,
                inventory_complete=True,
                retention_days=14,
                active_kernel=["6.8.0-136-generic"],
            )
            with patch.object(env, "gc_locked") as gc:
                with self.assertRaises(FileNotFoundError):
                    env.collect_environments(args, directory / "missing-headers")
                gc.assert_not_called()

    def test_first_inactive_observation_starts_grace_and_references_prevent_deletion(
        self,
    ):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            root, image, cache = self.fixture(directory, 1)
            state = env.lifecycle(root)
            state.pop("inactive_since")
            env.atomic(root / "lifecycle.json", state)
            with patch.object(env.subprocess, "run") as run:
                env.gc_locked(directory, set(), 14)
                run.assert_not_called()
            self.assertGreater(env.lifecycle(root)["inactive_since"], 1)
            other, _, _ = self.fixture(directory, 2)
            env.atomic(other / "profile.json", {"image": image})
            state["inactive_since"] = 1
            env.atomic(root / "lifecycle.json", state)
            with patch.object(env.subprocess, "run") as run:
                env.gc_locked(directory, {other.name}, 14)
                run.assert_not_called()
            self.assertTrue(root.exists() and cache.exists())

    def test_base_digest_pinned_once_and_changed_explicit_digest_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            base = "docker.io/library/ubuntu@sha256:" + "a" * 64
            with patch.object(
                env, "command", side_effect=["", json.dumps([{"RepoDigests": [base]}])]
            ) as command:
                self.assertEqual(
                    env.pinned_base(directory, "docker.io/library/ubuntu:24.04"), base
                )
                self.assertEqual(
                    env.pinned_base(directory, "docker.io/library/ubuntu:24.04"), base
                )
                self.assertEqual(command.call_count, 2)
                with self.assertRaisesRegex(ValueError, "differs"):
                    env.pinned_base(
                        directory, "docker.io/library/ubuntu@sha256:" + "b" * 64
                    )

    def test_first_pin_uses_local_digest_without_registry_access(self):
        requested = "docker.io/library/ubuntu@sha256:" + "a" * 64
        with tempfile.TemporaryDirectory() as tmp, patch.object(
            env.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)
        ) as lookup, patch.object(env, "command") as registry:
            directory = Path(tmp)
            self.assertEqual(env.pinned_base(directory, requested), requested)
            self.assertEqual(json.loads((directory / "base-image.json").read_text())["base_image"], requested)
            self.assertEqual(lookup.call_args.args[0], ["podman", "image", "exists", requested])
            registry.assert_not_called()

    def test_prepare_pulls_missing_explicit_digest_without_substituting_another_reference(self):
        requested = "docker.io/library/ubuntu@sha256:" + "a" * 64
        other = "registry.example/ubuntu@sha256:" + "b" * 64
        args = SimpleNamespace(base_image=requested, min_free_gib=8, package=[])
        settings = {"compiler_package": "gcc=1", "cxx_package": "g++=1"}
        with (
            tempfile.TemporaryDirectory() as tmp,
            patch.object(env, "require_space"),
            patch.object(env.subprocess, "run", return_value=subprocess.CompletedProcess([], 1)),
            patch.object(
                env, "command", side_effect=["", json.dumps([{"RepoDigests": [other, requested]}])]
            ) as command,
            patch.object(env, "stage_recipe", side_effect=RuntimeError("recipe reached")),
        ):
            with self.assertRaisesRegex(RuntimeError, "recipe reached"):
                env.prepare_locked(args, Path(tmp), settings)
            self.assertEqual(settings["base"], requested)
            command.assert_called_once_with(["podman", "pull", requested])

    def test_base_image_lookup_failure_reports_storage_error_without_pull(self):
        requested = "docker.io/library/ubuntu@sha256:" + "a" * 64
        failed = subprocess.CompletedProcess(
            ["podman", "image", "exists", requested], 125, stderr="cannot access overlay storage"
        )
        with (
            tempfile.TemporaryDirectory() as tmp,
            patch.object(env.subprocess, "run", return_value=failed),
            patch.object(env, "command") as registry,
        ):
            directory = Path(tmp)
            with self.assertRaisesRegex(ValueError, "cannot access overlay storage"):
                env.pinned_base(directory, requested)
            registry.assert_not_called()
            self.assertFalse((directory / "base-image.json").exists())


class KernelPurge(unittest.TestCase):
    def test_purge_removes_only_that_kernels_sealed_caches(self):
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {"HOME": tmp}):
            directory = Path(tmp) / "environments"
            root = directory / ("compiler-" + "1" * 20)
            root.mkdir(parents=True)
            env.atomic(root / "profile.json", {"image": "sha256:" + "1" * 64})
            caches = {}
            for number, kernel in [(1, "6.8.0-136-generic"), (2, "6.8.0-147-generic"), (3, "6.8.0-136-generic")]:
                cache = (root / "cache" if number == 3 else directory / "cache") / (str(number) * 64)
                cache.mkdir(parents=True)
                env.atomic(cache / "sealed.json", {"inputs": {"schema": 2, "kernel": kernel}})
                (cache / "object").write_bytes(b"x" * 8192)
                caches[number] = cache
            unsealed = directory / "cache" / ("4" * 64)
            unsealed.mkdir()
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                env.purge_kernel(SimpleNamespace(action="kernel-inventory", profile=None, profiles_dir=str(directory)))
            self.assertEqual(json.loads(out.getvalue())["kernels"], ["6.8.0-136-generic", "6.8.0-147-generic"])
            self.assertTrue(all(cache.exists() for cache in caches.values()))
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                env.purge_kernel(SimpleNamespace(kernel="6.8.0-136-generic", profile=None, profiles_dir=str(directory)))
            result = json.loads(out.getvalue().splitlines()[-1])
            self.assertEqual(result["removed"], 2)
            self.assertGreater(result["bytes"], 0)
            self.assertFalse(caches[1].exists() or caches[3].exists())
            self.assertTrue(caches[2].exists() and unsealed.exists())

            (directory / "cache" / ("5" * 64)).symlink_to(caches[2])
            with self.assertRaisesRegex(ValueError, "invalid baseline cache"):
                env.purge_kernel(SimpleNamespace(kernel="6.8.0-147-generic", profile=None, profiles_dir=str(directory)))
            self.assertTrue(caches[2].exists())
            with self.assertRaisesRegex(ValueError, "invalid kernel"):
                env.purge_kernel(SimpleNamespace(kernel="../x", profile=None, profiles_dir=str(directory)))


if __name__ == "__main__":
    unittest.main()
