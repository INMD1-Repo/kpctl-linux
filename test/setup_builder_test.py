"""Exercise installer choices without installing packages or writing system files."""

import errno
import json
import os
from pathlib import Path
import pty
import re
import select
import signal
import subprocess
import tempfile
import time
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "deploy/setup-builder.sh"
PROMPT = "ccache를 사용하시겠습니까? [Y/n] "


class BuilderCacheChoice(unittest.TestCase):
    def plan(self, *arguments):
        result = subprocess.run(
            ["bash", str(SCRIPT), "--plan", *arguments],
            input="",
            text=True,
            capture_output=True,
            timeout=5,
            check=True,
        )
        self.assertNotIn(PROMPT, result.stdout + result.stderr)
        return json.loads(result.stdout)

    def run_install_selection(self, arguments=(), answer=None, terminal=True):
        # Run the exact installer from a readable temporary directory. The id
        # probe reports the selected settings and refuses root, before the first
        # installation operation. Also drop privileges when this suite is root.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o755)
            script = root / "setup-builder.sh"
            script.write_bytes(SCRIPT.read_bytes())
            script.chmod(0o444)
            bash_env = root / "test-environment.sh"
            bash_env.write_text(
                "id() {\n"
                "  if [ \"$*\" = -u ]; then\n"
                "    printf 'CACHE_SELECTION:%s:%s:%s\\n' \"$CACHE_GIB\" \"$CACHE_TOTAL_GIB\" \"$HOST_MODE\" >&2\n"
                "    printf 'CACHE_SERVICE:%s\\n' \"${cache_service_settings[@]}\" >&2\n"
                "    printf '65534\\n'\n"
                "  else command id \"$@\"; fi\n"
                "}\n"
            )
            bash_env.chmod(0o444)
            environment = dict(os.environ, BASH_ENV=str(bash_env))
            def mapped_identity(path):
                try:
                    return any(
                        start <= 65534 < start + count
                        for start, _, count in (
                            map(int, line.split()) for line in Path(path).read_text().splitlines()
                        )
                    )
                except FileNotFoundError:
                    return True

            can_drop = os.geteuid() == 0 and mapped_identity("/proc/self/uid_map") and mapped_identity("/proc/self/gid_map")
            options = {"user": 65534, "group": 65534} if can_drop else {}
            command = ["bash", str(script), *arguments]
            if not terminal:
                result = subprocess.run(
                    command,
                    input="",
                    text=True,
                    capture_output=True,
                    timeout=5,
                    cwd=root,
                    env=environment,
                    **options,
                )
                return result.returncode, result.stdout + result.stderr
            master, slave = pty.openpty()
            process = subprocess.Popen(
                command,
                stdin=slave,
                stdout=slave,
                stderr=slave,
                cwd=root,
                env=environment,
                start_new_session=True,
                **options,
            )
            os.close(slave)
            output = bytearray()
            deadline = time.monotonic() + 5
            sent = False
            try:
                while time.monotonic() < deadline:
                    ready, _, _ = select.select([master], [], [], 0.05)
                    if ready:
                        try:
                            data = os.read(master, 65536)
                        except OSError as error:
                            if error.errno != errno.EIO:
                                raise
                            break
                        if not data:
                            break
                        output.extend(data)
                        if answer is not None and not sent and PROMPT.encode() in output:
                            os.write(master, answer.encode())
                            sent = True
                else:
                    self.fail("installer selection did not finish: " + output.decode())
                process.wait(timeout=2)
                return process.returncode, output.decode()
            finally:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
                os.close(master)

    def assert_selection(self, output, maximum, total=40, host=0):
        match = re.search(r"CACHE_SELECTION:(\d+):(\d+):(\d+)", output)
        self.assertIsNotNone(match, output)
        self.assertEqual(tuple(map(int, match.groups())), (maximum, total, host))

    def test_plan_describes_sandbox_defaults_and_disabled_cache_without_prompt(self):
        default = self.plan()
        self.assertEqual(
            default["cache"],
            {"enabled": True, "mode": "sandbox_sealed", "max_gib": 20, "total_gib": 40},
        )
        for arguments in [("--cache-gib", "0"), ("--no-cache",)]:
            with self.subTest(arguments=arguments):
                plan = self.plan(*arguments)
                self.assertFalse(plan["cache"]["enabled"])
                self.assertEqual(plan["cache"]["max_gib"], 0)
                self.assertEqual(plan["cache"]["total_gib"], 40)
        plan = self.plan("--cache-gib", "8", "--cache-total-gib", "16")
        self.assertEqual((plan["cache"]["max_gib"], plan["cache"]["total_gib"]), (8, 16))

    def test_host_choice_controls_writable_ccache_without_claiming_sealed_budget(self):
        enabled = self.plan("--host-mode", "--cache-gib", "60")
        self.assertEqual(enabled["cache"], {"enabled": True, "mode": "host_writable", "max_gib": 60, "total_gib": None})
        self.assertIn("Environment=CCACHE_NODISABLE=1 CCACHE_MAXSIZE=60Gi", enabled["ccache_service_settings"])
        self.assertIn("UnsetEnvironment=CCACHE_DISABLE", enabled["ccache_service_settings"])
        disabled = self.plan("--host-mode", "--no-cache")
        self.assertFalse(disabled["cache"]["enabled"])
        self.assertIn("Environment=CCACHE_DISABLE=1", disabled["ccache_service_settings"])
        self.assertIn("UnsetEnvironment=CCACHE_NODISABLE CCACHE_MAXSIZE", disabled["ccache_service_settings"])

    def test_interactive_default_yes_and_no_are_used_before_installation(self):
        for answer, maximum in [("\n", 20), ("y\n", 20), ("n\n", 0)]:
            with self.subTest(answer=answer):
                status, output = self.run_install_selection(answer=answer)
                self.assertEqual(status, 1, output)
                self.assertIn(PROMPT, output)
                self.assert_selection(output, maximum)
        status, output = self.run_install_selection(("--host-mode",), answer="n\n")
        self.assertEqual(status, 1, output)
        self.assertIn("호스트 ccache", output)
        self.assert_selection(output, 0, host=1)
        self.assertIn("CACHE_SERVICE:Environment=CCACHE_DISABLE=1", output)

    def test_explicit_cache_choice_skips_question_even_with_terminal(self):
        for arguments, maximum in [
            (("--cache-gib", "8"), 8),
            (("--cache-gib", "0"), 0),
            (("--no-cache",), 0),
            (("--no-cache", "--cache-gib", "8"), 8),
            (("--cache-gib", "8", "--no-cache"), 0),
        ]:
            with self.subTest(arguments=arguments):
                status, output = self.run_install_selection(arguments)
                self.assertEqual(status, 1, output)
                self.assertNotIn(PROMPT, output)
                self.assert_selection(output, maximum)

    def test_unattended_default_stays_enabled_and_plan_never_asks(self):
        status, output = self.run_install_selection(terminal=False)
        self.assertEqual(status, 1, output)
        self.assertNotIn(PROMPT, output)
        self.assert_selection(output, 20)
        status, output = self.run_install_selection(("--plan",))
        self.assertEqual(status, 0, output)
        self.assertNotIn(PROMPT, output)
        self.assertNotIn("CACHE_SELECTION", output)
        self.assertTrue(json.loads(output)["cache"]["enabled"])

    def test_invalid_interactive_answer_repeats_question(self):
        status, output = self.run_install_selection(answer="maybe\nn\n")
        self.assertEqual(status, 1, output)
        self.assertEqual(output.count(PROMPT), 2, output)
        self.assertIn("y 또는 n", output)
        self.assert_selection(output, 0)


if __name__ == "__main__":
    unittest.main()
