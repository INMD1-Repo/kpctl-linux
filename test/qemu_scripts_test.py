import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import unittest


SCRIPTS = Path(__file__).resolve().parents[1] / "deploy/testvm/qemu"


class QEMUCommandContract(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.env = dict(os.environ, KPCTL_TESTVM_ROOT=str(self.root))

    def run_script(self, name, *args, check=True):
        return subprocess.run([str(SCRIPTS / name), *args], env=self.env,
                              capture_output=True, text=True, timeout=20, check=check)

    def test_cleanup_is_idempotent_and_console_handles_removed_vm(self):
        vm_id = "kpctl-test-123-bios"
        directory = self.root / vm_id
        directory.mkdir()
        (directory / "console.log").write_text("Kernel panic - test\n")
        self.assertEqual(self.run_script("list.sh").stdout, vm_id + "\n")
        self.assertEqual(self.run_script("console.sh", vm_id).stdout, "Kernel panic - test\n")
        self.run_script("delete.sh", vm_id)
        self.run_script("delete.sh", vm_id)
        self.assertEqual(self.run_script("console.sh", vm_id).stdout, "")
        self.assertEqual(self.run_script("list.sh").stdout, "")
        self.assertFalse(directory.exists())

    def test_reused_pid_does_not_authorize_killing_unrelated_process(self):
        process = subprocess.Popen(["sleep", "60"])
        self.addCleanup(lambda: process.wait(timeout=5))
        self.addCleanup(process.terminate)
        vm_id = "kpctl-test-reused-bios"
        directory = self.root / vm_id
        directory.mkdir()
        (directory / "pid").write_text(str(process.pid))
        self.run_script("delete.sh", vm_id)
        self.assertIsNone(process.poll())
        self.assertFalse(directory.exists())

    def test_qmp_quit_is_sent_even_if_pid_file_was_lost(self):
        vm_id = "kpctl-test-missing-pid-bios"
        directory = self.root / vm_id
        directory.mkdir()
        commands = []
        with socket.socket(socket.AF_UNIX) as listener:
            try:
                listener.bind(str(directory / "qmp.sock"))
            except PermissionError:
                self.skipTest("sandbox does not permit Unix sockets")
            listener.listen(1)
            listener.settimeout(5)

            def qmp_server():
                with listener.accept()[0] as conn:
                    conn.settimeout(5)
                    stream = conn.makefile("rwb", buffering=0)
                    stream.write(b'{"QMP":{}}\r\n')
                    commands.append(json.loads(stream.readline())["execute"])
                    stream.write(b'{"return":{}}\r\n')
                    commands.append(json.loads(stream.readline())["execute"])

            server = threading.Thread(target=qmp_server, daemon=True)
            server.start()
            self.run_script("delete.sh", vm_id)
            server.join(timeout=5)
            self.assertFalse(server.is_alive())
        self.assertEqual(commands, ["qmp_capabilities", "quit"])
        self.assertFalse(directory.exists())

    def test_path_traversal_and_symlink_vm_directories_are_rejected(self):
        for command in ("delete.sh", "console.sh"):
            with self.subTest(command=command, kind="traversal"):
                result = self.run_script(command, "../other", check=False)
                self.assertNotEqual(result.returncode, 0)
        target = self.root / "other"
        target.mkdir()
        (target / "valuable").write_text("preserve")
        vm_id = "kpctl-test-symlink-bios"
        (self.root / vm_id).symlink_to(target, target_is_directory=True)
        self.assertNotEqual(self.run_script("delete.sh", vm_id, check=False).returncode, 0)
        self.assertEqual((target / "valuable").read_text(), "preserve")
        self.assertEqual(self.run_script("list.sh").stdout, "")


if __name__ == "__main__":
    unittest.main()
