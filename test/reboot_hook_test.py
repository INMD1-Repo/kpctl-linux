import os
from pathlib import Path
import subprocess
import tempfile
import unittest


HOOK = Path(__file__).resolve().parents[1]/"configs/reboot-hook.example.sh"
APPROVED = dict(KPCTL_REBOOT_APPROVED="1", KPCTL_REBOOT_ID="7", KPCTL_TARGET_KERNEL="6.8.0-147-generic", KPCTL_TARGET_ID="test-target")


class RebootHook(unittest.TestCase):
    def test_truncated_qemu_name_blocks_reboot(self):
        # Only name a sleeping child. systemctl is a harmless stub even if the
        # guard regresses, so this test can never reboot the machine.
        child = subprocess.Popen(["python3", "-c", "import ctypes,time; ctypes.CDLL(None).prctl(15,b'qemu-system-x86_64',0,0,0); print('ready',flush=True); time.sleep(30)"], stdout=subprocess.PIPE, text=True)
        self.assertEqual(child.stdout.readline().strip(), "ready")
        try:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root/"systemctl").write_text("#!/bin/sh\necho unexpected-reboot > \"$KPCTL_REBOOT_MARKER\"\n")
                (root/"systemctl").chmod(0o755)
                env = dict(os.environ, **APPROVED, PATH=directory+":"+os.environ["PATH"], KPCTL_REBOOT_MARKER=str(root/"marker"))
                result = subprocess.run(["sh", str(HOOK)], env=env, capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("남아 있어", result.stderr)
                self.assertFalse((root/"marker").exists())
        finally:
            child.terminate(); child.wait(); child.stdout.close()

    def test_inventory_error_blocks_and_empty_inventory_uses_normal_reboot(self):
        for status in [1, 2]:
            with self.subTest(status=status), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root/"pgrep").write_text(f"#!/bin/sh\nexit {status}\n")
                (root/"systemctl").write_text('#!/bin/sh\nprintf "%s\\n" "$*" > "$KPCTL_REBOOT_MARKER"\n')
                for name in ["pgrep", "systemctl"]:
                    (root/name).chmod(0o755)
                result = subprocess.run(["/bin/sh", str(HOOK)], env=dict(os.environ, **APPROVED, PATH=directory, KPCTL_REBOOT_MARKER=str(root/"marker")), capture_output=True)
                self.assertEqual(result.returncode == 0, status == 1)
                if status == 1:
                    self.assertEqual((root/"marker").read_text(), "reboot\n")
                else:
                    self.assertFalse((root/"marker").exists())

    def test_no_agent_approval_never_reboots(self):
        result = subprocess.run(["/bin/sh",str(HOOK)],env={"PATH":"/nonexistent"},capture_output=True,text=True)
        self.assertNotEqual(result.returncode,0)
        self.assertIn("관리자 승인",result.stderr)


if __name__ == "__main__":
    unittest.main()
