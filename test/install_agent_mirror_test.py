"""install-agent.sh 의 미러 전환(apt-mirror 구간)을 가짜 apt-get·dpkg 로 시험합니다.

실제 호스트에서 공식 저장소를 막았을 때 apt-get update 가 경고만 내고 0 으로 끝나 전환하지 않던 문제(C18)가
다시 생기지 않도록 합니다. 미러 순서는 저장소의 deploy/mirrors.list 를 그대로 씁니다.
"""
from pathlib import Path
import os
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = (ROOT/"deploy/install-agent.sh").read_text()
BLOCK = re.search(r"^# >>> apt-mirror.*?\n(.*?)^# <<< apt-mirror", SCRIPT, re.S | re.M).group(1)

# 가짜 apt-get: 저장소 설정 옵션이 없으면 호스트 설정(HOST_MODE), 있으면 sources.list 의 주소로 미러를 고르고
# FAIL_MIRRORS 에 든 미러는 실패시킵니다. ok | warn(경고만, 0 종료) | fail(100 종료)
FAKE_APT = r'''#!/bin/bash
src=""
for a in "$@"; do case "$a" in Dir::Etc::sourcelist=*) src=${a#*=} ;; esac; done
echo "$src" >> "$CALLS"
if [ -z "$src" ]; then mode=$HOST_MODE
else
  mode=ok
  for m in $FAIL_MIRRORS; do grep -q "$m" "$src" && mode=fail; done
fi
case "$mode" in
  ok) echo "Hit:1 http://mirror stable InRelease"; exit 0 ;;
  warn) echo "W: Failed to fetch http://archive.ubuntu.com/ubuntu/dists/x/InRelease  Unable to connect"
        echo "W: Some index files failed to download. They have been ignored, or old ones used instead."; exit 0 ;;
  *) echo "E: Failed to fetch http://mirror/dists/x/InRelease"; exit 100 ;;
esac
'''


def run(host_mode, fail_mirrors="", arch="amd64"):
    with tempfile.TemporaryDirectory() as directory:
        d = Path(directory)
        (d/"bin").mkdir()
        (d/"bin/apt-get").write_text(FAKE_APT)
        (d/"bin/dpkg").write_text(f"#!/bin/bash\necho {arch}\n")
        for f in ["apt-get", "dpkg"]:
            (d/"bin"/f).chmod(0o755)
        program = ("set -euo pipefail\nHERE=" + str(ROOT/"deploy") + "\nAPT=(-y)\n" + BLOCK +
                   'apt_update\necho "SRC=${APT_SRC[*]+${APT_SRC[*]}}"\necho "APTLEN=${#APT[@]}"\n'
                   'cat "$KPCTL_APT_MIRROR_DIR/sources.list" 2>/dev/null || true\n')
        env = dict(os.environ, PATH=f"{d/'bin'}:{os.environ['PATH']}", HOST_MODE=host_mode, FAIL_MIRRORS=fail_mirrors,
                   CALLS=str(d/"calls"), KPCTL_APT_MIRROR_DIR=str(d/"mirror"))
        out = subprocess.run(["bash", "-c", program], env=env, text=True, capture_output=True)
        calls = (d/"calls").read_text().splitlines() if (d/"calls").exists() else []
        return out.returncode, out.stdout + out.stderr, calls


class InstallAgentMirror(unittest.TestCase):
    def test_host_sources_work_no_mirror(self):
        rc, out, calls = run("ok")
        self.assertEqual(rc, 0, out)
        self.assertIn("SRC=\n", out)
        self.assertEqual(calls, [""])

    def test_warning_only_update_counts_as_failure(self):
        rc, out, _ = run("warn")
        self.assertEqual(rc, 0, out)
        self.assertIn("official 미러", out)
        self.assertIn("http://archive.ubuntu.com/ubuntu", out)
        self.assertIn("http://security.ubuntu.com/ubuntu", out)
        self.assertIn("APTLEN=7", out)  # -y + 옵션 6개

    def test_order_official_kaist_kakao(self):
        rc, out, calls = run("fail", "archive.ubuntu.com")
        self.assertIn("kaist 미러", out)
        self.assertIn("http://ftp.kaist.ac.kr/ubuntu ", out)
        self.assertNotIn("kakao", out)
        rc, out, calls = run("fail", "archive.ubuntu.com ftp.kaist.ac.kr")
        self.assertEqual(rc, 0, out)
        self.assertIn("http://mirror.kakao.com/ubuntu ", out)
        self.assertEqual(len(calls), 4)  # 호스트, official, kaist, kakao
        self.assertRegex(out, r"mirror\.kakao\.com/ubuntu \S+-security main universe")

    def test_all_fail_keeps_going_without_mirror(self):
        rc, out, calls = run("fail", "archive.ubuntu.com ftp.kaist.ac.kr mirror.kakao.com")
        self.assertEqual(rc, 0, out)
        self.assertIn("미러도 모두 실패", out)
        self.assertIn("SRC=\n", out)
        self.assertIn("APTLEN=1", out)

    def test_arm64_uses_ports_and_skips_kakao(self):
        rc, out, calls = run("fail", "ports.ubuntu.com ftp.kaist.ac.kr", arch="arm64")
        self.assertIn("미러도 모두 실패", out)
        self.assertEqual(len(calls), 3, calls)  # 호스트, official ports, kaist ports — 카카오 줄은 amd64 뿐
        rc, out, _ = run("fail", "ports.ubuntu.com", arch="arm64")
        self.assertIn("http://ftp.kaist.ac.kr/ubuntu-ports", out)


if __name__ == "__main__":
    unittest.main()
