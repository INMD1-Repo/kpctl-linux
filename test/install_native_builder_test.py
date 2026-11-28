"""전용 VM의 설치 옵션과 트랙 준비·실행을 임시 디렉터리에서 검사합니다."""
import fcntl
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

DEPLOY = Path(__file__).resolve().parents[1] / "deploy"
DEB = "6.1.0-57-amd64"
R9 = "5.14.0-741.27.1.el9_9.x86_64"
R10 = "6.12.0-264.21.1.el10_3.x86_64"


def track(abi, family, version):
    return f"native__{family}__amd64__{abi}__{version}__" + "a" * 40


class NativeInstall(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.env = dict(os.environ, PATH=f"{self.bin}:{os.environ['PATH']}", FIXTURE=tmp.name,
                        SETUP=str(DEPLOY / "setup-native-builder.sh"))
        self.calls = self.root / "calls"
        for name in ("dnf", "apt-get", "useradd", "runuser", "install"):
            self.fake(name, 'echo "$0 $*" >> "$FIXTURE/calls"; exit 66')
        self.fake("id", "echo 0")
        self.fake("uname", "echo x86_64")
        self.fake("df", 'printf "Filesystem\n/dev/fixture 99999999 0 99999999\n"')
        self.fake("systemd-detect-virt", '[ "$1" != --vm ] || exit 0; echo "${VIRT:-none}"; [ -n "${VIRT:-}" ]')
        self.fake("systemctl", '[ "$*" = "show --property=Version --value" ] || { echo "$*" >> "$FIXTURE/calls"; exit 66; }')
        self.fake("grep", '[ "$3" = /proc/cpuinfo ] || exec /usr/bin/grep "$@"')
        self.release("debian", "12")

    def release(self, distro, version, extra=""):
        (self.root / "os-release").write_text(
            f'ID={distro}\nVERSION_ID={version}\nVERSION_CODENAME=bookworm\nVERSION="테스트 VM"\n{extra}')

    def fake(self, name, body):
        script = self.bin / name
        script.write_text("#!/bin/sh\n" + body + "\n")
        script.chmod(0o755)

    def setup_command(self, *args, body='main "$@"'):
        script = ('source "$SETUP"\nOS_RELEASE=$FIXTURE/os-release\nUNIT_DIR=$FIXTURE\n'
                  'AGENT=$FIXTURE/agent\nROOT_DIR=$FIXTURE\nOPT_DIR=$FIXTURE\n' + body)
        return subprocess.run(["bash", "-c", script, "setup-native-builder", *args],
                              env=self.env, capture_output=True, text=True, timeout=20)

    def test_plan_with_official_packages(self):
        for distro, release, abi, version, package in [
            ("debian", "12", DEB, "6.1.192-3_tdeb12u1", "debian-archive-keyring"),
            ("rocky", "9", R9, R9.removesuffix(".x86_64"), "rpm-build"),
            ("rocky", "10", R10, R10.removesuffix(".x86_64"), "xxhash-devel >= 0.8"),
        ]:
            with self.subTest(distro=distro, release=release):
                self.release(distro, release)
                target = abi + "=" + track(abi, f"{distro}__{release}", version)
                p = self.setup_command("--plan", "--target", target, "--jobs", "4", "--no-start",
                                       "--target", abi, "--user", "testbuild")
                self.assertEqual(p.returncode, 0, p.stderr)
                plan = json.loads(p.stdout)
                self.assertEqual((plan["distro"], plan["release"], plan["targets"], plan["user"],
                                  plan["jobs"], plan["start"]), (distro, release, [target, abi], "testbuild", 4, False))
                self.assertIn(package, plan["packages"])
                self.assertFalse(self.calls.exists())

    def test_invalid_args(self):
        good = track(DEB, "debian__12", "6.1.192-3")
        for args in [
            [], ["--target"], ["--target", "--plan"], ["--target", "6.12.118+deb13-amd64"],
            ["--target", DEB + "="], ["--target", DEB + "=" + good[:-1]], ["--target", DEB + "=" + good + "/"],
            ["--target", DEB + "=" + good.replace(DEB, R9)], ["--target", DEB + "=" + good.replace("debian__12", "rocky__9")],
            ["--unknown"], ["--user", "root"], ["--user", "test/bad"], ["--jobs", "0"], ["--jobs", "257"],
            ["--token-file", str(self.root / "os-release")], ["--worker", str(self.root / "os-release")],
        ]:
            with self.subTest(args=args):
                p = self.setup_command("--plan", *(["--target", DEB] if args else []), *args)
                self.assertEqual(p.returncode, 2, p.stderr)
                self.assertIn("!!", p.stderr)
        self.assertFalse(self.calls.exists())

    def test_host_and_existing_account(self):
        (self.root / "kpctl-native-builder.service").write_text("[Service]\nUser=original\n")
        self.assertEqual(json.loads(self.setup_command("--plan", "--target", DEB).stdout)["user"], "original")
        p = self.setup_command("--plan", "--target", DEB, "--user", "another")
        self.assertEqual(p.returncode, 2)
        self.assertIn("original", p.stderr)
        agent = self.root / "agent"
        agent.touch(mode=0o755)
        p = self.setup_command("--plan", "--target", DEB)
        self.assertEqual(p.returncode, 1)
        self.assertIn("에이전트", p.stderr)
        agent.unlink()
        self.env["VIRT"] = "lxc"
        p = self.setup_command("--plan", "--target", DEB)
        self.assertEqual(p.returncode, 1)
        self.assertIn("컨테이너", p.stderr)
        del self.env["VIRT"]
        for distro, rel, extra, abi, reason in [("debian", "13", "", DEB, "지원하지 않는"),
                                                ("debian", "12", "", R9, "커널이 아닙니다"),
                                                ("rocky", "10", "RELEASE_TYPE=development\n", R10, "정식 릴리스")]:
            self.release(distro, rel, extra)
            p = self.setup_command("--plan", "--target", abi)
            self.assertEqual(p.returncode, 1)
            self.assertIn(reason, p.stderr)
        self.assertFalse(self.calls.exists())

    def test_bundle_flavor_marker_must_match_host(self):
        # make dist 의 dist/builder/<종류>/builder-flavor 가 호스트 os-release ID 와 다르면 설치하지 않습니다
        marker = self.root / "builder-flavor"
        body = 'HERE=$FIXTURE\nmain "$@"'
        marker.write_text("rocky\n")
        p = self.setup_command("--plan", "--target", DEB, body=body)
        self.assertEqual(p.returncode, 1)
        self.assertIn("rocky 빌더용", p.stderr)
        marker.write_text("debian\n")
        p = self.setup_command("--plan", "--target", DEB, body=body)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertFalse(self.calls.exists())

    def test_packages_use_official_repos_and_signed_srpm(self):
        script = 'parse_args "$@"\ncheck_host\nTEMP=$FIXTURE\ninstall_packages'
        self.fake("apt-get", 'echo "$*" >> "$FIXTURE/calls"')
        p = self.setup_command("--target", DEB, body=script)
        self.assertEqual(p.returncode, 0, p.stderr)
        sources = (self.root / "sources.list").read_text().splitlines()
        self.assertEqual(len(sources), 4)
        self.assertTrue(all("signed-by=/usr/share/keyrings/debian-archive-keyring.gpg" in row for row in sources))
        self.assertTrue(all("Dir::Etc::sourceparts=-" in row for row in self.calls.read_text().splitlines()))

        self.release("rocky", "10")
        self.fake("dnf", """echo "$*" >> "$FIXTURE/calls"
for arg do
    case "$arg" in
        download) touch "$FIXTURE/kernel-$KVER.src.rpm";;
        *.spec) test "$(cat "$arg")" = 'BuildRequires: perl(ExtUtils::Embed)' || exit 1;;
    esac
done""")
        self.fake("rpm2cpio", """test -f "$1" && echo 'BuildRequires: perl(ExtUtils::Embed)'""")
        self.fake("cpio", 'cat > kernel.spec')
        self.fake("rpmkeys", 'echo "$*" >> "$FIXTURE/calls"')
        self.fake("rpm", 'case "$*" in *-Kv*) echo "$SIGNATURE";; *) echo "kernel-$KVER 1";; esac')
        self.env.update(SIGNATURE="Payload SHA256 digest: OK", KVER=R10.removesuffix(".x86_64"))
        for signed in (False, True):
            self.calls.unlink()
            if signed:
                self.env["SIGNATURE"] += "\nHeader RSA/SHA256 Signature: OK"
            (self.root / f"kernel-{self.env['KVER']}.src.rpm").unlink(missing_ok=True)
            p = self.setup_command("--target", R10, "--target", R10, body=script)
            self.assertEqual(p.returncode, 0 if signed else 1, p.stderr)
            calls = self.calls.read_text()
            self.assertIn("--enablerepo=baseos,appstream,crb,devel", calls)
            self.assertIn("download --source", calls)
            self.assertEqual(calls.count("download --source"), 1)
            deps = [line for line in calls.splitlines() if " builddep " in line]
            if signed:
                self.assertEqual(len(deps), 2)
                self.assertTrue(deps[0].endswith(f"kernel-{self.env['KVER']}.src.rpm"))
                self.assertIn("--define dist .el10_3", deps[1])
                self.assertTrue(deps[1].endswith("/kernel.spec"))
            else:
                self.assertEqual(deps, [])

    def test_rocky_missing_tag_and_prepare_failure_are_distinct(self):
        self.release("rocky", "10")
        repo = self.root / "inputs/rocky-kernel"
        repo.mkdir(parents=True)
        def git(*args):
            return subprocess.check_output(["git", "-C", repo, *args], text=True).strip()
        git("init", "-q")
        git("-c", "user.name=fixture", "-c", "user.email=fixture@example.org",
            "-c", "commit.gpgSign=false", "commit", "--allow-empty", "-qm", "kernel")
        version = R10.removesuffix(".x86_64")
        tag = f"patched/r10/kernel-{version}"
        script = ('parse_args "$@"\ncheck_host\nSTAGE=$(mktemp -d "$FIXTURE/plan.XXXXXX")\n'
                  'as_builder() { "$@"; }\nplan_targets\nprepare_targets')
        p = self.setup_command("--target", R10, body=script)
        self.assertNotEqual(p.returncode, 0)
        self.assertIn(f"공식 Git 태그를 찾지 못했습니다 ({tag})", p.stderr)

        git("tag", tag)
        (self.root / "kpctl-native-builder.py").write_text("""
import json, sys
from pathlib import Path
assert sys.argv[1] == "prepare"
plan = json.loads(Path(sys.argv[sys.argv.index("--plan") + 1]).read_text())
Path(plan["git"]).joinpath("observed.json").write_text(json.dumps(plan))
sys.exit("rpmbuild -bp: newt-devel is needed")
""")
        p = self.setup_command("--target", R10, body=script)
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("rpmbuild -bp: newt-devel is needed", p.stderr)
        self.assertNotIn("태그를 찾지 못했습니다", p.stderr)
        plan = json.loads((repo / "observed.json").read_text())
        self.assertEqual((plan["abi"], plan["version"], plan["revision"], plan["suite"]),
                         (R10, version, git("rev-parse", "HEAD"), "BaseOS"))
        self.assertFalse((self.root / "tracks").exists())

    def test_config_permissions_and_timer(self):
        # 소유권만 모의 처리하고 파일 생성·권한·교체는 실제 install/mv 로 확인합니다.
        self.fake("install", """exec python3 -c '
import os, sys
args = sys.argv[1:]
for option in ("-o", "-g"):
    if option in args:
        i = args.index(option)
        del args[i:i + 2]
os.execv("/usr/bin/install", ["install", *args])
' "$@" """)
        self.fake("systemctl", 'echo "$*" >> "$FIXTURE/calls"')
        self.fake("chown", 'test "$1" = "root:testbuild"')
        etc = self.root / "etc"
        ca = self.root / "tls/ca.crt"
        cfg = dict(controller_url="https://ctl", token_file=str(etc / "token"), ca_file=str(ca), builder="fixture")
        (self.root / "worker").write_text(json.dumps(cfg))
        secret = "fixture-native-token-123456"
        token = self.root / "input-token"
        token.write_text(secret)
        script = ('parse_args "$@"\nETC_DIR=$FIXTURE/etc TLS_DIR=$FIXTURE/tls TEMP=$FIXTURE\n'
                  'HERE=$(dirname "$SETUP")/systemd\nUNIT_DIR=$FIXTURE/units\nmkdir -p "$UNIT_DIR"\n'
                  'BUILD_GROUP=testbuild\nas_builder() { "$@"; }\n'
                  'install_config_and_units\nstart_timer')
        args = ["--target", DEB, "--worker", str(self.root / "worker"), "--ca-file", str(self.root / "os-release"),
                "--user", "testbuild", "--token-file", str(token)]
        p = self.setup_command(*args, "--no-start", body=script)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(self.calls.read_text().splitlines(), ["daemon-reload"])
        self.assertEqual((etc / "token").read_text(), secret)
        self.assertEqual(json.loads((etc / "worker.json").read_text()), cfg)
        for path in [etc / "token", etc / "worker.json"]:
            self.assertEqual(path.stat().st_mode & 0o777, 0o640)
        self.assertIn("Group=testbuild", (self.root / "units/kpctl-native-builder.service").read_text())
        self.assertEqual(ca.read_text(), (self.root / "os-release").read_text())
        self.assertNotIn(secret, p.stdout + p.stderr + self.calls.read_text())
        token.write_text("short")
        p = self.setup_command(*args, body=script)
        self.assertEqual(p.returncode, 1)
        self.assertEqual((etc / "token").read_text(), secret)
        p = self.setup_command("--target", DEB, body=script)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("enable --now kpctl-native-builder.timer", self.calls.read_text())
        self.assertIn("start --no-block kpctl-native-builder.service", self.calls.read_text())

    def test_prepare_before_publishing_tracks(self):
        driver = self.root / "kpctl-native-builder.py"
        driver.write_text("""
import json, sys
from pathlib import Path
p = json.loads(Path(sys.argv[sys.argv.index("--plan") + 1]).read_text())
if sys.argv[1] == "discover":
    if p["suite"] == "bookworm-security":
        sys.exit(1)
    for version in ["6.1.192-2", "6.1.192-3"]:
        print(json.dumps(dict(p, abi="6.1.0-57-amd64", version=version)))
elif sys.argv[1] == "prepare":
    print(json.dumps({"track": "native__debian__12__amd64__" + p["abi"] + "__" + p["version"] + "__" + "a"*40}))
else:
    sys.exit(66)
""")
        tracks = self.root / "tracks"
        tracks.mkdir()
        (tracks / "이전트랙").mkdir()
        wanted = track(DEB, "debian__12", "6.1.192-3")
        target = DEB + "=" + wanted
        script = ('parse_args "$@"\ncheck_host\nSTAGE=$(mktemp -d "$FIXTURE/.plan.XXXXXX")\n'
                  'trap \'rm -rf "$STAGE"\' EXIT\nas_builder() { "$@"; }\nplan_targets\nprepare_targets')
        p = self.setup_command("--target", target, "--target", target[:-1] + "b", body=script)
        self.assertEqual(p.returncode, 1)
        self.assertIn("빌드 ID 불일치", p.stderr)
        self.assertEqual([x.name for x in tracks.iterdir()], ["이전트랙"])
        for jobs in (2, 4):
            p = self.setup_command("--target", target, "--jobs", str(jobs), body=script)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertIn("이전트랙", p.stderr)
            plan = json.loads((tracks / wanted / "base.json").read_text())
            self.assertEqual((plan["jobs"], plan["version"], plan["suite"]), (jobs, "6.1.192-3", "bookworm"))
            self.assertEqual(json.loads((tracks / wanted / "base-proof.json").read_text())["track"], wanted)


class NativeWork(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.env = dict(os.environ, KPCTL_NATIVE_ROOT=tmp.name, KPCTL_NATIVE_DRIVER=str(self.root / "driver.py"),
                        KPCTL_NATIVE_WORKER=str(self.root / "worker.json"))
        self.calls = self.root / "calls"
        self.tracks = self.root / "tracks"
        self.tracks.mkdir()

    def run_work(self):
        return subprocess.run(["bash", DEPLOY / "kpctl-native-work.sh"], capture_output=True,
                              env=self.env, cwd=self.root, text=True, timeout=10)

    def test_track_order_and_flock(self):
        python = self.root / "python3"
        python.write_text("""#!/bin/bash
set -eu
[[ $1 == -I && $2 == -c && $4 == "$KPCTL_NATIVE_DRIVER" && $5 == work ]]
shift 5
[[ $1 == --plan && $3 == --proof && $4 == "${2%/*}/base-proof.json" ]]
[[ $5 == --cache && $6 == "$KPCTL_NATIVE_ROOT/cache" && $7 == --work-dir && $8 == "$KPCTL_NATIVE_ROOT/work" ]]
[[ $9 == --controller && ${10} == "$KPCTL_NATIVE_WORKER" && ${11} == --fetch ]]
echo "$2" >> "$KPCTL_NATIVE_ROOT/calls"
[[ $2 != */first/base.json ]]
""")
        python.chmod(0o755)
        self.env["PATH"] = f"{self.root}:{self.env['PATH']}"
        empty = self.run_work()
        self.assertEqual(empty.returncode, 0)
        self.assertIn("대상 커널 없음", empty.stdout)
        for name in ("last", "partial", "first"):
            folder = self.tracks / name
            folder.mkdir()
            (folder / "base.json").touch()
            if name != "partial":
                (folder / "base-proof.json").touch()
        with (self.root / "work.lock").open("w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            locked = self.run_work()
            self.assertEqual((locked.returncode, locked.stdout, locked.stderr), (0, "", ""))
            self.assertFalse(self.calls.exists())
        p = self.run_work()
        self.assertEqual(p.returncode, 1)
        self.assertEqual(self.calls.read_text().splitlines(), [str(self.tracks / t / "base.json") for t in ("first", "last")])
        self.assertIn("!! first", p.stderr)

    def test_import_only_installed_driver_directory(self):
        tools = self.root / "tools"
        tools.mkdir()
        (tools / "native_inputs.py").write_text("value = 1\n")
        (self.root / "native_inputs.py").write_text('raise RuntimeError("작업 디렉터리 모듈")\n')
        (tools / "driver.py").write_text("import native_inputs, sys\nassert native_inputs.value == 1 and sys.argv[1] == 'work'\n")
        self.env.update(KPCTL_NATIVE_DRIVER=str(tools / "driver.py"), PYTHONPATH=str(self.root))
        folder = self.tracks / "one"
        folder.mkdir()
        (folder / "base.json").touch()
        (folder / "base-proof.json").touch()
        p = self.run_work()
        self.assertEqual(p.returncode, 0, p.stderr)
