import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

spec=importlib.util.spec_from_file_location("prepare",Path(__file__).resolve().parents[1]/"deploy/kpctl-prepare-kernel.py")
prepare=importlib.util.module_from_spec(spec)
spec.loader.exec_module(prepare)


class KernelPreparation(unittest.TestCase):
    def test_only_replacement_can_upgrade_exact_held_target_packages(self):
        versions={"linux-image-7.0.0-43-generic":"7.0.0-43.44","linux-modules-7.0.0-43-generic":"7.0.0-43.44"}
        for replacement in [False,True]:
            with self.subTest(replacement=replacement):
                args=prepare.kernel_install_command(["-o","test=value"],versions,replacement=replacement)
                self.assertEqual(args[0],"apt-get")
                self.assertIn("--no-remove",args)
                self.assertIn("--no-install-recommends",args)
                self.assertEqual("--no-upgrade" in args,not replacement)
                self.assertEqual("--allow-change-held-packages" in args,replacement)
                self.assertEqual(args[args.index("install")+1:],[name+"="+version for name,version in versions.items()])
                self.assertNotIn("unhold",args)

    def test_replacement_plan_still_rejects_current_abi_and_other_packages(self):
        prepare.validate_install_plan("Inst linux-image-7.0.0-43-generic [7.0.0-43.43] (7.0.0-43.44 Ubuntu)\n"
                                      "Inst linux-main-modules-zfs-7.0.0-43-generic (7.0.0-43.44 Ubuntu)\n","7.0.0-43")
        for plan in ["Inst linux-image-7.0.0-14-generic (7.0.0-14.15 Ubuntu)\n",
                     "Inst linux-modules-7.0.0-14-generic (7.0.0-14.15 Ubuntu)\n",
                     "Inst openssh-server (1 Ubuntu)\n", "Remv linux-image-7.0.0-14-generic\n"]:
            with self.subTest(plan=plan),self.assertRaises(ValueError):
                prepare.validate_install_plan(plan,"7.0.0-43")

    def replacement_record(self):
        return dict(kernel="6.8.0-86-generic",package_version="6.8.0-86.86",
                    entry="gnulinux-advanced-abc>gnulinux-6.8.0-86-generic-advanced-abc",
                    fallback_entry="gnulinux-advanced-abc>gnulinux-6.8.0-85-generic-advanced-abc",
                    image_sha256="a"*64,initrd_sha256="b"*64,config_sha256="c"*64,grub_sha256="d"*64)

    def test_replacement_id_matches_go_boot_target_id(self):
        # Shared test vector with internal/model/reboot_test.go. JSON field order,
        # whitespace and an on-disk ID field do not affect the protocol identity.
        expected="0a3008930c2a6f3c644d9e3e99bf9473b9a374a19cd739c67eaf175c71ef6878"
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            target=root/"boot-target.json"
            record=self.replacement_record()
            record["id"]="ignored-on-disk-id"
            target.write_text(json.dumps(record,sort_keys=True,indent=2))
            target.chmod(0o600)
            prepare.validate_replacement_target(root,expected)
            record["package_version"]="6.8.0-86.87"
            target.write_text(json.dumps(record))
            with self.assertRaisesRegex(ValueError,"changed"):
                prepare.validate_replacement_target(root,expected)

    def test_replacement_refuses_unsafe_or_corrupt_records_before_package_commands(self):
        expected="0a3008930c2a6f3c644d9e3e99bf9473b9a374a19cd739c67eaf175c71ef6878"
        for kind in ["missing","symlink","dangling symlink","fifo","directory","writable","owner","large","invalid json","invalid fields","invalid ID"]:
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                root=Path(directory)
                target=root/"boot-target.json"
                target.write_text(json.dumps(self.replacement_record()))
                target.chmod(0o600)
                owner=os.geteuid()
                identity=expected
                if kind=="missing":
                    target.unlink()
                elif kind in ["symlink","dangling symlink"]:
                    other=root/"other.json"
                    if kind=="symlink":
                        other.write_text(target.read_text())
                        other.chmod(0o600)
                    target.unlink()
                    target.symlink_to(other)
                elif kind=="fifo":
                    target.unlink()
                    os.mkfifo(target,0o600)
                elif kind=="directory":
                    target.unlink()
                    target.mkdir()
                elif kind=="writable":
                    target.chmod(0o666)
                elif kind=="owner":
                    owner+=1
                elif kind=="large":
                    target.write_text(" "*8193)
                elif kind=="invalid json":
                    target.write_text("invalid")
                elif kind=="invalid fields":
                    target.write_text('{"kernel": 123}')
                elif kind=="invalid ID":
                    identity="wrong"
                with mock.patch.object(prepare.os,"geteuid",return_value=owner), mock.patch.object(prepare,"command") as command:
                    with self.assertRaises((OSError,ValueError)):
                        prepare.prepare(root,identity)
                    command.assert_not_called()

    def test_only_new_abi_payload_and_regulatory_data_are_allowed(self):
        abi="7.0.0-42"
        for name in ["linux-image-7.0.0-42-generic","linux-modules-7.0.0-42-generic","linux-main-modules-zfs-7.0.0-42-generic","wireless-regdb"]:
            self.assertTrue(prepare.allowed_package(name,abi),name)
        for name in ["libc6","linux-libc-dev","linux-tools-common","bpftool","openssh-server","linux-image-7.0.0-28-generic"]:
            self.assertFalse(prepare.allowed_package(name,abi),name)

    def test_grub_entry_requires_matching_root_kernel_and_initrd(self):
        kernel="7.0.0-42-generic"
        grub='''if [ "${next_entry}" ]; then set default="${next_entry}"; fi
submenu 'Advanced options for Ubuntu' $menuentry_id_option 'gnulinux-advanced-abc' {
 menuentry 'Ubuntu' $menuentry_id_option 'gnulinux-7.0.0-42-generic-advanced-abc' {
  linux /vmlinuz-7.0.0-42-generic root=UUID=abc
  initrd /initrd.img-7.0.0-42-generic
\t}
}
'''
        self.assertEqual(prepare.boot_entry(grub,kernel),"gnulinux-advanced-abc>gnulinux-7.0.0-42-generic-advanced-abc")
        with self.assertRaises(ValueError):
            prepare.boot_entry(grub.replace("/initrd.img-7.0.0-42-generic","/initrd.img-7.0.0-28-generic"),kernel)
        with self.assertRaises(ValueError):
            prepare.boot_entry(grub.replace("gnulinux-advanced-abc","gnulinux-advanced-def"),kernel)

    def run_mirrors(self, behaviour):
        """behaviour: 미러 이름 → "ok" | "fail" | "empty". 실제 apt 대신 sources.list 를 보고 흉내 냄."""
        calls=[]
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            def fake(args, capture=True):
                text=(root/"sources.list").read_text()
                name="kaist" if "ftp.kaist.ac.kr" in text else "kakao" if "mirror.kakao.com" in text else "official"
                calls.append((name,args[-1] if args[-1]=="update" else args[-2]))
                mode=behaviour[name]
                if mode=="fail" and args[-1]=="update":
                    raise prepare.subprocess.CalledProcessError(100,args)
                if args[-1]=="linux-image-generic":
                    return "linux-image-generic:\n  Candidate: "+("(none)" if mode=="empty" else "7.0.0.43.43")+"\n"
                return ""
            with mock.patch.object(prepare,"command",side_effect=fake):
                mirrors=prepare.load_mirrors(Path(__file__).resolve().parents[1]/"deploy/mirrors.list","amd64")
                try:
                    return prepare.use_working_mirror(root,"amd64","resolute",[],mirrors),calls,(root/"sources.list").read_text()
                except ValueError as error:
                    return str(error),calls,(root/"sources.list").read_text()

    def test_official_mirror_is_used_first(self):
        name,calls,sources=self.run_mirrors({"official":"ok","kaist":"ok"})
        self.assertEqual(name,"official")
        self.assertTrue(all(c[0]=="official" for c in calls))
        self.assertIn("http://security.ubuntu.com/ubuntu resolute-security main",sources)

    def test_falls_back_to_kaist_when_official_fails_or_is_incomplete(self):
        for mode in ["fail","empty"]:
            with self.subTest(mode=mode):
                name,calls,sources=self.run_mirrors({"official":mode,"kaist":"ok"})
                self.assertEqual(name,"kaist")
                self.assertIn("signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] http://ftp.kaist.ac.kr/ubuntu resolute-security main",sources)
                self.assertNotIn("archive.ubuntu.com",sources)

    def test_falls_back_to_kakao_after_kaist(self):
        name,calls,sources=self.run_mirrors({"official":"fail","kaist":"fail","kakao":"ok"})
        self.assertEqual(name,"kakao")
        self.assertEqual([c[0] for c in calls if c[1]=="update"],["official","kaist","kakao"])
        self.assertIn("http://mirror.kakao.com/ubuntu resolute-security main",sources)

    def test_reports_every_mirror_when_all_fail(self):
        message,_,_=self.run_mirrors({"official":"fail","kaist":"empty","kakao":"fail"})
        self.assertIn("no usable package mirror",message)
        self.assertIn("official: exit 100",message)
        self.assertIn("kaist: linux-image-generic not published",message)
        self.assertIn("kakao: exit 100",message)

    def test_mirror_list_order_arch_and_missing_file(self):
        shipped=Path(__file__).resolve().parents[1]/"deploy/mirrors.list"
        self.assertEqual([m[0] for m in prepare.load_mirrors(shipped,"amd64")],["official","kaist","kakao"])
        self.assertEqual([m[0] for m in prepare.load_mirrors(shipped,"arm64")],["official","kaist"])
        self.assertEqual(prepare.load_mirrors(shipped,"amd64")[0][2],"http://security.ubuntu.com/ubuntu")
        self.assertEqual(prepare.load_mirrors(Path("/nonexistent/mirrors.list"),"amd64"),[prepare.OFFICIAL["amd64"]])
        with tempfile.TemporaryDirectory() as directory:
            bad=Path(directory)/"mirrors.list"
            for line in ["kaist amd64 ftp.kaist.ac.kr/ubuntu","kaist i386 http://k/ubuntu","kaist amd64"]:
                bad.write_text("official amd64 http://a/ubuntu\n"+line+"\n")
                with self.subTest(line=line),self.assertRaises(ValueError):
                    prepare.load_mirrors(bad,"amd64")


if __name__=="__main__":
    unittest.main()
