#!/usr/bin/env python3
"""Prepare a signed, published Ubuntu GA kernel. Never reboot or restart services.

Uses isolated official archive indexes, installs only new kernel packages,
retains the running kernel, and records exact files for a later admin approval.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess


SERIES = {"22.04": ("jammy", "5.15.0"), "24.04": ("noble", "6.8.0"), "26.04": ("resolute", "7.0.0")}


def command(args, capture=True):
    return subprocess.run(args, check=True, text=True, stdout=subprocess.PIPE if capture else None,
                          env=dict(os.environ, LC_ALL="C", DEBIAN_FRONTEND="noninteractive", NEEDRESTART_MODE="l")).stdout


# 미러 순서는 설치 묶음의 mirrors.list 한 곳에서 정합니다 (설치 스크립트가 /etc/kpctl 에 설치).
# 파일이 없는 이전 설치는 공식 저장소만 씁니다. 모든 미러는 같은 Ubuntu 서명 키로 검증합니다.
MIRRORS_FILE = Path("/etc/kpctl/mirrors.list")
OFFICIAL = {"amd64": ("official", "http://archive.ubuntu.com/ubuntu", "http://security.ubuntu.com/ubuntu"),
            "arm64": ("official", "http://ports.ubuntu.com/ubuntu-ports", "http://ports.ubuntu.com/ubuntu-ports")}


def load_mirrors(path, arch):
    """[(이름, 저장소, 보안 주소)] for arch, in file order. 형식 오류는 거부합니다 (설치 전 점검과 같은 규칙)."""
    if not path.exists():
        return [OFFICIAL[arch]]
    out = []
    for number, line in enumerate(path.read_text().splitlines(), 1):
        fields = line.split()
        if not fields or fields[0].startswith("#"):
            continue
        if not 3 <= len(fields) <= 4 or not re.fullmatch(r"[a-z0-9][a-z0-9-]*", fields[0]) or fields[1] not in OFFICIAL \
                or not all(re.fullmatch(r"https?://[^\s/?#]+(/[^\s?#]*)?", u) for u in fields[2:]):
            raise ValueError(f"{path}:{number}: invalid mirror line")
        if fields[1] == arch:
            out.append((fields[0], fields[2], fields[3] if len(fields) == 4 else fields[2]))
    if not out:
        raise ValueError(f"{path}: no mirror for {arch}")
    return out


def mirror_sources(arch, series, archive, security):
    return "".join(f"deb [arch={arch} signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] {uri} {suite} main\n"
                   for uri, suite in [(archive, series), (archive, series+"-updates"), (security, series+"-security")])


def use_working_mirror(root, arch, series, options, mirrors):
    """Point the isolated sources at the first mirror whose indexes download and publish the GA meta package."""
    errors = []
    for name, archive, security in mirrors:
        (root/"sources.list").write_text(mirror_sources(arch, series, archive, security))
        shutil.rmtree(root/"lists", ignore_errors=True)  # 미러끼리 색인을 섞지 않음
        (root/"lists").mkdir(mode=0o755)
        try:
            command(["apt-get", *options, "-o", "APT::Update::Error-Mode=any", "update"], capture=False)
            policy = command(["apt-cache", *options, "policy", "linux-image-generic"])
        except subprocess.CalledProcessError as error:
            errors.append(f"{name}: exit {error.returncode}")
            continue
        if re.search(r"^\s*Candidate: [0-9]", policy, re.M):
            print("package mirror: "+name, flush=True)
            return name
        errors.append(name+": linux-image-generic not published")
    raise ValueError("no usable package mirror ("+"; ".join(errors)+")")


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024*1024), b""):
            h.update(block)
    return h.hexdigest()


def boot_entry(grub, kernel):
    # Only Ubuntu's generated, non-recovery entry for this exact ABI is accepted.
    parent = re.findall(r"^submenu .* '([a-z0-9-]*gnulinux-advanced-[a-fA-F0-9-]+)' \{$", grub, re.M)
    child = re.findall(r"^\s*menuentry .* '(gnulinux-"+re.escape(kernel)+r"-advanced-[a-fA-F0-9-]+)' \{$", grub, re.M)
    if len(parent) != 1 or len(child) != 1 or "${next_entry}" not in grub:
        raise ValueError("matching normal GRUB entry/next_entry support is missing")
    suffix = child[0].split("-advanced-", 1)[1]
    if parent[0] != "gnulinux-advanced-"+suffix:
        raise ValueError("GRUB entry belongs to a different root filesystem")
    start = grub.index("'"+child[0]+"'")
    body = grub[start:grub.find("\n\t}", start)]
    if not re.search(r"^\s*linux(?:efi)?\s+\S*/vmlinuz-"+re.escape(kernel)+r"(?:\s|$)", body, re.M) or not re.search(r"^\s*initrd(?:efi)?\s+\S*/initrd.img-"+re.escape(kernel)+r"(?:\s|$)", body, re.M):
        raise ValueError("GRUB entry does not load the expected kernel and initrd")
    return parent[0]+">"+child[0]


def allowed_package(name, abi):
    return name in {"linux-image-"+abi+"-generic", "linux-modules-"+abi+"-generic", "linux-modules-extra-"+abi+"-generic", "wireless-regdb"} or bool(
        re.fullmatch(r"linux-main-modules-[a-z0-9-]+-"+re.escape(abi)+r"-generic",name))


def kernel_install_command(options, versions, replacement=False):
    # A newer publication of the already prepared ABI may be held. Only its
    # exact target versions can change; the simulated plan is checked below.
    mode = ["--allow-change-held-packages"] if replacement else ["--no-upgrade"]
    return ["apt-get", *options, "--no-remove", *mode, "--no-install-recommends", "install",
            *[name+"="+version for name, version in versions.items()]]


def validate_install_plan(plan, abi):
    for name in re.findall(r"^Inst (\S+)", plan, re.M):
        if not allowed_package(name, abi):
            raise ValueError("would change a non-kernel package: "+name)
    if re.search(r"^Remv", plan, re.M):
        raise ValueError("unsafe package plan")


def validate_replacement_target(state_dir, expected_id):
    """Compare the pinned record again while the preparation lock is held."""
    if not re.fullmatch(r"[a-f0-9]{64}", expected_id):
        raise ValueError("invalid replacement target ID")
    descriptor = os.open(state_dir/"boot-target.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022 or info.st_size > 8192:
            raise ValueError("replacement target record has unsafe owner, permissions, type or size")
        content = handle.read(8193)
    if len(content) > 8192:
        raise ValueError("replacement target record is too large")
    record = json.loads(content)
    fields = ["kernel", "package_version", "entry", "fallback_entry", "image_sha256", "initrd_sha256", "config_sha256", "grub_sha256"]
    if not isinstance(record, dict) or any(not isinstance(record.get(key, ""), str) for key in fields):
        raise ValueError("replacement target record has invalid fields")
    # Keep this byte-for-byte compatible with model.BootTargetID in Go.
    actual = hashlib.sha256("\n".join(record.get(key, "") for key in fields).encode()).hexdigest()
    if actual != expected_id:
        raise ValueError("prepared target changed before replacement")


def prepare(state_dir, replace_target_id=None, mirrors_file=MIRRORS_FILE):
    if replace_target_id is not None:
        validate_replacement_target(state_dir, replace_target_id)
    if command(["dpkg", "--audit"]).strip():
        raise ValueError("unconfigured packages require review before preparing a kernel")
    release = dict(line.split("=", 1) for line in Path("/etc/os-release").read_text().splitlines() if "=" in line)
    series, branch = SERIES[release["VERSION_ID"].strip('"')]
    current = Path("/proc/sys/kernel/osrelease").read_text().strip()
    signature = Path("/proc/version_signature").read_text().strip()
    match = re.fullmatch(re.escape(branch)+r"-([0-9]+)-generic", current)
    if not match or "~" in signature or release.get("ID", "").strip('"') != "ubuntu":
        raise ValueError("only the matching Ubuntu GA generic kernel is supported")
    arch = command(["dpkg", "--print-architecture"]).strip()
    if arch not in ["amd64", "arm64"]:
        raise ValueError("unsupported architecture")
    root = Path("/var/cache/kpctl-kernels")
    root.mkdir(mode=0o755, exist_ok=True)
    for path in [root/"lists", root/"archives", root/"empty"]:
        path.mkdir(mode=0o755, exist_ok=True)
    sources = root/"sources.list"
    options = ["-o", "Dir::Etc::sourcelist="+str(sources), "-o", "Dir::Etc::sourceparts="+str(root/"empty"), "-o", "Dir::Etc::preferences=/dev/null",
               "-o", "Dir::Etc::preferencesparts="+str(root/"empty"), "-o", "Dir::State::lists="+str(root/"lists"), "-o", "Dir::Cache::archives="+str(root/"archives"),
               "-o", "DPkg::Lock::Timeout=300", "-o", "Acquire::AllowInsecureRepositories=false", "-o", "APT::Get::AllowUnauthenticated=false",
               "-o", "Acquire::Retries=3"]
    # APT otherwise upgrades installed sibling binaries from the same source
    # (libc headers, perf, bpftool). This operation prepares a boot ABI only.
    options += ["-o", "APT::Get::Upgrade-By-Source-Package=false"]
    use_working_mirror(root, arch, series, options, load_mirrors(mirrors_file, arch))
    def candidate(package):
        policy = command(["apt-cache", *options, "policy", package])
        found = re.search(r"^\s*Candidate: ([0-9][0-9A-Za-z.+:~\-]*)$", policy, re.M)
        if not found:
            raise ValueError("no published package: "+package)
        return found[1]
    meta = command(["apt-cache", *options, "show", "linux-image-generic="+candidate("linux-image-generic")])
    targets = set(re.findall(r"\blinux-image-("+re.escape(branch)+r"-[0-9]+-generic)\b", meta))
    if len(targets) != 1:
        raise ValueError("ambiguous GA image dependency")
    target = targets.pop()
    abi = target.removesuffix("-generic")
    if int(abi.rsplit("-",1)[1]) <= int(match[1]):
        raise ValueError("a newer GA ABI is not yet published")
    if os.statvfs("/boot").f_bavail*os.statvfs("/boot").f_frsize < 256*1024*1024:
        raise ValueError("insufficient /boot free space; existing kernels are retained")
    grub_path=Path("/boot/grub/grub.cfg")
    fallback=boot_entry(grub_path.read_text(),current)
    mount=command(["findmnt","-n","-o","FSTYPE,SOURCE","-T","/boot/grub/grubenv"]).split()
    if len(mount)!=2 or mount[0] not in ["ext2","ext3","ext4"] or str(Path(mount[1]).resolve()).startswith(("/dev/dm-","/dev/md")):
        raise ValueError("one-shot GRUB fallback requires a verified plain ext2/3/4 boot filesystem")
    environment=command(["grub-editenv","/boot/grub/grubenv","list"])
    if re.search(r"^next_entry=.+",environment,re.M):
        raise ValueError("an existing next-boot selection must be reviewed first")
    # Preserve the known running kernel across power loss or an unsuccessful
    # first boot. Only an approved, confirmed boot commits a new saved_entry.
    command(["grub-set-default","--boot-directory=/boot",fallback])
    dropin=Path("/etc/default/grub.d/99-kpctl-boot.cfg")
    dropin.parent.mkdir(parents=True,exist_ok=True)
    dropin.write_text('GRUB_DEFAULT=saved\nGRUB_SAVEDEFAULT=false\n')
    command(["update-grub"],capture=False)
    if 'set default="${saved_entry}"' not in grub_path.read_text():
        raise ValueError("GRUB did not retain the explicitly saved fallback")
    names = ["linux-image-"+target, "linux-modules-"+target]
    # Newer GA releases consolidate extra drivers in linux-modules. Follow the
    # official image meta dependency; headers are a builder requirement only.
    if "linux-modules-extra-"+target in meta:
        names.append("linux-modules-extra-"+target)
    versions = {name:candidate(name) for name in names}
    install = kernel_install_command(options, versions, replacement=replace_target_id is not None)
    plan = command([*install, "--simulate"])
    validate_install_plan(plan, abi)
    print(plan, flush=True)
    # Explicit new ABI package names avoid unholding/upgrading the running ABI.
    command([*install, "--assume-yes"], capture=False)
    for name, version in versions.items():
        actual = command(["dpkg-query", "-W", "-f=${db:Status-Status} ${Version}", name]).strip()
        if actual != "installed "+version:
            raise ValueError("installed package version differs: "+name)
    command(["apt-mark", "manual", *names], capture=False)
    command(["apt-mark", "hold", *names], capture=False)
    reader = shutil.which("lsinitrd") or shutil.which("lsinitramfs")
    if not reader or target not in command([reader, "/boot/initrd.img-"+target]):
        raise ValueError("prepared initrd could not be validated for the new kernel")
    if not Path("/lib/modules", target, "modules.dep").is_file():
        raise ValueError("new kernel modules were not prepared")
    grub_path = Path("/boot/grub/grub.cfg")
    grub = grub_path.read_text()
    result = dict(kernel=target,package_version=versions["linux-image-"+target],entry=boot_entry(grub,target),fallback_entry=fallback,
                  image_sha256=digest(Path("/boot/vmlinuz-"+target)),initrd_sha256=digest(Path("/boot/initrd.img-"+target)),
                  config_sha256=digest(Path("/boot/config-"+target)),grub_sha256=digest(grub_path))
    state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    temp = state_dir/"boot-target.json.tmp"
    with temp.open("w") as handle:
        os.fchmod(handle.fileno(),0o600)
        json.dump(result,handle,indent=2);handle.write("\n");handle.flush();os.fsync(handle.fileno())
    os.replace(temp,state_dir/"boot-target.json")
    print(json.dumps({"running_kernel":current,"prepared_kernel":target,"reboot":"requires_explicit_admin_approval"}),flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path, default=Path("/var/lib/kpctl-agent"))
    parser.add_argument("--replace-target-id", help="refresh only this exact validated preparation record")
    parser.add_argument("--mirrors", type=Path, default=MIRRORS_FILE, help="mirror order (default: %(default)s)")
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit("root required")
    with open("/run/lock/kpctl-kernel-prepare.lock", "a") as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        prepare(args.state_dir, args.replace_target_id, args.mirrors)
