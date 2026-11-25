#!/usr/bin/env python3
"""Rootless package-image preparation and disposable kernel-build execution.

No sudo, host package installation, controller token, signing key or host
network is available to a kernel build. Package changes happen during image
preparation only. A clean retry uses the same image and a fresh workspace, once.
"""

import argparse
import contextlib
from collections import Counter
import datetime as dt
import errno
import fcntl
import hashlib
import json
import email.utils
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.parse
import urllib.request
import uuid

IMAGE = re.compile(r"^sha256:[0-9a-f]{64}$")
REGISTRY_DIGEST = re.compile(r"[^\s]+@sha256:[0-9a-f]{64}")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
KERNEL = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+-[0-9]+-[A-Za-z0-9_-]+$")
MODULE = re.compile(r"^[a-z][a-z0-9_]{0,54}$")
PACKAGE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+.:_-]*=[A-Za-z0-9][A-Za-z0-9.+:~_-]*$")
WORK = "/var/lib/kpctl-builder"
PIN = "e0a8f7c681964e9128449446a34f7f3e631a8621"
REQUEST_KEYS = {
    "kernel",
    "base_commit",
    "name",
    "work_dir",
    "out_dir",
    "boot_dir",
    "patch_files",
    "build_tool",
    "jobs",
    "timeout_minutes",
}
KERNEL_KEYS = {"kernel", "git_dir", "base_tag", "tag_glob", "vmlinux", "paths"}


# Removing a stopped kernel-build container deletes tens of GiB of overlay
# files. 25 s was too short on the real builder: the stale container from an
# interrupted run was never removed, so every later run failed at start-up
# (61 of 81 failures, 2026-11-19..23). A failure still keeps the marker so the
# next run retries the removal.
CONTAINER_REMOVE_SECONDS = 600
SNAPSHOT_TIMEOUT_MINUTES = 20


class BuildCancelled(Exception):
    # subprocess retries InterruptedError internally; use a distinct exception
    # so SIGTERM reliably reaches our container cleanup.
    pass


class DiskSpaceError(Exception):
    pass


def disk_space_error(error):
    return isinstance(error, DiskSpaceError) or (
        isinstance(error, OSError) and error.errno in (errno.ENOSPC, errno.EDQUOT)
    )


class BuildBusy(Exception):
    pass


class ArchiveUnavailable(ValueError):
    pass


def sha(data):
    return hashlib.sha256(data).hexdigest()


def atomic(path, data):
    path = Path(path)
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("w") as handle:
        os.fchmod(handle.fileno(), 0o600)
        json.dump(data, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def command(args, **kwargs):
    return subprocess.run(
        args, check=True, text=True, capture_output=True, **kwargs
    ).stdout


def engine():
    if os.geteuid() == 0:
        raise ValueError(
            "run as the dedicated non-root builder user, without sudo/rootful Podman"
        )
    runtime = Path("/run/user") / str(os.getuid())
    if runtime.is_dir() and runtime.stat().st_uid == os.getuid():
        os.environ.setdefault("XDG_RUNTIME_DIR", str(runtime))
    info = json.loads(command(["podman", "info", "--format=json"]))
    if not info["host"]["security"]["rootless"]:
        raise ValueError("rootless Podman is required")


def identity(text):
    match = re.search(r"\(Ubuntu[^)]*\)\s+\d+\.\d+\.\d+", text)
    if not match:
        raise ValueError("Ubuntu GCC package identity is unavailable")
    return match.group()


def kernel_compiler(kernel, headers_root=Path("/usr/src")):
    if not KERNEL.fullmatch(kernel):
        raise ValueError("invalid kernel name")
    header = headers_root / ("linux-headers-" + kernel) / "include/generated/compile.h"
    compiler = identity(header.read_text())
    match = re.fullmatch(r"\(Ubuntu ([A-Za-z0-9.+:~_-]+)\) (\d+)\.\d+\.\d+", compiler)
    if not match:
        raise ValueError("target headers do not identify an exact Ubuntu GCC package")
    version, major = match.groups()
    return {
        "compiler_identity": compiler,
        "compiler_package": "gcc-" + major + "=" + version,
        "cxx_package": "g++-" + major + "=" + version,
    }


def compiler_directory(directory, compiler):
    return Path(directory).resolve() / ("compiler-" + sha(compiler.encode())[:20])


def kernel_publication_time(kernel, version, series):
    architecture = command(["dpkg", "--print-architecture"]).strip()
    target = f"https://api.launchpad.net/1.0/ubuntu/{series}/{architecture}"
    package = "linux-headers-" + kernel
    query = urllib.parse.urlencode(
        {
            "ws.op": "getPublishedBinaries",
            "binary_name": package,
            "version": version,
            "exact_match": "true",
            "distro_arch_series": target,
            "ws.size": 300,
        }
    )
    with urllib.request.urlopen(
        "https://api.launchpad.net/1.0/ubuntu/+archive/primary?" + query,
        timeout=20,
    ) as response:
        entries = json.load(response)["entries"]
    dates = []
    for entry in entries:
        if (
            entry.get("binary_package_name") != package
            or entry.get("binary_package_version") != version
            or entry.get("distro_arch_series_link") != target
            or entry.get("pocket") not in ("Release", "Updates", "Security")
            or not entry.get("date_published")
        ):
            continue
        date = dt.datetime.fromisoformat(entry["date_published"])
        if date.tzinfo is None:
            raise ValueError("kernel publication time has no timezone")
        dates.append(date.astimezone(dt.timezone.utc))
    if not dates:
        raise ValueError("no matching official kernel package publication")
    return min(dates)


def snapshot_candidates(args):
    requested = args.snapshot
    if requested == "none":
        return [""], {"kind": "explicit_live_archive"}
    if requested != "auto":
        dt.datetime.strptime(requested, "%Y%m%dT%H%M%SZ")
        return [requested], {"kind": "explicit_snapshot"}
    if args.sources:
        sources = Path(args.sources).read_text()
        pinned = re.findall(r"(?mi)^Snapshot:\s*(\d{8}T\d{6}Z)\s*$", sources)
        if pinned:
            if len(set(pinned)) != 1:
                raise ValueError(
                    "multiple snapshot IDs in custom sources; choose an explicit recipe"
                )
            return [pinned[0]], {"kind": "custom_snapshot"}
        return [""], {"kind": "custom_signed_sources"}
    version = command(
        ["dpkg-query", "-W", "-f=${source:Version}", "linux-headers-" + args.kernel]
    ).strip()
    tag = args.base_tag or "Ubuntu-" + version
    if not re.fullmatch(r"Ubuntu-[A-Za-z0-9.+~_-]+", tag):
        raise ValueError("invalid Ubuntu kernel package tag")
    series = {"5.15.0": "jammy", "6.8.0": "noble", "7.0.0": "resolute"}.get(
        args.kernel.split("-")[0]
    )
    repository = args.git_dir or ("/srv/ubuntu-" + series if series else None)
    if not repository:
        raise ValueError(
            "automatic snapshot date needs --git-dir and the target package tag"
        )
    git_args = ["git", "-C", repository]
    try:
        timestamp = command(
            git_args + ["log", "-1", "--format=%cI", tag + "^{commit}", "--"],
            timeout=60,
        ).strip()
    except subprocess.CalledProcessError:
        command(git_args + ["fetch", "--tags", "--quiet"], timeout=180)
        timestamp = command(
            git_args + ["log", "-1", "--format=%cI", tag + "^{commit}", "--"],
            timeout=60,
        ).strip()
    date = dt.datetime.fromisoformat(timestamp).astimezone(dt.timezone.utc)
    basis = {
        "kind": "kernel_package_tag_time",
        "tag": tag,
        "commit_time": timestamp,
    }
    dates = []
    if series:
        try:
            published = kernel_publication_time(args.kernel, version, series)
        except (OSError, ValueError, KeyError) as error:
            print("커널 정식 배포일 조회 실패, Git 시각 후보 사용: " + str(error), flush=True)
            basis["publication_lookup_error"] = str(error)
        else:
            # The Git commit can precede both the kernel build and the GCC SRU
            # migration to Updates/Security. Allow the archive mirror to sync.
            dates.extend(published + dt.timedelta(days=offset) for offset in (1, 2))
            basis.update(
                kind="kernel_package_publication_time",
                publication_time=published.isoformat(),
            )
    dates.extend(date + dt.timedelta(days=offset) for offset in (0, -1, 1, -7, 7, -30))
    minimum = dt.datetime(2023, 3, 2, tzinfo=dt.timezone.utc)
    candidates = []
    for date in dates:
        candidate = max(date, minimum).strftime("%Y%m%dT%H%M%SZ")
        if candidate not in candidates:
            candidates.append(candidate)
    return candidates, basis


def run_snapshot_probe(argv, name, archive, log_path, timeout_minutes, timeout_option="--snapshot-timeout-minutes"):
    with log_path.open("a+", encoding="utf-8", errors="replace") as log:
        log.write(f"\nSnapshot {archive}\n")
        log.flush()
        start = log.tell()
        try:
            result = subprocess.run(
                argv, stdout=log, stderr=subprocess.STDOUT, text=True,
                timeout=timeout_minutes * 60,
            )
        except (subprocess.TimeoutExpired, BuildCancelled, KeyboardInterrupt) as error:
            # Killing the attached Podman client can leave the APT container running.
            try:
                subprocess.run(
                    ["podman", "--cgroup-manager=cgroupfs", "rm", "--force", "--ignore", name],
                    stdout=log, stderr=subprocess.STDOUT, timeout=CONTAINER_REMOVE_SECONDS,
                    check=True,
                )
            except (OSError, subprocess.SubprocessError) as cleanup_error:
                print(f"스냅샷 검사 컨테이너 정리 실패: {name}: {cleanup_error}", file=log, flush=True)
                print(f"스냅샷 검사 컨테이너 정리 실패: {name} (로그 {log_path})", file=sys.stderr)
            if not isinstance(error, subprocess.TimeoutExpired):
                raise
            log.write(f"\n스냅샷 검사 시간 초과 ({timeout_minutes:g}분)\n")
            log.seek(start)
            raise ValueError(
                f"{archive} 스냅샷 검사 시간 초과 ({timeout_minutes:g}분). "
                f"APT 전송 상태를 확인하고 필요하면 {timeout_option} 값을 늘리세요. "
                f"로그: {log_path}\n{log.read()[-2000:]}"
            ) from None
        log.seek(start)
        return result.returncode, log.read()


def archive_origin(uri):
    try:
        url = urllib.parse.urlsplit(uri)
        port = url.port
    except ValueError:
        return None
    if url.scheme not in ("http", "https") or not url.hostname:
        return None
    return (url.scheme, url.hostname, port if port is not None else (443 if url.scheme == "https" else 80))


def transient_archive_failure(output):
    # APT can cancel queued indexes with no individual HTTP status after another
    # request fails. Correlate those only with a confirmed outage on the same origin.
    summaries = {
        "E: Some index files failed to download. They have been ignored, or old ones used instead.",
        "E: Unable to fetch some archives, maybe run apt-get update or try with --fix-missing?",
        "E: Unable to fetch some archives, maybe run apt update or try with --fix-missing?",
        "E: Failed to fetch some archives.",
    }
    retryable = re.compile(r"^(429|500|502|503|504)\b")
    confirmed, unexplained = set(), set()
    for line in output.splitlines():
        if not line.startswith(("E:", "W:", "dpkg:", "dpkg-deb:")) or line in summaries:
            continue
        item = re.fullmatch(r"E: Failed to fetch (https?://\S+)(?:\s+(.*))?", line.rstrip())
        if not item:
            return False
        origin = archive_origin(item[1])
        if origin is None:
            return False
        if not item[2]:
            unexplained.add(origin)
        elif retryable.match(item[2]):
            confirmed.add(origin)
        else:
            return False
    if not confirmed or not unexplained.issubset(confirmed):
        return False

    # Err: may show several transport attempts (including a missing compressed
    # variant), or a decisive APT authentication/integrity error on the next line.
    for block in re.finditer(r"(?m)^(Err:\d+|E: Failed to fetch) (\S+)[^\n]*((?:\n[ \t][^\n]*)*)", output):
        marker, uri, details = block.groups()
        cancelled = marker.startswith("Err:") and not details.strip()
        if unexplained and cancelled and archive_origin(uri) not in confirmed:
            return False
        for line in details.splitlines():
            detail = line.strip()
            if not detail or retryable.match(detail):
                continue
            if not unexplained and marker.startswith("Err:") and re.fullmatch(
                r"404\s+Not Found(?:\s+\[IP: [^\]]+\])?", detail, re.I
            ):
                continue
            return False
    return True


def image_archive_error(output):
    _, start, last_apt = output.rpartition("KPCTL_IMAGE_APT_BEGIN\n")
    failed = re.search(r"^KPCTL_IMAGE_APT_FAILED (?:100|123)$", last_apt, re.M)
    if not start or not failed:
        return ""
    diagnostics = last_apt[:failed.start()]
    if not transient_archive_failure(diagnostics):
        return ""
    return diagnostics[-2000:]


def remaining_image_minutes(deadline, log_path):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ValueError(f"컴파일러 이미지 준비 제한 시간(--image-timeout-minutes)을 소진했습니다. 로그: {log_path}")
    return remaining / 60


def select_snapshot(args, root, settings, *, image_deadline=None):
    candidates, basis = snapshot_candidates(args)
    recipe = root / "recipe"
    timeout_minutes = getattr(args, "snapshot_timeout_minutes", SNAPSHOT_TIMEOUT_MINUTES)
    log_path = root / "snapshot-probe.log"
    script = r"""set -euo pipefail
export LC_ALL=C
bash /tmp/environment/configure-apt.sh "$1"
echo '== apt-get update (binary package indexes) =='
apt-get -q -o APT::Sandbox::User=root \
    -o Acquire::http::Timeout=20 -o Acquire::https::Timeout=20 \
    -o Acquire::IndexTargets::deb-src::Sources::DefaultEnabled=false -o Acquire::Languages=none \
    -o Acquire::IndexTargets::deb::DEP-11::DefaultEnabled=false \
    -o Acquire::IndexTargets::deb::CNF::DefaultEnabled=false update
echo '== resolve exact GCC packages =='
bash /tmp/environment/toolchain-pins.sh "$2" "$3" > /tmp/kpctl-toolchain.lock
mapfile -t pins < /tmp/kpctl-toolchain.lock
echo '== simulate exact GCC install =='
apt-get -s -o APT::Sandbox::User=root --no-install-recommends --allow-downgrades install "${pins[@]}" || {
    status=$?
    if [ "$status" -eq 100 ]; then exit 3; fi
    exit "$status"
}
printf 'KPCTL_TOOLCHAIN_PIN %s\n' "${pins[@]}"
"""
    failures = []
    unavailable = []
    automatic = getattr(args, "snapshot", "auto") == "auto" and not getattr(args, "sources", None)
    remaining = list(candidates)
    while remaining:
        snapshot = remaining.pop(0)
        archive = snapshot or "configured archive"
        name = "kpctl-snapshot-" + uuid.uuid4().hex
        argv = [
            "podman",
            "--cgroup-manager=cgroupfs",
            "run",
            "--cgroups=disabled",
            "--name",
            name,
            "--rm",
            "--pull=never",
            "--network=host",
            "--http-proxy=false",
            "--security-opt=no-new-privileges",
            "--user=0",
            *mount(recipe, "/tmp/environment"),
            "--entrypoint=/bin/bash",
            settings["base"],
            "-ec",
            script,
            "snapshot-probe",
            snapshot,
            settings["compiler_package"],
            settings["cxx_package"],
        ]
        probe_minutes = timeout_minutes
        timeout_option = "--snapshot-timeout-minutes"
        if image_deadline is not None:
            image_minutes = remaining_image_minutes(image_deadline, log_path)
            if image_minutes <= probe_minutes:
                probe_minutes = image_minutes
                timeout_option = "--image-timeout-minutes"
        print(f"서명 APT·GCC 의존성 확인: {archive} (제한 {probe_minutes:g}분, 로그 {log_path})", flush=True)
        status, output = run_snapshot_probe(argv, name, archive, log_path, probe_minutes, timeout_option)
        if status == 0:
            pins = [
                line.removeprefix("KPCTL_TOOLCHAIN_PIN ")
                for line in output.splitlines()
                if line.startswith("KPCTL_TOOLCHAIN_PIN ")
            ]
            required = {settings["compiler_package"], settings["cxx_package"]}
            if not required.issubset(pins) or not all(PACKAGE.fullmatch(pin) for pin in pins):
                raise ValueError("invalid exact GCC dependency plan")
            if unavailable:
                basis = dict(basis, unavailable_snapshots=unavailable)
            return {
                "snapshot_id": snapshot,
                "snapshot_time_basis": basis,
                "compiler_family": pins,
            }
        if status == 3:
            failures.append(archive + ": " + output[-2000:])
            continue
        temporary = status == 100 and transient_archive_failure(output)
        if snapshot and automatic and temporary:
            unavailable.append(snapshot)
            if getattr(args, "allow_live_fallback", False):
                print(f"{archive} HTTP 재시도 소진. 이번 설치에 허용된 Ubuntu 기본 저장소에서 GCC 버전을 확인합니다.", flush=True)
                remaining = [""]
                basis = {"kind": "live_archive_fallback"}
                continue
            if len(unavailable) == 1 and remaining:
                print(f"{archive} HTTP 재시도 소진. 다음 서명 스냅샷을 확인합니다.", flush=True)
                continue
        error_type = ArchiveUnavailable if temporary else ValueError
        raise error_type(
            f"{archive} 스냅샷 검사를 완료하지 못했습니다 (종료 코드 {status}). "
            f"로그: {log_path}\n{output[-2000:]}"
        )
    if unavailable:
        raise ArchiveUnavailable("HTTP 오류로 확인하지 못한 날짜: " + ", ".join(unavailable) + f" (로그 {log_path})")
    raise ValueError(
        "exact GCC packages unavailable in verified snapshots; no compiler substitution:\n"
        + "\n".join(failures)
    )


def recipe_hash(root):
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            digest.update(
                (str(path.relative_to(root)) + "->" + os.readlink(path)).encode()
            )
        elif path.is_file():
            digest.update(
                str(path.relative_to(root)).encode() + b"\0" + path.read_bytes()
            )
    return digest.hexdigest()


def image_probe(image):
    script = """import json
import subprocess
commands = {
    "gcc": ["gcc", "--version"],
    "ld": ["ld", "--version"],
    "make": ["make", "--version"],
}
print(json.dumps({
    name: subprocess.check_output(command, text=True).splitlines()[0]
    for name, command in commands.items()
}))
"""
    return json.loads(
        command(
            [
                "podman",
                "--cgroup-manager=cgroupfs",
                "run",
                "--cgroups=disabled",
                "--rm",
                "--pull=never",
                "--network=none",
                "--http-proxy=false",
                "--read-only",
                "--cap-drop=all",
                "--security-opt=no-new-privileges",
                "--entrypoint=python3",
                image,
                "-c",
                script,
            ]
        )
    )


def image_packages(image):
    return command(
        [
            "podman",
            "--cgroup-manager=cgroupfs",
            "run",
            "--cgroups=disabled",
            "--rm",
            "--pull=never",
            "--network=none",
            "--read-only",
            "--http-proxy=false",
            "--cap-drop=all",
            "--security-opt=no-new-privileges",
            "--entrypoint=cat",
            image,
            "/usr/local/share/kpctl/packages.lock",
        ]
    )


# 이미지 빌드(apt build-dep 포함) 제한 시간. 서명 스냅샷 저장소가 느린 곳에서는 수백 MB 를
# 받는 데 한 시간이 넘게 걸릴 수 있어 넉넉히 두고, prepare/rebuild 의 --image-timeout-minutes 로 바꿀 수 있음.
IMAGE_BUILD_TIMEOUT_MINUTES = 180


def stop_podman_build(process, grace):
    # Leave the session leader waitable until the last signal. Its PID (and hence
    # our process group ID) cannot then be recycled for an unrelated build.
    flags = os.WEXITED | os.WNOHANG | os.WNOWAIT
    try:
        exited = os.waitid(os.P_PID, process.pid, flags)
    except ChildProcessError:
        return  # Popen.wait may have already reaped it when Ctrl-C arrived.
    try:
        os.killpg(process.pid, signal.SIGTERM)
        deadline = time.monotonic() + grace
        while exited is None and time.monotonic() < deadline:
            time.sleep(0.1)
            exited = os.waitid(os.P_PID, process.pid, flags)
        if exited is None:
            print("Podman 이미지 빌드가 SIGTERM에 응답하지 않아 강제 종료합니다. "
                  "중간 컨테이너가 남았는지 확인하세요.", file=sys.stderr, flush=True)
    finally:
        # An OCI helper can outlive the CLI. Limit escalation to this invocation.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        finally:
            process.wait(timeout=5)


def run_podman_build(args, log, timeout):
    # Podman --force-rm owns intermediate containers. Its ps --external also
    # includes containers created concurrently by other Podman/Buildah clients.
    process = subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
    try:
        returncode = process.wait(timeout=timeout)
    except (subprocess.TimeoutExpired, BuildCancelled, KeyboardInterrupt) as error:
        try:
            # On service cancellation the parent gives this helper 30s to exit.
            stop_podman_build(process, 120 if isinstance(error, subprocess.TimeoutExpired) else 20)
        except (OSError, subprocess.SubprocessError, BuildCancelled, KeyboardInterrupt) as cleanup_error:
            print(f"Podman 이미지 빌드 중단 처리 실패: {cleanup_error}", file=sys.stderr, flush=True)
        raise
    if returncode:
        raise subprocess.CalledProcessError(returncode, args)


def build_image(root, settings, locked, timeout_minutes=IMAGE_BUILD_TIMEOUT_MINUTES):
    iid = root / "image.iid"
    iid.unlink(missing_ok=True)
    args = [
        "podman",
        "--cgroup-manager=cgroupfs",
        "build",
        "--pull=never",
        "--network=host",
        "--force-rm",
        "--no-cache",
        "--layers=false",
        "--label=io.kpctl.profile=" + sha(str(root.resolve()).encode()),
        "--http-proxy=false",
        "--iidfile",
        str(iid),
        "--build-arg",
        "BASE_IMAGE=" + settings["base"],
        "--build-arg",
        "LOCKED=" + str(int(locked)),
        "--build-arg",
        "COMPILER_PACKAGE=" + settings["compiler_package"],
        "--build-arg",
        "CXX_PACKAGE=" + settings["cxx_package"],
        "--build-arg",
        "SNAPSHOT_ID=" + settings.get("snapshot_id", ""),
        "-f",
        str(root / "recipe/Containerfile"),
        str(root / "recipe"),
    ]
    with (root / "image-build.log").open("w") as log:
        try:
            run_podman_build(args, log, timeout_minutes * 60)
        except subprocess.CalledProcessError as error:
            log.flush()
            if not locked:
                diagnostics = image_archive_error((root / "image-build.log").read_text(errors="replace"))
                if diagnostics:
                    raise ArchiveUnavailable(
                        f"APT 패키지 다운로드 실패. 로그: {root / 'image-build.log'}\n{diagnostics}"
                    ) from None
            with (root / "image-build.log").open("rb") as evidence:
                evidence.seek(max(0, log.tell() - 2000))
                tail = evidence.read(2000).decode(errors="replace").strip()
            error.stderr = f"로그: {root / 'image-build.log'}\n{tail}"
            raise
        except subprocess.TimeoutExpired:
            fetched = re.findall(
                r"(?m)^Fetched .*$", (root / "image-build.log").read_text(errors="replace")
            )
            raise ValueError(
                "컴파일러 이미지 빌드가 "
                + f"{timeout_minutes:g}"
                + "분 안에 끝나지 않아 멈췄습니다"
                + (" (마지막 다운로드: " + fetched[-1] + ")" if fetched else "")
                + ". 대개 패키지 저장소(서명 스냅샷)가 느린 탓이니 --image-timeout-minutes 를 늘려 다시 실행하세요. 로그: "
                + str(root / "image-build.log")
            ) from None
    image = iid.read_text().strip()
    if not IMAGE.fullmatch(image):
        raise ValueError("invalid image ID from Podman")
    remember_image(root, image)
    try:
        tools = image_probe(image)
        if identity(tools["gcc"]) != settings["compiler_identity"]:
            raise ValueError(
                "image GCC differs from the pinned target compiler: " + tools["gcc"]
            )
        packages = image_packages(image)
        if not packages or not all(
            PACKAGE.fullmatch(line) for line in packages.splitlines()
        ):
            raise ValueError("invalid installed-package manifest")
    except Exception:
        try:
            cleanup_images(root, set(), profile_references(root.parent))
        except Exception as cleanup_error:
            print("미검증 이미지 정리 보류: " + str(cleanup_error), flush=True)
        raise
    return image, tools, packages


def asset_paths():
    here = Path(__file__).resolve().parent
    if (here / "build-environment/Containerfile").is_file():
        return here / "build-environment", here
    root = Path("/usr/local/share/kpctl/build-environment")
    return root, root


def stage_recipe(args, root):
    recipe = root / "recipe"
    if recipe.is_symlink():
        raise ValueError("image recipe cannot be a symlink")
    if recipe.exists():
        remove_worktree(recipe)
    recipe.mkdir(exist_ok=True)
    images, helpers = asset_paths()
    for name in (
        "Containerfile",
        "install-packages.sh",
        "configure-apt.sh",
        "toolchain-pins.sh",
    ):
        shutil.copy2(images / name, recipe / name)
    for name in ("kpctl-kpatch-fixes.sh", "kpctl-kpatch-cold-test.py"):
        shutil.copy2(helpers / name, recipe / name)
    shutil.copytree(
        helpers / "kpatch-fixes", recipe / "kpatch-fixes", dirs_exist_ok=True
    )
    (recipe / "packages.lock").write_text("")
    (recipe / "base-packages.lock").write_text("")
    shutil.copyfile(
        "/etc/ssl/certs/ca-certificates.crt", recipe / "ca-certificates.crt"
    )
    (recipe / "extra-packages").write_text("\n".join(args.package) + "\n")
    sources = Path(args.sources).read_text() if args.sources else ""
    if re.search(r"[a-z][a-z0-9+.-]*://[^/\s]*@", sources, re.I) or re.search(
        r"trusted\s*=\s*yes|Trusted:\s*yes", sources, re.I
    ):
        raise ValueError(
            "do not embed repository credentials or disable APT signature checks"
        )
    (recipe / "sources").write_text(sources)
    source = args.kpatch_source
    if not source:
        source = str(root / "kpatch-input")
        if not Path(source).is_dir():
            command(["git", "init", "--quiet", source])
        command(
            [
                "git",
                "-C",
                source,
                "fetch",
                "--depth=1",
                "https://github.com/dynup/kpatch.git",
                PIN,
            ]
        )
    archive = root / "kpatch.tar"
    with archive.open("wb") as output:
        subprocess.run(
            [
                "git",
                "-c",
                "safe.directory=" + str(Path(source).resolve()),
                "-C",
                source,
                "archive",
                PIN,
            ],
            check=True,
            stdout=output,
        )
    target = recipe / "kpatch"
    target.mkdir(exist_ok=True)
    with tarfile.open(archive) as tar:
        tar.extractall(target, filter="data")
    archive.unlink()
    if not args.kpatch_source:
        shutil.rmtree(source)
    return recipe


def prepare(args):
    engine()
    settings = kernel_compiler(args.kernel)
    root = (
        compiler_directory(args.profiles_dir, settings["compiler_identity"])
        if args.profiles_dir
        else Path(args.directory).resolve()
    )
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    with user_build_lock(), profile_lock(root / "profile.json"):
        if args.profiles_dir:
            args.base_image = pinned_base(
                Path(args.profiles_dir).resolve(), args.base_image
            )
        return prepare_locked(args, root, settings)


def resolve_base_image(requested):
    pinned = "@sha256:" in requested
    try:
        if pinned:
            if not REGISTRY_DIGEST.fullmatch(requested):
                raise ValueError("invalid registry base digest")
            present = subprocess.run(
                ["podman", "image", "exists", requested], capture_output=True, text=True
            )
            if present.returncode == 0:
                return requested
            if present.returncode != 1:
                present.check_returncode()
        command(["podman", "pull", requested])
        if pinned:
            return requested
        data = json.loads(command(["podman", "image", "inspect", requested]))[0]
    except subprocess.CalledProcessError as error:
        detail = (error.stderr or "").strip()
        raise ValueError(f"기본 이미지 준비 실패: {error}" + ("\n" + detail if detail else "")) from None
    for digest in data.get("RepoDigests") or []:
        if REGISTRY_DIGEST.fullmatch(digest):
            return digest
    raise ValueError("an immutable registry base digest is required")


def pinned_base(directory, requested):
    pin = directory / "base-image.json"
    if pin.is_symlink():
        raise ValueError("base image pin cannot be a symlink")
    existing_pin = pin.exists()
    if existing_pin:
        base = json.loads(pin.read_text())["base_image"]
    else:
        bases = {
            json.loads(p.read_text())["settings"]["base"]
            for p in directory.glob("compiler-*/profile.json")
        }
        if len(bases) > 1:
            raise ValueError(
                "existing profiles use different base images; choose a new registry"
            )
        base = bases.pop() if bases else resolve_base_image(requested)
    if not REGISTRY_DIGEST.fullmatch(base):
        raise ValueError("invalid base image pin")
    if "@sha256:" in requested and requested != base:
        raise ValueError("base image differs from the registry pin; use a new registry")
    if not existing_pin:
        atomic(pin, {"base_image": base})
    return base


def build_initial_image(args, root, settings):
    timeout = getattr(args, "image_timeout_minutes", IMAGE_BUILD_TIMEOUT_MINUTES)
    deadline = time.monotonic() + timeout * 60
    try:
        return build_image(root, settings, False, timeout)
    except ArchiveUnavailable:
        if not (getattr(args, "allow_live_fallback", False) and args.snapshot == "auto"
                and not args.sources and settings["snapshot_id"]):
            raise

    snapshot = settings["snapshot_id"]
    failed_log = f"image-build-{snapshot}-{uuid.uuid4().hex}.log"
    (root / "image-build.log").rename(root / failed_log)
    print(f"{snapshot} 이미지 빌드 중 HTTP 재시도 소진. Ubuntu 기본 저장소에서 GCC 버전을 다시 확인합니다. "
          f"로그: {root / failed_log}", flush=True)
    live_args = argparse.Namespace(**{**vars(args), "snapshot": "none", "allow_live_fallback": False})
    live = select_snapshot(live_args, root, settings, image_deadline=deadline)
    basis = settings["snapshot_time_basis"]
    live["snapshot_time_basis"] = {
        **basis, "kind": "live_archive_fallback", "failed_stage": "image_build", "failed_log": failed_log,
        "unavailable_snapshots": [*basis.get("unavailable_snapshots", []), snapshot],
    }
    remaining = remaining_image_minutes(deadline, root / failed_log)
    settings.update(live)
    return build_image(root, settings, False, remaining)


def prepare_locked(args, root, settings):
    if (root / "profile.json").exists():
        _, existing = load_profile(root / "profile.json")
        if existing["settings"]["compiler_identity"] != settings["compiler_identity"]:
            raise ValueError("profile compiler does not match target headers")
        wanted_limits = {
            "memory_mib": args.memory_mib,
            "pids": args.pids,
            "disk_free_mib": args.min_free_gib * 1024,
        }
        recipe = root / "recipe"
        wanted_sources = Path(args.sources).read_text() if args.sources else ""
        if (
            existing["limits"] != wanted_limits
            or existing.get("cache", {}).get("max_gib", 0) != args.cache_gib
            or existing.get("cache", {}).get("total_gib", 40) != args.cache_total_gib
            or (recipe / "sources").read_text() != wanted_sources
            or sorted((recipe / "extra-packages").read_text().split())
            != sorted(args.package)
        ):
            raise ValueError(
                "profile options changed; prepare a new directory instead of mutating an existing profile"
            )
        print(
            json.dumps(
                {
                    "profile": str(root / "profile.json"),
                    "image": existing["image"],
                    "existing": True,
                }
            )
        )
        touch_profile(root)
        return
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    require_space(root, args.min_free_gib * 1024)
    settings["base"] = resolve_base_image(args.base_image)
    if not all(
        PACKAGE.fullmatch(p)
        for p in [settings["compiler_package"], settings["cxx_package"], *args.package]
    ):
        raise ValueError("package specifications must be explicit name=version pairs")
    recipe = stage_recipe(args, root)
    settings.update(select_snapshot(args, root, settings))
    base_packages = command(
        [
            "podman",
            "--cgroup-manager=cgroupfs",
            "run",
            "--cgroups=disabled",
            "--rm",
            "--pull=never",
            "--network=none",
            "--http-proxy=false",
            "--read-only",
            "--cap-drop=all",
            "--security-opt=no-new-privileges",
            "--entrypoint=dpkg-query",
            settings["base"],
            "-W",
            "-f=${binary:Package}=${Version}\\n",
        ]
    )
    (recipe / "base-packages.lock").write_text(
        "\n".join(sorted(base_packages.splitlines())) + "\n"
    )
    image, tools, packages = build_initial_image(args, root, settings)
    (recipe / "packages.lock").write_text(packages)
    profile = {
        "schema": 1,
        "image": image,
        "settings": settings,
        "tools": tools,
        "limits": {
            "memory_mib": args.memory_mib,
            "pids": args.pids,
            "disk_free_mib": args.min_free_gib * 1024,
        },
        "packages_sha256": sha(packages.encode()),
        "recipe_sha256": recipe_hash(recipe),
        "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "kpatch_commit": PIN,
        "cache": {
            "max_gib": args.cache_gib,
            "total_gib": args.cache_total_gib,
            "directory": (
                str(Path(args.profiles_dir).resolve() / "cache")
                if args.profiles_dir
                else str(root / "cache")
            ),
        },
    }
    atomic(root / "profile.json", profile)
    touch_profile(root)
    print(
        json.dumps(
            {
                "profile": str(root / "profile.json"),
                "image": image,
                "packages_sha256": profile["packages_sha256"],
            }
        )
    )


def load_profile(path, verify_image=True):
    path = Path(path).resolve()
    profile = json.loads(path.read_text())
    if profile.get("schema") != 1 or not IMAGE.fullmatch(profile.get("image", "")):
        raise ValueError("invalid environment profile")
    limits = profile.get("limits", {})
    if (
        not 1024 <= limits.get("memory_mib", 0) <= 1048576
        or not 128 <= limits.get("pids", 0) <= 32768
    ):
        raise ValueError("explicit image memory/pid limits are required")
    if not 8192 <= limits.get("disk_free_mib", 61440) <= 67108864:
        raise ValueError("invalid minimum scratch disk space")
    if not 0 <= profile.get("cache", {}).get("max_gib", 0) <= 1024:
        raise ValueError("invalid baseline cache size")
    cache = profile.get("cache", {})
    if not cache.get("max_gib", 0) <= cache.get("total_gib", 40) <= 4096:
        raise ValueError("invalid total baseline cache budget")
    if recipe_hash(path.parent / "recipe") != profile["recipe_sha256"]:
        raise ValueError("image recipe or package lock changed; review a new profile")
    if (
        sha((path.parent / "recipe/packages.lock").read_bytes())
        != profile["packages_sha256"]
    ):
        raise ValueError("package lock mismatch")
    if verify_image:
        actual = json.loads(command(["podman", "image", "inspect", profile["image"]]))[
            0
        ]["Id"]
        if actual.removeprefix("sha256:") != profile["image"].removeprefix("sha256:"):
            raise ValueError("image ID mismatch")
    return path, profile


def rebuild(path, timeout_minutes=IMAGE_BUILD_TIMEOUT_MINUTES):
    path, profile = load_profile(path, verify_image=False)
    image, tools, packages = build_image(
        path.parent, profile["settings"], True, timeout_minutes
    )
    if (
        sha(packages.encode()) != profile["packages_sha256"]
        or tools != profile["tools"]
    ):
        raise ValueError(
            "clean image changed locked packages/toolchain; refusing automatic use"
        )
    profile["image"] = image
    atomic(path, profile)
    touch_profile(path.parent)
    # Publish and verify first. A cleanup error must not roll back the new image.
    try:
        cleanup_images(path.parent, {image}, profile_references(path.parent.parent))
    except Exception as error:
        print("새 이미지 검증 완료; 이전 이미지 정리 보류: " + str(error), flush=True)
    return profile


def lifecycle(root):
    path = root / "lifecycle.json"
    if path.is_symlink():
        raise ValueError("profile lifecycle cannot be a symlink")
    return json.loads(path.read_text()) if path.exists() else {}


def touch_profile(root):
    state = lifecycle(root)
    state.update(last_used_at=time.time(), inactive_since=None)
    atomic(root / "lifecycle.json", state)


def remember_image(root, image):
    state = lifecycle(root)
    state.setdefault("images", {})[image] = time.time()
    state["owned_images"] = sorted(set(state.get("owned_images", [])) | {image})
    atomic(root / "lifecycle.json", state)


def profile_references(directory, excluding=None):
    """Malformed/symlink profiles block deletion rather than hide references."""
    references = set()
    for path in directory.glob("*/profile.json"):
        if path.parent == excluding:
            continue
        if path.is_symlink() or path.parent.is_symlink():
            raise ValueError("unsafe profile reference; cleanup deferred")
        data = json.loads(path.read_text())
        if not IMAGE.fullmatch(data.get("image", "")):
            raise ValueError("invalid profile reference; cleanup deferred")
        references.add(data["image"])
    return references


def cleanup_images(root, keep, references, older_than=None):
    state = lifecycle(root)
    remaining = dict(state.get("images", {}))
    for image, created in list(remaining.items()):
        if (
            image in keep
            or image in references
            or (older_than is not None and created > older_than)
        ):
            continue
        if not IMAGE.fullmatch(image):
            raise ValueError("invalid managed image ID")
        inspect = subprocess.run(
            ["podman", "image", "inspect", image], capture_output=True, text=True
        )
        if inspect.returncode:
            # Only a confirmed absent image is safe to forget.
            exists = subprocess.run(
                ["podman", "image", "exists", image], capture_output=True
            )
            if exists.returncode == 1:
                del remaining[image]
            continue
        data = json.loads(inspect.stdout)[0]
        labels = data.get("Config", {}).get("Labels") or {}
        if labels.get("io.kpctl.profile") != sha(str(root.resolve()).encode()):
            print("환경 정리 보류: 소유 표식이 다른 이미지 " + image, flush=True)
            continue
        result = subprocess.run(
            ["podman", "--cgroup-manager=cgroupfs", "image", "rm", "--no-prune", image],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            del remaining[image]
            remove_image_caches(root, image)
            print("환경 이미지 정리: " + image, flush=True)
        else:
            print(
                "환경 이미지 정리 보류 (사용 중 또는 삭제 실패): "
                + image
                + " "
                + result.stderr[-1000:],
                flush=True,
            )
    state["images"] = remaining
    atomic(root / "lifecycle.json", state)
    return remaining


def remove_image_caches(root, image):
    for caches in (root / "cache", root.parent / "cache"):
        if not caches.exists():
            continue
        if caches.is_symlink():
            raise ValueError("cache directory cannot be a symlink")
        for entry in caches.iterdir():
            if entry.name == ".policy.json":
                continue
            if entry.is_symlink() or not re.fullmatch(r"[0-9a-f]{64}", entry.name):
                raise ValueError("invalid cache entry during image cleanup")
            if not (entry / "sealed.json").exists():
                continue
            sealed = json.loads(read_guest(entry, "sealed.json", 64 * 1024 * 1024))
            if sealed.get("inputs", {}).get("image") == image:
                remove_worktree(entry)
                print("환경 캐시 정리: " + entry.name[:16], flush=True)


def tree_bytes(root):
    total = 0
    for base, dirs, files in os.walk(root, followlinks=False):
        for name in dirs + files:
            try:
                total += os.lstat(os.path.join(base, name)).st_blocks * 512
            except FileNotFoundError:
                pass
    return total


def kernel_cache_directories(args):
    """Inventory only explicitly configured profile cache directories."""
    profiles = []
    if args.profile:
        profiles.append(Path(args.profile))
    if args.profiles_dir:
        directory = Path(args.profiles_dir)
        if directory.is_symlink():
            raise ValueError("profiles directory cannot be a symlink")
        if directory.is_dir():
            profiles += sorted(directory.glob("compiler-*/profile.json"))
    caches = {}
    for path in profiles:
        if path.is_symlink() or not path.is_file():
            continue
        root = path.resolve().parent
        profile = json.loads(path.read_text())
        candidates = [root / "cache", root.parent / "cache"]
        configured = profile.get("cache", {}).get("directory")
        if configured:
            if not Path(configured).is_absolute():
                raise ValueError("invalid shared cache directory")
            candidates.append(Path(configured))
        for cache in candidates:
            if cache.is_symlink():
                raise ValueError("cache directory cannot be a symlink")
            if cache.is_dir():
                caches[str(cache.resolve())] = (cache, profile)
    return list(caches.values())


def purge_kernel(args):
    """Inventory or remove sealed baseline caches of one unused kernel."""
    inventory = getattr(args, "action", "purge-kernel") == "kernel-inventory"
    if not inventory and not re.fullmatch(
        r"[0-9]+\.[0-9]+\.[0-9]+-[0-9]+-generic", args.kernel
    ):
        raise ValueError("invalid kernel name")
    caches = kernel_cache_directories(args)
    removed, freed = 0, 0
    with user_build_lock():
        # Validate the whole inventory before deleting anything.
        targets = []
        kernels = set()
        for caches_dir, _ in caches:
            for entry in sorted(caches_dir.iterdir()):
                if entry.name == ".policy.json":
                    continue
                if (
                    entry.is_symlink()
                    or not entry.is_dir()
                    or not re.fullmatch(r"[0-9a-f]{64}", entry.name)
                ):
                    raise ValueError("invalid baseline cache directory")
                if not (entry / "sealed.json").is_file():
                    continue
                sealed = json.loads(read_guest(entry, "sealed.json", 64 * 1024 * 1024))
                kernel = sealed.get("inputs", {}).get("kernel", "")
                if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+-[0-9]+-generic", kernel):
                    kernels.add(kernel)
                if not inventory and kernel == args.kernel:
                    targets.append(entry)
        if inventory:
            print(json.dumps({"kernels": sorted(kernels)}))
            return
        for entry in targets:
            size = tree_bytes(entry)
            remove_worktree(entry)
            removed += 1
            freed += size
            print("커널 캐시 삭제: " + entry.name[:16], flush=True)
    print(json.dumps({"kernel": args.kernel, "removed": removed, "bytes": freed}))


def collect_environments(args, headers_root=Path("/usr/src")):
    directory = Path(args.profiles_dir).resolve()
    if not args.inventory_complete or not 1 <= args.retention_days <= 3650:
        raise ValueError(
            "complete target inventory and positive retention are required"
        )
    # Resolve ALL active headers before any mutation or deletion.
    active = {
        compiler_directory(
            directory, kernel_compiler(k, headers_root)["compiler_identity"]
        ).name
        for k in args.active_kernel
    }
    directory.mkdir(parents=True, exist_ok=True)
    try:
        with user_build_lock(timeout=0):
            gc_locked(directory, active, args.retention_days)
            minimum = getattr(args, "min_free_gib", 0)
            if minimum:
                # Reuse the same global budget and inactive-first LRU. Only
                # reproducible baseline caches are eligible for pressure eviction.
                for caches, profile in kernel_cache_directories(
                    argparse.Namespace(profile=None, profiles_dir=str(directory))
                ):
                    cache_room(
                        caches, profile, set(args.active_kernel),
                        min_free_bytes=minimum * 1024**3,
                        space_path=Path(args.work_dir),
                    )
    except BuildBusy:
        print("환경 정리 보류: 빌드 계정 잠금 사용 중", flush=True)


def gc_locked(directory, active, retention_days):
    now = time.time()
    cutoff = now - retention_days * 86400
    profile_references(directory)  # Check the full inventory before deletion.
    for root in sorted(directory.glob("compiler-*")):
        if (
            root.is_symlink()
            or not root.is_dir()
            or not re.fullmatch(r"compiler-[0-9a-f]{20}", root.name)
        ):
            raise ValueError("invalid compiler profile directory; cleanup deferred")
        try:
            with profile_lock(root / "profile.json", timeout=0):
                state = lifecycle(root)
                if root.name in active:
                    touch_profile(root)
                    profile = (
                        json.loads((root / "profile.json").read_text())
                        if (root / "profile.json").exists()
                        else {}
                    )
                    cleanup_images(
                        root,
                        {profile.get("image")},
                        profile_references(directory),
                        cutoff,
                    )
                    continue
                inactive = state.get("inactive_since")
                if inactive is None:
                    state["inactive_since"] = now
                    atomic(root / "lifecycle.json", state)
                    continue
                if max(inactive, state.get("last_used_at", 0)) > cutoff:
                    continue
                if any((root / "runs").glob("attempt-*/container-name")):
                    print("환경 정리 보류: 잔여 컨테이너 " + root.name, flush=True)
                    continue
                refs = profile_references(directory, excluding=root)
                remaining = cleanup_images(root, set(), refs)
                # Unknown legacy images are retained until explicitly migrated.
                profile = (
                    json.loads((root / "profile.json").read_text())
                    if (root / "profile.json").exists()
                    else {}
                )
                owned = set(state.get("owned_images", []))
                if (
                    remaining
                    or profile.get("image") in refs
                    or (profile and profile["image"] not in owned)
                ):
                    print(
                        "환경 정리 보류: 참조 또는 미추적 이미지 " + root.name,
                        flush=True,
                    )
                    continue
                for image in owned:
                    remove_image_caches(root, image)
                # Keep small logs/recipes/evidence, release the profile name for
                # future preparation; large scratch/cache/image data are gone.
                cache = root / "cache"
                if cache.exists():
                    if cache.is_symlink():
                        raise ValueError("invalid legacy cache path")
                    remove_worktree(cache)
                if (root / "runs").exists():
                    remove_worktree(root / "runs")
                archive = directory / "retired"
                if archive.is_symlink():
                    raise ValueError("retired archive cannot be a symlink")
                archive.mkdir(exist_ok=True)
                if (root / "recipe").exists():
                    if (root / "recipe").is_symlink():
                        raise ValueError("recipe cannot be a symlink")
                    remove_worktree(root / "recipe")
                os.replace(root, archive / (root.name + "-" + uuid.uuid4().hex))
                print("환경 프로파일 정리: " + root.name, flush=True)
        except BuildBusy:
            print("환경 정리 보류: 프로파일 잠금 사용 중 " + root.name, flush=True)
    print("환경 정리 확인 완료 · 비활성 보관 " + str(retention_days) + "일", flush=True)


@contextlib.contextmanager
def profile_lock(path, timeout=60):
    with (Path(path).resolve().parent / "run.lock").open("a") as lock:
        wait_for_lock(lock, timeout)
        yield


@contextlib.contextmanager
def user_build_lock(timeout=60):
    directory = Path.home() / ".local/state/kpctl-build-environment"
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    with (directory / "kernel-build.lock").open("a") as lock:
        os.fchmod(lock.fileno(), 0o600)
        wait_for_lock(lock, timeout)
        yield


def wait_for_lock(lock, timeout):
    deadline = time.monotonic() + timeout
    announced = False
    while True:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return
        except BlockingIOError as error:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise BuildBusy(
                    "another kernel build is running under the same build account"
                ) from error
            if not announced:
                print(
                    "다른 커널 빌드가 끝나기를 기다립니다 (최대 "
                    + str(timeout)
                    + "초)",
                    flush=True,
                )
                announced = True
            time.sleep(min(0.25, remaining))


def require_space(directory, minimum_mib):
    free = shutil.disk_usage(directory).free
    if free < minimum_mib * 1024 * 1024:
        raise DiskSpaceError(
            "insufficient disk space: "
            + str(round(free / 1024**3, 1))
            + " GiB free; need "
            + str(round(minimum_mib / 1024, 1))
            + " GiB on "
            + str(directory)
        )


def read_guest(root, relative, limit, tail=False):
    """Traverse guest-produced outputs without following any symlink."""
    parts = Path(relative).parts
    if not parts or any(p in (".", "..", "/") for p in parts):
        raise ValueError("invalid guest output path")
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parts[:-1]:
            next_fd = os.open(
                part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd
            )
            os.close(fd)
            fd = next_fd
        file = os.open(
            parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd
        )
        with os.fdopen(file, "rb") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or (info.st_size > limit and not tail):
                raise ValueError("guest output is not a bounded regular file")
            if tail:
                handle.seek(max(0, info.st_size - limit))
            data = handle.read(limit + 1)
            if len(data) > limit:
                raise ValueError("guest output grew beyond the limit")
            return data
    finally:
        os.close(fd)


def retryable(response):
    if response.get("cleanup_error"):
        return False
    text = (response.get("error", "") + "\n" + response.get("log", "")).lower()
    kind = response.get("kind")
    corruption = any(
        p in text
        for p in (
            "file truncated",
            "file format not recognized",
            "stale file handle",
            "input/output error",
        )
    )
    if kind != "environment" and not (kind in ("build", "unknown") and corruption):
        return False
    return not any(
        p in text
        for p in (
            "no space left",
            "out of diskspace",
            "insufficient disk space",
            "permission denied",
            "operation not permitted",
            "deadline exceeded",
            "timed out",
            "cancelled",
            "검증 실패",
            "대상 gcc",
            "rustc",
            "bindgen",
            "symbol crc",
            "심볼 crc",
            "vermagic",
            "version disagreement",
        )
    )


def inherited_limits(group_file=Path("/proc/self/cgroup"), root=Path("/sys/fs/cgroup")):
    """Check actual kernel limits: rootless cgroupfs may ignore Podman flags."""
    unified = [
        line[3:]
        for line in group_file.read_text().splitlines()
        if line.startswith("0::")
    ]
    if len(unified) != 1 or ".." in Path(unified[0]).parts:
        raise ValueError("cgroup v2 is required")
    current = root / unified[0].lstrip("/")
    limits = {"memory.max": [], "pids.max": []}
    while True:
        for key, values in limits.items():
            path = current / key
            if path.is_file():
                value = path.read_text().strip()
                if value != "max":
                    values.append(int(value))
        if current == root:
            break
        current = current.parent
    return {key: min(values) if values else None for key, values in limits.items()}


def require_limits(profile):
    actual = inherited_limits()
    expected = {
        "memory.max": profile["limits"]["memory_mib"] * 1024 * 1024,
        "pids.max": profile["limits"]["pids"],
    }
    if any(
        actual[key] is None or actual[key] > value or actual[key] <= 0
        for key, value in expected.items()
    ):
        raise ValueError(
            "run inside a systemd service with MemoryMax and TasksMax at or below profile limits; effective limits="
            + str(actual)
        )
    return actual


def remove_worktree(root):
    # Guest code may leave unwritable directories; never follow guest symlinks.
    try:
        remove_owned_worktree(root)
    except PermissionError:
        # Old attempts may contain mount placeholders created by the rootless
        # runtime's mapped UID. Only our subordinate IDs are mapped here, and
        # chown -hR never dereferences guest-controlled symbolic links.
        subprocess.run(
            ["podman", "unshare", "chown", "-hR", "0:0", str(root)],
            check=True,
            capture_output=True,
            timeout=120,
        )
        remove_owned_worktree(root)


def remove_owned_worktree(root):
    os.chmod(root, 0o700, follow_symlinks=False)
    for parent, directories, _ in os.walk(root, followlinks=False):
        os.chmod(parent, 0o700, follow_symlinks=False)
        for name in directories:
            path = Path(parent) / name
            if not path.is_symlink():
                os.chmod(path, 0o700, follow_symlinks=False)
    shutil.rmtree(root)


def cleanup_container(root):
    marker = root / "container-name"
    if marker.exists():
        name = marker.read_text().strip()
        if not re.fullmatch(r"kpctl-build-[0-9a-f]{32}", name):
            raise ValueError("invalid saved container identity")
        subprocess.run(
            ["podman", "--cgroup-manager=cgroupfs", "rm", "--force", "--ignore", name],
            capture_output=True,
            timeout=CONTAINER_REMOVE_SECONDS,
            check=True,
        )
        marker.unlink()


def mount(source, target, mode="ro"):
    source = str(Path(source).resolve(strict=True))
    if ":" in source or "\n" in source:
        raise ValueError("unsupported mount source path")
    return ["--volume", source + ":" + target + ":" + mode]


def interrupted_logs(root, kernel):
    logs = []
    for directory, relative in [
        (root / "home", ".kpatch/build.log"),
        (root / "work", "src/" + kernel + "/klp-tmp/build.log"),
    ]:
        try:
            data = read_guest(directory, relative, 256 * 1024, tail=True)
            logs.append(
                "----- "
                + relative
                + " (tail) -----\n"
                + data.decode("utf-8", errors="replace")
            )
        except (OSError, ValueError):
            pass
    return "\n".join(logs)


def run_limited(args, root, timeout):
    deadline = time.monotonic() + timeout
    next_space_check = time.monotonic() + 5
    # Drain both pipes continuously: communicate() only returned compiler output
    # after exit, leaving the controller blind throughout a long native build.
    output = {"stdout": bytearray(), "stderr": bytearray()}
    with subprocess.Popen(
        args, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    ) as process, selectors.DefaultSelector() as ready:
        ready.register(process.stdout, selectors.EVENT_READ, "stdout")
        ready.register(process.stderr, selectors.EVENT_READ, "stderr")
        try:
            while ready.get_map() or process.poll() is None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(args, timeout)
                for key, _ in ready.select(min(1, remaining)):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        ready.unregister(key.fileobj)
                        continue
                    output[key.data].extend(chunk)
                    stream = sys.stdout if key.data == "stdout" else sys.stderr
                    if hasattr(stream, "buffer"):
                        stream.buffer.write(chunk)
                        stream.buffer.flush()
                    else:
                        stream.write(chunk.decode("utf-8", errors="replace"))
                        stream.flush()
                if (
                    time.monotonic() >= min(next_space_check, deadline)
                    and process.poll() is None
                ):
                    require_space(root, 5120)
                    next_space_check = time.monotonic() + 5
            return subprocess.CompletedProcess(
                args,
                process.wait(),
                output["stdout"].decode("utf-8", errors="replace"),
                output["stderr"].decode("utf-8", errors="replace"),
            )
        except BaseException:
            process.kill()
            process.wait(timeout=10)
            raise


def stage_inputs(req, worker, root, warmup):
    work = root / "work"
    home = root / "home"
    inputs = root / "inputs"
    for path in (
        work,
        home,
        inputs,
        inputs / "boot",
        inputs / "patches",
        inputs / "repository",
        work / "tmp",
    ):
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
    (inputs / "vmlinux").touch(mode=0o600)
    shutil.copyfile(worker, inputs / "builder")
    (inputs / "builder").chmod(0o755)
    kernel = req["kernel"]["kernel"]
    shutil.copyfile(
        Path(req["boot_dir"]) / ("config-" + kernel),
        inputs / "boot" / ("config-" + kernel),
    )
    local = dict(req)
    local["kernel"] = dict(req["kernel"])
    local.update(
        work_dir=WORK, out_dir=WORK + "/out", boot_dir="/inputs/boot", patch_files=[]
    )
    local["kernel"].update(git_dir="/inputs/repository", vmlinux="/inputs/vmlinux")
    if warmup:
        local["cache_warmup"] = True
        local["patch_files"] = []
    (inputs / "ccache.conf").write_text("")
    for i, path in enumerate([] if warmup else req["patch_files"]):
        filename = str(i).zfill(4) + ".patch"
        shutil.copyfile(path, inputs / "patches" / filename)
        local["patch_files"].append("/inputs/patches/" + filename)
    atomic(inputs / "request.json", local)


def kernel_header_mounts(kernel, headers_root=Path("/usr/src")):
    version, abi, _ = kernel.split("-", 2)
    flavored = headers_root / ("linux-headers-" + kernel)
    mounts = mount(flavored, "/usr/src/" + flavored.name)
    # Ubuntu flavored headers link to sibling common headers and sometimes to
    # the kernel Rust package. Keep those paths without hiding image tool sources.
    for name in ("linux-headers-" + version + "-" + abi, "linux-lib-rust-" + kernel):
        source = headers_root / name
        if source.is_dir():
            mounts += mount(source, "/usr/src/" + name)
    return mounts


def container_args(req, profile, root, cache, warmup):
    work, home, inputs = root / "work", root / "home", root / "inputs"
    kernel = req["kernel"]["kernel"]
    name = "kpctl-build-" + uuid.uuid4().hex
    (root / "container-name").write_text(name)
    # The system service delegates its own cgroup. Moving its children into a
    # separate user-manager systemd scope fails cgroup v2's common-ancestor rule.
    args = [
        "podman",
        "--cgroup-manager=cgroupfs",
        "run",
        "--name",
        name,
        "--pull=never",
        "--network=none",
        "--http-proxy=false",
        "--userns=keep-id",
        "--user",
        str(os.getuid()) + ":" + str(os.getgid()),
        "--cap-drop=all",
        "--security-opt=no-new-privileges",
        "--read-only",
        "--tmpfs=/tmp:rw,nosuid,nodev,size=512m",
        "--memory=" + str(profile["limits"]["memory_mib"]) + "m",
        "--pids-limit=" + str(profile["limits"]["pids"]),
        "--env=KPCTL_ISOLATED_WORKER=1",
        "--entrypoint=/inputs/builder",
    ]
    args += (
        mount(inputs, "/inputs")
        + mount(work, WORK, "rw")
        + mount(home, "/home/kpbuild", "rw")
    )
    args += mount(req["kernel"]["git_dir"], "/inputs/repository")
    args += mount(req["kernel"]["vmlinux"], "/inputs/vmlinux")
    args += kernel_header_mounts(kernel) + mount(
        "/lib/modules/" + kernel, "/lib/modules/" + kernel
    )
    if cache is not None:
        args += mount(cache, "/ccache", "rw" if warmup else "ro")
        args += [
            "--env=CCACHE_DIR=/ccache",
            "--env=CCACHE_CONFIGPATH=/inputs/ccache.conf",
            "--env=CCACHE_TEMPDIR=" + WORK + "/tmp",
            "--env=CCACHE_COMPILERCHECK=content",
            "--env=CCACHE_MAXSIZE=" + str(profile["cache"]["max_gib"]) + "G",
            "--env=CCACHE_STATSLOG=" + WORK + "/ccache-stats.log",
            "--env=CCACHE_NOHARDLINK=1",
            "--env=CCACHE_SLOPPINESS=",
        ]
        if not warmup:
            args += ["--env=CCACHE_READONLY=1", "--env=CCACHE_STATS=1"]
        else:
            args += ["--env=CCACHE_STATS=1"]
    else:
        args += ["--env=CCACHE_DISABLE=1"]
    args += [profile["image"], "-build-request", "/inputs/request.json"]
    return args


def read_cache_stats(work, enabled, warmup, elapsed):
    report = {
        "enabled": enabled,
        "build_seconds": round(elapsed, 3),
        "hits": 0,
        "misses": 0,
        "hit_rate": None,
    }
    if not enabled:
        return report
    try:
        log = read_guest(work, "ccache-stats.log", 32 * 1024 * 1024).decode("utf-8")
        counters = Counter(
            line.strip()
            for line in log.splitlines()
            if line.strip() and not line.startswith("#")
        )
        if any(not re.fullmatch(r"[a-z0-9_]+", name) for name in counters):
            raise ValueError("invalid ccache stats log")
        hits = counters["direct_cache_hit"] + counters["preprocessed_cache_hit"]
        misses = counters["cache_miss"]
        total = hits + misses
        report.update(
            hits=hits,
            misses=misses,
            hit_rate=round(hits / total, 6) if total else None,
            counters=dict(counters),
        )
        if not warmup:
            if total == 0:
                report["warning"] = (
                    "ccache 호출 통계가 없습니다. 컴파일러 경로·캐시 설정을 확인하세요."
                )
            elif hits / total < 0.7:
                report["warning"] = (
                    "ccache 적중률 "
                    + str(round(hits * 100 / total, 1))
                    + "% (70% 미만). 기준 캐시·컴파일 인자·용량을 확인하세요."
                )
    except (OSError, ValueError, UnicodeError) as error:
        report["warning"] = "ccache 통계 수집 실패: " + str(error)
    return report


def attempt(req, profile, worker, root, timeout, cache=None, warmup=False):
    response = None
    try:
        response, artifact = run_attempt(
            req, profile, worker, root, timeout, cache, warmup
        )
    finally:
        try:
            cleanup_container(root)
        except (Exception, KeyboardInterrupt) as error:
            # Keep the marker for recovery. An earlier result or exception still
            # explains why the build failed, and no module is exported without cleanup.
            message = "container cleanup failed: " + str(error)
            if response is None:
                print(message, file=sys.stderr, flush=True)
            else:
                response["cleanup_error"] = message
                log = response.get("log", "")
                response["log"] = f"{log}\n{message}" if log else message
                if response.get("success"):
                    response.update(success=False, kind="environment", error=message)
                    artifact = None
    return response, artifact


def run_attempt(req, profile, worker, root, timeout, cache, warmup):
    staged_at = time.monotonic()
    work = root / "work"
    kernel = req["kernel"]["kernel"]
    stage_inputs(req, worker, root, warmup)
    args = container_args(req, profile, root, cache, warmup)
    started = time.monotonic()
    try:
        run = run_limited(args, root, timeout)
        try:
            response = json.loads(read_guest(work, "result.json", 8 * 1024 * 1024))
        except (OSError, ValueError) as error:
            kind = (
                "preflight" if run.returncode in (125, 126, 127, 137) else "environment"
            )
            return {
                "success": False,
                "kind": kind,
                "error": "container exit "
                + str(run.returncode)
                + " before producing a valid response: "
                + str(error),
                "log": run.stdout + run.stderr,
            }, None
        if run.returncode and response.get("success"):
            raise ValueError(
                "container exited unsuccessfully despite a success response"
            )
        response["cache"] = read_cache_stats(
            work, cache is not None, warmup, time.monotonic() - started
        )
        response.setdefault("timings", {})["input_stage_seconds"] = round(
            started - staged_at, 3
        )
        print(
            "ccache 통계: " + json.dumps(response["cache"], ensure_ascii=False),
            flush=True,
        )
        artifact = (
            read_guest(work, "out/" + req["name"] + ".ko", 256 * 1024 * 1024)
            if response.get("success") and not warmup
            else None
        )
        return response, artifact
    except (subprocess.TimeoutExpired, BuildCancelled, DiskSpaceError) as error:
        message = (
            str(error)
            if isinstance(error, DiskSpaceError)
            else (
                "build timed out"
                if isinstance(error, subprocess.TimeoutExpired)
                else "build cancelled"
            )
        )
        return {
            "success": False,
            "kind": "disk_space" if isinstance(error, DiskSpaceError) else "environment",
            "error": message,
            "log": interrupted_logs(root, kernel),
            "cache": read_cache_stats(
                work, cache is not None, warmup, time.monotonic() - started
            ),
        }, None


def cache_identity(req, profile, worker=None):
    kernel = req["kernel"]["kernel"]
    return {
        "schema": 2,
        "kernel": kernel,
        "image": profile["image"],
        "build_tool": req["build_tool"],
        "config_sha256": sha(
            (Path(req["boot_dir"]) / ("config-" + kernel)).read_bytes()
        ),
    }


def cache_manifest(directory, max_bytes, hash_content=True):
    """Reject links/special files and optionally hash contents for a full audit."""
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("baseline cache is not a real directory")
    result = {}
    size = 0
    for parent, directories, files in os.walk(directory, followlinks=False):
        if any((Path(parent) / name).is_symlink() for name in directories):
            raise ValueError("symlink in baseline cache")
        for name in sorted(files):
            path = Path(parent) / name
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, "rb") as handle:
                info = os.fstat(handle.fileno())
                disk_bytes = max(info.st_size, info.st_blocks * 512)
                size += disk_bytes
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_nlink != 1
                    or size > max_bytes
                    or len(result) >= 1000000
                ):
                    raise ValueError("baseline cache is not a bounded regular tree")
                record = {
                    "size": info.st_size,
                    "disk_bytes": disk_bytes,
                    "mtime_ns": info.st_mtime_ns,
                    "ctime_ns": info.st_ctime_ns,
                    "inode": info.st_ino,
                    "device": info.st_dev,
                    "mode": stat.S_IMODE(info.st_mode),
                }
                if hash_content:
                    digest = hashlib.sha256()
                    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                        digest.update(chunk)
                    record["sha256"] = digest.hexdigest()
                result[str(path.relative_to(directory))] = record
    return result


def seal_cache(directory):
    for parent, directories, files in os.walk(
        directory, topdown=False, followlinks=False
    ):
        for name in files:
            os.chmod(Path(parent) / name, 0o400, follow_symlinks=False)
        for name in directories:
            os.chmod(Path(parent) / name, 0o500, follow_symlinks=False)
    directory.chmod(0o500)


def verify_cache(entry, maximum, full=False):
    sealed = json.loads((entry / "sealed.json").read_text())
    if sealed.get("inputs", {}).get("schema") != 2:
        raise ValueError("old baseline cache format; prepare a new cache")
    state_path = entry / "state.json"
    state = json.loads(state_path.read_text()) if state_path.is_file() else {}
    full = full or time.time() - state.get("verified_at", 0) >= 86400
    actual = cache_manifest(entry / "ccache", maximum, hash_content=full)
    expected = sealed["files"]
    if not full:
        expected = {
            name: {key: value for key, value in record.items() if key != "sha256"}
            for name, record in expected.items()
        }
    if actual != expected:
        raise ValueError(
            "sealed baseline cache changed; review and explicitly remove the cache"
        )
    state["last_used_at"] = time.time()
    if full:
        state["verified_at"] = time.time()
    atomic(state_path, state)
    return sealed


def cache_room(
    caches, profile, active, keep=None, reserve=0, wanted=None,
    min_free_bytes=0, space_path=None,
):
    """LRU inactive kernels first. Avoid repeatedly rebuilding active caches."""
    policy = caches / ".policy.json"
    requested = profile["cache"].get("total_gib", max(40, profile["cache"]["max_gib"]))
    if not policy.exists():
        atomic(policy, {"total_gib": requested})
    if policy.is_symlink():
        raise ValueError("cache policy cannot be a symlink")
    total_gib = json.loads(policy.read_text())["total_gib"]
    if not isinstance(total_gib, int) or not 1 <= total_gib <= 4096:
        raise ValueError("invalid shared cache budget")
    budget = total_gib * 1024**3
    entries = []
    for entry in caches.iterdir():
        if entry == policy:
            continue
        if (
            entry.is_symlink()
            or not entry.is_dir()
            or not re.fullmatch(r"[0-9a-f]{64}", entry.name)
        ):
            raise ValueError("invalid baseline cache directory")
        if not (entry / "sealed.json").is_file():
            remove_worktree(entry)
            continue
        sealed = json.loads((entry / "sealed.json").read_text())
        files = cache_manifest(entry / "ccache", budget * 2, hash_content=False)
        size = sum(record["disk_bytes"] for record in files.values())
        state = (
            json.loads((entry / "state.json").read_text())
            if (entry / "state.json").is_file()
            else {}
        )
        inputs = sealed.get("inputs", {})
        current = inputs.get("schema") == 2 and inputs.get("kernel") in active
        if wanted and inputs.get("kernel") == wanted["kernel"] and inputs != wanted:
            current = False
        entries.append((current, state.get("last_used_at", 0), entry, size))
    used = sum(item[3] for item in entries)
    def pressure():
        return min_free_bytes and shutil.disk_usage(space_path).free < min_free_bytes

    for current, _, entry, size in sorted(entries, key=lambda item: (item[0], item[1])):
        low_space = pressure()
        if used + reserve <= budget and not low_space:
            return True
        if entry.name == keep or (current and used <= budget and not low_space):
            continue
        print("비활성 기준 캐시 LRU 정리: " + entry.name[:16], flush=True)
        remove_worktree(entry)
        used -= size
    return used + reserve <= budget and not pressure()


def prepare_cache(args, path, profile, req, state, deadline, logs):
    maximum = profile.get("cache", {}).get("max_gib", 0)
    if not maximum:
        return None, {"enabled": False}
    inputs = cache_identity(req, profile)
    key = sha(json.dumps(inputs, sort_keys=True).encode())
    caches = Path(profile["cache"].get("directory", path.parent / "cache"))
    if not caches.is_absolute() or caches.is_symlink():
        raise ValueError("invalid shared cache directory")
    caches.mkdir(mode=0o700, exist_ok=True)
    entry = caches / key
    if entry.is_symlink():
        raise ValueError("baseline cache entry cannot be a symlink")
    active = set(getattr(args, "active_kernel", [])) | {req["kernel"]["kernel"]}
    started = time.monotonic()
    if entry.is_dir() and (entry / "sealed.json").is_file():
        sealed = verify_cache(entry, maximum * 1024**3)
        if sealed["inputs"] != inputs:
            raise ValueError("sealed baseline cache identity mismatch")
        if not cache_room(caches, profile, active, keep=key, wanted=inputs):
            remove_worktree(entry)
            cache_room(caches, profile, active)
            return None, {
                "enabled": False,
                "warning": "활성 커널의 기준 캐시가 전체 용량 한도를 초과했습니다. cache.total_gib를 늘리세요.",
            }
        print("검증한 기준 ccache를 읽기 전용으로 사용: " + key[:16], flush=True)
        return entry / "ccache", {
            "key": key,
            "warmup": False,
            "files": len(sealed["files"]),
            "baseline_stats": sealed.get("baseline_stats", {}),
            "baseline_timings": sealed.get("baseline_timings", {}),
            "baseline_seconds": sealed.get("baseline_stats", {}).get(
                "build_seconds", 0
            ),
            "verification_seconds": round(time.monotonic() - started, 3),
        }
    if not cache_room(
        caches, profile, active, reserve=maximum * 1024**3, wanted=inputs
    ):
        warning = "활성 커널 기준 캐시 보관 공간이 부족해 추가 기준 빌드 없이 일반 빌드합니다. cache.total_gib를 늘리세요."
        print(warning, flush=True)
        return None, {"enabled": False, "warning": warning}
    try:
        require_space(
            path.parent,
            profile.get("limits", {}).get("disk_free_mib", 61440) + maximum * 2048,
        )
    except DiskSpaceError:
        # A pressure eviction must not immediately recreate the same large
        # cache. The normal build still enforces its own minimum free space.
        warning = "기준 캐시 재생성 공간이 부족해 추가 기준 빌드 없이 일반 빌드합니다."
        print(warning, flush=True)
        return None, {"enabled": False, "warning": warning}
    entry.mkdir(mode=0o700)
    cache = entry / "ccache"
    cache.mkdir(mode=0o700)
    root = Path(tempfile.mkdtemp(prefix="attempt-", dir=state))
    print("패치를 적용하지 않은 기준 빌드로 ccache 준비: " + key[:16], flush=True)
    published = False
    try:
        baseline = dict(req, patch_files=[])
        response, _ = attempt(
            baseline,
            profile,
            args.worker,
            root,
            max(1, deadline - time.monotonic()),
            cache=cache,
            warmup=True,
        )
        logs.append(response.get("log", ""))
        if not response.get("success"):
            if response.get("kind") == "disk_space":
                raise DiskSpaceError(response["error"])
            raise ValueError(
                "baseline cache build failed: " + response.get("error", "unknown error")
            )
        files = cache_manifest(cache, maximum * 1024**3)
        if not any(name.endswith("R") for name in files):
            raise ValueError("baseline compiler did not populate ccache")
        seal_cache(cache)
        sealed_files = cache_manifest(cache, maximum * 1024**3, hash_content=False)
        for name, record in sealed_files.items():
            record["sha256"] = files[name]["sha256"]
        atomic(
            entry / "sealed.json",
            {
                "inputs": inputs,
                "files": sealed_files,
                "origin": {
                    "base_commit": req["base_commit"],
                    "worker_sha256": sha(Path(args.worker).read_bytes()),
                    "recipe_sha256": profile["recipe_sha256"],
                },
                "baseline_stats": response.get("cache", {}),
                "baseline_timings": response.get("timings", {}),
            },
        )
        atomic(
            entry / "state.json",
            {"last_used_at": time.time(), "verified_at": time.time()},
        )
        published = True
        return cache, {
            "key": key,
            "warmup": True,
            "files": len(files),
            "baseline_seconds": response.get("cache", {}).get(
                "build_seconds", round(time.monotonic() - started, 3)
            ),
            "baseline_stats": response.get("cache", {}),
            "baseline_timings": response.get("timings", {}),
        }
    finally:
        if not (root / "container-name").exists():
            remove_worktree(root)
        if not published and not (root / "container-name").exists():
            remove_worktree(entry)


def run_build(args):
    engine()
    path, profile = load_profile(args.profile)
    actual_limits = require_limits(profile)
    req = json.loads(Path(args.request).read_text())
    if set(req) != REQUEST_KEYS or set(req["kernel"]) != KERNEL_KEYS:
        raise ValueError("worker request must contain build inputs only")
    if (
        not KERNEL.fullmatch(req["kernel"]["kernel"])
        or not MODULE.fullmatch(req["name"])
        or not COMMIT.fullmatch(req["base_commit"])
    ):
        raise ValueError("invalid build target")
    if not 1 <= req["timeout_minutes"] <= 1440 or req["jobs"] < 0:
        raise ValueError("invalid build limits")
    out = Path(req["out_dir"]).resolve()
    out.mkdir(parents=True, exist_ok=True)
    try:
        with user_build_lock(), profile_lock(path):
            return run_locked(args, path, profile, req, out, actual_limits)
    except BuildBusy as error:
        atomic(
            out / "environment-result.json",
            {"success": False, "kind": "busy", "error": str(error), "log": ""},
        )
        return 1


def manage_cache(args):
    engine()
    path, profile = load_profile(args.profile, verify_image=False)
    caches = Path(profile.get("cache", {}).get("directory", path.parent / "cache"))
    if not caches.is_absolute() or caches.is_symlink():
        raise ValueError("invalid shared cache directory")
    caches.mkdir(mode=0o700, exist_ok=True)
    with user_build_lock(), profile_lock(path):
        if args.action == "cache-budget":
            if (
                not max(1, profile.get("cache", {}).get("max_gib", 0))
                <= args.total_gib
                <= 4096
            ):
                raise ValueError(
                    "shared budget must cover one configured baseline cache"
                )
            atomic(caches / ".policy.json", {"total_gib": args.total_gib})
            if not cache_room(caches, profile, set()):
                raise ValueError("cannot enforce shared cache budget")
            print(json.dumps({"total_gib": args.total_gib, "directory": str(caches)}))
        else:
            count = 0
            maximum = 4096 * 1024**3
            for entry in caches.iterdir():
                if entry.name == ".policy.json":
                    continue
                if (
                    entry.is_symlink()
                    or not entry.is_dir()
                    or not re.fullmatch(r"[0-9a-f]{64}", entry.name)
                ):
                    raise ValueError("invalid baseline cache directory")
                verify_cache(entry, maximum, full=args.full)
                count += 1
            print(json.dumps({"verified": count, "full_audit": args.full}))


def run_locked(args, path, profile, req, out, actual_limits):
    touch_profile(path.parent)
    records = []
    logs = []
    # The one-time unpatched baseline (ccache warm-up) and the real build each
    # get the full limit. Sharing one deadline left a cold first build about an
    # hour for klp-build after a two-hour baseline, so it never finished
    # (2026-11-23: baseline 2h06m, then cancelled; warm rerun finished in 72m).
    budget = req["timeout_minutes"] * 60
    deadline = time.monotonic() + budget
    state = path.parent / "runs"
    state.mkdir(mode=0o700, exist_ok=True)
    # Recover only this profile's own interrupted attempts, before starting work.
    for stale in state.glob("attempt-*"):
        if stale.is_symlink() or not stale.is_dir():
            raise ValueError("invalid old attempt directory")
        cleanup_container(stale)
        remove_worktree(stale)
    response = {
        "success": False,
        "kind": "environment",
        "error": "build did not start",
        "log": "",
    }
    cache_info = {"enabled": False}
    try:
        require_space(
            path.parent, profile.get("limits", {}).get("disk_free_mib", 61440)
        )
        cache, cache_info = prepare_cache(
            args, path, profile, req, state, deadline, logs
        )
        if cache_info.get("warmup"):
            deadline = time.monotonic() + budget
        for index in range(2 if args.retry_clean else 1):
            require_space(
                path.parent, profile.get("limits", {}).get("disk_free_mib", 61440)
            )
            if index:
                print(
                    "환경 오류: 같은 고정 이미지와 새 빈 작업 공간으로 1회 재시도 (ccache 비활성)",
                    flush=True,
                )
            root = Path(tempfile.mkdtemp(prefix="attempt-", dir=state))
            print(
                "격리 빌드 시도 "
                + str(index + 1)
                + ": "
                + req["kernel"]["kernel"]
                + " · 이미지 "
                + profile["image"],
                flush=True,
            )
            record = {
                "attempt": index + 1,
                "image": profile["image"],
                "kind": "interrupted",
                "success": False,
                "clean_retry": bool(index),
            }
            records.append(record)
            try:
                options = {"cache": cache} if cache is not None and not index else {}
                response, artifact = attempt(
                    req,
                    profile,
                    args.worker,
                    root,
                    max(1, deadline - time.monotonic()),
                    **options
                )
                record.update(
                    kind=response.get("kind"), success=response.get("success")
                )
                record["cache"] = response.get("cache", {})
                record["timings"] = response.get("timings", {})
                logs.append(response.get("log", ""))
                if response.get("success"):
                    target = out / (req["name"] + ".ko")
                    temporary = target.with_suffix(".ko.tmp")
                    temporary.write_bytes(artifact)
                    os.replace(temporary, target)
                    break
                if not retryable(response):
                    break
            finally:
                if not (root / "container-name").exists():
                    remove_worktree(root)
    except (Exception, KeyboardInterrupt) as error:
        response = {
            "success": False,
            "kind": "disk_space" if disk_space_error(error) else "environment",
            "error": str(error),
            "log": "",
        }
    metrics = response.setdefault(
        "cache", {"enabled": False, "hits": 0, "misses": 0, "hit_rate": None}
    )
    metrics.update(kernel=req["kernel"]["kernel"])
    baseline = cache_info.get("baseline_stats", {})
    expected_calls = baseline.get("hits", 0) + baseline.get("misses", 0)
    calls = metrics.get("hits", 0) + metrics.get("misses", 0)
    if metrics.get("enabled") and expected_calls >= 100 and calls < expected_calls // 2:
        metrics["warning"] = (
            "ccache 적용 컴파일 수가 기준 빌드보다 크게 줄었습니다. 컴파일러 경로를 확인하세요."
        )
    for field in ("key", "baseline_seconds", "verification_seconds", "warning"):
        if field in cache_info:
            metrics[field] = cache_info[field]
    provenance = {
        "schema": 1,
        "kernel": req["kernel"]["kernel"],
        "base_commit": req["base_commit"],
        "worker_sha256": sha(Path(args.worker).read_bytes()),
        "packages_sha256": profile["packages_sha256"],
        "recipe_sha256": profile["recipe_sha256"],
        "build_tool": req["build_tool"],
        "jobs": req["jobs"],
        "effective_limits": actual_limits,
        "attempts": records,
        "cache": cache_info,
    }
    evidence = path.parent / "evidence"
    evidence.mkdir(mode=0o700, exist_ok=True)
    atomic(evidence / (uuid.uuid4().hex + ".json"), provenance)
    response["log"] = (
        "\n".join(logs)
        + "\n격리 환경: "
        + json.dumps(provenance, ensure_ascii=False)
        + "\nccache 측정: "
        + json.dumps(metrics, ensure_ascii=False)
        + "\n"
    )
    atomic(out / "environment-result.json", response)
    return 0 if response.get("success") else 1


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    p = sub.add_parser("prepare")
    directories = p.add_mutually_exclusive_group(required=True)
    directories.add_argument("--directory")
    directories.add_argument("--profiles-dir")
    p.add_argument("--kernel", required=True)
    p.add_argument("--base-image", required=True)
    p.add_argument("--kpatch-source")
    p.add_argument("--sources")
    p.add_argument("--package", action="append", default=[])
    p.add_argument("--memory-mib", type=int, required=True)
    p.add_argument("--pids", type=int, default=4096)
    p.add_argument("--min-free-gib", type=int, default=60)
    p.add_argument("--cache-gib", type=int, default=20)
    p.add_argument("--cache-total-gib", type=int, default=40)
    p.add_argument("--snapshot", default="auto")
    p.add_argument("--allow-live-fallback", action="store_true",
                   help="allow the base image's signed Ubuntu archive for this preparation after transient snapshot HTTP errors")
    p.add_argument("--snapshot-timeout-minutes", type=int, default=SNAPSHOT_TIMEOUT_MINUTES,
                   help="maximum minutes per signed snapshot probe (default: %(default)s)")
    p.add_argument("--git-dir")
    p.add_argument("--base-tag")
    p.add_argument(
        "--image-timeout-minutes", type=int, default=IMAGE_BUILD_TIMEOUT_MINUTES
    )
    p = sub.add_parser("rebuild")
    p.add_argument("--profile", required=True)
    p.add_argument(
        "--image-timeout-minutes", type=int, default=IMAGE_BUILD_TIMEOUT_MINUTES
    )
    p = sub.add_parser("purge-kernel")
    p.add_argument("--kernel", required=True)
    p.add_argument("--profile")
    p.add_argument("--profiles-dir")
    p = sub.add_parser("kernel-inventory")
    p.add_argument("--profile")
    p.add_argument("--profiles-dir")
    p = sub.add_parser("gc")
    p.add_argument("--profiles-dir", required=True)
    p.add_argument("--inventory-complete", action="store_true")
    p.add_argument("--active-kernel", action="append", default=[])
    p.add_argument("--retention-days", type=int, default=14)
    p.add_argument("--min-free-gib", type=int, default=0)
    p.add_argument("--work-dir")
    p = sub.add_parser("run")
    p.add_argument("--profile", required=True)
    p.add_argument("--request", required=True)
    p.add_argument("--worker", required=True)
    p.add_argument("--retry-clean", action="store_true")
    p.add_argument("--active-kernel", action="append", default=[])
    p = sub.add_parser("cache-budget")
    p.add_argument("--profile", required=True)
    p.add_argument("--total-gib", type=int, required=True)
    p = sub.add_parser("verify-cache")
    p.add_argument("--profile", required=True)
    p.add_argument("--full", action="store_true")
    return parser.parse_args()


def main():
    args = parse_args()

    def interrupted(signum, frame):
        raise BuildCancelled("build cancelled")

    signal.signal(signal.SIGTERM, interrupted)
    if args.action == "prepare":
        if args.allow_live_fallback and (args.snapshot != "auto" or args.sources):
            raise ValueError("--allow-live-fallback requires --snapshot auto and default Ubuntu sources")
        if not 1 <= args.snapshot_timeout_minutes <= 1440:
            raise ValueError("--snapshot-timeout-minutes must be between 1 and 1440")
        if (
            not 1024 <= args.memory_mib <= 1048576
            or not 128 <= args.pids <= 32768
            or not 8 <= args.min_free_gib <= 65536
            or not 0 <= args.cache_gib <= 1024
            or not args.cache_gib <= args.cache_total_gib <= 4096
            or not 10 <= args.image_timeout_minutes <= 1440
        ):
            raise ValueError("invalid memory/pid limits")
        prepare(args)
    elif args.action == "rebuild":
        engine()
        with user_build_lock(), profile_lock(args.profile):
            rebuild(args.profile, args.image_timeout_minutes)
    elif args.action in ("cache-budget", "verify-cache"):
        manage_cache(args)
    elif args.action in ("purge-kernel", "kernel-inventory"):
        purge_kernel(args)
    elif args.action == "gc":
        engine()
        collect_environments(args)
    else:
        return run_build(args)
    return 0


def cli():
    try:
        return main()
    except BuildBusy as error:
        print("격리 빌드 환경 사용 중: " + str(error), file=sys.stderr)
        return os.EX_TEMPFAIL
    except ArchiveUnavailable as error:
        print("APT 저장소 일시 장애: " + str(error), file=sys.stderr)
        return os.EX_UNAVAILABLE
    except subprocess.CalledProcessError as error:
        detail = (error.stderr or error.stdout or "").strip()
        if isinstance(detail, bytes):
            detail = detail.decode(errors="replace")
        print(f"{error.cmd[0]} 종료 코드 {error.returncode}\n{detail[-3000:]}", file=sys.stderr)
        return 1
    except Exception as error:
        if disk_space_error(error):
            print("빌드 디스크 공간 부족: " + str(error), file=sys.stderr)
            return os.EX_CANTCREAT
        print("격리 빌드 환경 오류: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(cli())
