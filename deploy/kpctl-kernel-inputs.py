#!/usr/bin/env python3
"""Fetch pinned kernel packages from the controller for the root debug helper."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import ssl
import stat
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request


LIMIT = 16 << 30
CONFIG = "/etc/kpctl/builder.json"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise RuntimeError("컨트롤러 입력 다운로드의 리디렉션을 거부했습니다")


def load_connection(path=CONFIG):
    info = os.stat(path)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise RuntimeError("컨트롤러 접속 설정은 root 소유이며 그룹·다른 사용자가 쓸 수 없어야 합니다")
    config = json.loads(Path(path).read_text())
    url = config.get("controller_url", "").rstrip("/")
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.query or parsed.fragment):
        raise RuntimeError("컨트롤러 입력 전달에는 HTTPS controller_url이 필요합니다")
    token = config.get("token", "")
    if not isinstance(token, str) or not token or "\n" in token or "\r" in token:
        raise RuntimeError("빌더 인증 토큰이 올바르지 않습니다")
    context = ssl.create_default_context(cafile=config.get("ca_file") or None)
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context), NoRedirect()
    )
    return url, token, opener


def fetch_file(opener, url, token, directory, filename, package, version, arch):
    path = directory / filename
    temporary = path.with_name(path.name + ".partial")
    request = urllib.request.Request(url, headers={"Authorization": "Bearer " + token})
    try:
        # The controller may need to fill its cache before sending headers.
        with opener.open(request, timeout=35 * 60) as response:
            size_text = response.headers.get("Content-Length", "")
            digest = response.headers.get("X-Checksum-Sha256", "")
            if not re.fullmatch(r"[0-9]+", size_text) or not 0 < int(size_text) <= LIMIT:
                raise RuntimeError("컨트롤러 파일 크기 정보가 올바르지 않습니다: " + filename)
            if not re.fullmatch(r"[0-9a-f]{64}", digest):
                raise RuntimeError("컨트롤러 파일 SHA-256 정보가 없습니다: " + filename)
            expected = int(size_text)
            total, checksum = 0, hashlib.sha256()
            with temporary.open("xb") as output:
                while True:
                    chunk = response.read(1 << 20)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > expected:
                        raise RuntimeError("컨트롤러 파일 크기 초과: " + filename)
                    checksum.update(chunk)
                    output.write(chunk)
                output.flush()
                os.fsync(output.fileno())
            if total != expected or checksum.hexdigest() != digest:
                raise RuntimeError("컨트롤러 파일 크기·SHA-256 불일치: " + filename)
        output = subprocess.check_output(
            ["dpkg-deb", "--field", str(temporary), "Package", "Version", "Architecture"], text=True
        )
        fields = dict(line.split(": ", 1) for line in output.splitlines() if ": " in line)
        if (fields.get("Package"), fields.get("Version"), fields.get("Architecture")) != (package, version, arch):
            raise RuntimeError("입력 패키지 이름·버전·아키텍처 불일치: " + filename)
        os.replace(temporary, path)
        return path
    finally:
        temporary.unlink(missing_ok=True)


def download_inputs(kernel, version, arch, directory, image, connection, keep_image=False):
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+-[0-9]+-generic", kernel):
        raise RuntimeError("커널 이름이 올바르지 않습니다")
    abi = kernel.removesuffix("-generic")
    if not re.fullmatch(re.escape(abi) + r"\.[0-9]+", version) or arch not in ("amd64", "arm64"):
        raise RuntimeError("커널 패키지 버전·아키텍처가 올바르지 않습니다")
    signed, unsigned = "linux-image-" + kernel, "linux-image-unsigned-" + kernel
    if image not in (signed, unsigned):
        raise RuntimeError("커널 이미지 패키지가 올바르지 않습니다")
    url, token, opener = connection
    base = f"{url}/api/builder/kernel-inputs/{kernel}/{version}/{arch}/"

    def fetch(package, architecture=arch, extension="deb"):
        filename = f"{package}_{version}_{architecture}.{extension}"
        print("  컨트롤러에서 받음: " + filename, file=sys.stderr)
        return fetch_file(opener, base + filename, token, directory, filename, package, version, architecture)

    def choose(packages, extension="deb"):
        for index, package in enumerate(packages):
            try:
                return fetch(package, extension=extension)
            except urllib.error.HTTPError as error:
                error.close()
                if error.code != 404 or index == len(packages) - 1:
                    raise
        raise RuntimeError("정식 커널 입력 패키지가 없습니다")

    images = [image, unsigned] if image == signed and not keep_image else [image]
    return [
        choose(images), fetch("linux-modules-" + kernel), fetch("linux-headers-" + kernel),
        fetch("linux-headers-" + abi, "all"),
        choose([unsigned + "-dbgsym", signed + "-dbgsym"], "ddeb"),
    ]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kernel")
    parser.add_argument("version")
    parser.add_argument("directory", type=Path)
    parser.add_argument("image")
    parser.add_argument("--keep-image", action="store_true")
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise RuntimeError("root 도우미에서 실행해야 합니다")
    info = args.directory.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
        raise RuntimeError("다운로드 디렉터리는 root 전용이어야 합니다")
    arch = subprocess.check_output(["dpkg", "--print-architecture"], text=True).strip()
    paths = download_inputs(args.kernel, args.version, arch, args.directory, args.image, load_connection(), args.keep_image)
    for path in paths:
        print(path)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print("컨트롤러 커널 입력 전달 실패: " + str(error), file=sys.stderr)
        sys.exit(3)
