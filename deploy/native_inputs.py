"""Verify and unpack one official AMD64 distribution kernel in a private directory."""
import base64
import datetime
import email.utils
import hashlib
import lzma
import os
from pathlib import Path
import re
import shutil
import ssl
import subprocess
import sys
import tempfile
import urllib.request

SALSA = "https://salsa.debian.org/kernel-team/linux.git"
ROCKY = "https://git.rockylinux.org/staging/rpms/kernel.git"
DEBIAN = {"12": ("bookworm", "6.1"), "13": ("trixie", "6.12")}
KEYS = {
    "bookworm": {"B8B80B5B623EAB6AD8775C45B7C5D7D6350947F8", "4D64FEC119C2029067D6E791F8D2585B8783D481"},
    "bookworm-security": {"05AB90340C0C5E797F44A8C8254CF3B5AEC0A8F0"},
    "trixie": {"04B54C3CDCA79751B16BC6B5225629DF75B188BD", "41587F7DB8C774BCCF131416762F67A0B2C39DE4"},
    "trixie-security": {"5E04A1E3223A19A20706E20F9904613D4CCE68C6"},
    "9": {"21CB256AE16FC54C6E652949702D426D350D275D"},
    "10": {"FC226859C0860BF0DDB95B085B106C736FEDFC85"},
}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def run(*args, cwd=None):
    return subprocess.check_output(args, cwd=cwd, env={**os.environ, "LC_ALL": "C"}).decode().strip()


def digest(path):
    with path.open("rb") as f:
        h = hashlib.sha256()
        while block := f.read(1024 * 1024):
            h.update(block)
        return h.hexdigest()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        raise ValueError("unexpected archive redirect")


class Archive:
    def __init__(self, cache, root, fetch):
        self.cache, self.root, self.fetch = cache, root, fetch

    def entry(self, name):
        require(re.fullmatch(r"[\w+~./-]+", name) and not name.startswith("/") and ".." not in name, "invalid archive path")
        return self.cache / name

    def authenticated(self, name, verify):
        """Publish the initial download or its replacement only after authentication."""
        path = self.entry(name)
        if path.exists():
            try:
                return path, verify(path)
            except (ValueError, OSError, subprocess.SubprocessError) as err:
                if not self.fetch:
                    raise ValueError(f"{name}: {err}; retry with --fetch or a fresh --cache generation") from err
        require(self.fetch, f"missing signed archive input: {path}; use --fetch or populate a fresh --cache generation")
        path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=path.parent) as tmp:
            try:
                fresh = Archive(Path(tmp), self.root, True).file(name)
                result = verify(fresh)
            except (ValueError, OSError, subprocess.SubprocessError) as err:
                raise ValueError(f"{name}: fresh archive input rejected: {err}; check the official archive and --cache generation") from err
            os.replace(fresh, path)
            return path, result

    def file(self, name, checksum=None):
        path = self.entry(name)
        if not path.exists() or checksum and self.fetch and digest(path) != checksum:
            require(self.fetch, f"missing signed archive input: {path}")
            path.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as f:
                try:
                    with urllib.request.build_opener(NoRedirect).open(f"{self.root}/{name}", timeout=90) as stream:
                        shutil.copyfileobj(stream, f)
                    f.close()
                    if checksum:
                        require(digest(Path(f.name)) == checksum, f"SHA256 mismatch: {name}; check --cache generation and retry with --fetch")
                    os.replace(f.name, path)
                finally:
                    Path(f.name).unlink(missing_ok=True)
        if checksum:
            require(digest(path) == checksum, f"SHA256 mismatch: {name}; check --cache generation and retry with --fetch")
        return path


def paragraphs(text):
    for chunk in text.strip().split("\n\n"):
        fields = {}
        for line in chunk.splitlines():
            if line.startswith((" ", "\t")):
                fields[key] += "\n" + line.strip()
            elif ": " in line or line.endswith(":"):
                key, value = line.split(":", 1)
                require(key not in fields, "duplicate control field " + key)
                fields[key] = value.strip()
        yield fields


def one(items, description):
    matches = list(items)
    require(len(matches) == 1, f"expected one {description}, found {len(matches)}")
    return matches[0]


def git(plan, *args):
    # Keep partial clones offline too. Missing objects must be fetched explicitly
    # into the trusted checkout before starting a package preparation.
    env = {**os.environ, "LC_ALL": "C", "GIT_ALLOW_PROTOCOL": "", "GIT_NO_LAZY_FETCH": "1", "GIT_TERMINAL_PROMPT": "0"}
    return subprocess.check_output(["git", "--no-replace-objects", "-C", plan["git"], *args], env=env).decode().strip()


def pin(plan, remote, branch, tag):
    rev = plan["revision"]
    require(re.fullmatch("[a-f0-9]{40}", rev), "need immutable packaging commit")
    require(git(plan, "remote", "get-url", "origin") == remote, "wrong packaging Git origin")
    require(git(plan, "rev-parse", f"refs/tags/{tag}^{{commit}}") == rev, "release tag revision mismatch")
    git(plan, "merge-base", "--is-ancestor", rev, "refs/remotes/origin/" + branch)


def signed_indices(plan, archive, suite, work):
    def metadata(release):
        verified = work / "Release"
        verified.unlink(missing_ok=True)
        status = run("gpgv", "--keyring", Path(plan["keyring"]).resolve(), "--status-fd", "1", "--output", verified, release)
        fprs = {line.split()[-1] for line in status.splitlines() if line.startswith("[GNUPG:] VALIDSIG ")}
        signer = one(sorted(fprs & KEYS[suite])[:1], "Debian suite signing fingerprint")
        meta = next(paragraphs(verified.read_text()))
        require(meta["Codename"] == suite and meta["Origin"] == "Debian", "wrong signed release")
        require(not suite.endswith("-security") or "Valid-Until" in meta, "signed security Release lacks expiration")
        if "Valid-Until" in meta:
            require(email.utils.parsedate_to_datetime(meta["Valid-Until"]) >= datetime.datetime.now(datetime.timezone.utc), "signed Release expired")
        hashes = {p: h for h, _, p in (line.split() for line in meta["SHA256"].splitlines() if line)}
        return signer, hashes
    _, (signer, hashes) = archive.authenticated(f"dists/{suite}/InRelease", metadata)
    indices = []
    for path in ("main/binary-amd64/Packages.xz", "main/source/Sources.xz"):
        data = archive.file(f"dists/{suite}/{path}", hashes[path])
        indices.append(lzma.open(data, "rt", encoding="utf8").read())
    return signer, indices


def git_blob(path):
    data = path.read_bytes()
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def extract_deb(plan, work, cache, fetch, source_only):
    suite, line = DEBIAN[plan["release"]]
    require(plan["suite"] in (suite, suite + "-security"), "unsupported Debian suite")
    suite = plan["suite"]
    version, abi, rev = plan["version"], plan["abi"], plan["revision"]
    security = suite.endswith("-security")
    archive = Archive(cache / suite, "https://security.debian.org/debian-security" if security else "https://deb.debian.org/debian", fetch)
    pin(plan, SALSA, f"debian/{line}/{suite}", "debian/" + version.replace("~", "_"))
    signer, (packages, sources) = signed_indices(plan, archive, suite, work)
    source = one((p for p in paragraphs(sources) if p.get("Package") == "linux" and p["Version"] == version), "signed linux source")
    require(source["Format"] == "3.0 (quilt)", "unsupported source package format")
    files = []
    for row in source["Checksums-Sha256"].strip().splitlines():
        sha, size, name = row.split()
        files.append(archive.file(source["Directory"] + "/" + name, sha))
    dsc = one((p for p in files if p.suffix == ".dsc"), "DSC")
    tree = work / "source"
    subprocess.run(["dpkg-source", "-x", dsc, tree], check=True, stdout=subprocess.DEVNULL)
    tracked = set()
    for row in git(plan, "ls-tree", "-r", rev, "debian/patches", "debian/changelog").splitlines():
        mode, kind, blob, path = row.split(None, 3)
        tracked.add(path)
        require(mode in ("100644", "100755") and not (tree / path).is_symlink()
                and git_blob(tree / path) == blob, f"DSC and Git differ: {path}")
    shipped = {"debian/changelog"} | {str(p.relative_to(tree)) for p in (tree/"debian/patches").rglob("*") if p.is_file()}
    require(shipped == tracked, "DSC patch inventory differs from Git")
    require((tree / ".pc/applied-patches").is_file(), "quilt patches not applied")
    needed = {"linux-image-" + abi, "linux-headers-" + abi, "linux-image-" + abi + "-dbg"}
    entries = {name: [] for name in needed}
    for p in paragraphs(packages):
        if p.get("Package") in needed and p["Version"] == version and p["Architecture"] == "amd64":
            entries[p["Package"]].append(p)
    image = one(entries["linux-image-" + abi], "signed image index entry")
    require(image.get("Built-Using") == f"linux (= {version})" and image["Source"].split()[0] == "linux-signed-amd64", "signed image does not refer to selected linux source")
    proof = {"source_sha256": digest(dsc), "package_sha256": image["SHA256"], "signer": signer}
    if source_only:
        return tree, proof
    root = work / "packages"
    for name, rows in entries.items():
        p = one(rows, name)
        if name != image["Package"]:
            require(p["Source"].split()[0] == "linux", f"{name} source mismatch")
        pkg = archive.file(p["Filename"], p["SHA256"])
        subprocess.run(["dpkg-deb", "-x", pkg, root], check=True)
    debug = one(root.glob(f"usr/lib/debug/boot/vmlinux-{abi}"), "Debian vmlinux")
    headers = root / "usr/src" / ("linux-headers-" + abi)
    return tree, proof, root, debug, headers / ".config", headers / "Module.symvers"


ARMOR = re.compile(r"-----BEGIN PGP PUBLIC KEY BLOCK-----[^\n]*\n(.*?)-----END PGP PUBLIC KEY BLOCK-----", re.S)


def dearmor(text):
    """Binary OpenPGP data of every ASCII-armored public key block (RFC 9580 §6.2).

    The CRC24 footer is optional and must not cause rejection (RFC 9580 §6.1); key
    fingerprints are pinned, so integrity does not depend on it.
    """
    blocks = []
    for body in ARMOR.findall(text):
        lines = [line.strip() for line in body.splitlines()]
        if "" in lines and all(":" in line for line in lines[:lines.index("")]):
            lines = lines[lines.index("") + 1:]
        while lines and not lines[-1]:
            lines.pop()
        if lines and re.fullmatch(r"=[A-Za-z0-9+/]{4}", lines[-1]):
            lines.pop()  # CRC24 footer; "==" padding on its own line stays data
        data = re.sub(r"\s+", "", "".join(lines))
        blocks.append(base64.b64decode(data, validate=True))
    return blocks


def openpgp_packets(data):
    i = 0
    def take(n):
        require(i + n <= len(data), "truncated OpenPGP packet header")
        return data[i:i + n]
    while i < len(data):
        head = data[i]
        require(head & 0x80, "invalid OpenPGP packet header")
        if head & 0x40:
            tag = head & 0x3F
            i += 1
            first = take(1)[0]
            if first < 192:
                size, i = first, i + 1
            elif first < 224:
                size, i = ((first - 192) << 8) + take(2)[1] + 192, i + 2
            else:
                require(first == 255, "partial-length packet in a public key")
                size, i = int.from_bytes(take(5)[1:], "big"), i + 5
        else:
            tag, kind = (head >> 2) & 0x0F, head & 3
            require(kind != 3, "indeterminate-length packet in a public key")
            width = (1, 2, 4)[kind]
            i += 1
            size, i = int.from_bytes(take(width), "big"), i + width
        body = data[i:i + size]
        require(len(body) == size, "truncated OpenPGP packet")
        yield tag, body
        i += size


def key_fingerprint(body):
    # v4: SHA-1 over 0x99 + 2-octet length; v5/v6: SHA-256 over 0x9A/0x9B + 4-octet length (RFC 9580 §5.5.4).
    version = body[0]
    if version == 4:
        return 4, hashlib.sha1(b"\x99" + len(body).to_bytes(2, "big") + body).hexdigest().upper()
    if version in (5, 6):
        prefix = b"\x9a" if version == 5 else b"\x9b"
        return version, hashlib.sha256(prefix + len(body).to_bytes(4, "big") + body).hexdigest().upper()
    return version, ""


def key_id(version, fingerprint):
    # v4 key ID is the low 64 bits of the fingerprint, v5/v6 the high 64 bits (RFC 9580 §5.5.4).
    return fingerprint[-16:] if version == 4 else fingerprint[:16]


def openpgp_keys(path):
    """(version, fingerprint, primary) of every key in an armored or binary key file.

    GnuPG 2.4 rejects a whole file that contains an RFC 9580 v6 key, and Rocky 10.3
    ships its v4 release key next to a v6 key. RPM itself accepts both.
    """
    raw = Path(path).read_bytes()
    # Binary OpenPGP starts with a packet header (high bit set); anything else must be armor.
    blocks = [raw] if raw[:1] and raw[0] & 0x80 else dearmor(raw.decode("ascii", "replace"))
    keys = []
    for block in blocks:
        for tag, body in openpgp_packets(block):
            if tag in (6, 14):
                require(body, "empty OpenPGP key packet")
                keys.append((*key_fingerprint(body), tag == 6))
    require(keys, "no OpenPGP keys in " + str(path))
    return keys


def pinned_signer(path, pins):
    keys = openpgp_keys(path)
    return one((fpr for version, fpr, primary in keys if primary and version == 4 and fpr in pins), "pinned release signing key"), keys


RPM_RESULT = re.compile(r"\s+(.+): (OK|NOKEY)")
RPM_SIGNER = re.compile(r"(?i)signature,\s*key (id|fingerprint:?)\s*([0-9a-f]+)$")


def verify_rpm(path, db, signer, keys=()):
    """Valid RPM signature by the pinned v4 key and a valid SHA256 payload digest.

    The keyring can hold more keys than the pin (Rocky 10.3 adds a v6 key), so an OK
    signature from any imported key is not enough: one OK signature must name the
    pinned key, by its exact fingerprint or by a key ID that no other keyring key
    shares. Other signatures may only be OK or NOKEY (rpmkeys then exits 1 even
    though the pinned signature verified); any other result rejects the package.
    """
    proc = subprocess.run(["rpmkeys", "--dbpath", str(db), "--checksig", "--verbose", str(path)],
                          capture_output=True, env={**os.environ, "LC_ALL": "C"})
    # Every indented result line must be exactly "<check>: OK" or "<check>: NOKEY";
    # anything else (BAD, "BAD (Expected ...)", NOTTRUSTED, ...) rejects the package.
    lines = [line for line in proc.stdout.decode().splitlines() if line[:1].isspace() and line.strip()]
    matches = [(line, RPM_RESULT.fullmatch(line)) for line in lines]
    failed = [line.strip() for line, m in matches if not m]
    results = [(m[1], m[2]) for _, m in matches if m]
    require(results and not failed, f"RPM verification failed: {path}: " + "; ".join(failed or [proc.stderr.decode().strip()]))
    nokey = [what for what, result in results if result == "NOKEY"]
    require(all(RPM_SIGNER.search(what) for what in nokey), f"RPM verification failed: {path}: NOKEY on a digest")
    require(proc.returncode == 0 or proc.returncode == 1 and nokey,
            f"rpmkeys exited {proc.returncode}: {path}: {proc.stderr.decode().strip()}")
    require(("Payload SHA256 digest", "OK") in results, "missing RPM SHA256 payload digest: " + str(path))
    known = list(keys) + [(4, signer, True)]
    def names_signer(what):
        m = RPM_SIGNER.search(what)
        if not m:
            return False
        reported = m[2].upper()
        if m[1].lower().startswith("fingerprint"):
            return reported == signer
        require(len(reported) in (8, 16), "unexpected RPM key ID: " + what)
        return {fpr for version, fpr, _ in known if key_id(version, fpr).endswith(reported)} == {signer}
    require(any(names_signer(what) for what, result in results if result == "OK"),
            "no valid RPM signature by the pinned release key: " + str(path))


def unpack_rpm(path, dest):
    dest.mkdir(parents=True, exist_ok=True)
    with subprocess.Popen(["rpm2cpio", path], stdout=subprocess.PIPE) as proc:
        subprocess.run(["cpio", "--quiet", "-idm", "--no-absolute-filenames"], cwd=dest, stdin=proc.stdout, check=True)
        require(proc.wait() == 0, "RPM extraction failed")


def rocky_build_config(config, source, spec, version, work):
    # Rocky 10 kernel.spec edits the shipped kernel-core .config for local use
    # after building the official image. Preserve the vendor's actual keyring.
    text = config.read_text()
    marker = "# The kernel was built with"
    vendor = source / "configs" / ("kernel-" + version.split("-")[0] + "-x86_64.config")
    def trust_option(lines):
        return one((line for line in lines if line.startswith("CONFIG_SYSTEM_TRUSTED_KEYS=")), "vendor trust configuration")
    trusted = trust_option(vendor.read_text().splitlines())
    if marker not in text:
        require(trust_option(text.splitlines()) == trusted, "unrecorded Rocky trust policy change")
        return config
    reset = (marker + '\n# CONFIG_SYSTEM_TRUSTED_KEYS="certs/rhel.pem"\n'
             '# We are resetting this value to facilitate local builds\nCONFIG_SYSTEM_TRUSTED_KEYS=""')
    original = 'CONFIG_SYSTEM_TRUSTED_KEYS="certs/rhel.pem"'
    require(text.count(marker) == 1 and text.count(reset) == 1 and original == trusted
            and (source/"certs/rhel.pem").is_file() and marker in spec.read_text(),
            "unrecognized Rocky packaging config rewrite; cannot establish original trusted keys")
    path = work/"config.build"
    path.write_text(text.replace(reset, original))
    return path


def extract_rocky(plan, work, cache, fetch, source_only):
    rel, ver, abi, rev = (plan[k] for k in ("release", "version", "abi", "revision"))
    require(plan["suite"] == "BaseOS", "only the Rocky BaseOS release is supported")
    pin(plan, ROCKY, "r" + rel, f"patched/r{rel}/kernel-{ver}")
    archive = Archive(cache / ("rocky" + rel), f"https://dl.rockylinux.org/pub/rocky/{rel}", fetch)
    key = Path(plan["keyring"]).resolve()
    signer, keys = pinned_signer(key, KEYS[rel])
    db = work / "rpmdb"
    run("rpmkeys", "--dbpath", db, "--import", key)
    srpm_name = f"kernel-{ver}.src.rpm"
    def query(pkg):
        return run("rpm", "--dbpath", db, "-qp", "--qf", "%{NAME} %{EPOCHNUM} %{VERSION}-%{RELEASE} %{ARCH} %{SOURCERPM} %{SOURCEPACKAGE}", pkg).split()
    def verify_source(file):
        verify_rpm(file, db, signer, keys)
        info = query(file)
        require(info[:3] == ["kernel", "0", ver] and info[-1] == "1", "wrong SRPM NEVR")
    src, _ = archive.authenticated("BaseOS/source/tree/Packages/k/" + srpm_name, verify_source)
    specdir = work / "srpm"
    unpack_rpm(src, specdir)
    expected = set()
    for row in git(plan, "ls-tree", "-r", rev, "SPECS", "SOURCES").splitlines():
        mode, kind, blob, name = row.split(None, 3)
        file = specdir / Path(name).name
        # Dist-git can contain unused public certificates omitted by rpmbuild -bs.
        if file.exists():
            require(file.is_file() and git_blob(file) == blob, "SRPM/Git mismatch: " + name)
            expected.add(file.name)
    for row in git(plan, "show", rev + ":.kernel.metadata").splitlines():
        sha, name = row.split()
        require(sha == digest(specdir / Path(name).name), "lookaside blob mismatch: " + name)
        expected.add(Path(name).name)
    require("kernel.spec" in expected and expected == {p.name for p in specdir.iterdir()}, "SRPM contains unidentified sources")
    def package(name, repo):
        def verify_binary(file):
            verify_rpm(file, db, signer, keys)
            require(query(file)[:5] == [name, "0", ver, "x86_64", srpm_name], "wrong build: " + name)
        pkg, _ = archive.authenticated(f"{repo}/Packages/k/{name}-{abi}.rpm", verify_binary)
        return pkg
    core = package("kernel-core", "BaseOS/x86_64/os")
    proof = {"signer": signer, "source_sha256": digest(src), "package_sha256": digest(core)}
    # Native RPM macros and BuildRequires are part of %prep.
    native_environment(plan)
    # Security errata can use .el9_9/.el10_3 rather than the environment's default .el9/.el10.
    dist = "." + ver.rsplit(".", 1)[-1]
    macros = ["--target", "x86_64", "--define", "dist " + dist, "--define", f"_tmppath {work}",
              "--define", f"_topdir {work}/rpmbuild", "--define", f"_sourcedir {specdir}", "--define", f"_specdir {specdir}"]
    spec = specdir / "kernel.spec"
    require(run("rpmspec", "-q", "--srpm", "--qf", "%{VERSION}-%{RELEASE}", *macros, spec) == ver, "expanded Rocky spec does not match signed SRPM NVR")
    subprocess.run(["rpmbuild", "-bp", *macros, spec], check=True, stdout=sys.stderr)
    tree = one((p.parent for p in (work / "rpmbuild/BUILD").rglob("Kbuild") if (p.parent / "init/main.c").is_file()), "Rocky %prep source")
    if source_only:
        return tree, proof
    root = work / "packages"
    for name, repo in (("kernel-modules-core", "BaseOS/x86_64/os"), ("kernel-devel", "AppStream/x86_64/os"), ("kernel-debuginfo", "BaseOS/x86_64/debug/tree")):
        unpack_rpm(package(name, repo), root)
    unpack_rpm(core, root)
    debug = one(root.glob(f"usr/lib/debug/lib/modules/{abi}/vmlinux"), "Rocky vmlinux")
    config = rocky_build_config(root / "lib/modules" / abi / "config", tree, spec, ver, work)
    return tree, proof, root, debug, config, root / "usr/src/kernels" / abi / "Module.symvers"


def native_environment(plan):
    info = {k: v.strip('"') for k, v in (l.split("=", 1) for l in Path("/etc/os-release").read_text().splitlines() if "=" in l)}
    if plan["distro"] == "debian":
        require(info.get("VERSION_CODENAME") == DEBIAN[plan["release"]][0], "use the matching Debian stable codename")
    if plan["distro"] == "rocky":
        description = info.get("VERSION", "").lower()
        require(info.get("RELEASE_TYPE", "stable") == "stable" and not any(s in description for s in ("beta","candidate"," rc")), "unsupported Rocky prerelease build environment")
    require(info.get("ID") == plan["distro"] and info["VERSION_ID"].split(".")[0] == plan["release"] and os.uname().machine == "x86_64", "use a trusted matching AMD64 distribution build environment")


def public_module_cert(debug, dest, trusted_keys=None):
    # The vendor's certs/system_certificates.S places the public module cert
    # between these symbols in the signed build's unstripped vmlinux.
    wanted = {"__module_cert_start", "__module_cert_end", "module_cert_size"}
    if trusted_keys is not None:
        wanted.add("__cert_list_end")
    symbols = {}
    for line in run("readelf", "-Ws", debug).splitlines():
        fields = line.split()
        if len(fields) == 8 and fields[-1] in wanted:
            require(fields[-1] not in symbols, "duplicate built-in module certificate symbol")
            symbols[fields[-1]] = (int(fields[1], 16), fields[6])
    require(symbols.keys() == wanted, "signed vmlinux lacks module certificate symbols")
    start, index = symbols["__module_cert_start"]
    end, end_index = symbols["__module_cert_end"]
    size_addr, size_index = symbols["module_cert_size"]
    require(index == end_index == size_index and index.isdecimal() and 0 < end - start <= 65536,
            "invalid built-in module certificate bounds")
    section = re.search(r"^\s*\[\s*"+index+r"\]\s+\S+\s+PROGBITS\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)\b",
                        run("readelf", "-SW", debug), re.M)
    require(section, "missing file-backed module certificate section")
    address, offset, length = (int(x, 16) for x in section.groups())
    require(address <= start < end <= address + length and address <= size_addr <= address + length - 8,
            "module certificate is outside its signed ELF section")
    with debug.open("rb") as f:
        f.seek(offset + size_addr - address)
        require(int.from_bytes(f.read(8), "little") == end - start, "wrong module certificate length")
        f.seek(offset + start - address)
        der = f.read(end - start)
        if trusted_keys is not None:
            limit, list_index = symbols["__cert_list_end"]
            require(index == list_index and end < limit <= address + length, "invalid built-in trusted list")
            certs = re.findall("-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", trusted_keys.read_text(), re.S)
            require(certs and f.read(limit-end) == b"".join(ssl.PEM_cert_to_DER_cert(c) for c in certs),
                    "signed SRPM public certificates differ from installed kernel trust list")
    dest.parent.mkdir(parents=True, exist_ok=True)
    pem = subprocess.check_output(["openssl", "x509", "-inform", "DER", "-outform", "PEM"], input=der)
    require(subprocess.check_output(["openssl", "x509", "-outform", "DER"], input=pem) == der,
            "public certificate round-trip mismatch")
    dest.write_bytes(pem)


def discover(plan, cache, work, fetch, limit):
    """Resolve archived image versions to released package commits, without a preselected revision."""
    distro, rel, suite = (plan[k] for k in ("distro", "release", "suite"))
    if distro == "debian":
        stable, series = DEBIAN[rel]
        require(suite in (stable, stable + "-security"), "unsupported Debian archive")
        remote = "https://security.debian.org/debian-security" if suite.endswith("-security") else "https://deb.debian.org/debian"
        _, (packages, sources) = signed_indices(plan, Archive(cache / suite, remote, fetch), suite, work)
        versions = {p["Version"] for p in paragraphs(sources) if p.get("Package") == "linux"}
        for entry in paragraphs(packages):
            ver = entry.get("Version", "")
            name = entry.get("Package", "")
            if not (ver in versions and name.startswith("linux-image-" + series + ".") and name.endswith("-amd64")
                    and entry.get("Architecture") == "amd64" and entry.get("Source","").split(" ")[0] == "linux-signed-amd64"
                    and entry.get("Built-Using") == f"linux (= {ver})"):
                continue
            abi = name.removeprefix("linux-image-")
            pattern = r"6\.1\.0-\d+-amd64" if rel == "12" else r"6\.12\.\d+\+deb13(?:\.\d+)?-amd64"
            if not re.fullmatch(pattern, abi):
                continue
            tag = "debian/" + ver.replace("~", "_")
            try:
                rev = git(plan, "rev-parse", f"refs/tags/{tag}^{{commit}}")
                released = dict(plan, revision=rev, abi=abi, version=ver)
                pin(released, SALSA, f"debian/{series}/{suite}", tag)
            except subprocess.CalledProcessError:
                print(f"missing release tag or ancestry: {tag}", file=sys.stderr)
                continue
            yield released
    else:
        require(distro=="rocky" and rel in ("9","10") and suite=="BaseOS", "unsupported Rocky archive")
        require(git(plan,"remote","get-url","origin")==ROCKY,"wrong Rocky Git origin")
        prefix=f"patched/r{rel}/kernel-"
        tags=git(plan,"tag","--merged",f"refs/remotes/origin/r{rel}","--sort=-version:refname","-l",prefix+"*").splitlines()
        for tag in tags[:limit]:
            ver=tag.removeprefix(prefix)
            rev=git(plan,"rev-parse",f"refs/tags/{tag}^{{commit}}")
            released=dict(plan, revision=rev, abi=ver+".x86_64", version=ver)
            try:
                with tempfile.TemporaryDirectory(dir=work) as tmp:
                    prepare(released,Path(tmp)/"release",cache,fetch,source_only=True)
            except (ValueError,OSError,subprocess.SubprocessError) as err:
                print(f"excluded {tag}: {err}",file=sys.stderr)
                continue
            yield released


def image_build_id(source, image, work):
    with tempfile.NamedTemporaryFile(dir=work) as elf:
        subprocess.run(["sh", source / "scripts/extract-vmlinux", image], stdout=elf, check=True)
        elf.flush()
        return one(re.findall(r"Build ID: ([0-9a-f]{40})\b", run("readelf", "-n", elf.name)), "packaged kernel build ID")


def prepare(plan, work, cache, fetch=False, source_only=False):
    work.mkdir(mode=0o700)
    rel, distro, abi, version = (plan[k] for k in ("release", "distro", "abi", "version"))
    patterns = {("debian", "12"): r"6\.1\.0-[0-9]+-amd64", ("debian", "13"): r"6\.12\.[0-9]+\+deb13(?:\.[0-9]+)?-amd64", ("rocky", "9"): r"5\.14\.0-[0-9]+(?:\.[0-9]+)*\.el9(?:_[0-9]+)?\.x86_64", ("rocky", "10"): r"6\.12\.0-[0-9]+(?:\.[0-9]+)*\.el10(?:_[0-9]+)?\.x86_64"}
    require(re.fullmatch(patterns.get((distro, rel), r"(?!)"), abi), "unsupported distribution/release/ABI")
    if distro == "debian":
        require(re.fullmatch(re.escape(DEBIAN[rel][1]) + rf"\.[0-9]+-[0-9]+(?:[+~]deb{rel}u[0-9]+)?", version), "invalid Debian version")
        require(rel != "13" or abi.split("+")[0] == version.split("-")[0], "Debian ABI and source release mismatch")
        result = extract_deb(plan, work, cache, fetch, source_only)
    else:
        require(version + ".x86_64" == abi, "wrong Rocky NEVR")
        result = extract_rocky(plan, work, cache, fetch, source_only)
    source, proof = result[:2]
    proof["revision"] = plan["revision"]
    if source_only:
        return source, proof
    _, _, root, debug, config, symvers = result
    # Work around readelf flooding stdout with other kernel notes.
    out = run("readelf", "-n", debug)
    buildid = one(re.findall(r"Build ID: ([0-9a-f]{40})\b", out), "GNU kernel build ID")
    image = root / "boot" / ("vmlinuz-" + abi) if distro == "debian" else root / "lib/modules" / abi / "vmlinuz"
    require(image_build_id(source, image, work) == buildid, "image and debug package build IDs differ")
    require("CONFIG_LIVEPATCH=y" in config.read_text().splitlines(), f"{abi}: official CONFIG_LIVEPATCH is disabled")
    require(symvers.stat().st_size > 0 and ".debug_info" in run("readelf", "-SW", debug), "missing Module.symvers or unstripped DWARF")
    track = "__".join(("native", distro, rel, "amd64", abi, version.replace("~", "_t"), buildid))
    proof["track"] = track
    ref = next((f for f in root.rglob("*.ko*") if re.search(r"\.ko(?:\.(?:xz|zst|gz))?$", f.name) and f.is_file() and not f.is_symlink()), None)
    require(ref is not None, "no official reference module")
    return dict(source=source, proof=proof, config=config, symvers=symvers, debug=debug, reference=ref)
