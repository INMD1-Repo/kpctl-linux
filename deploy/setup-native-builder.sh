#!/bin/bash
# Debian 12·Rocky 9·10 AMD64 네이티브 빌더 설치. dist/builder/debian 또는 dist/builder/rocky 에서 root 로 실행합니다 (보통 kpctl install-builder 가 SSH 로 실행).
#
# 빌더 호스트는 대상과 같은 배포판·릴리스의 전용 VM 입니다. 이 스크립트는 그 VM 에
#   배포판 공식 빌드 도구 → (Debian 12·Rocky 9) 고정 kpatch → 전용 계정·디렉터리 → 공식 패키징 Git
#   → 대상 커널마다 discover 계획(base.json)·prepare 영수증(base-proof.json) → worker.json·토큰·CA
#   → kpctl-native-builder.timer (kpctl-native-builder.py work 를 1분마다, flock 직렬화, systemd 샌드박스)
# 를 준비합니다. 다시 실행해도 안전해야 합니다 (기존 계정·Git·캐시·설정 재사용).
#
# 하지 않는 것 (보안 경계, docs/operations/distribution-kernels.md):
#   - 컨트롤러 승인 핀(distribution-proofs/<track>.json) 작성: 빌더와 독립된 환경에서 운영자가 합니다.
#   - 수정 후보 수집(collect): 사람이 경로·제목·CVE 를 검토해 실행합니다.
#
# 설치 경로
#   /opt/kpctl/native-builder/             kpctl-native-builder.py, native_inputs.py, kpctl-native-work.sh (root 0755)
#   /usr/local/bin/kpctl-builder           -verify-distribution-module 용 (root 0755)
#   /etc/kpctl/native-builder/worker.json  controller_url, ca_file, token_file, builder (root:<계정> 0640)
#   /etc/kpctl/native-builder/token        빌더 토큰 (root:<계정> 0640)
#   /etc/kpctl/tls/ca.crt                  컨트롤러 CA (선택)
#   /var/lib/kpctl-native/                 <계정> 0700
#     inputs/<debian-linux|rocky-kernel>   공식 패키징 Git (--no-checkout, 태그·원격 브랜치 포함, shallow 금지)
#     cache/  work/                        서명 인덱스·패키지 캐시, 작업마다 새 하위 디렉터리
#     tracks/<track>/base.json             대상 커널 계획 (discover 결과 중 abi·version 이 맞는 한 줄)
#     tracks/<track>/base-proof.json       prepare --fetch 영수증 (track 에 실행 커널 build ID 포함)
#   /etc/systemd/system/kpctl-native-builder.{service,timer}
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
START=1 PLAN=0 WORKER_INPUT="" TOKEN_INPUT="" CA_INPUT="" JOBS="" BUILD_USER=""
TARGETS=()   # "ABI" 또는 "ABI=TRACK"
KPATCH_REF=e0a8f7c681964e9128449446a34f7f3e631a8621  # setup-builder.sh 와 같은 고정 kpatch
ROOT_DIR=/var/lib/kpctl-native ETC_DIR=/etc/kpctl/native-builder OPT_DIR=/opt/kpctl/native-builder

usage() {
  cat <<'HELP'
사용법: sudo ./setup-native-builder.sh [옵션] --target <ABI[=TRACK]> [--target ...]
  --target ABI[=TRACK] 대상 커널 uname -r (반복). TRACK 을 주면 prepare 영수증의 track 과 정확히 같아야 합니다
  --worker FILE        worker.json (controller_url, ca_file, token_file, builder). 없으면 기존 설정 유지
  --token-file FILE    빌더 토큰 (--worker 와 함께)
  --ca-file FILE       CA 를 /etc/kpctl/tls/ca.crt 로 설치
  --jobs N             컴파일 병렬 수 1~256 (기본 CPU 수, 최대 256)
  --user NAME          빌드 실행 계정 (기본 kpbuild, 재설치 때는 기존 서비스 계정)
  --no-start           설치·설정만 하고 타이머 시작 생략
  --plan               점검 결과·설치할 패키지·대상을 JSON 으로 표시하고 아무것도 바꾸지 않음
  --help               도움말
HELP
}

fail() { echo "!! $*" >&2; exit 1; }
bad_arg() { echo "!! $*" >&2; exit 2; }
step() { echo "■ $*" >&2; }

# 커널과 패키지 버전 형식은 internal/model/distribution.go 의 profiles 와 같습니다.
profile() {
  if [[ $1 =~ ^6\.1\.0-[0-9]+-amd64$ ]]; then echo debian__12
  elif [[ $1 =~ ^5\.14\.0-[0-9]+(\.[0-9]+)*\.el9(_[0-9]+)?\.x86_64$ ]]; then echo rocky__9
  elif [[ $1 =~ ^6\.12\.0-[0-9]+(\.[0-9]+)*\.el10(_[0-9]+)?\.x86_64$ ]]; then echo rocky__10
  else return 1
  fi
}

valid_target() {
  local abi=${1%%=*} track=${1#*=} family prefix version
  family=$(profile "$abi") || return 1
  [[ $1 == *=* ]] || return 0
  prefix="native__${family}__amd64__${abi}__"
  [[ $track == "$prefix"* && ${#track} -le 200 && ${track##*__} =~ ^[0-9a-f]{40}$ ]] || return 1
  version=${track#"$prefix"}
  [[ $version == *__* ]] || return 1
  version=${version%__*}
  if [[ $family == debian__12 ]]; then
    [[ $version =~ ^6\.1\.[0-9]+-[0-9]+((\+|_t)deb12u[0-9]+)?$ ]]
  else
    [[ $version.x86_64 == "$abi" ]]
  fi
}

UNIT_DIR=/etc/systemd/system
OS_RELEASE=/etc/os-release
AGENT=/usr/local/bin/kpctl-agent
TLS_DIR=/etc/kpctl/tls
UNIT=kpctl-native-builder
parse_args() {
  local installed="" input
  while (($#)); do
    case $1 in
      --no-start) START=0 ;;
      --plan) PLAN=1 ;;
      --help|-h) usage; exit 0 ;;
      --target|--worker|--token-file|--ca-file|--jobs|--user)
        [[ -n ${2:-} && $2 != -* ]] || bad_arg "$1 값이 필요합니다"
        case $1 in
          --target) valid_target "$2" || bad_arg "잘못된 대상 커널 또는 track: $2"; TARGETS+=("$2") ;;
          --worker) WORKER_INPUT=$2 ;;
          --token-file) TOKEN_INPUT=$2 ;;
          --ca-file) CA_INPUT=$2 ;;
          --jobs) JOBS=$2 ;;
          --user) BUILD_USER=$2 ;;
        esac
        shift ;;
      *) bad_arg "알 수 없는 옵션: $1" ;;
    esac
    shift
  done
  ((${#TARGETS[@]})) || bad_arg "--target 으로 대상 커널을 지정하세요"
  if [[ -n $WORKER_INPUT || -n $TOKEN_INPUT ]]; then
    [[ -n $WORKER_INPUT && -n $TOKEN_INPUT ]] || bad_arg "--worker 와 --token-file 은 함께 지정하세요"
  fi
  for input in "$WORKER_INPUT" "$TOKEN_INPUT" "$CA_INPUT"; do
    [[ -z $input || -f $input && -r $input ]] || bad_arg "입력 파일을 읽을 수 없습니다: $input"
  done
  if [[ -z $JOBS ]]; then JOBS=$(nproc); ((JOBS <= 256)) || JOBS=256; fi
  [[ $JOBS =~ ^[1-9][0-9]{0,2}$ ]] && ((JOBS <= 256)) || bad_arg "--jobs 는 1~256 사이 정수입니다"
  if [[ -f $UNIT_DIR/$UNIT.service ]]; then
    installed=$(sed -n 's/^User=//p' "$UNIT_DIR/$UNIT.service")
  fi
  BUILD_USER=${BUILD_USER:-${installed:-kpbuild}}
  [[ $BUILD_USER =~ ^[a-z_][a-z0-9_-]{0,31}$ && $BUILD_USER != root ]] || bad_arg "잘못된 빌드 계정: $BUILD_USER"
  [[ -z $installed || $BUILD_USER == "$installed" ]] || bad_arg "기존 서비스 계정은 $installed 입니다"
}

check_host() {
  step "1. 전용 빌더 호스트 점검"
  [[ $(id -u) == 0 ]] || fail "root 로 실행하세요"
  # shellcheck source=/dev/null
  . "$OS_RELEASE"
  DISTRO=$ID RELEASE=${VERSION_ID%%.*}
  case "$DISTRO:$RELEASE" in
    debian:12) [[ ${VERSION_CODENAME:-} == bookworm ]] || fail "Debian 12 bookworm 이 필요합니다" ;;
    rocky:9|rocky:10)
      local desc=${VERSION:-}; desc=${desc,,}
      [[ ${RELEASE_TYPE:-stable} == stable && $desc != *beta* && $desc != *candidate* && $desc != *" rc"* ]] || fail "Rocky 정식 릴리스가 필요합니다" ;;
    *) fail "지원하지 않는 릴리스: $DISTRO $VERSION_ID (Debian 12·Rocky 9·10 지원)" ;;
  esac
  # make dist 의 배포판별 묶음에는 builder-flavor(debian | rocky) 가 있습니다. 다른 배포판 묶음이면 설치하지 않습니다.
  if [[ -f $HERE/builder-flavor ]]; then
    local flavor; flavor=$(tr -d '[:space:]' < "$HERE/builder-flavor")
    [[ $flavor == "$DISTRO" ]] || fail "이 묶음은 ${flavor:-?} 빌더용입니다 ($DISTRO 호스트에는 dist/builder/$DISTRO 를 쓰세요)"
  fi
  [[ $(uname -m) == x86_64 ]] || fail "AMD64 전용 빌더입니다"
  [[ ! -x $AGENT ]] || fail "에이전트가 설치된 운영 호스트입니다"
  local virt flag target
  virt=$(systemd-detect-virt --container) || [[ $? == 1 && $virt == none ]] || fail "컨테이너 여부를 확인하지 못했습니다"
  [[ $virt == none ]] || fail "컨테이너($virt) 안에는 설치할 수 없습니다"
  if ! systemd-detect-virt --vm --quiet; then echo "경고: 대상과 같은 릴리스의 전용 VM 을 권장합니다" >&2; fi
  systemctl show --property=Version --value >/dev/null || fail "systemd 로 부팅한 전용 VM 이 필요합니다"
  if [[ $DISTRO == rocky && $RELEASE == 10 ]]; then
    for flag in avx2 bmi2 fma movbe; do
      grep -qw "$flag" /proc/cpuinfo || fail "Rocky 10 에 필요한 x86-64-v3 CPU 기능 누락: $flag"
    done
  fi
  FREE_KB=$(df -Pk /var | awk 'NR == 2 {print $4}')
  [[ $FREE_KB =~ ^[0-9]+$ ]] && ((FREE_KB >= 40 * 1024 * 1024)) || fail "/var 여유 공간이 40 GiB 이상 필요합니다"
  for target in "${TARGETS[@]}"; do
    [[ $(profile "${target%%=*}") == "${DISTRO}__${RELEASE}" ]] || fail "$target 은 $DISTRO $RELEASE 커널이 아닙니다"
  done
  if [[ $DISTRO == debian ]]; then
    KEYRING=/usr/share/keyrings/debian-archive-keyring.gpg
    GIT_DIR=$ROOT_DIR/inputs/debian-linux
    GIT_URL=https://salsa.debian.org/kernel-team/linux.git
    PACKAGES=(ca-certificates git python3 dpkg-dev gpgv gcc make binutils kmod libelf-dev libssl-dev bc bison flex
              cpio xz-utils zstd dwarves debian-archive-keyring rsync elfutils patchutils gawk libdw-dev libxxhash-dev)
  else
    KEYRING=/etc/pki/rpm-gpg/RPM-GPG-KEY-Rocky-$RELEASE
    GIT_DIR=$ROOT_DIR/inputs/rocky-kernel
    GIT_URL=https://git.rockylinux.org/staging/rpms/kernel.git
    PACKAGES=(ca-certificates dnf-plugins-core rpm-build rpmdevtools cpio git gnupg2 gcc make elfutils-libelf-devel
              elfutils-devel kmod python3 patchutils redhat-rpm-config)
    if [[ $RELEASE == 10 ]]; then PACKAGES+=('xxhash-libs >= 0.8' 'xxhash-devel >= 0.8'); fi
  fi
}

show_plan() {
  python3 -I - "$DISTRO" "$RELEASE" "$FREE_KB" "$BUILD_USER" "$JOBS" "$START" "${TARGETS[@]}" -- "${PACKAGES[@]}" <<'PY'
import json, sys
distro, release, free, user, jobs, start, *args = sys.argv[1:]
i = args.index("--")
print(json.dumps(dict(distro=distro, release=release, arch="x86_64", var_free_kib=int(free),
                      user=user, jobs=int(jobs), start=bool(int(start)), targets=args[:i], packages=args[i+1:])))
PY
}

install_packages() {
  step "2. 배포판 공식 빌드 패키지 설치"
  if [[ $DISTRO == debian ]]; then
    local sources=$TEMP/sources.list
    cat > "$sources" <<APT
deb [signed-by=$KEYRING] https://deb.debian.org/debian bookworm main
deb [signed-by=$KEYRING] https://security.debian.org/debian-security bookworm-security main
deb-src [signed-by=$KEYRING] https://deb.debian.org/debian bookworm main
deb-src [signed-by=$KEYRING] https://security.debian.org/debian-security bookworm-security main
APT
    local apt=(apt-get -o "Dir::Etc::sourcelist=$sources" -o Dir::Etc::sourceparts=- -o "Dir::State::lists=$TEMP/lists")
    mkdir -p "$TEMP/lists/partial"
    export DEBIAN_FRONTEND=noninteractive
    "${apt[@]}" update
    "${apt[@]}" -y --no-install-recommends install "${PACKAGES[@]}"
    "${apt[@]}" -y --no-install-recommends build-dep linux
    return
  fi
  local repos=baseos,appstream,crb target version srpm signature
  [[ $RELEASE != 10 ]] || repos+=,devel
  local dnf=(dnf -y '--disablerepo=*' "--enablerepo=$repos" --setopt=gpgcheck=1)
  "${dnf[@]}" install "${PACKAGES[@]}"
  rpmkeys --dbpath "$TEMP/rpmdb" --import "$KEYRING"
  for target in "${TARGETS[@]}"; do
    version=${target%%=*}; version=${version%.x86_64}
    srpm="$TEMP/kernel-$version.src.rpm"
    [[ ! -f $srpm ]] || continue
    "${dnf[@]}" --enablerepo=baseos-source download --source --destdir "$TEMP" "kernel-$version"
    signature=$(LC_ALL=C rpm --dbpath "$TEMP/rpmdb" -Kv "$srpm")
    grep -Eiq 'signature.*: OK$' <<< "$signature" || fail "$version SRPM 의 Rocky 서명을 확인하지 못했습니다"
    [[ $(rpm --dbpath "$TEMP/rpmdb" -qp --qf '%{NAME}-%{VERSION}-%{RELEASE} %{SOURCEPACKAGE}' "$srpm") == "kernel-$version 1" ]] || fail "다른 버전의 SRPM 입니다: $version"
    "${dnf[@]}" builddep "$srpm"
  done
}

install_kpatch() {
  step "3. 커널 빌드 도구 준비"
  if [[ $DISTRO == rocky && $RELEASE == 10 ]]; then echo "Rocky 10 커널 소스의 klp-build 사용"; return; fi
  local marker=/usr/local/share/kpctl/kpatch-ref
  if [[ -f $marker && $(cat "$marker") == "$KPATCH_REF" ]] && command -v kpatch-build >/dev/null; then return; fi
  git clone --no-checkout https://github.com/dynup/kpatch.git "$TEMP/kpatch"
  git -C "$TEMP/kpatch" checkout --detach "$KPATCH_REF"
  bash "$HERE/kpctl-kpatch-fixes.sh" "$TEMP/kpatch"
  make -C "$TEMP/kpatch" -j"$JOBS"
  python3 -I "$HERE/kpctl-kpatch-cold-test.py" "$TEMP/kpatch/kpatch-build/create-diff-object"
  make -C "$TEMP/kpatch" install
  install -d -m 0755 /usr/local/share/kpctl
  echo "$KPATCH_REF" > "$marker"
}

as_builder() {
  runuser -u "$BUILD_USER" -- env HOME="$ROOT_DIR" sh -c 'cd "$HOME" && exec "$@"' sh "$@"
}

setup_user_and_files() {
  step "4. 전용 계정·작업 디렉터리·프로그램 설치"
  if ! id "$BUILD_USER" >/dev/null 2>&1; then
    useradd --system --user-group --no-create-home --home-dir "$ROOT_DIR" --shell /sbin/nologin "$BUILD_USER"
  fi
  [[ $(id -u "$BUILD_USER") != 0 && $(id -g "$BUILD_USER") != 0 ]] || fail "비특권 빌드 계정이 필요합니다"
  # 설정과 토큰을 읽는 기본 그룹은 이 계정 전용이어야 합니다.
  python3 -I - "$BUILD_USER" <<'PYUSER'
import grp, os, pwd, sys
user = pwd.getpwnam(sys.argv[1])
group = grp.getgrgid(user.pw_gid)
others = {p.pw_name for p in pwd.getpwall() if p.pw_gid == group.gr_gid} | set(group.gr_mem)
if others - {user.pw_name}:
    sys.exit("!! 빌드 계정 전용 기본 그룹이 필요합니다")
member = {grp.getgrgid(gid).gr_name for gid in os.getgrouplist(user.pw_name, group.gr_gid)}
if member & {"root", "sudo", "wheel", "docker", "lxd", "disk"}:
    sys.exit("!! 관리자 그룹에 속하지 않은 비특권 빌드 계정이 필요합니다")
PYUSER
  BUILD_GROUP=$(id -gn "$BUILD_USER")
  [[ $BUILD_GROUP =~ ^[a-z_][a-z0-9_-]*$ ]] || fail "서비스 그룹 이름을 확인하세요"
  [[ ! -L $ROOT_DIR ]] || fail "작업 디렉터리가 심볼릭 링크입니다"
  install -d -m 0700 -o "$BUILD_USER" -g "$BUILD_GROUP" "$ROOT_DIR"
  as_builder mkdir -p "$ROOT_DIR"/{inputs,cache,work,tracks}
  install -d -m 0755 "$OPT_DIR" /usr/local/bin
  install -m 0755 "$HERE/kpctl-native-builder.py" "$HERE/native_inputs.py" "$HERE/kpctl-native-work.sh" "$OPT_DIR/"
  install -m 0755 "$HERE/kpctl-builder" /usr/local/bin/kpctl-builder
}

prepare_git() {
  step "5. 공식 패키징 Git 준비"
  if [[ ! -e $GIT_DIR ]]; then
    as_builder git clone --no-checkout "$GIT_URL" "$STAGE/checkout"
    as_builder mv -T "$STAGE/checkout" "$GIT_DIR"
  fi
  [[ $(as_builder git -C "$GIT_DIR" remote get-url origin) == "$GIT_URL" ]] || fail "패키징 Git origin 이 다릅니다: $GIT_DIR"
  [[ $(as_builder git -C "$GIT_DIR" rev-parse --is-shallow-repository) == false ]] || fail "전체 이력이 있는 패키징 Git 이 필요합니다"
  as_builder git -C "$GIT_DIR" fetch --tags origin '+refs/heads/*:refs/remotes/origin/*'
}

plan_targets() {
  step "6. 대상 커널의 공식 서명 릴리스와 Git 태그 선택"
  as_builder python3 -I - "$STAGE" "$ROOT_DIR" "$OPT_DIR" "$DISTRO" "$RELEASE" "$GIT_DIR" "$KEYRING" "$JOBS" "${TARGETS[@]}" <<'PY'
import json, subprocess, sys
from pathlib import Path

stage, root, tools = map(Path, sys.argv[1:4])
distro, release, git, keyring, jobs, *targets = sys.argv[4:]
driver = [sys.executable, "-Es", str(tools / "kpctl-native-builder.py"), "discover",
          "--plan", str(stage / "suite.json"), "--cache", str(root / "cache"),
          "--work-dir", str(root / "work"), "--fetch"]
if distro == "rocky":
    prefix = f"patched/r{release}/kernel-"
    tags = subprocess.check_output(["git", "-C", git, "tag", "--merged", f"refs/remotes/origin/r{release}",
                                    "--sort=-version:refname", "-l", prefix + "*"], text=True).splitlines()
    wanted = {prefix + t.partition("=")[0].removesuffix(".x86_64") for t in targets}
    limit = max((i for i, tag in enumerate(tags, 1) if tag in wanted), default=0)
    if not limit or limit > 100:
        sys.exit("!! 공식 서명 릴리스·Git 태그를 찾지 못했습니다 (discover 가 검사하는 최근 100개 태그): " + ", ".join(sorted(wanted)))
    driver.extend(["--limit", str(limit)])

pending = dict(enumerate(targets))
for suite in (["bookworm-security", "bookworm"] if distro == "debian" else ["BaseOS"]):
    (stage / "suite.json").write_text(json.dumps(dict(distro=distro, release=release, suite=suite, git=git, keyring=keyring)))
    result = subprocess.run(driver, stdout=subprocess.PIPE, text=True)
    if result.returncode:
        continue
    plans = [json.loads(line) for line in result.stdout.splitlines()]
    for index, target in list(pending.items()):
        abi, _, track = target.partition("=")
        version = track.split("__")[5].replace("_t", "~") if track else ""
        matches = [p for p in plans if p["abi"] == abi and (not version or p["version"] == version)]
        if not matches:
            continue
        if len(matches) != 1:
            sys.exit(f"!! {abi}: 패키지 버전이 여럿입니다. 대상 호스트의 track 이 필요합니다")
        dest = stage / str(index)
        dest.mkdir()
        (dest / "base.json").write_text(json.dumps(dict(matches[0], jobs=int(jobs)), indent=2) + "\n")
        del pending[index]
    if not pending:
        break
if pending:
    sys.exit("!! " + ", ".join(pending.values()) + ": 공식 서명 릴리스·Git 태그를 찾지 못했습니다")
PY
}

prepare_targets() {
  step "7. 대상별 패키지·영수증 준비와 빌드 ID 대조"
  as_builder python3 -I - "$STAGE" "$ROOT_DIR" "$OPT_DIR" "${TARGETS[@]}" <<'PY'
import fcntl, json, re, subprocess, sys
from pathlib import Path

stage, root, tools = map(Path, sys.argv[1:4])
tracks = root / "tracks"
ready = {}
for index, target in enumerate(sys.argv[4:]):
    folder = stage / str(index)
    base, proof = folder / "base.json", folder / "base-proof.json"
    with proof.open("w") as output:
        subprocess.run([sys.executable, "-Es", str(tools / "kpctl-native-builder.py"), "prepare",
                        "--plan", base, "--cache", root / "cache", "--work-dir", root / "work", "--fetch"],
                       stdout=output, check=True)
    track = json.loads(proof.read_text())["track"]
    abi, _, expected = target.partition("=")
    plan = json.loads(base.read_text())
    prefix = "__".join(("native", plan["distro"], plan["release"], "amd64", abi, plan["version"].replace("~", "_t"), ""))
    if not re.fullmatch(re.escape(prefix) + "[0-9a-f]{40}", track) or "/" in track or len(track) > 200:
        sys.exit(f"!! {abi}: prepare 영수증의 track 형식 또는 버전이 다릅니다")
    if expected and track != expected:
        sys.exit(f"!! 빌드 ID 불일치: 등록 호스트 {expected}, prepare {track}")
    print(f"  {abi}: {track}", flush=True)
    ready[track] = folder

# 모든 영수증을 대조한 뒤 작업 실행과 직렬화합니다. 기존 트랙의 다른 파일은 유지합니다.
with (root / "work.lock").open("a") as lock:
    fcntl.flock(lock, fcntl.LOCK_EX)
    for track, folder in ready.items():
        dest = tracks / track
        if dest.exists():
            (folder / "base.json").replace(dest / "base.json")
            (folder / "base-proof.json").replace(dest / "base-proof.json")
        else:
            folder.rename(dest)
for old in sorted(tracks.iterdir()):
    if old.is_dir() and old.name not in ready:
        print(f"경고: 이번 설치 대상에 없는 기존 트랙을 유지합니다: {old.name}", file=sys.stderr)
PY
}

install_config_and_units() {
  step "8. 빌더 설정·토큰·서비스 설치"
  install -d -m 0750 -o root -g "$BUILD_GROUP" "$ETC_DIR"
  local conf=$ETC_DIR/worker.json token=$ETC_DIR/token ca=$TLS_DIR/ca.crt
  if [[ -n $WORKER_INPUT ]]; then
    # 같은 파일시스템의 root 전용 임시 디렉터리에서 완성한 파일만 공개합니다.
    CONFIG_STAGE=$(mktemp -d "$ETC_DIR/.install.XXXXXX")
    install -m 0640 -o root -g "$BUILD_GROUP" "$TOKEN_INPUT" "$CONFIG_STAGE/token"
    install -m 0640 -o root -g "$BUILD_GROUP" "$WORKER_INPUT" "$CONFIG_STAGE/worker.json"
    python3 -I - "$CONFIG_STAGE" "$token" <<'PY'
import json, sys
from pathlib import Path
stage = Path(sys.argv[1])
cfg = json.loads((stage / "worker.json").read_text())
if (set(cfg) - {"controller_url", "token_file", "builder", "ca_file"} or cfg.get("token_file") != sys.argv[2]
        or not cfg.get("builder") or not cfg.get("controller_url", "").startswith("https://")):
    sys.exit("!! worker.json 의 컨트롤러·토큰 파일·빌더 이름을 확인하세요")
if len((stage / "token").read_text().strip()) < 16:
    sys.exit("!! 16자 이상의 빌더 토큰이 필요합니다")
PY
    # 컨트롤러를 바꾸다 중단돼도 이전 주소로 새 토큰이 전송되지 않게 합니다.
    if [[ -e $conf ]]; then
      install -m 0640 -o root -g "$BUILD_GROUP" /dev/null "$CONFIG_STAGE/empty"
      mv -fT "$CONFIG_STAGE/empty" "$token"
    fi
    mv -fT "$CONFIG_STAGE/worker.json" "$conf"
    mv -fT "$CONFIG_STAGE/token" "$token"
  else
    local file
    for file in "$conf" "$token"; do
      [[ -f $file && ! -L $file ]] || fail "기존 설정 파일이 필요합니다: $file"
      chown "root:$BUILD_GROUP" "$file"
      chmod 0640 "$file"
    done
  fi
  if [[ -n $CA_INPUT ]]; then
    install -d -m 0755 "$TLS_DIR"
    CA_TEMP=$(mktemp "$TLS_DIR/.ca.XXXXXX")
    install -m 0644 "$CA_INPUT" "$CA_TEMP"
    mv -fT "$CA_TEMP" "$ca"
  fi
  as_builder test -r "$conf" && as_builder test -r "$token" || fail "빌드 계정이 읽을 수 있는 worker.json 과 토큰이 필요합니다"
  as_builder python3 -I - "$conf" "$token" <<'PY'
import json, sys
from pathlib import Path
cfg = json.loads(Path(sys.argv[1]).read_text())
if cfg.get("token_file") != sys.argv[2] or len(Path(sys.argv[2]).read_text().strip()) < 16:
    sys.exit("!! 기존 빌더 토큰을 확인하세요 (-reset-config 로 다시 설치)")
if cfg.get("ca_file"):
    with open(cfg["ca_file"], "rb"):
        pass
PY
  sed -e "s/^User=.*/User=$BUILD_USER/" -e "s/^Group=.*/Group=$BUILD_GROUP/" "$HERE/$UNIT.service" > "$TEMP/$UNIT.service"
  install -m 0644 "$TEMP/$UNIT.service" "$HERE/$UNIT.timer" "$UNIT_DIR/"
  systemctl daemon-reload
}

start_timer() {
  step "9. 네이티브 빌더 타이머"
  if ((START)); then
    systemctl enable --now "$UNIT.timer"
    systemctl start --no-block "$UNIT.service"
  else
    echo "타이머 시작 생략 (--no-start)"
  fi
}

cleanup() {
  if [[ -n ${STAGE:-} ]]; then as_builder rm -rf -- "$STAGE"; fi
  if [[ -n ${CONFIG_STAGE:-} ]]; then rm -rf -- "$CONFIG_STAGE"; fi
  if [[ -n ${CA_TEMP:-} ]]; then rm -f -- "$CA_TEMP"; fi
  rm -rf -- "$TEMP"
}

main() {
  parse_args "$@"
  check_host
  if ((PLAN)); then show_plan; return; fi
  exec 8>/run/kpctl-native-builder-install.lock
  flock -n 8 || fail "다른 네이티브 빌더 설치가 진행 중입니다"
  if systemctl is-active --quiet "$UNIT.timer" || systemctl is-active --quiet "$UNIT.service"; then
    fail "실행 중인 빌더를 먼저 중지하세요 (kpctl install-builder -stop-running)"
  fi
  TEMP=$(mktemp -d /var/tmp/kpctl-native-install.XXXXXX)
  STAGE="" CONFIG_STAGE="" CA_TEMP=""
  trap cleanup EXIT
  trap 'exit 129' HUP
  trap 'exit 130' INT
  trap 'exit 143' TERM
  install_packages
  install_kpatch
  setup_user_and_files
  STAGE=$(as_builder mktemp -d "$ROOT_DIR/work/.install.XXXXXX")
  prepare_git
  plan_targets
  prepare_targets
  install_config_and_units
  start_timer
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
  set -E
  trap 'echo "!! 설치 실패 (setup-native-builder.sh ${LINENO}행)" >&2' ERR
  main "$@"
fi
