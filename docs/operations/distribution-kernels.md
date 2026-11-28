# Debian 및 Rocky Linux 공식 기본 AMD64 커널

Ubuntu 컨트롤러가 서명, VM 검사, 호스트별 MOK 선택과 링 배포를 담당한다. 대상과 같은 배포판의 별도 빌더가 패키징 Git, 공식 패키지, 실행 커널의 GNU build ID를 대조한다. 아래 표는 2026-11-28 KST에 확인한 개별 릴리스다. 네 릴리스의 서명된 소스·바이너리를 실제로 풀고 config, DWARF vmlinux, Module.symvers, 정식 참조 모듈, image/debug build ID 일치를 확인했다.

| 대상 | 실행 ABI 및 linux 소스 버전 또는 SRPM NVR | 검증한 packaging commit | 빌드 결과 |
|---|---|---|---|
| Debian 12 bookworm-security | `6.1.0-57-amd64` · `6.1.192-3` | `1c45e37eb6cae0a32f9e36a11ea799cddd6b3eaf` | 실제 시험 모듈 통과, 심볼 CRC 13건 |
| Debian 13 trixie-security | `6.12.118+deb13-amd64` · `6.12.118-1` | `06aefed4099c5ef39c58333b64ef63ee51b41092` | 공식 소스·실행 커널 식별까지 확인. [기본 커널의 IBT 제약](#debian13-ibt)으로 라이브패치 빌드·배포 불가 |
| Rocky 9 BaseOS | `5.14.0-741.27.1.el9_9.x86_64` · `kernel-5.14.0-741.27.1.el9_9` | `a452e800f38b2b61b5e92c036942e22e738ac663` | 실제 시험 모듈 통과, 심볼 CRC 15건 |
| Rocky 10 BaseOS | `6.12.0-264.21.1.el10_3.x86_64` · `kernel-6.12.0-264.21.1.el10_3` | `3bc0814aa7c851b9987a7a8cf50aa28baac3919c` | 정식 CONFIG_KLP_BUILD=y. 아래 .20.1 기준 커널에 이 .21.1의 수정을 실제 빌드·서명, CRC 18건 |

각 행의 GNU build ID와 sha256은 다음과 같다. DSC는 Debian 서명 아카이브 Sources가 인증하는 .dsc 파일, SRPM은 Rocky 서명 원본이다. 이미지 열은 Debian linux-image 또는 Rocky kernel-core 패키지 전체 바이트다.

| 대상 | 실행 이미지 GNU build ID | DSC/SRPM SHA256 | 이미지 패키지 SHA256 |
|---|---|---|---|
| Debian 12 | `6a2b4ac77585b8cf102cba771300e573c8489b69` | `935ea63f59b054c1b1f686f2ed5812c240ee7455959627157c872df57bd9c122` | `14d219d01e1283261817d961dbb3895cb5b4288d0de10e0ba0632a0d993e15bf` |
| Debian 13 | `67e5e727aeb3cb468dfe1bb8f9738f944c3a7d50` | `c0d49c11a1121881a1bdec865a6c980ba500aaf46fdd8c1a80d998ec5b2b41da` | `57dee9124ac6c57b75a8aed09052245942027dd46649d3d02285c35c11cfda98` |
| Rocky 9 | `b1a25d7182be9a5204a49f4c314a1e97465695c5` | `ea7fe563b0f4e18008ac1c60e9ca6e791d6178fd49c53ef03b3f85db2715fe2d` | `718163834c8f38bf382b01791a8aa98acbd689e95f2e5c31dde67c9e7eb6ac1a` |
| Rocky 10 | `7454689549d6bd3ddbf9a694ab9d3cd292e91710` | `3bf6f0985ad6dfa6457c0a02a770d95c3635d9e7e2b9c6e5e31c6b5bc02913ea` | `85f1d25c94e0df5c45ec34ab6cf659f942c087d0ffb7667ccaf98ebe8351b501` |

네 config 모두 LIVEPATCH=y, MODVERSIONS=y였다. Debian 12 및 Rocky 9에서는 각 배포판의 정확한 GCC로 `fs/proc/version.c`의 무해한 표시 변경을 컴파일했다. ELF, livepatch=Y, 모듈명, 정식 모듈의 전체 vermagic과 심볼 CRC 검증을 통과했다. 생성된 서명 전 모듈 SHA256은 각각 `ebae3adb1132a2a7ca1ee3e157f7c234bc1ef6c110e93e00bf52fa2300097b4d`, `491c5e16f94223c699486b9d9e8bee592d8df0cfa879ed2ba1c587ff46b96a56`이다. 시험 모듈은 CVE 수정으로 배포하지 않았다. 두 실제 모듈의 사본을 Ubuntu의 /usr/bin/kmodsign과 일회성 인증서로 서명하고 컨트롤러 CMS 검증을 통과했다. 실기 커널 로드, UEFI/MOK 신뢰, VM 전환·롤백은 별도 검증이 필요하다.

<a id="debian13-ibt"></a>

### Debian 13 기본 커널: 정식 보안 업데이트 사용

확인한 trixie 기본 AMD64 커널(`6.12.118+deb13-amd64`)은 `CONFIG_LIVEPATCH=y`이지만 `CONFIG_X86_KERNEL_IBT=y`이고 `CONFIG_KLP_BUILD`가 없다. Debian의 `kpatch-build`는 이 IBT 설정을 지원하지 않고, 이 커널 소스에는 대체 도구인 `klp-build`도 없다. 이는 컨트롤러의 키나 MOK 등록으로 해결할 수 있는 서명 오류가 아니다. [Debian 커널 팀의 확인](https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1070494#12)과 [kpatch의 IBT 지원 범위](https://github.com/dynup/kpatch/issues/1320)를 참고한다.

이 커널에서 보안 수정이 필요하면 Debian의 정식 서명 커널 업데이트를 설치하고 계획된 재부팅 후 `uname -r`로 새 커널이 실행 중인지 확인한다. 이는 `.ko` 라이브패치 적용과 별개의 운영 절차다. 공식 `trixie-backports`에서는 `7.3.4-1~bpo13+1`의 AMD64 헤더에 IBT와 `CONFIG_KLP_BUILD=y`가 함께 있는 것을 확인했다. 그러나 이는 다른 커널로 전환하는 것이며, stable과 보안 업데이트 제공 정책도 다르다. 이 구현에서는 backports로 자동 전환하지 않으며 해당 커널의 모듈 빌드나 실기 동작을 검증하지 않았다.

## 릴리스 선택

Debian은 bookworm의 기본 6.1, trixie의 기본 6.12만 받는다. 정식 suite 또는 대응하는 security suite의 InRelease 서명 지문, Codename, SHA256 색인, 정확한 linux-image의 Built-Using과 버전, linux 소스, orig·debian.tar·DSC를 확인한다. dpkg-source -x가 quilt를 적용하고, 패치와 changelog를 Git blob과 대조한다. 이 환경에서는 DSC 개인 서명자의 공개키가 없어 dpkg-source가 경고했으며, DSC와 모든 입력 파일은 서명된 Sources의 SHA256으로 인증했다. Bookworm 이미지의 `Source: linux-signed-amd64 (6.1.192+3)`와 `Built-Using: linux (= 6.1.192-3)`은 서로 다른 필드다. 일반 bookworm 브랜치 tip `e2b17dbb`에는 미출시 변경이 있었다. Bookworm의 linux-6.12, backports, testing, RT, cloud 이미지 및 다른 arch는 대상 밖이다. ABI에 `+deb13.1`이 붙으면 다른 ABI로 검사한다. [Debian packaging Git](https://salsa.debian.org/kernel-team/linux) · [Debian 아카이브 키](https://ftp-master.debian.org/keys.html)

실제 bookworm stable `6.1.176-1`(`6.1.0-50-amd64`, commit `1e55d42705efc34abffa49deeb9c434397315899`)과 bookworm-security `6.1.192-3`의 서명된 릴리스를 풀어 `fs/ext4/mballoc.c`의 변경 11,410바이트(SHA256 `d7619f2cfd5bfc1dc7801cd96182e3d522d8769d414fd0e1f53e9de73989e7f0`)를 추출했다. bookworm-security의 서명 Packages에서 `6.1.192-1`, `6.1.192-2`, `6.1.192-3`의 AMD64 ABI는 각각 -55, -56, -57이다. -57에 6.1.192-1을 조합한 계획은 차단된다. 서명 메타데이터 유효기간과 해당 이미지의 패키지 기록을 함께 보관해야 한다.

Rocky는 r9 또는 r10의 `patched/rN/kernel-<version-release>`와 BaseOS의 서명된 SRPM·kernel-core를 대조한다. 저장소 HEAD는 r8이다. SRPM 내 spec·소스와 Git blob 및 .kernel.metadata의 lookaside SHA256을 대조하고 %dist를 정확히 펼쳐 같은 NVR인지 검사한 뒤 rpmbuild -bp를 실행한다. 원격 lookaside를 따로 다운로드할 필요 없이 서명 SRPM에서 원본 tar를 추출한다. 별도 r9-security/r10-security의 태그 없는 재빌드와 BaseOS는 다른 계통이다. 예를 들어 `.el10_3.0.1` 및 `.el10_3.0.2`에 대응하는 불변 릴리스가 확인되기 전에는 계획이 거부된다. Rocky 10 실행 호스트와 빌더 VM에는 x86-64-v3 CPU 기능이 필요하다. 배포판 명칭 amd64/x86_64는 트랙에서 amd64로 정규화한다. [Rocky dist-git](https://git.rockylinux.org/staging/rpms/kernel) · [Rocky 공식 패키지](https://dl.rockylinux.org/pub/rocky/)

Rocky 10 kernel-core의 config에는 로컬 빌드를 위해 지운 CONFIG_SYSTEM_TRUSTED_KEYS와 원래 값이 함께 기록돼 있다. 빌더는 서명 SRPM의 spec과 %prep의 x86_64 설정에서 원래 값을 확인하고 `certs/rhel.pem`을 복원한다. 이 파일은 Rocky SRPM이 제공한 인증서 네 개이며 첫 인증서 주체는 Rocky Enterprise Software Foundation이다. 정식 커널에 내장된 DER 목록과 바이트가 같았다(Rocky 10 SHA256 `149a966760426282c1a5fdb3455b6ce330ff17a4d351efcd11dc4c1f5d4fdc0f`). 전체 빌드에는 같은 공식 vmlinux에서 추출한 모듈 서명 공개 인증서(SHA256 `81c3ac04063fb97038c2a13cc25962fd1812269f33988217e2c25112f98555de`)를 Kbuild에 제공한다. 실제 make certs/에서 동일한 인증서를 확인했다. 알려지지 않은 설정 수정이나 컴파일 후 Kconfig 차이는 승인 전 오류로 처리한다.

## 빌더 준비와 입력 고정

빌더는 전용 비특권 사용자와 해당 정식 릴리스의 격리된 VM 또는 rootless 컨테이너를 사용한다. Debian은 공식 archive keyring으로 검증한 signed apt root, Rocky는 해당 배포판 키로 CHECKSUM 서명과 OCI 이미지 SHA256을 확인한 root에서 준비했다. 신뢰하는 원본 배포 환경에서 소스와 빌드 툴을 읽기 전용으로 제공하고, 매번 별도의 쓰기 가능한 작업 디렉터리를 제공한다. 패키지를 실행 호스트에 설치할 필요는 없다.

- Debian 빌드 이미지에는 배포판의 git, python3, dpkg-dev, gpgv, gcc, make, binutils, kmod, libelf-dev, libssl-dev, bc, bison, flex, cpio, xz-utils, zstd, dwarves 및 필요한 커널 build dependencies를 준비한다. 예시 GCC 버전은 bookworm `gcc-12 (Debian 12.2.0-14+deb12u1) 12.2.0`, trixie `x86_64-linux-gnu-gcc-14 (Debian 14.2.0-19) 14.2.0`이다.
- Rocky 격리 이미지에서 공식 BaseOS/AppStream/CRB와 배포판 키를 사용해 rpm-build, rpmdevtools, cpio, git, gnupg2, gcc, make, elfutils-libelf-devel, kmod, 패키징 매크로와 정확한 SRPM의 BuildRequires를 준비한다. `dnf builddep /path/kernel-<NVR>.src.rpm`으로 의존성을 확인한다. Rocky 10 klp-build에는 patchutils(recountdiff), xxhash-libs와 xxhash-devel 0.8 이상이 필요했다. 두 xxhash 패키지는 Rocky 10 공식 devel 저장소의 서명된 0.8.2-11.el10이었다. 고정한 실제 GCC는 Rocky 9 11.5.0-17, Rocky 10 14.4.1-5였다.
- `make dist`의 dist/builder에서 kpctl-builder를 PATH에 두고 두 Python 파일을 같은 디렉터리에 둔다. CONFIG_KLP_BUILD가 없는 경우에는 해당 환경에서 repo의 고정 kpatch `e0a8f7c681964e9128449446a34f7f3e631a8621`에 `bash kpctl-kpatch-fixes.sh /src/kpatch`를 실행하고 make로 빌드해서 kpatch-build와 helper를 설치한다. 정확한 컴파일러, 설정, 디버그/CRC, 참조 모듈 중 하나라도 없으면 작업 오류가 반환된다. Bookworm 전체 baseline 컴파일의 certs 단계는 패키징 전용 output/signing_key.pem을 요구했다. 빌더는 인증된 vmlinux의 __module_cert_start/end와 module_cert_size를 대조해 정확한 내장 공개 인증서만 복원한다. 실제 Bookworm 빌드에서 make certs/가 원래 모듈 서명 인증서 SHA256 `25afe670c0e5211989968deaf68c8ede93808d093ac146e5a102468dd942970d`를 재현했다. 기존 C 파일 변경을 모두 포함하는 디렉터리만 컴파일하는 `build_dirs`를 시험했다. 헤더·새 파일·삭제·rename 또는 다른 소스에서 include하는 C 파일이 있으면 전체 빌드가 필요하다. IBT를 거부한 trixie에서는 호환되는 빌드 도구를 검증할 때까지 공식 업데이트 커널로 전환한다. LIVEPATCH가 비활성인 정식 패키지는 설치 및 prepare 단계에서 차단된다.

신뢰한 로컬 Git checkout에 다음 ref를 가져온다. shallow checkout에서는 ancestry 검사가 실패할 수 있다. 헤드의 후보를 먼저 읽고 배포한 버전 태그의 peeled commit을 계획에 적는다. 오프라인 작업에는 관련 태그, 커밋, blob까지 가져온 checkout을 사용한다.

```sh
git clone --no-checkout https://salsa.debian.org/kernel-team/linux.git /inputs/debian-linux
git -C /inputs/debian-linux fetch origin refs/tags/debian/6.1.192-3:refs/tags/debian/6.1.192-3
git -C /inputs/debian-linux rev-parse 'refs/tags/debian/6.1.192-3^{commit}'
git clone --no-checkout https://git.rockylinux.org/staging/rpms/kernel.git /inputs/rocky-kernel
git -C /inputs/rocky-kernel rev-parse 'refs/tags/patched/r9/kernel-5.14.0-741.27.1.el9_9^{commit}'
```

실제 컴파일한 Debian 12 기준 계획 base.json은 다음과 같다. 각 배포판의 자체 keyring을 사용한다. Rocky는 릴리스 공식 단일 ASCII-armored 공개키 파일을 지정한다. fixed.json에는 같은 계통의 이후 출시된 패키지와 대응하는 commit을 넣는다. 이 예에서는 base.json을 복사해 suite를 `bookworm-security`, abi를 `6.1.0-57-amd64`, version을 `6.1.192-3`, revision을 위 표의 `1c45e37e…` 전체 값으로 바꾼다.

```json
{
  "distro": "debian", "release": "12", "suite": "bookworm",
  "abi": "6.1.0-50-amd64", "version": "6.1.176-1",
  "revision": "1e55d42705efc34abffa49deeb9c434397315899",
  "git": "/inputs/debian-linux", "keyring": "/usr/share/keyrings/debian-archive-keyring.gpg",
  "jobs": 4, "build_dirs": ["kernel/time"]
}
```

Rocky 9에서 실제 컴파일한 별도 사례의 base.json은 다음과 같다. fixed.json에는 `5.14.0-741.27.1.el9_9`의 ABI 및 위 표의 전체 commit을 사용하고, 다음 명령의 --path를 `mm/damon/ops-common.c`로 바꾼다.

```json
{
  "distro": "rocky", "release": "9", "suite": "BaseOS",
  "abi": "5.14.0-741.24.1.el9_9.x86_64", "version": "5.14.0-741.24.1.el9_9",
  "revision": "8545ab18a43ed091d9e92474fc68260957b3f807",
  "git": "/inputs/rocky-kernel", "keyring": "/etc/pki/rpm-gpg/RPM-GPG-KEY-Rocky-9",
  "jobs": 4, "build_dirs": ["mm/damon"]
}
```

Rocky 10의 위와 같은 BaseOS 계획에는 `release=10`, 기준 버전 `6.12.0-264.20.1.el10_3`, 기준 commit `109ca28ad1835f6f597dbfb8d547b750d2a3482d`, `RPM-GPG-KEY-Rocky-10`을 지정한다. ABI는 버전 뒤에 `.x86_64`를 붙인다. fixed 계획에는 표의 `.21.1` 버전·ABI·commit을 넣고 `--path mm/truncate.c`를 사용한다. in-tree klp-build는 기준 커널과 모듈 오브젝트 전체를 빌드하므로 build_dirs를 생략한다.

## 후보 검토와 작업 실행

`history`는 공식 Git 브랜치의 패키징 커밋, 제목 및 해당 태그를 나열한다. `changes`는 서명된 두 소스 트리의 C, 헤더, 어셈블리, Kconfig·Kbuild 차이를 열거한다. 커널 changelog, Debian quilt 또는 Rocky spec의 수정 내역을 확인하고 하나의 수정에 필요한 모든 파일을 선택한다. candidate는 선택한 C·헤더·어셈블리 파일의 추가·수정·삭제를 보존한다. Kbuild 및 Kconfig 변경은 별도 검토가 필요하다. 전체 tarball 업데이트에서 같은 파일에 섞인 수정과 다른 디렉터리의 의존성은 사람이 확인한다. 아래 명령은 Debian 12에서 검증한 시간 처리 코드 변경을 사용한다. `--cve`는 검토한 식별자마다 선택해서 준다. collect는 기존 활성 패치와 함께 시험 컴파일·검증한 뒤 해당 정식 트랙으로 보낸다. 같은 패키징 commit의 별도 후보는 diff SHA256으로 식별한다.

```sh
umask 077
mkdir -p /work/cache /work/tmp
driver=/opt/kpctl/builder/kpctl-native-builder.py
args=(--plan base.json --cache /work/cache --work-dir /work/tmp)
python3 "$driver" history --plan base.json
python3 "$driver" prepare "${args[@]}" --fetch > base-proof.json
python3 "$driver" fixed-proof "${args[@]}" --fixed fixed.json --fetch > fixed-proof.json
python3 "$driver" changes "${args[@]}" --fixed fixed.json
python3 "$driver" candidate "${args[@]}" --fixed fixed.json --path kernel/time/time.c > review.patch
python3 "$driver" collect "${args[@]}" --fixed fixed.json --path kernel/time/time.c --title '검토한 배포판 수정 제목' --controller worker.json
python3 "$driver" work "${args[@]}" --controller worker.json --proof base-proof.json
```

worker.json은 `controller_url`(HTTPS), `ca_file`, `token_file`, `builder`(고유 이름)을 갖는다. work는 한 번 조회하여 한 작업을 처리하므로 해당 환경의 스케줄러에서 주기적으로 실행한다. 동시 실행은 환경별 flock으로 직렬화할 수 있다. 캐시는 관리자가 소유하고 메타데이터 세대마다 새 디렉터리를 만든다. --fetch가 없으면 누락 파일에 경로가 표시된다. 패키지 404, 만료된 서명, 다른 키, sha256 불일치, 불명확한 태그, build ID나 컴파일러 불일치가 있는 상태에서는 새 모듈을 승인할 수 없다.

운영자가 빌드 가능한 트랙에 대해 독립된 신뢰 환경에서 동일 계획으로 prepare를 다시 실행하고, 그 JSON의 track과 대상 `kpctl-agent -identify` 출력을 대조한다. 그 결과를 컨트롤러 데이터 디렉터리의 `distribution-proofs/<track>.json`에 컨트롤러가 읽을 수 있는 권한으로 설치한다. 같은 독립 환경에서 base와 fixed 계획으로 fixed-proof를 실행해 두 정식 릴리스의 Git ancestry 및 배포판 버전 증가를 확인한다. 그 JSON을 같은 디렉터리 아래 `<track>/<fixed-commit>.json`에 둔다. 일반 builder API에는 승인 핀 쓰기 권한이 없다. 승인 시 Git commit·서명 키 지문·SRPM/DSC·패키지 해시·실행 identity가 제출된 빌드와 모두 일치해야 한다.

## 공식 릴리스와 수정 파일 발견

`discover`에는 커밋, ABI, 패키지 버전, 수정할 파일을 넣을 필요가 없다. suite.json에는 distro, release, suite, git(공식 저장소의 로컬 checkout), keyring만 지정한다. Git 태그와 해당 원격 추적 브랜치의 이력을 먼저 받아 둔다. Debian은 서명된 Packages의 기본 이미지와 Built-Using을 Sources의 linux 버전, Salsa 릴리스 태그·브랜치 조상과 대조한다. Rocky는 배포판 환경에서 r9/r10의 최신 릴리스 태그 중 `--limit`개를 검사하고, 서명된 BaseOS SRPM·kernel-core와 spec·소스가 확인된 계획만 출력한다. 태그나 패키지가 빠진 릴리스는 stderr에 사유가 남는다. 출력은 줄마다 별개의 JSON 계획이다.

```sh
python3 "$driver" discover --plan suite.json --cache /work/cache --work-dir /work/tmp --fetch > plans.jsonl
jq -r '[.abi,.version,.revision] | @tsv' plans.jsonl
jq -c 'select(.version=="6.1.192-1")' plans.jsonl > base.json
jq -c 'select(.version=="6.1.192-2")' plans.jsonl > fixed.json
python3 "$driver" changes --plan base.json --fixed fixed.json --cache /work/cache --work-dir /work/tmp --fetch
```

2026-11-28 KST의 공식 bookworm-security에서 확인한 출력 일부다.

```text
6.1.0-55-amd64  6.1.192-1  3d8e2f4856a4abed3a630d525048bfd94e0fa494
6.1.0-56-amd64  6.1.192-2  d626510210e97b5339e53237d29c553088dc4548
6.1.0-57-amd64  6.1.192-3  1c45e37eb6cae0a32f9e36a11ea799cddd6b3eaf
modified        fs/ext4/mballoc.c
```

`changes` 출력은 앞의 두 릴리스에 대한 재현 결과다. 제목, 필요한 전체 파일 집합, 패치 간 의존성과 CVE 관련성은 검토자가 판정한다. 도구는 CVE를 추정하지 않는다. Debian 13에서는 `discover`, `history`, `changes`, `candidate`, `inspect`로 조사한다. `inspect`는 패키지·실행 이미지 증거 확인용이다. stock 6.12의 `prepare`, `candidate-proof`, `collect`, `work`, 배포 승인은 차단된다.

## 후보 본문 승인과 연속 업데이트

독립 검토 환경에서 base·fixed에 더해 선택한 파일 집합의 `candidate-proof`를 만든다. 기존 prepare와 fixed-proof도 함께 필요하다. 서명 출처, 대상 트랙, 수정 릴리스, 경로, diff SHA256, 후보 ID, 검토한 CVE 목록과 증분 선행 후보 ID를 확인한다. CLI 패치 목록과 웹의 패치 출처 열에서 후보 ID와 배포판 서명 키 지문을 대조한다.

```sh
python3 "$driver" candidate-proof "${args[@]}" --fixed fixed.json --path fs/ext4/mballoc.c > candidate.json
track=$(jq -r .base.track candidate.json)
rev=$(jq -r .fixed.revision candidate.json)
sha=$(jq -r .sha256 candidate.json)
jq '{candidate_id,paths,cves,parent_candidate,signer:.fixed.signer}' candidate.json
# 컨트롤러 관리자가 관리 전용 경로에서 실행한다.
install -d -m 0750 "$DATA/distribution-proofs/$track/$rev"
install -m 0640 candidate.json "$DATA/distribution-proofs/$track/$rev/$sha.json"
```

`$DATA`는 컨트롤러 데이터 디렉터리다. 승인 핀은 독립 검토자가 인증한 통로로 전달하며 builder 토큰으로 쓸 수 없다. 제출된 본문의 SHA256은 후보 ID에 들어간다. 컨트롤러는 작업을 배정할 때 보존한 파일을 재검사한다. 승인 직전과 서명·VM 검사 후 배포를 게시하기 직전에 각 파일의 SHA256과 경로, 계통, CVE, 선행 후보를 독립 핀과 대조한다. 키 교체로 이전 누적본을 새로 서명하는 경우에도 그 버전의 핀이 필요하다. 같은 릴리스의 서로 다른 diff는 개별 핀을 갖는다. 기존 릴리스 핀만 남은 과거 작업은 본문을 독립 검토하고 새 누적본을 승인해야 새 호스트가 받는다. 이미 로드된 보호는 유지된다.

컴파일된 커널 모듈이 검토한 소스와 diff에서 만들어졌다는 보증은 지정한 빌더의 격리와 무결성에 의존한다. 컨트롤러의 독립 핀과 CMS 검증은 바이너리를 재현 빌드하지 않는다. 운영에서는 빌더 토큰과 배포판별 빌드 환경을 그 신뢰 경계 안에서 관리한다.

같은 파일 집합에 다음 정식 업데이트가 나오면 기준 호스트의 base.json을 유지한다. 직전 후보의 fixed.json과 독립 핀을 보존하고 다음과 같이 차이만 추가한다.

```sh
chain=(--previous fixed.json --parent-pin candidate.json --fixed next.json --path fs/ext4/mballoc.c)
python3 "$driver" candidate-proof "${args[@]}" "${chain[@]}" > next-candidate.json
python3 "$driver" collect "${args[@]}" "${chain[@]}" --title '검토한 다음 수정' --controller worker.json
```

다음 수정의 fixed-proof와 candidate-proof도 위 경로에 별도로 설치한다. 직전 패키지와 다음 패키지의 서명·순서·Git 조상 관계를 확인하고 직전 소스에서 다음 소스로 가는 diff를 만든다. 동시 수집 사이 활성 목록이 달라지면 409가 반환되므로 최신 목록에서 collect를 다시 실행한다. 동일 후보 재시도는 중복 작업을 만들지 않는다. 다른 파일의 독립 후보는 작업에 남는다. 보류·빌드 실패 시 링의 기존 승인 버전이 유지된다. 여러 경로의 선행 후보가 서로 다르면 동일 선행 후보를 공유하는 파일 집합으로 나누어 검토한다.

캐시에 만료된 InRelease, 손상된 색인·패키지나 서명에 실패한 RPM이 있으면 `--fetch`로 공식 출처에서 다시 확인한다. 서명·유효기간 검사를 통과한 새 메타데이터와 RPM, 서명 색인에 지정된 해시가 일치한 파일만 재사용한다. 공식 파일이 회수됐거나 키가 일치하지 않으면 새 빈 `--cache` 디렉터리에서 원인을 확인한다. 기존 승인 핀과 다른 새 세대는 독립 검토가 필요하다.

## 실제 대상 설치 및 Secure Boot canary

Debian 13에서는 상태 보고 에이전트를 설치할 수 있다. 보호 상태와 IBT 설정을 유지하면서 Debian 서명 trixie-security를 사용하는지 `apt-cache policy linux-image-amd64`로 확인하고 `apt-get update`, `apt-get install --only-upgrade linux-image-amd64`로 정식 보안 커널을 준비한다. 유지보수 시간에 계획된 재부팅 후 `uname -r`, 설치 패키지 버전 및 `kpctl-agent -identify` 결과를 확인한다. 설치된 메타패키지가 없는 시스템은 관리자가 정식 기본 커널 메타패키지를 선택해야 한다.

실행 커널의 식별에 실패하면 에이전트는 사유·uname·관측한 활성 모듈을 계속 보고한다. 에이전트는 Debian의 /boot/vmlinuz 및 Rocky kernel-core가 설치한 /lib/modules/<ABI>/vmlinuz에서 ELF GNU build ID를 추출해 실행 메모리와 대조한다. 식별이 회복된 새 보고가 수락될 때까지 적용·롤백·커널 준비·재부팅을 보류한다.

1. 전용 canary VM에 정식 배포판 이미지와 일치하는 패키지를 설치하고 해당 커널로 부팅한다. `uname -r`, `mokutil --sb-state`, `cat /sys/kernel/security/lockdown`과 `grep '^CONFIG_LIVEPATCH=' /boot/config-$(uname -r)`를 기록한다. 해당 커널의 /lib/modules 트리도 보존한다.
2. 컨트롤러에서 `sudo kpctl install -check -group canary node-01` 다음 `sudo kpctl install -group canary node-01`을 실행한다. 에이전트가 정식 패키지와 실행 메모리의 build ID를 확인한다. Rocky는 dnf, Debian은 apt로 필요한 런타임을 준비한다. 네이티브 호스트에서는 부팅 후 kpctl-agent.service가 컨트롤러에 연결하고 완전한 트랙을 다시 확인하고 나서 적용한다. 컨트롤러 연결이 끊긴 부팅에는 적용이 지연된다. Ubuntu 전용 디스크 커널 준비·자동 재부팅·Canonical 서비스 설정은 사용하지 않는다.
3. 컨트롤러에서 Ubuntu 헤더별 경로를 쓰던 경우 공통 키의 sign_command 실행 파일을 컨트롤러 자체에 설치된 고정 절대 경로(예: Ubuntu shim-signed의 `/usr/bin/kmodsign`)로 지정한다. 인수는 `sha256`, 공통 개인키, DER, `{module}` 순서다. 동일 명령으로 Ubuntu와 네이티브 모듈을 서명하고 CMS를 독립 검증한다. 전용 래퍼에 `{kernel}`은 대상의 uname ABI, `{track}`은 전체 트랙이다. 개인키는 컨트롤러 서비스 계정만 읽는다. `sudo kpctl signing list`로 운영 키를 확인하고 `sudo kpctl signing rollout-cert -host node-01 prod-2026`, `sudo kpctl hosts mok-status node-01`을 실행한다. 예약을 확인한 뒤 별도로 승인된 재부팅에서만 콘솔 MokManager로 등록한다. `mok-password`는 비공개 터미널에서 해당 호스트용 값만 조회한다. 재부팅 후 enrolled 보고와 Secure Boot on 상태를 확인한다. [공통 서명·MOK 콘솔 절차](secure-boot.md#mok-enrollment)
4. 시험 VM 이미지에 같은 공식 커널과 최신 `/usr/local/bin/kpctl-agent`를 준비한다. SSH 사용자도 해당 이미지에 맞춘다. testvm 이미지 매핑 키는 prepare가 출력한 전체 track이다. sb_on 시험에서는 펌웨어, enforcement, 미서명 거부, 정확한 서명 바이트, 전환·롤백과 커널 로그를 남긴다. `kpctl patches -kernel "$TRACK"`, `kpctl jobs`, `kpctl log "$JOB"`에서 결과를 확인한 뒤 `sudo kpctl approve "$JOB"`을 실행한다. 운영 canary에서 모듈 서명 거부가 있으면 서명 키링 및 커널 로그를 확인하고 승급을 보류한다.
5. 권한 있는 실기 시험에서 `kpctl hosts`, `kpatch list`, `cat /sys/kernel/livepatch/$MOD/transition`, `modinfo -F signer /var/lib/kpctl-agent/modules/$MOD.ko`와 해당 파일 SHA256을 대조한다. canary를 관찰한 뒤에만 다음 링으로 승급한다. 패키지 리비전이나 build ID가 달라지면 새 트랙을 준비한다. 제거 시 기본 uninstall은 현재 부팅에 올라간 모듈을 유지하고 에이전트 상태와 다음 부팅 적용 경로를 제거한다.

이번 검증에서는 공용 릴리스 자료와 격리 작업 디렉터리만 사용했다. OpenSSL CMS 서명·호스트별 MOK 선택과 잘못된 대상 거부는 자동시험 결과다. 실기 MOK 등록, 부팅, 커널 로드 및 운영 호스트 배포는 수행하지 않았다.

## 공식 변경으로 검증한 경로

| 기준 패키지 → 수정 패키지 | 선택한 정식 변경 | 실제 누적 모듈 SHA256 | 검증 |
|---|---|---|---|
| Debian 12 `6.1.176-1` → `6.1.192-3` | `kernel/time/time.c` · diff `e835f5c6aec83bae008d143582bac841943587218a415e6dae43525fee8f9174` | `305d744b4f377f529035117aff6b84b78f5a54f1744362d87790841cf532834a` | 이전 ABI 대상, CRC 13개 |
| Rocky 9 `5.14.0-741.24.1.el9_9` → `5.14.0-741.27.1.el9_9` | `mm/damon/ops-common.c` · diff `b8e27cd238add7b25f4a97e523d3bead59800d9487db42c726e4cfdaec7a2786` | `b4188854ece1ed363c6487f91979ab7394fe5248d0941a5b9b37f3f250d463f5` | 이전 ABI 대상, CRC 12개 |
| Rocky 10 `6.12.0-264.20.1.el10_3` → `6.12.0-264.21.1.el10_3` | `mm/truncate.c` · diff `99eba1fadeccd58424c99f8469ddd425dbc8882ffb82e54c64705dd46dbaa75a` | `a178892e12fdf453f9ee3fb8c32cd4f58d4ea85b4fec83bec360faa3aab90279` | 이전 ABI 대상, CRC 18개 |

Rocky 9 기준 커밋은 `8545ab18a43ed091d9e92474fc68260957b3f807`이다. Debian 12와 Rocky 9의 정식 빌더 환경에서 실제 collect와 work를 임시 HTTPS 컨트롤러에 연결해 다시 실행했다. collect는 서명 입력 두 개를 풀어 diff를 만들고 시험 컴파일 후 등록했다. work는 작업을 수신해 기준 패키지를 다시 검증하고 별도 누적 빌드 결과를 제출했다. Ubuntu kmodsign으로 서명한 사본의 승인 후 호스트 토큰으로 다운로드한 SHA256은 각각 `096b7454f63611b7b57d92c7759eb93dafb845703d0f835fbaf6659e60115b83`, `43e97039ca0efc2ef912ea82b2bc653065fbb6a13a0be4c6b47a7fab7118891b`였다. 소스·패키지·컴파일러·모듈·HTTP·CMS는 실제이며 호스트 상태와 MOK 등록 보고는 모의 데이터, 키는 일회용이다. Debian 12의 별도 ext4 파일 단독 시행은 `ext4_buddy.bd_buddy_folio` 선언이 없어 컴파일에서 거부됐다. 이 변경을 운영에 승인하지 않았다.

Debian 13 stable `6.12.117-1`(`f142d2e2e48fc8d4b59383e775ac7d8414173066`)과 security `6.12.118-1`의 서명 입력을 사용한 오프라인 changes 결과는 658개였다. Rocky 10 기준 `6.12.0-264.20.1.el10_3`의 Git 커밋은 `109ca28ad1835f6f597dbfb8d547b750d2a3482d`, 서명 SRPM SHA256은 `3474f8e856e03d898eeea0a2a4f706da330f0b0fca794a515c0f1e02bc2d29b0`이다. 이전 릴리스의 정식 config와 GCC로 다시 빌드한 Module.symvers는 심볼 25,275개 전체가 서명 kernel-devel 파일과 바이트 단위로 일치했다(SHA256 `3e0d89edbf53d54ff5505d795029aede0be6a141f601956e6cd41108918ab556`). 두 릴리스의 %prep 트리를 대조해 x86 이외의 arch 디렉터리를 제외한 뒤 9개 경로를 찾았다. 공통 drivers/ 아래의 ARM 전용 변경도 목록에 남으므로 적용 가능 여부는 config와 실제 빌드로 확인한다. `net/ipv6/sit.c` 정식 diff SHA256은 `7bdbac634e3c49716d1b8a4560caec65a2088ade6e72eea4e1121b54f6e4a410`이다. Rocky 공식 klp-build가 이 수정으로 모듈을 생성했지만 ELF의 `.klp.rela.net/ipv4/ip_tunnel..text`가 커널 모듈 이름 대신 경로를 참조했다. 독립 검증에서 이 후보를 거부했고 서명·승인하지 않았다. trixie main에서 배포하는 kpatch-build 0.9.10-1로 실제 빌드를 시도해 IBT 거부를 재현했다. 프로젝트가 고정한 kpatch 소스도 같은 Kconfig 검사를 수행한다. Debian 커널 팀의 프로젝트 기록에도 이 제약이 명시돼 있다. [Debian 커널 팀의 빌더 검토](https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1070494#12) · [trixie kpatch-build 검사 코드](https://sources.debian.org/src/kpatch/0.9.10-1/kpatch-build/kpatch-build/)

Rocky 10은 `.20.1` SRPM에 포함된 klp-build로 기준 vmlinux와 모듈을 컴파일했다. 원래 오브젝트를 보존해 같은 도구의 `--short-circuit=2`로 `mm/truncate.c` 수정을 컴파일했고, 도구가 보고한 변경 함수는 `truncate_inode_partial_folio`였다. 공식 config·공개 인증서, 전체 vermagic, livepatch ELF, 외부 심볼 CRC 18개를 검증했다. 이 실제 모듈을 Python HTTPS 작업 제출 경로에서 재사용해 독립 핀 승인과 Ubuntu CMS 서명 후 모의 등록 호스트가 다운로드했다(서명본 SHA256 `7636930bf74c8e01f25ac00cd529cf99d236f1589d46fa802ecc0e0b3485c978`). Rocky 10의 이 통합 시험에서는 두 번째 컴파일 호출을 이미 검증한 결과로 대체했다.

| Debian 서명 색인 | 확인한 InRelease SHA256 |
|---|---|
| bookworm | `77737fa4b34f2693e982cc9ee35736816c35a7778fc2d326cc1bbf5b301fe1aa` |
| bookworm-security | `7276f8ad3a56df57e6501a554af49923a4371b77983cfe1db28d4606da14d50f` |
| trixie | `bfacad4ca61899ce20d4a0d439f29339f66541561b67506364efb88e27dee870` |
| trixie-security | `17fb20dc37dc8509a64fd79f9d5a484038c9f47cc8bed7cae912f47491e18bb6` |

네 대상 모두 실제 배포판의 dpkg-query 또는 rpm, 서명된 패키지의 메타데이터, 공식 디버그 ELF에서 추출한 커널 노트를 사용해 격리된 파일시스템에서 `kpctl-agent -identify`를 실행했다. /proc와 /sys는 해당 입력으로 구성한 시험 파일이다. Rocky에서 kernel-core NEVRA로 직접 조회하고 패키지명·arch·epoch·버전을 확인한다. 에이전트 출력 네 개 모두 독립 prepare 트랙과 일치했다. 서명된 배포판 mokutil에서 MOK와 펌웨어 DB를 구분하는 조회와 hash-file 옵션도 확인했다. 사용한 프로그램 버전은 Debian 12 `0.6.0-2`, Debian 13 `0.7.2-1`, Rocky 9 `0.7.2-6.el9_9`, Rocky 10 `0.7.2-7.el10_3`이다.

## 최초 구현의 회귀 검증

- 오프라인 패키지 시험은 두 Debian suite에 대해 소형 orig tar·quilt 패치를 만들고 InRelease에 시험키로 실제 서명한다. Packages·Sources 해시와 dpkg-source 적용 결과를 검사한다. 두 Rocky 릴리스에서는 작은 실제 SRPM·RPM에 시험 서명을 하고 dist-git 태그·lookaside·spec·%prep·DWARF 입력을 검사한다. 이 시험의 ELF는 사용자 공간 fixture다.
- 최초 구현에서는 네 조합에 대해 에이전트 식별, Git 태그·ancestry, trial 컴파일러 호출, HTTP 작업 배정과 모의 호스트 적용을 시험했다. 후속 검토 이후 Debian 13은 조사 전용이며 해당 조합의 배정·승인·적용 성공 fixture를 차단 시험으로 교체했다. 설치·제거 전체 스크립트는 별도 파일시스템과 네트워크 네임스페이스에서 패키지 도구와 systemd를 대체해 실행한다.
- `make test`는 Go 전체 및 race, Python, Ubuntu GA/HWE와 CMS·MOK E2E, QEMU 스크립트 ShellCheck, 웹 시험과 Go 내장 번들 일치 검사를 실행한다. 호스트의 모듈 목록과 네트워크를 격리해 실행했다. Go 전체·race, 웹 62개, Ubuntu E2E와 내장 번들 검사를 통과했다. Python 157개 중 156개가 이 실행에서 통과했다. 중첩 네임스페이스 제약으로 건너뛴 설치·제거 시험 한 개는 별도 실행에서 네 배포판 모두 통과했다. `make dist` 뒤 두 Python 드라이버와 에이전트 설치 스크립트가 배포 묶음에 원본 그대로 포함됨을 확인했다. 패키지 도구가 없는 CI에서는 해당 실제 archive 시험이 skip될 수 있으므로 rpmbuild, rpmsign, rpmkeys, cpio, dpkg-source, gpg, cc, bwrap의 제공 여부를 확인한다.
- 실기 시험이 허용될 때까지 남는 검증은 대상 배포판별 UEFI에서 승인 키 등록, 부팅 후 커널 키링 신뢰, 실제 서명 모듈 로드·전환·재부팅 복구·롤백이다. 공개키/ELF 검사와 모의 VM의 부팅 인자 대조 결과만으로 이 단계를 완료 처리하지 않는다.

## 독립 리뷰 후속 검증

2026-11-28 KST에 Debian의 공식 Salsa 태그와 서명된 bookworm·bookworm-security 색인으로 `discover`를 실행했다. 정식 패키지와 Git 사이의 대응이 없는 태그는 후보에서 제외됐다. 서명된 Sources의 SHA256으로 .dsc와 구성 파일을 검증했다. 격리 환경의 dpkg-source는 일부 업로더의 개인 키가 없어 .dsc의 추가 인라인 서명을 확인하지 못했다고 출력했다. 이 사례의 인증 근거는 Debian 릴리스 키, Sources 색인과 패키지 해시 체인이다.

| 실제 Debian 12 후보 | 독립 검토와 빌드 결과 |
|---|---|
| `6.1.176-1` / `6.1.0-50-amd64` → `6.1.192-1` / `6.1.0-55-amd64`, `kernel/time/time.c` | 기준 Git `1e55d42705efc34abffa49deeb9c434397315899`, 수정 Git `3d8e2f4856a4abed3a630d525048bfd94e0fa494`. 독립 `candidate-proof`의 diff SHA256 `e835f5c6aec83bae008d143582bac841943587218a415e6dae43525fee8f9174`. 정식 기준의 GCC·config·vmlinux·Module.symvers로 classic 모듈을 만들고 대상 vermagic, livepatch 표식, 외부 심볼 CRC 13개를 확인했다. |
| `6.1.192-1` → `6.1.192-2`, `fs/ext4/mballoc.c` | 실제 `changes`가 출력한 유일한 경로다. 후보 ID `d626510210e97b5339e53237d29c553088dc4548/eb5acf6e4b1ba2da4c8712a912c35f9e920fdbc9412de5bd347528780d7f106a`. 제한 디렉터리 빌드에서 kpatch가 원래의 ext4.ko를 찾지 못해 거부했다. 별도 전체 트리 빌드는 앞 행의 빌드·서명 확인 후 중단했다. 이 후보는 미승인이다. |

독립 환경에서 만든 base·fixed·candidate JSON을 임시 컨트롤러의 관리 영역에 설치했다. 정식 Debian 12 도구 환경에서 수정하지 않은 `collect`가 시험 빌드와 제출을 실행하고 `work`가 배정된 누적본을 다시 빌드했다. 실제 CMS 서명과 바이트 검증 후 임시 호스트의 인증된 다운로드까지 317.44초에 통과했다. 서명본 SHA256은 `8a8e767726818b43a3be0c81f35d9a0d2c675df20ef58166e556fd42184da7ca`였다. 별도로 같은 입력에서 이미 컴파일한 모듈을 재사용한 시험의 서명본 SHA256은 `d5ee7c7df82be5961b1124237c7224c9b2ed98f70da412b8aa542fb0355d08ee`이다. 키는 시험마다 새로 생성하므로 서명본 해시는 달라진다. CVE는 지정하지 않았다.

재현할 때에는 위의 `discover`를 bookworm과 bookworm-security에서 각각 실행하고, 두 버전의 계획을 선택한다. 공식 입력을 확보한 뒤 독립 환경에서 `prepare`, `fixed-proof`, `candidate-proof`와 `candidate`의 결과를 각각 base-proof.json, fixed-proof.json, candidate.json, candidate.patch에 기록한다. 실제 컴파일한 모듈이 있는 격리 Ubuntu 컨트롤러에서는 다음 명령으로 승인과 CMS, 임시 호스트 다운로드를 다시 검사할 수 있다. 서명용 `/usr/bin/kmodsign`과 OpenSSL이 필요하다.

```sh
jq -n --slurpfile base base-proof.json --slurpfile fixed fixed-proof.json \
  --arg pin "$(realpath candidate.json)" --arg patch "$(realpath candidate.patch)" \
  --arg module "$(realpath "$KO")" \
  '{Base:$base[0], Fixed:$fixed[0], Pin:$pin, Patch:$patch, Module:$module}' > release-test.json
KPCTL_TEST_NATIVE_RELEASE="$(realpath release-test.json)" \
  go test -count=1 -v -run '^TestDistributionVerifiedReleaseTransport$' ./internal/controller
```

`KPCTL_TEST_NATIVE_RUNNER=/절대경로/래퍼`를 함께 주면 이미 컴파일한 파일을 재사용하는 부분도 실제 빌드로 시험할 수 있다. 래퍼는 첫 인자의 임시 디렉터리에 있는 `ca`·`token`과 둘째 인자의 루프백 HTTPS 주소로 worker.json을 만들고, 위 절차의 `collect`와 `work --proof`를 순서대로 실행한다. 빌더는 해당 배포판 환경과 검증한 캐시를 읽을 수 있어야 한다. 전체 경로의 재현 시간에 맞춰 Go의 `-timeout`을 지정한다.

**실행 이미지 식별.** 배포판 공식 패키지의 압축 커널 이미지에서 추출한 GNU build ID가 Debian 12 `210cfeaa36862392f72c64cd5b63aa31dd0445c2`, Debian 13 `67e5e727aeb3cb468dfe1bb8f9738f944c3a7d50`, Rocky 9 `b1a25d7182be9a5204a49f4c314a1e97465695c5`, Rocky 10 `7454689549d6bd3ddbf9a694ab9d3cd292e91710`으로 기준 패키지의 디버그 ELF와 일치했다. 실제 호스트 보고에 실패한 순간과 복구 후 동작은 fixture로 검사했다. 에이전트는 식별 실패 중 현재 버전·로드 목록·오류를 보고하며, OS 또는 이미지 근거가 복구된 뒤 컨트롤러 보고가 성공해야 적용을 재개한다. Rocky 두 릴리스의 실컴파일 기록은 앞 절의 최초 구현 검증에 해당한다.

**회귀 재현.** `make GO_TEST_FLAGS=-count=1 test`에는 Go 전체·race, 오프라인 Git/서명 아카이브, Ubuntu GA/HWE 및 CMS·MOK E2E, ShellCheck, 웹·내장 번들 검사가 포함된다. 중첩 네임스페이스가 막히면 설치 분기는 외부 임시 네임스페이스를 생성할 수 있는 환경에서 `PYTHONPATH=test python3 -B -m unittest native_builder_test.NativeFixtures.test_full_native_install_and_cleanup_in_namespace`로 재현한다. 전체 시험에서 Go·race, Ubuntu E2E, ShellCheck와 웹 63개·번들 일치를 확인했다. Python 159개 중 158개가 통과했으며 네 배포판 설치·제거를 다루는 1개는 외부에서 별도 통과했다. 과거 후보 미검증·파일 손상·키 교체, 같은 경로를 바꾼 두 정식 릴리스와 별도 경로의 독립 후보, 오래된 목록의 재시도는 합성 입력으로 검증했다.

**기존 L4.** 비교 대상인 secure-boot-signing과 현재 작업에서 빌더 잠금 디렉터리를 읽기 전용으로 두고 호스트의 설치 커널을 노출하면 동일한 세 실패가 재현됐다. 잠금을 임시 쓰기 가능 경로에 둔 경우 두 수집 시험이 통과했으며, `TestDiskCleanupRunsCachePolicyAfterUnusedKernelPurge`는 두 트리 모두 호스트의 추가 커널을 세어 실패했다. 잠금·설치 커널·로드 모듈 목록을 격리한 전체 시험 결과를 사용했다. 운영 호스트 접속, 실기 MOK, 모듈 로드, 부팅 후 보호 상태 확인은 수행하지 않았다.

### 후속 수정 파일

독립 리뷰 직전 스냅샷 대비 35개 파일을 수정했다. 루트의 `MEMORY.md`와 앞 절의 Debian 13 IBT 조사 내용은 보존했다.

- 식별·상태·설치 — `internal/agent/{agent,distribution,distribution_test,kernel_image,kernel_image_test}.go`, `internal/model/{model,distribution}.go`, `internal/remote/{hostcheck,hostcheck_test,steps}.go`, `cmd/kpctl-agent/main.go`, `deploy/install-agent.sh`.
- 후보·배정·서명 — `internal/controller/{distribution,distribution_test,handlers_admin,handlers_agent,handlers_builder,jobs,rollout,signing}.go`, `deploy/{kpctl-native-builder,native_inputs}.py`, `test/{native_archive_test,native_builder_test}.py`.
- 운영 표시·문서 — `cmd/kpctl/{commands,status,distribution_test}.go`, `web/src/pages/{Hosts,Patches}.jsx`, `web/src/selectors.js`, `web/src/test/security.test.jsx`, `internal/controller/web/app.js`, `README.md`, `docs/development/code-map.md`, 이 문서.

## 변경 검토 기준

기준 HEAD는 `cc7a10e9a6f090e6f2c4a84fe503f6971520c55f`이다. 기존 리뷰 워크트리의 추적 변경분은 `git diff --binary` SHA256 `5dd273266042ec9803808b9607a8881c61fe8094ef66d97dcd03af8851299074`이며 두 워크트리에서 처음 동일함을 확인했다. 기존 미추적 파일 일곱 개만 모드를 보존해 승계했다. 커밋은 만들지 않았다.

### 최초 승계 시 기존 리뷰와 바이트·모드가 같았던 파일

- 루트 `MEMORY.md` (이후 배포판별 최종 재리뷰 결과를 추가함)
- `cmd/kpctl/` `main.go`, `signing.go`, `signing_key.go`, `signing_key_test.go`, `signing_test.go`
- `configs/` `controller.example.json`
- `docs/features/` `signing.md`
- `docs/install/` `controller.md`
- `docs/operations/` `commands.md`, `upgrade.md`
- `internal/agent/` `signing.go`, `signing_test.go`
- `internal/controller/` `module_signature.go`, `module_signature_test.go`, `mok_rollout_test.go`, `server.go`, `signing_admin.go`, `signing_admin_test.go`, `signing_identity_test.go`, `signing_legacy_join_test.go`, `signing_rotation_test.go`, `signing_test.go`, `testvm_artifacts_test.go`, `testvm_test.go`
- `internal/model/` `signing.go`
- `test/fake/` `mokutil`, `sign-file`

### 기존 리뷰 변경 위에 이번 작업을 더한 파일

- 루트 `README.md`
- `cmd/kpctl/` `status.go`
- `docs/development/` `code-map.md`
- `docs/operations/` `secure-boot.md`
- `internal/agent/` `agent.go`, `agent_test.go`
- `internal/controller/` `handlers_admin.go`, `handlers_agent.go`, `rollout.go`, `signing.go`
- `internal/model/` `model.go`
- `test/` `e2e.sh`

### 이번 배포판 작업에서 새로 추가하거나 변경한 파일

- 루트 `Makefile`
- `cmd/kpctl-agent/` `main.go`
- `cmd/kpctl-builder/` `main.go`
- `cmd/kpctl/` `commands.go`
- `deploy/` `install-agent.sh`, `kpctl-native-builder.py`, `native_inputs.py`, `setup-builder.sh`, `uninstall-agent.sh`
- `docs/operations/` `distribution-kernels.md`
- `internal/agent/` `config.go`, `distribution.go`, `distribution_test.go`
- `internal/builder/` `module.go`
- `internal/controller/` `auto.go`, `coverage.go`, `distribution.go`, `distribution_test.go`, `handlers_builder.go`, `jobs.go`, `state.go`, `testvm.go`, `util.go`
- `internal/controller/web/` `app.js`
- `internal/klpcheck/` `check.go`
- `internal/klpcheck/klptest/` `elf.go`
- `internal/model/` `distribution.go`, `distribution_test.go`
- `internal/remote/` `hostcheck.go`, `hostcheck_test.go`, `steps.go`
- `internal/testvm/` `manager.go`, `manager_test.go`
- `test/` `native_archive_test.py`, `native_builder_test.py`
- `web/src/pages/` `Hosts.jsx`, `Overview.jsx`, `Patches.jsx`
- `web/src/` `selectors.js`
