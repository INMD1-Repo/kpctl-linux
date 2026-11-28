// 이 파일: remote 패키지의 HostsEntry, step, run 구현·자료형.
package remote

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"kpctl/internal/model"
)

// Session 은 호스트 한 대에 대한 작업입니다. 실행한 명령과 출력이 Log 에 쌓입니다.
type Session struct {
	SSH    *SSH
	Target string // 접속 대상 (user@host, IP, ~/.ssh/config 별칭)
	Facts  Facts  // Preflight 가 채움
	Log    strings.Builder
	OnStep func(target, msg string) // 진행 상황 표시용 (nil 이면 표시 안 함)
}

// Facts 는 사전 점검에서 알아낸 호스트 정보입니다.
type Facts struct {
	Hostname           string // 에이전트가 이 이름으로 컨트롤러에 등록됨
	UID                string
	Distro             string
	ReleaseType        string
	ReleaseDescription string
	NativePackage      string
	Release            string
	Arch               string
	Kernel             string
	Sudo               string // ok | no
	Livepatch          string // yes | no
	SecureBoot         string
	Controller         string // 호스트에서 본 컨트롤러 /healthz 응답 코드 (000 = 접속 실패, nocurl = curl 없음)
	Agent              string // installed | none
	Role               string // infra(컨트롤러·빌드 서버) | host
	Codename           string // /etc/os-release 의 VERSION_CODENAME (예: noble)

	// 빌드 서버 설치(kpctl install-builder)용
	BuilderActive string // yes | no — kpctl-builder 서비스가 돌고 있는지
	BuilderConfig string // yes | no — /etc/kpctl/builder.json 이 이미 있는지

	// Debian/Rocky 네이티브 빌더 설치용 (native_builder.go 의 nativeBuilderChecks 가 판정)
	NativeBuilderActive string // yes | no — kpctl-native-builder.timer 가 켜져 있는지
	NativeBuilderConfig string // yes | no — /etc/kpctl/native-builder/worker.json 이 이미 있는지
	Virt                string // systemd-detect-virt --vm (none = 물리 서버)
	X86V3               string // yes | no — x86-64-v3 CPU 기능 (Rocky 10 필요)

	// 호스트가 컨트롤러 이름을 DNS 로 찾지 못할 때만 채워집니다.
	// ViaIP 는 SSH 로 접속해 온 주소($SSH_CONNECTION 의 첫 칸 = 호스트에서 본 컨트롤러 IP)로 접속한 /healthz 응답 코드.
	// 에이전트 설치용 (hostChecks 가 판정)
	Container    string // none | lxc | docker ... (systemd-detect-virt --container)
	Systemd      string // yes | no
	Modules      string // yes | no — /lib/modules/<실행 커널>
	Lockdown     string // none | integrity | confidentiality | ""(모름)
	OtherPatches string // kpctl_ 이 아닌 라이브패치 이름들 (Canonical lkp_* 등)
	BootFS       string // "<fstype> <장치>" of /boot/grub/grubenv, GRUB 이 없으면 "none ..."
	Archive      string // 마지막으로 시도한 Ubuntu 미러의 HTTP 응답 코드 (000 = 접속 불가, "" = curl 없음)
	ArchiveVia   string // mirrors.list 의 이름 — 접속된(또는 마지막으로 시도한) 미러
	BootFreeKB   string
	VarFreeKB    string
	Python3      string // yes | no
	Dpkg         string // ok | broken
	Now          string // 호스트 시각 (유닉스 초)

	NameResolves string // yes | no | ip(URL 이 IP 라 확인 불필요)
	ControllerIP string
	ViaIP        string
}

// OSLabel 은 안내문용 OS 표시입니다. 예: "Ubuntu 24.04 (noble)", "Rocky 10.1", "Debian 12 (bookworm)".
// Rocky 처럼 VERSION_CODENAME 이 없는 배포판도 빈 따옴표 대신 릴리스로 보입니다.
func (f Facts) OSLabel() string {
	label := model.DistroLabel(f.Distro)
	if f.Release != "" {
		label += " " + f.Release
	}
	if f.Codename != "" {
		label += " (" + f.Codename + ")"
	}
	return label
}

// HostsEntry 는 설치할 때 호스트의 /etc/hosts 에 넣을 "IP 이름" 입니다. 필요 없으면 빈 문자열.
// 이름을 못 찾지만 SSH 로 접속해 온 컨트롤러 IP 로는 /healthz 가 200 일 때만 씁니다.
func (f Facts) HostsEntry(controllerURL string) string {
	if f.NameResolves != "no" || f.ViaIP != "200" || f.ControllerIP == "" {
		return ""
	}
	name, _ := urlHostPort(controllerURL)
	if name == "" {
		return ""
	}
	return f.ControllerIP + " " + name
}

func (s *Session) step(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(&s.Log, "\n== %s %s\n", time.Now().Format("15:04:05"), msg)
	if s.OnStep != nil {
		s.OnStep(s.Target, msg)
	}
}

// run 은 원격 명령을 실행하고 명령과 출력을 로그에 남깁니다.
// stdin 내용은 로그에 남기지 않습니다 (토큰 같은 비밀값을 넘기는 데 쓰므로).
func (s *Session) run(command, stdin string) (string, error) {
	fmt.Fprintf(&s.Log, "$ %s\n", command)
	out, err := s.SSH.Run(s.Target, command, stdin)
	s.Log.WriteString(out)
	if err != nil {
		fmt.Fprintf(&s.Log, "!! %v\n", err)
		return out, fmt.Errorf("%w\n%s", err, lastLines(out, 15))
	}
	return out, nil
}

// sudo 는 root 가 아니면 "sudo -n " 을 붙입니다. -n: 비밀번호를 묻지 않고 바로 실패.
func (s *Session) sudo() string {
	if s.Facts.UID == "0" {
		return ""
	}
	return "sudo -n "
}

// ─────────────────────────────────────────────
// 1. 사전 점검 (아무것도 바꾸지 않음)
// ─────────────────────────────────────────────

// preflightScript 는 원격에서 읽기만 하는 점검 스크립트입니다. 결과를 key=value 줄로 출력합니다.
// 점검 항목을 추가하려면 여기에 echo 줄을 넣고, Facts 와 Preflight 의 판정을 고치세요.
const preflightScript = `
echo "hostname=$(hostname)"
echo "uid=$(id -u)"
echo "arch=$(uname -m)"
echo "kernel=$(uname -r)"
if [ "$(id -u)" = 0 ] || sudo -n true 2>/dev/null; then echo "sudo=ok"; else echo "sudo=no"; fi
# /boot/config 가 없는 이미지도 있어 /sys/kernel/livepatch(CONFIG_LIVEPATCH 일 때만 있음)도 봅니다
if [ -d /sys/kernel/livepatch ] || grep -qs '^CONFIG_LIVEPATCH=y' "/boot/config-$(uname -r)"; then echo "livepatch=yes"; else echo "livepatch=no"; fi
sb=$(mokutil --sb-state 2>/dev/null | head -1); echo "secureboot=${sb:-unknown}"
if [ -n "$1" ]; then
  if command -v curl >/dev/null 2>&1; then
    # 접속 가능 여부만 보는 것이라 인증서 검증은 생략(-k). 실제 통신은 에이전트가 CA 로 검증함.
    echo "controller=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 5 "$1/healthz" 2>/dev/null)"
    # $2 = 컨트롤러 이름, $3 = 포트. 이름을 못 찾으면 SSH 로 접속해 온 주소(= 컨트롤러)로 다시 시도
    if [ -z "$2" ]; then
      echo "nameresolves=ip"
    elif getent ahosts "$2" >/dev/null 2>&1; then
      echo "nameresolves=yes"
    else
      echo "nameresolves=no"
      ip=${SSH_CONNECTION%% *}
      if [ -n "$ip" ] && [ "$ip" != "$SSH_CONNECTION" ]; then
        echo "controllerip=$ip"
        case "$ip" in *:*) rip="[$ip]" ;; *) rip=$ip ;; esac
        echo "viaip=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 5 --resolve "$2:$3:$rip" "$1/healthz" 2>/dev/null)"
      fi
    fi
  else
    echo "controller=nocurl"
  fi
fi
if [ -x /usr/local/bin/kpctl-agent ]; then echo "agent=installed"; else echo "agent=none"; fi
if [ -e /etc/kpctl/controller.json ] || [ -e /etc/kpctl/builder.json ]; then echo "role=infra"; else echo "role=host"; fi
. /etc/os-release
echo "distro=${ID:-unknown}"
echo "release=${VERSION_ID:-}"
echo "release_type=${RELEASE_TYPE:-}"
echo "release_description=${VERSION:-}"
echo "codename=${VERSION_CODENAME:-}"
abi=$(uname -r)
case "$ID" in
  debian)
    read -r installed name arch ver <<<"$(dpkg-query -W -f='${db:Status-Eflag}.${db:Status-Status} ${Package} ${Architecture} ${Version}' "linux-image-$abi" 2>/dev/null)"
    if [ "$installed" = ok.installed ] && [ "$name" = "linux-image-$abi" ] && [ "$arch" = amd64 ] && grep -Fq " Debian $ver " /proc/sys/kernel/version; then
      echo "nativepackage=$ver"
    fi ;;
  rocky)
    if [ "$(rpm -q "kernel-core-$abi" --qf '%{NAME} %{EPOCHNUM} %{ARCH} %{VERSION}-%{RELEASE}.%{ARCH}' 2>/dev/null)" = "kernel-core 0 x86_64 $abi" ]; then
      echo "nativepackage=${abi%.x86_64}"
    fi ;;
esac
c=$(systemd-detect-virt --container 2>/dev/null)
if [ -z "$c" ] && { [ -e /.dockerenv ] || [ -e /run/.containerenv ]; }; then c=container; fi
echo "container=${c:-none}"
if [ -d /run/systemd/system ]; then echo "systemd=yes"; else echo "systemd=no"; fi
if [ -d "/lib/modules/$(uname -r)" ]; then echo "modules=yes"; else echo "modules=no"; fi
echo "lockdown=$(sed -n 's/.*\[\(.*\)\].*/\1/p' /sys/kernel/security/lockdown 2>/dev/null)"
echo "otherpatches=$(ls /sys/kernel/livepatch 2>/dev/null | grep -v '^kpctl_' | tr '\n' ' ')"
# 커널 자동 준비(kpctl-prepare-kernel) 조건: 일반 ext /boot 의 GRUB, Ubuntu 공식 저장소 접속
read -r bfs bdev <<<"$(findmnt -n -o FSTYPE,SOURCE -T /boot/grub/grubenv 2>/dev/null)"
echo "bootfs=${bfs:-none} $(readlink -f "${bdev:-none}" 2>/dev/null)"
# $4 = 설치 묶음의 mirrors.list. 이 호스트 아키텍처의 미러를 위에서부터 시도합니다. 미러는 IP 가 여럿이고
# 일부가 막힌 망이 있어 (apt 는 다른 IP 로 넘어감) 미러마다 세 번 중 한 번만 되면 접속 가능으로 봅니다
case "$(uname -m)" in x86_64) darch=amd64 ;; aarch64) darch=arm64 ;; *) darch=$(uname -m) ;; esac
if [ "$ID" = ubuntu ] && [ -n "${4:-}" ] && command -v curl >/dev/null 2>&1; then
  code="" via=""
  while read -r name arch url _; do
    case "$name" in ""|"#"*) continue ;; esac
    [ "$arch" = "$darch" ] || continue
    via=$name
    for i in 1 2 3; do code=$(curl -s -o /dev/null -w '%{http_code}' --connect-timeout 3 --max-time 5 "$url/" 2>/dev/null); case "$code" in [23]*) break 2 ;; esac; done
  done <<<"$4"
  echo "archive=${code:-000}"
  echo "archivemirror=$via"
fi
echo "bootfree=$(df -Pk /boot 2>/dev/null | awk 'NR==2{print $4}')"
echo "varfree=$(df -Pk /var 2>/dev/null | awk 'NR==2{print $4}')"
if command -v python3 >/dev/null 2>&1; then echo "python3=yes"; else echo "python3=no"; fi
if [ "$ID" = ubuntu ] && [ -n "$(dpkg --audit 2>/dev/null)" ]; then echo "dpkg=broken"; else echo "dpkg=ok"; fi
echo "now=$(date +%s)"
if systemctl is-active --quiet kpctl-builder 2>/dev/null; then echo "builderactive=yes"; else echo "builderactive=no"; fi
if [ -e /etc/kpctl/builder.json ]; then echo "builderconfig=yes"; else echo "builderconfig=no"; fi
if systemctl is-active --quiet kpctl-native-builder.timer 2>/dev/null; then echo "nativebuilderactive=yes"; else echo "nativebuilderactive=no"; fi
if [ -e /etc/kpctl/native-builder/worker.json ]; then echo "nativebuilderconfig=yes"; else echo "nativebuilderconfig=no"; fi
echo "virt=$(systemd-detect-virt --vm 2>/dev/null || true)"
# x86-64-v3: AVX2·BMI1/2·FMA·MOVBE 등 (Rocky 10 실행 호스트와 빌더에 필요)
if grep -qw avx2 /proc/cpuinfo && grep -qw bmi2 /proc/cpuinfo && grep -qw fma /proc/cpuinfo && grep -qw movbe /proc/cpuinfo; then echo "x86v3=yes"; else echo "x86v3=no"; fi
`

// PreflightOptions 는 점검 기준입니다.
type PreflightOptions struct {
	ForInstall    bool   // 설치용이면 아키텍처, CONFIG_LIVEPATCH, 컨트롤러 접속까지 확인
	Arch          string // 에이전트(또는 빌더) 바이너리 아키텍처
	ControllerURL string // 호스트에서 접속할 컨트롤러 주소
	Mirrors       string // 설치 묶음의 mirrors.list (비우면 저장소 접속을 확인하지 않음)

	// ForBuilder: 빌드 서버 설치용. 아키텍처·컨트롤러 접속에 더해 Ubuntu 시리즈, 실행 중인 빌더, 에이전트 여부를 봅니다.
	ForBuilder     bool
	Series         []string // 지원하는 Ubuntu 코드네임 (model.SupportedLTS)
	StopBuilder    bool     // 실행 중인 빌더를 설치 전에 멈춰도 됨 (아니면 문제로 보고)
	AllowWithAgent bool     // 에이전트가 있는 운영 호스트에도 설치 허용
}

// Preflight 는 접속, sudo, 커널, 컨트롤러 접속 가능 여부를 확인합니다.
// problems 가 하나라도 있으면 설치를 진행하면 안 됩니다. warnings 는 알려만 줍니다.
func (s *Session) Preflight(o PreflightOptions) (problems, warnings []string, err error) {
	s.step("사전 점검")
	url, name, port := "", "", ""
	if o.ForInstall || o.ForBuilder {
		url = o.ControllerURL
		name, port = urlHostPort(url)
	}
	mirrors := ""
	if o.ForInstall {
		mirrors = o.Mirrors
	}
	out, err := s.run("bash -s -- "+shq(url)+" "+shq(name)+" "+shq(port)+" "+shq(mirrors), preflightScript)
	if err != nil {
		return nil, nil, fmt.Errorf("SSH 접속 실패: %w", err)
	}
	kv := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
			kv[k] = v
		}
	}
	s.Facts = Facts{
		Distro: kv["distro"], ReleaseType: kv["release_type"], ReleaseDescription: kv["release_description"],
		Release: kv["release"], NativePackage: kv["nativepackage"], Hostname: kv["hostname"], UID: kv["uid"], Arch: kv["arch"], Kernel: kv["kernel"],
		Sudo: kv["sudo"], Livepatch: kv["livepatch"], SecureBoot: kv["secureboot"],
		Controller: kv["controller"], Agent: kv["agent"], Role: kv["role"], Codename: kv["codename"],
		BuilderActive: kv["builderactive"], BuilderConfig: kv["builderconfig"],
		NativeBuilderActive: kv["nativebuilderactive"], NativeBuilderConfig: kv["nativebuilderconfig"], Virt: kv["virt"], X86V3: kv["x86v3"],
		NameResolves: kv["nameresolves"], ControllerIP: kv["controllerip"], ViaIP: kv["viaip"],
		Container: kv["container"], Systemd: kv["systemd"], Modules: kv["modules"], Lockdown: kv["lockdown"],
		OtherPatches: kv["otherpatches"], BootFreeKB: kv["bootfree"], VarFreeKB: kv["varfree"],
		Python3: kv["python3"], Dpkg: kv["dpkg"], Now: kv["now"], BootFS: kv["bootfs"], Archive: kv["archive"], ArchiveVia: kv["archivemirror"],
	}
	f := s.Facts
	if f.Hostname == "" || f.UID == "" {
		return nil, nil, fmt.Errorf("점검 결과를 읽지 못했습니다 (원격 셸이 bash 인지 확인):\n%s", lastLines(out, 10))
	}

	if f.Sudo != "ok" {
		problems = append(problems, "root 가 아니고 비밀번호 없는 sudo 도 안 됩니다 (root 로 접속하거나 NOPASSWD sudo 설정)")
	}
	if o.ForInstall || o.ForBuilder {
		what := "에이전트"
		if o.ForBuilder {
			what = "빌더"
		}
		if f.Arch != o.Arch {
			problems = append(problems, fmt.Sprintf("아키텍처 불일치: 호스트 %s, %s 바이너리 %s", f.Arch, what, o.Arch))
		}
		switch {
		case f.Controller == "200":
		case f.Controller == "nocurl":
			warnings = append(warnings, "curl 이 없어 컨트롤러 접속을 미리 확인하지 못했습니다")
		case f.HostsEntry(o.ControllerURL) != "":
			warnings = append(warnings, fmt.Sprintf("호스트가 컨트롤러 이름을 찾지 못해 /etc/hosts 에 '%s' 를 추가합니다 (SSH 로 접속한 주소로 접속 확인함)", f.HostsEntry(o.ControllerURL)))
		default:
			problems = append(problems, controllerProblem(o.ControllerURL, f))
		}
	}
	if o.ForBuilder {
		supported := false
		for _, c := range o.Series {
			supported = supported || c == f.Codename && f.Distro == "ubuntu"
		}
		switch {
		case supported:
		case f.IsNativeBuilderOS():
			// Debian/Rocky 는 setup-native-builder.sh 로 설치하는 네이티브 빌더 (native_builder.go)
			p, w := nativeBuilderChecks(f, o)
			problems, warnings = append(problems, p...), append(warnings, w...)
		case f.Distro == "ubuntu":
			problems = append(problems, fmt.Sprintf("지원하지 않는 Ubuntu 시리즈 %s (지원: %s). 빌더는 대상 LTS 와 같은 Ubuntu 에 설치합니다", f.OSLabel(), strings.Join(o.Series, ", ")))
		default:
			problems = append(problems, fmt.Sprintf("지원하지 않는 OS %s 입니다. 빌더는 Ubuntu(%s) 또는 대상과 같은 Debian 12·Rocky 9·10 에 설치합니다", f.OSLabel(), strings.Join(o.Series, ", ")))
		}
		if f.BuilderActive == "yes" && !f.IsNativeBuilderOS() {
			if o.StopBuilder {
				warnings = append(warnings, "실행 중인 kpctl-builder 를 멈추고 다시 설치합니다 (진행 중인 빌드는 실패로 끝납니다)")
			} else {
				problems = append(problems, "kpctl-builder 가 실행 중입니다. 작업이 끝난 뒤 -stop-running 으로 다시 실행하세요")
			}
		}
		if f.Agent == "installed" && !o.AllowWithAgent && !f.IsNativeBuilderOS() { // 네이티브는 NativeBuilderHardBlock
			problems = append(problems, "에이전트가 설치된 운영 호스트입니다. 빌더는 패치 대상과 분리된 서버에 설치하세요 (원인을 알면 -force)")
		}
	}
	if o.ForInstall {
		if f.Role == "infra" {
			problems = append(problems, "컨트롤러 또는 빌드 서버입니다. 에이전트는 패치 대상 호스트에만 설치합니다")
		}
		p, w := hostChecks(f, time.Now())
		problems, warnings = append(problems, p...), append(warnings, w...)
	}
	fmt.Fprintf(&s.Log, "점검 결과: %+v\n문제: %v\n경고: %v\n", f, problems, warnings)
	return problems, warnings, nil
}

// ─────────────────────────────────────────────
// 2. 설치
// ─────────────────────────────────────────────

type InstallOptions struct {
	ControllerURL string // 에이전트가 접속할 컨트롤러 주소
	EnrollToken   string
	CAFile        string // 로컬 CA 인증서 파일 (선택)
}

// Install 은 파일을 임시 디렉터리에 복사하고 install-agent.sh 를 실행합니다.
// Preflight 를 먼저 불러야 합니다 (sudo 여부를 알아야 하므로).
//
// 등록 토큰은 명령줄에 넣지 않고(원격 ps 에 보이므로) 표준 입력으로 0600 파일에 쓴 뒤 경로만 넘깁니다.
func (s *Session) Install(b *Bundle, o InstallOptions) (err error) {
	s.step("임시 디렉터리 만들기")
	out, err := s.run("mktemp -d /tmp/kpctl-install.XXXXXX", "")
	if err != nil {
		return err
	}
	dir := strings.TrimSpace(out)
	if !strings.HasPrefix(dir, "/tmp/kpctl-install.") {
		return fmt.Errorf("임시 디렉터리 이름이 이상합니다: %q", dir)
	}
	defer func() {
		// 성공하든 실패하든 임시 파일(토큰 포함)은 지움
		if _, cerr := s.run(s.sudo()+"rm -rf "+shq(dir), ""); cerr != nil && err == nil {
			err = fmt.Errorf("임시 디렉터리 %s 삭제 실패 (토큰 파일이 남아 있을 수 있음): %w", dir, cerr)
		}
	}()

	s.step("파일 복사")
	files := []string{}
	for _, f := range bundleFiles {
		files = append(files, b.Path(f))
	}
	for _, f := range bundleOptionalFiles {
		if _, err := os.Stat(b.Path(f)); err == nil {
			files = append(files, b.Path(f))
		}
	}
	if o.CAFile != "" {
		if _, err := os.Stat(o.CAFile); err != nil {
			return fmt.Errorf("CA 파일: %w", err)
		}
		// 원래 파일 이름 그대로 복사되고, 설치 스크립트가 /etc/kpctl/ca.crt 로 설치합니다
		files = append(files, o.CAFile)
	}
	fmt.Fprintf(&s.Log, "$ scp %s → %s\n", strings.Join(files, " "), dir)
	if err := s.SSH.Copy(s.Target, files, dir); err != nil {
		return err
	}

	s.step("등록 토큰 전달")
	if _, err := s.run("umask 077; cat > "+shq(dir+"/enroll-token"), o.EnrollToken); err != nil {
		return err
	}

	if e := s.Facts.HostsEntry(o.ControllerURL); e != "" {
		s.step("컨트롤러 이름 등록 (/etc/hosts: " + e + ")")
		if _, err := s.run(s.sudo()+"bash -s -- "+shq(e), hostsEntryScript); err != nil {
			return err
		}
	}

	s.step("설치 스크립트 실행 (apt 설치 포함, 몇 분 걸릴 수 있음)")
	cmd := s.sudo() + "bash " + shq(dir+"/install-agent.sh") + " " + shq(o.ControllerURL) + " " + shq("@"+dir+"/enroll-token")
	if o.CAFile != "" {
		cmd += " " + shq(dir+"/"+baseName(o.CAFile))
	}
	_, err = s.run(cmd, "")
	return err
}

// ─────────────────────────────────────────────
// 3. 제거
// ─────────────────────────────────────────────

// Uninstall 은 uninstall-agent.sh 를 표준 입력으로 보내 실행합니다 (파일 복사 불필요).
// removePatches 가 false 면 이미 적용된 라이브패치는 그대로 둡니다 (보안 수정 유지).
func (s *Session) Uninstall(b *Bundle, removePatches bool) error {
	script, err := os.ReadFile(b.Path("uninstall-agent.sh"))
	if err != nil {
		return err
	}
	s.step("에이전트 제거")
	cmd := s.sudo() + "bash -s --"
	if removePatches {
		cmd += " --remove-patches"
	}
	_, err = s.run(cmd, string(script))
	return err
}

// ── 도우미 ──

// PinHostsFunc 는 "IP 이름 # kpctl" 줄을 /etc/hosts 에 고정하는 셸 함수 kpctl_pin_host 입니다.
// cloud-init(manage_etc_hosts)이 부팅마다 /etc/hosts 를 템플릿으로 다시 쓰는 시스템에서는
// 그 템플릿(/etc/cloud/templates/hosts.*.tmpl)에도 같은 줄을 넣어 재부팅 뒤에도 남깁니다.
// 같은 이름의 예전 kpctl 줄은 바꿉니다. uninstall-agent.sh 가 두 곳의 "# kpctl" 줄을 지웁니다.
// 원격 설치(hostsEntryScript)와 DHCP 부트스트랩 스크립트가 함께 씁니다.
const PinHostsFunc = `
kpctl_pin_host() {
  local ip=$1 name=$2 f
  for f in "${KPCTL_ROOT:-}/etc/hosts" "${KPCTL_ROOT:-}"/etc/cloud/templates/hosts.*.tmpl; do
    [ -f "$f" ] || continue
    grep -v "[[:space:]]$name[[:space:]]*# kpctl\$" "$f" > "$f.kpctl-new" || true
    echo "$ip $name # kpctl" >> "$f.kpctl-new"
    cat "$f.kpctl-new" > "$f"   # 덮어쓰기(mv 아님): 권한·소유자·SELinux 라벨 유지
    rm -f "$f.kpctl-new"
  done
}
`

// hostsEntryScript 는 $1 = "IP 이름" 을 kpctl_pin_host 로 고정하고 실제로 찾아지는지 확인합니다.
const hostsEntryScript = "set -e\n" + PinHostsFunc + `
kpctl_pin_host "${1%% *}" "${1#* }"
getent ahosts "${1#* }" >/dev/null || { echo "!! /etc/hosts 에 넣었지만 ${1#* } 을 찾지 못합니다 (nsswitch.conf 확인)"; exit 1; }
`

// urlHostPort 는 URL 의 호스트 이름과 포트를 돌려줍니다. 호스트가 IP 면 이름은 빈 문자열입니다.
func urlHostPort(raw string) (name, port string) {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return "", ""
	}
	if net.ParseIP(u.Hostname()) != nil {
		return "", ""
	}
	port = u.Port()
	if port == "" {
		port = "443"
		if u.Scheme == "http" {
			port = "80"
		}
	}
	return u.Hostname(), port
}

// controllerProblem 은 컨트롤러에 접속하지 못한 이유를 점검 결과에 맞춰 설명합니다.
func controllerProblem(ctrlURL string, f Facts) string {
	msg := fmt.Sprintf("호스트에서 컨트롤러 %s 에 접속하지 못했습니다 (HTTP %s)", ctrlURL, f.Controller)
	name, _ := urlHostPort(ctrlURL)
	switch {
	case f.NameResolves == "no" && f.ControllerIP != "":
		return msg + fmt.Sprintf(" — 호스트가 %s 를 찾지 못하고, SSH 로 접속한 주소 %s 로도 접속되지 않습니다 (HTTP %s). 방화벽이나 컨트롤러 listen 주소 확인", name, f.ControllerIP, f.ViaIP)
	case f.NameResolves == "no":
		return msg + fmt.Sprintf(" — 호스트가 %s 를 찾지 못합니다. 호스트 DNS 나 /etc/hosts 확인", name)
	case f.NameResolves == "yes":
		return msg + fmt.Sprintf(" — %s 는 찾았지만 접속되지 않습니다. 방화벽이나 이름이 가리키는 IP 확인", name)
	}
	return msg + " — 방화벽/DNS 확인"
}

func lastLines(s string, n int) string {
	ls := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(ls) > n {
		ls = ls[len(ls)-n:]
	}
	return strings.Join(ls, "\n")
}

func baseName(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}
