// 이 파일: builder 패키지의 kernels, contains, outsideReason 구현·자료형.
package builder

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"kpctl/internal/client"
	"kpctl/internal/model"
)

// kernels 는 이번 자동 수집 대상 커널 목록입니다.
//
// 설정에 kernels 를 적었으면 그것만 씁니다. 비어 있으면(자동 모드) 컨트롤러에 등록된 호스트들이
// 지금 쓰는 커널 중 이 빌드 서버 시리즈의 GA generic 커널을 모두 대상으로 합니다.
// 그래서 호스트가 새 커널로 재부팅하면 다음 주기부터 그 커널도 저절로 수집됩니다.
func (b *Builder) kernels() []KernelConfig {
	return b.availableKernels(nil)
}

// When a caller asks for specific kernels, record why any of those must wait.
func (b *Builder) availableKernels(requested map[string]error) []KernelConfig {
	hasSpace := func(hosts []model.HostKernel, window kernelRange) bool {
		ready := b.cleanupForDisk(hosts, window)
		if !ready && b.diskBlocked {
			for _, kernel := range b.activeKernels {
				if _, wanted := requested[kernel]; wanted {
					requested[kernel] = errDiskSpace
				}
			}
		}
		return ready
	}
	report := func(kernel string, err error) {
		if errors.Is(err, errBuildDeferred) {
			if _, wanted := requested[kernel]; wanted {
				requested[kernel] = err
			}
			return
		}
		b.reportProblem(kernel, err.Error())
	}
	b.activeKernels = nil
	if !b.cfg.autoKernels() {
		for _, k := range b.cfg.Kernels {
			b.activeKernels = append(b.activeKernels, k.Kernel)
		}
		if !hasSpace(nil, kernelRange{}) {
			return nil
		}
		b.maintainSandbox()
		if b.cfg.Sandbox == nil && !b.cfg.autoControllerInputs() {
			return b.cfg.Kernels
		}
		var ready []KernelConfig
		for _, k := range b.cfg.Kernels {
			if err := b.prepareConfiguredInputs(k); err != nil {
				b.reportProblem(k.Kernel, err.Error())
				log.Printf("[%s] 컨트롤러 입력 준비 실패: %v", k.Kernel, err)
				continue
			}
			if b.cfg.Sandbox != nil {
				if _, err := b.ensureSandboxProfile(k); err != nil {
					report(k.Kernel, err)
					log.Printf("[%s] 격리 환경 준비 필요: %v", k.Kernel, err)
					continue
				}
			}
			ready = append(ready, k)
		}
		return ready
	}
	var resp model.HostKernelsResponse
	if err := b.c.Do("GET", "/api/builder/kernels", nil, &resp); err != nil {
		log.Printf("호스트 커널 목록 조회 실패: %v", err)
		if client.Retryable(err) {
			for kernel := range requested {
				requested[kernel] = fmt.Errorf("%w: 호스트 커널 목록 조회 실패: %w", errBuildDeferred, err)
			}
		}
		return nil
	}
	window, werr := b.kernelWindow()
	if werr == nil {
		b.lastWindow = window
	} else if b.lastWindow.latest > 0 {
		// 범위는 앞으로만 움직이므로 마지막으로 확인한 범위 밖 커널은 여전히 범위 밖입니다.
		// 일시적인 APT·Git 장애로 오래된 커널의 긴 시험 빌드가 다시 시작되지 않게 합니다.
		log.Printf("최근 커널 범위 확인 실패, 마지막으로 확인한 범위(ABI %d 이상) 사용: %v", b.lastWindow.floor, werr)
		window, werr = b.lastWindow, nil
	} else {
		// 시작 뒤 한 번도 범위를 확인하지 못했으면 모든 호스트 커널을 대상으로 둡니다 (수집 자체도 같은 APT 확인에서 멈춤).
		log.Printf("최근 커널 범위 확인 실패, 이번 주기는 범위 제한 없이 진행: %v", werr)
	}
	var out []KernelConfig
	for _, hk := range resp.Kernels {
		if s := model.LTSForKernel(hk.Kernel); s != nil && s.Codename == b.cfg.Series && !model.IsHWESignature(hk.Signature) &&
			window.contains(hk.Kernel) {
			b.activeKernels = append(b.activeKernels, hk.Kernel)
		}
	}
	if !hasSpace(resp.Kernels, window) {
		return nil
	}
	b.maintainSandbox()
	for _, hk := range resp.Kernels {
		if s := model.LTSForKernel(hk.Kernel); s != nil && s.Codename == b.cfg.Series && !model.IsHWESignature(hk.Signature) && werr == nil {
			if !window.contains(hk.Kernel) {
				// 디버그 심볼 설치·GCC 프로파일 준비보다 먼저 거릅니다. 수집 문제가 아니므로 자동 배포 보류도 걸지 않습니다.
				reason := window.outsideReason()
				log.Printf("[%s] 자동 수집 대상 아님 (호스트 %d대): %s", hk.Kernel, hk.Hosts, reason)
				b.reportOutside(hk.Kernel, reason, window.latestTag)
				continue
			}
			b.reportOutside(hk.Kernel, "", window.latestTag)
		}
		k, skip := b.autoKernel(hk)
		mine := k.Kernel != "" || skip != nil && model.LTSForKernel(hk.Kernel) != nil &&
			model.LTSForKernel(hk.Kernel).Codename == b.cfg.Series && !model.IsHWESignature(hk.Signature)
		if skip != nil {
			log.Printf("[%s] 자동 수집 준비 보류 (호스트 %d대): %v", hk.Kernel, hk.Hosts, skip)
		}
		if mine && skip != nil {
			// 준비 조건이 갖춰져도 이전 시험 빌드 문제가 해결됐다고 볼 수 없습니다.
			// 문제 해제는 discover 가 실제 수집을 끝까지 검증한 뒤에만 보고합니다.
			report(hk.Kernel, skip)
		}
		if skip != nil || k.Kernel == "" {
			continue // 수집할 수 없거나, 다른 시리즈 빌드 서버가 맡는 커널
		}
		out = append(out, k)
	}
	return out
}

// kernelRange 는 자동 모드에서 수집할 ABI 범위입니다. floor 가 0 이면 제한하지 않습니다.
// latest 는 정식 배포 최신 ABI 입니다. 디스크 정리는 이 범위를 바꾸지 않습니다.
type kernelRange struct {
	floor     int
	kept      []int
	latest    int
	latestTag string // APT 공식 색인에서 확인한 정확한 패키지 버전 (같은 ABI 재배포 포함)
}

type kernelRangeReport struct {
	reason, latestTag string
}

var genericABI = regexp.MustCompile(`-([0-9]+)-generic$`)

func (r kernelRange) contains(kernel string) bool {
	if r.floor == 0 {
		return true
	}
	m := genericABI.FindStringSubmatch(kernel)
	if m == nil {
		return true
	}
	abi, _ := strconv.Atoi(m[1])
	return abi >= r.floor
}

func (r kernelRange) outsideReason() string {
	names := make([]string, len(r.kept))
	for i, abi := range r.kept {
		names[i] = strconv.Itoa(abi)
	}
	return fmt.Sprintf("최근 %d개 ABI(%s) 밖 · 자동 수집하지 않음", len(r.kept), strings.Join(names, "·"))
}

// reportOutside 는 범위 밖 여부를 컨트롤러에 알립니다. 범위 밖이 되면 이전 수집 문제도 지웁니다.
func (b *Builder) reportOutside(kernel, reason, latestTag string) {
	if b.lastOutside == nil {
		b.lastOutside = map[string]kernelRangeReport{}
	}
	report := kernelRangeReport{reason: reason, latestTag: latestTag}
	if old, ok := b.lastOutside[kernel]; ok && old == report {
		return
	}
	// 범위 밖 호스트는 discover 를 실행하지 않으므로 최신 공식 태그도 여기서
	// 보고해야 준비된 부팅 대상이 지금의 공식 최신 패키지와 같은지 확인할 수 있습니다.
	req := model.UpstreamReport{Outside: &reason, LatestTag: latestTag}
	if reason != "" {
		cleared := ""
		req.Problem = &cleared
	}
	if err := b.c.Do("POST", "/api/builder/kernels/"+kernel+"/upstream", req, nil); err != nil {
		log.Printf("[%s] 커널 범위 보고 실패: %v", kernel, err)
		return
	}
	b.lastOutside[kernel] = report
	if reason != "" {
		if b.lastProblem == nil {
			b.lastProblem = map[string]string{}
		}
		b.lastProblem[kernel] = ""
	}
}

// kernelWindow 는 정식 배포 최신 ABI 를 포함해 Git 태그에 있는 최근 max_kernels 개 ABI 를 고릅니다.
// 오래된 커널일수록 CVE 이외 커밋이 문맥을 바꿔 시험 빌드가 멈추기 쉬우므로 범위를 좁게 유지합니다.
func (b *Builder) kernelWindow() (kernelRange, error) {
	s := model.LTSByCodename(b.cfg.Series)
	if s == nil {
		return kernelRange{}, fmt.Errorf("시리즈 %q 를 모릅니다", b.cfg.Series)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	version, err := publishedKernelVersion(ctx, s.Codename, s.Kernel)
	if err != nil {
		return kernelRange{}, err
	}
	tags, err := exec.CommandContext(ctx, "git", "-C", filepath.Join(b.cfg.GitRoot, "ubuntu-"+s.Codename),
		"tag", "-l", "Ubuntu-"+s.Kernel+"-*").Output()
	if err != nil {
		return kernelRange{}, fmt.Errorf("커널 Git 태그 확인 실패: %w", err)
	}
	n := b.cfg.MaxKernels
	if n <= 0 {
		n = 1 << 20
	}
	r, err := recentABIs(s.Kernel, "Ubuntu-"+version, strings.Fields(string(tags)), n)
	if err != nil {
		return r, err
	}
	r.latest = r.kept[0]
	if b.cfg.MaxKernels <= 0 {
		r.floor = 0
	}
	return r, nil
}

// recentABIs 는 최신 정식 배포 태그 이하의 ABI 중 최근 n개를 고릅니다. 같은 ABI 의 재배포 태그는 하나로 셉니다.
func recentABIs(kernel, latestTag string, tags []string, n int) (kernelRange, error) {
	tagRE := regexp.MustCompile(`^Ubuntu-` + regexp.QuoteMeta(kernel) + `-([0-9]+)\.[0-9]+$`)
	abiOf := func(tag string) int {
		m := tagRE.FindStringSubmatch(tag)
		if m == nil {
			return 0
		}
		abi, _ := strconv.Atoi(m[1])
		return abi
	}
	latest := abiOf(latestTag)
	if latest == 0 {
		return kernelRange{}, fmt.Errorf("정식 배포 태그 %s 에서 ABI 를 읽지 못했습니다", latestTag)
	}
	seen := map[int]bool{latest: true}
	abis := []int{latest}
	for _, tag := range tags {
		if abi := abiOf(tag); abi > 0 && abi < latest && !seen[abi] {
			seen[abi] = true
			abis = append(abis, abi)
		}
	}
	sort.Sort(sort.Reverse(sort.IntSlice(abis)))
	if len(abis) > n {
		abis = abis[:n]
	}
	return kernelRange{floor: abis[len(abis)-1], kept: abis, latest: latest, latestTag: latestTag}, nil
}

// autoKernel 은 호스트 커널 하나의 자동 수집 설정을 만듭니다.
// 준비하지 못한 이유를 돌려줍니다. 다른 시리즈면 빈 설정을 돌려줍니다.
func (b *Builder) autoKernel(hk model.HostKernel) (KernelConfig, error) {
	s := model.LTSForKernel(hk.Kernel)
	if s == nil {
		return KernelConfig{}, errors.New("지원 LTS 의 GA generic 커널이 아님 (필요하면 kernels 에 직접 적으세요)")
	}
	if model.IsHWESignature(hk.Signature) {
		return KernelConfig{}, fmt.Errorf("HWE 커널 (%s) — 기본 지원 대상이 아님", model.SignatureVersion(hk.Signature))
	}
	if s.Codename != b.cfg.Series {
		return KernelConfig{}, nil
	}

	k := KernelConfig{
		Kernel:  hk.Kernel,
		GitDir:  filepath.Join(b.cfg.GitRoot, "ubuntu-"+s.Codename),
		TagGlob: "Ubuntu-" + s.Kernel + "-*",
		Vmlinux: b.cfg.vmlinuxFor(hk.Kernel),
		Paths:   b.cfg.Paths,
	}
	// 기준 태그: 호스트가 보고한 패키지 버전 그대로. 보고가 없으면(예전 에이전트) git fetch 뒤에 고릅니다.
	if v := model.SignatureVersion(hk.Signature); v != "" {
		k.BaseTag = "Ubuntu-" + v
	}

	if _, err := os.Stat(filepath.Join(k.GitDir, ".git")); err != nil {
		return KernelConfig{}, fmt.Errorf("커널 git 이 없음 → git clone https://git.launchpad.net/~ubuntu-kernel/ubuntu/+source/linux/+git/%s %s",
			s.Codename, k.GitDir)
	}
	if _, err := os.Stat(k.Vmlinux); err != nil || b.cfg.autoControllerInputs() {
		// 호스트가 오래된 커널을 써도 사람 손 없이 빌드하도록 디버그 심볼을 직접 설치 (kpctl-kernel-debug)
		if ierr := b.installDebug(hk.Kernel, model.SignatureVersion(hk.Signature)); ierr != nil {
			return KernelConfig{}, fmt.Errorf("디버그 심볼 없음 (%s), 자동 설치 실패: %w → 빌드 서버의 kpctl-kernel-debug 도우미·대상 입력 패키지를 확인하세요 (%s)",
				k.Vmlinux, ierr, hk.Kernel)
		}
		if _, err := os.Stat(k.Vmlinux); err != nil {
			return KernelConfig{}, fmt.Errorf("디버그 심볼을 설치했지만 %s 이 없습니다", k.Vmlinux)
		}
	}
	// 커널을 빌드한 gcc 와 빌드 서버 gcc 가 다르면 시험 빌드가 모두 실패해서
	// 멀쩡한 CVE 까지 "라이브패치 불가"로 잘못 분류되므로 미리 막습니다.
	if b.cfg.Sandbox != nil {
		if _, err := b.ensureSandboxProfile(k); err != nil {
			return KernelConfig{}, err
		}
	} else if kernelGCC, mine := gccVersions(hk.Kernel); kernelGCC != "" && mine != "" && gccID(kernelGCC) != gccID(mine) {
		return KernelConfig{}, fmt.Errorf("이 커널을 빌드한 컴파일러(%s)가 빌드 서버 컴파일러(%s)와 다릅니다 → 같은 gcc 를 설치하거나 호스트를 새 커널로", kernelGCC, mine)
	}
	return k, nil
}

// resolveKernel 은 빌드 작업의 커널 설정을 찾습니다. 자동 모드면 커널 git·기준 태그까지 채워서
// 소스를 git 에서 꺼낼 수 있게 합니다 (Ubuntu 저장소에는 오래된 커널 소스가 없음).
func (b *Builder) resolveKernel(kernel string) (KernelConfig, error) {
	k := b.cfg.kernelConfig(kernel)
	if k.GitDir != "" || !b.cfg.autoKernels() {
		return k, nil
	}
	deferred := map[string]error{kernel: nil}
	for _, ak := range b.availableKernels(deferred) {
		if ak.Kernel == kernel {
			if ak.BaseTag == "" {
				if tag, err := resolveBaseTag(ak); err == nil {
					ak.BaseTag = tag
				}
			}
			return ak, nil
		}
	}
	return k, deferred[kernel]
}

// debugRetry 는 디버그 심볼 자동 설치에 실패한 커널을 다시 시도하기까지 기다리는 시간입니다.
const debugRetry = 6 * time.Hour

// installDebug 는 디버그 심볼·이미지·헤더를 설치합니다 (sudo kpctl-kernel-debug <커널> <버전>).
// 실패하면 6시간 동안은 다시 시도하지 않고 같은 오류를 돌려줍니다.
func (b *Builder) installDebug(kernel, version string) error {
	if !*b.cfg.AutoDebugSymbols {
		return fmt.Errorf("auto_debug_symbols 가 꺼져 있음")
	}
	if _, err := os.Stat(b.cfg.DebugHelper); err != nil {
		return fmt.Errorf("도우미 %s 가 없음 (docs/operations/builder-migration.md의 도우미·sudo 규칙 설치 절차 확인)", b.cfg.DebugHelper)
	}
	if f, ok := b.debugFailed[kernel]; ok && time.Since(f.at) < debugRetry {
		return f.err
	}
	log.Printf("[%s] 디버그 심볼 자동 설치 시작 (패키지 버전 %s)", kernel, dash(version))
	b.setStep("디버그 심볼·헤더 준비: " + kernel)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Minute)
	defer cancel()
	args := []string{"-n", b.cfg.DebugHelper}
	if b.cfg.ControllerKernelInputs {
		if version == "" {
			return fmt.Errorf("컨트롤러 입력 전달에는 호스트가 보고한 정확한 패키지 버전이 필요합니다")
		}
		args = append(args, "--controller")
	}
	args = append(args, kernel)
	if version != "" {
		args = append(args, version)
	}
	out, err := b.commandOutput(exec.CommandContext(ctx, "sudo", args...))
	if err != nil {
		err = fmt.Errorf("%v: %s", err, strings.TrimSpace(lastLines(string(out), 2)))
		if b.debugFailed == nil {
			b.debugFailed = map[string]debugFailure{}
		}
		b.debugFailed[kernel] = debugFailure{at: time.Now(), err: err}
		log.Printf("[%s] 디버그 심볼 자동 설치 실패 (6시간 뒤 다시): %v", kernel, err)
		return err
	}
	delete(b.debugFailed, kernel)
	log.Printf("[%s] 디버그 심볼 자동 설치 완료", kernel)
	return nil
}

type debugFailure struct {
	at  time.Time
	err error
}

// gccVersions 는 커널을 빌드한 gcc 와 이 서버 gcc 를 "gcc (Ubuntu 15.2.0-16ubuntu1) 15.2.0" 꼴로 돌려줍니다.
// 확인할 수 없으면 "" (막지 않음).
func gccVersions(kernel string) (kernelGCC, mine string) {
	kernelGCC = kernelCompiler(kernel, "")
	if out, err := exec.Command("gcc", "--version").Output(); err == nil {
		mine = gccRe.FindString(string(out))
	}
	return kernelGCC, mine
}

// gccID 는 실행 파일 이름(gcc, gcc-13, x86_64-linux-gnu-gcc-13)을 뺀 "(배포판 패키지 버전) gcc 버전" 입니다.
// 커널 compile.h 에는 "gcc-13 (...)", gcc --version 에는 "gcc (...)" 처럼 이름만 달리 찍히기 때문입니다.
// 예: "gcc-13 (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0" → "(Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0"
func gccID(s string) string {
	if i := strings.Index(s, "("); i >= 0 {
		return s[i:]
	}
	return s
}

var gccRe = regexp.MustCompile(`gcc[^\n"]*?\) [0-9]+\.[0-9]+\.[0-9]+`)

// reportProblem 은 이 커널을 수집할 수 없는 이유를 알립니다 ("" = 해결됨). 같은 내용은 다시 보내지 않습니다.
func (b *Builder) reportProblem(kernel, problem string) {
	b.reportProblemKind(kernel, problem, "", problem == "")
}

// kind 를 지정한 해제는 그 종류의 문제만 지웁니다. 다른 빌드 오류를 덮어 지우지 않습니다.
func (b *Builder) reportProblemKind(kernel, problem, kind string, recovered bool) bool {
	if b.c == nil {
		return false
	} // 컨트롤러 없는 오프라인 검증 경로
	if b.lastProblem == nil {
		b.lastProblem = map[string]string{}
	}
	if b.lastProblemKind == nil {
		b.lastProblemKind = map[string]string{}
	}
	if old, ok := b.lastProblem[kernel]; ok && old == problem && b.lastProblemKind[kernel] == kind {
		return true
	}
	req := model.UpstreamReport{Problem: &problem, ProblemKind: kind, Recovered: recovered}
	if err := b.c.Do("POST", "/api/builder/kernels/"+kernel+"/upstream", req, nil); err != nil {
		log.Printf("[%s] 수집 문제 보고 실패: %v", kernel, err)
		return false
	}
	_, known := b.lastProblemKind[kernel]
	if problem != "" || kind == "" || b.lastProblemKind[kernel] == kind || !known {
		b.lastProblem[kernel], b.lastProblemKind[kernel] = problem, kind
	}
	return true
}

// resolveBaseTag 는 기준 태그를 모를 때 커널 ABI 에 맞는 첫 태그를 고릅니다.
// 예: 6.8.0-85-generic → "Ubuntu-6.8.0-85.*" 중 가장 낮은 것
func resolveBaseTag(k KernelConfig) (string, error) {
	out, err := git(k.GitDir, "tag", "-l", "Ubuntu-"+model.KernelABI(k.Kernel)+".*", "--sort=v:refname")
	if err != nil {
		return "", err
	}
	tags := lines(out)
	if len(tags) == 0 {
		return "", fmt.Errorf("%s 커널에 맞는 태그(Ubuntu-%s.*)가 git 에 없습니다", k.Kernel, model.KernelABI(k.Kernel))
	}
	return tags[0], nil
}
