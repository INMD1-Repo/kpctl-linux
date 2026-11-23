// 이 파일: builder 패키지의 buildThresholdMiB, cleanupTarget, problem 구현·자료형.
package builder

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"kpctl/internal/model"
)

const problemDiskSpace = "disk_space"

var errDiskSpace = fmt.Errorf("%w: 디스크 부족 · 빌드 보류", errBuildBusy)

var diskFreeBytes = func(dir string) (uint64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, err
	}
	return st.Bavail * uint64(st.Bsize), nil
}

// Python 도우미와 같은 profile.json의 값을 읽습니다. 준비 설정은 프로파일이
// 아직 없는 대상에만 적용하며, 여러 활성 프로파일이면 가장 큰 요구량을 씁니다.
func (b *Builder) buildThresholdMiB(kernels ...string) (uint64, error) {
	fallback := uint64(60 * 1024)
	s := b.cfg.Sandbox
	if s == nil {
		return fallback, nil
	}
	if s.Prepare != nil && s.Prepare.MinFreeGiB > 0 {
		fallback = uint64(s.Prepare.MinFreeGiB) * 1024
	}
	paths := []string{s.Profile}
	if s.ProfilesDir != "" {
		if len(kernels) == 0 {
			kernels = append(kernels, b.activeKernels...)
			for _, k := range b.cfg.Kernels {
				kernels = append(kernels, k.Kernel)
			}
		}
		paths = nil
		for _, kernel := range kernels {
			compiler := gccID(kernelCompiler(kernel, b.headersRoot))
			path := ""
			if compiler != "" {
				path = filepath.Join(s.ProfilesDir, compilerProfileName(compiler), "profile.json")
			}
			paths = append(paths, path)
		}
	}
	minimum := uint64(0)
	seen := map[string]bool{}
	for _, path := range paths {
		if seen[path] {
			continue
		}
		seen[path] = true
		value := fallback
		if path != "" {
			data, err := os.ReadFile(path)
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				return 0, fmt.Errorf("빌드 여유 기준 읽기 실패: %s: %w", path, err)
			}
			if err == nil {
				var profile struct {
					Limits struct {
						DiskFreeMiB *uint64 `json:"disk_free_mib"`
					} `json:"limits"`
				}
				if err := json.Unmarshal(data, &profile); err != nil {
					return 0, fmt.Errorf("빌드 여유 기준 해석 실패: %s: %w", path, err)
				}
				value = 61440 // Python load_profile/run_locked의 필드 생략 시 기본값.
				if profile.Limits.DiskFreeMiB != nil {
					value = *profile.Limits.DiskFreeMiB
				}
				if value < 8192 || value > 67108864 {
					return 0, fmt.Errorf("빌드 여유 기준이 잘못됐습니다: %s", path)
				}
			}
		}
		minimum = max(minimum, value)
	}
	if len(paths) == 0 {
		minimum = fallback
	}
	return minimum, nil
}

type buildDiskSpace struct {
	free, minimum, cleanup uint64
}

func (s buildDiskSpace) cleanupTarget() uint64 {
	return max(s.minimum, s.cleanup)
}

func (s buildDiskSpace) problem(err error) string {
	if err != nil {
		return "디스크 부족 · 빌드 보류 (여유 공간·빌드 기준 확인 실패: " + err.Error() + ")"
	}
	return fmt.Sprintf("디스크 부족 · 빌드 보류 (여유 %.1f GiB < 필요 %g GiB)", float64(s.free)/(1<<30), float64(s.minimum)/(1<<30))
}

func (b *Builder) diskSpace(kernels ...string) (buildDiskSpace, error) {
	var space buildDiskSpace
	if b.cfg.WorkDir == "" || b.cfg.KernelCleanupFreeGiB < 0 {
		return space, nil
	}
	minimum, err := b.buildThresholdMiB(kernels...)
	if err != nil {
		return space, err
	}
	space.minimum = minimum << 20
	b.diskMinimum.Store(space.minimum)
	space.cleanup = space.minimum + (20 << 30)
	if b.cfg.KernelCleanupFreeGiB > 0 {
		space.cleanup = uint64(b.cfg.KernelCleanupFreeGiB) << 30
	}
	space.free, err = diskFreeBytes(b.cfg.WorkDir)
	return space, err
}

// kernel-retention.json 은 더 이상 읽거나 쓰지 않습니다. 정리는 지원 범위를 바꾸지 않습니다.
func (b *Builder) cleanupForDisk(hosts []model.HostKernel, window kernelRange) bool {
	if b.cfg.WorkDir == "" || b.cfg.KernelCleanupFreeGiB < 0 {
		return true
	}
	space, spaceErr := b.diskSpace()
	if spaceErr == nil && space.free >= space.cleanupTarget() {
		b.diskBlocked = false
		b.lastDiskProblem = ""
		b.diskChecked = b.clearDiskProblem(hosts)
		return true
	}
	preventive := spaceErr == nil && space.free >= space.minimum
	if preventive && time.Since(b.diskCleanupAt) < time.Hour {
		b.diskBlocked = false
		b.lastDiskProblem = ""
		b.diskChecked = b.clearDiskProblem(hosts)
		return true
	}
	if preventive {
		b.diskCleanupAt = time.Now()
		log.Printf("디스크 정리 시도 (여유 %.1f GiB, 정리 기준 %g GiB, 빌드 필요 %g GiB)", float64(space.free)/(1<<30), float64(space.cleanup)/(1<<30), float64(space.minimum)/(1<<30))
	}
	target := space.minimum
	if preventive {
		target = space.cleanupTarget()
	}
	if spaceErr == nil && b.cfg.autoKernels() && window.latest > 0 {
		inventory, err := b.kernelDataInventory()
		if err != nil {
			log.Printf("커널 자료 목록 확인 실패, 확인한 자료만 정리: %v", err)
		}
		for _, kernel := range inventory {
			if b.stopping() {
				return false
			}
			if err := b.canPurgeKernel(kernel, hosts, window); err != nil {
				continue
			}
			b.PurgeKernels([]string{kernel}) // 실패해도 경계를 저장하지 않으며 다음 주기에 다시 찾습니다.
			space, spaceErr = b.diskSpace()
			if spaceErr == nil && space.free >= target {
				b.diskBlocked = false
				b.lastDiskProblem = ""
				b.diskChecked = b.clearDiskProblem(hosts)
				return true
			}
		}
	}
	// 예방 정리에서는 캐시를 유지합니다. 부족할 때만 빌드 최소 여유까지
	// 기존 비활성 프로파일 보관 정책과 기준 캐시 LRU 를 적용합니다.
	if spaceErr == nil && space.free < space.minimum {
		b.maintainSandboxSpace(int((space.minimum + (1<<30 - 1)) >> 30))
	}
	space, spaceErr = b.diskSpace()
	if spaceErr == nil && space.free >= space.minimum {
		b.diskBlocked = false
		b.lastDiskProblem = ""
		b.diskChecked = b.clearDiskProblem(hosts)
		return true
	}
	problem := space.problem(spaceErr)
	for _, kernel := range b.diskProblemKernels(hosts) {
		b.reportProblemKind(kernel, problem, problemDiskSpace, false)
	}
	if b.lastDiskProblem != problem {
		log.Print(problem)
		b.lastDiskProblem = problem
	}
	b.diskBlocked = true
	return false
}

func (b *Builder) diskProblemKernels(hosts []model.HostKernel) []string {
	seen := map[string]bool{}
	for _, k := range b.cfg.Kernels {
		seen[k.Kernel] = true
	}
	for _, h := range hosts {
		if b.ownKernel(h.Kernel) && !model.IsHWESignature(h.Signature) {
			seen[h.Kernel] = true
		}
	}
	// 공간 부족 때 보고한 커널이 재부팅으로 목록에서 사라져도 복구 보고를 보냅니다.
	for kernel, kind := range b.lastProblemKind {
		if kind == problemDiskSpace && b.lastProblem[kernel] != "" {
			seen[kernel] = true
		}
	}
	var kernels []string
	for kernel := range seen {
		kernels = append(kernels, kernel)
	}
	sort.Strings(kernels)
	return kernels
}

func (b *Builder) clearDiskProblem(hosts []model.HostKernel) bool {
	ok := true
	for _, kernel := range b.diskProblemKernels(hosts) {
		if !b.reportProblemKind(kernel, "", problemDiskSpace, true) {
			ok = false
		}
	}
	return ok
}

// 작업을 받기 전에 검사하여 디스크 부족을 누적 빌드 실패로 기록하지 않습니다.
func (b *Builder) ensureBuildSpace() bool {
	if b.cfg.WorkDir == "" || b.cfg.KernelCleanupFreeGiB < 0 {
		return true
	}
	space, spaceErr := b.diskSpace()
	if spaceErr == nil && space.free >= space.minimum {
		// 재시작 뒤의 컨트롤러 표시도 해제할 수 있게 여유 회복 때 목록을 확인합니다.
		if b.diskChecked && !b.diskBlocked && (space.free >= space.cleanupTarget() || time.Since(b.diskCleanupAt) < time.Hour) {
			return true
		}
	}
	var hosts []model.HostKernel
	if b.cfg.autoKernels() {
		var resp model.HostKernelsResponse
		if err := b.c.Do("GET", "/api/builder/kernels", nil, &resp); err != nil {
			log.Printf("공간 정리용 호스트 목록 확인 실패: %v", err)
			return spaceErr == nil && space.free >= space.minimum // 목록을 모르면 삭제하지 않되, 예방 정리 때문에 빌드를 막지 않습니다.
		}
		hosts = resp.Kernels
	}
	window, _ := b.kernelWindow()
	b.activeKernels = nil
	for _, k := range b.cfg.Kernels {
		b.activeKernels = append(b.activeKernels, k.Kernel)
	}
	for _, h := range hosts {
		if b.ownKernel(h.Kernel) && !model.IsHWESignature(h.Signature) && window.contains(h.Kernel) {
			b.activeKernels = append(b.activeKernels, h.Kernel)
		}
	}
	b.diskBlocked = !b.cleanupForDisk(hosts, window)
	return !b.diskBlocked
}

func (b *Builder) ownKernel(kernel string) bool {
	s := model.LTSForKernel(kernel)
	return s != nil && s.Codename == b.cfg.Series && genericABI.MatchString(kernel)
}

// 등록 호스트 목록과 별개로 디버그 입력·소스·시험 기록·봉인 캐시에서 남아 있는 커널을 찾습니다.
func (b *Builder) kernelDataInventory() ([]string, error) {
	seen := map[string]bool{}
	add := func(kernel string) {
		if b.ownKernel(kernel) {
			seen[kernel] = true
		}
	}
	for kernel := range b.purgePending {
		add(kernel)
	}
	headers := b.headersRoot
	if headers == "" {
		headers = "/usr/src"
	}
	for _, p := range []struct{ dir, prefix string }{{b.cfg.DebugDir, "vmlinux-"}, {filepath.Join(b.cfg.WorkDir, "src"), ""}, {headers, "linux-headers-"}, {"/lib/modules", ""}} {
		if p.dir == "" {
			continue
		}
		entries, err := os.ReadDir(p.dir)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), p.prefix) {
				add(strings.TrimPrefix(entry.Name(), p.prefix))
			}
		}
	}
	trials, err := filepath.Glob(filepath.Join(b.cfg.WorkDir, "trial-*", "out", "environment-request.json"))
	if err != nil {
		return nil, err
	}
	for _, path := range trials {
		var req struct {
			Kernel KernelConfig `json:"kernel"`
		}
		data, err := os.ReadFile(path)
		if err == nil && json.Unmarshal(data, &req) == nil {
			add(req.Kernel.Kernel)
		}
	}
	var inventoryErr error
	if s := b.cfg.Sandbox; s != nil {
		args := []string{"kernel-inventory"}
		if s.ProfilesDir != "" {
			args = append(args, "--profiles-dir", s.ProfilesDir)
		}
		if s.Profile != "" {
			args = append(args, "--profile", s.Profile)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, s.Helper, args...)
		killProcessGroup(cmd)
		out, err := b.commandOutput(cmd)
		if err != nil {
			inventoryErr = err
		} else {
			var res struct {
				Kernels []string `json:"kernels"`
			}
			inventoryErr = json.Unmarshal([]byte(strings.TrimSpace(lastLines(string(out), 1))), &res)
			for _, kernel := range res.Kernels {
				add(kernel)
			}
		}
	}
	var kernels []string
	for kernel := range seen {
		kernels = append(kernels, kernel)
	}
	sort.Slice(kernels, func(i, j int) bool {
		a, _ := strconv.Atoi(genericABI.FindStringSubmatch(kernels[i])[1])
		c, _ := strconv.Atoi(genericABI.FindStringSubmatch(kernels[j])[1])
		return a < c
	})
	return kernels, inventoryErr
}
