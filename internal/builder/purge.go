// 이 파일: builder 패키지의 PurgeKernels, purgeKernel, canPurgeKernel 구현·자료형.
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
	"strconv"
	"strings"
	"time"

	"kpctl/internal/model"
)

// PurgeKernels 는 관리자가 웹에서 요청한 범위 밖 커널의 빌드 서버 자료를 지우고 결과를 알립니다.
// 컨트롤러의 패치·작업·모듈 기록과 호스트에 적용된 라이브패치는 건드리지 않습니다.
func (b *Builder) PurgeKernels(kernels []string) {
	for _, kernel := range kernels {
		if b.stopping() {
			return
		}
		b.setStep("빌드 서버 자료 삭제: " + kernel)
		summary, err := b.purgeKernel(kernel)
		result := summary
		if err != nil {
			if b.purgePending == nil {
				b.purgePending = map[string]bool{}
			}
			b.purgePending[kernel] = true
			result = "삭제하지 않음: " + err.Error()
			if summary != "" {
				result = summary + " · 중단: " + err.Error()
			}
			log.Printf("[%s] 빌드 서버 자료 삭제 실패: %v", kernel, err)
		} else {
			delete(b.purgePending, kernel)
			log.Printf("[%s] 빌드 서버 자료 삭제: %s", kernel, summary)
		}
		if len(result) > 3900 {
			result = result[:3900]
		}
		if err := b.c.Do("POST", "/api/builder/kernels/"+kernel+"/upstream", model.UpstreamReport{Purged: &result}, nil); err != nil {
			log.Printf("[%s] 자료 삭제 결과 보고 실패: %v", kernel, err)
		}
	}
}

// purgeKernel 은 등록 호스트가 더 이상 사용하지 않음을 다시 확인한 뒤 자료를 지웁니다.
func (b *Builder) purgeKernel(kernel string) (string, error) {
	if !b.cfg.autoKernels() {
		return "", errors.New("kernels 를 직접 지정한 빌드 서버는 자료 삭제를 지원하지 않습니다")
	}
	var resp model.HostKernelsResponse
	if err := b.c.Do("GET", "/api/builder/kernels", nil, &resp); err != nil {
		return "", fmt.Errorf("등록 호스트 커널 확인 실패: %w", err)
	}
	window, err := b.kernelWindow()
	if err != nil {
		return "", fmt.Errorf("최근 커널 범위를 확인하지 못했습니다: %w", err)
	}
	if err := b.canPurgeKernel(kernel, resp.Kernels, window); err != nil {
		return "", err
	}

	var done []string
	// 1) 격리 빌드의 봉인 캐시 (도우미가 빌드 계정 잠금을 직접 잡습니다)
	if s := b.cfg.Sandbox; s != nil {
		args := []string{"purge-kernel", "--kernel", kernel}
		if s.ProfilesDir != "" {
			args = append(args, "--profiles-dir", s.ProfilesDir)
		}
		if s.Profile != "" {
			args = append(args, "--profile", s.Profile)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		cmd := exec.CommandContext(ctx, s.Helper, args...)
		killProcessGroup(cmd)
		out, err := b.commandOutput(cmd)
		cancel()
		if err != nil {
			return strings.Join(done, " · "), fmt.Errorf("격리 캐시 삭제 실패: %v: %s", err, strings.TrimSpace(lastLines(string(out), 3)))
		}
		var res struct {
			Removed int   `json:"removed"`
			Bytes   int64 `json:"bytes"`
		}
		if json.Unmarshal([]byte(strings.TrimSpace(lastLines(string(out), 1))), &res) == nil {
			done = append(done, fmt.Sprintf("격리 캐시 %d개(%s)", res.Removed, humanBytes(res.Bytes)))
		}
	}

	// 2) 작업 디렉터리: 같은 빌드 계정·작업 디렉터리의 빌드와 겹치지 않게 잠급니다.
	userLock, err := lockUserBuild()
	if err != nil {
		return strings.Join(done, " · "), fmt.Errorf("다른 빌드가 진행 중이라 나머지는 지우지 않았습니다. 다시 요청하세요: %w", err)
	}
	defer userLock.Close()
	lock, err := b.lockBuild()
	if err != nil {
		return strings.Join(done, " · "), fmt.Errorf("작업 디렉터리 사용 중: %w", err)
	}
	defer lock.Close()
	trials, err := b.purgeKernelWorkDir(kernel)
	if err != nil {
		return strings.Join(done, " · "), err
	}
	done = append(done, fmt.Sprintf("시험·소스 기록 %d개", trials))

	// 3) 디버그 심볼·커널 패키지 (도우미가 실행 중 커널·다른 패키지 연쇄 삭제를 다시 막습니다)
	if _, err := os.Stat(b.cfg.DebugHelper); err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
		out, err := b.commandOutput(exec.CommandContext(ctx, "sudo", "-n", b.cfg.DebugHelper, "--remove", kernel))
		cancel()
		if err != nil {
			return strings.Join(done, " · "), fmt.Errorf("디버그 심볼 삭제 실패: %v: %s", err, strings.TrimSpace(lastLines(string(out), 3)))
		}
		done = append(done, strings.TrimSpace(lastLines(string(out), 1)))
	} else {
		if err := os.Remove(filepath.Join(b.cfg.DebugDir, "vmlinux-"+kernel)); err == nil {
			done = append(done, "vmlinux 삭제")
		} else if !errors.Is(err, os.ErrNotExist) {
			return strings.Join(done, " · "), err
		}
	}

	delete(b.lastTarget, kernel)
	delete(b.debugFailed, kernel)
	return strings.Join(done, " · "), nil
}

func (b *Builder) canPurgeKernel(kernel string, hosts []model.HostKernel, window kernelRange) error {
	if !b.ownKernel(kernel) {
		return fmt.Errorf("이 빌드 서버 시리즈(%s)의 GA generic 커널이 아닙니다", b.cfg.Series)
	}
	release, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return fmt.Errorf("실행 중 커널 확인 실패: %w", err)
	}
	return purgeKernelProtection(kernel, hosts, window, strings.TrimSpace(string(release)))
}

func purgeKernelProtection(kernel string, hosts []model.HostKernel, window kernelRange, running string) error {
	for _, host := range hosts {
		if host.Kernel == kernel {
			return errors.New("등록 호스트가 사용하는 커널이라 지우지 않습니다")
		}
	}
	abi, _ := strconv.Atoi(genericABI.FindStringSubmatch(kernel)[1])
	if window.latest == 0 || abi >= window.latest {
		return errors.New("정식 배포 최신 커널 이상이거나 최신을 확인하지 못해 지우지 않습니다")
	}
	if running == kernel {
		return errors.New("빌드 서버가 지금 실행 중인 커널입니다")
	}
	return nil
}

// purgeKernelWorkDir 는 그 커널의 남은 시험 빌드 기록과 klp 소스를 지웁니다. 다른 커널의 것은 남깁니다.
func (b *Builder) purgeKernelWorkDir(kernel string) (int, error) {
	n := 0
	if path := b.trialFailurePath(kernel); path != "" {
		if err := os.Remove(path); err == nil {
			n++
		} else if !os.IsNotExist(err) {
			return n, err
		}
	}
	src := filepath.Join(b.cfg.WorkDir, "src", kernel)
	if fi, err := os.Lstat(src); err == nil && fi.IsDir() {
		if err := os.RemoveAll(src); err != nil {
			return n, err
		}
		n++
	}
	dirs, err := filepath.Glob(filepath.Join(b.cfg.WorkDir, "trial-*"))
	if err != nil {
		return n, err
	}
	for _, dir := range dirs {
		fi, err := os.Lstat(dir)
		if err != nil || !fi.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, "out", "environment-request.json"))
		if err != nil {
			continue // 커널을 확인할 수 없는 기록은 남깁니다.
		}
		var req struct {
			Kernel struct {
				Kernel string `json:"kernel"`
			} `json:"kernel"`
		}
		if json.Unmarshal(data, &req) != nil || req.Kernel.Kernel != kernel {
			continue
		}
		if err := os.RemoveAll(dir); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

func humanBytes(n int64) string {
	const gib = 1 << 30
	if n >= gib {
		return strconv.FormatFloat(float64(n)/gib, 'f', 1, 64) + " GiB"
	}
	return strconv.FormatInt(n>>20, 10) + " MiB"
}
