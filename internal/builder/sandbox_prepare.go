// 이 파일: builder 패키지의 ensureSandboxProfile, maintainSandbox, maintainSandboxSpace 구현·자료형.
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
	"syscall"
	"time"
)

// Legacy configs omit both flags. Leave those helpers on their own defaults
// when the builder binary is updated independently of the installed helper.
func (p *SandboxPreparation) timeouts() ([]string, time.Duration) {
	var args []string
	snapshotMinutes, imageMinutes := 20, 180
	if p.SnapshotTimeoutMinutes != nil {
		snapshotMinutes = *p.SnapshotTimeoutMinutes
		args = append(args, "--snapshot-timeout-minutes", strconv.Itoa(snapshotMinutes))
	}
	if p.ImageTimeoutMinutes != nil {
		imageMinutes = *p.ImageTimeoutMinutes
		args = append(args, "--image-timeout-minutes", strconv.Itoa(imageMinutes))
	}
	candidates := 1
	if p.Snapshot == "auto" && p.Sources == "" {
		candidates = 8 // Two publication dates plus up to six dates around the kernel Git tag.
	}
	// Keep time for the base image, Git inputs, manifest verification and cleanup.
	return args, time.Duration(candidates*snapshotMinutes+imageMinutes+45) * time.Minute
}

const profileFailureCooldown = 30 * time.Minute

type archiveCooldown struct {
	retryAt time.Time
	cause   error
}

func (e *archiveCooldown) Error() string { return e.cause.Error() }
func (e *archiveCooldown) Unwrap() error { return e.cause }

func (b *Builder) ensureSandboxProfile(k KernelConfig) (string, error) {
	path, err := b.sandboxProfile(k.Kernel)
	if err == nil || !errors.Is(err, errSandboxProfileMissing) {
		return path, err
	}
	s := b.cfg.Sandbox
	if s.AutoPrepare == nil || !*s.AutoPrepare {
		return "", err
	}
	key := gccID(kernelCompiler(k.Kernel, b.headersRoot))
	failureKey := key + " " + k.Kernel + " " + k.BaseTag
	if previous, ok := b.profileFailed[failureKey]; ok && time.Since(previous.at) < profileFailureCooldown {
		if errors.Is(previous.err, errBuildDeferred) {
			b.retryDiscovery = true
		}
		return "", previous.err
	}
	p := s.Prepare
	if p == nil {
		return "", fmt.Errorf("sandbox.prepare 설정이 없습니다")
	}
	base := p.BaseImage
	if base == "" {
		var pin struct {
			BaseImage string `json:"base_image"`
		}
		data, readErr := os.ReadFile(filepath.Join(s.ProfilesDir, "base-image.json"))
		if readErr == nil {
			_ = json.Unmarshal(data, &pin)
		}
		base = pin.BaseImage
	}
	if !regexpBaseDigest.MatchString(base) {
		return "", fmt.Errorf("자동 준비의 base_image를 설치 시 고정한 @sha256 digest로 지정하세요")
	}
	args := []string{"prepare", "--kernel", k.Kernel, "--base-image", base, "--memory-mib", strconv.Itoa(p.MemoryMiB),
		"--pids", strconv.Itoa(p.PIDs), "--min-free-gib", strconv.Itoa(p.MinFreeGiB), "--cache-gib", strconv.Itoa(*p.CacheGiB),
		"--cache-total-gib", strconv.Itoa(p.CacheTotalGiB), "--snapshot", p.Snapshot}
	timeoutArgs, timeout := p.timeouts()
	args = append(args, timeoutArgs...)
	if s.ProfilesDir != "" {
		args = append(args, "--profiles-dir", s.ProfilesDir)
	} else {
		args = append(args, "--directory", filepath.Dir(s.Profile))
	}
	if k.GitDir != "" {
		args = append(args, "--git-dir", k.GitDir)
	}
	if k.BaseTag != "" {
		args = append(args, "--base-tag", k.BaseTag)
	}
	if p.Sources != "" {
		args = append(args, "--sources", p.Sources)
	}
	for _, pin := range p.Packages {
		args = append(args, "--package", pin)
	}
	b.setStep("대상 GCC 프로파일 자동 준비 · 서명 스냅샷·고정 레시피")
	log.Printf("[%s] 대상 컴파일러 프로파일 자동 준비: %s", k.Kernel, key)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, s.Helper, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM) }
	cmd.WaitDelay = 30 * time.Second
	profilePath := s.Profile
	if s.ProfilesDir != "" {
		// Same deterministic path as the pure selector, including an absent file.
		profilePath = filepath.Join(s.ProfilesDir, compilerProfileName(key), "profile.json")
	}
	stop := b.followBuildLog(filepath.Join(filepath.Dir(profilePath), "image-build.log"))
	defer stop()
	output, prepareErr := b.commandOutput(cmd)
	var exit *exec.ExitError
	detail := strings.TrimSpace(lastLines(string(output), 20))
	if errors.As(prepareErr, &exit) {
		switch exit.ExitCode() {
		case 73: // EX_CANTCREAT: the helper's disk space check failed.
			b.retryDiscovery = true
			return "", fmt.Errorf("%w: %s", errDiskSpace, detail)
		case 75: // EX_TEMPFAIL: another process owns the build lock.
			b.retryDiscovery = true
			return "", errBuildBusy
		}
	}
	if prepareErr == nil {
		path, prepareErr = b.sandboxProfile(k.Kernel)
	}
	if prepareErr != nil {
		failure := fmt.Errorf("대상 GCC 프로파일 자동 준비 실패 (30분 뒤 재시도): %w: %s", prepareErr, detail)
		failedAt := time.Now()
		// The helper reserves EX_UNAVAILABLE (69) for confirmed APT archive outages.
		if exit != nil && exit.ExitCode() == 69 {
			failure = &archiveCooldown{
				retryAt: failedAt.Add(profileFailureCooldown),
				cause:   fmt.Errorf("%w: APT 저장소 일시 장애 · 30분 뒤 재시도\n%s", errBuildDeferred, detail),
			}
			b.retryDiscovery = true
		}
		if b.profileFailed == nil {
			b.profileFailed = map[string]debugFailure{}
		}
		b.profileFailed[failureKey] = debugFailure{at: failedAt, err: failure}
		return "", failure
	}
	delete(b.profileFailed, failureKey)
	b.setStep("대상 GCC 프로파일 자동 준비 완료")
	return path, nil
}

func (b *Builder) maintainSandbox() {
	b.maintainSandboxSpace(0)
}

func (b *Builder) maintainSandboxSpace(minFreeGiB int) {
	s := b.cfg.Sandbox
	if s == nil || s.ProfilesDir == "" {
		return
	}
	args := []string{"gc", "--profiles-dir", s.ProfilesDir, "--inventory-complete", "--retention-days", strconv.Itoa(s.RetentionDays)}
	if minFreeGiB > 0 {
		args = append(args, "--min-free-gib", strconv.Itoa(minFreeGiB), "--work-dir", b.cfg.WorkDir)
	}
	for _, kernel := range b.activeKernels {
		args = append(args, "--active-kernel", kernel)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, s.Helper, args...)
	killProcessGroup(cmd)
	output, err := b.commandOutput(cmd)
	if err != nil {
		log.Printf("격리 환경 정리 보류: %v: %s", err, lastLines(string(output), 5))
	}
	if b.progress != nil {
		detail := strings.TrimSpace(lastLines(string(output), 5))
		if len(detail) > 3000 {
			detail = detail[:3000]
		}
		b.progress.mu.Lock()
		b.progress.maintenance = fmt.Sprintf("%s · %s", time.Now().UTC().Format(time.RFC3339), detail)
		if err != nil {
			b.progress.maintenance += " · 정리 보류"
		}
		b.progress.mu.Unlock()
	}
}
