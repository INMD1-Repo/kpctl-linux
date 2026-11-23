// 이 파일: agent 패키지의 maybePrepareKernel, finishKernelPrepare, failKernelPrepare 구현·자료형.
package agent

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"kpctl/internal/model"
)

const (
	kernelPrepareRetry   = 6 * time.Hour
	kernelPrepareTimeout = 45 * time.Minute
	kernelPrepareGrace   = 30 * time.Second
	kernelPrepareBin     = "/usr/local/sbin/kpctl-prepare-kernel"
)

type kernelPrepareResult struct {
	err error
}

// The worker only returns a result. State remains owned by Cycle, including
// during network reports, patch application and reboot approval expiry checks.
func (a *Agent) maybePrepareKernel(resp model.ReportResponse) bool {
	if !resp.PrepareKernel || resp.Reboot != nil || resp.RebootID != 0 || a.st.PendingReboot != nil || a.st.BootChoiceArmed || a.prepareDone != nil {
		return false
	}
	kernel := a.kernelRelease()
	if model.LTSForKernel(kernel) == nil || model.IsHWESignature(a.kernelSignature()) {
		return false
	}
	// Only an explicit request bound to the currently validated record permits
	// refreshing an old prepared target. Keep it until the helper atomically
	// publishes its replacement; ordinary preparation never overwrites records.
	info, recordErr := os.Lstat(a.cfg.BootTargetPath)
	if resp.PrepareKernelTargetID != "" {
		if recordErr != nil || !info.Mode().IsRegular() {
			return false
		}
		target, _ := a.bootTarget()
		if target == nil || target.ID != resp.PrepareKernelTargetID {
			return false
		}
		if next, err := a.grubEnv(); err != nil || next != "" {
			return false
		}
	} else if !os.IsNotExist(recordErr) {
		// Corrupt records and dangling symlinks also require review.
		return false
	}
	now := time.Now()
	// 새 관리자 요청(원인을 고친 뒤 다시 누름)은 재시도 대기를 건너뜁니다. 요청 시각을 기록해
	// 같은 요청으로 반복 실행하지 않으며, 두 시계를 비교하지 않아 시계 차이와 무관합니다.
	var request time.Time
	if resp.PrepareKernelRequest != nil {
		request = *resp.PrepareKernelRequest
	}
	if p := a.st.KernelPrepare; p != nil && p.Kernel == kernel {
		fresh := !request.IsZero() && !request.Equal(p.Request)
		if now.Before(p.NextAttemptAt) && !fresh {
			return false
		}
	}
	parent := a.prepareCtx
	if parent == nil {
		parent = context.Background()
	}
	if parent.Err() != nil {
		return false
	}
	before := a.st.KernelPrepare
	a.st.KernelPrepare = &model.KernelPrepareStatus{Kernel: kernel, State: "preparing", AttemptedAt: now, Request: request}
	if filepath.Clean(a.cfg.BootTargetPath) != filepath.Join(a.cfg.StateDir, "boot-target.json") {
		a.st.KernelPrepare.State = "failed"
		a.st.KernelPrepare.Error = "자동 커널 준비에는 boot_target_path가 state_dir/boot-target.json이어야 합니다"
		a.st.KernelPrepare.NextAttemptAt = now.Add(kernelPrepareRetry)
	}
	if err := a.saveState(); err != nil {
		a.st.KernelPrepare = before
		log.Printf("커널 준비 상태 저장 실패로 실행하지 않습니다: %v", err)
		return false
	}
	if a.st.KernelPrepare.State == "failed" {
		log.Print(a.st.KernelPrepare.Error)
		return true
	}
	ctx, cancel := context.WithTimeout(parent, kernelPrepareTimeout)
	done := make(chan kernelPrepareResult, 1)
	a.prepareDone, a.prepareCancel = done, cancel
	run := a.prepareRun
	if run == nil {
		replaceID := resp.PrepareKernelTargetID
		run = func(ctx context.Context, stateDir string) error {
			args := []string{"--state-dir", stateDir}
			if replaceID != "" {
				args = append(args, "--replace-target-id", replaceID)
			}
			return runKernelPrepareCommand(ctx, kernelPrepareGrace, kernelPrepareBin, args...)
		}
	}
	stateDir := a.cfg.StateDir
	go func() {
		err := run(ctx, stateDir)
		cancel()
		done <- kernelPrepareResult{err: err}
	}()
	log.Print("공식 GA 커널 자동 준비 시작 (재부팅은 관리자 승인 필요)")
	return true
}

func (a *Agent) finishKernelPrepare(result kernelPrepareResult) {
	a.prepareCancel()
	a.prepareDone, a.prepareCancel = nil, nil
	p := a.st.KernelPrepare
	err := result.err
	if err == nil {
		if target, problem := a.bootTarget(); target == nil {
			err = fmt.Errorf("준비한 커널 검증 실패: %s", problem)
		}
	}
	if err != nil {
		a.failKernelPrepare(err)
		log.Printf("공식 GA 커널 준비 실패: %s", p.Error)
	} else {
		p.State, p.Error, p.NextAttemptAt = "prepared", "", time.Time{}
		log.Print("공식 GA 커널 준비 완료 (재부팅은 관리자 승인 필요)")
	}
	if err := a.saveState(); err != nil {
		log.Printf("커널 준비 결과 저장 실패: %v", err)
	}
}

func (a *Agent) failKernelPrepare(err error) {
	p := a.st.KernelPrepare
	p.State, p.Error = "failed", err.Error()
	p.NextAttemptAt = time.Now().Add(kernelPrepareRetry)
	if _, recordErr := os.Lstat(a.cfg.BootTargetPath); !os.IsNotExist(recordErr) {
		if target, problem := a.bootTarget(); target == nil {
			p.Error += "; 준비 기록·파일 검토 필요 (자동 갱신 중지): " + problem
			p.NextAttemptAt = time.Time{}
		}
	}
}

func (a *Agent) pollKernelPrepare() {
	if a.prepareDone == nil {
		return
	}
	select {
	case result := <-a.prepareDone:
		a.finishKernelPrepare(result)
	default:
	}
}

func (a *Agent) stopKernelPrepare() {
	if a.prepareDone != nil {
		a.prepareCancel()
		a.finishKernelPrepare(<-a.prepareDone)
	}
}

// Keep only the end of apt output so long package logs cannot grow agent RAM.
type prepareOutput struct{ tail []byte }

func (b *prepareOutput) Write(data []byte) (int, error) {
	n := len(data)
	if len(data) >= 4096 {
		b.tail = append(b.tail[:0], data[len(data)-4096:]...)
	} else {
		b.tail = append(b.tail, data...)
		if len(b.tail) > 4096 {
			copy(b.tail, b.tail[len(b.tail)-4096:])
			b.tail = b.tail[:4096]
		}
	}
	return n, nil
}

// Cancel the entire package-command group, allowing TERM to finish cleanly
// before the bounded final cleanup. Killing only Python can leave apt/dpkg
// running, or keep stdout pipes open indefinitely.
func runKernelPrepareCommand(ctx context.Context, grace time.Duration, bin string, args ...string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	cmd := exec.Command(bin, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.WaitDelay = 5 * time.Second
	out := &prepareOutput{}
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Start(); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("커널 준비 도우미 %s 가 없습니다. 에이전트를 다시 설치하세요 (kpctl install <호스트>): %w", bin, err)
		}
		return err
	}
	defer syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	var err error
	select {
	case err = <-done:
	case <-ctx.Done():
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
		timer := time.NewTimer(grace)
		select {
		case <-done:
			// Wait the remaining grace only if a descendant survived TERM.
			if syscall.Kill(-cmd.Process.Pid, 0) == nil {
				<-timer.C
			}
		case <-timer.C:
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			<-done
		}
		timer.Stop()
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		err = ctx.Err()
	}
	if err != nil {
		return fmt.Errorf("공식 커널 준비: %w: %s", err, strings.TrimSpace(string(out.tail)))
	}
	return nil
}
