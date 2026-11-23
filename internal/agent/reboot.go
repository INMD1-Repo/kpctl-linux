// 이 파일: agent 패키지의 bootID, bootTarget, clearBootChoice 구현·자료형.
package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"kpctl/internal/model"
)

func (a *Agent) bootID() string {
	data, _ := os.ReadFile(a.cfg.BootIDPath)
	return strings.TrimSpace(string(data))
}

func (a *Agent) bootTarget() (*model.BootTarget, string) {
	info, err := os.Stat(a.cfg.BootTargetPath)
	if err != nil {
		return nil, "다음 GA 커널 준비 필요 (kpctl-prepare-kernel)"
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Size() > 8192 {
		return nil, "커널 준비 기록의 권한·형식 오류"
	}
	if st, ok := info.Sys().(*syscall.Stat_t); !ok || st.Uid != uint32(os.Geteuid()) {
		return nil, "커널 준비 기록 소유자 오류"
	}
	data, err := os.ReadFile(a.cfg.BootTargetPath)
	if err != nil {
		return nil, err.Error()
	}
	var target model.BootTarget
	if err = json.Unmarshal(data, &target); err != nil {
		return nil, "커널 준비 기록 해석 실패"
	}
	target.ID = model.BootTargetID(target)
	if !model.ValidBootTarget(a.kernelRelease(), &target) || model.IsHWESignature(a.kernelSignature()) {
		return nil, "더 새로운 동일 계열 GA 커널이 필요합니다"
	}
	files := map[string]string{filepath.Join(a.cfg.BootDir, "vmlinuz-"+target.Kernel): target.ImageSHA256, filepath.Join(a.cfg.BootDir, "initrd.img-"+target.Kernel): target.InitrdSHA256, filepath.Join(a.cfg.BootDir, "config-"+target.Kernel): target.ConfigSHA256, a.cfg.GrubConfig: target.GrubSHA256}
	for path, want := range files {
		sum, err := fileSHA256(path)
		if err != nil || sum != want {
			return nil, "준비된 커널·initrd·GRUB 파일 변경: " + filepath.Base(path)
		}
	}
	grub, err := os.ReadFile(a.cfg.GrubConfig)
	if err != nil {
		return nil, err.Error()
	}
	parts := strings.Split(target.Entry, ">")
	if len(parts) != 2 || !strings.Contains(string(grub), "'"+parts[0]+"'") || !strings.Contains(string(grub), "'"+parts[1]+"'") || !strings.Contains(string(grub), `set default="${saved_entry}"`) {
		return nil, "검증한 GRUB 부팅 항목을 찾을 수 없습니다"
	}
	if saved, err := a.grubField("saved_entry"); err != nil || saved != target.FallbackEntry {
		return nil, "현재 커널의 기본 부팅 항목이 고정되지 않았습니다"
	}
	return &target, ""
}

func (a *Agent) clearBootChoice() error {
	p := a.st.PendingReboot
	if p == nil {
		return nil
	}
	if a.st.BootChoiceArmed {
		next, err := a.grubEnv()
		if err != nil {
			return err
		}
		if next == p.Target.Entry {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := exec.CommandContext(ctx, a.cfg.GrubEditenvBin, a.cfg.GrubEnv, "unset", "next_entry").Run(); err != nil {
				return err
			}
			if next, err := a.grubEnv(); err != nil || next == p.Target.Entry {
				return fmt.Errorf("만료된 다음 부팅 항목 정리를 확인하지 못했습니다: %v", err)
			}
		}
	}
	a.st.BootChoiceArmed = false
	return nil
}

// Run before network IO, so an expired one-shot choice is removed even when
// the controller cannot be reached or the agent died after selecting GRUB.
func (a *Agent) expireBootChoice() error {
	p := a.st.PendingReboot
	if p != nil && !time.Now().Before(p.ExpiresAt) {
		if err := a.clearBootChoice(); err != nil {
			return err
		}
		if a.bootID() == p.FromBootID || a.bootID() == "" {
			a.st.PendingReboot = nil
		}
		return a.saveState()
	}
	return nil
}

func (a *Agent) reconcileBootChoice(resp model.ReportResponse) error {
	p := a.st.PendingReboot
	if p == nil {
		return nil
	}
	result := resp.RebootResult
	if a.bootID() != p.FromBootID {
		if result == nil || result.ID != p.ID {
			return nil
		}
		if result.Status == "booted" && a.kernelRelease() == p.Target.Kernel && model.SignatureVersion(a.kernelSignature()) == p.Target.PackageVersion {
			stage, err := os.OpenFile(a.cfg.KernelPrepareLock, os.O_CREATE|os.O_RDWR, 0600)
			if err != nil {
				return err
			}
			defer stage.Close()
			if err := syscall.Flock(int(stage.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
				return fmt.Errorf("디스크 커널 준비 중에는 기본 부팅 확정을 보류합니다: %w", err)
			}
			for path, want := range map[string]string{filepath.Join(a.cfg.BootDir, "vmlinuz-"+p.Target.Kernel): p.Target.ImageSHA256, filepath.Join(a.cfg.BootDir, "initrd.img-"+p.Target.Kernel): p.Target.InitrdSHA256, filepath.Join(a.cfg.BootDir, "config-"+p.Target.Kernel): p.Target.ConfigSHA256, a.cfg.GrubConfig: p.Target.GrubSHA256} {
				sum, err := fileSHA256(path)
				if err != nil || sum != want {
					return fmt.Errorf("부팅 후 준비 파일 변경으로 기본 커널을 확정하지 못했습니다")
				}
			}
			if err := a.clearBootChoice(); err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			if err := exec.CommandContext(ctx, a.cfg.GrubSetDefaultBin, "--boot-directory="+a.cfg.BootDir, p.Target.Entry).Run(); err != nil {
				return err
			}
			if saved, err := a.grubField("saved_entry"); err != nil || saved != p.Target.Entry {
				return fmt.Errorf("새 커널 기본 부팅 확정 실패")
			}
			if err := a.retireBootTarget(p.Target); err != nil {
				return err
			}
			a.st.BootConfirmedID = p.ID
		} else if err := a.clearBootChoice(); err != nil {
			return err
		}
		a.st.PendingReboot = nil
		return a.saveState()
	}
	active := resp.Reboot != nil && resp.Reboot.ID == p.ID && time.Now().Before(resp.Reboot.ExpiresAt)
	if !active {
		if err := a.clearBootChoice(); err != nil {
			return err
		}
		a.st.PendingReboot = nil
		return a.saveState()
	}
	return nil
}

// A confirmed target is now the running baseline. Retire only its exact record
// so a later out-of-window jump can prepare another official kernel. Preserve
// a newer record prepared manually while confirmation was in progress. The
// caller holds KernelPrepareLock through GRUB confirmation and retirement.
func (a *Agent) retireBootTarget(confirmed model.BootTarget) error {
	info, err := os.Lstat(a.cfg.BootTargetPath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Size() > 8192 {
		return nil
	}
	if owner, ok := info.Sys().(*syscall.Stat_t); !ok || owner.Uid != uint32(os.Geteuid()) {
		return nil
	}
	data, err := os.ReadFile(a.cfg.BootTargetPath)
	if err != nil {
		return err
	}
	var recorded model.BootTarget
	if json.Unmarshal(data, &recorded) != nil {
		return nil
	}
	recorded.ID = model.BootTargetID(recorded)
	if recorded != confirmed {
		return nil
	}
	if err := os.Remove(a.cfg.BootTargetPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// Read argv[0] and executable names, so Linux's 15-byte comm truncation cannot
// hide QEMU. Process exit races are harmless; permission/read failures are not.
func (a *Agent) localVMCount() *int {
	entries, err := os.ReadDir(a.cfg.ProcDir)
	if err != nil {
		return nil
	}
	count := 0
	guest := func(name string) bool {
		name = strings.TrimSuffix(filepath.Base(name), " (deleted)")
		return strings.HasPrefix(name, "qemu-system-") || name == "qemu-kvm" || name == "kvm" || name == "firecracker" || name == "cloud-hypervisor" || name == "crosvm" || name == "bhyve" || name == "lxc-start" || name == "conmon" || strings.HasPrefix(name, "containerd-shim")
	}
	for _, entry := range entries {
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue
		}
		root := filepath.Join(a.cfg.ProcDir, entry.Name())
		args, err := os.ReadFile(filepath.Join(root, "cmdline"))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil
		}
		exe, err := os.Readlink(filepath.Join(root, "exe"))
		if err != nil && !os.IsNotExist(err) {
			return nil
		}
		first := strings.SplitN(string(args), "\x00", 2)[0]
		if guest(first) || guest(exe) {
			count++
		}
	}
	return &count
}

func (a *Agent) grubEnv() (string, error) { return a.grubField("next_entry") }
func (a *Agent) grubField(field string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, a.cfg.GrubEditenvBin, a.cfg.GrubEnv, "list").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("GRUB 환경 확인 실패: %w", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, field+"=") {
			return strings.TrimPrefix(line, field+"="), nil
		}
	}
	return "", nil
}

func (a *Agent) maybeReboot(approval *model.RebootApproval) {
	if approval == nil || approval.ID <= a.st.LastRebootID {
		return
	}
	if a.prepareDone != nil {
		log.Print("커널 준비 작업이 끝난 뒤 재부팅 승인을 확인합니다")
		return
	}
	if a.st.BootChoiceArmed {
		log.Print("이전 부팅 선택 정리를 먼저 확인해야 합니다")
		return
	}
	fail := func(err error) {
		a.st.RebootError = err.Error()
		_ = a.saveState()
		log.Printf("재부팅 실행 거부: %v", err)
	}
	a.st.LastRebootID = approval.ID
	a.st.RebootError = ""
	cp := *approval
	a.st.PendingReboot = &cp
	if err := a.saveState(); err != nil {
		log.Printf("상태 저장 실패로 재부팅을 실행하지 않습니다: %v", err)
		return
	}
	if !time.Now().Before(approval.ExpiresAt) || approval.FromBootID == "" || a.bootID() != approval.FromBootID || a.kernelRelease() != approval.FromKernel {
		fail(fmt.Errorf("만료됐거나 현재 부팅과 다른 재부팅 승인"))
		return
	}
	if a.lastErr != "" {
		fail(fmt.Errorf("에이전트 오류가 있어 재부팅하지 않습니다: %s", a.lastErr))
		return
	}
	locks := []*os.File{}
	defer func() {
		for _, f := range locks {
			f.Close()
		}
	}()
	stage, err := os.OpenFile(a.cfg.KernelPrepareLock, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		fail(err)
		return
	}
	locks = append(locks, stage)
	if err = syscall.Flock(int(stage.Fd()), syscall.LOCK_SH|syscall.LOCK_NB); err != nil {
		fail(fmt.Errorf("디스크 커널 준비 작업이 진행 중입니다"))
		return
	}
	for _, path := range a.cfg.PackageLocks {
		f, err := os.OpenFile(path, os.O_RDWR, 0)
		if err != nil {
			fail(err)
			return
		}
		locks = append(locks, f)
		lock := syscall.Flock_t{Type: syscall.F_WRLCK, Whence: 0}
		if err = syscall.FcntlFlock(f.Fd(), syscall.F_SETLK, &lock); err != nil {
			fail(fmt.Errorf("APT/dpkg 작업이 진행 중입니다"))
			return
		}
	}
	target, problem := a.bootTarget()
	if target == nil || *target != approval.Target {
		fail(fmt.Errorf("승인한 디스크 커널과 다릅니다: %s", problem))
		return
	}
	if count := a.localVMCount(); count == nil || *count != 0 {
		fail(fmt.Errorf("로컬 VM·컨테이너가 없음을 확인하지 못했습니다"))
		return
	}
	if next, err := a.grubEnv(); err != nil || next != "" {
		fail(fmt.Errorf("다른 GRUB 다음 부팅 요청이 있거나 확인 실패: %v", err))
		return
	}
	// No legacy ID-only requests are executed. Claim again immediately before
	// changing GRUB, so cancellation, expiry and drain changes are authoritative.
	if err := a.c.Do("POST", "/api/agent/reboot/claim", model.RebootClaim{ID: approval.ID, BootID: a.bootID(), TargetID: target.ID}, nil); err != nil {
		fail(fmt.Errorf("관리자 재부팅 승인 재확인 실패: %w", err))
		return
	}
	a.st.BootChoiceArmed = true
	if err := a.saveState(); err != nil {
		fail(err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	out, err := exec.CommandContext(ctx, a.cfg.GrubRebootBin, "--boot-directory="+a.cfg.BootDir, target.Entry).CombinedOutput()
	cancel()
	cleanup := func() {
		if next, e := a.grubEnv(); e == nil && next == target.Entry {
			_ = exec.Command(a.cfg.GrubEditenvBin, a.cfg.GrubEnv, "unset", "next_entry").Run()
		}
	}
	if err != nil {
		cleanup()
		fail(fmt.Errorf("승인 커널 부팅 선택 실패: %w: %s", err, strings.TrimSpace(string(out))))
		return
	}
	if next, e := a.grubEnv(); e != nil || next != target.Entry {
		cleanup()
		fail(fmt.Errorf("승인 커널의 GRUB 다음 부팅 선택을 확인하지 못했습니다"))
		return
	}
	// Check again after the controller round trip. A changed target never boots.
	if latest, _ := a.bootTarget(); latest == nil || *latest != *target || !time.Now().Before(approval.ExpiresAt) {
		cleanup()
		fail(fmt.Errorf("승인 이후 디스크 커널이 바뀌었거나 승인이 만료됐습니다"))
		return
	}
	ctx, cancel = context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/sh", a.cfg.RebootHook)
	cmd.Env = append(os.Environ(), "KPCTL_REBOOT_ID="+strconv.Itoa(approval.ID), "KPCTL_REBOOT_APPROVED=1", "KPCTL_TARGET_KERNEL="+target.Kernel, "KPCTL_TARGET_ID="+target.ID)
	if out, err := cmd.CombinedOutput(); err != nil {
		cleanup()
		fail(fmt.Errorf("재부팅 훅 실패: %w: %s", err, strings.TrimSpace(string(out))))
	}
}
