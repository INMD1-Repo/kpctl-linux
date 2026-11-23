// 이 파일: builder 패키지의 resolveTaskKernel, checkTaskKernelWindow, prepareConfiguredInputs 구현·자료형.
package builder

import (
	"fmt"
	"log"
	"strings"

	"kpctl/internal/model"
)

// resolveTaskKernel uses the controller's snapshot before preparing debug
// symbols or choosing a source tag. Older controllers retain the lookup path.
func (b *Builder) resolveTaskKernel(task model.BuildTask) (KernelConfig, error) {
	info := task.KernelInfo
	if info != nil {
		if err := info.Validate(task.Job.Kernel); err != nil {
			return KernelConfig{}, fmt.Errorf("%w: %v", errBuildEnv, err)
		}
	}
	if err := b.checkTaskKernelWindow(task.Job.Kernel); err != nil {
		return KernelConfig{}, err
	}
	if info == nil {
		k := b.resolveKernel(task.Job.Kernel)
		if !b.cfg.autoKernels() {
			return k, b.prepareConfiguredInputs(k)
		}
		return k, nil
	}
	if !b.cfg.autoKernels() {
		k := b.cfg.kernelConfig(task.Job.Kernel)
		if k.BaseTag != "" && k.BaseTag != info.BaseTag {
			return KernelConfig{}, fmt.Errorf("%w: 설정한 기준 태그 %s와 컨트롤러 기준 %s가 다릅니다", errBuildEnv, k.BaseTag, info.BaseTag)
		}
		if k.GitDir != "" {
			k.BaseTag = info.BaseTag
		}
		return k, b.prepareConfiguredInputs(k)
	}
	// autoKernel keeps the normal series, HWE, debug symbol and toolchain checks.
	b.profileBusy = false
	k, reason := b.autoKernel(model.HostKernel{Kernel: info.Kernel, Signature: info.Signature})
	if b.profileBusy {
		return KernelConfig{}, errBuildBusy
	}
	if reason != "" || k.Kernel == "" {
		return KernelConfig{}, fmt.Errorf("%w: 컨트롤러 커널 기준으로 준비할 수 없습니다 (%s): %s", errBuildEnv, info.Kernel, reason)
	}
	return k, nil
}

// A queued cumulative job can predate an administrator's max_kernels change.
// Apply the same automatic range policy before installing its inputs, including
// when the controller supplies an exact kernel snapshot and bypasses kernels().
func (b *Builder) checkTaskKernelWindow(kernel string) error {
	if !b.cfg.autoKernels() || b.cfg.MaxKernels <= 0 {
		return nil
	}
	series := model.LTSForKernel(kernel)
	if series == nil || series.Codename != b.cfg.Series {
		return nil // Preserve the existing series and unsupported-kernel checks.
	}
	window, err := b.kernelWindow()
	if err == nil {
		b.lastWindow = window
	} else if b.lastWindow.latest > 0 {
		log.Printf("작업의 최근 커널 범위 확인 실패, 마지막으로 확인한 범위(ABI %d 이상) 사용: %v", b.lastWindow.floor, err)
		window = b.lastWindow
	} else {
		log.Printf("작업의 최근 커널 범위 확인 실패, 확인 이력이 없어 범위 제한 없이 진행: %v", err)
		return nil
	}
	if window.contains(kernel) {
		if b.c != nil {
			b.reportOutside(kernel, "", window.latestTag)
		}
		return nil
	}
	reason := window.outsideReason()
	if b.c != nil {
		b.reportOutside(kernel, reason, window.latestTag)
	}
	return &buildFailure{kind: model.FailureUnsupported, err: fmt.Errorf("빌더 범위 밖 커널 %s: %s · 공식 커널 준비 및 관리자 승인 재부팅 필요", kernel, reason)}
}

func (b *Builder) prepareConfiguredInputs(k KernelConfig) error {
	if !b.cfg.autoControllerInputs() {
		return nil
	}
	version, ok := strings.CutPrefix(k.BaseTag, "Ubuntu-")
	if !ok || version == "" {
		return fmt.Errorf("%w: 컨트롤러 입력 전달에는 정확한 Ubuntu 기준 태그가 필요합니다 (%s)", errBuildEnv, k.Kernel)
	}
	if err := b.installDebug(k.Kernel, version); err != nil {
		return fmt.Errorf("%w: %v", errBuildEnv, err)
	}
	return nil
}
