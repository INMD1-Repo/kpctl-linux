// 이 파일: 라이브패치 실제 전환 상태·외부 공급자 거부와 자기 모듈 정리.
package agent

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"kpctl/internal/model"
)

// kpatch 는 kpatch 명령을 실행합니다.
//
//	kpatch install <file.ko>   /var/lib/kpatch/<커널>/ 에 복사 → 재부팅해도 kpatch.service 가 다시 올림
//	kpatch load <file.ko>      지금 커널에 올림
//	kpatch unload <name>       내림
//	kpatch uninstall <name>    설치본 삭제
func (a *Agent) kpatch(args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, a.cfg.KpatchBin, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("kpatch %s 실패: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// readTrim 은 파일 내용을 읽어 앞뒤 공백을 지웁니다.
func readTrim(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// loadedPatches 는 /sys/kernel/livepatch/ 아래의 모든 라이브패치를 읽습니다.
// (우리 것이 아닌 패치도 보고용으로 모두 읽습니다)
func (a *Agent) loadedPatches() []model.LoadedPatch {
	entries, err := os.ReadDir(a.cfg.LivepatchSysfs)
	if err != nil {
		return nil
	}
	var out []model.LoadedPatch
	for _, e := range entries {
		dir := filepath.Join(a.cfg.LivepatchSysfs, e.Name())
		out = append(out, model.LoadedPatch{
			Name:    e.Name(),
			Enabled: readTrim(filepath.Join(dir, "enabled")) == "1",
			// 읽기 실패도 미완료로 보고하여 컨트롤러가 정상으로 판단하지 않게 합니다.
			Transition: readTrim(filepath.Join(dir, "transition")) != "0",
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// patchEnabled 는 해당 이름의 라이브패치가 켜져 있는지 확인합니다.
func (a *Agent) patchEnabled(name string) bool {
	return readTrim(filepath.Join(a.cfg.LivepatchSysfs, name, "enabled")) == "1"
}

// checkCanLoad 는 atomic replace 가 다른 공급자의 패치를 없애지 않도록 확인합니다.
// replace 는 접두사와 무관하게 기존 라이브패치 전체를 교체합니다.
func (a *Agent) checkCanLoad(name string) error {
	entries, err := os.ReadDir(a.cfg.LivepatchSysfs)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("라이브패치 상태 확인 실패: %w", err)
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(a.cfg.LivepatchSysfs, e.Name())
		values := make(map[string]string, 2)
		for _, attr := range []string{"enabled", "transition"} {
			data, err := os.ReadFile(filepath.Join(dir, attr))
			if err != nil {
				return fmt.Errorf("%s %s 확인 실패: %w", e.Name(), attr, err)
			}
			v := strings.TrimSpace(string(data))
			if v != "0" && v != "1" {
				return fmt.Errorf("%s %s 상태가 올바르지 않습니다: %q", e.Name(), attr, v)
			}
			values[attr] = v
		}
		if !strings.HasPrefix(e.Name(), a.cfg.ModulePrefix) && (values["enabled"] == "1" || values["transition"] == "1") {
			return fmt.Errorf("외부 라이브패치 %s 가 활성 또는 전환 중이므로 atomic replace 를 실행하지 않습니다", e.Name())
		}
		if e.Name() != name && values["transition"] == "1" {
			return fmt.Errorf("%s 의 라이브패치 전환이 끝나지 않아 새 패치를 적용하지 않습니다", e.Name())
		}
	}
	return nil
}

// moduleLoaded 는 커널 모듈이 메모리에 올라가 있는지 확인합니다.
// (교체된 이전 패치는 /sys/kernel/livepatch 에서는 사라져도 모듈은 남아 있을 수 있음)
func (a *Agent) moduleLoaded(name string) bool {
	_, err := os.Stat(filepath.Join(a.cfg.ModuleSysfs, name))
	return err == nil
}

// waitTransition 은 패치 전환이 끝날 때까지 기다립니다.
// 전환은 모든 태스크가 새 코드로 넘어가야 끝나며, 보통 수 초 안에 끝납니다.
// enabled=1 이고 transition=0 인 경우에만 완료로 봅니다. 상태를 읽을 수 없어도 실패입니다.
func (a *Agent) waitTransition(name string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	dir := filepath.Join(a.cfg.LivepatchSysfs, name)
	for {
		if !a.patchEnabled(name) {
			return false
		}
		switch readTrim(filepath.Join(dir, "transition")) {
		case "0":
			return true
		case "1":
		default:
			return false
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return false
		}
		time.Sleep(min(time.Second, remaining))
	}
}

func (a *Agent) kernelRelease() string { return readTrim(a.cfg.OSReleasePath) }

func (a *Agent) kernelSignature() string { return readTrim(a.cfg.SignaturePath) }

func (a *Agent) tainted() int64 {
	v, _ := strconv.ParseInt(readTrim(a.cfg.TaintedPath), 10, 64)
	return v
}

// ourLoadedModules 는 메모리에 올라간 우리 모듈(접두사가 맞는 것) 이름 목록입니다.
func (a *Agent) ourLoadedModules() []string {
	seen := map[string]bool{}
	for _, dir := range []string{a.cfg.LivepatchSysfs, a.cfg.ModuleSysfs} {
		entries, _ := os.ReadDir(dir)
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), a.cfg.ModulePrefix) {
				seen[e.Name()] = true
			}
		}
	}
	var out []string
	for n := range seen {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}
