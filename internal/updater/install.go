// 이 파일: 역할별 바이너리·도우미·번들·systemd 유닛 원자적 설치와 서비스 재시작.
package updater

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func installRoles(sysRoot, repoDir, binDir string, roles []Role, opts Options) ([]string, error) {
	var installed []string
	for _, role := range roles {
		switch role {
		case RoleController:
			items, err := installController(sysRoot, repoDir, binDir)
			if err != nil {
				return installed, err
			}
			installed = append(installed, items...)
		case RoleBuilder:
			items, err := installUbuntuBuilder(sysRoot, repoDir, binDir)
			if err != nil {
				return installed, err
			}
			installed = append(installed, items...)
		case RoleNativeBuilder:
			items, err := installNativeBuilder(sysRoot, repoDir, binDir)
			if err != nil {
				return installed, err
			}
			installed = append(installed, items...)
		}
	}
	return installed, nil
}

func installController(sysRoot, repoDir, binDir string) ([]string, error) {
	var items []string

	// 1) 실행 파일 (/usr/local/bin/kpctl-controller, kpctl)
	for _, name := range []string{"kpctl-controller", "kpctl"} {
		dst := sysPath(sysRoot, "usr/local/bin", name)
		if err := atomicCopyFile(filepath.Join(binDir, name), dst, 0o755); err != nil {
			return items, err
		}
		items = append(items, "/usr/local/bin/"+name)
	}

	// 2) 에이전트 설치 묶음 (/usr/local/share/kpctl/agent)
	agentDir := sysPath(sysRoot, "usr/local/share/kpctl/agent")
	if err := replaceDir(agentDir, func(tmp string) error {
		files := []struct {
			src, dst string
			mode     os.FileMode
		}{
			{filepath.Join(binDir, "kpctl-agent"), "kpctl-agent", 0o755},
			{filepath.Join(repoDir, "deploy/install-agent.sh"), "install-agent.sh", 0o755},
			{filepath.Join(repoDir, "deploy/uninstall-agent.sh"), "uninstall-agent.sh", 0o755},
			{filepath.Join(repoDir, "deploy/kpctl-prepare-kernel.py"), "kpctl-prepare-kernel.py", 0o755},
			{filepath.Join(repoDir, "deploy/mirrors.list"), "mirrors.list", 0o644},
			{filepath.Join(repoDir, "deploy/systemd/kpctl-agent.service"), "kpctl-agent.service", 0o644},
			{filepath.Join(repoDir, "configs/reboot-hook.example.sh"), "reboot-hook.example.sh", 0o644},
			{filepath.Join(repoDir, "deploy/kpatch/kpatch"), "kpatch", 0o755},
			{filepath.Join(repoDir, "deploy/kpatch/kpatch.service"), "kpatch.service", 0o644},
		}
		for _, f := range files {
			if err := atomicCopyFile(f.src, filepath.Join(tmp, f.dst), f.mode); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return items, fmt.Errorf("에이전트 묶음 갱신 실패: %w", err)
	}
	items = append(items, "/usr/local/share/kpctl/agent")

	// 3) 빌더 설치 묶음 + 자동 업데이트용 kpctl-builder (/usr/local/share/kpctl/builder)
	builderDir := sysPath(sysRoot, "usr/local/share/kpctl/builder")
	if err := replaceDir(builderDir, func(tmp string) error {
		// 최상위 kpctl-builder (빌드 서버 self_update 대상)
		if err := atomicCopyFile(filepath.Join(binDir, "kpctl-builder"), filepath.Join(tmp, "kpctl-builder"), 0o755); err != nil {
			return err
		}
		// ubuntu/
		ubDir := filepath.Join(tmp, "ubuntu")
		ubFiles := []struct {
			src, dst string
			mode     os.FileMode
		}{
			{filepath.Join(binDir, "kpctl-builder"), "kpctl-builder", 0o755},
			{filepath.Join(binDir, "kpctl"), "kpctl", 0o755},
			{filepath.Join(repoDir, "deploy/setup-builder.sh"), "setup-builder.sh", 0o755},
			{filepath.Join(repoDir, "deploy/kpctl-kernel-debug.sh"), "kpctl-kernel-debug.sh", 0o755},
			{filepath.Join(repoDir, "deploy/systemd/kpctl-builder.service"), "kpctl-builder.service", 0o644},
			{filepath.Join(repoDir, "configs/builder.example.json"), "builder.example.json", 0o644},
			{filepath.Join(repoDir, "deploy/kpctl-kernel-inputs.py"), "kpctl-kernel-inputs.py", 0o755},
			{filepath.Join(repoDir, "deploy/kpctl-kpatch-fixes.sh"), "kpctl-kpatch-fixes.sh", 0o755},
			{filepath.Join(repoDir, "deploy/kpctl-kpatch-cold-test.py"), "kpctl-kpatch-cold-test.py", 0o755},
			{filepath.Join(repoDir, "deploy/setup-build-environment.sh"), "setup-build-environment.sh", 0o755},
			{filepath.Join(repoDir, "deploy/kpctl-build-environment.py"), "kpctl-build-environment.py", 0o755},
		}
		for _, f := range ubFiles {
			if err := atomicCopyFile(f.src, filepath.Join(ubDir, f.dst), f.mode); err != nil {
				return err
			}
		}
		if err := copyDirTree(filepath.Join(repoDir, "deploy/kpatch-fixes"), filepath.Join(ubDir, "kpatch-fixes")); err != nil {
			return err
		}
		if err := copyDirTree(filepath.Join(repoDir, "deploy/build-environment"), filepath.Join(ubDir, "build-environment")); err != nil {
			return err
		}
		if err := atomicWriteFile(filepath.Join(ubDir, "builder-flavor"), []byte("ubuntu\n"), 0o644); err != nil {
			return err
		}

		// debian/, rocky/
		for _, flavor := range []string{"debian", "rocky"} {
			ndir := filepath.Join(tmp, flavor)
			nfiles := []struct {
				src, dst string
				mode     os.FileMode
			}{
				{filepath.Join(binDir, "kpctl-builder"), "kpctl-builder", 0o755},
				{filepath.Join(binDir, "kpctl"), "kpctl", 0o755},
				{filepath.Join(repoDir, "deploy/setup-native-builder.sh"), "setup-native-builder.sh", 0o755},
				{filepath.Join(repoDir, "deploy/kpctl-native-builder.py"), "kpctl-native-builder.py", 0o755},
				{filepath.Join(repoDir, "deploy/native_inputs.py"), "native_inputs.py", 0o755},
				{filepath.Join(repoDir, "deploy/kpctl-native-work.sh"), "kpctl-native-work.sh", 0o755},
				{filepath.Join(repoDir, "deploy/systemd/kpctl-native-builder.service"), "kpctl-native-builder.service", 0o644},
				{filepath.Join(repoDir, "deploy/systemd/kpctl-native-builder.timer"), "kpctl-native-builder.timer", 0o644},
				{filepath.Join(repoDir, "deploy/kpctl-kpatch-fixes.sh"), "kpctl-kpatch-fixes.sh", 0o755},
				{filepath.Join(repoDir, "deploy/kpctl-kpatch-cold-test.py"), "kpctl-kpatch-cold-test.py", 0o755},
			}
			for _, f := range nfiles {
				if err := atomicCopyFile(f.src, filepath.Join(ndir, f.dst), f.mode); err != nil {
					return err
				}
			}
			if err := copyDirTree(filepath.Join(repoDir, "deploy/kpatch-fixes"), filepath.Join(ndir, "kpatch-fixes")); err != nil {
				return err
			}
			if err := atomicWriteFile(filepath.Join(ndir, "builder-flavor"), []byte(flavor+"\n"), 0o644); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return items, fmt.Errorf("빌더 묶음 갱신 실패: %w", err)
	}
	items = append(items, "/usr/local/share/kpctl/builder")

	// 4) CVE 인벤토리 도우미
	cveSrc := filepath.Join(repoDir, "deploy/kpctl-cve-inventory.py")
	if pathExists(cveSrc) {
		if err := atomicCopyFile(cveSrc, sysPath(sysRoot, "usr/local/libexec/kpctl-cve-inventory"), 0o755); err != nil {
			return items, err
		}
		items = append(items, "/usr/local/libexec/kpctl-cve-inventory")
	}

	// 5) systemd 유닛
	units := []string{
		"kpctl-controller.service",
		"kpctl-cve-inventory.service",
		"kpctl-cve-inventory.timer",
		"kpctl-autoenroll.service",
		"kpctl-autoenroll.timer",
	}
	if pathExists(sysPath(sysRoot, "etc/systemd/system/kpctl-dnsmasq.service")) ||
		pathExists(sysPath(sysRoot, "etc/kpctl/dnsmasq.conf")) {
		units = append(units, "kpctl-dnsmasq.service")
	}
	for _, u := range units {
		src := filepath.Join(repoDir, "deploy/systemd", u)
		if !pathExists(src) {
			continue
		}
		if err := atomicCopyFile(src, sysPath(sysRoot, "etc/systemd/system", u), 0o644); err != nil {
			return items, err
		}
		items = append(items, "/etc/systemd/system/"+u)
	}
	return items, nil
}

func installUbuntuBuilder(sysRoot, repoDir, binDir string) ([]string, error) {
	var items []string

	unitDst := sysPath(sysRoot, "etc/systemd/system/kpctl-builder.service")
	buildUser, buildGroup := readUnitUserGroup(unitDst)

	// 1) 바이너리
	for _, name := range []string{"kpctl-builder", "kpctl"} {
		src := filepath.Join(binDir, name)
		if !pathExists(src) {
			continue
		}
		dst := sysPath(sysRoot, "usr/local/bin", name)
		if err := atomicCopyFile(src, dst, 0o755); err != nil {
			return items, err
		}
		items = append(items, "/usr/local/bin/"+name)
	}

	// 2) 디버그 심볼·커널 입력 도우미
	if err := atomicCopyFile(filepath.Join(repoDir, "deploy/kpctl-kernel-debug.sh"), sysPath(sysRoot, "usr/local/sbin/kpctl-kernel-debug"), 0o755); err != nil {
		return items, err
	}
	items = append(items, "/usr/local/sbin/kpctl-kernel-debug")
	if err := atomicCopyFile(filepath.Join(repoDir, "deploy/kpctl-kernel-inputs.py"), sysPath(sysRoot, "usr/local/libexec/kpctl-kernel-inputs"), 0o755); err != nil {
		return items, err
	}
	items = append(items, "/usr/local/libexec/kpctl-kernel-inputs")

	// 3) sandbox 빌드 환경 도우미 (설치되어 있거나 기본 sandbox 빌더인 경우)
	if pathExists(sysPath(sysRoot, "usr/local/libexec/kpctl-build-environment")) ||
		pathExists(sysPath(sysRoot, "usr/local/share/kpctl/build-environment")) {
		if err := atomicCopyFile(filepath.Join(repoDir, "deploy/kpctl-build-environment.py"), sysPath(sysRoot, "usr/local/libexec/kpctl-build-environment"), 0o755); err != nil {
			return items, err
		}
		items = append(items, "/usr/local/libexec/kpctl-build-environment")

		envDir := sysPath(sysRoot, "usr/local/share/kpctl/build-environment")
		if err := replaceDir(envDir, func(tmp string) error {
			for _, asset := range []string{"Containerfile", "install-packages.sh", "configure-apt.sh", "toolchain-pins.sh"} {
				if err := atomicCopyFile(filepath.Join(repoDir, "deploy/build-environment", asset), filepath.Join(tmp, asset), 0o644); err != nil {
					return err
				}
			}
			for _, helper := range []string{"kpctl-kpatch-fixes.sh", "kpctl-kpatch-cold-test.py"} {
				if err := atomicCopyFile(filepath.Join(repoDir, "deploy", helper), filepath.Join(tmp, helper), 0o644); err != nil {
					return err
				}
			}
			return copyDirTree(filepath.Join(repoDir, "deploy/kpatch-fixes"), filepath.Join(tmp, "kpatch-fixes"))
		}); err != nil {
			return items, fmt.Errorf("빌드 환경 레시피 갱신 실패: %w", err)
		}
		items = append(items, "/usr/local/share/kpctl/build-environment")
	}

	// 4) systemd 서비스 (기존 User=/Group= 보존)
	unitTmpl, err := os.ReadFile(filepath.Join(repoDir, "deploy/systemd/kpctl-builder.service"))
	if err != nil {
		return items, err
	}
	rendered, err := renderUbuntuBuilderUnit(unitTmpl, buildUser, buildGroup)
	if err != nil {
		return items, err
	}
	if err := atomicWriteFile(unitDst, rendered, 0o644); err != nil {
		return items, err
	}
	items = append(items, "/etc/systemd/system/kpctl-builder.service")

	return items, nil
}

func installNativeBuilder(sysRoot, repoDir, binDir string) ([]string, error) {
	var items []string

	unitDst := sysPath(sysRoot, "etc/systemd/system/kpctl-native-builder.service")
	buildUser, buildGroup := readUnitUserGroup(unitDst)

	// 1) 바이너리
	for _, name := range []string{"kpctl-builder", "kpctl"} {
		src := filepath.Join(binDir, name)
		if !pathExists(src) {
			continue
		}
		dst := sysPath(sysRoot, "usr/local/bin", name)
		if err := atomicCopyFile(src, dst, 0o755); err != nil {
			return items, err
		}
		items = append(items, "/usr/local/bin/"+name)
	}

	// 2) 네이티브 빌더 스크립트 (/opt/kpctl/native-builder)
	optDir := sysPath(sysRoot, "opt/kpctl/native-builder")
	for _, name := range []string{"kpctl-native-builder.py", "native_inputs.py", "kpctl-native-work.sh"} {
		if err := atomicCopyFile(filepath.Join(repoDir, "deploy", name), filepath.Join(optDir, name), 0o755); err != nil {
			return items, err
		}
		items = append(items, "/opt/kpctl/native-builder/"+name)
	}

	// 3) systemd 서비스·타이머 (기존 User=/Group= 보존)
	svcTmpl, err := os.ReadFile(filepath.Join(repoDir, "deploy/systemd/kpctl-native-builder.service"))
	if err != nil {
		return items, err
	}
	rendered, err := renderNativeBuilderUnit(svcTmpl, buildUser, buildGroup)
	if err != nil {
		return items, err
	}
	if err := atomicWriteFile(unitDst, rendered, 0o644); err != nil {
		return items, err
	}
	items = append(items, "/etc/systemd/system/kpctl-native-builder.service")

	timerDst := sysPath(sysRoot, "etc/systemd/system/kpctl-native-builder.timer")
	if err := atomicCopyFile(filepath.Join(repoDir, "deploy/systemd/kpctl-native-builder.timer"), timerDst, 0o644); err != nil {
		return items, err
	}
	items = append(items, "/etc/systemd/system/kpctl-native-builder.timer")

	return items, nil
}

func readUnitUserGroup(unitPath string) (string, string) {
	u, g := "kpbuild", "kpbuild"
	data, err := os.ReadFile(unitPath)
	if err != nil {
		return u, g
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "User=") {
			if v := strings.TrimSpace(strings.TrimPrefix(line, "User=")); v != "" {
				u = v
			}
		}
		if strings.HasPrefix(line, "Group=") {
			if v := strings.TrimSpace(strings.TrimPrefix(line, "Group=")); v != "" {
				g = v
			}
		}
	}
	return u, g
}

func renderUbuntuBuilderUnit(tmpl []byte, user, group string) ([]byte, error) {
	lines := strings.Split(string(tmpl), "\n")
	userOK, ownerOK := false, false
	for i, line := range lines {
		switch {
		case line == "User=kpbuild":
			line = "User=" + user
			userOK = true
		case line == "Group=kpbuild":
			line = "Group=" + group
		default:
			if strings.Contains(line, "= kpbuild:1 ]") {
				line = strings.ReplaceAll(line, "= kpbuild:1 ]", "= "+user+":1 ]")
				ownerOK = true
			}
			line = strings.ReplaceAll(line, "~kpbuild", "~"+user)
			line = strings.ReplaceAll(line, "# kpbuild 소유", "# "+user+" 소유")
		}
		lines[i] = line
	}
	if !userOK || !ownerOK {
		return nil, fmt.Errorf("kpctl-builder.service 계정 치환 실패 (User=%v, ownerCheck=%v)", userOK, ownerOK)
	}
	return []byte(strings.Join(lines, "\n")), nil
}

func renderNativeBuilderUnit(tmpl []byte, user, group string) ([]byte, error) {
	lines := strings.Split(string(tmpl), "\n")
	userOK := false
	for i, line := range lines {
		switch {
		case strings.HasPrefix(line, "User="):
			lines[i] = "User=" + user
			userOK = true
		case strings.HasPrefix(line, "Group="):
			lines[i] = "Group=" + group
		}
	}
	if !userOK {
		return nil, fmt.Errorf("kpctl-native-builder.service 계정 치환 실패")
	}
	return []byte(strings.Join(lines, "\n")), nil
}

func restartServices(sysRoot string, roles []Role, opts Options) error {
	runCtl := opts.SystemctlFunc
	if runCtl == nil {
		runCtl = func(args ...string) (string, error) {
			cmd := exec.Command("systemctl", args...)
			var buf bytes.Buffer
			cmd.Stdout = &buf
			cmd.Stderr = &buf
			err := cmd.Run()
			return strings.TrimSpace(buf.String()), err
		}
	}

	if out, err := runCtl("daemon-reload"); err != nil {
		return fmt.Errorf("systemctl daemon-reload 실패: %w (%s)", err, out)
	}

	for _, role := range roles {
		switch role {
		case RoleController:
			if out, err := runCtl("restart", "kpctl-controller"); err != nil {
				return fmt.Errorf("kpctl-controller 재시작 실패: %w (%s)", err, out)
			}
			fmt.Fprintln(opts.Stdout, "  kpctl-controller 재시작 완료")
		case RoleBuilder:
			if out, err := runCtl("restart", "kpctl-builder"); err != nil {
				return fmt.Errorf("kpctl-builder 재시작 실패: %w (%s)", err, out)
			}
			fmt.Fprintln(opts.Stdout, "  kpctl-builder 재시작 완료")
		case RoleNativeBuilder:
			// 진행 중인 6시간 oneshot 빌드를 강제 중단하지 않고 타이머를 갱신합니다.
			if _, err := runCtl("is-active", "--quiet", "kpctl-native-builder.timer"); err == nil {
				if out, err := runCtl("restart", "kpctl-native-builder.timer"); err != nil {
					return fmt.Errorf("kpctl-native-builder.timer 재시작 실패: %w (%s)", err, out)
				}
				fmt.Fprintln(opts.Stdout, "  kpctl-native-builder.timer 재시작 완료")
			} else {
				fmt.Fprintln(opts.Stdout, "  kpctl-native-builder.timer 가 비활성 상태라 재시작을 건너뛰었습니다 (파일은 갱신됨)")
			}
		}
	}
	return nil
}

func atomicCopyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".kpctl-upd-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := io.Copy(tmp, in); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, dst); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func atomicWriteFile(dst string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".kpctl-upd-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, dst); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func copyDirTree(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		return atomicCopyFile(path, target, info.Mode().Perm())
	})
}

func replaceDir(dst string, populate func(tmpDir string) error) error {
	parent := filepath.Dir(dst)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return err
	}
	tmp, err := os.MkdirTemp(parent, ".kpctl-dir-*")
	if err != nil {
		return err
	}
	cleanupTmp := true
	defer func() {
		if cleanupTmp {
			_ = os.RemoveAll(tmp)
		}
	}()
	if err := os.Chmod(tmp, 0o755); err != nil {
		return err
	}
	if err := populate(tmp); err != nil {
		return err
	}
	backup := ""
	if pathExists(dst) {
		backup = fmt.Sprintf("%s.bak-%d", dst, os.Getpid())
		_ = os.RemoveAll(backup)
		if err := os.Rename(dst, backup); err != nil {
			return err
		}
	}
	if err := os.Rename(tmp, dst); err != nil {
		if backup != "" {
			_ = os.Rename(backup, dst)
		}
		return err
	}
	cleanupTmp = false
	if backup != "" {
		_ = os.RemoveAll(backup)
	}
	return nil
}
