// 이 파일: ELF·전체 vermagic·심볼 CRC 독립 검증.
package builder

import (
	"bufio"
	"context"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"kpctl/internal/klpcheck"
	"kpctl/internal/model"
)

// verifyModule 은 도구의 성공 여부와 별도로 실제 ELF·타깃 ABI·심볼 CRC 를 확인합니다.
// Ubuntu 의 가변 길이 __versions 는 예전 libkmod 로 읽을 수 없어 직접 해석합니다.
func (b *Builder) verifyModule(k KernelConfig, out buildOutput) (string, error) {
	return verifyWithInputs(k.Kernel, out, filepath.Join(b.cfg.BootDir, "config-"+k.Kernel), "", []string{filepath.Join("/usr/src/linux-headers-"+k.Kernel, "Module.symvers"), filepath.Join("/lib/modules", k.Kernel, "build/Module.symvers")})
}

func VerifyDistributionModule(track string, version int, path, config, symvers, reference string) (string, error) {
	k, ok := model.DistributionTrack(track)
	if !ok || version < 1 || reference == "" {
		return "", fmt.Errorf("invalid native module target")
	}
	return verifyWithInputs(k.ABI, buildOutput{ModulePath: path, ModuleName: model.NativeModuleName(track, version)}, config, reference, []string{symvers})
}

func verifyWithInputs(kernel string, out buildOutput, configPath, referencePath string, symvers []string) (string, error) {
	f, err := elf.Open(out.ModulePath)
	if err != nil {
		return "", fmt.Errorf("커널 모듈 ELF 읽기 실패: %w", err)
	}
	defer f.Close()
	if f.Type != elf.ET_REL {
		return "", fmt.Errorf("재배치 가능한 커널 모듈이 아닙니다: %s", f.Type)
	}
	machines := map[string]elf.Machine{"amd64": elf.EM_X86_64, "arm64": elf.EM_AARCH64, "ppc64le": elf.EM_PPC64, "s390x": elf.EM_S390}
	if machine, ok := machines[runtime.GOARCH]; !ok || f.Machine != machine {
		return "", fmt.Errorf("빌드 서버와 모듈의 아키텍처가 다릅니다: %s", f.Machine)
	}
	section := f.Section(".modinfo")
	if section == nil {
		return "", fmt.Errorf(".modinfo 가 없습니다")
	}
	data, err := section.Data()
	if err != nil {
		return "", err
	}
	info := map[string]string{}
	for _, entry := range strings.Split(string(data), "\x00") {
		key, value, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		if old, exists := info[key]; exists && old != value && (key == "name" || key == "vermagic" || key == "livepatch") {
			return "", fmt.Errorf("중복된 모듈 정보가 일치하지 않습니다: %s", key)
		}
		info[key] = value
	}
	magic := strings.Fields(info["vermagic"])
	if len(magic) == 0 || magic[0] != kernel || info["name"] != out.ModuleName || info["livepatch"] != "Y" {
		return "", fmt.Errorf("모듈 정보 불일치: name=%q vermagic=%q livepatch=%q (대상 %s/%s)", info["name"], info["vermagic"], info["livepatch"], out.ModuleName, kernel)
	}
	if err := klpcheck.Verify(f); err != nil {
		return "", err
	}
	config, err := os.ReadFile(configPath)
	if err != nil {
		return "", fmt.Errorf("대상 커널 설정을 읽을 수 없습니다: %w", err)
	}
	if referencePath != "" && !strings.Contains("\n"+string(config)+"\n", "\nCONFIG_LIVEPATCH=y\n") {
		return "", fmt.Errorf("정식 대상 커널의 CONFIG_LIVEPATCH=y가 필요합니다")
	}
	wantVersions := strings.Contains("\n"+string(config)+"\n", "\nCONFIG_MODVERSIONS=y\n")
	if err := verifyVermagicFlags(magic[1:], string(config)); err != nil {
		return "", err
	}
	if !wantVersions && referencePath == "" {
		return fmt.Sprintf("모듈 검증: %s %s livepatch=Y\n", out.ModuleName, info["vermagic"]), nil
	}
	var referenceMagic string
	if referencePath != "" {
		referenceMagic, err = readVermagic(kernel, referencePath)
	} else {
		referenceMagic, err = targetModuleVermagic(kernel)
	}
	if err != nil {
		return "", err
	}
	if info["vermagic"] != referenceMagic {
		return "", fmt.Errorf("대상 정식 모듈의 전체 vermagic 과 다릅니다: %q != %q", info["vermagic"], referenceMagic)
	}
	if !wantVersions {
		return fmt.Sprintf("모듈 검증: %s %s livepatch=Y\n", out.ModuleName, info["vermagic"]), nil
	}
	versions, format, err := moduleVersions(f)
	if err != nil {
		return "", err
	}
	if referencePath != "" {
		symbols, err := f.Symbols()
		if err != nil {
			return "", err
		}
		for _, symbol := range symbols {
			if symbol.Section == elf.SHN_UNDEF && elf.ST_BIND(symbol.Info) == elf.STB_GLOBAL {
				if _, ok := versions[symbol.Name]; !ok {
					return "", fmt.Errorf("모듈에서 참조하는 외부 심볼의 CRC가 없습니다: %s", symbol.Name)
				}
			}
		}
	}
	var reference []byte
	for _, path := range symvers {
		reference, err = os.ReadFile(path)
		if err == nil {
			break
		}
	}
	if err != nil {
		return "", fmt.Errorf("대상 커널의 Module.symvers 가 필요합니다: %w", err)
	}
	if err := compareModuleVersions(versions, string(reference)); err != nil {
		return "", err
	}
	return fmt.Sprintf("모듈 검증: %s %s livepatch=Y 심볼 CRC %d건 (%s)\n", out.ModuleName, info["vermagic"], len(versions), format), nil
}

func verifyVermagicFlags(flags []string, config string) error {
	enabled := func(key string) bool { return strings.Contains("\n"+config+"\n", "\n"+key+"=y\n") }
	want := map[string]bool{
		"SMP": enabled("CONFIG_SMP"), "mod_unload": enabled("CONFIG_MODULE_UNLOAD"),
		"modversions": enabled("CONFIG_MODVERSIONS"), "preempt_rt": enabled("CONFIG_PREEMPT_RT"),
		"preempt": enabled("CONFIG_PREEMPT_BUILD") && !enabled("CONFIG_PREEMPT_RT"),
	}
	seen := map[string]bool{}
	for _, flag := range flags {
		if seen[flag] {
			return fmt.Errorf("중복 vermagic 플래그: %s", flag)
		}
		seen[flag] = true
	}
	for flag, required := range want {
		if seen[flag] != required {
			return fmt.Errorf("대상 커널 설정과 vermagic 플래그가 다릅니다: %s", flag)
		}
	}
	return nil
}

// 헤더로 빌드한 결과끼리만 비교하지 않고 설치된 정식 커널 모듈을 기준으로 삼습니다.
func targetModuleVermagic(kernel string) (string, error) {
	var module string
	err := filepath.WalkDir(filepath.Join("/lib/modules", kernel, "kernel"), func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() && (strings.HasSuffix(path, ".ko") || strings.HasSuffix(path, ".ko.zst") || strings.HasSuffix(path, ".ko.xz") || strings.HasSuffix(path, ".ko.gz")) {
			module = path
			return fs.SkipAll
		}
		return nil
	})
	if err != nil || module == "" {
		return "", fmt.Errorf("대상 정식 커널 모듈이 필요합니다: %s (%v)", kernel, err)
	}
	return readVermagic(kernel, module)
}

func readVermagic(kernel, module string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "modinfo", "-F", "vermagic", module).Output()
	if err != nil {
		return "", fmt.Errorf("정식 모듈 vermagic 확인 실패: %w", err)
	}
	// modinfo 가 추가하는 개행만 제거합니다. vermagic 자체의 끝 공백은 보존합니다.
	magic := strings.TrimSuffix(string(out), "\n")
	if fields := strings.Fields(magic); len(fields) == 0 || fields[0] != kernel {
		return "", fmt.Errorf("정식 모듈의 대상 버전이 다릅니다: %q", magic)
	}
	return magic, nil
}

func moduleVersions(f *elf.File) (map[string]uint32, string, error) {
	if crcs, names := f.Section("__version_ext_crcs"), f.Section("__version_ext_names"); crcs != nil || names != nil {
		if crcs == nil || names == nil {
			return nil, "", fmt.Errorf("확장 심볼 버전 섹션이 불완전합니다")
		}
		c, err := crcs.Data()
		if err != nil {
			return nil, "", err
		}
		n, err := names.Data()
		if err != nil {
			return nil, "", err
		}
		if len(c) == 0 || len(c)%4 != 0 {
			return nil, "", fmt.Errorf("확장 심볼 버전 길이가 일치하지 않습니다")
		}
		out := map[string]uint32{}
		for i := 0; i < len(c)/4; i++ {
			end := strings.IndexByte(string(n), 0)
			if end < 0 {
				return nil, "", fmt.Errorf("확장 심볼 이름이 잘렸습니다")
			}
			if err := addModuleVersion(out, string(n[:end]), f.ByteOrder.Uint32(c[i*4:])); err != nil {
				return nil, "", err
			}
			n = n[end+1:]
		}
		for _, padding := range n {
			if padding != 0 {
				return nil, "", fmt.Errorf("확장 심볼 이름 개수가 일치하지 않습니다")
			}
		}
		if f.Section("__versions") != nil {
			basic, _, err := basicModuleVersions(f)
			if err != nil {
				return nil, "", err
			}
			for name, crc := range basic {
				if extended, ok := out[name]; !ok || extended != crc {
					return nil, "", fmt.Errorf("기본·확장 심볼 버전 불일치: %s", name)
				}
			}
		}
		return out, "extended", nil
	}
	return basicModuleVersions(f)
}

func basicModuleVersions(f *elf.File) (map[string]uint32, string, error) {
	section := f.Section("__versions")
	if section == nil {
		return nil, "", fmt.Errorf("심볼 버전 섹션이 없습니다")
	}
	data, err := section.Data()
	if err != nil {
		return nil, "", err
	}
	relative, relErr := relativeModuleVersions(data, f.ByteOrder)
	classic, classicErr := classicModuleVersions(data, f.ByteOrder, f.Class)
	if relErr == nil && classicErr == nil {
		return nil, "", fmt.Errorf("심볼 버전 형식을 명확히 판별할 수 없습니다")
	}
	if relErr == nil {
		return relative, "relative", nil
	}
	if classicErr == nil {
		return classic, "classic", nil
	}
	return nil, "", fmt.Errorf("심볼 버전 해석 실패: 가변 길이=%v 고정 길이=%v", relErr, classicErr)
}

func addModuleVersion(out map[string]uint32, name string, crc uint32) error {
	if name == "" || strings.IndexFunc(name, func(r rune) bool { return r < 33 || r > 126 }) >= 0 {
		return fmt.Errorf("심볼 이름이 잘못됐습니다: %q", name)
	}
	if _, exists := out[name]; exists {
		return fmt.Errorf("중복 심볼 버전: %s", name)
	}
	out[name] = crc
	return nil
}

func relativeModuleVersions(data []byte, order binary.ByteOrder) (map[string]uint32, error) {
	out := map[string]uint32{}
	for off := 0; off < len(data); {
		if len(data)-off < 8 {
			return nil, fmt.Errorf("잘린 버전 레코드")
		}
		next, crc := int(order.Uint32(data[off:])), order.Uint32(data[off+4:])
		if next == 0 {
			for _, v := range data[off:] {
				if v != 0 {
					return nil, fmt.Errorf("잘못된 종료 레코드")
				}
			}
			if len(out) == 0 {
				return nil, fmt.Errorf("비어 있는 버전 정보")
			}
			return out, nil
		}
		if next < 12 || next%4 != 0 || next > len(data)-off {
			return nil, fmt.Errorf("잘못된 다음 레코드 위치")
		}
		name := data[off+8 : off+next]
		end := strings.IndexByte(string(name), 0)
		if end < 0 {
			return nil, fmt.Errorf("종료되지 않은 심볼 이름")
		}
		for _, v := range name[end:] {
			if v != 0 {
				return nil, fmt.Errorf("잘못된 심볼 패딩")
			}
		}
		if err := addModuleVersion(out, string(name[:end]), crc); err != nil {
			return nil, err
		}
		off += next
	}
	return nil, fmt.Errorf("종료 레코드가 없습니다")
}

func classicModuleVersions(data []byte, order binary.ByteOrder, class elf.Class) (map[string]uint32, error) {
	if len(data) == 0 || len(data)%64 != 0 {
		return nil, fmt.Errorf("고정 레코드 길이가 아닙니다")
	}
	width := 4
	if class == elf.ELFCLASS64 {
		width = 8
	} else if class != elf.ELFCLASS32 {
		return nil, fmt.Errorf("알 수 없는 ELF 클래스")
	}
	out := map[string]uint32{}
	for off := 0; off < len(data); off += 64 {
		crc := uint64(order.Uint32(data[off:]))
		if width == 8 {
			crc = order.Uint64(data[off:])
		}
		if crc > 0xffffffff {
			return nil, fmt.Errorf("심볼 CRC 범위를 벗어났습니다")
		}
		name := data[off+width : off+64]
		end := strings.IndexByte(string(name), 0)
		if end < 0 {
			return nil, fmt.Errorf("종료되지 않은 심볼 이름")
		}
		if err := addModuleVersion(out, string(name[:end]), uint32(crc)); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func compareModuleVersions(versions map[string]uint32, reference string) error {
	refs := map[string]uint32{}
	scanner := bufio.NewScanner(strings.NewReader(reference))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		crc, err := strconv.ParseUint(fields[0], 0, 32)
		if err != nil {
			return fmt.Errorf("잘못된 대상 심볼 CRC: %w", err)
		}
		if old, exists := refs[fields[1]]; exists && old != uint32(crc) {
			return fmt.Errorf("대상 심볼 버전이 중복됩니다: %s", fields[1])
		}
		refs[fields[1]] = uint32(crc)
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	for name, crc := range versions {
		if expected, ok := refs[name]; !ok || expected != crc {
			return fmt.Errorf("대상 커널 심볼 CRC 불일치: %s (%#x)", name, crc)
		}
	}
	return nil
}
