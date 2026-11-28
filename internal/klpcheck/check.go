// Package klpcheck checks livepatch ELF relocations without invoking build or load tools.
package klpcheck

import (
	"debug/elf"
	"encoding/binary"
	"fmt"
	"regexp"
	"strings"
)

// include/uapi/linux/elf.h; the module loader leaves these relocations/symbols
// for livepatch to resolve, rather than resolving them during module loading.
const (
	shfRelaLivepatch elf.SectionFlag  = 0x00100000
	shnLivepatch     elf.SectionIndex = 0xff20
)

var moduleNameRE = regexp.MustCompile(`^[A-Za-z0-9_]{1,55}$`)

// CheckFile opens and checks a module. A signed module's appended signature does
// not change its ELF sections, so this also accepts signed build artifacts.
func CheckFile(path string) error {
	f, err := elf.Open(path)
	if err != nil {
		return fmt.Errorf("커널 모듈 ELF 읽기 실패: %w", err)
	}
	defer f.Close()
	return Verify(f)
}

// CheckTarget also binds the module's own name and vermagic to an exact target.
func CheckTarget(path, kernel, name string) error {
	f, err := elf.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := Verify(f); err != nil {
		return err
	}
	section := f.Section(".modinfo")
	if section == nil {
		return fmt.Errorf("missing .modinfo")
	}
	data, err := section.Data()
	if err != nil {
		return err
	}
	want := map[string]string{"name": name, "livepatch": "Y", "vermagic": kernel}
	seen := map[string]bool{}
	for _, entry := range strings.Split(string(data), "\x00") {
		k, v, ok := strings.Cut(entry, "=")
		expected, required := want[k]
		if !ok || !required {
			continue
		}
		if k == "vermagic" {
			v, _, _ = strings.Cut(v, " ")
		}
		if seen[k] || v != expected {
			return fmt.Errorf("module %s mismatch: got %q, expected %q", k, v, expected)
		}
		seen[k] = true
	}
	if len(seen) != len(want) {
		return fmt.Errorf("incomplete module identity")
	}
	return nil
}

// Verify checks the ELF64 x86-64 format supported here, livepatch relocation
// metadata, and relocations that could corrupt host-wide ftrace state.
// https://docs.kernel.org/livepatch/module-elf-format.html
func Verify(f *elf.File) error {
	if f.Class != elf.ELFCLASS64 || f.Data != elf.ELFDATA2LSB || f.Machine != elf.EM_X86_64 || f.Type != elf.ET_REL {
		return fmt.Errorf("지원하지 않는 모듈 ELF 형식: %s %s %s %s", f.Class, f.Data, f.Machine, f.Type)
	}
	var symtab *elf.Section
	names := map[string]bool{}
	for _, s := range f.Sections {
		if s.Name != "" && names[s.Name] {
			return fmt.Errorf("중복 ELF 섹션: %s", s.Name)
		}
		names[s.Name] = true
		if s.Type == elf.SHT_SYMTAB {
			if symtab != nil || s.Entsize != 24 || s.Size%24 != 0 || s.Size < 24 || int(s.Link) >= len(f.Sections) || f.Sections[s.Link].Type != elf.SHT_STRTAB {
				return fmt.Errorf("잘못된 ELF 심볼 테이블: %s", s.Name)
			}
			symtab = s
		}
	}
	if symtab == nil {
		return fmt.Errorf("ELF 심볼 테이블이 없습니다")
	}
	syms, err := f.Symbols() // debug/elf omits symbol zero.
	if err != nil {
		return fmt.Errorf("ELF 심볼 해석 실패: %w", err)
	}
	for _, sym := range syms {
		// The kernel documentation describes external symbols, with zero-size
		// examples, but does NOT explicitly require st_size == 0. Keep this
		// conservative guard: 7.0.0-28 v7-v9 converted defined functions into
		// SHN_LIVEPATCH symbols while retaining their size, corrupting ftrace.
		// Nonzero size alone is not proof of a function body or a universal ABI rule.
		if sym.Section == shnLivepatch && sym.Size != 0 {
			return fmt.Errorf("Size≠0 livepatch 심볼 (klp-build 도구 결함 의심): %s", sym.Name)
		}
	}

	relocs := map[*elf.Section][]elf.Rela64{}
	objects := map[string]bool{}
	for _, s := range f.Sections {
		rest, klp := strings.CutPrefix(s.Name, ".klp.rela.")
		if s.Name == ".klp.rela" || s.Flags&shfRelaLivepatch != 0 && !klp {
			return fmt.Errorf("잘못된 livepatch 재배치 섹션 이름: %s", s.Name)
		}
		if klp {
			obj, section, ok := strings.Cut(rest, ".")
			if !ok || section == "" || obj != "vmlinux" && !moduleNameRE.MatchString(obj) {
				return fmt.Errorf("잘못된 klp 재배치 섹션 대상 이름: %s", s.Name)
			}
			if s.Type != elf.SHT_RELA || s.Flags&(elf.SHF_ALLOC|shfRelaLivepatch) != elf.SHF_ALLOC|shfRelaLivepatch {
				return fmt.Errorf("klp 재배치 섹션은 SHT_RELA, SHF_ALLOC, SHF_RELA_LIVEPATCH 가 필요합니다: %s", s.Name)
			}
			objects[obj] = true
		}
		if s.Type == elf.SHT_REL {
			return fmt.Errorf("x86-64 모듈의 예상 밖 SHT_REL 섹션: %s", s.Name)
		}
		if s.Type != elf.SHT_RELA {
			continue
		}
		if s.Entsize != 24 || s.Size%24 != 0 || int(s.Link) >= len(f.Sections) || f.Sections[s.Link] != symtab || s.Info == 0 || int(s.Info) >= len(f.Sections) {
			return fmt.Errorf("잘못된 ELF 재배치 섹션: %s", s.Name)
		}
		data, err := s.Data()
		if err != nil {
			return fmt.Errorf("ELF 재배치 읽기 실패 (%s): %w", s.Name, err)
		}
		target := f.Sections[s.Info]
		if klp {
			_, section, _ := strings.Cut(rest, ".")
			if section != target.Name && "."+section != target.Name {
				return fmt.Errorf("klp 재배치 섹션 이름과 대상 섹션이 다릅니다: %s → %s", s.Name, target.Name)
			}
		}
		// Match the relocation target, not just the relocation section name.
		ftrace := target.Name == "__mcount_loc" || target.Name == "__patchable_function_entries"
		for off := 0; off < len(data); off += 24 {
			e := elf.Rela64{Off: binary.LittleEndian.Uint64(data[off:]), Info: binary.LittleEndian.Uint64(data[off+8:]), Addend: int64(binary.LittleEndian.Uint64(data[off+16:]))}
			index := e.Info >> 32
			if index > uint64(len(syms)) || e.Off >= target.Size {
				return fmt.Errorf("ELF 재배치의 심볼 인덱스 또는 위치가 범위 밖입니다: %s", s.Name)
			}
			live := index != 0 && syms[index-1].Section == shnLivepatch
			if ftrace && live {
				return fmt.Errorf("ftrace 위치표가 livepatch 심볼을 참조합니다: %s → %s", target.Name, syms[index-1].Name)
			}
			if klp && !live {
				return fmt.Errorf("klp 재배치가 SHN_LIVEPATCH 심볼을 참조하지 않습니다: %s", s.Name)
			}
			relocs[s] = append(relocs[s], e)
		}
	}
	listed, err := objectNames(f, syms, relocs)
	if err != nil {
		return err
	}
	for obj := range objects {
		if obj != "vmlinux" && !listed[obj] {
			return fmt.Errorf("klp 재배치 대상 %s 가 패치 객체 목록에 없습니다", obj)
		}
	}
	return nil
}
