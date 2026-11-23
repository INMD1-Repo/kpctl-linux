// 이 파일: klpcheck 패키지의 objectNames, pointedSection, objectString 구현·자료형.
package klpcheck

import (
	"bytes"
	"debug/elf"
	"fmt"
)

// objectNames reads the two build tools' on-disk object lists. Unknown formats
// cannot establish module membership and are never inferred from .klp.rela names.
func objectNames(f *elf.File, syms []elf.Symbol, relocs map[*elf.Section][]elf.Rela64) (map[string]bool, error) {
	names := map[string]bool{}
	if objects, rela := f.Section(".init.klp_objects"), f.Section(".rela.init.klp_objects"); objects != nil || rela != nil {
		if objects == nil || rela == nil || rela.Type != elf.SHT_RELA || f.Sections[rela.Info] != objects {
			return nil, fmt.Errorf("klp 객체 목록 재배치가 불완전합니다")
		}
		at := map[uint64]elf.Rela64{}
		for _, e := range relocs[rela] {
			if _, exists := at[e.Off]; exists {
				return nil, fmt.Errorf("klp 객체 목록의 중복 포인터")
			}
			at[e.Off] = e
		}
		data, err := objects.Data()
		if err != nil {
			return nil, err
		}
		count := 0
		for off, e := range at {
			sym, section := pointedSection(f, syms, e)
			if section == nil || section.Name != ".init.klp_funcs" {
				continue
			}
			if off < 8 || off+8 > uint64(len(data)) || elf.R_X86_64(uint32(e.Info)) != elf.R_X86_64_64 || elf.ST_TYPE(sym.Info) != elf.STT_SECTION {
				return nil, fmt.Errorf("klp 객체 함수 포인터가 잘못됐습니다")
			}
			count++
			n, ok := at[off-8]
			if !ok { // vmlinux is represented by a NULL name pointer.
				if f.ByteOrder.Uint64(data[off-8:]) != 0 {
					return nil, fmt.Errorf("klp 객체 이름이 NULL 또는 재배치 포인터가 아닙니다")
				}
				names["vmlinux"] = true
				continue
			}
			name, err := objectString(f, syms, n, ".rodata")
			if err != nil {
				return nil, err
			}
			names[name] = true
		}
		if count == 0 {
			return nil, fmt.Errorf("klp 객체 목록을 해석하지 못했습니다")
		}
	}
	if funcs, rela := f.Section(".kpatch.funcs"), f.Section(".rela.kpatch.funcs"); funcs != nil || rela != nil {
		// kpatch kmod/patch/kpatch-patch.h: struct kpatch_patch_func contains
		// seven 64-bit fields; objname is the final pointer (offset 48).
		// https://github.com/dynup/kpatch/blob/master/kmod/patch/kpatch-patch.h
		if funcs == nil || rela == nil || rela.Type != elf.SHT_RELA || f.Sections[rela.Info] != funcs || funcs.Size == 0 || funcs.Size%56 != 0 {
			return nil, fmt.Errorf("kpatch 객체 목록 형식이 잘못됐습니다")
		}
		at := map[uint64]elf.Rela64{}
		for _, e := range relocs[rela] {
			if _, exists := at[e.Off]; exists {
				return nil, fmt.Errorf("kpatch 객체 목록의 중복 포인터")
			}
			at[e.Off] = e
		}
		for off := uint64(48); off < funcs.Size; off += 56 {
			e, ok := at[off]
			if !ok {
				return nil, fmt.Errorf("kpatch 객체 이름 포인터가 없습니다")
			}
			name, err := objectString(f, syms, e, ".kpatch.strings")
			if err != nil {
				return nil, err
			}
			names[name] = true
		}
	}
	return names, nil
}

func pointedSection(f *elf.File, syms []elf.Symbol, e elf.Rela64) (elf.Symbol, *elf.Section) {
	index := e.Info >> 32
	if index == 0 || index > uint64(len(syms)) {
		return elf.Symbol{}, nil
	}
	sym := syms[index-1]
	if int(sym.Section) >= len(f.Sections) {
		return sym, nil
	}
	return sym, f.Sections[sym.Section]
}

func objectString(f *elf.File, syms []elf.Symbol, e elf.Rela64, sectionName string) (string, error) {
	sym, s := pointedSection(f, syms, e)
	if s == nil || s.Name != sectionName || elf.R_X86_64(uint32(e.Info)) != elf.R_X86_64_64 || e.Addend < 0 || sym.Value > s.Size || uint64(e.Addend) >= s.Size-sym.Value {
		return "", fmt.Errorf("패치 객체 이름 포인터가 %s 밖이거나 잘못됐습니다", sectionName)
	}
	data, err := s.Data()
	if err != nil {
		return "", err
	}
	str := data[sym.Value+uint64(e.Addend):]
	end := bytes.IndexByte(str, 0)
	if end < 0 || !moduleNameRE.Match(str[:end]) {
		return "", fmt.Errorf("잘못된 패치 객체 이름 문자열")
	}
	return string(str[:end]), nil
}
