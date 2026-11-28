// Package klptest generates small ELF fixtures for klpcheck and agent tests.
// These synthetic files exercise metadata only and must never be kernel-loaded.
package klptest

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
)

type Options struct {
	Modinfo       string
	Object        string // relocation object; default rxrpc
	ListedObject  string // declared patch object; default rxrpc
	Kpatch        bool
	Ftrace        string // __mcount_loc or __patchable_function_entries
	LivepatchSize uint64
}

// Module produces an ELF64 x86-64 ET_REL with section/string/symbol tables,
// a patch object list, and one livepatch relocation. No compiler is needed.
func Module(opts Options) []byte {
	if opts.Object == "" {
		opts.Object = "rxrpc"
	}
	if opts.ListedObject == "" {
		opts.ListedObject = "rxrpc"
	}
	type section struct {
		name string
		hdr  elf.Section64
		data []byte
	}
	encode := func(v any) []byte {
		var b bytes.Buffer
		if err := binary.Write(&b, binary.LittleEndian, v); err != nil {
			panic(err)
		}
		return b.Bytes()
	}
	sections := []section{{}}
	add := func(name string, typ elf.SectionType, flags elf.SectionFlag, data []byte) uint16 {
		sections = append(sections, section{name, elf.Section64{Type: uint32(typ), Flags: uint64(flags), Addralign: 8}, data})
		return uint16(len(sections) - 1)
	}
	if opts.Modinfo != "" {
		add(".modinfo", elf.SHT_PROGBITS, elf.SHF_ALLOC, []byte(opts.Modinfo))
	}
	strtab := add(".strtab", elf.SHT_STRTAB, 0, []byte("\x00.klp.sym.rxrpc.original,0\x00"))
	symtab := add(".symtab", elf.SHT_SYMTAB, 0, nil)
	text := add(".text", elf.SHT_PROGBITS, elf.SHF_ALLOC|elf.SHF_EXECINSTR, make([]byte, 16))
	stringsName, objectsName := ".rodata", ".init.klp_objects"
	objectsSize := 32
	if opts.Kpatch {
		stringsName, objectsName, objectsSize = ".kpatch.strings", ".kpatch.funcs", 56
	}
	strs := add(stringsName, elf.SHT_PROGBITS, elf.SHF_ALLOC, []byte(opts.ListedObject+"\x00"))
	funcs := add(".init.klp_funcs", elf.SHT_PROGBITS, elf.SHF_ALLOC, make([]byte, 24))
	objects := add(objectsName, elf.SHT_PROGBITS, elf.SHF_ALLOC, make([]byte, objectsSize))
	rela := func(name string, target uint16, flags elf.SectionFlag, entries ...elf.Rela64) {
		i := add(name, elf.SHT_RELA, flags|elf.SHF_INFO_LINK, encode(entries))
		sections[i].hdr.Link, sections[i].hdr.Info, sections[i].hdr.Entsize = uint32(symtab), uint32(target), 24
	}
	if opts.Kpatch {
		rela(".rela"+objectsName, objects, 0, elf.Rela64{Off: 48, Info: uint64(2)<<32 | uint64(elf.R_X86_64_64)})
	} else {
		entries := []elf.Rela64{{Off: 8, Info: uint64(3)<<32 | uint64(elf.R_X86_64_64)}}
		if opts.ListedObject != "vmlinux" {
			entries = append(entries, elf.Rela64{Info: uint64(2)<<32 | uint64(elf.R_X86_64_64)})
		}
		rela(".rela"+objectsName, objects, 0, entries...)
	}
	rela(".klp.rela."+opts.Object+"..text", text, elf.SHF_ALLOC|0x00100000, elf.Rela64{Info: uint64(4)<<32 | uint64(elf.R_X86_64_64)})
	// Plain .rela.text references to livepatch symbols are valid native output.
	rela(".rela.text", text, 0, elf.Rela64{Info: uint64(4)<<32 | uint64(elf.R_X86_64_64)})
	if opts.Ftrace != "" {
		target := add(opts.Ftrace, elf.SHT_PROGBITS, elf.SHF_ALLOC, make([]byte, 8))
		rela(".rela"+opts.Ftrace, target, 0, elf.Rela64{Info: uint64(4)<<32 | uint64(elf.R_X86_64_64)})
	}
	sections[symtab].data = encode([]elf.Sym64{
		{},
		{Info: byte(elf.STT_SECTION), Shndx: text},
		{Info: byte(elf.STT_SECTION), Shndx: strs},
		{Info: byte(elf.STT_SECTION), Shndx: funcs},
		{Name: 1, Info: byte(elf.STB_GLOBAL)<<4 | byte(elf.STT_NOTYPE), Shndx: 0xff20, Size: opts.LivepatchSize},
	})
	sections[symtab].hdr.Link, sections[symtab].hdr.Info, sections[symtab].hdr.Entsize = uint32(strtab), 4, 24
	shstrtab := add(".shstrtab", elf.SHT_STRTAB, 0, nil)
	names := []byte{0}
	for i := 1; i < len(sections); i++ {
		sections[i].hdr.Name = uint32(len(names))
		names = append(names, sections[i].name...)
		names = append(names, 0)
	}
	sections[shstrtab].data = names
	var out bytes.Buffer
	out.Write(make([]byte, 64))
	for i := 1; i < len(sections); i++ {
		for out.Len()%8 != 0 {
			out.WriteByte(0)
		}
		sections[i].hdr.Off, sections[i].hdr.Size = uint64(out.Len()), uint64(len(sections[i].data))
		out.Write(sections[i].data)
	}
	for out.Len()%8 != 0 {
		out.WriteByte(0)
	}
	head := elf.Header64{Type: uint16(elf.ET_REL), Machine: uint16(elf.EM_X86_64), Version: 1, Shoff: uint64(out.Len()), Ehsize: 64, Shentsize: 64, Shnum: uint16(len(sections)), Shstrndx: shstrtab}
	copy(head.Ident[:], []byte{'\x7f', 'E', 'L', 'F', byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), 1})
	for _, s := range sections {
		out.Write(encode(s.hdr))
	}
	data := out.Bytes()
	copy(data[:64], encode(head))
	return data
}
