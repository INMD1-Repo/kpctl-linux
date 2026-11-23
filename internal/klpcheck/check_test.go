// 이 파일: klpcheck_test 패키지의 TestVerify, TestMalformedELFFailsClosed, TestCheckFile 회귀 시험.
package klpcheck_test

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"kpctl/internal/klpcheck"
	"kpctl/internal/klpcheck/klptest"
)

func TestVerify(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts klptest.Options
		want string
	}{
		{"native", klptest.Options{}, ""},
		{"kpatch", klptest.Options{Kpatch: true}, ""},
		{"vmlinux", klptest.Options{Object: "vmlinux", ListedObject: "vmlinux"}, ""},
		{"path object", klptest.Options{Object: "net/rxrpc/rxrpc"}, "net/rxrpc/rxrpc"},
		{"unlisted native object", klptest.Options{ListedObject: "sunrpc"}, "패치 객체 목록"},
		{"unlisted kpatch object", klptest.Options{Kpatch: true, ListedObject: "sunrpc"}, "패치 객체 목록"},
		{"mcount", klptest.Options{Ftrace: "__mcount_loc"}, "__mcount_loc"},
		{"patchable entries", klptest.Options{Ftrace: "__patchable_function_entries"}, "__patchable_function_entries"},
		{"sized livepatch symbol", klptest.Options{LivepatchSize: 16}, "Size≠0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			check(t, klptest.Module(tc.opts), tc.want)
		})
	}
}

func check(t *testing.T, data []byte, want string) {
	t.Helper()
	f, err := elf.NewFile(bytes.NewReader(data))
	if err == nil {
		defer f.Close()
		err = klpcheck.Verify(f)
	}
	if want == "" && err != nil || want != "" && (err == nil || !strings.Contains(err.Error(), want)) {
		t.Fatalf("Verify = %v, want %q", err, want)
	}
}

func TestMalformedELFFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func([]byte)
	}{
		{"not ELF", func(b []byte) { b[0] = 0 }},
		{"wrong class", func(b []byte) { b[4] = byte(elf.ELFCLASS32) }},
		{"wrong byte order", func(b []byte) { b[5] = byte(elf.ELFDATA2MSB) }},
		{"executable", func(b []byte) { binary.LittleEndian.PutUint16(b[16:], uint16(elf.ET_EXEC)) }},
		{"wrong machine", func(b []byte) { binary.LittleEndian.PutUint16(b[18:], uint16(elf.EM_AARCH64)) }},
		{"missing alloc", func(b []byte) { sectionHeader(t, b, ".klp.rela.rxrpc..text", 8, 0x00100000|uint64(elf.SHF_INFO_LINK)) }},
		{"missing livepatch flag", func(b []byte) {
			sectionHeader(t, b, ".klp.rela.rxrpc..text", 8, uint64(elf.SHF_ALLOC|elf.SHF_INFO_LINK))
		}},
		{"misnamed flagged section", func(b []byte) { sectionHeader(t, b, ".rela.text", 8, 0x00100000) }},
		{"truncated rela", func(b []byte) { sectionHeader(t, b, ".rela.text", 32, 23) }},
		{"invalid entsize", func(b []byte) { sectionHeader(t, b, ".rela.text", 56, 16) }},
		{"invalid symbol table", func(b []byte) { sectionHeader(t, b, ".symtab", 56, 16) }},
		{"invalid relocation link", func(b []byte) { sectionHeader(t, b, ".rela.text", 40, 999) }},
		{"invalid relocation target", func(b []byte) { sectionHeader(t, b, ".rela.text", 40, 999<<32|2) }},
		{"invalid symbol index", func(b []byte) { editReloc(t, b, ".rela.text", 8, 99<<32|1) }},
		{"invalid relocation offset", func(b []byte) { editReloc(t, b, ".rela.text", 0, 16) }},
		{"klp non-livepatch reference", func(b []byte) { editReloc(t, b, ".klp.rela.rxrpc..text", 8, 1<<32|1) }},
		{"wrong object name pointer", func(b []byte) { editReloc(t, b, ".rela.init.klp_objects", 24+8, 1<<32|1) }},
		{"object name outside strings", func(b []byte) { editReloc(t, b, ".rela.init.klp_objects", 24+16, 999) }},
		{"object list without funcs", func(b []byte) { editReloc(t, b, ".rela.init.klp_objects", 8, 1<<32|1) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := klptest.Module(klptest.Options{})
			tc.edit(data)
			f, err := elf.NewFile(bytes.NewReader(data))
			if err == nil {
				defer f.Close()
				err = klpcheck.Verify(f)
			}
			if err == nil {
				t.Fatal("malformed ELF must be rejected")
			}
		})
	}
	check(t, []byte("broken ELF"), "EOF")
}

func sectionHeader(t *testing.T, data []byte, name string, field int, value uint64) {
	t.Helper()
	f, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for i, s := range f.Sections {
		if s.Name == name {
			off := int(binary.LittleEndian.Uint64(data[40:])) + i*64 + field
			binary.LittleEndian.PutUint64(data[off:], value)
			return
		}
	}
	t.Fatal("missing fixture section", name)
}

func editReloc(t *testing.T, data []byte, name string, offset int, value uint64) {
	t.Helper()
	f, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	s := f.Section(name)
	if s == nil {
		t.Fatal("missing fixture section", name)
	}
	binary.LittleEndian.PutUint64(data[int(s.Offset)+offset:], value)
}

func TestCheckFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "module.ko")
	if err := klpcheck.CheckFile(path); err == nil {
		t.Fatal("missing file must fail")
	}
	data := append(klptest.Module(klptest.Options{}), []byte("~Module signature appended~\n")...)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := klpcheck.CheckFile(path); err != nil {
		t.Fatal(err)
	}
}

// Optional read-only regression against real controller artifacts.
func TestBuiltModules(t *testing.T) {
	dir := os.Getenv("KPCTL_TEST_ARTIFACTS")
	if dir == "" {
		t.Skip("KPCTL_TEST_ARTIFACTS 가 없으면 실제 산출물 시험만 건너뜁니다")
	}
	for _, tc := range []struct {
		kernel   string
		versions []int
		bad      bool
	}{
		{"7.0.0-28-generic", []int{3, 5, 6}, false},
		{"7.0.0-28-generic", []int{7, 8, 9}, true},
		{"6.8.0-136-generic", []int{2, 3, 4, 5, 6}, false},
	} {
		for _, v := range tc.versions {
			name := fmt.Sprintf("kpctl_%s_v%d.ko", strings.NewReplacer(".", "_", "-", "_").Replace(tc.kernel), v)
			t.Run(name, func(t *testing.T) {
				f, err := elf.Open(filepath.Join(dir, tc.kernel, name))
				if err != nil {
					t.Fatal(err) // Missing/unreadable artifacts are not evidence of rejecting a known defect.
				}
				defer f.Close()
				err = klpcheck.Verify(f)
				if tc.bad != (err != nil) {
					t.Fatalf("error = %v, want rejection %v", err, tc.bad)
				}
				t.Logf("검사 결과: %v", err)
			})
		}
	}
}
