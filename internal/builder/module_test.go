// 이 파일: builder 패키지의 TestUbuntuRelativeModuleVersionsAndCRCs, TestClassicModuleVersions, TestELFModuleVersionFormats 회귀 시험.
package builder

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func relativeVersions(records ...struct {
	name string
	crc  uint32
}) []byte {
	var out []byte
	for _, r := range records {
		next := (8 + len(r.name) + 1 + 3) &^ 3
		record := make([]byte, next)
		binary.LittleEndian.PutUint32(record, uint32(next))
		binary.LittleEndian.PutUint32(record[4:], r.crc)
		copy(record[8:], r.name)
		out = append(out, record...)
	}
	// Ubuntu emits an eight-byte terminator plus the C string's final NUL.
	return append(out, make([]byte, 9)...)
}

func TestUbuntuRelativeModuleVersionsAndCRCs(t *testing.T) {
	data := relativeVersions(struct {
		name string
		crc  uint32
	}{"module_layout", 0xaabbccdd}, struct {
		name string
		crc  uint32
	}{"klp_enable_patch", 0x12345678})
	want := map[string]uint32{"module_layout": 0xaabbccdd, "klp_enable_patch": 0x12345678}
	got, err := relativeModuleVersions(data, binary.LittleEndian)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("Ubuntu variable-length records: %v %v", got, err)
	}
	reference := "0xaabbccdd\tmodule_layout\tvmlinux\tEXPORT_SYMBOL\n0x12345678\tklp_enable_patch\tvmlinux\tEXPORT_SYMBOL_GPL\n"
	if err := compareModuleVersions(got, reference); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{
		strings.Replace(reference, "0xaabbccdd", "0xaabbccde", 1),
		"0xaabbccdd\tmodule_layout\tvmlinux\n",
		reference + "0x1\tmodule_layout\tvmlinux\n",
	} {
		if err := compareModuleVersions(got, invalid); err == nil {
			t.Fatal("mismatched, missing or conflicting symbol CRC must fail")
		}
	}
	for _, corrupt := range [][]byte{
		data[:len(data)-9], // missing terminator
		append([]byte{1}, data[1:]...),
		append(append([]byte{}, data[:len(data)-1]...), 1),
	} {
		if _, err := relativeModuleVersions(corrupt, binary.LittleEndian); err == nil {
			t.Fatal("corrupt variable-length records must fail")
		}
	}
}

func TestClassicModuleVersions(t *testing.T) {
	for _, class := range []elf.Class{elf.ELFCLASS32, elf.ELFCLASS64} {
		for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
			data := make([]byte, 64)
			width := 4
			if class == elf.ELFCLASS64 {
				width = 8
				order.PutUint64(data, 0xf1234567)
			} else {
				order.PutUint32(data, 0xf1234567)
			}
			copy(data[width:], "module_layout")
			got, err := classicModuleVersions(data, order, class)
			if err != nil || got["module_layout"] != 0xf1234567 {
				t.Fatalf("%s %s: %v %v", class, order, got, err)
			}
		}
	}
}

func TestELFModuleVersionFormats(t *testing.T) {
	root := t.TempDir()
	base := filepath.Join(root, "base.o")
	cmd := exec.Command("cc", "-c", "-x", "c", "-", "-o", base)
	cmd.Stdin = strings.NewReader("int fixture;\n")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ELF fixture: %v %s", err, out)
	}
	classic := make([]byte, 64)
	binary.LittleEndian.PutUint64(classic, 0x1234)
	copy(classic[8:], "module_layout")
	for _, tc := range []struct {
		name     string
		sections map[string][]byte
		format   string
	}{
		{"classic", map[string][]byte{"__versions": classic}, "classic"},
		{"extended", map[string][]byte{"__version_ext_crcs": {0x34, 0x12, 0, 0}, "__version_ext_names": []byte("module_layout\x00")}, "extended"},
		{"extended-ubuntu-string-terminator", map[string][]byte{"__version_ext_crcs": {0x34, 0x12, 0, 0}, "__version_ext_names": []byte("module_layout\x00\x00")}, "extended"},
		{"extended-unterminated", map[string][]byte{"__version_ext_crcs": {0x34, 0x12, 0, 0}, "__version_ext_names": []byte("module_layout")}, ""},
		{"mixed", map[string][]byte{"__versions": classic, "__version_ext_crcs": {0x34, 0x12, 0, 0}, "__version_ext_names": []byte("module_layout\x00")}, "extended"},
		{"mixed-mismatch", map[string][]byte{"__versions": classic, "__version_ext_crcs": {0x35, 0x12, 0, 0}, "__version_ext_names": []byte("module_layout\x00")}, ""},
		{"incomplete", map[string][]byte{"__version_ext_crcs": {0x34, 0x12, 0, 0}}, ""},
		{"bad-count", map[string][]byte{"__version_ext_crcs": {0x34, 0x12, 0, 0}, "__version_ext_names": []byte("one\x00two\x00")}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(root, tc.name+".o")
			args := []string{}
			for name, data := range tc.sections {
				section := filepath.Join(root, tc.name+name)
				if err := os.WriteFile(section, data, 0o644); err != nil {
					t.Fatal(err)
				}
				args = append(args, "--add-section", name+"="+section)
			}
			if out, err := exec.Command("objcopy", append(args, base, path)...).CombinedOutput(); err != nil {
				t.Fatalf("ELF sections: %v %s", err, out)
			}
			f, err := elf.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			versions, format, err := moduleVersions(f)
			if tc.format == "" {
				if err == nil {
					t.Fatal("invalid sections must fail")
				}
			} else if err != nil || format != tc.format || versions["module_layout"] != 0x1234 {
				t.Fatalf("%v %s %v", versions, format, err)
			}
		})
	}
}

func TestVermagicFlagsMatchTargetConfig(t *testing.T) {
	config := "CONFIG_SMP=y\nCONFIG_PREEMPT_BUILD=y\nCONFIG_MODULE_UNLOAD=y\nCONFIG_MODVERSIONS=y\n"
	if err := verifyVermagicFlags(strings.Fields("SMP preempt mod_unload modversions"), config); err != nil {
		t.Fatal(err)
	}
	for _, flags := range []string{"SMP preempt modversions", "SMP mod_unload modversions", "SMP preempt_rt mod_unload modversions", "SMP preempt mod_unload modversions SMP"} {
		if err := verifyVermagicFlags(strings.Fields(flags), config); err == nil {
			t.Fatalf("target flag mismatch must fail: %s", flags)
		}
	}
	if err := verifyVermagicFlags([]string{"modversions"}, "CONFIG_LIVEPATCH=y\n"); err == nil {
		t.Fatal("modversions must not be silently added either")
	}
}

func TestVerifyModuleRequiresMatchingKernelAndLivepatchMetadata(t *testing.T) {
	root := t.TempDir()
	kernel := "6.8.0-136-generic"
	fake, err := filepath.Abs("../../test/fake/kpatch-build")
	if err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(fake, "-a", kernel, "-n", "kpctl_test", "-o", root).CombinedOutput(); err != nil {
		t.Fatalf("fixture: %v %s", err, out)
	}
	b := &Builder{cfg: &Config{BootDir: root}}
	k := KernelConfig{Kernel: kernel}
	module := buildOutput{ModuleName: "kpctl_test", ModulePath: filepath.Join(root, "kpctl_test.ko")}
	config := filepath.Join(root, "config-"+kernel)
	if _, err := b.verifyModule(k, module); err == nil {
		t.Fatal("missing authoritative target config must fail")
	}
	if err := os.WriteFile(config, []byte("CONFIG_LIVEPATCH=y\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := b.verifyModule(k, module); err != nil {
		t.Fatal(err)
	}
	if _, err := b.verifyModule(KernelConfig{Kernel: "7.0.0-28-generic"}, module); err == nil {
		t.Fatal("wrong target ABI must fail")
	}
	wrongName := module
	wrongName.ModuleName = "other"
	if _, err := b.verifyModule(k, wrongName); err == nil {
		t.Fatal("wrong module name must fail")
	}
	if err := os.WriteFile(config, []byte("CONFIG_LIVEPATCH=y\nCONFIG_MODVERSIONS=y\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := b.verifyModule(k, module); err == nil {
		t.Fatal("target modversions cannot be omitted")
	}
	data, err := os.ReadFile(module.ModulePath)
	if err != nil {
		t.Fatal(err)
	}
	data = bytes.Replace(data, []byte("livepatch=Y"), []byte("livepatch=N"), 1)
	if err := os.WriteFile(module.ModulePath, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := b.verifyModule(k, module); err == nil {
		t.Fatal("ordinary module cannot be accepted as a livepatch")
	}
	if err := os.WriteFile(module.ModulePath, []byte("not ELF"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := b.verifyModule(k, module); err == nil {
		t.Fatal("tool exit zero is insufficient without a real ELF module")
	}
}

// Opt-in read-only check against an artifact and installed target headers on a real builder.
func TestSystemBuiltModule(t *testing.T) {
	path := os.Getenv("KPCTL_TEST_MODULE")
	if path == "" {
		t.Skip("set KPCTL_TEST_MODULE, KPCTL_TEST_KERNEL and KPCTL_TEST_MODULE_NAME on the builder")
	}
	b := &Builder{cfg: &Config{BootDir: "/boot"}}
	report, err := b.verifyModule(KernelConfig{Kernel: os.Getenv("KPCTL_TEST_KERNEL")}, buildOutput{
		ModuleName: os.Getenv("KPCTL_TEST_MODULE_NAME"), ModulePath: path,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Log(strings.TrimSpace(report))
}
