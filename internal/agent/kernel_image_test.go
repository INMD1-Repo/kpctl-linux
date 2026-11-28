package agent

import (
	"bytes"
	"compress/gzip"
	"debug/elf"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"kpctl/internal/model"
)

func TestInstalledImageBuildIDMismatch(t *testing.T) {
	root := t.TempDir()
	exe := filepath.Join(root, "fixture")
	cmd := exec.Command("cc", "-x", "c", "-Wl,--build-id=sha1", "-o", exe, "-")
	cmd.Stdin = bytes.NewBufferString("int main(void){return 0;}\n")
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	e, err := elf.Open(exe)
	if err != nil {
		t.Fatal(err)
	}
	data, err := e.Section(".note.gnu.build-id").Data()
	if err != nil {
		t.Fatal(err)
	}
	e.Close()
	id, err := RunningBuildID(data)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	if _, err := gz.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	image := make([]byte, 2560)
	copy(image[0x202:], "HdrS")
	binary.LittleEndian.PutUint16(image[0x206:], 0x208)
	binary.LittleEndian.PutUint32(image[0x24c:], uint32(compressed.Len()))
	k := model.DistributionKernel{Distro: "debian", ABI: "6.1.0-55-amd64", BuildID: id}
	if err := os.WriteFile(filepath.Join(root, "vmlinuz-"+k.ABI), append(image, compressed.Bytes()...), 0600); err != nil {
		t.Fatal(err)
	}
	var check KernelImageCheck
	if err := check.Verify(&k, root, ""); err != nil {
		t.Fatal(err)
	}
	k.BuildID = "different"
	if err := check.Verify(&k, root, ""); err == nil {
		t.Fatal("cached image masked running build ID mismatch")
	}
}

func TestAuthenticatedInstalledImage(t *testing.T) {
	path := os.Getenv("KPCTL_TEST_INSTALLED_KERNEL")
	if path == "" {
		t.Skip("requires an authenticated vendor image")
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	id, err := kernelImageBuildID(f, st.Size())
	if err != nil || id != os.Getenv("KPCTL_EXPECTED_BUILD_ID") {
		t.Fatalf("build ID %s: %v", id, err)
	}
	t.Logf("verified installed ELF %s", id)
}
