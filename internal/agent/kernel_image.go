// Compare the running notes with the ELF in the installed AMD64 bzImage.
package agent

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"kpctl/internal/model"
)

// KernelImageCheck caches a successful extraction across reports while the same
// installed image remains on disk. The running build ID is compared every time.
type KernelImageCheck struct {
	info    os.FileInfo
	buildID string
}

func (c *KernelImageCheck) Verify(k *model.DistributionKernel, boot, modules string) error {
	path := filepath.Join(boot, "vmlinuz-"+k.ABI)
	if k.Distro == "rocky" {
		path = filepath.Join(modules, k.ABI, "vmlinuz")
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("invalid kernel image %s", path)
	}
	if c.info == nil || !os.SameFile(info, c.info) || info.Size() != c.info.Size() || !info.ModTime().Equal(c.info.ModTime()) {
		id, err := kernelImageBuildID(f, info.Size())
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		c.info, c.buildID = info, id
	}
	if k.BuildID != c.buildID {
		return fmt.Errorf("installed %s %s build ID %s differs from running %s", k.ABI, k.Version, c.buildID, k.BuildID)
	}
	return nil
}

func kernelImageBuildID(image io.ReaderAt, size int64) (string, error) {
	// Linux x86 boot protocol 2.08, offsets relative to the protected-mode payload.
	var header [0x250]byte
	if _, err := image.ReadAt(header[:], 0); err != nil {
		return "", err
	}
	if string(header[0x202:0x206]) != "HdrS" || binary.LittleEndian.Uint16(header[0x206:]) < 0x208 {
		return "", fmt.Errorf("unsupported x86 boot header")
	}
	setup := int64(header[0x1f1])
	if setup == 0 {
		setup = 4
	}
	offset := (setup+1)*512 + int64(binary.LittleEndian.Uint32(header[0x248:]))
	length := int64(binary.LittleEndian.Uint32(header[0x24c:]))
	if length < 10 || offset+length > size {
		return "", fmt.Errorf("invalid compressed kernel extent")
	}
	var magic [6]byte
	if _, err := image.ReadAt(magic[:], offset); err != nil {
		return "", err
	}
	var trailer [4]byte
	if _, err := image.ReadAt(trailer[:], offset+length-4); err != nil {
		return "", err
	}
	expected := int64(binary.LittleEndian.Uint32(trailer[:]))
	if expected <= 0 || expected > 512<<20 {
		return "", fmt.Errorf("invalid kernel ELF size")
	}
	var program string
	switch {
	case bytes.HasPrefix(magic[:], []byte{0x1f, 0x8b}):
		program = "gzip"
	case bytes.Equal(magic[:], []byte{0xfd, '7', 'z', 'X', 'Z', 0}):
		program = "xz"
		length -= 4
	case bytes.HasPrefix(magic[:], []byte{0x28, 0xb5, 0x2f, 0xfd}):
		program = "zstd"
		length -= 4
	default:
		return "", fmt.Errorf("unsupported kernel compression")
	}
	tmp, err := os.CreateTemp("", "kpctl-kernel-elf-*")
	if err != nil {
		return "", err
	}
	defer tmp.Close()
	if err := os.Remove(tmp.Name()); err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, program, "-dc")
	cmd.Stdin = io.NewSectionReader(image, offset, length)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", err
	}
	if err = cmd.Start(); err != nil {
		return "", err
	}
	n, copyErr := io.Copy(tmp, io.LimitReader(stdout, expected+1))
	if copyErr != nil || n != expected {
		cancel()
	}
	if err := cmd.Wait(); err != nil {
		return "", fmt.Errorf("%s kernel extraction: %w", program, err)
	}
	if copyErr != nil || n != expected {
		return "", fmt.Errorf("invalid kernel decompressed length %d", n)
	}
	f, err := elf.NewFile(tmp)
	if err != nil {
		return "", err
	}
	for _, sec := range f.Sections {
		if sec.Type == elf.SHT_NOTE && sec.Size <= 1<<20 {
			data, err := sec.Data()
			if err != nil {
				return "", err
			}
			if id, err := RunningBuildID(data); err == nil {
				return id, nil
			}
		}
	}
	return "", fmt.Errorf("installed ELF GNU build ID unavailable")
}
