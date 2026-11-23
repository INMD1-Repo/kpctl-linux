// 이 파일: controller 패키지의 handleKernelInput, cacheKernelInput 구현·자료형.
package controller

import (
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"time"

	"kpctl/internal/model"
)

const kernelInputLimit int64 = 16 << 30
const kernelInputUpstream = "https://launchpad.net/ubuntu/+archive/primary/+files/"

// handleKernelInput supplies exact kernel packages through the controller.
// Completed packages are shared by builders; failed downloads are never cached.
func (s *Server) handleKernelInput(w http.ResponseWriter, r *http.Request) {
	kernel, version, arch, name := r.PathValue("kernel"), r.PathValue("version"), r.PathValue("arch"), r.PathValue("file")
	names, err := model.KernelInputNames(kernel, version, arch)
	if err != nil || !slices.Contains(names, name) {
		writeErr(w, fail(http.StatusBadRequest, "허용되지 않은 커널 입력 패키지"))
		return
	}
	s.kernelInputsMu.Lock()
	path := filepath.Join(s.cfg.DataDir, "kernel-inputs", kernel, version, arch, name)
	err = s.cacheKernelInput(r, path, name)
	var f *os.File
	var size int64
	var sum string
	if err == nil {
		f, err = os.Open(path)
	}
	if err == nil {
		h := sha256.New()
		size, err = io.Copy(h, f)
		sum = fmt.Sprintf("%x", h.Sum(nil))
		if err == nil {
			_, err = f.Seek(0, io.SeekStart)
		}
	}
	s.kernelInputsMu.Unlock()
	if f != nil {
		defer f.Close()
	}
	if err != nil {
		writeErr(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprint(size))
	w.Header().Set("X-Checksum-Sha256", sum)
	w.Header().Set("ETag", `"`+sum+`"`)
	info, err := f.Stat()
	if err != nil {
		writeErr(w, err)
		return
	}
	http.ServeContent(w, r, name, info.ModTime(), f)
}

func (s *Server) cacheKernelInput(r *http.Request, path, name string) error {
	if err := r.Context().Err(); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > kernelInputLimit {
			return fmt.Errorf("커널 입력 캐시 파일이 올바르지 않습니다: %s", name)
		}
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	c := s.kernelInputsClient
	if c == nil {
		c = &http.Client{Timeout: 30 * time.Minute, CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.URL.Scheme != "https" || len(via) >= 10 {
				return fmt.Errorf("커널 입력 다운로드의 리디렉션을 거부했습니다")
			}
			return nil
		}}
	}
	// Construct a new request: never forward the builder's Authorization header.
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, kernelInputUpstream+name, nil)
	if err != nil {
		return err
	}
	resp, err := c.Do(req)
	if err != nil {
		return fail(http.StatusBadGateway, "커널 입력 패키지 받기 실패: %s: %v", name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return fail(http.StatusNotFound, "정식 입력 패키지가 없습니다: %s", name)
	}
	if resp.StatusCode != http.StatusOK {
		return fail(http.StatusBadGateway, "커널 입력 패키지 받기 실패: %s (HTTP %d)", name, resp.StatusCode)
	}
	if resp.ContentLength > kernelInputLimit {
		return fail(http.StatusBadGateway, "커널 입력 패키지가 크기 제한을 넘습니다: %s", name)
	}
	var space syscall.Statfs_t
	if err := syscall.Statfs(filepath.Dir(path), &space); err != nil {
		return err
	}
	// Keep room for controller state/log writes while filling the package cache.
	const reserve uint64 = 512 << 20
	free := space.Bavail * uint64(space.Bsize)
	if free <= reserve || resp.ContentLength > 0 && uint64(resp.ContentLength) > free-reserve {
		return fail(http.StatusInsufficientStorage, "컨트롤러 커널 입력 캐시의 여유 공간이 부족합니다: %s", name)
	}
	limit := min(kernelInputLimit, int64(min(free-reserve, uint64(kernelInputLimit))))
	f, err := os.CreateTemp(filepath.Dir(path), ".input-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	n, err := io.Copy(f, io.LimitReader(resp.Body, limit+1))
	if err != nil || n <= 0 || n > limit || resp.ContentLength >= 0 && n != resp.ContentLength {
		return fail(http.StatusBadGateway, "커널 입력 패키지 다운로드가 불완전합니다: %s", name)
	}
	if err := f.Chmod(0o640); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
