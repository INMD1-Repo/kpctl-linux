// 이 파일: 빌드 서버 자동 업데이트
//
// 컨트롤러가 가진 kpctl-builder 와 지금 실행 파일의 sha256 이 다르면, 새 파일을 받아
// KPCTL_BUILDER_UPDATE_PATH 에 두고 종료합니다 (종료 코드 75).
// systemd 가 다시 시작하면서 root 로 /usr/local/bin 에 설치합니다 (kpctl-builder.service 의 ExecStartPre).
// 빌드 서버는 빌드 계정(기본 kpbuild, setup-builder.sh --user)으로 돌아서 /usr/local/bin 에 직접 쓸 수 없기 때문입니다.
//
// KPCTL_BUILDER_UPDATE_PATH 가 없으면(예전 서비스 파일) 받지 않습니다. 받아도 설치할 주체가 없어
// 종료→재시작→다시 받기를 반복하게 되기 때문입니다.
package builder

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"kpctl/internal/model"
)

// ExitRestartForUpdate 는 새 실행 파일을 받아 두고 재시작을 요청할 때의 종료 코드입니다.
const ExitRestartForUpdate = 75

func fileSHA256(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

func selfSHA256() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	return fileSHA256(exe)
}

// updatePath 는 새 실행 파일을 둘 곳입니다. 자동 업데이트를 할 수 없으면 "".
func (b *Builder) updatePath() string {
	if !*b.cfg.SelfUpdate || b.selfSHA == "" {
		return ""
	}
	return os.Getenv("KPCTL_BUILDER_UPDATE_PATH")
}

// CheckUpdate 는 컨트롤러에 새 kpctl-builder 가 있으면 받아 둡니다. 받아 뒀으면 true (재시작 필요).
func (b *Builder) CheckUpdate() bool {
	dest := b.updatePath()
	if dest == "" {
		return false
	}
	var resp model.BuilderUpdateResponse
	if err := b.c.Do("POST", "/api/builder/update", model.BuilderUpdateRequest{SHA256: b.selfSHA}, &resp); err != nil {
		log.Printf("자동 업데이트 확인 실패 (다음에 다시): %v", err)
		return false
	}
	if !resp.Update {
		return false
	}
	log.Printf("새 kpctl-builder 발견 (sha256 %s) → 받는 중", short(resp.SHA256))
	if err := b.fetchUpdate(dest, resp.SHA256); err != nil {
		log.Printf("자동 업데이트 실패 (지금 버전으로 계속): %v", err)
		return false
	}
	log.Printf("새 kpctl-builder 를 %s 에 받았습니다. 재시작하면 systemd 가 설치합니다", dest)
	return true
}

// fetchUpdate 는 받기 → sha256 확인 → 실행 시험 → 제자리로 옮기기 순서로 합니다.
func (b *Builder) fetchUpdate(dest, want string) error {
	if err := os.MkdirAll(filepath.Dir(dest), 0o750); err != nil {
		return err
	}
	tmp := dest + ".tmp"
	_ = os.Remove(tmp)
	defer os.Remove(tmp)
	if err := b.c.Download("/api/builder/binary", tmp); err != nil {
		return fmt.Errorf("받기 실패: %w", err)
	}
	if got := fileSHA256(tmp); got != want {
		return fmt.Errorf("sha256 불일치: 받은 파일 %s, 컨트롤러 %s", short(got), short(want))
	}
	if err := os.Chmod(tmp, 0o755); err != nil {
		return err
	}
	// 이 서버에서 실행되는 파일인지 (아키텍처 등) 확인: -h 는 사용법을 출력하고 0 으로 끝남
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, tmp, "-h").CombinedOutput(); err != nil {
		return fmt.Errorf("받은 파일이 실행되지 않습니다: %v %s", err, lastLines(string(out), 3))
	}
	return os.Rename(tmp, dest)
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}
