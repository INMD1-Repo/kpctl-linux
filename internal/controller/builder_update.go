// 이 파일: 빌드 서버 자동 업데이트
//
// 컨트롤러에 새 kpctl-builder(builder_binary)를 두면, 빌드 서버들이 10분마다 확인해서 스스로 바꿉니다.
//
//	POST /api/builder/update   {"sha256": 지금 실행 파일}  → {"update": true, "sha256": 새 파일}
//	GET  /api/builder/binary   새 실행 파일
//
// 빌드 서버는 받은 파일의 sha256 을 확인하고 작업 디렉터리에 둔 뒤 종료합니다.
// systemd 가 다시 시작하면서 root 로 /usr/local/bin 에 설치합니다 (kpctl-builder.service 의 ExecStartPre).
package controller

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	"kpctl/internal/model"
)

var binCache struct {
	sync.Mutex
	mtime time.Time
	size  int64
	sum   string
}

// builderBinarySHA 는 builder_binary 의 sha256 입니다. 파일이 없으면 "" (자동 업데이트 안 함).
// 파일이 바뀌지 않았으면 다시 계산하지 않습니다.
func (s *Server) builderBinarySHA() (string, int64) {
	fi, err := os.Stat(s.cfg.BuilderBinary)
	if err != nil || !fi.Mode().IsRegular() {
		return "", 0
	}
	binCache.Lock()
	defer binCache.Unlock()
	if binCache.sum != "" && fi.ModTime().Equal(binCache.mtime) && fi.Size() == binCache.size {
		return binCache.sum, binCache.size
	}
	f, err := os.Open(s.cfg.BuilderBinary)
	if err != nil {
		return "", 0
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", 0
	}
	binCache.mtime, binCache.size, binCache.sum = fi.ModTime(), fi.Size(), hex.EncodeToString(h.Sum(nil))
	return binCache.sum, binCache.size
}

// POST /api/builder/update
func (s *Server) handleBuilderUpdate(w http.ResponseWriter, r *http.Request) {
	var req model.BuilderUpdateRequest
	if err := readJSON(r, &req); err != nil {
		writeErr(w, err)
		return
	}
	sum, size := s.builderBinarySHA()
	if sum == "" || req.SHA256 == "" || sum == req.SHA256 {
		writeJSON(w, http.StatusOK, model.BuilderUpdateResponse{})
		return
	}
	writeJSON(w, http.StatusOK, model.BuilderUpdateResponse{Update: true, SHA256: sum, Size: size})
}

// GET /api/builder/binary
func (s *Server) handleBuilderBinary(w http.ResponseWriter, r *http.Request) {
	if sum, _ := s.builderBinarySHA(); sum == "" {
		writeErr(w, fail(http.StatusNotFound, "컨트롤러에 kpctl-builder 가 없습니다 (%s)", s.cfg.BuilderBinary))
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeFile(w, r, s.cfg.BuilderBinary)
}
