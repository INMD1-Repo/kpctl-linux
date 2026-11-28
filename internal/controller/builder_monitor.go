// 이 파일: controller 패키지의 recordBuilder, builderLogFile, liveLogFile 구현·자료형.
package controller

import (
	"crypto/sha256"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"kpctl/internal/model"
)

// Both task polling and heartbeats update the same record without discarding
// activity reported while a long trial or compiler command is still running.
func (s *Server) recordBuilder(st *State, req model.NextJobRequest, remote string) *model.BuilderInfo {
	if st.Builders == nil {
		st.Builders = map[string]*model.BuilderInfo{}
	}
	b := st.Builders[req.Builder]
	if b == nil {
		b = &model.BuilderInfo{Name: req.Builder}
		st.Builders[req.Builder] = b
	}
	addr, _, err := net.SplitHostPort(remote)
	if err != nil {
		addr = remote
	}
	latest, _ := s.builderBinarySHA()
	b.Series, b.Kernels, b.CanRefresh = req.Series, req.Kernels, req.CanRefresh
	b.CanPrerelease = req.CanPrerelease
	b.Addr, b.LastSeen = strings.TrimPrefix(addr, "::ffff:"), time.Now()
	b.SHA256, b.UpToDate = req.BinarySHA256, latest == "" || latest == req.BinarySHA256
	return b
}

func (s *Server) builderLogFile(name string) string {
	return filepath.Join(s.cfg.DataDir, "logs", fmt.Sprintf("builder-%x.log", sha256.Sum256([]byte(name))))
}

func (s *Server) liveLogFile(id int) string {
	return filepath.Join(s.cfg.DataDir, "logs", fmt.Sprintf("job-%d.live.log", id))
}

func saveLiveLog(path, content string) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".live-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0o640); err == nil {
		_, err = f.WriteString(content)
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(f.Name(), path)
}

func (s *Server) handleBuilderHeartbeat(w http.ResponseWriter, r *http.Request) {
	// JSON may expand a log byte into a six-byte Unicode escape. Bound the
	// decoded logs separately so a full valid tail still fits on the wire.
	r.Body = http.MaxBytesReader(w, r.Body, 12*model.BuilderLogLimit+65536)
	var req model.BuilderHeartbeatRequest
	if err := readJSON(r, &req); err != nil {
		writeErr(w, err)
		return
	}
	if strings.TrimSpace(req.Builder) == "" || len(req.Builder) > 128 || strings.ContainsAny(req.Builder, "/\\\r\n") ||
		len(req.Log) > model.BuilderLogLimit || len(req.JobLog) > model.BuilderLogLimit || len(req.Activity.Message) > 4096 || len(req.Maintenance) > 4096 {
		writeErr(w, fail(http.StatusBadRequest, "빌드 서버 이름이나 상태·로그 크기가 잘못됐습니다"))
		return
	}
	if req.Cache != nil && (req.Cache.Hits < 0 || req.Cache.Misses < 0 || len(req.Cache.Warning) > 2048 ||
		(req.Cache.HitRate != nil && (*req.Cache.HitRate < 0 || *req.Cache.HitRate > 1))) {
		writeErr(w, fail(http.StatusBadRequest, "캐시 측정값이 잘못됐습니다"))
		return
	}
	err := s.store.Update(func(st *State) error {
		// A native oneshot sends an empty idle heartbeat between timer runs.
		// Keep the previous compiler output available until the next activity.
		keepLog := req.Environment == "distribution" && req.Activity.Phase == "idle" && req.Log == ""
		if !keepLog {
			if err := saveLiveLog(s.builderLogFile(req.Builder), req.Log); err != nil {
				return err
			}
		}
		// An old attempt or another builder cannot renew a claim, nor overwrite
		// the running attempt's log. Finished job logs use a separate file.
		j := st.job(req.Activity.JobID)
		owns := j != nil && j.Status == model.JobRunning && j.Builder == req.Builder &&
			j.Kernel == req.Activity.Kernel && j.StartedAt.Equal(req.Activity.JobStartedAt)
		if owns {
			if err := saveLiveLog(s.liveLogFile(j.ID), req.JobLog); err != nil {
				return err
			}
		}
		b := s.recordBuilder(st, req.NextJobRequest, r.RemoteAddr)
		if req.Maintenance != "" {
			b.Maintenance = req.Maintenance
		}
		b.HeartbeatAt, b.Activity, b.Resources = time.Now(), &req.Activity, &req.Resources
		b.Environment = req.Environment
		if !keepLog {
			b.LogTruncated = req.LogTruncated
		}
		if req.Cache != nil {
			b.Cache = req.Cache
		}
		if owns {
			j.HeartbeatAt = b.HeartbeatAt
		}
		return nil
	})
	if err != nil {
		writeErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleBuilderDetail(w http.ResponseWriter, r *http.Request, who string) {
	var body []byte
	var readErr error
	s.store.View(func(st *State) {
		b := st.Builders[r.PathValue("name")]
		if b == nil {
			readErr = fail(http.StatusNotFound, "빌드 서버가 없습니다")
			return
		}
		data, err := os.ReadFile(s.builderLogFile(b.Name))
		if err != nil && !os.IsNotExist(err) {
			readErr = err
			return
		}
		body = mustJSON(model.BuilderDetail{Builder: b, Log: string(data)})
	})
	if readErr != nil {
		writeErr(w, readErr)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeRaw(w, http.StatusOK, body)
}
