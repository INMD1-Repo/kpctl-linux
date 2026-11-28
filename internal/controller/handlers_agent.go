// 이 파일: 에이전트 등록·보고·승인된 서명 사본 다운로드 API.
package controller

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"kpctl/internal/model"
)

// 이 파일: 호스트 에이전트가 부르는 API

// POST /api/agent/register — 등록 토큰으로 호스트 등록, 호스트 전용 토큰 발급
func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req model.RegisterRequest
	if err := readJSON(r, &req); err != nil {
		writeErr(w, err)
		return
	}
	enroll := s.enrollByToken(req.EnrollToken)
	if enroll == nil {
		writeErr(w, fail(http.StatusUnauthorized, "등록 토큰이 맞지 않습니다"))
		return
	}
	req.Hostname = strings.TrimSpace(req.Hostname)
	if req.Hostname == "" || !validKernel(req.Kernel) {
		writeErr(w, fail(http.StatusBadRequest, "hostname 과 kernel 이 필요합니다"))
		return
	}
	if !s.cfg.AllowSelfEnroll && isSelfHostname(req.Hostname) {
		s.audit("enroll:"+enroll.Name, "등록 거부: 컨트롤러 자신 (%s) ← %s", req.Hostname, r.RemoteAddr)
		writeErr(w, fail(http.StatusForbidden, "컨트롤러(%s)는 호스트로 등록할 수 없습니다. 패치 대상이 아니니 에이전트를 지우세요 (uninstall-agent.sh)", req.Hostname))
		return
	}

	token := randHex(32)
	host := &model.Host{
		ID:           "h-" + randHex(4),
		Hostname:     req.Hostname,
		Ring:         enroll.Ring,
		RebootPolicy: enroll.RebootPolicy,
		VMCount:      -1,
		TokenHash:    hashToken(token),
		RegisteredAt: time.Now(),
		LastSeen:     time.Now(),
		Status:       model.HostStatus{Kernel: req.Kernel},
	}

	err := s.store.Update(func(st *State) error {
		// 같은 이름으로 다시 등록하면 (에이전트 재설치 등) 기존 설정을 이어받고 옛 기록은 지움
		for id, old := range st.Hosts {
			if old.Hostname == req.Hostname {
				host.Ring = old.Ring
				host.RebootPolicy = old.RebootPolicy
				host.Cordoned = old.Cordoned
				delete(st.Hosts, id)
			}
		}
		st.Hosts[host.ID] = host
		return nil
	})
	if err != nil {
		writeErr(w, err)
		return
	}
	s.audit("enroll:"+enroll.Name, "호스트 등록 %s(%s) kernel=%s ring=%d policy=%s",
		host.Hostname, host.ID, req.Kernel, host.Ring, host.RebootPolicy)
	writeJSON(w, http.StatusOK, model.RegisterResponse{HostID: host.ID, HostToken: token})
}

// isSelfHostname 은 이 이름이 컨트롤러 자신인지 봅니다. 대소문자와 도메인은 무시합니다.
func isSelfHostname(name string) bool {
	self, err := os.Hostname()
	if err != nil {
		return false
	}
	short := func(n string) string {
		n, _, _ = strings.Cut(strings.ToLower(n), ".")
		return n
	}
	return short(name) == short(self)
}

func (s *Server) enrollByToken(token string) *EnrollToken {
	var enroll *EnrollToken
	for i := range s.cfg.EnrollTokens {
		if token != "" && sameSecret(s.cfg.EnrollTokens[i].Token, token) {
			enroll = &s.cfg.EnrollTokens[i]
		}
	}
	return enroll
}

// GET /api/bootstrap/agent.tar.gz — 에이전트 설치 묶음. 등록 토큰으로 받습니다.
// VM 이 스스로 등록할 때 kpctl bootstrap 이 만든 스크립트가 부릅니다.
func (s *Server) handleBootstrapBundle(w http.ResponseWriter, r *http.Request) {
	enroll := s.enrollByToken(bearer(r))
	if enroll == nil {
		writeErr(w, fail(http.StatusUnauthorized, "등록 토큰이 맞지 않습니다"))
		return
	}
	data, err := bundleArchive(s.cfg.AgentBundleDir)
	if err != nil {
		writeErr(w, fail(http.StatusServiceUnavailable, "에이전트 묶음을 만들지 못했습니다 (agent_bundle_dir 확인): %v", err))
		return
	}
	s.audit("enroll:"+enroll.Name, "에이전트 묶음 전달 → %s", r.RemoteAddr)
	w.Header().Set("Content-Type", "application/gzip")
	_, _ = w.Write(data)
}

// bundleArchive 는 묶음 디렉터리의 일반 파일을 agent/<파일> 로 담은 tar.gz 를 만듭니다.
func bundleArchive(dir string) ([]byte, error) {
	for _, need := range []string{"kpctl-agent", "install-agent.sh"} {
		if _, err := os.Stat(filepath.Join(dir, need)); err != nil {
			return nil, err
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() { // 심볼릭 링크로 묶음 밖 파일이 나가지 않도록
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		hdr := &tar.Header{Name: "agent/" + e.Name(), Mode: int64(info.Mode().Perm()), Size: int64(len(data)), ModTime: info.ModTime()}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, err
		}
		if _, err := tw.Write(data); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// POST /api/agent/report — 상태 보고. 응답으로 "있어야 할 패치 버전"과 재부팅 지시를 돌려줌
func (s *Server) handleReport(w http.ResponseWriter, r *http.Request, hostID string) {
	var req model.ReportRequest
	if err := readJSON(r, &req); err != nil {
		writeErr(w, err)
		return
	}
	// A scoped automatic approval uses the same drain/approval lock as manual
	// maintenance. Refresh scheduler evidence before the atomic state update.
	if s.autoJumpKernelHost(hostID) {
		s.rebootMu.Lock()
		defer s.rebootMu.Unlock()
		if req.Status.BootTarget != nil {
			s.refreshRebootDrain(hostID)
		}
	}
	var resp model.ReportResponse
	certs, certErr := s.signingCerts()
	resp.SigningCerts = certs
	var jumped *model.RebootApproval
	var rebootDone, kernelChanged, blockedLegacy bool
	var name, oldKernel, scheduledMOK string
	err := s.store.Update(func(st *State) error {
		h := st.Hosts[hostID]
		if h == nil {
			return fail(http.StatusNotFound, "호스트 등록이 지워졌습니다")
		}
		name, oldKernel = h.Hostname, h.Status.Kernel
		kernelChanged = oldKernel != "" && oldKernel != req.Status.Kernel

		h.Status = req.Status
		// Preserve the reported policy bit. Eligibility and the status API compute
		// effective policy, including the conservative default for older agents.
		if certErr != nil {
			h.Status.SecurityWarning = joinSecurityWarnings(h.Status.SecurityWarning, "서명 인증서 목록을 읽지 못했습니다: 관리자 확인 필요")
		}
		if record := st.MOKRequests[hostID]; record != nil && req.Status.MOKImport != nil && record.Request.ID == req.Status.MOKImport.ID && record.Request.KeyID == req.Status.MOKImport.KeyID {
			cp := *req.Status.MOKImport
			record.Result = &cp
		}
		h.LastSeen = time.Now()
		if req.AutoImportCert && hostSignatureRequired(h.Status) {
			for _, cert := range certs {
				if cert.Active && h.Status.EnrolledCerts[cert.ID] == "not_enrolled" {
					if scheduled, warning, err := s.scheduleMOK(st, h, cert, false, ""); err != nil {
						h.Status.SecurityWarning = joinSecurityWarnings(h.Status.SecurityWarning, "MOK 자동 예약 미지원: 수동 등록 필요")
					} else if warning != "" {
						h.Status.SecurityWarning = joinSecurityWarnings(h.Status.SecurityWarning, warning)
					} else if scheduled {
						scheduledMOK = cert.ID
					}
				}
			}
		}
		if record := st.MOKRequests[hostID]; record != nil && record.Result == nil {
			cp := record.Request
			resp.MOKImport = &cp
		}
		if len(s.cfg.Scheduler.VMCountCommand) == 0 {
			h.VMCount = -1
			if req.Status.LocalVMCount != nil {
				h.VMCount = *req.Status.LocalVMCount
			}
			h.VMCountCheckedAt = h.LastSeen
		}

		// 에이전트가 재부팅 요청을 실행하고 돌아왔으면 요청을 지움 (재부팅 반복 방지)
		before := h.RebootRequestID
		reconcileReboot(h, req)
		rebootDone = before != 0 && h.RebootRequestID == 0
		jumped = s.maybeApproveKernelJump(st, h, time.Now())

		resp.Desired = s.desired(st, h)
		if resp.Desired.Blocked && len(req.Status.EnrolledCerts) == 0 && req.Status.Version != 0 && resp.Desired.Version == 0 {
			blockedLegacy = true
		}
		resp.PrepareKernel = s.shouldPrepareKernel(st, h)
		if r := h.KernelPrepareRequest; resp.PrepareKernel && r != nil {
			at := r.RequestedAt
			resp.PrepareKernelRequest = &at
		}
		resp.PrepareKernelTargetID = s.kernelRefreshTargetID(st, h)
		if resp.PrepareKernelTargetID != "" {
			resp.PrepareKernel = true
		}
		// ID-only agents must never execute the new scoped reboot approval.
		resp.RebootID = 0
		if h.RebootApproval != nil {
			cp := *h.RebootApproval
			resp.Reboot = &cp
		}
		if h.RebootResult != nil {
			cp := *h.RebootResult
			resp.RebootResult = &cp
		}
		return nil
	})
	if err != nil {
		writeErr(w, err)
		return
	}
	if scheduledMOK != "" {
		s.audit("agent", "MOK 인증서 자동 예약 host=%s key=%s", hostID, scheduledMOK)
	}
	if blockedLegacy {
		writeErr(w, fail(http.StatusConflict, "배포 제외: 기존 보호를 유지하세요. 에이전트 갱신과 서명 설정 확인 필요"))
		return
	}
	if kernelChanged {
		s.audit("agent", "%s 커널 변경 %s → %s", name, oldKernel, req.Status.Kernel)
	}
	if jumped != nil {
		s.audit("auto-kernel-jump", "%s 공식 커널 자동 점프 승인 요청 #%d %s → %s target=%s expires=%s", name, jumped.ID, jumped.FromKernel, jumped.Target.Kernel, jumped.Target.ID, jumped.ExpiresAt.Format(time.RFC3339))
	}
	if rebootDone {
		s.audit("agent", "%s 재부팅 요청 처리 보고 (현재 kernel=%s, 오류=%q). 확인 후 kpctl host uncordon 하세요",
			name, req.Status.Kernel, req.Status.Error)
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) shouldPrepareKernel(st *State, h *model.Host) bool {
	if r := h.KernelPrepareRequest; r != nil && (r.Kernel != h.Status.Kernel || h.Status.BootTarget != nil) {
		h.KernelPrepareRequest = nil // 준비가 끝났거나 커널이 바뀜
	}
	if (!s.cfg.AutoPrepareKernel && h.KernelPrepareRequest == nil) || h.RebootPolicy != model.RebootDrain ||
		h.Status.BootTarget != nil || h.RebootApproval != nil || h.RebootRequestID != 0 ||
		!validKernel(h.Status.Kernel) || model.LTSForKernel(h.Status.Kernel) == nil ||
		model.IsHWESignature(h.Status.KernelSignature) {
		return false
	}
	// BootProblem 은 준비 기록이 없는 정상 상태에서도 설정됩니다. 손상 여부와
	// 실제 준비 가능 여부는 에이전트와 공식 커널 준비 도우미가 디스크에서 확인합니다.
	if manual := h.KernelPrepareRequest; manual != nil && manual.Kernel == h.Status.Kernel {
		return true
	}
	u := st.Upstream[h.Status.Kernel]
	return u != nil && strings.TrimSpace(u.Outside) != ""
}

// GET /artifacts/{kernel}/{file} — 패치 모듈(.ko) 다운로드
func (s *Server) handleArtifact(w http.ResponseWriter, r *http.Request) {
	kernel := r.PathValue("kernel")
	file := r.PathValue("file")
	module := strings.TrimSuffix(file, ".ko")
	if !validKernel(kernel) || !strings.HasSuffix(file, ".ko") || !validModule(module) {
		writeErr(w, fail(http.StatusBadRequest, "잘못된 경로입니다"))
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	key := r.URL.Query().Get("key")
	if key != "" && !model.ValidSigningKeyID(key) {
		writeErr(w, fail(http.StatusBadRequest, "서명 키 ID 가 잘못됐습니다"))
		return
	}
	path := s.signingArtifactFile(kernel, module, key)
	if key == "" {
		http.ServeFile(w, r, path)
		return
	}
	var expected string
	s.store.View(func(st *State) {
		for _, job := range st.Jobs {
			if job.Kernel == kernel && job.ModuleName == module && job.Status == model.JobReleased {
				if artifact, ok := job.SigningArtifacts[key]; ok {
					expected = artifact.SHA256
				}
			}
		}
	})
	if expected == "" {
		writeErr(w, fail(http.StatusNotFound, "승인된 서명 사본이 없습니다"))
		return
	}
	moduleFile, err := os.Open(path)
	if err != nil {
		writeErr(w, fail(http.StatusNotFound, "승인된 서명 사본을 읽지 못했습니다"))
		return
	}
	defer moduleFile.Close()
	info, err := moduleFile.Stat()
	if err != nil || !info.Mode().IsRegular() {
		writeErr(w, fail(http.StatusConflict, "서명 사본 파일 상태를 확인하지 못했습니다"))
		return
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, moduleFile); err != nil || fmt.Sprintf("%x", hash.Sum(nil)) != expected {
		writeErr(w, fail(http.StatusConflict, "승인된 서명 사본 SHA256 불일치"))
		return
	}
	if _, err := moduleFile.Seek(0, io.SeekStart); err != nil {
		writeErr(w, err)
		return
	}
	// 검증한 같은 파일 descriptor로 제공해 atomic rename과의 경합에도 바이트를 고정합니다.
	http.ServeContent(w, r, module+".ko", info.ModTime(), moduleFile)
}
