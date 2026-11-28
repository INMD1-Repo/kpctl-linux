// 이 파일: 기존 서명 설정 호환, 키별 산출물 생성과 인증서 전달.
package controller

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"kpctl/internal/model"
	"kpctl/internal/testvm"
)

type SigningKey struct {
	ID          string   `json:"id"`
	SignCommand []string `json:"sign_command"`
	Cert        string   `json:"cert,omitempty"`
	Active      bool     `json:"active"`
}

type SigningConfig struct {
	Mode string       `json:"mode"`
	Keys []SigningKey `json:"keys"`
}

func (c *Config) validateSigning() error {
	if c.Signing == nil {
		return nil
	}
	if c.SignCommand != nil {
		return fmt.Errorf("signing 과 sign_command 는 함께 사용할 수 없습니다")
	}
	if c.Signing.Mode == "" {
		c.Signing.Mode = "always"
	}
	if c.Signing.Mode != "always" && c.Signing.Mode != "when_required" && c.Signing.Mode != "never" {
		return fmt.Errorf("signing.mode 는 always, when_required, never 중 하나여야 합니다")
	}
	active := 0
	seen := map[string]bool{}
	for _, key := range c.Signing.Keys {
		if !model.ValidSigningKeyID(key.ID) || seen[key.ID] {
			return fmt.Errorf("서명 키 ID 가 잘못됐거나 중복됩니다: %q", key.ID)
		}
		seen[key.ID] = true
		if key.Active {
			active++
		}
		if c.Signing.Mode != "never" && len(key.SignCommand) == 0 {
			return fmt.Errorf("서명 키 %s 의 sign_command 가 필요합니다", key.ID)
		}
	}
	if active != 1 {
		return fmt.Errorf("signing.keys 의 active 키는 정확히 하나여야 합니다 (현재 %d)", active)
	}
	return nil
}

func (s *Server) signingConfig() SigningConfig {
	if s.cfg.Signing != nil {
		c := *s.cfg.Signing
		if c.Mode == "" {
			c.Mode = "always"
		}
		return c
	}
	c := SigningConfig{Mode: "always"}
	if len(s.cfg.SignCommand) > 0 {
		key := SigningKey{ID: "default", SignCommand: s.cfg.SignCommand, Active: true}
		for _, arg := range key.SignCommand {
			if strings.HasSuffix(arg, ".der") && !strings.Contains(arg, "{") {
				key.Cert = arg
			}
		}
		c.Keys = []SigningKey{key}
	}
	return c
}

func (s *Server) signingCerts() ([]model.SigningCert, error) {
	var certs []model.SigningCert
	for _, key := range s.signingConfig().Keys {
		if key.Cert == "" {
			continue
		}
		der, err := os.ReadFile(key.Cert)
		if err != nil {
			return nil, fmt.Errorf("서명 키 %s 인증서를 읽지 못했습니다", key.ID)
		}
		if _, err := x509.ParseCertificate(der); err != nil {
			return nil, fmt.Errorf("서명 키 %s 인증서가 DER X.509 형식이 아닙니다", key.ID)
		}
		h := sha256.Sum256(der)
		pinned, initialized := s.signingCertSHA256[key.ID]
		if initialized && pinned == "" {
			return nil, fmt.Errorf("키 %s의 공개 DER를 준비한 뒤 컨트롤러를 재시작해 지문을 고정하세요", key.ID)
		}
		if pinned != "" && pinned != hex.EncodeToString(h[:]) {
			return nil, fmt.Errorf("서명 키 %s 인증서 변경 감지: 새 키 ID로 교체해야 합니다", key.ID)
		}
		certs = append(certs, model.SigningCert{ID: key.ID, SHA256: hex.EncodeToString(h[:]), DER: der, Active: key.Active})
	}
	return certs, nil
}

func (s *Server) signingArtifactFile(kernel, module, key string) string {
	if key == "" {
		return s.artifactFile(kernel, module)
	}
	return filepath.Join(filepath.Dir(s.artifactFile(kernel, module)), "signed-"+key, module+".ko")
}

func (s *Server) unsignedArtifactFile(kernel, module string) string {
	return filepath.Join(filepath.Dir(s.artifactFile(kernel, module)), ".unsigned-"+module+".ko")
}

// prepareSigningArtifacts는 기존 시험 호출을 유지합니다. 이전 버전 variant의 메타데이터
// 게시까지 필요한 운영 승인은 WithRotations 반환을 최종 상태 갱신에서 함께 커밋합니다.
func (s *Server) prepareSigningArtifacts(id int, kernel, module string) (artifacts map[string]model.SigningArtifact, activeKey string, err error) {
	artifacts, activeKey, _, err = s.prepareSigningArtifactsWithRotations(id, kernel, module)
	return
}

type signingRotation struct {
	PreviousID                        int
	Kernel, Module, KeyID             string
	UnsignedSHA256, SHA256            string
	PreviousActiveKey, PreviousSHA256 string
	Data                              []byte
	VMTest                            *model.VMTestResult
	PrivateOnly                       bool // 이전 unsigned variant는 시험용 재서명만 하고 운영 바이트를 바꾸지 않음
	PreviousVariantSHA256             string
}

// redactSigningOutput은 서명 도구의 오류 출력에서 sign_command 인자(개인키·인증서 경로 등)를 가립니다.
// 오류는 API 응답·감사 로그에 실리므로 도구가 되돌려 준 키 경로가 그대로 노출되지 않게 합니다.
// 실행 파일 이름(첫 인자)과 치환 자리표시자는 비밀이 아니므로 그대로 둡니다.
func redactSigningOutput(out string, command []string) string {
	if strings.Contains(out, "PRIVATE KEY-----") {
		return "<redacted>"
	}
	for i, arg := range command {
		if i == 0 || arg == "" || strings.Contains(arg, "{") {
			continue
		}
		out = strings.ReplaceAll(out, arg, "<redacted>")
	}
	return out
}

func signingBytesSHA256(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func signModule(key SigningKey, kernel, path, unsignedSum string, certDER []byte) (string, error) {
	out, err := runCommand(key.SignCommand, map[string]string{"module": path, "kernel": kernel}, 5*time.Minute)
	if err != nil {
		if filepath.Base(key.SignCommand[0]) == "sign-file" && (errors.Is(err, os.ErrNotExist) || errors.Is(err, exec.ErrNotFound) || errors.Is(err, os.ErrPermission)) {
			return "", fail(http.StatusInternalServerError, "키 %s: 컨트롤러의 linux-headers-%s 및 서비스 계정의 sign-file 실행 권한 확인: %v", key.ID, kernel, err)
		}
		return "", fail(http.StatusInternalServerError, "모듈 서명 실패 (키 %s): %v\n%s", key.ID, err, redactSigningOutput(out, key.SignCommand))
	}
	sum, err := verifyModuleSignature(path, unsignedSum, certDER)
	if err != nil {
		return "", fail(http.StatusInternalServerError, "모듈 서명 검증 실패 (키 %s): %v", key.ID, err)
	}
	return sum, nil
}

// writeSigningBytes는 서명 전 원본·variant를 임시 파일에서 원자적으로 게시합니다.
func writeSigningBytes(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".signing-bytes-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if err := file.Chmod(0o640); err != nil {
		file.Close()
		return err
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}

// pinnedUnsignedArtifact는 built 작업만 최초 pin을 허용합니다. 기존 released 작업의
// pin이 없다고 현재 서명 파일에서 원본을 추정하여 키 교체에 사용하지 않습니다.
func (s *Server) pinnedUnsignedArtifact(id int, kernel, module string) ([]byte, error) {
	var pinned string
	var checkErr error
	s.store.View(func(st *State) {
		job := st.job(id)
		if job == nil || job.Status != model.JobBuilt || job.Kernel != kernel || job.ModuleName != module {
			checkErr = fail(http.StatusConflict, "서명 전 원본을 고정할 built 작업 상태가 바뀌었습니다")
			return
		}
		pinned = job.UnsignedSHA256
	})
	if checkErr != nil {
		return nil, checkErr
	}
	original := s.unsignedArtifactFile(kernel, module)
	data, err := os.ReadFile(original)
	if os.IsNotExist(err) {
		data, err = os.ReadFile(s.artifactFile(kernel, module))
		if err == nil && pinned != "" && signingBytesSHA256(data) != pinned {
			return nil, fmt.Errorf("업로드한 서명 전 원본 SHA256이 일치하지 않습니다")
		}
		if err == nil {
			err = writeSigningBytes(original, data)
		}
	} else if err == nil && pinned == "" {
		// 이전 built 상태의 첫 승인만 허용하되, 보존본과 현재 raw 파일이 다르면
		// 어느 쪽도 신뢰할 근거가 없으므로 임의로 하나를 선택하지 않습니다.
		raw, rawErr := os.ReadFile(s.artifactFile(kernel, module))
		if rawErr != nil || signingBytesSHA256(raw) != signingBytesSHA256(data) {
			return nil, fmt.Errorf("기존 built 원본을 고정할 수 없습니다: raw 파일과 보존본이 다릅니다")
		}
	}
	if err != nil {
		return nil, err
	}
	checksum := signingBytesSHA256(data)
	if pinned != "" && pinned != checksum {
		return nil, fmt.Errorf("보존된 서명 전 원본 SHA256이 바뀌었습니다")
	}
	if err := s.store.Update(func(st *State) error {
		job := st.job(id)
		if job == nil || job.Status != model.JobBuilt || job.Kernel != kernel || job.ModuleName != module {
			return fail(http.StatusConflict, "서명 전 원본 pin 중 작업 상태가 바뀌었습니다")
		}
		if job.UnsignedSHA256 != "" && job.UnsignedSHA256 != checksum {
			return fmt.Errorf("서명 전 원본 pin이 현재 바이트와 다릅니다")
		}
		actual, err := fileSHA256(original)
		if err != nil || actual != checksum {
			return fmt.Errorf("서명 전 원본이 pin 기록 중 바뀌었습니다")
		}
		job.UnsignedSHA256 = checksum
		return nil
	}); err != nil {
		return nil, err
	}
	return data, nil
}

// prepareSigningArtifactsWithRotations는 현재 원본에서 서명 사본을 만듭니다.
// 새 키가 이전 누적본에 없으면 pin된 그 원본으로만 private 이전 사본을 준비하고,
// 모든 키·모드의 시험이 끝난 뒤 최종 승인 경로에 검증된 바이트만 돌려줍니다.
func (s *Server) prepareSigningArtifactsWithRotations(id int, kernel, module string) (artifacts map[string]model.SigningArtifact, activeKey string, rotations []signingRotation, err error) {
	cfg := s.signingConfig()
	certs, certErr := s.signingCerts()
	if certErr != nil && (s.cfg.Signing != nil || len(s.signingCertSHA256) > 0) {
		return nil, "", nil, certErr
	}
	certDER := make(map[string][]byte, len(certs))
	for _, cert := range certs {
		certDER[cert.ID] = cert.DER
	}
	modes, required := s.testVMRequirements(kernel)
	shouldSign := cfg.Mode != "never" && (cfg.Mode == "always" || required)
	if s.cfg.TestVM.Enabled && required && (cfg.Mode == "never" || len(cfg.Keys) == 0) {
		return nil, "", nil, fail(http.StatusConflict, "서명이 필요한 호스트/VM 모드가 있습니다. sign_command 또는 signing 과 MOK 인증서를 설정하세요")
	}
	path := s.artifactFile(kernel, module)
	original := s.unsignedArtifactFile(kernel, module)
	data, readErr := s.pinnedUnsignedArtifact(id, kernel, module)
	if readErr != nil {
		return nil, "", nil, readErr
	}
	candidateDir, err := os.MkdirTemp(filepath.Dir(path), ".sign-approve-")
	if err != nil {
		return nil, "", nil, err
	}
	defer os.RemoveAll(candidateDir)
	keys := cfg.Keys
	if len(keys) == 0 {
		keys = []SigningKey{{Active: true}}
	}
	needed := map[string]bool{}
	for _, key := range keys {
		if key.Active {
			activeKey = key.ID
			needed[key.ID] = true
		}
	}
	s.store.View(func(st *State) {
		for _, h := range st.Hosts {
			if h.Status.Kernel != kernel || !hostSignatureRequired(h.Status) {
				continue
			}
			for _, key := range keys {
				if h.Status.EnrolledCerts[key.ID] == "enrolled" {
					needed[key.ID] = true
				}
			}
		}
	})
	artifacts = map[string]model.SigningArtifact{}
	unsignedSum := signingBytesSHA256(data)
	for _, key := range keys {
		if !needed[key.ID] {
			continue
		}
		candidate := filepath.Join(candidateDir, key.ID, module+".ko")
		if err := os.MkdirAll(filepath.Dir(candidate), 0o750); err != nil {
			return nil, "", nil, err
		}
		if err := os.WriteFile(candidate, data, 0o640); err != nil {
			return nil, "", nil, err
		}
		signed := shouldSign && len(key.SignCommand) > 0
		sum := unsignedSum
		if signed {
			sum, err = signModule(key, kernel, candidate, unsignedSum, certDER[key.ID])
			if err != nil {
				return nil, "", nil, err
			}
		}
		var evidence *model.VMTestResult
		if s.cfg.TestVM.Enabled {
			previous, rotation, prevErr := s.previousSigningCandidate(kernel, key, candidateDir, signed, certDER[key.ID])
			if prevErr != nil {
				return nil, "", nil, prevErr
			}
			if rotation != nil {
				// 원본도 전후 검사합니다. 현재 원본과 이전 원본의 경로는 서로 다릅니다.
				if actual, err := fileSHA256(s.unsignedArtifactFile(kernel, rotation.Module)); err != nil || actual != rotation.UnsignedSHA256 {
					return nil, "", nil, fmt.Errorf("이전 누적본의 원본이 VM 시험 전에 바뀌었습니다")
				}
			}
			if err := s.testModule(id, kernel, candidate, sum, modes, testvm.ArtifactSet{ModulePath: candidate, UnsignedPath: original, PreviousPath: previous, KeyID: key.ID}); err != nil {
				return nil, "", nil, err
			}
			s.store.View(func(st *State) {
				if j := st.job(id); j != nil && j.VMTest != nil {
					cp := *j.VMTest
					evidence = &cp
				}
			})
			if rotation != nil {
				if actual, err := fileSHA256(s.unsignedArtifactFile(kernel, rotation.Module)); err != nil || actual != rotation.UnsignedSHA256 {
					return nil, "", nil, fmt.Errorf("이전 누적본의 원본이 VM 시험 중 바뀌었습니다")
				}
				previousBytes, err := os.ReadFile(previous)
				if err != nil || signingBytesSHA256(previousBytes) != rotation.SHA256 {
					return nil, "", nil, fmt.Errorf("새 키로 시험한 이전 누적본 SHA256이 바뀌었습니다")
				}
				rotation.Data, rotation.VMTest = previousBytes, rotationVMEvidence(evidence, rotation.SHA256)
				rotations = append(rotations, *rotation)
			}
		}
		final := s.signingArtifactFile(kernel, module, key.ID)
		if err := os.MkdirAll(filepath.Dir(final), 0o750); err != nil {
			return nil, "", nil, err
		}
		if err := os.Rename(candidate, final); err != nil {
			return nil, "", nil, err
		}
		artifacts[key.ID] = model.SigningArtifact{KeyID: key.ID, File: filepath.Base(final), SHA256: sum, Signed: signed, VMTest: evidence}
	}
	return artifacts, activeKey, rotations, nil
}

// deployedSigningJob은 정식/출시 전 링에서 실제 목표로 쓰는 최신 누적본을 고릅니다.
func (s *Server) deployedSigningJob(kernel string) *model.Job {
	var previous *model.Job
	s.store.View(func(st *State) {
		if t := st.Tracks[kernel]; t != nil {
			rings := map[int]bool{}
			for ring := range t.RingVersions {
				rings[ring] = true
			}
			for ring := range t.PrereleaseRingVersions {
				rings[ring] = true
			}
			for ring := range rings {
				version := t.TargetVersion(ring)
				if j := st.releasedJob(kernel, version); version != 0 && j != nil && (previous == nil || j.ID > previous.ID) {
					cp := *j
					previous = &cp
				}
			}
		}
	})
	return previous
}

func (s *Server) existingPreviousSigningArtifact(previous *model.Job, key string) (string, error) {
	kernel := previous.Kernel
	path, sum := "", ""
	if a, ok := previous.SigningArtifacts[key]; ok {
		path, sum = s.signingArtifactFile(kernel, previous.ModuleName, key), a.SHA256
	} else if len(previous.SigningArtifacts) == 0 && s.cfg.Signing == nil && (key == "default" || key == "") {
		path, sum = s.artifactFile(kernel, previous.ModuleName), previous.SHA256
	} else {
		return "", fmt.Errorf("이전 누적 v%d에 키 %s 사본이 없어 교체·롤백 시험을 할 수 없습니다. 기존 키를 유지한 채 새 키 등록 후 누적본을 먼저 준비하세요", previous.Version, key)
	}
	actual, err := fileSHA256(path)
	if err != nil || actual != sum {
		return "", fmt.Errorf("이전 누적본 SHA256 검증 실패: %v", err)
	}
	return path, nil
}

// previousSigningArtifact는 기존 조회 호출과 같은 fail-closed 의미를 유지합니다.
func (s *Server) previousSigningArtifact(kernel, key string) (string, error) {
	previous := s.deployedSigningJob(kernel)
	if previous == nil {
		return "", nil
	}
	return s.existingPreviousSigningArtifact(previous, key)
}

func (s *Server) previousSigningCandidate(kernel string, key SigningKey, candidateDir string, requireSigned bool, certDER []byte) (string, *signingRotation, error) {
	previous := s.deployedSigningJob(kernel)
	if previous == nil {
		return "", nil, nil
	}
	existing, found := previous.SigningArtifacts[key.ID]
	privateOnly := found && !existing.Signed && requireSigned
	if found && !privateOnly || len(previous.SigningArtifacts) == 0 && s.cfg.Signing == nil && (key.ID == "default" || key.ID == "") {
		path, err := s.existingPreviousSigningArtifact(previous, key.ID)
		if err == nil && requireSigned {
			// Older Signed metadata only recorded signer exit status. Recheck
			// the released bytes against the selected certificate before reuse.
			_, err = verifyModuleSignature(path, previous.UnsignedSHA256, certDER)
		}
		return path, nil, err
	}
	if previous.UnsignedSHA256 == "" {
		return "", nil, fmt.Errorf("이전 누적 v%d에 키 %s 사본과 서명 전 원본 pin이 없어 안전한 키 교체·롤백 시험을 할 수 없습니다", previous.Version, key.ID)
	}
	data, err := os.ReadFile(s.unsignedArtifactFile(kernel, previous.ModuleName))
	if err != nil || signingBytesSHA256(data) != previous.UnsignedSHA256 {
		return "", nil, fmt.Errorf("이전 누적 v%d의 보존된 서명 전 원본이 없거나 SHA256이 다릅니다", previous.Version)
	}
	if len(key.SignCommand) == 0 || s.signingConfig().Mode == "never" {
		return "", nil, fmt.Errorf("이전 누적본의 새 키 %s 사본을 만들 서명 명령이 필요합니다", key.ID)
	}
	path := filepath.Join(candidateDir, "previous", key.ID, previous.ModuleName+".ko")
	if err := writeSigningBytes(path, data); err != nil {
		return "", nil, err
	}
	checksum, err := signModule(key, kernel, path, previous.UnsignedSHA256, certDER)
	if err != nil {
		return "", nil, err
	}
	return path, &signingRotation{PreviousID: previous.ID, Kernel: kernel, Module: previous.ModuleName, KeyID: key.ID,
		UnsignedSHA256: previous.UnsignedSHA256, SHA256: checksum, PreviousActiveKey: previous.ActiveSigningKey, PreviousSHA256: previous.SHA256,
		PrivateOnly: privateOnly, PreviousVariantSHA256: existing.SHA256}, nil
}

func rotationVMEvidence(evidence *model.VMTestResult, checksum string) *model.VMTestResult {
	if evidence == nil {
		return nil
	}
	copy := *evidence
	copy.SHA256, copy.Steps = checksum, nil
	for _, step := range evidence.Steps {
		switch step.Name {
		case "boot", "load_previous", "replace", "rollback", "cleanup", "kernel_log":
			copy.Steps = append(copy.Steps, step)
		}
	}
	return &copy
}

// publishSigningRotationsLocked는 모든 검사를 먼저 끝내고 실제 파일만 게시합니다.
// 반환한 메타데이터 커밋은 현재 active 파일의 rename까지 성공한 뒤 호출해야 합니다.
// 중간 파일 게시 실패의 미참조 파일은 artifact API의 released metadata gate로 숨깁니다.
func (s *Server) publishSigningRotationsLocked(st *State, id int, rotations []signingRotation) (func(), error) {
	current := st.job(id)
	if current == nil || current.Status != model.JobBuilt {
		return nil, fail(http.StatusConflict, "키 교체를 게시할 현재 작업 상태가 바뀌었습니다")
	}
	currentOriginal, err := fileSHA256(s.unsignedArtifactFile(current.Kernel, current.ModuleName))
	if current.UnsignedSHA256 == "" || err != nil || currentOriginal != current.UnsignedSHA256 {
		return nil, fmt.Errorf("현재 서명 전 원본 SHA256이 최종 승인 전에 바뀌었습니다")
	}
	type change struct {
		job       *model.Job
		artifacts map[string]model.SigningArtifact
	}
	changes := map[int]*change{}
	for _, rotation := range rotations {
		previous := st.job(rotation.PreviousID)
		if previous == nil || previous.Status != model.JobReleased || previous.Kernel != rotation.Kernel || previous.Kernel != current.Kernel || previous.ModuleName != rotation.Module ||
			previous.UnsignedSHA256 == "" || previous.UnsignedSHA256 != rotation.UnsignedSHA256 || previous.ActiveSigningKey != rotation.PreviousActiveKey || previous.SHA256 != rotation.PreviousSHA256 {
			return nil, fmt.Errorf("키 교체 시험 뒤 이전 누적본 상태가 바뀌었습니다")
		}
		stored, exists := previous.SigningArtifacts[rotation.KeyID]
		if rotation.PrivateOnly {
			if !exists || stored.Signed || stored.SHA256 != rotation.PreviousVariantSHA256 {
				return nil, fmt.Errorf("시험용 재서명 중 이전 unsigned variant가 바뀌었습니다")
			}
		} else if exists {
			return nil, fmt.Errorf("키 교체 이전 사본이 이미 게시되어 있습니다")
		}
		if rotation.VMTest == nil || rotation.VMTest.Status != "passed" || rotation.VMTest.SHA256 != rotation.SHA256 || signingBytesSHA256(rotation.Data) != rotation.SHA256 {
			return nil, fmt.Errorf("키 교체 이전 사본의 검증 증거 또는 SHA256이 잘못됐습니다")
		}
		if len(rotation.VMTest.Modes) == 0 {
			return nil, fmt.Errorf("키 교체 이전 사본의 VM 모드 검증이 없습니다")
		}
		for _, mode := range rotation.VMTest.Modes {
			for _, name := range []string{"load_previous", "replace", "rollback"} {
				passed := false
				for _, step := range rotation.VMTest.Steps {
					passed = passed || step.Mode == mode && step.KeyID == rotation.KeyID && step.Name == name && step.Status == "passed"
				}
				if !passed {
					return nil, fmt.Errorf("키 교체 이전 사본의 %s/%s 시험 통과 증거가 없습니다", mode, name)
				}
			}
		}
		actual, err := fileSHA256(s.unsignedArtifactFile(rotation.Kernel, rotation.Module))
		if err != nil || actual != rotation.UnsignedSHA256 {
			return nil, fmt.Errorf("키 교체 게시 전에 이전 원본 SHA256이 바뀌었습니다")
		}
		if rotation.PrivateOnly {
			continue
		}
		item := changes[previous.ID]
		if item == nil {
			item = &change{job: previous, artifacts: map[string]model.SigningArtifact{}}
			for key, artifact := range previous.SigningArtifacts {
				item.artifacts[key] = artifact
			}
			changes[previous.ID] = item
		}
		if _, duplicate := item.artifacts[rotation.KeyID]; duplicate {
			return nil, fmt.Errorf("키 교체 variant가 중복됐습니다")
		}
		item.artifacts[rotation.KeyID] = model.SigningArtifact{KeyID: rotation.KeyID, File: rotation.Module + ".ko", SHA256: rotation.SHA256, Signed: true, VMTest: rotation.VMTest}
	}
	// 검사 중 실패해도 State의 기존 map을 수정하지 않습니다.
	for _, rotation := range rotations {
		if rotation.PrivateOnly {
			continue
		}
		if err := writeSigningBytes(s.signingArtifactFile(rotation.Kernel, rotation.Module, rotation.KeyID), rotation.Data); err != nil {
			return nil, err
		}
	}
	return func() {
		for _, item := range changes {
			item.job.SigningArtifacts = item.artifacts
		}
	}, nil
}
