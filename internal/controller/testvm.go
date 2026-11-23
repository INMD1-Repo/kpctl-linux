// 이 파일: 승인 VM 수명·시험 입력 해시·키별 단계 증거 연결.
package controller

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"kpctl/internal/model"
	"kpctl/internal/testvm"
)

type testVMRegistry struct{ store *Store }

func (r testVMRegistry) Remember(vm testvm.Instance) error {
	return r.store.Update(func(st *State) error {
		if st.TestVMs == nil {
			st.TestVMs = map[string]testvm.Instance{}
		}
		st.TestVMs[vm.ID] = vm
		return nil
	})
}

func (r testVMRegistry) Forget(id string) error {
	return r.store.Update(func(st *State) error { delete(st.TestVMs, id); return nil })
}

func (s *Server) initTestVM() error {
	s.testVMCtx, s.testVMCancel = context.WithCancel(context.Background())
	// Configured commands can still clean up after a feature was disabled.
	if !s.cfg.TestVM.Enabled && (len(s.cfg.TestVM.DeleteCmd) == 0 || len(s.cfg.TestVM.ListCmd) == 0) {
		return nil
	}
	m, err := testvm.New(s.cfg.TestVM, testVMRegistry{s.store}, nil, filepath.Join(s.cfg.DataDir, "testlogs"))
	if err != nil {
		s.testVMCancel()
		return err
	}
	var recorded []testvm.Instance
	s.store.View(func(st *State) {
		for _, vm := range st.TestVMs {
			recorded = append(recorded, vm)
		}
	})
	if err := m.Recover(s.testVMCtx, recorded); err != nil {
		s.testVMCancel()
		return fmt.Errorf("test VM startup cleanup failed: %w", err)
	}
	if err := s.store.Update(func(st *State) error {
		for _, j := range st.Jobs {
			if j.VMTest != nil && j.VMTest.Status == "running" {
				j.VMTest.Status, j.VMTest.Error, j.VMTest.FinishedAt = "failed", "컨트롤러 재시작으로 중단된 시험: VM 정리 완료", time.Now()
			}
		}
		return nil
	}); err != nil {
		s.testVMCancel()
		return err
	}
	s.testVM = m
	return nil
}

func (s *Server) testVMRequirements(kernel string) (modes []string, signatureRequired bool) {
	s.store.View(func(st *State) {
		modes, signatureRequired = s.testVMRequirementsLocked(st, kernel)
	})
	return modes, signatureRequired
}

func (s *Server) testVMRequirementsLocked(st *State, kernel string) (modes []string, signatureRequired bool) {
	var fleet []model.HostStatus
	for _, h := range st.Hosts {
		if h.Status.Kernel != kernel {
			continue
		}
		fleet = append(fleet, h.Status)
		h := h.Status
		if hostSignatureRequired(h) {
			signatureRequired = true
		}
	}
	modes = testvm.SelectModes(s.cfg.TestVM.Modes, fleet)
	for _, mode := range modes {
		if mode == "sb_on" && s.cfg.TestVM.Enabled {
			signatureRequired = true
		}
	}
	return modes, signatureRequired
}

func (s *Server) testModule(id int, kernel, path, sum string, modes []string, inputs ...testvm.ArtifactSet) error {
	if s.testVM == nil {
		return fmt.Errorf("test_vm is enabled but manager is unavailable")
	}
	artifacts := testvm.ArtifactSet{ModulePath: path}
	if len(inputs) > 0 {
		artifacts = inputs[0]
		artifacts.ModulePath = path
	}
	inputSHA := map[string]string{path: sum}
	for _, input := range []string{artifacts.UnsignedPath, artifacts.PreviousPath} {
		if input == "" {
			continue
		}
		checksum, err := fileSHA256(input)
		if err != nil {
			return fmt.Errorf("VM 시험 입력 읽기 실패: %w", err)
		}
		inputSHA[input] = checksum
	}
	started := time.Now()
	if err := s.store.Update(func(st *State) error {
		j := st.job(id)
		if j == nil || j.Status != model.JobBuilt {
			return fail(http.StatusConflict, "작업 %d 상태가 바뀌었습니다", id)
		}
		j.VMTest = &model.VMTestResult{Status: "running", SHA256: sum, Modes: modes, StartedAt: started}
		return nil
	}); err != nil {
		return err
	}
	type outcome struct {
		mode  string
		steps []model.VMTestStep
		err   error
	}
	results := make(chan outcome, len(modes))
	for _, mode := range modes {
		go func(mode string) {
			steps, err := s.testVM.RunWithArtifacts(s.testVMCtx, id, kernel, mode, artifacts)
			results <- outcome{mode: mode, steps: steps, err: err}
		}(mode)
	}
	// Wait for every mode, including destruction, before permitting release.
	failed := map[string]error{}
	stepResults := map[string][]model.VMTestStep{}
	for range modes {
		result := <-results
		stepResults[result.mode] = result.steps
		if result.err != nil {
			failed[result.mode] = result.err
		}
	}
	var errs []error
	var steps []model.VMTestStep
	for _, mode := range modes {
		steps = append(steps, stepResults[mode]...)
		if err := failed[mode]; err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", mode, err))
		}
	}
	for input, before := range inputSHA {
		if after, err := fileSHA256(input); err != nil || after != before {
			errs = append(errs, fmt.Errorf("module changed during VM tests: %v", err))
		}
	}
	testErr := errors.Join(errs...)
	stateErr := s.store.Update(func(st *State) error {
		j := st.job(id)
		if j == nil {
			return fail(http.StatusConflict, "작업 %d 이 삭제되었습니다", id)
		}
		status, message := "passed", ""
		if testErr != nil {
			status, message = "failed", testErr.Error()
		}
		j.VMTest = &model.VMTestResult{Status: status, SHA256: sum, Modes: modes, StartedAt: started, FinishedAt: time.Now(), Error: message, Steps: steps}
		if testErr != nil && st.track(kernel).AutoHold == "" {
			setAutoHold(st.track(kernel), fmt.Sprintf("job %d VM 시험 실패 — testlogs 검토 필요", id), holdManual, "")
		}
		return nil
	})
	if testErr != nil {
		s.audit("testvm", "VM 시험 실패 job %d kernel=%s modes=%s: %s", id, kernel, strings.Join(modes, ","), firstLine(testErr.Error()))
		return errors.Join(fail(http.StatusConflict, "VM 시험 실패 (testlogs 확인): %v", testErr), stateErr)
	}
	if stateErr != nil {
		return stateErr
	}
	s.audit("testvm", "VM 시험 통과 job %d kernel=%s modes=%s sha256=%s", id, kernel, strings.Join(modes, ","), sum)
	return nil
}

// combinedVMResult는 공개 기본 SHA를 유지하며 키별 시험 단계 증거를 합칩니다.
func combinedVMResult(active model.SigningArtifact, artifacts map[string]model.SigningArtifact) *model.VMTestResult {
	if active.VMTest == nil {
		return nil
	}
	result := *active.VMTest
	result.Steps = nil
	var ids []string
	for id := range artifacts {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if test := artifacts[id].VMTest; test != nil {
			result.Steps = append(result.Steps, test.Steps...)
		}
	}
	return &result
}
