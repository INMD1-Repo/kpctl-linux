// 이 파일: 가짜 VM 통신으로 승인 산출물·미서명 원본·동일 키 이전 버전과 단계 증거 연결을 검증합니다.
package controller

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"kpctl/internal/model"
	"kpctl/internal/testvm"
)

type vmArtifactCopy struct {
	Path, Dir string
	Data      []byte
}

type vmArtifactInvocation struct {
	Endpoint testvm.Endpoint
	Command  string
	Copies   []vmArtifactCopy
}

type vmArtifactRunner struct {
	mu       sync.Mutex
	pending  map[string][]vmArtifactCopy
	tests    []vmArtifactInvocation
	onModule func(vmArtifactInvocation) error
}

func (r *vmArtifactRunner) Copy(ctx context.Context, endpoint testvm.Endpoint, path, dir string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pending == nil {
		r.pending = map[string][]vmArtifactCopy{}
	}
	r.pending[endpoint.ID] = append(r.pending[endpoint.ID], vmArtifactCopy{Path: path, Dir: dir, Data: data})
	return nil
}

func (r *vmArtifactRunner) Run(ctx context.Context, endpoint testvm.Endpoint, command, stdin string) (string, error) {
	mode := "bios"
	if strings.Contains(endpoint.ID, "sb_on") {
		mode = "sb_on"
	}
	if strings.Contains(command, "uname -r") {
		if mode == "sb_on" {
			return testKernel + "\nuefi\non\nintegrity\non\n", nil
		}
		return testKernel + "\nbios\noff\nnone\noff\n", nil
	}
	if strings.Contains(stdin, "kpatch load") {
		r.mu.Lock()
		invocation := vmArtifactInvocation{Endpoint: endpoint, Command: command, Copies: append([]vmArtifactCopy(nil), r.pending[endpoint.ID]...)}
		delete(r.pending, endpoint.ID)
		r.tests = append(r.tests, invocation)
		onModule := r.onModule
		r.mu.Unlock()
		if onModule != nil {
			if err := onModule(invocation); err != nil {
				return "KPCTL_STEP\tload_new\tfailed\tfake module error\n", err
			}
		}
		var output strings.Builder
		for _, name := range []string{"negative_signature", "load_previous", "load_new", "replace", "smoke", "rollback", "cleanup"} {
			fmt.Fprintf(&output, "KPCTL_STEP\t%s\tpassed\tfake VM runner\n", name)
		}
		return output.String(), nil
	}
	if strings.Contains(stdin, "/proc/sys/kernel/random/boot_id") {
		return "artifact-fixture-boot\n", nil
	}
	return "", nil
}

func (r *vmArtifactRunner) invocations() []vmArtifactInvocation {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]vmArtifactInvocation(nil), r.tests...)
}

func enableArtifactVM(t *testing.T, s *Server, r *vmArtifactRunner, modes testvm.Modes) {
	t.Helper()
	enableApprovalVM(t, s, r)
	s.cfg.TestVM.Modes = modes
	if len(modes) > 1 || (len(modes) == 1 && modes[0] == "sb_on") {
		var image testvm.Image
		for _, configured := range s.cfg.TestVM.Images[testKernel] {
			image = configured
			break
		}
		vars := filepath.Join(t.TempDir(), "vars.fd")
		if err := os.WriteFile(vars, []byte("fake vars"), 0o600); err != nil {
			t.Fatal(err)
		}
		for _, mode := range modes {
			modeImage := image
			if mode != "bios" {
				modeImage.Vars = vars
			}
			s.cfg.TestVM.Images[testKernel][mode] = modeImage
		}
	}
	m, err := testvm.New(s.cfg.TestVM, testVMRegistry{s.store}, r, filepath.Join(s.cfg.DataDir, "testlogs"))
	if err != nil {
		t.Fatal(err)
	}
	s.testVM = m
}

func configureArtifactSigning(t *testing.T, s *Server, oldKey bool) {
	t.Helper()
	signer := vmScript(t, t.TempDir(), "sign-key.sh", `printf ':%s' "$2" >> "$1"`)
	s.cfg.SignCommand = nil
	s.cfg.Signing = &SigningConfig{Mode: "always", Keys: []SigningKey{
		{ID: "new", Active: true, SignCommand: []string{signer, "{module}", "new"}},
		{ID: "old", SignCommand: []string{signer, "{module}", "old"}},
	}}
	if oldKey {
		addHost(t, s, "old-key-host", 1)
		if err := s.store.Update(func(st *State) error {
			st.Hosts["old-key-host"].Status = signingHost(map[string]string{"new": "not_enrolled", "old": "enrolled"}).Status
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
}

func addArtifactBuilt(t *testing.T, s *Server, payload string) (id int, module string) {
	t.Helper()
	id = addBuilt(t, s, "manual")
	s.store.View(func(st *State) { module = st.job(id).ModuleName })
	if err := os.WriteFile(s.artifactFile(testKernel, module), []byte(payload), 0o640); err != nil {
		t.Fatal(err)
	}
	return
}

func copyWithBytes(invocation vmArtifactInvocation, payload string) (vmArtifactCopy, bool) {
	for _, copy := range invocation.Copies {
		if string(copy.Data) == payload {
			return copy, true
		}
	}
	return vmArtifactCopy{}, false
}

func TestVMApprovalTransfersUnsignedOriginalAndSameKeyPreviousArtifact(t *testing.T) {
	s := newAutoServer(t, AutoRollout{})
	runner := &vmArtifactRunner{}
	enableArtifactVM(t, s, runner, testvm.Modes{"sb_on", "bios"})
	configureArtifactSigning(t, s, true)
	previous, _ := addArtifactBuilt(t, s, "previous")
	if _, _, _, err := s.approveJob(previous, "tester"); err != nil {
		t.Fatal(err)
	}
	id, module := addArtifactBuilt(t, s, "candidate")
	if _, _, _, err := s.approveJob(id, "tester"); err != nil {
		t.Fatal(err)
	}
	seen := map[string]int{}
	for _, invocation := range runner.invocations() {
		for _, key := range []string{"new", "old"} {
			current, ok := copyWithBytes(invocation, "candidate:"+key)
			if !ok {
				continue
			}
			seen[key]++
			if strings.Contains(invocation.Endpoint.ID, "sb_on") {
				if unsigned, ok := copyWithBytes(invocation, "candidate"); !ok || unsigned.Dir == current.Dir {
					t.Errorf("%s: unsigned original missing or collides with signed path: %+v", key, invocation)
				}
			}
			if _, ok := copyWithBytes(invocation, "previous:"+key); !ok {
				t.Errorf("%s: previous artifact signed by same key missing: %+v", key, invocation)
			}
			other := "new"
			if key == "new" {
				other = "old"
			}
			if _, ok := copyWithBytes(invocation, "previous:"+other); ok {
				t.Errorf("%s: replacement used another signing key", key)
			}
		}
	}
	for _, key := range []string{"new", "old"} {
		if seen[key] != 2 {
			t.Errorf("%s: expected signed module tested in both modes, got %d", key, seen[key])
		}
	}
	s.store.View(func(st *State) {
		job := st.job(id)
		if job.Status != model.JobReleased || job.VMTest == nil {
			t.Errorf("tested artifact was not released: %+v", job)
			return
		}
		for _, key := range []string{"new", "old"} {
			artifact := job.SigningArtifacts[key]
			expected := fmt.Sprintf("%x", sha256.Sum256([]byte("candidate:"+key)))
			if artifact.SHA256 != expected || artifact.VMTest == nil || artifact.VMTest.SHA256 != expected {
				t.Errorf("%s: evidence hash differs from tested bytes: %+v", key, artifact)
			}
			data, err := os.ReadFile(s.signingArtifactFile(testKernel, module, key))
			if err != nil || string(data) != "candidate:"+key {
				t.Errorf("%s: published bytes differ: %q (%v)", key, data, err)
			}
			for _, mode := range []string{"sb_on", "bios"} {
				found := false
				for _, step := range job.VMTest.Steps {
					if step.KeyID == key && step.Mode == mode && step.Name == "load_new" && step.Status == "passed" {
						found = true
					}
				}
				if !found {
					t.Errorf("missing aggregated step evidence: key=%s mode=%s steps=%+v", key, mode, job.VMTest.Steps)
				}
			}
		}
		active, err := os.ReadFile(s.artifactFile(testKernel, module))
		if err != nil || string(active) != "candidate:new" || job.SHA256 != fmt.Sprintf("%x", sha256.Sum256(active)) {
			t.Errorf("legacy default URL does not serve exact active tested bytes: %q (%v)", active, err)
		}
	})
}

func TestVMReplacementUsesCurrentlyDeployedVersion(t *testing.T) {
	s := newAutoServer(t, AutoRollout{})
	runner := &vmArtifactRunner{}
	enableArtifactVM(t, s, runner, testvm.Modes{"bios"})
	configureArtifactSigning(t, s, false)
	first, _ := addArtifactBuilt(t, s, "deployed")
	if _, _, _, err := s.approveJob(first, "tester"); err != nil {
		t.Fatal(err)
	}
	second, _ := addArtifactBuilt(t, s, "released-but-rolled-back")
	if _, _, _, err := s.approveJob(second, "tester"); err != nil {
		t.Fatal(err)
	}
	if err := s.store.Update(func(st *State) error {
		st.track(testKernel).RingVersions[1] = st.job(first).Version
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	third, _ := addArtifactBuilt(t, s, "next")
	if _, _, _, err := s.approveJob(third, "tester"); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, invocation := range runner.invocations() {
		if _, ok := copyWithBytes(invocation, "next:new"); !ok {
			continue
		}
		found = true
		if _, ok := copyWithBytes(invocation, "deployed:new"); !ok {
			t.Error("replacement omitted currently deployed artifact")
		}
		if _, ok := copyWithBytes(invocation, "released-but-rolled-back:new"); ok {
			t.Error("replacement selected latest historical release instead of rollout target")
		}
	}
	if !found {
		t.Fatal("new artifact was not tested")
	}
}

func TestVMApprovalRejectsMissingSameKeyPreviousCopyWithoutPinnedOriginal(t *testing.T) {
	s := newAutoServer(t, AutoRollout{})
	runner := &vmArtifactRunner{}
	enableArtifactVM(t, s, runner, testvm.Modes{"bios"})
	configureArtifactSigning(t, s, false)
	previous, _ := addArtifactBuilt(t, s, "previous")
	if _, _, _, err := s.approveJob(previous, "tester"); err != nil {
		t.Fatal(err)
	}
	// 업그레이드 전 배포 이력에는 원본 pin이 없습니다. 서명된 alias에서 추정하지 않습니다.
	if err := s.store.Update(func(st *State) error { st.job(previous).UnsignedSHA256 = ""; return nil }); err != nil {
		t.Fatal(err)
	}
	configureArtifactSigning(t, s, true)
	id, _ := addArtifactBuilt(t, s, "candidate")
	if _, _, _, err := s.approveJob(id, "tester"); err == nil {
		t.Fatal("approval silently skipped replacement for missing previous old-key copy")
	}
	if ringVersion(s, 1) != 1 {
		t.Fatal("missing previous signed copy changed rollout")
	}
	s.store.View(func(st *State) {
		if st.job(id).Status != model.JobBuilt {
			t.Errorf("failed approval changed job status: %+v", st.job(id))
		}
	})
}

func TestVMApprovalRejectsInputMutationDuringTests(t *testing.T) {
	for _, input := range []string{"unsigned", "previous"} {
		t.Run(input, func(t *testing.T) {
			s := newAutoServer(t, AutoRollout{})
			runner := &vmArtifactRunner{}
			enableArtifactVM(t, s, runner, testvm.Modes{"bios"})
			configureArtifactSigning(t, s, false)
			previous, previousModule := addArtifactBuilt(t, s, "previous")
			if _, _, _, err := s.approveJob(previous, "tester"); err != nil {
				t.Fatal(err)
			}
			id, module := addArtifactBuilt(t, s, "candidate")
			path := s.unsignedArtifactFile(testKernel, module)
			if input == "previous" {
				path = s.signingArtifactFile(testKernel, previousModule, "new")
			}
			runner.onModule = func(vmArtifactInvocation) error {
				return os.WriteFile(path, []byte("changed while VM test ran"), 0o640)
			}
			if _, _, _, err := s.approveJob(id, "tester"); err == nil {
				t.Fatal("VM input mutation did not block release")
			}
			if ringVersion(s, 1) != 1 {
				t.Fatal("mutated input changed rollout")
			}
			s.store.View(func(st *State) {
				if job := st.job(id); job.Status != model.JobBuilt || job.VMTest == nil || job.VMTest.Status != "failed" {
					t.Errorf("mutated input lacks failed evidence: %+v", job)
				}
			})
		})
	}
}
