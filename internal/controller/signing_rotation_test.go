// 이 파일: 가짜 VM 통신으로 키 교체의 원본 pin·동일 키 이전본 시험·최종 게시를 검증합니다.
package controller

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"kpctl/internal/model"
	"kpctl/internal/testvm"
)

type rotationFixture struct {
	s        *Server
	runner   *vmArtifactRunner
	previous int
	module   string
	alias    []byte
	jobJSON  []byte
}

func rotationPayload(value, key string) string { return value + ":" + key + ":" + testKernel }

func newRotationFixture(t *testing.T) *rotationFixture {
	t.Helper()
	s := newAutoServer(t, AutoRollout{})
	runner := &vmArtifactRunner{}
	enableArtifactVM(t, s, runner, testvm.Modes{"sb_on", "bios"})
	signer := vmScript(t, t.TempDir(), "rotation-sign.sh", `printf ':%s:%s' "$2" "$3" >> "$1"`)
	s.cfg.SignCommand = nil
	s.cfg.Signing = &SigningConfig{Mode: "always", Keys: []SigningKey{
		{ID: "old", Active: true, SignCommand: []string{signer, "{module}", "old", "{kernel}"}},
		{ID: "new", SignCommand: []string{signer, "{module}", "new", "{kernel}"}},
	}}
	previous, module := addArtifactBuilt(t, s, "previous")
	if _, _, _, err := s.approveJob(previous, "tester"); err != nil {
		t.Fatal(err)
	}
	fixture := &rotationFixture{s: s, runner: runner, previous: previous, module: module}
	var err error
	fixture.alias, err = os.ReadFile(s.artifactFile(testKernel, module))
	if err != nil {
		t.Fatal(err)
	}
	s.store.View(func(st *State) { fixture.jobJSON, _ = json.Marshal(st.job(previous)) })
	if err := s.store.Update(func(st *State) error {
		host := st.Hosts["gpu-test"]
		host.Status.Firmware, host.Status.SecureBoot, host.Status.Lockdown, host.Status.SigEnforce = "uefi", "on", "integrity", "off"
		host.Status.EnrolledCerts = map[string]string{"old": "enrolled", "new": "enrolled"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func (fixture *rotationFixture) assertPreviousUnchanged(t *testing.T) {
	t.Helper()
	fixture.s.store.View(func(st *State) {
		data, _ := json.Marshal(st.job(fixture.previous))
		if string(data) != string(fixture.jobJSON) {
			t.Errorf("failed approval mutated previous job: before=%s after=%s", fixture.jobJSON, data)
		}
	})
	data, err := os.ReadFile(fixture.s.artifactFile(testKernel, fixture.module))
	if err != nil || string(data) != string(fixture.alias) {
		t.Errorf("previous default alias changed: %q (%v)", data, err)
	}
	if ringVersion(fixture.s, 1) != 1 {
		t.Errorf("failed rotation changed rollout")
	}
	files, err := filepath.Glob(filepath.Join(filepath.Dir(fixture.s.artifactFile(testKernel, fixture.module)), ".sign-approve-*"))
	if err != nil || len(files) != 0 {
		t.Errorf("private signing candidates survived: %v (%v)", files, err)
	}
}

func TestSigningRotationBootstrapsPreviousVariantOnlyAfterAllVMTests(t *testing.T) {
	fixture := newRotationFixture(t)
	s := fixture.s
	id, _ := addArtifactBuilt(t, s, "candidate")
	var newTests atomic.Int32
	fixture.runner.onModule = func(invocation vmArtifactInvocation) error {
		if _, ok := copyWithBytes(invocation, rotationPayload("candidate", "new")); !ok {
			return nil
		}
		newTests.Add(1)
		if _, ok := copyWithBytes(invocation, rotationPayload("previous", "new")); !ok {
			return errors.New("new-key previous variant was not tested")
		}
		var published bool
		s.store.View(func(st *State) { _, published = st.job(fixture.previous).SigningArtifacts["new"] })
		if published {
			return errors.New("previous metadata published before VM completion")
		}
		if _, err := os.Stat(s.signingArtifactFile(testKernel, fixture.module, "new")); !os.IsNotExist(err) {
			return errors.New("previous candidate escaped private directory")
		}
		return nil
	}
	if _, _, _, err := s.approveJob(id, "tester"); err != nil {
		t.Fatal(err)
	}
	if got := newTests.Load(); got != 2 {
		t.Fatalf("new key did not test both modes: %d", got)
	}
	var before model.Job
	if err := json.Unmarshal(fixture.jobJSON, &before); err != nil {
		t.Fatal(err)
	}
	s.store.View(func(st *State) {
		previous := st.job(fixture.previous)
		if previous.ActiveSigningKey != before.ActiveSigningKey || previous.SHA256 != before.SHA256 || previous.UnsignedSHA256 != signingBytesSHA256([]byte("previous")) {
			t.Errorf("rotation changed previous identity: %+v", previous)
		}
		variant, ok := previous.SigningArtifacts["new"]
		want := signingBytesSHA256([]byte(rotationPayload("previous", "new")))
		if !ok || !variant.Signed || variant.SHA256 != want || variant.VMTest == nil || variant.VMTest.Status != "passed" || variant.VMTest.SHA256 != want {
			t.Errorf("previous signed variant lacks exact evidence: %+v", variant)
		}
		if variant.VMTest != nil {
			for _, mode := range []string{"sb_on", "bios"} {
				for _, name := range []string{"load_previous", "replace", "rollback"} {
					found := false
					for _, step := range variant.VMTest.Steps {
						found = found || step.KeyID == "new" && step.Mode == mode && step.Name == name && step.Status == "passed"
					}
					if !found {
						t.Errorf("missing previous variant step %s/%s", mode, name)
					}
				}
			}
			for _, step := range variant.VMTest.Steps {
				if step.Name == "negative_signature" {
					t.Error("previous evidence incorrectly claims new-module negative test")
				}
			}
		}
		if st.job(id).Status != model.JobReleased || st.job(id).UnsignedSHA256 != signingBytesSHA256([]byte("candidate")) {
			t.Errorf("current release pin missing: %+v", st.job(id))
		}
	})
	data, err := os.ReadFile(s.signingArtifactFile(testKernel, fixture.module, "new"))
	if err != nil || string(data) != rotationPayload("previous", "new") {
		t.Fatalf("wrong published previous bytes: %q (%v)", data, err)
	}
	alias, err := os.ReadFile(s.artifactFile(testKernel, fixture.module))
	if err != nil || string(alias) != string(fixture.alias) {
		t.Fatalf("historical active alias changed: %q (%v)", alias, err)
	}
	fixture.runner.onModule = nil
	// 두 키 사본을 가진 누적본 이후 active를 전환하고, 과거 버전도 새 키로 배포할 수 있습니다.
	s.cfg.Signing.Keys[0].Active, s.cfg.Signing.Keys[1].Active = false, true
	next, _ := addArtifactBuilt(t, s, "after-rotation")
	if _, _, _, err := s.approveJob(next, "tester"); err != nil {
		t.Fatal(err)
	}
	callAPI(t, s, "POST", "/api/kernels/"+testKernel+"/rollback", `{"version":1}`, http.StatusOK)
	var desired model.DesiredPatch
	s.store.View(func(st *State) { desired = s.desired(st, st.Hosts["gpu-test"]) })
	if desired.Blocked || desired.Version != 1 || desired.SHA256 != signingBytesSHA256(data) || !strings.Contains(desired.URL, "key=new") {
		t.Fatalf("new key cannot roll back to previous bytes: %+v", desired)
	}
	request := httptest.NewRequest("GET", desired.URL, nil)
	request.Header.Set("Authorization", "Bearer "+testAdmin)
	response := httptest.NewRecorder()
	s.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Body.String() != string(data) {
		t.Fatalf("published previous variant not downloadable: %d %s", response.Code, response.Body.String())
	}
}

func TestSigningRotationFailureNeverPublishesPreviousMetadata(t *testing.T) {
	for _, kind := range []string{"new-key VM failure", "later-key VM failure", "outer fleet check", "previous signer failure", "current original changed between keys"} {
		t.Run(kind, func(t *testing.T) {
			fixture := newRotationFixture(t)
			s := fixture.s
			id, currentModule := addArtifactBuilt(t, s, "candidate")
			if kind == "later-key VM failure" {
				command := append([]string(nil), s.cfg.Signing.Keys[1].SignCommand...)
				command[2] = "third"
				s.cfg.Signing.Keys = append(s.cfg.Signing.Keys, SigningKey{ID: "third", SignCommand: command})
				if err := s.store.Update(func(st *State) error { st.Hosts["gpu-test"].Status.EnrolledCerts["third"] = "enrolled"; return nil }); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "outer fleet check" {
				s.cfg.TestVM.Modes = nil
			}
			if kind == "previous signer failure" {
				script := vmScript(t, t.TempDir(), "fail-previous.sh", `printf ':%s:%s' "$2" "$3" >> "$1"
case "$1" in */previous/*) exit 1 ;; esac`)
				s.cfg.Signing.Keys[1].SignCommand[0] = script
			}
			if kind == "current original changed between keys" {
				t.Setenv("KPCTL_TEST_ROTATION_UNSIGNED", s.unsignedArtifactFile(testKernel, currentModule))
				script := vmScript(t, t.TempDir(), "change-source.sh", `printf ':%s:%s' "$2" "$3" >> "$1"
case "$1" in */previous/*) ;; *) printf changed > "$KPCTL_TEST_ROTATION_UNSIGNED" ;; esac`)
				s.cfg.Signing.Keys[1].SignCommand[0] = script
			}
			fixture.runner.onModule = func(invocation vmArtifactInvocation) error {
				if kind == "new-key VM failure" {
					if _, ok := copyWithBytes(invocation, rotationPayload("candidate", "new")); ok {
						return errors.New("new key VM rejected")
					}
				}
				if kind == "later-key VM failure" {
					if _, ok := copyWithBytes(invocation, rotationPayload("candidate", "third")); ok {
						return errors.New("later key VM rejected")
					}
				}
				if kind == "outer fleet check" {
					if _, ok := copyWithBytes(invocation, rotationPayload("candidate", "new")); ok {
						return s.store.Update(func(st *State) error {
							st.Hosts["new-sb-off"] = &model.Host{ID: "new-sb-off", Status: model.HostStatus{Kernel: testKernel, Firmware: "uefi", SecureBoot: "off", Lockdown: "none", SigEnforce: "off"}}
							return nil
						})
					}
				}
				return nil
			}
			if _, _, _, err := s.approveJob(id, "tester"); err == nil {
				t.Fatal("failed rotation released")
			}
			fixture.assertPreviousUnchanged(t)
			if _, err := os.Stat(s.signingArtifactFile(testKernel, fixture.module, "new")); !os.IsNotExist(err) {
				t.Fatal("failed rotation published previous variant", err)
			}
		})
	}
}

func TestSigningRotationRequiresPinnedUnmodifiedPreviousOriginal(t *testing.T) {
	for _, kind := range []string{"missing original", "corrupt original", "missing pin", "changed during VM"} {
		t.Run(kind, func(t *testing.T) {
			fixture := newRotationFixture(t)
			s := fixture.s
			path := s.unsignedArtifactFile(testKernel, fixture.module)
			switch kind {
			case "missing original":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			case "corrupt original":
				if err := os.WriteFile(path, []byte("corrupted"), 0o640); err != nil {
					t.Fatal(err)
				}
			case "missing pin":
				if err := s.store.Update(func(st *State) error { st.job(fixture.previous).UnsignedSHA256 = ""; return nil }); err != nil {
					t.Fatal(err)
				}
				s.store.View(func(st *State) { fixture.jobJSON, _ = json.Marshal(st.job(fixture.previous)) })
			}
			id, _ := addArtifactBuilt(t, s, "candidate")
			if kind == "changed during VM" {
				fixture.runner.onModule = func(invocation vmArtifactInvocation) error {
					if _, ok := copyWithBytes(invocation, rotationPayload("candidate", "new")); ok {
						return os.WriteFile(path, []byte("changed during VM"), 0o640)
					}
					return nil
				}
			}
			if _, _, _, err := s.approveJob(id, "tester"); err == nil {
				t.Fatal("unverified previous source allowed rotation")
			}
			fixture.assertPreviousUnchanged(t)
		})
	}
}

func TestSigningRotationPartialFilePublicationDoesNotExposeMetadata(t *testing.T) {
	fixture := newRotationFixture(t)
	s := fixture.s
	command := append([]string(nil), s.cfg.Signing.Keys[1].SignCommand...)
	command[2] = "third"
	s.cfg.Signing.Keys = append(s.cfg.Signing.Keys, SigningKey{ID: "third", SignCommand: command})
	if err := s.store.Update(func(st *State) error { st.Hosts["gpu-test"].Status.EnrolledCerts["third"] = "enrolled"; return nil }); err != nil {
		t.Fatal(err)
	}
	id, _ := addArtifactBuilt(t, s, "candidate")
	// 마지막 variant 경로를 디렉터리로 막되 현재 모듈의 같은 키 사본은 정상 게시할 수 있습니다.
	blocked := s.signingArtifactFile(testKernel, fixture.module, "third")
	if err := os.MkdirAll(blocked, 0o750); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := s.approveJob(id, "tester"); err == nil {
		t.Fatal("partial previous variant publication released")
	}
	fixture.assertPreviousUnchanged(t)
	request := httptest.NewRequest("GET", fmt.Sprintf("/artifacts/%s/%s.ko?key=new", testKernel, fixture.module), nil)
	request.Header.Set("Authorization", "Bearer "+testAdmin)
	response := httptest.NewRecorder()
	s.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("unreferenced variant escaped metadata gate: %d %s", response.Code, response.Body.String())
	}
}

func TestSigningRotationStateSaveFailureKeepsLiveJobsUnchanged(t *testing.T) {
	fixture := newRotationFixture(t)
	s := fixture.s
	id, module := addArtifactBuilt(t, s, "candidate")
	artifacts, active, rotations, err := s.prepareSigningArtifactsWithRotations(id, testKernel, module)
	if err != nil {
		t.Fatal(err)
	}
	if len(rotations) != 1 {
		t.Fatalf("missing staged rotation: %+v", rotations)
	}
	err = s.store.updateAtomic(func(st *State) error {
		commit, err := s.publishSigningRotationsLocked(st, id, rotations)
		if err != nil {
			return err
		}
		commit()
		job := st.job(id)
		job.Status, job.SigningArtifacts, job.ActiveSigningKey, job.SHA256 = model.JobReleased, artifacts, active, artifacts[active].SHA256
		return nil
	}, stateAtomicIO{createTemp: func(string, string) (*os.File, error) { return nil, errors.New("injected persistence failure") }, rename: os.Rename, syncDir: (*os.File).Sync})
	if err == nil {
		t.Fatal("injected persistence failure ignored")
	}
	fixture.assertPreviousUnchanged(t)
	s.store.View(func(st *State) {
		if st.job(id).Status != model.JobBuilt || len(st.job(id).SigningArtifacts) != 0 {
			t.Errorf("failed save exposed current release: %+v", st.job(id))
		}
	})
}

func TestSigningBuilderResultPinsUploadedBytesBeforeFirstApproval(t *testing.T) {
	s := newAutoServer(t, AutoRollout{})
	id := addBuilt(t, s, "manual")
	started := time.Now()
	var module string
	if err := s.store.Update(func(st *State) error {
		job := st.job(id)
		job.Status, job.Builder, job.StartedAt = model.JobRunning, "builder", started
		module = job.ModuleName
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	raw := []byte("uploaded unsigned module")
	postBuildResult(t, s, id, model.BuildResult{Success: true, Builder: "builder", JobStartedAt: &started, ModuleName: module, ModuleBase64: base64.StdEncoding.EncodeToString(raw)}, http.StatusOK)
	s.store.View(func(st *State) {
		if st.job(id).UnsignedSHA256 != signingBytesSHA256(raw) || st.job(id).Status != model.JobBuilt {
			t.Errorf("raw upload was not pinned: %+v", st.job(id))
		}
	})
	if err := os.WriteFile(s.artifactFile(testKernel, module), []byte("tampered before first approval"), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := s.approveJob(id, "tester"); err == nil {
		t.Fatal("first approval accepted bytes different from upload pin")
	}
	if _, err := os.Stat(s.unsignedArtifactFile(testKernel, module)); !os.IsNotExist(err) {
		t.Fatal("tampered raw became preserved original", err)
	}
}

func TestSigningRotationTestsFormerlyUnsignedPreviousPrivately(t *testing.T) {
	s := newAutoServer(t, AutoRollout{})
	runner := &vmArtifactRunner{}
	enableArtifactVM(t, s, runner, testvm.Modes{"sb_on", "bios"})
	s.cfg.TestVM.Modes = testvm.Modes{"bios"}
	signer := vmScript(t, t.TempDir(), "sign-prod.sh", `printf ':%s:%s' "$2" "$3" >> "$1"`)
	s.cfg.SignCommand = nil
	s.cfg.Signing = &SigningConfig{Mode: "when_required", Keys: []SigningKey{{ID: "prod", Active: true, SignCommand: []string{signer, "{module}", "prod", "{kernel}"}}}}
	if err := s.store.Update(func(st *State) error {
		host := st.Hosts["gpu-test"]
		host.Status.Firmware, host.Status.SecureBoot, host.Status.Lockdown, host.Status.SigEnforce = "bios", "off", "none", "off"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	previous, previousModule := addArtifactBuilt(t, s, "previous")
	if _, _, _, err := s.approveJob(previous, "tester"); err != nil {
		t.Fatal(err)
	}
	var oldJSON []byte
	s.store.View(func(st *State) {
		job := st.job(previous)
		oldJSON, _ = json.Marshal(job)
		if job.SigningArtifacts["prod"].Signed {
			t.Error("when_required signed an unrequired module")
		}
	})
	s.cfg.TestVM.Modes = testvm.Modes{"sb_on", "bios"}
	if err := s.store.Update(func(st *State) error {
		host := st.Hosts["gpu-test"]
		host.Status.Firmware, host.Status.SecureBoot, host.Status.Lockdown = "uefi", "on", "integrity"
		host.Status.EnrolledCerts = map[string]string{"prod": "enrolled"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	id, _ := addArtifactBuilt(t, s, "candidate")
	var privateTests atomic.Int32
	runner.onModule = func(invocation vmArtifactInvocation) error {
		if _, ok := copyWithBytes(invocation, rotationPayload("candidate", "prod")); !ok {
			return nil
		}
		if _, ok := copyWithBytes(invocation, rotationPayload("previous", "prod")); !ok {
			return errors.New("former unsigned previous was not privately signed")
		}
		privateTests.Add(1)
		data, err := os.ReadFile(s.signingArtifactFile(testKernel, previousModule, "prod"))
		if err != nil || string(data) != "previous" {
			return errors.New("private signing changed published unsigned previous")
		}
		return nil
	}
	if _, _, _, err := s.approveJob(id, "tester"); err != nil {
		t.Fatal(err)
	}
	if got := privateTests.Load(); got != 2 {
		t.Fatalf("private signed previous not tested in both modes: %d", got)
	}
	s.store.View(func(st *State) {
		data, _ := json.Marshal(st.job(previous))
		if string(data) != string(oldJSON) {
			t.Error("private test changed historical unsigned metadata")
		}
		if !st.job(id).SigningArtifacts["prod"].Signed {
			t.Error("new enforced version was not signed")
		}
		if result := s.rolloutEligibility(st.Hosts["gpu-test"], st.job(previous)); result.Status != "blocked_artifact" {
			t.Errorf("old unsigned rollback became eligible on enforced host: %+v", result)
		}
	})
	for _, path := range []string{s.artifactFile(testKernel, previousModule), s.signingArtifactFile(testKernel, previousModule, "prod")} {
		data, err := os.ReadFile(path)
		if err != nil || string(data) != "previous" {
			t.Errorf("historical unsigned bytes changed: %q (%v)", data, err)
		}
	}
}
