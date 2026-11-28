package controller

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"kpctl/internal/klpcheck"
	"kpctl/internal/klpcheck/klptest"
	"kpctl/internal/model"
)

func installFixedReceipt(t *testing.T, dir, track string, fixed *model.FixedRelease) {
	t.Helper()
	path := filepath.Join(dir, track)
	if err := os.MkdirAll(path, 0700); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(fixed)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(path, fixed.Revision+".json"), data, 0600); err != nil {
		t.Fatal(err)
	}
}

func installCandidateReceipt(t *testing.T, dir string, base model.DistributionProof, fixed model.FixedRelease, content []byte, parent string) {
	t.Helper()
	paths, err := candidatePaths(content)
	if err != nil {
		t.Fatal(err)
	}
	sum := fmt.Sprintf("%x", sha256.Sum256(content))
	pin := candidatePin{Base: base, Fixed: fixed, Paths: paths, SHA256: sum, CandidateID: fixed.Revision + "/" + sum, Parent: parent}
	data, _ := json.Marshal(pin)
	folder := filepath.Join(dir, base.Track, fixed.Revision)
	if err := os.MkdirAll(folder, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(folder, sum+".json"), data, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestDistributionReleaseFlow(t *testing.T) {
	key := testSigningKey(t, "fleet", true)
	for _, tc := range []struct{ d, r, abi, v, fpr string }{
		{"debian", "12", "6.1.0-57-amd64", "6.1.192-3", "05AB90340C0C5E797F44A8C8254CF3B5AEC0A8F0"},
		{"debian", "13", "6.12.118+deb13-amd64", "6.12.118-1", "5E04A1E3223A19A20706E20F9904613D4CCE68C6"},
		{"rocky", "9", "5.14.0-741.27.1.el9_9.x86_64", "5.14.0-741.27.1.el9_9", "21CB256AE16FC54C6E652949702D426D350D275D"},
		{"rocky", "10", "6.12.0-264.21.1.el10_3.x86_64", "6.12.0-264.21.1.el10_3", "FC226859C0860BF0DDB95B085B106C736FEDFC85"},
	} {
		t.Run(tc.d+tc.r, func(t *testing.T) {
			s := newAutoServer(t, AutoRollout{})
			s.cfg.Signing = &SigningConfig{Mode: "always", Keys: []SigningKey{key}}
			identity := model.DistributionKernel{Distro: tc.d, Release: tc.r, Arch: "amd64", ABI: tc.abi, Version: tc.v, BuildID: strings.Repeat("1", 40)}
			track := identity.Track()
			host := signingHost(map[string]string{"fleet": "enrolled"})
			host.TokenHash = hashToken("native-token")
			host.Status.Kernel = tc.abi
			host.Status.Distribution = &identity
			if err := s.store.Update(func(st *State) error { st.Hosts[host.ID] = host; return nil }); err != nil {
				t.Fatal(err)
			}
			post := func(path string, v any, status int) string {
				b, err := json.Marshal(v)
				if err != nil {
					t.Fatal(err)
				}
				return callBuilderAPI(t, s, "POST", path, string(b), status)
			}
			post("/api/builder/kernels/"+track+"/upstream", model.UpstreamReport{LatestTag: "Ubuntu-6.8.0-90.90"}, 400)
			fixed := &model.FixedRelease{ABI: tc.abi, Version: tc.v + "+deb" + tc.r + "u1", Revision: strings.Repeat("a", 40), SourceSHA256: strings.Repeat("2", 64), PackageSHA256: strings.Repeat("3", 64), Signer: tc.fpr}
			if tc.d == "rocky" {
				fixed.Version = strings.Replace(tc.v, ".1.el", ".2.el", 1)
				fixed.ABI = fixed.Version + ".x86_64"
			}
			if tc.r == "13" {
				post("/api/builder/kernels/"+track+"/discovered", model.DiscoveredRequest{}, 409)
				if got := post("/api/builder/next", model.NextJobRequest{NativeTrack: track, Builder: "trixie"}, 409); !strings.Contains(got, "trixie-security") {
					t.Fatal("blocked builder did not receive remediation", got)
				}
				req := httptest.NewRequest("GET", "/api/status", nil)
				req.Header.Set("Authorization", "Bearer "+testAdmin)
				rec := httptest.NewRecorder()
				s.Handler().ServeHTTP(rec, req)
				if rec.Code != 200 || !strings.Contains(rec.Body.String(), "blocked_unsupported") || !strings.Contains(rec.Body.String(), "trixie-security") {
					t.Fatal("missing inventory-only status", rec.Code)
				}
				for _, target := range []string{track, tc.abi} {
					req = httptest.NewRequest("GET", "/artifacts/"+target+"/test.ko", nil)
					req.Header.Set("Authorization", "Bearer "+testAdmin)
					rec = httptest.NewRecorder()
					s.Handler().ServeHTTP(rec, req)
					if rec.Code != 409 {
						t.Fatal("stock trixie artifact endpoint not blocked", target, rec.Code)
					}
				}

				s.store.View(func(st *State) {
					if !s.desired(st, host).Blocked || s.rolloutEligibility(host, nil).Status != "blocked_unsupported" {
						t.Fatal("trixie management enabled")
					}
				})
				return
			}
			post("/api/builder/kernels/"+track+"/discovered", model.DiscoveredRequest{ExpectedActive: []string{}, Patches: []model.DiscoveredPatch{{FixedRelease: fixed, Commit: strings.Repeat("a", 40), Title: "fixture", Content: "diff --git a/x.c b/x.c\n--- a/x.c\n+++ b/x.c\n@@ -1 +1 @@\n-x\n+y\n"}}}, 200)
			post("/api/builder/next", model.NextJobRequest{Builder: "legacy"}, 204)
			wrong := identity
			wrong.BuildID = strings.Repeat("2", 40)
			post("/api/builder/next", model.NextJobRequest{Builder: "other", NativeTrack: wrong.Track()}, 204)
			var task model.BuildTask
			if err := json.Unmarshal([]byte(post("/api/builder/next", model.NextJobRequest{Builder: "native", NativeTrack: track}, 200)), &task); err != nil {
				t.Fatal(err)
			}
			if task.Job.Kernel != track || len(task.Patches) != 1 || task.Patches[0].Validate() != nil {
				t.Fatal(task)
			}
			name := model.NativeModuleName(track, 1)
			proof := model.DistributionProof{Track: track, SourceSHA256: strings.Repeat("a", 64), PackageSHA256: strings.Repeat("b", 64), Revision: strings.Repeat("c", 40), Signer: tc.fpr}
			raw := klptest.Module(klptest.Options{Modinfo: "name=" + name + "\x00livepatch=Y\x00vermagic=" + tc.abi + " SMP modversions\x00"})
			post("/api/builder/jobs/1/result", model.BuildResult{Builder: "native", JobStartedAt: &task.Job.StartedAt, Success: true, ModuleName: name, ModuleBase64: base64.StdEncoding.EncodeToString(raw), DistributionProof: &proof}, 200)
			if _, _, _, err := s.approveJob(1, "operator"); err == nil {
				t.Fatal("approved without independent package receipt")
			}
			dir := filepath.Join(s.cfg.DataDir, "distribution-proofs")
			if err := os.MkdirAll(dir, 0700); err != nil {
				t.Fatal(err)
			}
			data, _ := json.Marshal(proof)
			if err := os.WriteFile(filepath.Join(dir, track+".json"), data, 0600); err != nil {
				t.Fatal(err)
			}
			if _, _, _, err := s.approveJob(1, "operator"); err == nil {
				t.Fatal("approved without independent fixed-release receipt")
			}
			installFixedReceipt(t, dir, track, fixed)
			if _, _, _, err := s.approveJob(1, "operator"); err == nil {
				t.Fatal("approved with release pins alone")
			}
			content, err := os.ReadFile(s.patchFile(task.Job.PatchIDs[0]))
			if err != nil {
				t.Fatal(err)
			}
			installCandidateReceipt(t, dir, proof, *fixed, content, "")
			if err := os.WriteFile(s.patchFile(task.Job.PatchIDs[0]), append(append([]byte{}, content...), '\n'), 0600); err != nil {
				t.Fatal(err)
			}
			if _, _, _, err := s.approveJob(1, "operator"); err == nil {
				t.Fatal("approved corrupted stored patch")
			}
			if err := os.WriteFile(s.patchFile(task.Job.PatchIDs[0]), content, 0600); err != nil {
				t.Fatal(err)
			}
			if _, _, _, err := s.approveJob(1, "operator"); err != nil {
				t.Fatal(err)
			}
			url := "/artifacts/" + track + "/" + name + ".ko"
			get := func(want int) {
				req := httptest.NewRequest("GET", url, nil)
				req.Header.Set("Authorization", "Bearer native-token")
				rec := httptest.NewRecorder()
				s.Handler().ServeHTTP(rec, req)
				if rec.Code != want {
					t.Fatalf("artifact http %d, want %d", rec.Code, want)
				}
			}
			// A new signing key also needs the independently reviewed historical bytes.
			if err := os.WriteFile(s.patchFile(task.Job.PatchIDs[0]), []byte("damaged"), 0600); err != nil {
				t.Fatal(err)
			}
			if _, _, err := s.previousSigningCandidate(track, SigningKey{ID: "rotation"}, t.TempDir(), true, nil); err == nil || !strings.Contains(err.Error(), "SHA256") {
				t.Fatalf("rotation did not check historical patch: %v", err)
			}
			if err := os.WriteFile(s.patchFile(task.Job.PatchIDs[0]), content, 0600); err != nil {
				t.Fatal(err)
			}
			get(200)
			if err := s.store.Update(func(st *State) error { st.Hosts[host.ID].Status.Distribution = &wrong; return nil }); err != nil {
				t.Fatal(err)
			}
			get(404)
			if err := s.store.Update(func(st *State) error { st.Hosts[host.ID].Status.Distribution = &identity; return nil }); err != nil {
				t.Fatal(err)
			}
			s.store.View(func(st *State) {
				want := s.desired(st, host)
				if want.Track != track || want.Version != 1 || want.ModuleName != name || want.Blocked || !strings.Contains(want.URL, track) {
					t.Fatal(want)
				}
				if st.Patches[0].Source != tc.d || !st.job(1).SigningArtifacts["fleet"].Signed {
					t.Fatal("lost source or signature")
				}
				other := *host
				other.Status.Distribution = &wrong
				if s.desired(st, &other).Version != 0 {
					t.Fatal("cross-build rollout")
				}
				other.Status.Distribution = nil
				if !s.desired(st, &other).Blocked {
					t.Fatal("legacy uname-only native recipient")
				}
				other.Status = host.Status
				other.Status.EnrolledCerts = map[string]string{"fleet": "not_enrolled"}
				if !s.desired(st, &other).Blocked {
					t.Fatal("missing MOK")
				}
			})
		})
	}
}

// This opt-in test signs a copy of a previously verified module with a fresh
// local certificate. It never loads the module or contacts a running service.
func TestDistributionCompiledArtifactCMS(t *testing.T) {
	module, track := os.Getenv("KPCTL_TEST_NATIVE_MODULE"), os.Getenv("KPCTL_TEST_NATIVE_TRACK")
	if module == "" && track == "" {
		t.Skip("requires compiled native module and track")
	}
	k, ok := model.DistributionTrack(track)
	if !ok {
		t.Fatal("invalid track")
	}
	if err := klpcheck.CheckTarget(module, k.ABI, model.NativeModuleName(track, 1)); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(module)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "module.ko")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	key := testSigningKey(t, "native-smoke", true)
	key.SignCommand[0] = "/usr/bin/kmodsign"
	cert, err := os.ReadFile(key.Cert)
	if err != nil {
		t.Fatal(err)
	}
	sum, err := signModule(key, track, path, signingBytesSHA256(raw), cert)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("verified CMS %s sha256 %s", k.ABI, sum)
}

// Exercise the real Python HTTPS client with an already compiled release delta.
// The native toolchain run supplies one module and its exact patch as a pair.
func TestDistributionVerifiedReleaseTransport(t *testing.T) {
	bundle := os.Getenv("KPCTL_TEST_NATIVE_RELEASE")
	if bundle == "" {
		t.Skip("requires an archived pair of authenticated release inputs")
	}
	var sample struct {
		Base               model.DistributionProof
		Fixed              model.FixedRelease
		Module, Patch, Pin string
	}
	b, err := os.ReadFile(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(b, &sample); err != nil {
		t.Fatal(err)
	}
	k, ok := model.DistributionTrack(sample.Base.Track)
	if !ok || !sample.Base.Valid(k.Track()) || !sample.Fixed.ValidFor(k, sample.Fixed.Revision) {
		t.Fatal("invalid package receipts")
	}
	s := newAutoServer(t, AutoRollout{})
	key := testSigningKey(t, "canary", true)
	key.SignCommand[0] = "/usr/bin/kmodsign"
	s.cfg.Signing = &SigningConfig{Mode: "always", Keys: []SigningKey{key}}
	host := signingHost(map[string]string{"canary": "enrolled"})
	host.TokenHash = hashToken("host-test-token")
	host.Status.Kernel = k.ABI
	host.Status.Distribution = &k
	if err := s.store.Update(func(st *State) error { st.Hosts[host.ID] = host; return nil }); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(s.cfg.DataDir, "distribution-proofs")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	b, _ = json.Marshal(sample.Base)
	if err := os.WriteFile(filepath.Join(dir, k.Track()+".json"), b, 0600); err != nil {
		t.Fatal(err)
	}
	installFixedReceipt(t, dir, k.Track(), &sample.Fixed)
	patchBody, err := os.ReadFile(sample.Patch)
	if err != nil {
		t.Fatal(err)
	}
	pinBody, err := os.ReadFile(sample.Pin)
	if err != nil {
		t.Fatal(err)
	}
	sum := fmt.Sprintf("%x", sha256.Sum256(patchBody))
	pinDir := filepath.Join(dir, k.Track(), sample.Fixed.Revision)
	if err := os.MkdirAll(pinDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pinDir, sum+".json"), pinBody, 0600); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewTLSServer(s.Handler())
	defer srv.Close()
	work := t.TempDir()
	if err := os.WriteFile(filepath.Join(work, "ca"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(work, "token"), []byte("builder-token-0123456789"), 0600); err != nil {
		t.Fatal(err)
	}
	const worker = `import importlib.util,json,sys
from pathlib import Path
from unittest.mock import patch
directory, url, sample = Path(sys.argv[1]),sys.argv[2],json.loads(Path(sys.argv[3]).read_text())
deploy=Path("../../deploy").resolve()
sys.path.insert(0,str(deploy))
spec=importlib.util.spec_from_file_location("driver",deploy/"kpctl-native-builder.py")
worker=importlib.util.module_from_spec(spec)
spec.loader.exec_module(worker)
client=worker.Controller(dict(controller_url=url,token_file=directory/"token",ca_file=directory/"ca"))
base, fixed = sample["Base"],sample["Fixed"]
track=base["track"]
delta=Path(sample["Patch"]).read_text()
artifact=Path(sample["Module"])
out=client.request("/api/builder/kernels/"+track+"/discovered",dict(expected_active=[],patches=[dict(commit=fixed["revision"],fixed_release=fixed,content=delta,title="Verified package delta")]))
assert out["added_patches"]==1
def existing_module(plan,inputs,version,patches,work):
    assert patches==[delta.encode()] and version==1
    return artifact.stem,artifact
with patch.object(worker,"compile_module",side_effect=existing_module):
    worker.work_once(client,dict(distro=track.split("__")[1],release=track.split("__")[2]),{"proof":base},"native",directory)
`
	cmd := exec.Command("python3", "-B", "-c", worker, work, srv.URL, bundle)
	// A native build environment can instead run both unmodified collect and
	// work commands against this ephemeral TLS controller and its test CA.
	if runner := os.Getenv("KPCTL_TEST_NATIVE_RUNNER"); runner != "" {
		cmd = exec.Command(runner, work, srv.URL, bundle)
	}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("worker %v: %s", err, out)
	}
	if _, _, _, err := s.approveJob(1, "fixture"); err != nil {
		t.Fatal(err)
	}
	var want model.DesiredPatch
	s.store.View(func(st *State) { want = s.desired(st, host) })
	if want.Blocked || want.Version != 1 {
		t.Fatal(want)
	}
	req := httptest.NewRequest("GET", want.URL, nil)
	req.Header.Set("Authorization", "Bearer host-test-token")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != 200 || signingBytesSHA256(rec.Body.Bytes()) != want.SHA256 {
		t.Fatalf("download HTTP %d", rec.Code)
	}
	t.Logf("approved and downloaded signed module for %s, sha256 %s", k.ABI, want.SHA256)
}

func TestIncrementalCandidateConcurrencyAndIndependentPaths(t *testing.T) {
	s := newAutoServer(t, AutoRollout{})
	k := model.DistributionKernel{Distro: "debian", Release: "12", Arch: "amd64", ABI: "6.1.0-55-amd64", Version: "6.1.192-1", BuildID: strings.Repeat("1", 40)}
	track := k.Track()
	submit := func(file, from, to, rev, parent string, active []string, want int) string {
		t.Helper()
		patch := fmt.Sprintf("diff --git a/%s b/%s\n--- a/%s\n+++ b/%s\n@@ -1 +1 @@\n-%s\n+%s\n", file, file, file, file, from, to)
		fixed := model.FixedRelease{ABI: k.ABI, Version: "6.1.192-" + to, Revision: strings.Repeat(rev, 40), SourceSHA256: strings.Repeat("a", 64), PackageSHA256: strings.Repeat("b", 64), Signer: "05AB90340C0C5E797F44A8C8254CF3B5AEC0A8F0"}
		req := model.DiscoveredRequest{ExpectedActive: active, Patches: []model.DiscoveredPatch{{FixedRelease: &fixed, Commit: fixed.Revision, Content: patch, ParentCandidate: parent}}}
		b, _ := json.Marshal(req)
		callBuilderAPI(t, s, "POST", "/api/builder/kernels/"+track+"/discovered", string(b), want)
		return fmt.Sprintf("%s/%x", fixed.Revision, sha256.Sum256([]byte(patch)))
	}
	first := submit("fs/x.c", "1", "2", "a", "", []string{}, 200)
	side := submit("net/y.c", "1", "2", "a", "", []string{first}, 200)
	if err := s.store.Update(func(st *State) error {
		j := st.job(2)
		j.Status = model.JobReleased
		st.track(track).RingVersions[1] = j.Version
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	submit("fs/x.c", "2", "3", "b", first, []string{first}, 409)
	submit("fs/x.c", "1", "3", "b", "", []string{first, side}, 409)
	second := submit("fs/x.c", "2", "3", "b", first, []string{first, side}, 200)
	submit("fs/x.c", "2", "3", "b", first, []string{first, side}, 200)
	if err := s.store.Update(func(st *State) error {
		j := st.job(3)
		base := model.DistributionProof{Track: track, Revision: strings.Repeat("e", 40), SourceSHA256: strings.Repeat("0", 64), PackageSHA256: strings.Repeat("1", 64), Signer: st.Patches[0].FixedRelease.Signer}
		j.DistributionProof = &base
		j.ModuleName = model.NativeModuleName(track, j.Version)
		dir := filepath.Join(s.cfg.DataDir, "distribution-proofs")
		for _, p := range st.Patches {
			body, err := os.ReadFile(s.patchFile(p.ID))
			if err != nil {
				return err
			}
			installCandidateReceipt(t, dir, base, *p.FixedRelease, body, p.ParentCandidate)
			installFixedReceipt(t, dir, track, p.FixedRelease)
		}
		data, _ := json.Marshal(base)
		if err := os.WriteFile(filepath.Join(dir, track+".json"), data, 0600); err != nil {
			return err
		}
		if err := s.checkDistributionProof(st, j); err != nil {
			return err
		}
		incomplete := *j
		incomplete.PatchIDs = j.PatchIDs[1:]
		if s.checkDistributionProof(st, &incomplete) == nil {
			t.Fatal("approved missing predecessor")
		}
		j.Status = model.JobFailed
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	s.store.View(func(st *State) {
		if len(st.Patches) != 3 || st.job(3).PatchIDs[2] != st.Patches[2].ID || st.Patches[2].CandidateID != second || len(st.job(3).PatchIDs) != 3 || len(st.job(2).PatchIDs) != 2 || st.track(track).RingVersions[1] != 2 || st.job(2).Status != model.JobReleased {
			t.Fatal("lost or duplicated released candidate")
		}
	})
}
