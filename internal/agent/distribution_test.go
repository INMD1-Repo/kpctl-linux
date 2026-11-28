package agent

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"kpctl/internal/client"
	"kpctl/internal/klpcheck/klptest"
	"kpctl/internal/model"
)

func TestIdentifyOfficialDistribution(t *testing.T) {
	for _, tc := range []struct{ id, version, codename, abi, pkg string }{
		{"debian", "12", "bookworm", "6.1.0-57-amd64", "6.1.192-3"},
		{"debian", "13", "trixie", "6.12.118+deb13-amd64", "6.12.118-1"},
		{"rocky", "9.9", "", "5.14.0-741.27.1.el9_9.x86_64", "5.14.0-741.27.1.el9_9"},
		{"rocky", "10.3", "", "6.12.0-264.21.1.el10_3.x86_64", "6.12.0-264.21.1.el10_3"},
	} {
		t.Run(tc.id+tc.version, func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
			distro := filepath.Join(dir, "os-release")
			writeTestFile(t, distro, "ID="+tc.id+"\nVERSION_ID=\""+tc.version+"\"\nVERSION_CODENAME="+tc.codename+"\n")
			path := filepath.Join(dir, "version")
			writeTestFile(t, path, "#1 SMP Debian "+tc.pkg+" (release)")
			bin, out := "rpm", "kernel-core x86_64 0 "+tc.pkg
			if tc.id == "debian" {
				bin, out = "dpkg-query", "ok.installed linux-image-"+tc.abi+" amd64 "+tc.pkg
			}
			check := ""
			if bin == "rpm" {
				check = "test \"$1\" = -q && test \"$2\" = 'kernel-core-" + tc.abi + "' || exit 1\n"
			}
			if err := os.WriteFile(filepath.Join(dir, bin), []byte("#!/bin/sh\n"+check+"echo '"+out+"'\n"), 0700); err != nil {
				t.Fatal(err)
			}
			notes := make([]byte, 36)
			binary.LittleEndian.PutUint32(notes, 4)
			binary.LittleEndian.PutUint32(notes[4:], 20)
			binary.LittleEndian.PutUint32(notes[8:], 3)
			copy(notes[12:], "GNU\x00")
			for i := 16; i < len(notes); i++ {
				notes[i] = 0xcc
			}
			note := filepath.Join(dir, "notes")
			if err := os.WriteFile(note, notes, 0600); err != nil {
				t.Fatal(err)
			}
			k, err := IdentifyKernel(tc.abi, note, distro, path)
			if err != nil || k.BuildID != strings.Repeat("cc", 20) || k.Track() == "" {
				t.Fatalf("%+v %v", k, err)
			}
			a, fixture := newTestAgent(t)
			a.distribution = k
			a.st.Kernel = k.Track()
			writeTestFile(t, filepath.Join(fixture, "proc/osrelease"), tc.abi)
			name := model.NativeModuleName(k.Track(), 1)
			data := klptest.Module(klptest.Options{Modinfo: "name=" + name + "\x00livepatch=Y\x00vermagic=" + tc.abi + " SMP modversions\x00"})
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(data) }))
			defer ts.Close()
			a.c, err = client.New(ts.URL, "fixture", "")
			if err != nil {
				t.Fatal(err)
			}
			d := model.DesiredPatch{Track: k.Track(), Version: 1, ModuleName: name, SHA256: fmt.Sprintf("%x", sha256.Sum256(data)), URL: "/artifacts/" + k.Track() + "/" + name + ".ko"}
			if tc.version == "13" {
				a.st.Version = 2
				setTestPatch(t, a, "kpctl_existing", "1", "0")
				if a.apply(d) || a.apply(model.DesiredPatch{}) || !a.moduleLoaded("kpctl_existing") || a.st.Version != 2 {
					t.Fatal("blocked trixie changed protection")
				}
				return
			}
			if !a.apply(d) || a.lastErr != "" || !a.moduleLoaded(name) {
				t.Fatalf("native application: %s", a.lastErr)
			}
			if _, err := os.Stat(filepath.Join(a.cfg.KpatchInstallDir, tc.abi, name+".ko")); !os.IsNotExist(err) {
				t.Fatal("ambiguous boot installation")
			}
			if _, err := os.Stat(a.installedModulePath(name)); err != nil {
				t.Fatal(err)
			}
			if a.apply(model.DesiredPatch{Track: "wrong", Version: 1}) {
				t.Fatal("mismatched track applied")
			}
			if tc.id == "debian" {
				writeTestFile(t, path, "older running package")
				if _, err := IdentifyKernel(tc.abi, note, distro, path); err == nil {
					t.Fatal("on-disk upgrade confused with running release")
				}
			}
			if _, err := RunningBuildID(notes[:len(notes)-1]); err == nil {
				t.Fatal("truncated note accepted")
			}
		})
	}
}

func TestIdentityFailureReportsWithoutChangingActiveProtection(t *testing.T) {
	a, _ := newTestAgent(t)
	active := previousVersion(t, a)
	a.st.HostToken = "test"
	if err := a.saveState(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(a.cfg.DistroReleasePath); err != nil {
		t.Fatal(err)
	}
	restarted, err := New(a.cfg)
	if err != nil {
		t.Fatal(err)
	}
	reports := make(chan model.HostStatus, 3)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req model.ReportRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
		}
		reports <- req.Status
		// An older controller may reply with an empty (v0) desired state.
		_ = json.NewEncoder(w).Encode(model.ReportResponse{PrepareKernel: true, Desired: model.DesiredPatch{Blocked: req.Status.IdentityError == ""}})
	}))
	defer srv.Close()
	restarted.c, err = client.New(srv.URL, "test", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.RunOnce(); err != nil {
		t.Fatal(err)
	}
	first := <-reports
	if first.TrackKey() != "" || first.IdentityError == "" || first.Version != 1 || len(first.Loaded) == 0 || !restarted.patchEnabled(active) || restarted.st.ModuleName != active {
		t.Fatal(first)
	}
	writeTestFile(t, a.cfg.DistroReleasePath, "ID=ubuntu\n")
	if err := restarted.RunOnce(); err != nil {
		t.Fatal(err)
	}
	second := <-reports
	if second.IdentityError != "" || second.TrackKey() != testKernel || !restarted.patchEnabled(active) {
		t.Fatal(second)
	}
}

func TestLegacyKernelIdentityBoundaries(t *testing.T) {
	for _, tc := range []struct {
		abi, signature string
		blocked        bool
	}{
		{"5.10.0-custom", "", true},
		{"6.8.0-85-generic", "", false},
		{"6.8.0-85-generic", "Ubuntu 6.8.0-85.85~22.04.1-generic 6.8.12", false},
		{"6.11.0-42-generic", "Ubuntu 6.11.0-42.42~24.04.1-generic 6.11.12", false},
	} {
		status := model.HostStatus{Kernel: tc.abi, KernelSignature: tc.signature}
		if (status.ManagementBlock() != "") != tc.blocked {
			t.Errorf("%s: %s", tc.abi, status.ManagementBlock())
		}
	}
}
