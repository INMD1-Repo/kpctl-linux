// 이 파일: controller 패키지의 TestVendorRangeBoundaries, TestCoverageRequiresRealModuleAndDoesNotHideMissingCVEs 회귀 시험.
package controller

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kpctl/internal/model"
)

func TestVendorRangeBoundaries(t *testing.T) {
	if _, err := exec.LookPath("dpkg"); err != nil {
		t.Skip("dpkg required for Ubuntu version semantics")
	}
	for _, tc := range []struct {
		name, base, want string
		events           []map[string]string
	}{
		{"vulnerable", "6.8.0-136.136", "affected", []map[string]string{{"introduced": "0"}, {"fixed": "6.8.0-139.139"}}},
		{"fixed is exclusive", "6.8.0-139.139", "base_fixed", []map[string]string{{"introduced": "0"}, {"fixed": "6.8.0-139.139"}}},
		{"Debian tilde is older", "6.8.0-139.139~test1", "affected", []map[string]string{{"introduced": "0"}, {"fixed": "6.8.0-139.139"}}},
		{"last affected inclusive", "7.0.0-28.28", "affected", []map[string]string{{"introduced": "0"}, {"last_affected": "7.0.0-28.28"}}},
		{"limit is not a fix", "7.0.0-28.28", "outside_range", []map[string]string{{"introduced": "0"}, {"limit": "7.0.0-28.28"}}},
		{"not yet introduced", "7.0.0-28.28", "outside_range", []map[string]string{{"introduced": "7.0.0-29.29"}}},
		{"reintroduced after fix", "7.0.0-28.28", "affected", []map[string]string{{"introduced": "0"}, {"fixed": "7.0.0-20.20"}, {"introduced": "7.0.0-25.25"}}},
		{"unknown events", "7.0.0-28.28", "unknown", []map[string]string{{"introduced": "0"}, {"resolved": "7.0.0-20.20"}}},
		{"reversed interval", "7.0.0-28.28", "unknown", []map[string]string{{"introduced": "7.0.0-30.30"}, {"fixed": "7.0.0-20.20"}}},
		{"missing introduction", "7.0.0-28.28", "unknown", []map[string]string{{"fixed": "7.0.0-20.20"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := assessBase(tc.base, vendorRelease{Ranges: []vendorRange{{Type: "ECOSYSTEM", Events: tc.events}}}, debCompare)
			if got.Status != tc.want {
				t.Fatalf("%+v want %s", got, tc.want)
			}
		})
	}
	if got := assessBase("7.0.0-28.28", vendorRelease{}, debCompare); got.Status != "unknown" {
		t.Fatal(got)
	}
}

func coverageFixture(t *testing.T, s *Server) {
	t.Helper()
	f := vendorInventory{Schema: 1, Source: vendorFeedURL, SHA256: strings.Repeat("a", 64), FetchedAt: time.Now(), Complete: true, SourceCount: 1000}
	for i := 0; i < 101; i++ {
		f.Records = append(f.Records, vendorCVE{ID: fmt.Sprintf("CVE-2026-%04d", 1000+i), Priority: "high", Releases: map[string]vendorRelease{}})
	}
	f.Records[0].Releases["noble"] = vendorRelease{Versions: []string{"6.8.0-85.85"}}
	f.Records[1].Releases["noble"] = vendorRelease{Versions: []string{"6.8.0-85.85"}}
	f.Records[2].Releases["noble"] = vendorRelease{Versions: []string{"6.8.0-85.85"}}
	for i := 0; i < 2; i++ {
		release := f.Records[i].Releases["noble"]
		release.Ranges = []vendorRange{{Type: "ECOSYSTEM", Events: []map[string]string{{"introduced": "0"}, {"fixed": "6.8.0-86.86"}}}}
		f.Records[i].Releases["noble"] = release
	}
	f.KernelCount = len(f.Records)
	dir := filepath.Join(s.cfg.DataDir, "coverage")
	if err := os.MkdirAll(dir, 0750); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(f)
	if err := os.WriteFile(filepath.Join(dir, "vendor.json"), data, 0640); err != nil {
		t.Fatal(err)
	}
}

func TestCoverageRequiresRealModuleAndDoesNotHideMissingCVEs(t *testing.T) {
	s := newAutoServer(t, AutoRollout{})
	addHost(t, s, "canary", 1)
	callAPI(t, s, "GET", "/api/coverage?host=missing", "", http.StatusNotFound)
	_ = s.store.Update(func(st *State) error {
		h := st.Hosts["canary"]
		h.Status.KernelSignature = "Ubuntu 6.8.0-85.85-generic 6.8.12"
		h.Status.Version = 2
		h.Status.Loaded = []model.LoadedPatch{{Name: "module", Enabled: true}}
		st.Patches = append(st.Patches, &model.Patch{ID: "p1", Kernel: testKernel, CVEs: []string{"CVE-2026-1000"}, State: model.PatchActive})
		st.Jobs = append(st.Jobs, &model.Job{ID: 1, Kernel: testKernel, Version: 2, Status: model.JobReleased, ModuleName: "module", PatchIDs: []string{"p1"}})
		return nil
	})
	callAPI(t, s, "GET", "/api/coverage?host=canary", "", http.StatusServiceUnavailable)
	coverageFixture(t, s)
	for _, tc := range []struct {
		name              string
		transition, stale bool
		want              string
	}{{"confirmed", false, false, "included"}, {"transition", true, false, "pending"}, {"stale", false, true, "pending"}} {
		t.Run(tc.name, func(t *testing.T) {
			_ = s.store.Update(func(st *State) error {
				h := st.Hosts["canary"]
				h.Status.Loaded[0].Transition = tc.transition
				h.LastSeen = time.Now()
				if tc.stale {
					h.LastSeen = h.LastSeen.Add(-time.Hour)
				}
				return nil
			})
			body := callAPI(t, s, "GET", "/api/coverage?host=canary&state=all", "", http.StatusOK)
			var got struct {
				Counts map[string]int `json:"counts"`
			}
			if err := json.Unmarshal([]byte(body), &got); err != nil {
				t.Fatal(err)
			}
			if got.Counts[tc.want] != 1 || got.Counts["not_collected"] != 1 || got.Counts["unknown"] != 98 || got.Counts["vendor_fix_unknown"] != 1 {
				t.Fatalf("%v", got.Counts)
			}
		})
	}
	_ = s.store.Update(func(st *State) error {
		h := st.Hosts["canary"]
		h.LastSeen = time.Now()
		h.Status.Loaded[0].Transition = false
		st.Unpatchable = append(st.Unpatchable, &model.Unpatchable{Kernel: testKernel, CVEs: []string{"CVE-2026-1000"}, Reason: "another required commit failed"})
		return nil
	})
	body := callAPI(t, s, "GET", "/api/coverage?host=canary&state=partial", "", http.StatusOK)
	if !strings.Contains(body, `"partial":1`) || !strings.Contains(body, "another required commit failed") || !strings.Contains(body, `"included_patch_ids":["p1"]`) {
		t.Fatal(body)
	}
	_ = s.store.Update(func(st *State) error {
		st.Hosts["canary"].Status.KernelSignature = "Ubuntu 6.8.0-86.86-generic 6.8.12"
		return nil
	})
	callAPI(t, s, "GET", "/api/coverage?host=canary", "", http.StatusBadRequest)
}
