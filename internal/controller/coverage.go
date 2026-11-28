// 이 파일: controller 패키지의 debCompare, assessBase, coverageBase 구현·자료형.
package controller

// Coverage is reconciled against an independent, complete vendor inventory.
// A CVE name in a loaded module is evidence of inclusion, not proof that every
// fix needed for that CVE is present or that a configuration is exploitable.
import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"kpctl/internal/model"
)

const vendorFeedURL = "https://security-metadata.canonical.com/osv/osv-all.tar.xz"

type vendorRange struct {
	Type   string              `json:"type"`
	Events []map[string]string `json:"events"`
}
type vendorRelease struct {
	Ranges   []vendorRange `json:"ranges"`
	Versions []string      `json:"versions"`
}
type vendorCVE struct {
	ID       string                   `json:"id"`
	Priority string                   `json:"priority"`
	Releases map[string]vendorRelease `json:"releases"`
}
type vendorInventory struct {
	Schema      int         `json:"schema_version"`
	Source      string      `json:"source_url"`
	License     string      `json:"license"`
	SHA256      string      `json:"snapshot_sha256"`
	FetchedAt   time.Time   `json:"fetched_at"`
	Complete    bool        `json:"complete"`
	SourceCount int         `json:"source_cve_count"`
	KernelCount int         `json:"kernel_cve_count"`
	Records     []vendorCVE `json:"records"`
}
type baseFinding struct{ Status, Fixed string }
type coverageCache struct {
	mtime time.Time
	size  int64
	feed  vendorInventory
	bases map[string]map[string]baseFinding
}

var debVersion = regexp.MustCompile(`^[0-9][0-9A-Za-z.+:~\-]*$`)
var cveID = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)
var sha256Hex = regexp.MustCompile(`^[a-f0-9]{64}$`)

// coveragePageSize 는 CVE 현황 표 한 페이지의 행 수입니다. 웹 화면(Coverage.jsx)의 PAGE_SIZE 와 맞춥니다.
const coveragePageSize = 15

// Ask dpkg rather than approximating Ubuntu's epoch/revision/~ ordering.
func debCompare(a, b string) (int, error) {
	if !debVersion.MatchString(a) || !debVersion.MatchString(b) {
		return 0, fmt.Errorf("invalid Debian version")
	}
	for i, op := range []string{"lt", "eq"} {
		err := exec.Command("dpkg", "--compare-versions", a, op, b).Run()
		if err == nil {
			return i - 1, nil
		}
		if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 1 {
			return 0, fmt.Errorf("dpkg version comparison failed: %w", err)
		}
	}
	return 1, nil
}

func assessBase(base string, release vendorRelease, compare func(string, string) (int, error)) baseFinding {
	for _, v := range release.Versions {
		if v == base {
			return baseFinding{Status: "affected"}
		}
	}
	if len(release.Ranges) == 0 {
		return baseFinding{Status: "unknown"}
	}
	affected, fixedBefore := false, ""
	for _, r := range release.Ranges {
		if r.Type != "ECOSYSTEM" || len(r.Events) == 0 {
			return baseFinding{Status: "unknown"}
		}
		open, inside := false, false
		lower, previous := "", ""
		for _, event := range r.Events {
			if len(event) != 1 {
				return baseFinding{Status: "unknown"}
			}
			for kind, version := range event {
				if kind == "introduced" {
					if open {
						return baseFinding{Status: "unknown"}
					}
					open = true
					if previous != "" {
						if version == "0" {
							return baseFinding{Status: "unknown"}
						}
						c, err := compare(previous, version)
						if err != nil || c > 0 {
							return baseFinding{Status: "unknown"}
						}
					}
					lower = version
					if version == "0" {
						inside = true
					} else {
						c, err := compare(base, version)
						if err != nil {
							return baseFinding{Status: "unknown"}
						}
						inside = c >= 0
					}
					continue
				}
				if !open || (kind != "fixed" && kind != "last_affected" && kind != "limit") {
					return baseFinding{Status: "unknown"}
				}
				if lower != "0" {
					c, err := compare(lower, version)
					if err != nil || c > 0 {
						return baseFinding{Status: "unknown"}
					}
				}
				c, err := compare(base, version)
				if err != nil {
					return baseFinding{Status: "unknown"}
				}
				if inside && (c < 0 || (kind == "last_affected" && c == 0)) {
					affected = true
				}
				if kind == "fixed" && c >= 0 {
					fixedBefore = version
				}
				open, inside = false, false
				previous = version
			}
		}
		if open && inside {
			affected = true
		}
	}
	if affected {
		return baseFinding{Status: "affected"}
	}
	if fixedBefore != "" {
		return baseFinding{Status: "base_fixed", Fixed: fixedBefore}
	}
	return baseFinding{Status: "outside_range"}
}

// Caller holds coverageMu. Inventory and base assessments are immutable until
// an atomic vendor.json replacement changes the snapshot.
func (s *Server) coverageBase(series, base string) (*coverageCache, map[string]baseFinding, error) {
	path := filepath.Join(s.cfg.DataDir, "coverage", "vendor.json")
	info, err := os.Stat(path)
	if err != nil {
		return nil, nil, err
	}
	if info.Size() > 64<<20 {
		return nil, nil, fmt.Errorf("oversized inventory")
	}
	if s.coverage == nil || !s.coverage.mtime.Equal(info.ModTime()) || s.coverage.size != info.Size() {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, nil, err
		}
		var feed vendorInventory
		if err := json.Unmarshal(data, &feed); err != nil {
			return nil, nil, err
		}
		if feed.Schema != 1 || !feed.Complete || feed.Source != vendorFeedURL || !sha256Hex.MatchString(feed.SHA256) || feed.FetchedAt.IsZero() || feed.SourceCount < 1000 || feed.SourceCount < feed.KernelCount || feed.KernelCount != len(feed.Records) || feed.KernelCount < 100 {
			return nil, nil, fmt.Errorf("incomplete or invalid official inventory")
		}
		seen := map[string]bool{}
		for _, row := range feed.Records {
			if !cveID.MatchString(row.ID) || seen[row.ID] {
				return nil, nil, fmt.Errorf("invalid or duplicate CVE")
			}
			seen[row.ID] = true
		}
		s.coverage = &coverageCache{mtime: info.ModTime(), size: info.Size(), feed: feed, bases: map[string]map[string]baseFinding{}}
	}
	key := series + "/" + base
	if s.coverage.bases[key] == nil {
		memo := map[string]int{}
		compare := func(a, b string) (int, error) {
			key := a + "/" + b
			if c, ok := memo[key]; ok {
				return c, nil
			}
			c, err := debCompare(a, b)
			if err == nil {
				memo[key] = c
			}
			return c, err
		}
		rows := map[string]baseFinding{}
		for _, row := range s.coverage.feed.Records {
			result := baseFinding{Status: "unknown"}
			if release, ok := row.Releases[series]; ok {
				result = assessBase(base, release, compare)
			}
			rows[row.ID] = result
		}
		s.coverage.bases[key] = rows
	}
	return s.coverage, s.coverage.bases[key], nil
}

type coverageRow struct {
	CVE               string   `json:"cve"`
	Priority          string   `json:"priority"`
	BaseStatus        string   `json:"base_status"`
	Status            string   `json:"status"`
	Fixed             string   `json:"fixed,omitempty"`
	VendorFixVersions []string `json:"vendor_fix_versions,omitempty"`
	PatchIDs          []string `json:"patch_ids,omitempty"`
	IncludedPatchIDs  []string `json:"included_patch_ids,omitempty"`
	Details           []string `json:"details,omitempty"`
}

func (s *Server) validationStatus() *model.ValidationStatus {
	path := filepath.Join(s.cfg.DataDir, "validation-state.json")
	info, err := os.Stat(path)
	if err != nil || info.Size() > 1<<20 {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var v model.ValidationStatus
	if json.Unmarshal(data, &v) != nil {
		return nil
	}
	return &v
}

func (s *Server) handleCoverage(w http.ResponseWriter, r *http.Request, who string) {
	var host *model.Host
	patches := []model.Patch{}
	unpatchable := map[string][]string{}
	adminExcluded := map[string]bool{}
	included := map[string]bool{}
	s.store.View(func(st *State) {
		if h := st.Hosts[r.URL.Query().Get("host")]; h != nil {
			cp := *h
			cp.TokenHash = ""
			host = &cp
			if j := st.releasedJob(h.Status.TrackKey(), h.Status.Version); j != nil && len(h.Status.Loaded) == 1 {
				lp := h.Status.Loaded[0]
				age := time.Since(h.LastSeen)
				if lp.Name == j.ModuleName && lp.Enabled && !lp.Transition && h.Status.Error == "" && age >= -30*time.Second && age <= time.Duration(s.settings().HostStaleMinutes)*time.Minute {
					for _, id := range j.PatchIDs {
						included[id] = true
					}
				}
			}
			for _, p := range st.Patches {
				if p.Kernel == h.Status.TrackKey() {
					cp := *p
					patches = append(patches, cp)
				}
			}
			for _, u := range st.Unpatchable {
				if u.Kernel == h.Status.TrackKey() {
					for _, cve := range u.CVEs {
						detail := u.Title + ": " + u.Reason
						if u.Decision != nil {
							adminExcluded[cve] = true
							detail = "미해결 · 관리자 제외: " + detail
						}
						unpatchable[cve] = append(unpatchable[cve], detail)
					}
				}
			}
		}
	})
	if host == nil {
		writeErr(w, fail(http.StatusNotFound, "호스트를 찾을 수 없습니다"))
		return
	}
	if host.Status.Distribution != nil {
		writeErr(w, fail(http.StatusBadRequest, "이 배포판의 전체 CVE 인벤토리는 제공하지 않습니다. 공식 릴리스에서 수집한 수정은 kpctl patches -kernel %s 에서 확인하세요", host.Status.TrackKey()))
		return
	}
	lts := model.LTSForKernel(host.Status.Kernel)
	base := model.SignatureVersion(host.Status.KernelSignature)
	if lts == nil || model.IsHWESignature(host.Status.KernelSignature) || !debVersion.MatchString(base) || !strings.HasPrefix(base, model.KernelABI(host.Status.Kernel)+".") {
		writeErr(w, fail(http.StatusBadRequest, "정확한 Ubuntu GA 커널 서명이 필요합니다"))
		return
	}
	s.coverageMu.Lock()
	cache, findings, err := s.coverageBase(lts.Codename, base)
	if err != nil {
		s.coverageMu.Unlock()
		writeErr(w, fail(http.StatusServiceUnavailable, "공식 CVE 목록을 읽을 수 없습니다: %v", err))
		return
	}
	feed := cache.feed // immutable after unlock
	s.coverageMu.Unlock()
	byCVE := map[string][]model.Patch{}
	for _, p := range patches {
		for _, id := range p.CVEs {
			byCVE[id] = append(byCVE[id], p)
		}
	}
	counts := map[string]int{}
	rows := []coverageRow{}
	seen := map[string]bool{}
	for _, record := range feed.Records {
		seen[record.ID] = true
		finding := findings[record.ID]
		row := coverageRow{CVE: record.ID, Priority: record.Priority, BaseStatus: finding.Status, Status: finding.Status, Fixed: finding.Fixed}
		for _, interval := range record.Releases[lts.Codename].Ranges {
			for _, event := range interval.Events {
				if fixed := event["fixed"]; debVersion.MatchString(fixed) {
					row.VendorFixVersions = append(row.VendorFixVersions, fixed)
				}
			}
		}
		if finding.Status == "affected" {
			row.Status = "not_collected"
			if len(row.VendorFixVersions) == 0 {
				row.Status = "vendor_fix_unknown"
			}
			if len(unpatchable[record.ID]) > 0 {
				row.Status = "unpatchable"
			}
			for _, p := range byCVE[record.ID] {
				if p.State == model.PatchActive {
					row.Status = "pending"
				} else if row.Status == "not_collected" || row.Status == "vendor_fix_unknown" {
					row.Status = "disabled"
				}
			}
		}
		missing := len(unpatchable[record.ID]) > 0
		row.Details = append(row.Details, unpatchable[record.ID]...)
		for _, p := range byCVE[record.ID] {
			row.PatchIDs = append(row.PatchIDs, p.ID)
			row.Details = append(row.Details, p.Title+" ["+p.State+"] "+p.Reason)
			if included[p.ID] {
				row.IncludedPatchIDs = append(row.IncludedPatchIDs, p.ID)
			} else {
				missing = true
			}
		}
		if len(row.IncludedPatchIDs) > 0 {
			row.Status = "included"
			if missing {
				row.Status = "partial"
			}
		}
		if adminExcluded[row.CVE] {
			row.Status = "admin_excluded"
		}
		counts[row.Status]++
		rows = append(rows, row)
	}
	// Locally collected CVEs absent from the snapshot must remain visible.
	for id, ps := range byCVE {
		if !seen[id] {
			row := coverageRow{CVE: id, Priority: "unknown", BaseStatus: "unknown", Status: "unknown"}
			missing := len(unpatchable[id]) > 0
			row.Details = append(row.Details, unpatchable[id]...)
			for _, p := range ps {
				row.PatchIDs = append(row.PatchIDs, p.ID)
				row.Details = append(row.Details, p.Title)
				if included[p.ID] {
					row.IncludedPatchIDs = append(row.IncludedPatchIDs, p.ID)
				} else {
					missing = true
				}
			}
			if len(row.IncludedPatchIDs) > 0 {
				row.Status = "included"
				if missing {
					row.Status = "partial"
				}
			}
			if adminExcluded[row.CVE] {
				row.Status = "admin_excluded"
			}
			counts[row.Status]++
			rows = append(rows, row)
		}
	}
	for id, details := range unpatchable {
		if !seen[id] && len(byCVE[id]) == 0 {
			status := "unpatchable"
			if adminExcluded[id] {
				status = "admin_excluded"
			}
			rows = append(rows, coverageRow{CVE: id, Priority: "unknown", BaseStatus: "unknown", Status: status, Details: details})
			counts[status]++
		}
	}
	priority := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "negligible": 4, "unknown": 5}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Priority != rows[j].Priority {
			return priority[rows[i].Priority] < priority[rows[j].Priority]
		}
		return rows[i].CVE > rows[j].CVE
	})
	filter := r.URL.Query().Get("state")
	if filter == "" {
		filter = "actionable"
	}
	query := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("q")))
	filtered := []coverageRow{}
	for _, row := range rows {
		if filter == "actionable" && (row.Status == "base_fixed" || row.Status == "outside_range" || row.Status == "unknown") {
			continue
		}
		if filter != "all" && filter != "actionable" && filter != row.Status {
			continue
		}
		if query != "" && !strings.Contains(row.CVE, query) {
			continue
		}
		filtered = append(filtered, row)
	}
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if offset < 0 {
		offset = 0
	}
	if offset > len(filtered) {
		offset = len(filtered)
	}
	end := offset + coveragePageSize
	if end > len(filtered) {
		end = len(filtered)
	}
	age := time.Since(feed.FetchedAt)
	writeJSON(w, http.StatusOK, map[string]any{"host_id": host.ID, "kernel": host.Status.Kernel, "base_version": base, "series": lts.Codename,
		"source_url": feed.Source, "source_sha256": feed.SHA256, "license": feed.License, "fetched_at": feed.FetchedAt, "source_stale": age > 72*time.Hour || age < -5*time.Minute,
		"inventory_count": len(feed.Records), "counts": counts, "total": len(filtered), "offset": offset, "rows": filtered[offset:end], "validation": s.validationStatus()})
}
