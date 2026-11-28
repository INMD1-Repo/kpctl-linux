package controller

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"kpctl/internal/model"
)

var candidatePath = regexp.MustCompile(`^[a-zA-Z0-9_./-]+\.[chS]$`)
var reviewedID = regexp.MustCompile(`^[0-9a-f]{40}/[0-9a-f]{64}$`)

func readProofFile(path string, dest any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, dest); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

// Only independent receipts installed by the controller operator can trigger collection.
func (s *Server) reviewedCandidates(st *State, kernel model.DistributionKernel) ([]model.ReviewedCandidate, error) {
	track := kernel.Track()
	dir := filepath.Join(s.cfg.DataDir, "distribution-proofs", track)
	var base model.DistributionProof
	if err := readProofFile(dir+".json", &base); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	if !base.Valid(track) {
		return nil, fmt.Errorf("invalid independent base receipt for %s", track)
	}
	known := map[string]bool{}
	for _, id := range st.knownCommits(track) {
		known[id] = true
	}
	latest := map[string]string{}
	for _, p := range st.activePatches(track) {
		paths := p.Paths
		if len(paths) == 0 && p.CandidateID != "" {
			body, err := os.ReadFile(s.patchFile(p.ID))
			if err != nil {
				return nil, err
			}
			paths, err = verifiedCandidatePaths(p, body)
			if err != nil {
				return nil, err
			}
		}
		for _, path := range paths {
			latest[path] = p.CandidateID
		}
	}
	files, err := filepath.Glob(filepath.Join(dir, "*", "*.json"))
	if err != nil {
		return nil, err
	}
	var pending []model.ReviewedCandidate
	for _, path := range files {
		rev := filepath.Base(filepath.Dir(path))
		sum := strings.TrimSuffix(filepath.Base(path), ".json")
		id := rev + "/" + sum
		if !reviewedID.MatchString(id) || known[id] || known[rev] {
			continue
		}
		var item model.ReviewedCandidate
		pin := &item.Pin
		if err := readProofFile(path, pin); err != nil {
			return nil, err
		}
		if pin.CandidateID != id || pin.SHA256 != sum || pin.Base != base || !pin.Fixed.ValidFor(kernel, rev) || len(pin.Paths) == 0 {
			return nil, fmt.Errorf("invalid independent candidate receipt: %s", path)
		}
		if pin.CVEs == nil {
			pin.CVEs = []string{}
		}
		var fixed model.FixedRelease
		if err := readProofFile(filepath.Join(dir, rev+".json"), &fixed); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return nil, err
		}
		if fixed != pin.Fixed {
			return nil, fmt.Errorf("independent fixed receipt differs: %s", rev)
		}
		if checkParent(latest, pin.Paths, pin.Parent) != nil {
			continue
		}
		if pin.Parent != "" {
			if !reviewedID.MatchString(pin.Parent) {
				return nil, fmt.Errorf("invalid parent candidate: %s", path)
			}
			var previous model.DistributionCandidateProof
			if err := readProofFile(filepath.Join(dir, pin.Parent+".json"), &previous); err != nil {
				return nil, err
			}
			if previous.CandidateID != pin.Parent || previous.Base != base || !slices.Equal(previous.Paths, pin.Paths) {
				return nil, fmt.Errorf("independent parent receipt differs: %s", path)
			}
			item.Previous = &previous
		}
		pending = append(pending, item)
	}
	return pending, nil
}

func candidatePaths(body []byte) ([]string, error) {
	var paths []string
	for _, line := range strings.Split(string(body), "\n") {
		if !strings.HasPrefix(line, "diff --git ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 4 {
			return nil, fmt.Errorf("invalid candidate paths")
		}
		path, ok := strings.CutPrefix(fields[2], "a/")
		if !ok || fields[3] != "b/"+path || !candidatePath.MatchString(path) || filepath.Clean(path) != path || !filepath.IsLocal(path) {
			return nil, fmt.Errorf("invalid candidate source path")
		}
		paths = append(paths, path)
	}
	if len(paths) == 0 || !slices.IsSorted(paths) || len(slices.Compact(slices.Clone(paths))) != len(paths) {
		return nil, fmt.Errorf("expected distinct sorted candidate paths")
	}
	return paths, nil
}

func verifiedCandidatePaths(p *model.Patch, body []byte) ([]string, error) {
	if p == nil || p.CandidateID == "" {
		return nil, fmt.Errorf("legacy native patch lacks a submitted candidate ID")
	}
	if p.CandidateID != fmt.Sprintf("%s/%x", p.Commit, sha256.Sum256(body)) {
		return nil, fmt.Errorf("stored candidate %s SHA256 differs from submitted ID", p.ID)
	}
	paths, err := candidatePaths(body)
	if err != nil {
		return nil, err
	}
	if len(p.Paths) > 0 && !slices.Equal(p.Paths, paths) {
		return nil, fmt.Errorf("stored candidate %s paths differ", p.ID)
	}
	return paths, nil
}

// Each changed file continues exactly the most recent delta in its own chain.
func checkParent(latest map[string]string, paths []string, parent string) error {
	for _, p := range paths {
		if latest[p] != parent {
			return fmt.Errorf("%s: expected predecessor %q, received %q", p, latest[p], parent)
		}
	}
	return nil
}

// The builder API cannot publish approval pins. An operator installs the receipt
// from an independently verified package preparation before the first release.
func (s *Server) checkDistributionProof(st *State, j *model.Job) error {
	if k, _ := model.DistributionTrack(j.Kernel); k.BuildBlock() != "" {
		return fmt.Errorf("%s", k.BuildBlock())
	}
	if !j.DistributionProof.Valid(j.Kernel) || j.ModuleName != model.NativeModuleName(j.Kernel, j.Version) {
		return fmt.Errorf("빌드의 서명 출처·모듈 대상이 일치하지 않습니다")
	}
	dir := filepath.Join(s.cfg.DataDir, "distribution-proofs")
	base, _ := model.DistributionTrack(j.Kernel)
	if len(j.PatchIDs) == 0 {
		return fmt.Errorf("empty native candidate set")
	}
	latest := map[string]string{}
	for _, id := range j.PatchIDs {
		p := st.patch(id)
		if p == nil || p.Kernel != j.Kernel || p.Source != base.Distro || !p.FixedRelease.ValidFor(base, p.Commit) || p.Commit == j.DistributionProof.Revision {
			return fmt.Errorf("패치 %s의 공식 수정 릴리스 증거가 없습니다", id)
		}
		body, err := os.ReadFile(s.patchFile(id))
		if err != nil {
			return fmt.Errorf("read candidate %s: %w", id, err)
		}
		paths, err := verifiedCandidatePaths(p, body)
		if err != nil {
			return err
		}
		_, sum, _ := strings.Cut(p.CandidateID, "/")
		if err := checkParent(latest, paths, p.ParentCandidate); err != nil {
			return err
		}
		for _, path := range paths {
			latest[path] = p.CandidateID
		}
		pinPath := filepath.Join(dir, j.Kernel, p.Commit, sum+".json")
		var pin model.DistributionCandidateProof
		data, err := os.ReadFile(pinPath)
		if err != nil {
			return fmt.Errorf("independent candidate-proof required for %s: %w", id, err)
		}
		if json.Unmarshal(data, &pin) != nil || pin.Base != *j.DistributionProof || pin.Fixed != *p.FixedRelease || pin.SHA256 != sum || pin.CandidateID != p.CandidateID || pin.Parent != p.ParentCandidate || !slices.Equal(pin.Paths, paths) || !slices.Equal(pin.CVEs, p.CVEs) {
			return fmt.Errorf("independent candidate-proof mismatch: %s", pinPath)
		}
		path := filepath.Join(dir, j.Kernel, p.Commit+".json")
		var approved model.FixedRelease
		data, err = os.ReadFile(path)
		if err != nil || json.Unmarshal(data, &approved) != nil || approved != *p.FixedRelease {
			return fmt.Errorf("패치 %s의 독립 검증 fixed-proof가 일치하지 않습니다: %s", id, path)
		}
	}
	path := filepath.Join(dir, j.Kernel+".json")
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("독립 검증한 prepare 결과가 필요합니다: %w", err)
	}
	var approved model.DistributionProof
	if err := json.Unmarshal(b, &approved); err != nil || approved != *j.DistributionProof {
		return fmt.Errorf("배포 승인 증거와 빌드 입력이 다릅니다: %s", path)
	}
	return nil
}

func writeProofAtomic(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".proof-*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmp)
		}
	}()
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Chmod(0o640); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func (s *Server) hasValidBaseProof(track string) (model.DistributionProof, bool) {
	if filepath.Base(track) != track {
		return model.DistributionProof{}, false
	}
	var base model.DistributionProof
	path := filepath.Join(s.cfg.DataDir, "distribution-proofs", track+".json")
	if err := readProofFile(path, &base); err != nil {
		return model.DistributionProof{}, false
	}
	if !base.Valid(track) {
		return model.DistributionProof{}, false
	}
	return base, true
}

// POST /api/distribution-proofs/base — 관리자가 배포판 기준 승인 핀(base-proof.json)을 등록합니다.
func (s *Server) handleInstallBaseProof(w http.ResponseWriter, r *http.Request, who string) {
	var proof model.DistributionProof
	if err := readJSON(r, &proof); err != nil {
		writeErr(w, err)
		return
	}
	if reason := model.KernelBuildBlock(proof.Track); reason != "" {
		writeErr(w, fail(http.StatusConflict, "%s", reason))
		return
	}
	if filepath.Base(proof.Track) != proof.Track || !proof.Valid(proof.Track) {
		writeErr(w, fail(http.StatusBadRequest, "유효한 배포판 기준 영수증(base-proof)이 아닙니다: %q", proof.Track))
		return
	}
	path := filepath.Join(s.cfg.DataDir, "distribution-proofs", proof.Track+".json")
	if err := writeProofAtomic(path, proof); err != nil {
		writeErr(w, fmt.Errorf("기준 승인 핀 저장 실패: %w", err))
		return
	}
	s.audit(who, "배포판 기준 승인 핀 등록 track=%s rev=%s", proof.Track, proof.Revision)
	writeJSON(w, http.StatusOK, map[string]any{"track": proof.Track, "installed": true})
}

// installAutoCandidatePins 는 native_auto_pin 이 켜져 있을 때 기준 영수증과 공식 서명 릴리스 검증을 통과한
// 수정 후보의 fixed-proof 와 candidate-proof 를 컨트롤러 distribution-proofs 디렉터리에 자동 기록합니다.
func (s *Server) installAutoCandidatePins(base model.DistributionProof, fixed model.FixedRelease, paths, cves []string, parent, title, sum string) error {
	installed, ok := s.hasValidBaseProof(base.Track)
	if !ok || installed != base {
		return fail(http.StatusConflict, "컨트롤러에 등록된 기준 승인 핀과 일치하지 않습니다")
	}
	dir := filepath.Join(s.cfg.DataDir, "distribution-proofs", base.Track)
	fixedPath := filepath.Join(dir, fixed.Revision+".json")
	var existingFixed model.FixedRelease
	if err := readProofFile(fixedPath, &existingFixed); err == nil {
		if existingFixed != fixed {
			return fail(http.StatusConflict, "이미 등록된 fixed-proof 와 다릅니다: %s", fixed.Revision)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	} else if err := writeProofAtomic(fixedPath, fixed); err != nil {
		return fmt.Errorf("fixed-proof 자동 저장 실패: %w", err)
	}
	if cves == nil {
		cves = []string{}
	}
	pin := model.DistributionCandidateProof{
		Base:        base,
		Fixed:       fixed,
		Paths:       paths,
		CVEs:        cves,
		Parent:      parent,
		SHA256:      sum,
		CandidateID: fixed.Revision + "/" + sum,
		Title:       title,
	}
	pinPath := filepath.Join(dir, fixed.Revision, sum+".json")
	if err := writeProofAtomic(pinPath, pin); err != nil {
		return fmt.Errorf("candidate-proof 자동 저장 실패: %w", err)
	}
	return nil
}
