// 이 파일: JSON 상태 조회·일반 저장과 승인용 원자 저장.
package controller

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"kpctl/internal/model"
	"kpctl/internal/testvm"
)

// State 는 컨트롤러가 기억하는 모든 것입니다. data_dir/state.json 에 통째로 저장됩니다.
// (호스트 수십~수백 대 규모에서는 JSON 파일 하나로 충분합니다. DB 가 필요 없습니다.)
type State struct {
	SigningCertSHA256 map[string]string             `json:"signing_cert_sha256,omitempty"`
	MOKRequests       map[string]*MOKEnrollment     `json:"mok_requests,omitempty"`
	NextJobID         int                           `json:"next_job_id"`
	NextPatchID       int                           `json:"next_patch_id"`
	NextRebootID      int                           `json:"next_reboot_id"`
	Tracks            map[string]*model.Track       `json:"tracks"`
	Patches           []*model.Patch                `json:"patches"`
	Jobs              []*model.Job                  `json:"jobs"`
	Hosts             map[string]*model.Host        `json:"hosts"`
	Unpatchable       []*model.Unpatchable          `json:"unpatchable"`
	Upstream          map[string]*model.Upstream    `json:"upstream,omitempty"` // 커널 → Ubuntu 최신 상황
	Builders          map[string]*model.BuilderInfo `json:"builders,omitempty"` // 빌드 서버 이름 → 마지막 확인
	TestVMs           map[string]testvm.Instance    `json:"test_vms,omitempty"`

	// 자동 배포 전체 일시 중지 (재시작해도 유지)
	AutoPaused   bool   `json:"auto_paused,omitempty"`
	AutoPausedBy string `json:"auto_paused_by,omitempty"`
}

// ── 조회 도우미 ──

// upstream 은 커널의 Ubuntu 최신 상황을 돌려줍니다. 없으면 새로 만듭니다.
func (st *State) upstream(kernel string) *model.Upstream {
	if st.Upstream == nil {
		st.Upstream = map[string]*model.Upstream{}
	}
	u := st.Upstream[kernel]
	if u == nil {
		u = &model.Upstream{}
		st.Upstream[kernel] = u
	}
	return u
}

// track 은 커널의 Track 을 돌려줍니다. 없으면 새로 만듭니다.
func (st *State) track(kernel string) *model.Track {
	t := st.Tracks[kernel]
	if t == nil {
		t = &model.Track{Kernel: kernel}
		st.Tracks[kernel] = t
	}
	if t.RingVersions == nil {
		t.RingVersions = map[int]int{}
	}
	if t.RingSetAt == nil {
		t.RingSetAt = map[int]time.Time{}
	}
	if t.PrereleaseRingVersions == nil {
		t.PrereleaseRingVersions = map[int]int{}
	}
	if t.PrereleaseRingSetAt == nil {
		t.PrereleaseRingSetAt = map[int]time.Time{}
	}
	return t
}

func (st *State) job(id int) *model.Job {
	for _, j := range st.Jobs {
		if j.ID == id {
			return j
		}
	}
	return nil
}

func (st *State) patch(id string) *model.Patch {
	for _, p := range st.Patches {
		if p.ID == id {
			return p
		}
	}
	return nil
}

// activePatches 는 커널의 활성 패치를 추가된 순서대로 돌려줍니다.
func (st *State) activePatches(kernel string) []*model.Patch {
	var out []*model.Patch
	for _, p := range st.Patches {
		if p.Kernel == kernel && !p.Prerelease && p.State == model.PatchActive {
			out = append(out, p)
		}
	}
	return out
}

// releasedJob 은 커널의 특정 버전으로 배포된 작업을 찾습니다.
func (st *State) releasedJob(kernel string, version int) *model.Job {
	for _, j := range st.Jobs {
		if j.Kernel == kernel && j.Version == version && j.Status == model.JobReleased {
			return j
		}
	}
	return nil
}

// latestReleased 는 커널에서 가장 높은 버전의 배포 작업을 찾습니다.
func (st *State) latestReleased(kernel string) *model.Job {
	var best *model.Job
	for _, j := range st.Jobs {
		if j.Kernel == kernel && !j.Prerelease && j.Status == model.JobReleased && (best == nil || j.Version > best.Version) {
			best = j
		}
	}
	return best
}

// knownCommits는 패치·이전 판정·관리자 제외로 이미 처리한 Ubuntu 커밋 목록입니다.
func (st *State) knownCommits(kernel string) []string {
	var out []string
	for _, p := range st.Patches {
		if p.Kernel == kernel && !p.Prerelease && p.Commit != "" {
			out = append(out, p.Commit)
		}
	}
	for _, u := range st.Unpatchable {
		if u.Kernel == kernel && u.Commit != "" {
			out = append(out, u.Commit)
		}
	}
	return out
}

func (st *State) excludedCommit(kernel, commit string) *model.Unpatchable {
	for _, u := range st.Unpatchable {
		if u.Kernel == kernel && u.Commit == commit && u.Decision != nil {
			return u
		}
	}
	return nil
}

// hostKernels 는 등록된 호스트들이 지금 쓰는 커널 목록입니다 (커널 이름순).
// uname -r 이 같아도 HWE 커널(예: 22.04 의 6.8)은 GA 커널과 다른 커널이므로 따로 셉니다.
func (st *State) hostKernels() []model.HostKernel {
	type key struct {
		kernel string
		hwe    bool
	}
	byKernel := map[key]*model.HostKernel{}
	for _, h := range st.Hosts {
		k := h.Status.Kernel
		if k == "" {
			continue
		}
		kk := key{k, model.IsHWESignature(h.Status.KernelSignature)}
		hk := byKernel[kk]
		if hk == nil {
			hk = &model.HostKernel{Kernel: k}
			byKernel[kk] = hk
		}
		hk.Hosts++
		if hk.Signature == "" {
			hk.Signature = h.Status.KernelSignature
		}
	}
	out := make([]model.HostKernel, 0, len(byKernel))
	for _, hk := range byKernel {
		out = append(out, *hk)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kernel != out[j].Kernel {
			return out[i].Kernel < out[j].Kernel
		}
		return out[i].Signature < out[j].Signature
	})
	return out
}

// ── 저장소 ──

// Store 는 State 를 잠금과 함께 보관하고 파일에 저장합니다.
//
// 사용법:
//
//	store.View(func(st *State) { ...읽기만... })
//	err := store.Update(func(st *State) error { ...고치기... })
//
// Update 규칙: 검사를 먼저 하고, 오류를 돌려줄 거라면 State 를 고치기 전에 돌려주세요.
// (오류를 돌려주면 파일에는 저장되지 않지만, 메모리에서 이미 고친 내용은 되돌아가지 않습니다.)
type Store struct {
	mu   sync.Mutex
	path string
	st   *State
}

func OpenStore(path string) (*Store, error) {
	st := &State{}
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		if err := json.Unmarshal(data, st); err != nil {
			return nil, err
		}
	case os.IsNotExist(err):
		// 처음 실행: 빈 상태로 시작
	default:
		return nil, err
	}
	if st.Tracks == nil {
		st.Tracks = map[string]*model.Track{}
	}
	if st.Hosts == nil {
		st.Hosts = map[string]*model.Host{}
	}
	return &Store{path: path, st: st}, nil
}

func (s *Store) View(fn func(st *State)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(s.st)
}

func (s *Store) Update(fn func(st *State) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := fn(s.st); err != nil {
		return err
	}
	return s.save()
}

// UpdateAtomic은 승인처럼 저장 실패에도 live 상태를 변경하면 안 되는 경로용입니다.
// 기존 Update의 동작은 유지하고, JSON 깊은 복제본의 저장을 끝낸 뒤에만 교체합니다.
func (s *Store) UpdateAtomic(fn func(st *State) error) error {
	return s.updateAtomic(fn, stateAtomicIO{createTemp: os.CreateTemp, rename: os.Rename, syncDir: (*os.File).Sync})
}

// stateAtomicIO는 rename 이후 directory fsync 실패까지 같은 경로로 재현하기 위한
// 좁은 파일 시스템 경계입니다. 운영에서는 os.Rename과 실제 File.Sync를 사용합니다.
type stateAtomicIO struct {
	createTemp func(string, string) (*os.File, error)
	rename     func(string, string) error
	syncDir    func(*os.File) error
}

func (s *Store) updateAtomic(fn func(st *State) error, ops stateAtomicIO) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := json.Marshal(s.st)
	if err != nil {
		return fmt.Errorf("상태 깊은 복제 직렬화 실패: %w", err)
	}
	staged := &State{}
	if err := json.Unmarshal(data, staged); err != nil {
		return fmt.Errorf("상태 깊은 복제 해석 실패: %w", err)
	}
	if err := fn(staged); err != nil {
		return err
	}
	data, err = json.MarshalIndent(staged, "", "  ")
	if err != nil {
		return fmt.Errorf("변경 상태 직렬화 실패: %w", err)
	}
	if err := persistAtomicState(s.path, data, ops); err != nil {
		return err
	}
	s.st = staged
	return nil
}

// persistAtomicState는 새 바이트와 이전 이름의 복구 경로를 모두 fsync합니다.
// rename 뒤 directory fsync가 실패하면 이전 inode를 복구합니다. 파일 시스템이
// 복구 rename/fsync도 거부하면 디스크·전원 장애 후 상태를 보장할 수 없으므로
// 보존한 백업과 불확실성을 오류로 명시하며 성공으로 처리하지 않습니다.
func persistAtomicState(path string, data []byte, ops stateAtomicIO) error {
	dir := filepath.Dir(path)
	directory, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("상태 저장 디렉터리 열기 실패: %w", err)
	}
	defer directory.Close()
	temp, err := ops.createTemp(dir, ".state-stage-*")
	if err != nil {
		return fmt.Errorf("상태 임시 파일 생성 실패: %w", err)
	}
	defer os.Remove(temp.Name())
	if _, err := temp.Write(data); err != nil {
		temp.Close()
		return fmt.Errorf("상태 임시 파일 기록 실패: %w", err)
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return fmt.Errorf("상태 임시 파일 fsync 실패: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("상태 임시 파일 닫기 실패: %w", err)
	}

	backup := ""
	keepBackup := false
	defer func() {
		if backup != "" && !keepBackup {
			_ = os.Remove(backup)
		}
	}()
	if info, statErr := os.Lstat(path); statErr == nil {
		if !info.Mode().IsRegular() {
			return fmt.Errorf("기존 상태가 일반 파일이 아니므로 원자 갱신을 중단합니다")
		}
		placeholder, err := os.CreateTemp(dir, ".state-previous-*")
		if err != nil {
			return fmt.Errorf("이전 상태 백업 이름 생성 실패: %w", err)
		}
		backup = placeholder.Name()
		if err := placeholder.Close(); err != nil {
			return fmt.Errorf("이전 상태 백업 이름 닫기 실패: %w", err)
		}
		if err := os.Remove(backup); err != nil {
			return fmt.Errorf("이전 상태 백업 이름 준비 실패: %w", err)
		}
		if err := os.Link(path, backup); err != nil {
			return fmt.Errorf("이전 상태 inode 백업 실패: %w", err)
		}
		if err := ops.syncDir(directory); err != nil {
			return fmt.Errorf("이전 상태 백업 directory fsync 실패 (상태 교체 전): %w", err)
		}
	} else if !os.IsNotExist(statErr) {
		return fmt.Errorf("이전 상태 확인 실패: %w", statErr)
	}
	if err := ops.rename(temp.Name(), path); err != nil {
		return fmt.Errorf("상태 atomic rename 실패: %w", err)
	}
	if commitErr := ops.syncDir(directory); commitErr != nil {
		var restoreErr error
		if backup != "" {
			restoreErr = ops.rename(backup, path)
		} else {
			restoreErr = os.Remove(path)
		}
		if restoreErr != nil {
			keepBackup = backup != ""
			return fmt.Errorf("상태 rename 후 directory fsync 실패 (%v), 이전 이름 복구도 실패 (%v); 디스크 상태를 확인해야 합니다. 이전 inode 백업=%q", commitErr, restoreErr, backup)
		}
		backup = ""
		if err := ops.syncDir(directory); err != nil {
			return fmt.Errorf("상태 rename 후 directory fsync 실패 (%v); 이전 이름은 복구했으나 복구 directory fsync도 실패하여 전원 장애 후 지속성은 미확인: %w", commitErr, err)
		}
		return fmt.Errorf("상태 rename 후 directory fsync 실패; 이전 상태 복구·fsync 완료: %w", commitErr)
	}
	return nil
}

// save 는 임시 파일에 쓴 뒤 이름을 바꿔서, 저장 중 죽어도 파일이 깨지지 않게 합니다.
func (s *Store) save() error {
	data, err := json.MarshalIndent(s.st, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(tmp, s.path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(s.path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
