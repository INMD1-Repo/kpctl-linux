// 이 파일: 승인용 깊은 복제 갱신의 저장 실패·rename 이후 복구 경계 시험.
package controller

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"kpctl/internal/model"
)

func TestRollbackSaveFailureKeepsLiveTargets(t *testing.T) {
	s := newAutoServer(t, AutoRollout{})
	addHost(t, s, "node", 1)
	id := addBuilt(t, s, "manual")
	if _, _, _, err := s.approveJob(id, "tester"); err != nil {
		t.Fatal(err)
	}
	if err := s.store.Update(func(st *State) error {
		st.Hosts["node"].UpdateNowKernel, st.Hosts["node"].UpdateNowVersion = testKernel, 1
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	path := s.store.path
	s.store.path = filepath.Join(path, "state.json")
	callAPI(t, s, "POST", "/api/kernels/"+testKernel+"/rollback", `{"version":0}`, http.StatusInternalServerError)
	s.store.path = path
	s.store.View(func(st *State) {
		track, h := st.track(testKernel), st.Hosts["node"]
		if track.TargetVersion(1) != 1 || track.AutoHold != "" || h.UpdateNowKernel != testKernel || h.UpdateNowVersion != 1 {
			t.Fatal("failed rollback changed live targets or hold")
		}
	})
	callAPI(t, s, "POST", "/api/kernels/"+testKernel+"/rollback", `{"version":0}`, http.StatusOK)
	if ringVersion(s, 1) != 0 {
		t.Fatal("rollback retry did not commit")
	}
}

func atomicStateFixture(t *testing.T) (*Store, []byte) {
	t.Helper()
	store, err := OpenStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Update(func(st *State) error {
		st.Hosts["node"] = &model.Host{ID: "node", Hostname: "original", Status: model.HostStatus{EnrolledCerts: map[string]string{"old": "enrolled"}}}
		st.Jobs = []*model.Job{{ID: 1, Kernel: testKernel, Status: model.JobReleased, Version: 1, SigningArtifacts: map[string]model.SigningArtifact{"old": {KeyID: "old", SHA256: "old-sha", Signed: true}}}}
		st.track(testKernel).RingVersions[1] = 1
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(store.path)
	if err != nil {
		t.Fatal(err)
	}
	return store, data
}
func mutateAtomicState(st *State) error {
	st.Hosts["node"].Hostname = "changed"
	st.Hosts["node"].Status.EnrolledCerts["new"] = "enrolled"
	st.Jobs[0].SigningArtifacts["new"] = model.SigningArtifact{KeyID: "new", SHA256: "new-sha", Signed: true}
	st.Tracks[testKernel].RingVersions[1] = 2
	return nil
}
func defaultAtomicStateIO() stateAtomicIO {
	return stateAtomicIO{createTemp: os.CreateTemp, rename: os.Rename, syncDir: (*os.File).Sync}
}
func requireAtomicStateUnchanged(t *testing.T, store *Store, original *State, disk []byte) {
	t.Helper()
	if store.st != original {
		t.Fatal("저장 실패가 live State 포인터를 교체함")
	}
	if original.Hosts["node"].Hostname != "original" || len(original.Hosts["node"].Status.EnrolledCerts) != 1 || len(original.Jobs[0].SigningArtifacts) != 1 || original.Tracks[testKernel].RingVersions[1] != 1 {
		t.Fatal("실패한 callback이 중첩된 live map/포인터를 변경함")
	}
	current, err := os.ReadFile(store.path)
	if err != nil || string(current) != string(disk) {
		t.Fatalf("실패가 기존 디스크 바이트를 변경함: %v\n%s", err, current)
	}
}

func TestStoreUpdateAtomicCommitsIndependentDeepCopyAfterDurableSave(t *testing.T) {
	store, _ := atomicStateFixture(t)
	original := store.st
	if err := store.UpdateAtomic(mutateAtomicState); err != nil {
		t.Fatal(err)
	}
	if store.st == original || original.Hosts["node"].Hostname != "original" || len(original.Jobs[0].SigningArtifacts) != 1 {
		t.Fatal("원래 State를 공유하거나 깊은 복제가 아님")
	}
	if store.st.Hosts["node"].Hostname != "changed" || len(store.st.Jobs[0].SigningArtifacts) != 2 {
		t.Fatal("저장 성공 뒤 live 복제본이 반영되지 않음")
	}
	reopened, err := OpenStore(store.path)
	if err != nil {
		t.Fatal(err)
	}
	if reopened.st.Hosts["node"].Hostname != "changed" || len(reopened.st.Jobs[0].SigningArtifacts) != 2 || reopened.st.Tracks[testKernel].RingVersions[1] != 2 {
		t.Fatal("성공한 갱신이 재시작 뒤 보존되지 않음")
	}
	info, err := os.Stat(store.path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("상태 파일 권한이 바뀜: %v %v", info, err)
	}
	leftovers, err := filepath.Glob(filepath.Join(filepath.Dir(store.path), ".state-*"))
	if err != nil || len(leftovers) != 0 {
		t.Fatalf("성공 뒤 stage/backup 파일 잔존: %v %v", leftovers, err)
	}
}

func TestStoreUpdateAtomicCallbackFailureLeavesMemoryAndDiskUntouched(t *testing.T) {
	store, disk := atomicStateFixture(t)
	original := store.st
	failure := errors.New("callback refused release")
	err := store.UpdateAtomic(func(st *State) error { _ = mutateAtomicState(st); return failure })
	if !errors.Is(err, failure) {
		t.Fatalf("callback 오류 누락: %v", err)
	}
	requireAtomicStateUnchanged(t, store, original, disk)
}

func TestStoreUpdateAtomicTemporaryWriteFailureLeavesLiveStateUntouched(t *testing.T) {
	store, disk := atomicStateFixture(t)
	original := store.st
	ops := defaultAtomicStateIO()
	ops.createTemp = func(dir, pattern string) (*os.File, error) {
		file, err := os.CreateTemp(dir, pattern)
		if err != nil {
			return nil, err
		}
		name := file.Name()
		if err := file.Close(); err != nil {
			return nil, err
		}
		return os.Open(name) // 실제 Write가 EBADF로 실패하는 읽기 전용 FD
	}
	err := store.updateAtomic(mutateAtomicState, ops)
	if err == nil || !strings.Contains(err.Error(), "임시 파일 기록 실패") {
		t.Fatalf("실제 임시 파일 Write 오류 누락: %v", err)
	}
	requireAtomicStateUnchanged(t, store, original, disk)
}

func TestStoreUpdateAtomicRenameFailureLeavesLiveStateUntouched(t *testing.T) {
	store, disk := atomicStateFixture(t)
	original := store.st
	ops := defaultAtomicStateIO()
	failure := errors.New("filesystem refused commit rename")
	ops.rename = func(_, _ string) error { return failure }
	err := store.updateAtomic(mutateAtomicState, ops)
	if !errors.Is(err, failure) || !strings.Contains(err.Error(), "atomic rename") {
		t.Fatalf("rename 오류 누락: %v", err)
	}
	requireAtomicStateUnchanged(t, store, original, disk)
}

func TestStoreUpdateAtomicPostRenameFsyncFailureRestoresPreviousInode(t *testing.T) {
	store, disk := atomicStateFixture(t)
	original := store.st
	ops := defaultAtomicStateIO()
	calls := 0
	failure := errors.New("directory fsync after rename failed")
	ops.syncDir = func(dir *os.File) error {
		calls++
		if calls == 2 {
			// 이 시점에 새 파일 이름은 이미 보이지만 live State는 아직 원래 상태입니다.
			bytes, err := os.ReadFile(store.path)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(bytes), `"hostname": "changed"`) || store.st != original {
				t.Fatal("rename/fsync/live 교체 순서가 다름")
			}
			return failure
		}
		return dir.Sync()
	}
	err := store.updateAtomic(mutateAtomicState, ops)
	if !errors.Is(err, failure) || calls != 3 || !strings.Contains(err.Error(), "이전 상태 복구·fsync 완료") {
		t.Fatalf("rename 뒤 fsync 오류 복구를 놓침: %v, calls=%d", err, calls)
	}
	requireAtomicStateUnchanged(t, store, original, disk)
}

func TestStoreUpdateAtomicFailedRestoreKeepsRecoverableBackupAndExplicitError(t *testing.T) {
	store, disk := atomicStateFixture(t)
	original := store.st
	ops := defaultAtomicStateIO()
	syncs, renames := 0, 0
	ops.syncDir = func(dir *os.File) error {
		syncs++
		if syncs == 2 {
			return errors.New("commit sync failed")
		}
		return dir.Sync()
	}
	ops.rename = func(old, new string) error {
		renames++
		if renames == 2 {
			return errors.New("restore rename failed")
		}
		return os.Rename(old, new)
	}
	err := store.updateAtomic(mutateAtomicState, ops)
	if err == nil || !strings.Contains(err.Error(), "이전 이름 복구도 실패") || !strings.Contains(err.Error(), "백업=") {
		t.Fatalf("복구 불가 상태를 명시하지 않음: %v", err)
	}
	if store.st != original || original.Hosts["node"].Hostname != "original" {
		t.Fatal("복구 불가 오류도 live 메모리를 바꿔서는 안 됨")
	}
	backups, err := filepath.Glob(filepath.Join(filepath.Dir(store.path), ".state-previous-*"))
	if err != nil || len(backups) != 1 {
		t.Fatalf("이전 inode 복구용 백업 누락: %v %v", backups, err)
	}
	backup, err := os.ReadFile(backups[0])
	if err != nil || string(backup) != string(disk) {
		t.Fatalf("복구용 백업이 원래 상태와 다름: %v", err)
	}
}

func TestStoreUpdateAtomicFailedRestoreFsyncDoesNotClaimDurability(t *testing.T) {
	store, disk := atomicStateFixture(t)
	original := store.st
	ops := defaultAtomicStateIO()
	calls := 0
	ops.syncDir = func(dir *os.File) error {
		calls++
		if calls >= 2 {
			return errors.New("persistent directory sync failure")
		}
		return dir.Sync()
	}
	err := store.updateAtomic(mutateAtomicState, ops)
	if err == nil || !strings.Contains(err.Error(), "전원 장애 후 지속성은 미확인") {
		t.Fatalf("지속성 미확인 상태를 성공/복구완료로 처리함: %v", err)
	}
	requireAtomicStateUnchanged(t, store, original, disk)
}

func TestStoreUpdateAtomicFirstSaveFsyncFailureRestoresMissingFile(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	original := store.st
	ops := defaultAtomicStateIO()
	calls := 0
	failure := errors.New("first save directory sync failed")
	ops.syncDir = func(dir *os.File) error {
		calls++
		if calls == 1 {
			return failure
		}
		return dir.Sync()
	}
	err = store.updateAtomic(func(st *State) error { st.NextJobID = 12; return nil }, ops)
	if !errors.Is(err, failure) || store.st != original || store.st.NextJobID != 0 {
		t.Fatalf("초기 상태 저장 실패가 반영됨: %v", err)
	}
	if _, err := os.Stat(store.path); !os.IsNotExist(err) {
		t.Fatalf("최초 저장 실패 뒤 새 state 파일이 남음: %v", err)
	}
}

func TestStoreUpdateAtomicStoredJSONMatchesLiveState(t *testing.T) {
	store, _ := atomicStateFixture(t)
	if err := store.UpdateAtomic(mutateAtomicState); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(store.path)
	if err != nil {
		t.Fatal(err)
	}
	var disk State
	if err := json.Unmarshal(data, &disk); err != nil {
		t.Fatal(err)
	}
	liveJSON, err := json.Marshal(store.st)
	if err != nil {
		t.Fatal(err)
	}
	diskJSON, err := json.Marshal(&disk)
	if err != nil {
		t.Fatal(err)
	}
	if string(liveJSON) != string(diskJSON) {
		t.Fatal("성공한 저장과 live State가 다름")
	}
}
