// 이 파일: controller 패키지의 TestBuilderNextIncludesFileAndKernelInfo, TestBuildKernelInfoUsesRecentValidGAReport 회귀 시험.
package controller

import (
	"encoding/json"
	"net/http"
	"os"
	"testing"
	"time"

	"kpctl/internal/model"
)

func TestBuilderNextIncludesFileAndKernelInfo(t *testing.T) {
	s := newAutoServer(t, AutoRollout{})
	addHost(t, s, "node", 1)
	id := addBuilt(t, s, "manual")
	content := "--- a\n+++ b\n@@\n+커널 수정\n"
	if err := s.store.Update(func(st *State) error {
		st.Hosts["node"].Status.KernelSignature = "Ubuntu 6.8.0-85.85-generic 6.8.12"
		st.job(id).Status = model.JobQueued
		return os.WriteFile(s.patchFile(st.job(id).PatchIDs[0]), []byte(content), 0o640)
	}); err != nil {
		t.Fatal(err)
	}
	body := callBuilderAPI(t, s, "POST", "/api/builder/next", `{"builder":"b1","series":"noble"}`, http.StatusOK)
	var task model.BuildTask
	if err := json.Unmarshal([]byte(body), &task); err != nil {
		t.Fatal(err)
	}
	if task.Job.ID != id || task.Job.Status != model.JobRunning || len(task.Patches) != 1 {
		t.Fatalf("unexpected task: %+v", task)
	}
	patch := task.Patches[0]
	if patch.Content != content || patch.Size != int64(len(content)) || patch.SHA256 == "" || patch.Validate() != nil {
		t.Fatalf("file metadata must describe exact transmitted bytes: %+v", patch)
	}
	if task.KernelInfo == nil || task.KernelInfo.Validate(testKernel) != nil || task.KernelInfo.BaseTag != "Ubuntu-6.8.0-85.85" {
		t.Fatalf("missing exact host build inputs: %+v", task.KernelInfo)
	}
	// The received snapshot stays stable after a later host report.
	if err := s.store.Update(func(st *State) error {
		st.Hosts["node"].Status.KernelSignature = "Ubuntu 6.8.0-85.86-generic 6.8.12"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if task.KernelInfo.PackageVersion != "6.8.0-85.85" {
		t.Fatal("host report changed a delivered task")
	}
}

func TestBuildKernelInfoUsesRecentValidGAReport(t *testing.T) {
	st := &State{Hosts: map[string]*model.Host{}}
	now := time.Now()
	add := func(id, signature string, at time.Time) {
		st.Hosts[id] = &model.Host{ID: id, LastSeen: at, Status: model.HostStatus{Kernel: testKernel, KernelSignature: signature}}
	}
	add("legacy", "", now)
	add("hwe", "Ubuntu 6.8.0-85.85~22.04.1-generic 6.8.12", now)
	add("wrong-abi", "Ubuntu 6.8.0-86.86-generic 6.8.12", now)
	if info := buildKernelInfo(st, testKernel); info != nil {
		t.Fatalf("must not invent a GA base from unsupported reports: %+v", info)
	}
	add("old", "Ubuntu 6.8.0-85.85-generic 6.8.12", now.Add(-time.Hour))
	add("current", "Ubuntu 6.8.0-85.86-generic 6.8.12", now.Add(-time.Minute))
	if info := buildKernelInfo(st, testKernel); info == nil || info.PackageVersion != "6.8.0-85.86" {
		t.Fatalf("must prefer the recent valid GA report: %+v", info)
	}
}
