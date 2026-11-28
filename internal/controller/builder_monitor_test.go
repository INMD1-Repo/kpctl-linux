// 이 파일: controller 패키지의 TestBuilderHeartbeatKeepsLongBuildAndLiveLogs, TestBusyBuilderRequeuesWithoutBlockingRollout, TestOnlyCurrentBuilderAttemptRenewsJob 회귀 시험.
package controller

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"kpctl/internal/model"
)

func heartbeat(t *testing.T, s *Server, req model.BuilderHeartbeatRequest, want int) {
	t.Helper()
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	callBuilderAPI(t, s, "POST", "/api/builder/heartbeat", string(data), want)
}

func postBuildResult(t *testing.T, s *Server, id int, res model.BuildResult, want int) string {
	t.Helper()
	body, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	return callBuilderAPI(t, s, "POST", fmt.Sprintf("/api/builder/jobs/%d/result", id), string(body), want)
}

func TestBuilderHeartbeatKeepsLongBuildAndLiveLogs(t *testing.T) {
	s := newAutoServer(t, AutoRollout{})
	id := addBuilt(t, s, "ubuntu")
	started := time.Now().Add(-4 * time.Hour)
	if err := s.store.Update(func(st *State) error {
		j := st.job(id)
		j.Status, j.Builder, j.StartedAt, j.HeartbeatAt = model.JobRunning, "b1", started, time.Time{}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	req := model.BuilderHeartbeatRequest{NextJobRequest: model.NextJobRequest{Builder: "b1", Series: "noble", CanRefresh: true},
		Activity:    model.BuilderActivity{Phase: "building", Kernel: testKernel, JobID: id, JobStartedAt: started, Step: "compile"},
		Environment: "isolated", Log: "service and compiler output", JobLog: "still compiling", Resources: model.BuilderResources{CPUs: 10, DiskAvailable: 63 << 30}}
	rate := 0.4
	req.Maintenance = "비활성 14일 프로파일 정리 완료"
	req.Resources.DiskMinimum = 60 << 30
	req.Cache = &model.BuildCacheStats{Enabled: true, Kernel: testKernel, Hits: 40, Misses: 60, HitRate: &rate, Warning: "70% 미만", BuildSeconds: 80}
	heartbeat(t, s, req, http.StatusNoContent)
	callBuilderAPI(t, s, "POST", "/api/builder/next", `{"builder":"other","series":"noble"}`, http.StatusNoContent)
	if body := callAPI(t, s, "GET", "/api/jobs/1/log", "", http.StatusOK); body != req.JobLog {
		t.Fatal(body)
	}
	// A normal queue poll must not erase the independently reported activity.
	callBuilderAPI(t, s, "POST", "/api/builder/next", `{"builder":"b1","series":"noble"}`, http.StatusNoContent)
	s.store.View(func(st *State) {
		if st.job(id).Status != model.JobRunning || st.Builders["b1"].Activity.Step != "compile" {
			t.Fatal("healthy long build lost")
		}
	})
	// Status, resources, and log survive a controller restart.
	s2, err := NewServer(s.cfg)
	if err != nil {
		t.Fatal(err)
	}
	var detail model.BuilderDetail
	if err := json.Unmarshal([]byte(callAPI(t, s2, "GET", "/api/builders/b1", "", http.StatusOK)), &detail); err != nil {
		t.Fatal(err)
	}
	if detail.Log != req.Log || detail.Builder.Resources.CPUs != 10 || detail.Builder.Environment != "isolated" {
		t.Fatalf("lost report: %+v", detail)
	}
	if detail.Builder.Cache == nil || detail.Builder.Cache.Hits != 40 || detail.Builder.Cache.Warning != "70% 미만" {
		t.Fatal("cache measurements or warning lost across controller restart")
	}
	if detail.Builder.Maintenance != req.Maintenance || detail.Builder.Resources.DiskMinimum != 60<<30 {
		t.Fatal("maintenance or disk threshold lost")
	}
	postBuildResult(t, s2, id, model.BuildResult{Builder: "b1", JobStartedAt: &started, Error: "review needed", Log: "complete failure log"}, http.StatusOK)
	req.JobLog = "late live output"
	heartbeat(t, s2, req, http.StatusNoContent)
	if body := callAPI(t, s2, "GET", "/api/jobs/1/log", "", http.StatusOK); body != "complete failure log" {
		t.Fatalf("final log overwritten: %s", body)
	}
}

func TestOnlyCurrentBuilderAttemptCanFinishJob(t *testing.T) {
	s := newAutoServer(t, AutoRollout{})
	id := addBuilt(t, s, "ubuntu")
	oldStart := time.Now().Add(-4 * time.Hour)
	const builder = "builder"
	if err := s.store.Update(func(st *State) error {
		j := st.job(id)
		j.Status, j.Builder, j.StartedAt = model.JobRunning, builder, oldStart
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// The same builder name can reclaim the job, so the start time must also match.
	var replacement model.BuildTask
	body := callBuilderAPI(t, s, "POST", "/api/builder/next", `{"builder":"builder","series":"noble"}`, http.StatusOK)
	if err := json.Unmarshal([]byte(body), &replacement); err != nil {
		t.Fatal(err)
	}
	if replacement.Job.ID != id || !replacement.Job.StartedAt.After(oldStart) {
		t.Fatalf("job was not reassigned: %+v", replacement.Job)
	}
	module := replacement.Job.ModuleName
	path := s.artifactFile(testKernel, module)
	livePath := s.liveLogFile(id)
	if err := os.WriteFile(livePath, []byte("replacement in progress"), 0o640); err != nil {
		t.Fatal(err)
	}
	staleSuccess := model.BuildResult{Success: true, Builder: builder, JobStartedAt: &oldStart,
		Log: "stale success", ModuleName: module, ModuleBase64: base64.StdEncoding.EncodeToString([]byte("stale module"))}
	staleFailure := model.BuildResult{Builder: "other", JobStartedAt: &replacement.Job.StartedAt, Error: "old failure", Log: "stale failure"}
	for _, stale := range []model.BuildResult{staleSuccess, staleFailure} {
		if body := postBuildResult(t, s, id, stale, http.StatusOK); !strings.Contains(body, `"result":"ignored"`) {
			t.Fatalf("stale result was not ignored: %s", body)
		}
	}
	postBuildResult(t, s, id, model.BuildResult{Error: "old protocol", Log: "no attempt"}, http.StatusBadRequest)
	s.store.View(func(st *State) {
		if j := st.job(id); j.Status != model.JobRunning || !j.StartedAt.Equal(replacement.Job.StartedAt) || st.Tracks[testKernel].AutoHold != "" {
			t.Errorf("stale result changed the assigned job or rollout: %+v", j)
		}
	})
	if data, err := os.ReadFile(path); err != nil || string(data) != "module" {
		t.Fatalf("stale result changed artifact: %q, %v", data, err)
	}
	if data, err := os.ReadFile(livePath); err != nil || string(data) != "replacement in progress" {
		t.Fatalf("stale result changed live log: %q, %v", data, err)
	}
	if _, err := os.Stat(s.logFile(id)); !os.IsNotExist(err) {
		t.Fatalf("stale result created a final log: %v", err)
	}

	current := staleSuccess
	current.JobStartedAt = &replacement.Job.StartedAt
	current.Log = "completed by replacement"
	current.ModuleBase64 = base64.StdEncoding.EncodeToString([]byte("replacement module"))
	postBuildResult(t, s, id, current, http.StatusOK)
	postBuildResult(t, s, id, staleSuccess, http.StatusOK)
	if data, err := os.ReadFile(path); err != nil || string(data) != "replacement module" {
		t.Fatalf("replacement artifact was lost: %q, %v", data, err)
	}
	if log := callAPI(t, s, "GET", fmt.Sprintf("/api/jobs/%d/log", id), "", http.StatusOK); log != current.Log {
		t.Fatalf("replacement log was lost: %q", log)
	}
}

func TestBusyBuilderRequeuesWithoutBlockingRollout(t *testing.T) {
	s := newAutoServer(t, AutoRollout{})
	id := addBuilt(t, s, "ubuntu")
	started := time.Now()
	if err := s.store.Update(func(st *State) error {
		j := st.job(id)
		j.Status, j.Builder = model.JobRunning, "busy-builder"
		j.StartedAt, j.HeartbeatAt = started, started
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	path := fmt.Sprintf("/api/builder/jobs/%d/result", id)
	deferred, _ := json.Marshal(model.BuildResult{Deferred: true, Builder: "busy-builder", JobStartedAt: &started, Error: "account busy", Log: "waiting for manual build"})
	callBuilderAPI(t, s, "POST", path, string(deferred), http.StatusOK)
	s.store.View(func(st *State) {
		j := st.job(id)
		if j.Status != model.JobQueued || j.Error != "" || j.Builder != "" || !j.StartedAt.IsZero() || !j.HeartbeatAt.IsZero() {
			t.Fatalf("busy job was failed or retained an old lease: %+v", j)
		}
		if hold := st.track(j.Kernel).AutoHold; hold != "" {
			t.Fatalf("contention blocked rollout: %s", hold)
		}
	})
	callBuilderAPI(t, s, "POST", "/api/builder/next", `{"builder":"replacement","series":"noble"}`, http.StatusOK)
	callBuilderAPI(t, s, "POST", path, string(deferred), http.StatusOK)
	s.store.View(func(st *State) {
		if j := st.job(id); j.Status != model.JobRunning || j.Builder != "replacement" {
			t.Fatal("stale busy response interrupted the replacement build")
		}
	})
	callBuilderAPI(t, s, "POST", path, `{"success":true,"deferred":true,"module_name":"invalid"}`, http.StatusBadRequest)
}

func TestOnlyCurrentBuilderAttemptRenewsJob(t *testing.T) {
	s := newAutoServer(t, AutoRollout{})
	id := addBuilt(t, s, "ubuntu")
	started := time.Now().Add(-4 * time.Hour)
	if err := s.store.Update(func(st *State) error {
		j := st.job(id)
		j.Status, j.Builder, j.StartedAt = model.JobRunning, "current", started
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, req := range []model.BuilderHeartbeatRequest{
		{NextJobRequest: model.NextJobRequest{Builder: "other"}, Activity: model.BuilderActivity{JobID: id, Kernel: testKernel, JobStartedAt: started}},
		{NextJobRequest: model.NextJobRequest{Builder: "current"}, Activity: model.BuilderActivity{JobID: id, Kernel: testKernel, JobStartedAt: started.Add(-time.Second)}},
	} {
		heartbeat(t, s, req, http.StatusNoContent)
	}
	s.store.View(func(st *State) {
		if !st.job(id).HeartbeatAt.IsZero() {
			t.Fatal("wrong owner renewed job")
		}
	})
	callBuilderAPI(t, s, "POST", "/api/builder/next", `{"builder":"replacement","series":"noble"}`, http.StatusOK)
	s.store.View(func(st *State) {
		if st.job(id).Builder != "replacement" {
			t.Fatal("dead job not reclaimed")
		}
	})
	if _, err := os.Stat(s.liveLogFile(id)); !os.IsNotExist(err) {
		t.Fatal("stale attempt log retained")
	}
	if body := callAPI(t, s, "GET", "/api/jobs/1/log", "", http.StatusOK); !strings.Contains(body, "첫 로그") {
		t.Fatal(body)
	}
}

func TestBuilderMonitorAuthenticationAndBounds(t *testing.T) {
	s := newAutoServer(t, AutoRollout{})
	callAPI(t, s, "POST", "/api/builder/heartbeat", `{"builder":"b1"}`, http.StatusUnauthorized)
	callBuilderAPI(t, s, "GET", "/api/builders/b1", "", http.StatusUnauthorized)
	callAPI(t, s, "GET", "/api/builders/missing", "", http.StatusNotFound)
	for _, name := range []string{"", "../escape", "bad\nname"} {
		heartbeat(t, s, model.BuilderHeartbeatRequest{NextJobRequest: model.NextJobRequest{Builder: name}}, http.StatusBadRequest)
	}
	heartbeat(t, s, model.BuilderHeartbeatRequest{NextJobRequest: model.NextJobRequest{Builder: "b1"}, Log: strings.Repeat("x", model.BuilderLogLimit+1)}, http.StatusBadRequest)
	// Compiler output can contain JSON escapes. The advertised 256 KiB limit
	// applies to the decoded log, including a full active job tail.
	escaped := strings.Repeat("\x01", model.BuilderLogLimit)
	heartbeat(t, s, model.BuilderHeartbeatRequest{NextJobRequest: model.NextJobRequest{Builder: "escaped"}, Log: escaped, JobLog: escaped}, http.StatusNoContent)
	callAPI(t, s, "GET", "/api/jobs/999/log", "", http.StatusNotFound)
}

func TestLatestCumulativeUpdateSkipsAndPinsVersions(t *testing.T) {
	s := newAutoServer(t, AutoRollout{})
	addHost(t, s, "target", 2)
	for i := 0; i < 5; i++ {
		id := addBuilt(t, s, "ubuntu")
		callAPI(t, s, "POST", "/api/jobs/"+leftPad(id)+"/approve", "", http.StatusOK)
	}
	if err := s.store.Update(func(st *State) error {
		h := st.Hosts["target"]
		h.Status.Version = 1
		h.UpdateNowKernel, h.UpdateNowVersion = testKernel, 2
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	path := "/api/hosts/target/update-now"
	callAPI(t, s, "POST", path, `{"kernel":"wrong-kernel","version":5}`, http.StatusConflict)
	callAPI(t, s, "POST", path, `{"kernel":"`+testKernel+`","version":4}`, http.StatusConflict)
	if desiredFor(s, "target") != 2 {
		t.Fatal("rejected request changed target")
	}
	callAPI(t, s, "POST", path, `{"kernel":"`+testKernel+`","version":5}`, http.StatusOK)
	if desiredFor(s, "target") != 5 || ringVersion(s, 2) != 0 {
		t.Fatal("must jump directly to v5 for this host")
	}
	s.store.View(func(st *State) {
		if h := st.Hosts["target"]; h.Status.Version != 1 || h.RebootApproval != nil {
			t.Fatal("request must await actual agent application")
		}
	})
	addBuilt(t, s, "ubuntu") // An unsigned/unapproved v6 is never an update target.
	callAPI(t, s, "POST", path, `{"kernel":"`+testKernel+`","version":5}`, http.StatusOK)
	if desiredFor(s, "target") != 5 {
		t.Fatal("unapproved build was selected")
	}
}

func TestNativeIdleHeartbeatPreservesCompilerLog(t *testing.T) {
	s := newAutoServer(t, AutoRollout{})
	req := model.BuilderHeartbeatRequest{
		NextJobRequest: model.NextJobRequest{Builder: "rocky", Series: "rocky10"},
		Activity:       model.BuilderActivity{Phase: "trial"}, Environment: "distribution",
		Log: "compiler output", LogTruncated: true,
	}
	heartbeat(t, s, req, http.StatusNoContent)
	req.Activity.Phase, req.Log, req.LogTruncated = "idle", "", false
	heartbeat(t, s, req, http.StatusNoContent)
	var detail model.BuilderDetail
	if err := json.Unmarshal([]byte(callAPI(t, s, "GET", "/api/builders/rocky", "", http.StatusOK)), &detail); err != nil {
		t.Fatal(err)
	}
	if detail.Log != "compiler output" || !detail.Builder.LogTruncated || detail.Builder.Activity.Phase != "idle" {
		t.Fatalf("idle status lost compiler output: %+v", detail)
	}
}
