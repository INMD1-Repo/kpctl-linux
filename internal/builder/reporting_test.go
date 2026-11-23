// 이 파일: builder 패키지의 TestLiveReportArrivesBeforeCompilerExits, TestLiveLogBoundAndJobIsolation, TestLongFailureMessageStillReports 회귀 시험.
package builder

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"kpctl/internal/client"
	"kpctl/internal/model"
)

func TestLiveReportArrivesBeforeCompilerExits(t *testing.T) {
	reports := make(chan model.BuilderHeartbeatRequest, 100)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var report model.BuilderHeartbeatRequest
		if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		select {
		case reports <- report:
		default:
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	c, err := client.New(server.URL, "test-builder-secret", "")
	if err != nil {
		t.Fatal(err)
	}
	b := &Builder{cfg: &Config{Name: "live-test", Token: "test-builder-secret", WorkDir: t.TempDir(), Jobs: 2}, c: c}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stop := b.startReporting(ctx, 10*time.Millisecond)
	defer stop()
	b.setActivity(model.BuilderActivity{Phase: "building", Kernel: "6.8.0-136-generic", JobID: 7, JobStartedAt: time.Now()})
	log.Print("credential test: test-builder-secret")
	input, release := io.Pipe()
	defer input.Close()
	defer release.Close()
	cmd := exec.Command("sh", "-c", "printf 'compiler started\\n'; read finish")
	cmd.Stdin = input
	finished := make(chan error, 1)
	go func() { _, err := b.commandOutput(cmd); finished <- err }()
	deadline := time.After(3 * time.Second)
	for {
		select {
		case report := <-reports:
			if !strings.Contains(report.JobLog, "compiler started") {
				continue
			}
			if report.Activity.JobID != 7 || strings.Contains(report.Log, "test-builder-secret") || !strings.Contains(report.Log, "[REDACTED]") {
				t.Fatalf("invalid live report: %+v", report)
			}
			select {
			case <-finished:
				t.Fatal("compiler exited before report")
			default:
			}
			// A graceful stop request must keep reporting until the build ends.
			cancel()
			_, _ = b.progress.Write([]byte("finishing after stop"))
			continued := false
			for !continued {
				select {
				case next := <-reports:
					continued = strings.Contains(next.JobLog, "finishing after stop")
				case <-deadline:
					t.Fatal("reporting stopped before the active build finished")
				}
			}
			_, _ = io.WriteString(release, "done\n")
			_ = release.Close()
			select {
			case err := <-finished:
				if err != nil {
					t.Fatal(err)
				}
			case <-deadline:
				t.Fatal("compiler did not finish")
			}
			return
		case <-deadline:
			t.Fatal("no live compiler output before exit")
		}
	}
}

func TestLiveLogBoundAndJobIsolation(t *testing.T) {
	b := &Builder{progress: &liveProgress{}}
	b.setActivity(model.BuilderActivity{Phase: "building", JobID: 1})
	_, _ = b.progress.Write([]byte(strings.Repeat("가", model.BuilderLogLimit)))
	if len(b.progress.log.data) > model.BuilderLogLimit || !b.progress.log.truncated || !utf8.Valid(b.progress.log.data) {
		t.Fatal("unbounded or broken UTF-8 log")
	}
	b.setActivity(model.BuilderActivity{Phase: "building", JobID: 2})
	_, _ = b.progress.Write([]byte("new job only"))
	if string(b.progress.jobLog.data) != "new job only" {
		t.Fatal("previous job leaked into new log")
	}
}

func TestLongFailureMessageStillReports(t *testing.T) {
	reports := make(chan model.BuilderHeartbeatRequest, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var report model.BuilderHeartbeatRequest
		if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
			t.Error(err)
		}
		reports <- report
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	c, err := client.New(server.URL, "test-builder-token", "")
	if err != nil {
		t.Fatal(err)
	}
	b := &Builder{cfg: &Config{Name: "long-error", WorkDir: t.TempDir()}, c: c, progress: &liveProgress{}}
	b.setActivity(model.BuilderActivity{Phase: "failed", Message: strings.Repeat("긴 오류", 5000)})
	b.progress.jobLog.write([]byte("previous job"))
	if err := b.reportProgress(context.Background()); err != nil {
		t.Fatal(err)
	}
	received := <-reports
	if received.Activity.Message == "" || len(received.Activity.Message) > 4096 || !utf8.ValidString(received.Activity.Message) || received.JobLog != "" {
		t.Fatal("failure report cannot be sent")
	}
}

func TestFollowBuildLogDoesNotReplayOldOutput(t *testing.T) {
	for _, kind := range []string{"unchanged", "append", "rewrite", "replace"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "build.log")
			if err := os.WriteFile(path, []byte("old output"), 0o600); err != nil {
				t.Fatal(err)
			}
			var output bytes.Buffer
			b := &Builder{output: &output}
			stop := b.followBuildLog(path)
			want := ""
			switch kind {
			case "append":
				f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
				if err != nil {
					t.Fatal(err)
				}
				_, _ = f.WriteString("new output")
				_ = f.Close()
				want = "new output"
			case "rewrite":
				want = "replacement output longer than old output"
				if err := os.WriteFile(path, []byte(want), 0o600); err != nil {
					t.Fatal(err)
				}
			case "replace":
				want = "new generation"
				if err := os.WriteFile(path+".new", []byte(want), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(path+".new", path); err != nil {
					t.Fatal(err)
				}
			}
			stop()
			if output.String() != want {
				t.Fatalf("live log = %q, want %q", output.String(), want)
			}
		})
	}
}
