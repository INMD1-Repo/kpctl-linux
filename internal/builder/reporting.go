// 이 파일: builder 패키지의 measurePhase, write, setCacheStats 구현·자료형.
package builder

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"kpctl/internal/client"
	"kpctl/internal/model"
)

type logTail struct {
	data      []byte
	truncated bool
}

func (b *Builder) measurePhase(name string) func() {
	started := time.Now()
	return func() {
		if b.timings != nil {
			b.timings[name] += time.Since(started).Seconds()
		}
	}
}

func (t *logTail) write(p []byte) {
	const limit = model.BuilderLogLimit
	if len(p) >= limit {
		t.truncated = t.truncated || len(t.data)+len(p) > limit
		t.data = append(t.data[:0], p[len(p)-limit:]...)
	} else {
		if extra := len(t.data) + len(p) - limit; extra > 0 {
			copy(t.data, t.data[extra:])
			t.data = t.data[:len(t.data)-extra]
			t.truncated = true
		}
		t.data = append(t.data, p...)
	}
	// A byte cap may cut the first UTF-8 character in a compiler message.
	for len(t.data) > 0 && !utf8.RuneStart(t.data[0]) {
		t.data = t.data[1:]
	}
}

type liveProgress struct {
	mu          sync.Mutex
	activity    model.BuilderActivity
	cache       *model.BuildCacheStats
	log, jobLog logTail
	maintenance string
}

func (b *Builder) setCacheStats(report *model.BuildCacheStats) {
	if b.progress == nil || report == nil {
		return
	}
	copy := *report
	if report.HitRate != nil {
		rate := *report.HitRate
		copy.HitRate = &rate
	}
	b.progress.mu.Lock()
	b.progress.cache = &copy
	b.progress.mu.Unlock()
}

func (p *liveProgress) Write(data []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.log.write(data)
	if p.activity.JobID > 0 {
		p.jobLog.write(data)
	}
	return len(data), nil
}

func (b *Builder) setActivity(a model.BuilderActivity) {
	if b.progress == nil {
		return
	}
	if a.StartedAt.IsZero() {
		a.StartedAt = time.Now()
	}
	a.CVEs = append([]string(nil), a.CVEs...)
	b.progress.mu.Lock()
	if a.JobID > 0 && a.JobID != b.progress.activity.JobID {
		b.progress.jobLog = logTail{}
	}
	b.progress.activity = a
	b.progress.mu.Unlock()
}

func (b *Builder) setStep(step string) {
	if b.progress != nil {
		b.progress.mu.Lock()
		b.progress.activity.Step = step
		b.progress.mu.Unlock()
	}
	if writer := b.liveOutput(); writer != nil {
		_, _ = io.WriteString(writer, "\n"+step+"\n")
	}
}

func (b *Builder) finishActivity(kernel, message string, err error) {
	phase := "idle"
	if err != nil {
		phase, message = "failed", err.Error()
	}
	b.setActivity(model.BuilderActivity{Phase: phase, Kernel: kernel, Message: message})
}

func (b *Builder) identity() model.NextJobRequest {
	req := model.NextJobRequest{Builder: b.cfg.Name, Series: b.cfg.Series, CanRefresh: true, CanPurge: true, CanPrerelease: true, BinarySHA256: b.selfSHA}
	for _, k := range b.cfg.Kernels {
		req.Kernels = append(req.Kernels, k.Kernel)
	}
	return req
}

// StartReporting runs independently from collection/compilation. It stays alive
// during graceful shutdown until the current build has published its result.
func (b *Builder) StartReporting(ctx context.Context) func() {
	return b.startReporting(ctx, 5*time.Second)
}

func (b *Builder) startReporting(ctx context.Context, interval time.Duration) func() {
	if b.c == nil {
		return func() {}
	}
	b.runContext = ctx
	b.progress = &liveProgress{}
	b.setActivity(model.BuilderActivity{Phase: "idle", Message: "작업 대기"})
	previous := log.Writer()
	log.SetOutput(io.MultiWriter(b.progress, previous))
	reportCtx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		var lastWarning time.Time
		for {
			if err := b.reportProgress(reportCtx); err != nil && reportCtx.Err() == nil && time.Since(lastWarning) >= time.Minute {
				log.Printf("빌드 상태 보고 실패 (빌드는 계속 진행): %v", err)
				lastWarning = time.Now()
			}
			select {
			case <-reportCtx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	var once sync.Once
	return func() {
		once.Do(func() {
			cancel()
			<-done
			log.SetOutput(previous)
			b.setActivity(model.BuilderActivity{Phase: "stopped", Message: "빌드 서버 종료"})
			_ = b.reportProgress(context.Background())
		})
	}
}

func (b *Builder) reportProgress(parent context.Context) error {
	p := b.progress
	p.mu.Lock()
	req := model.BuilderHeartbeatRequest{NextJobRequest: b.identity(), Activity: p.activity,
		Log: string(p.log.data), LogTruncated: p.log.truncated, Cache: p.cache, Maintenance: p.maintenance}
	if req.Activity.JobID > 0 {
		req.JobLog = string(p.jobLog.data)
	}
	p.mu.Unlock()
	req.Activity.Message = strings.ToValidUTF8(req.Activity.Message, "�")
	if len(req.Activity.Message) > 4096 {
		req.Activity.Message = req.Activity.Message[:4096]
		for !utf8.ValidString(req.Activity.Message) {
			req.Activity.Message = req.Activity.Message[:len(req.Activity.Message)-1]
		}
	}
	if b.cfg.Token != "" {
		req.Log = strings.ReplaceAll(req.Log, b.cfg.Token, "[REDACTED]")
		req.JobLog = strings.ReplaceAll(req.JobLog, b.cfg.Token, "[REDACTED]")
	}
	req.Resources = builderResources(b.cfg.WorkDir, b.cfg.Jobs)
	if s := b.cfg.Sandbox; s != nil {
		minimum := 60
		if s.Prepare != nil {
			minimum = s.Prepare.MinFreeGiB
		}
		req.Resources.DiskMinimum = uint64(minimum) << 30
	}
	// 실제 빌드 보류와 같은 기준(활성 프로파일의 disk_free_mib)을 확인했으면 그 값을 보냅니다.
	if v := b.diskMinimum.Load(); v > 0 {
		req.Resources.DiskMinimum = v
	}
	req.Environment = "host"
	if b.cfg.Sandbox != nil {
		req.Environment = "isolated"
	}
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	err := b.c.DoContext(ctx, "POST", "/api/builder/heartbeat", req, nil)
	if errors.Is(err, client.ErrNoContent) {
		return nil
	}
	return err
}

func builderResources(workDir string, jobs int) model.BuilderResources {
	r := model.BuilderResources{CPUs: runtime.NumCPU(), Jobs: jobs}
	if data, err := os.ReadFile("/proc/loadavg"); err == nil {
		if fields := strings.Fields(string(data)); len(fields) > 0 {
			r.Load1, _ = strconv.ParseFloat(fields[0], 64)
		}
	}
	if data, err := os.ReadFile("/proc/meminfo"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			n, _ := strconv.ParseUint(fields[1], 10, 64)
			switch fields[0] {
			case "MemTotal:":
				r.MemoryTotal = n * 1024
			case "MemAvailable:":
				r.MemoryAvailable = n * 1024
			}
		}
	}
	var disk syscall.Statfs_t
	if syscall.Statfs(workDir, &disk) == nil {
		r.DiskTotal, r.DiskAvailable = disk.Blocks*uint64(disk.Bsize), disk.Bavail*uint64(disk.Bsize)
	}
	return r
}

func (b *Builder) liveOutput() io.Writer {
	if b.progress != nil {
		return b.progress
	}
	return b.output
}

// The returned output still feeds failure classification and completed logs;
// a second writer makes it visible before the process exits.
func (b *Builder) commandOutput(cmd *exec.Cmd) ([]byte, error) {
	var buf bytes.Buffer
	var writer io.Writer = &buf
	if live := b.liveOutput(); live != nil {
		writer = io.MultiWriter(&buf, live)
	}
	cmd.Stdout, cmd.Stderr = writer, writer
	err := cmd.Run()
	return buf.Bytes(), err
}

// kpatch writes compiler details to a file instead of stdout. Follow only new
// content from this invocation; stale logs must not look like current output.
func (b *Builder) followBuildLog(path string) func() {
	writer := b.liveOutput()
	if writer == nil {
		return func() {}
	}
	initial, _ := os.Stat(path)
	var initialOffset int64
	var initialMarker []byte
	markerAt := func(f *os.File, offset int64) []byte {
		start := offset - 64
		if start < 0 {
			start = 0
		}
		data, _ := io.ReadAll(io.NewSectionReader(f, start, offset-start))
		return data
	}
	if initial != nil {
		if f, err := os.Open(path); err == nil {
			initialOffset = initial.Size()
			initialMarker = markerAt(f, initialOffset)
			_ = f.Close()
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		previous := initial
		offset, marker := initialOffset, initialMarker
		read := func() {
			f, err := os.Open(path)
			if err != nil {
				return
			}
			defer f.Close()
			info, err := f.Stat()
			if err != nil || !info.Mode().IsRegular() {
				return
			}
			if previous == nil || !os.SameFile(previous, info) || info.Size() < offset {
				offset = 0
			} else if offset > 0 && !bytes.Equal(markerAt(f, offset), marker) {
				// A file can be truncated and grow past the old offset between
				// reads. A short marker distinguishes that from an append.
				offset = 0
			}
			previous = info
			// Avoid replaying an unbounded file after a slow filesystem read.
			if info.Size()-offset > model.BuilderLogLimit {
				offset = info.Size() - model.BuilderLogLimit
			}
			n, _ := io.Copy(writer, io.NewSectionReader(f, offset, info.Size()-offset))
			offset += n
			marker = markerAt(f, offset)
		}
		for {
			select {
			case <-ctx.Done():
				read()
				return
			case <-ticker.C:
				read()
			}
		}
	}()
	return func() { cancel(); <-done }
}
