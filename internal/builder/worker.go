// 이 파일: 빌드 우선 처리·독립 수집 주기와 worker 수명.
package builder

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"kpctl/internal/client"
	"kpctl/internal/model"
)

type Builder struct {
	cfg     *Config
	c       *client.Client
	selfSHA string // 지금 실행 파일의 sha256 (자동 업데이트, 웹 표시용)

	// RestartForUpdate: 새 실행 파일을 받아 두어 재시작이 필요함 (main 이 종료 코드 75 로 끝냄)
	RestartForUpdate bool

	debugFailed       map[string]debugFailure // 디버그 심볼 자동 설치 실패 (커널별, 6시간 뒤 재시도)
	lastProblem       map[string]string       // 컨트롤러에 마지막으로 알린 수집 문제 (커널별)
	lastProblemKind   map[string]string
	lastOutside       map[string]kernelRangeReport // 컨트롤러에 마지막으로 알린 범위 밖 사유와 공식 최신 태그 (커널별)
	lastWindow        kernelRange                  // 마지막으로 확인에 성공한 최근 커널 범위 (일시 장애 때 사용)
	tagFailures       map[string]int               // 새 태그 확인 연속 실패 횟수 (커널별)
	diskBlocked       bool
	diskChecked       bool
	diskCleanupAt     time.Time // 예방 정리 시도는 재시작 뒤 처음과 이후 시간당 한 번
	lastDiskProblem   string    // 같은 디스크 부족 로그를 반복하지 않음
	purgePending      map[string]bool
	diskMinimum       atomic.Uint64     // 마지막으로 확인한 빌드 보류 기준(바이트). 하트비트 고루틴이 읽습니다.
	lastTarget        map[string]string // 마지막 수집에서 확인한 정식 배포 태그
	runContext        context.Context
	progress          *liveProgress
	output            io.Writer // offline worker output; never contains controller credentials
	headersRoot       string    // empty uses /usr/src
	modulesRoot       string    // empty uses /lib/modules
	activeKernels     []string
	profileFailed     map[string]debugFailure
	archiveJobRetryAt map[int]time.Time // only the work loop reads or writes this map
	timings           map[string]float64
	retryDiscovery    bool
	deferredDiscovery map[string]bool
	discoveryRetryAt  time.Time
	prereleaseNext    map[string]time.Time // 공식 수집 주기·범위와 독립적인 커널별 다음 확인
	cveFeedSnapshot   *cveFeedSnapshot     // URL·검증한 Git commit이 같으면 CNA 매핑 재파싱 생략
}

func New(cfg *Config) (*Builder, error) {
	c, err := client.New(cfg.ControllerURL, cfg.Token, cfg.CAFile)
	if err != nil {
		return nil, err
	}
	return &Builder{cfg: cfg, c: c, selfSHA: selfSHA256()}, nil
}

// Run 은 빌드 서버 메인 루프입니다.
//
// kpatch-build 는 같은 사용자 계정에서 동시에 두 개를 돌리면 캐시(~/.kpatch)가 꼬이므로,
// 빌드 작업과 자동 수집(시험 빌드 포함)을 한 루프에서 차례로 처리합니다.
func (b *Builder) Run(ctx context.Context) {
	b.runContext = ctx
	discoverEvery := time.Duration(*b.cfg.DiscoverMinutes) * time.Minute
	checkEvery := time.Duration(*b.cfg.UpdateCheckMinutes) * time.Minute
	log.Printf("빌드 서버 시작: %s → %s (자동 수집 %s마다, 새 태그 확인 %s마다)",
		b.cfg.Name, b.cfg.ControllerURL, every(discoverEvery), every(checkEvery))
	var lastDiscover, lastCheck, lastUpdate time.Time
	more := false // 시험 빌드 한도에 걸려 남은 커밋이 있음
	if b.updatePath() == "" {
		log.Printf("자동 업데이트 꺼짐 (self_update=false 이거나 서비스 파일에 KPCTL_BUILDER_UPDATE_PATH 가 없음)")
	}
	for {
		if b.stopping() {
			log.Printf("빌드 서버 종료: 진행 중이던 빌드 결과를 보존했습니다")
			return
		}
		// 0) 자동 업데이트: 시작할 때와 10분마다 (작업 사이에만 하므로 빌드가 끊기지 않음)
		if time.Since(lastUpdate) >= 10*time.Minute {
			lastUpdate = time.Now()
			if b.CheckUpdate() {
				b.RestartForUpdate = true
				log.Printf("새 버전으로 바꾸려고 종료합니다")
				return
			}
		}

		// 1) 빌드 작업이 있으면 먼저 처리 (긴급 패치가 자동 수집에 밀리지 않도록)
		if b.BuildNext() {
			continue // 연달아 있을 수 있으니 바로 다시 확인
		}
		// A manual refresh must survive contention even when automatic
		// collection is disabled.
		if len(b.deferredDiscovery) > 0 && !time.Now().Before(b.discoveryRetryAt) {
			var names []string
			for name := range b.deferredDiscovery {
				names = append(names, name)
			}
			b.deferredDiscovery = nil
			b.DiscoverKernels(names)
			continue
		}

		// 2) 자동 수집: 주기가 됐거나, 남은 커밋이 있거나, 원격에 새 태그가 올라왔으면 바로
		if discoverEvery > 0 {
			due := more || time.Since(lastDiscover) >= discoverEvery ||
				b.retryDiscovery && time.Since(lastDiscover) >= time.Duration(b.cfg.PollSeconds)*time.Second
			if !due && checkEvery > 0 && time.Since(lastCheck) >= checkEvery {
				lastCheck = time.Now()
				due = b.UpdatesAvailable()
			}
			if due {
				more = b.DiscoverAll()
				lastDiscover, lastCheck = time.Now(), time.Now()
				continue // 새 패치가 있으면 컨트롤러가 만든 빌드 작업을 바로 가져감
			}
		}

		// 출시 전 수집은 discover_minutes와 독립적이며 명시적으로 켠 커널만 확인합니다.
		if b.DiscoverPrereleases() {
			continue
		}

		select {
		case <-ctx.Done():
			log.Printf("빌드 서버 종료")
			return
		case <-time.After(time.Duration(b.cfg.PollSeconds) * time.Second):
		}
	}
}

func (b *Builder) stopping() bool {
	return b.runContext != nil && b.runContext.Err() != nil
}

func (b *Builder) deferDiscovery(kernel string) {
	if b.deferredDiscovery == nil {
		b.deferredDiscovery = map[string]bool{}
	}
	b.deferredDiscovery[kernel] = true
	b.discoveryRetryAt = time.Now().Add(time.Duration(b.cfg.PollSeconds) * time.Second)
}

// BuildNext 는 컨트롤러에서 작업을 하나 가져와 빌드하고 결과를 올립니다.
// 처리한 작업이 있으면 true.
func (b *Builder) BuildNext() bool {
	if b.stopping() {
		return false
	}
	if !b.ensureBuildSpace() {
		return false
	}
	req := b.nextRequest(time.Now())
	var task model.BuildTask
	err := b.c.Do("POST", "/api/builder/next", req, &task)
	if errors.Is(err, client.ErrNoContent) {
		return false
	}
	if err != nil {
		// 컨트롤러 재시작·재부팅 중의 연결 거부나 5xx 는 빌더 고장이 아닙니다. 활동을 "failed"로
		// 바꾸면 컨트롤러가 돌아와 "할 일 없음"(204)을 줘도 되돌릴 곳이 없어 웹에 실패로 계속 남습니다.
		// 연결이 끊긴 동안의 상태는 컨트롤러가 last_seen 으로 판단하므로 여기서는 로그만 남기고
		// 다음 폴링에서 다시 요청합니다. 인증 거부 같은 4xx 는 사람이 고쳐야 하므로 그대로 실패로 보입니다.
		if client.Retryable(err) {
			log.Printf("컨트롤러 연결 실패, %d초 뒤 다시 요청: %v", b.cfg.PollSeconds, err)
			return false
		}
		log.Printf("작업 요청 실패: %v", err)
		b.finishActivity("", "", err)
		return false
	}

	if task.Job.ID == 0 {
		// 관리자가 웹에서 "빌드"를 눌러 바로 수집을 요청함 → 수집하면 컨트롤러가 빌드 작업을 만듦
		if len(task.Purge) > 0 {
			b.PurgeKernels(task.Purge)
		}
		if len(task.Refresh) > 0 {
			log.Printf("관리자 요청으로 바로 수집: %v", task.Refresh)
			b.DiscoverKernels(task.Refresh)
			return true
		}
		return len(task.Purge) > 0
	}
	job := task.Job
	b.setActivity(model.BuilderActivity{Phase: "building", Kernel: job.Kernel, JobID: job.ID, Version: job.Version,
		JobStartedAt: job.StartedAt, Message: fmt.Sprintf("작업 %d · v%d 누적 패치 %d개", job.ID, job.Version, len(task.Patches))})
	log.Printf("빌드 시작: job %d kernel=%s v%d 패치 %d개 urgent=%v",
		job.ID, job.Kernel, job.Version, len(task.Patches), job.Urgent)

	result := b.build(task)
	result.Builder, result.JobStartedAt = b.cfg.Name, &job.StartedAt
	if result.Deferred {
		log.Printf("빌드 대기: job %d · %s", job.ID, result.Error)
	} else if result.Success {
		log.Printf("빌드 성공: job %d → %s", job.ID, result.ModuleName)
	} else {
		log.Printf("빌드 실패: job %d: %s", job.ID, result.Error)
	}

	b.setStep("결과 전송")
	if err := b.sendResult(job.ID, result); err != nil {
		log.Printf("결과 업로드 실패 job %d: %v (컨트롤러가 시간 초과 후 다시 대기열에 넣습니다)", job.ID, err)
		b.finishActivity(job.Kernel, "", err)
	} else if result.Deferred {
		b.finishActivity(job.Kernel, firstLineOf(result.Error), nil)
	} else if result.Success {
		b.finishActivity(job.Kernel, fmt.Sprintf("작업 %d 빌드 성공 · 승인 대기", job.ID), nil)
	} else {
		b.finishActivity(job.Kernel, "", errors.New(result.Error))
	}
	return !result.Deferred
}

func (b *Builder) nextRequest(now time.Time) model.NextJobRequest {
	req := b.identity()
	for id, retryAt := range b.archiveJobRetryAt {
		if now.Before(retryAt) {
			req.DeferredJobIDs = append(req.DeferredJobIDs, id)
		} else {
			delete(b.archiveJobRetryAt, id)
		}
	}
	return req
}

func (b *Builder) failedJob(id int, err error, log string) model.BuildResult {
	var outage *archiveCooldown
	if errors.As(err, &outage) {
		if b.archiveJobRetryAt == nil {
			b.archiveJobRetryAt = make(map[int]time.Time)
		}
		b.archiveJobRetryAt[id] = outage.retryAt
	}
	return model.BuildResult{Error: err.Error(), Log: log, Deferred: errors.Is(err, errBuildDeferred)}
}

// resultRetryDelays 는 결과 업로드를 다시 보내기 전 기다리는 시간입니다 (합계 약 4분).
// 긴 빌드가 끝난 순간 컨트롤러 재시작·일시 장애로 결과를 잃고 처음부터 다시 빌드하지 않게 합니다.
var resultRetryDelays = []time.Duration{5 * time.Second, 15 * time.Second, 30 * time.Second, 60 * time.Second, 120 * time.Second}

// sendResult 는 빌드 결과를 보냅니다. 컨트롤러는 이미 끝난 작업의 결과를 무시하므로 다시 보내도 안전합니다.
func (b *Builder) sendResult(id int, result model.BuildResult) error {
	path := fmt.Sprintf("/api/builder/jobs/%d/result", id)
	err := b.c.Do("POST", path, result, nil)
	for _, delay := range resultRetryDelays {
		if !client.Retryable(err) {
			return err
		}
		log.Printf("결과 업로드 실패 job %d: %v (%s 뒤 다시 보냄)", id, err, delay)
		time.Sleep(delay)
		err = b.c.Do("POST", path, result, nil)
	}
	return err
}

// build 는 작업 하나를 실제로 빌드합니다.
func (b *Builder) build(task model.BuildTask) model.BuildResult {
	job := task.Job
	for _, p := range task.Patches {
		if err := p.Validate(); err != nil {
			return model.BuildResult{Error: err.Error()}
		}
	}
	if task.KernelInfo != nil {
		if err := task.KernelInfo.Validate(job.Kernel); err != nil {
			return model.BuildResult{Error: err.Error()}
		}
	}
	dir := filepath.Join(b.cfg.WorkDir, fmt.Sprintf("job-%d", job.ID))
	_ = os.RemoveAll(dir)
	patchDir := filepath.Join(dir, "patches")
	if err := os.MkdirAll(patchDir, 0o750); err != nil {
		return model.BuildResult{Error: err.Error()}
	}

	k, err := b.resolveTaskKernel(task)
	if err != nil {
		return b.failedJob(job.ID, err, "")
	}
	// 패치마다 들어 있는 선행 커밋 묶음을 풀어 중복을 없애고 git 이력 순서로 저장 (prereq.go)
	var labels, contents []string
	for _, p := range task.Patches {
		labels = append(labels, p.ID)
		contents = append(contents, p.Content)
	}
	files, err := writePatchUnits(patchDir, flattenPatches(k.GitDir, labels, contents))
	if err != nil {
		return model.BuildResult{Error: err.Error()}
	}
	out, err := b.runBuild(k, moduleName(job.Kernel, job.Version), filepath.Join(dir, "out"), files)
	if err != nil {
		return b.failedJob(job.ID, err, out.Log)
	}

	data, err := os.ReadFile(out.ModulePath)
	if err != nil {
		return model.BuildResult{Error: err.Error(), Log: out.Log}
	}
	_ = os.RemoveAll(dir) // 성공하면 작업 디렉터리 정리 (실패 시에는 디버깅용으로 남김)
	return model.BuildResult{
		Success:      true,
		Log:          out.Log,
		ModuleName:   out.ModuleName,
		ModuleBase64: base64.StdEncoding.EncodeToString(data),
	}
}

func every(d time.Duration) string {
	if d <= 0 {
		return "끔"
	}
	return d.String()
}
