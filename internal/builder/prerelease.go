// 이 파일: 명시적으로 켠 커널의 출시 전 브랜치를 별도 주기로 수집합니다.
// 출시 전 수집 결과는 정식 APT 상한·수집 완료 태그를 바꾸지 않습니다.
// 공통 빌드 환경의 안전 보류는 유지하며 커밋별 재시험 기록과 검토 증거는 분리합니다.
package builder

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"kpctl/internal/model"
)

type prereleaseEvidence struct {
	Kernel       string              `json:"kernel"`
	Branch       string              `json:"branch"`
	PublishedTag string              `json:"published_tag,omitempty"`
	TipCommit    string              `json:"tip_commit,omitempty"`
	StartedAt    time.Time           `json:"started_at"`
	FinishedAt   time.Time           `json:"finished_at"`
	More         bool                `json:"more"`
	Failure      *model.TrialFailure `json:"failure,omitempty"`
	Error        string              `json:"error,omitempty"`
}

func (p PrereleaseConfig) branch() string {
	if p.Branch == "" {
		return "master-next"
	}
	return p.Branch
}

func (p PrereleaseConfig) interval() time.Duration {
	if p.PollMinutes <= 0 {
		return 30 * time.Minute
	}
	return time.Duration(p.PollMinutes) * time.Minute
}

// DiscoverPrereleases는 정식 discover_minutes와 독립적으로 due인 명시 커널만 확인합니다.
// true는 한 커널 이상 확인했음을 뜻합니다. 호출자는 새 빌드 작업부터 다시 확인합니다.
func (b *Builder) DiscoverPrereleases() bool {
	return b.discoverPrereleasesAt(time.Now())
}

func (b *Builder) discoverPrereleasesAt(now time.Time) bool {
	ran := false
	for _, k := range b.cfg.Kernels {
		if b.stopping() {
			return ran
		}
		if k.Prerelease == nil || !k.Prerelease.Enabled || now.Before(b.prereleaseNext[k.Kernel]) {
			continue
		}
		if b.prereleaseNext == nil {
			b.prereleaseNext = map[string]time.Time{}
		}
		ran = true
		more, err := b.discoverPrerelease(k)
		next := time.Now().Add(k.Prerelease.interval())
		if err == nil && more {
			next = time.Time{} // 시험 한도로 남은 후보는 빌드 작업 사이에서 계속 확인합니다.
		} else if errors.Is(err, errBuildBusy) {
			seconds := b.cfg.PollSeconds
			if seconds <= 0 {
				seconds = 30
			}
			next = time.Now().Add(time.Duration(seconds) * time.Second)
		}
		b.prereleaseNext[k.Kernel] = next
		if err != nil {
			log.Printf("[%s] 출시 전 수집 검토 필요: %v (prerelease/%s.json 확인)", k.Kernel, err, k.Kernel)
		}
	}
	return ran
}

func (b *Builder) savePrereleaseEvidence(evidence prereleaseEvidence) error {
	if !sandboxKernel.MatchString(evidence.Kernel) {
		return fmt.Errorf("출시 전 검토 기록의 커널 이름이 올바르지 않습니다")
	}
	dir := filepath.Join(b.cfg.WorkDir, "prerelease")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	data, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(dir, ".prerelease-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), filepath.Join(dir, evidence.Kernel+".json"))
}

func (b *Builder) discoverPrerelease(k KernelConfig) (more bool, err error) {
	if k.Prerelease == nil || !k.Prerelease.Enabled {
		return false, nil
	}
	evidence := prereleaseEvidence{Kernel: k.Kernel, Branch: k.Prerelease.branch(), StartedAt: time.Now()}
	b.setActivity(model.BuilderActivity{Phase: "discovering", Kernel: k.Kernel, Message: "출시 전 브랜치 CVE 수집 · 정식 배포와 분리"})
	defer func() {
		evidence.FinishedAt, evidence.More = time.Now(), more
		if err != nil {
			evidence.Error = err.Error()
		}
		if saveErr := b.savePrereleaseEvidence(evidence); saveErr != nil {
			err = errors.Join(err, fmt.Errorf("출시 전 검토 기록 저장 실패: %w", saveErr))
		}
		b.finishActivity(k.Kernel, "출시 전 수집 주기 완료", err)
	}()
	if !sandboxKernel.MatchString(k.Kernel) || !strings.HasSuffix(k.Kernel, "-generic") {
		return false, fmt.Errorf("출시 전 수집도 Ubuntu GA generic 커널만 지원합니다")
	}
	branch := k.Prerelease.branch()
	if _, err := git(k.GitDir, "check-ref-format", "refs/heads/"+branch); err != nil {
		return false, fmt.Errorf("출시 전 브랜치 이름이 잘못됐습니다: %w", err)
	}
	// git fetch -h에서 확인한 repository/refspec 계약을 사용합니다. 공식 branch의
	// 원격 추적 ref만 갱신하고 작업 트리·현재 branch·태그 상한을 덮어쓰지 않습니다.
	ref := "refs/remotes/origin/" + branch
	if _, err := git(k.GitDir, "fetch", "--quiet", "--tags", "origin", "refs/heads/"+branch+":"+ref); err != nil {
		return false, err
	}
	// explicit kernels 설정도 개발 태그를 상한으로 쓰지 않고 신뢰한 APT 색인과 정확히 대조합니다.
	published, err := b.officialTargetTag(k, false)
	if err != nil {
		return false, fmt.Errorf("출시 전 기준 정식 배포 확인 실패: %w", err)
	}
	evidence.PublishedTag = published
	if k.BaseTag == "" {
		k.BaseTag, err = resolveBaseTag(k)
		if err != nil {
			return false, err
		}
	}
	if _, err := git(k.GitDir, "merge-base", "--is-ancestor", k.BaseTag, published); err != nil {
		return false, fmt.Errorf("실행 기준 %s → 정식 상한 %s 순방향 이력을 확인하지 못했습니다", k.BaseTag, published)
	}
	tip, err := git(k.GitDir, "rev-parse", "--verify", ref+"^{commit}")
	if err != nil {
		return false, err
	}
	tip = strings.TrimSpace(tip)
	if !fullCommit.MatchString(tip) {
		return false, fmt.Errorf("출시 전 브랜치 tip의 정확한 commit ID를 확인하지 못했습니다")
	}
	evidence.TipCommit = tip
	if _, err := git(k.GitDir, "merge-base", "--is-ancestor", published, tip); err != nil {
		return false, fmt.Errorf("정식 상한 %s → 출시 전 브랜치 %s의 순방향 이력을 확인하지 못했습니다", published, branch)
	}
	if !b.cfg.SkipTrialBuild {
		if !b.ensureBuildSpace() {
			return false, errDiskSpace
		}
		// 정식 수집이 꺼져 있어도 대상 패키지·고정 GCC 환경 준비를 생략하지 않습니다.
		if err := b.prepareConfiguredInputs(k); err != nil {
			return false, err
		}
		if b.cfg.Sandbox != nil {
			if _, err := b.ensureSandboxProfile(k); err != nil {
				return false, err
			}
		}
		if _, err := os.Stat(k.Vmlinux); err != nil {
			return false, fmt.Errorf("%w: 디버그 심볼이 없어 출시 전 시험 빌드를 할 수 없습니다", errBuildEnv)
		}
	}
	log.Printf("[%s] 출시 전 %s..%s (%s) CVE 수집", k.Kernel, published, tip, branch)
	return b.discoverRange(k, published, tip, false, true, &evidence.Failure)
}
