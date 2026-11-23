// 이 파일: 주기적 등록·보안 보고·목표 적용·승인된 재부팅을 조정합니다.
package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"kpctl/internal/client"
	"kpctl/internal/klpcheck"
	"kpctl/internal/model"
)

// 같은 버전 적용이 실패했을 때 다시 시도할 때까지 기다리는 시간
const retryAfterFailure = 10 * time.Minute

type Agent struct {
	cfg             *Config
	c               *client.Client
	st              *localState
	lastErr         string // 다음 보고에 실어 보낼 오류
	securityWarning string // 인증서 수집 오류는 패치 적용 오류와 분리
	prepareDone     <-chan kernelPrepareResult
	prepareCancel   context.CancelFunc
	prepareCtx      context.Context
	prepareRun      func(context.Context, string) error // 테스트에서는 시스템 설치 명령을 대신함
}

func New(cfg *Config) (*Agent, error) {
	c, err := client.New(cfg.ControllerURL, "", cfg.CAFile)
	if err != nil {
		return nil, err
	}
	a := &Agent{cfg: cfg, c: c}
	if err := a.loadState(); err != nil {
		return nil, fmt.Errorf("상태 파일 읽기 실패: %w", err)
	}
	current := a.kernelRelease()
	if current != "" && a.st.Kernel != current {
		if a.st.Kernel != "" {
			a.st.Version = 0
			a.st.ModuleName = ""
			a.st.Installed = nil
			a.st.FailedVersion = 0
			a.st.FailedAt = time.Time{}
		}
		a.st.KernelPrepare = nil
		a.st.Kernel = current
		if err := a.saveState(); err != nil {
			return nil, err
		}
	}
	if p := a.st.KernelPrepare; p != nil && p.State == "preparing" {
		if target, _ := a.bootTarget(); target != nil {
			p.State, p.Error, p.NextAttemptAt = "prepared", "", time.Time{}
		} else {
			a.failKernelPrepare(fmt.Errorf("에이전트 재시작으로 커널 준비 완료를 확인하지 못했습니다"))
		}
		if err := a.saveState(); err != nil {
			return nil, err
		}
	}
	if !a.st.FailedAt.IsZero() {
		a.lastErr = "이전 라이브패치 적용 실패: 재시도 대기 중"
	}
	c.SetToken(a.st.HostToken)
	return a, nil
}

func (a *Agent) Run(ctx context.Context) {
	a.prepareCtx = ctx
	defer a.stopKernelPrepare()
	log.Printf("에이전트 시작: %s → %s", a.cfg.Hostname, a.cfg.ControllerURL)
	for {
		a.Cycle()
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Duration(a.cfg.IntervalSeconds) * time.Second):
		}
	}
}

// Cycle 은 한 주기의 일입니다: 등록 확인 → 보고 → 적용 → (바뀌었으면 다시 보고) → 재부팅 확인
func (a *Agent) Cycle() {
	if err := a.cycle(true); err != nil {
		log.Print(err)
	}
}

// RunOnce performs the installation check without starting a background
// package operation that would outlive the one-shot agent process.
func (a *Agent) RunOnce() error {
	return a.cycle(false)
}

func (a *Agent) cycle(allowPrepare bool) error {
	a.pollKernelPrepare()
	if err := a.expireBootChoice(); err != nil {
		a.lastErr = err.Error()
		return err
	}
	if err := a.ensureRegistered(); err != nil {
		return fmt.Errorf("등록 실패: %w", err)
	}
	resp, err := a.report()
	if err != nil {
		var httpErr *client.HTTPError
		if errors.As(err, &httpErr) && httpErr.Status == http.StatusUnauthorized {
			// 컨트롤러에서 호스트가 삭제됨 → 다음 주기에 다시 등록
			log.Printf("호스트 토큰이 거부되어 다음 주기에 다시 등록합니다")
			a.st.HostID, a.st.HostToken = "", ""
			a.c.SetToken("")
			_ = a.saveState()
		}
		return fmt.Errorf("보고 실패: %w", err)
	}

	// 공개 인증서를 먼저 확인해 현재 MOK 등록 상태로 목표를 다시 받습니다.
	// 등록 예약을 처리한 주기에는 재부팅 승인 실행 경로로 들어가지 않습니다.
	importRequested := resp.MOKImport != nil
	if a.reconcileSigning(resp) {
		resp, err = a.report()
		if err != nil {
			return fmt.Errorf("서명 상태 보고 실패: %w", err)
		}
	}
	if !importRequested && resp.MOKImport != nil {
		importRequested = true
		a.reconcileSigning(resp)
		if _, err := a.report(); err != nil {
			return fmt.Errorf("MOK 등록 예약 결과 보고 실패: %w", err)
		}
	}
	if importRequested {
		return nil
	}

	if err := a.reconcileBootChoice(resp); err != nil {
		a.lastErr = err.Error()
		return err
	}
	changed := a.apply(resp.Desired)
	if allowPrepare && a.maybePrepareKernel(resp) {
		changed = true
	}
	if changed {
		if _, err = a.report(); err != nil {
			err = fmt.Errorf("적용 후 보고 실패: %w", err)
		}
	}
	a.maybeReboot(resp.Reboot)
	return err
}

// ensureRegistered 는 아직 등록 전이면 등록 토큰으로 등록합니다.
func (a *Agent) ensureRegistered() error {
	if a.st.HostToken != "" {
		return nil
	}
	if a.cfg.EnrollToken == "" {
		return fmt.Errorf("enroll_token 이 설정되지 않았습니다")
	}
	var resp model.RegisterResponse
	err := a.c.Do("POST", "/api/agent/register", model.RegisterRequest{
		EnrollToken: a.cfg.EnrollToken,
		Hostname:    a.cfg.Hostname,
		Kernel:      a.kernelRelease(),
	}, &resp)
	if err != nil {
		return err
	}
	a.st.HostID, a.st.HostToken = resp.HostID, resp.HostToken
	a.c.SetToken(resp.HostToken)
	log.Printf("등록 완료: host_id=%s", resp.HostID)
	return a.saveState()
}

func (a *Agent) report() (model.ReportResponse, error) {
	var resp model.ReportResponse
	target, problem := a.bootTarget()
	security := a.securityStatus()
	enrolled, pending, certWarning := a.enrollmentStatus(security)
	var moduleSHA string
	if a.st.Version != 0 && a.st.ModuleName != "" {
		moduleSHA, _ = fileSHA256(a.installedModulePath(a.st.ModuleName))
	}
	warnings := []string{security.warning(), certWarning, a.securityWarning}
	var securityWarnings []string
	for _, warning := range warnings {
		if warning != "" {
			securityWarnings = append(securityWarnings, warning)
		}
	}
	err := a.c.Do("POST", "/api/agent/report", model.ReportRequest{
		Status: model.HostStatus{
			ModuleSHA256:      moduleSHA,
			Kernel:            a.kernelRelease(),
			Firmware:          security.firmware,
			SecureBoot:        security.secureBoot,
			Lockdown:          security.lockdown,
			SigEnforce:        security.sigEnforce,
			SignatureRequired: security.signatureRequired(),
			SecurityWarning:   strings.Join(securityWarnings, "; "),
			EnrolledCerts:     enrolled,
			MOKPending:        pending,
			MOKImport:         a.st.MOKImport,
			KernelSignature:   a.kernelSignature(),
			Version:           a.st.Version,
			Loaded:            a.loadedPatches(),
			Tainted:           a.tainted(),
			Error:             a.lastErr,
			BootID:            a.bootID(), BootTarget: target, BootProblem: problem, LocalVMCount: a.localVMCount(),
			KernelPrepare:   a.st.KernelPrepare,
			BootConfirmedID: a.st.BootConfirmedID,
		},
		LastRebootID:   a.st.LastRebootID,
		RebootError:    a.st.RebootError,
		AutoImportCert: a.cfg.MOKAutoImport,
	}, &resp)
	return resp, err
}

// apply 는 컨트롤러가 원하는 버전에 맞춥니다. 무언가 바꿨으면 true.
func (a *Agent) apply(d model.DesiredPatch) bool {
	// 제외는 보호 유지 요청입니다. v0 롤백처럼 기존 모듈을 내리지 않습니다.
	if d.Blocked {
		return false
	}
	// 이미 맞으면 할 일 없음 (기록만 보지 않고 커널에 실제로 올라가 있는지까지 확인)
	var upToDate bool
	var cleanupOnly bool
	if d.Version == 0 {
		upToDate = a.st.Version == 0 && len(a.ourLoadedModules()) == 0 && len(a.st.Installed) == 0
	} else {
		if a.st.Version == d.Version && a.waitTransition(d.ModuleName, 0) {
			sum, err := fileSHA256(a.installedModulePath(d.ModuleName))
			cleanupOnly = err == nil && sum == d.SHA256
		}
		upToDate = cleanupOnly && len(a.st.Installed) == 1 && a.st.Installed[0] == d.ModuleName
		// 정리에 실패한 예전 부팅용 설치본이나 모듈이 있으면 다음 시도에서 정리합니다.
		for _, names := range [][]string{a.st.Installed, a.ourLoadedModules()} {
			for _, name := range names {
				if name != d.ModuleName {
					upToDate = false
				}
			}
		}
	}
	if upToDate {
		// 커널 전환이 뒤늦게 끝난 경우에도 예전 실패 기록을 계속 보고하지 않습니다.
		if !a.st.FailedAt.IsZero() {
			a.lastErr = ""
			a.st.FailedVersion, a.st.FailedAt = 0, time.Time{}
			if err := a.saveState(); err != nil {
				log.Printf("상태 저장 실패: %v", err)
			}
			return true
		}
		return false
	}

	// 직전에 실패한 버전은 잠시 쉬었다가 다시 시도
	if !cleanupOnly && !a.st.FailedAt.IsZero() && d.Version == a.st.FailedVersion && time.Since(a.st.FailedAt) < retryAfterFailure {
		return false
	}

	var err error
	if cleanupOnly {
		a.st.Installed = appendUnique(a.st.Installed, d.ModuleName)
		err = a.removeOurModules(d.ModuleName)
	} else if d.Version == 0 {
		log.Printf("컨트롤러 지시: 패치 모두 내림")
		err = a.removeOurModules("")
		if err == nil {
			a.st.Version, a.st.ModuleName = 0, ""
		}
	} else {
		log.Printf("컨트롤러 지시: v%d (%s) 적용", d.Version, d.ModuleName)
		err = a.loadVersion(d)
	}

	if err != nil {
		log.Printf("적용 실패: %v", err)
		a.lastErr = err.Error()
		a.st.FailedVersion, a.st.FailedAt = d.Version, time.Now()
	} else {
		a.lastErr = ""
		a.st.FailedVersion, a.st.FailedAt = 0, time.Time{}
	}
	if serr := a.saveState(); serr != nil {
		log.Printf("상태 저장 실패: %v", serr)
	}
	return true
}

// loadVersion 은 모듈을 받아 검증하고 적용·설치한 뒤, 이전 버전 모듈을 정리합니다.
func (a *Agent) loadVersion(d model.DesiredPatch) error {
	if !strings.HasPrefix(d.ModuleName, a.cfg.ModulePrefix) {
		return fmt.Errorf("모듈 이름 %q 가 접두사 %q 로 시작하지 않습니다", d.ModuleName, a.cfg.ModulePrefix)
	}
	if d.ModuleName == "" || len(d.ModuleName) > 55 || strings.Trim(d.ModuleName, "abcdefghijklmnopqrstuvwxyz0123456789_") != "" {
		return fmt.Errorf("잘못된 모듈 이름: %q", d.ModuleName)
	}
	if err := a.checkCanLoad(d.ModuleName); err != nil {
		return err
	}

	// 1) 다운로드 + 해시 검증
	dir := filepath.Join(a.cfg.StateDir, "modules")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	path := filepath.Join(dir, d.ModuleName+".ko")
	part := path + ".part"
	defer os.Remove(part)
	if err := a.c.Download(d.URL, part); err != nil {
		return err
	}
	sum, err := fileSHA256(part)
	if err != nil {
		return err
	}
	if sum != d.SHA256 {
		os.Remove(part)
		return fmt.Errorf("모듈 해시 불일치: 받은 %s, 기대 %s", sum[:12], shortHash(d.SHA256))
	}
	if err := klpcheck.CheckFile(part); err != nil {
		return fmt.Errorf("라이브패치 모듈 ELF 검사 실패: %w", err)
	}
	if err := os.Rename(part, path); err != nil {
		return err
	}

	return a.activateVersion(d, path, 2*time.Minute)
}

// activateVersion 은 전환 완료를 확인한 모듈만 부팅용으로 설치하고 성공을 기록합니다.
func (a *Agent) activateVersion(d model.DesiredPatch, path string, timeout time.Duration) error {
	// 다운로드 중 다른 도구가 라이브패치를 올렸을 수 있어 load 직전에 다시 검사합니다.
	if err := a.checkCanLoad(d.ModuleName); err != nil {
		return err
	}
	if !a.patchEnabled(d.ModuleName) {
		if err := a.kpatch("load", path); err != nil {
			return err
		}
	}
	if !a.waitTransition(d.ModuleName, timeout) {
		return fmt.Errorf("%s 라이브패치 전환 완료를 확인하지 못했습니다 (대기 %s)", d.ModuleName, timeout)
	}

	// 실패한 후보를 다음 부팅 때 자동으로 올리지 않도록, 검증이 끝난 뒤 설치합니다.
	if err := a.installVersion(d, path); err != nil {
		return err
	}

	a.st.Version, a.st.ModuleName = d.Version, d.ModuleName

	// 이전 설치본이 남으면 부팅 시 예전 버전이 다시 올라갈 수 있으므로 정리 실패도 보고합니다.
	if err := a.removeOurModules(d.ModuleName); err != nil {
		return fmt.Errorf("v%d 전환 뒤 이전 모듈 정리 실패: %w", d.Version, err)
	}
	log.Printf("v%d 적용 완료", d.Version)
	return nil
}

// installVersion 은 설치 직후 중단된 작업도 파일 해시로 확인하여 이어갑니다.
func (a *Agent) installVersion(d model.DesiredPatch, path string) error {
	sum, err := fileSHA256(a.installedModulePath(d.ModuleName))
	switch {
	case os.IsNotExist(err):
		if err := a.kpatch("install", path); err != nil {
			return err
		}
	case err != nil:
		return fmt.Errorf("설치된 모듈 확인 실패: %w", err)
	case sum != d.SHA256:
		return fmt.Errorf("설치된 모듈 %s 의 해시가 기대값과 다릅니다 (설치본 %s, 기대 %s). 컨트롤러 버전 기록과 설치본을 확인하세요", d.ModuleName, shortHash(sum), shortHash(d.SHA256))
	}
	a.st.Installed = appendUnique(a.st.Installed, d.ModuleName)
	return a.saveState()
}

func (a *Agent) installedModulePath(name string) string {
	return filepath.Join(a.cfg.KpatchInstallDir, a.kernelRelease(), name+".ko")
}

// removeOurModules 는 keep 을 제외한 우리 모듈을 모두 내리고 설치본도 지웁니다.
// keep 이 "" 이면 전부 지웁니다. 접두사가 다른 모듈은 절대 건드리지 않습니다.
func (a *Agent) removeOurModules(keep string) error {
	var errs []string
	failedUnload := map[string]bool{}
	for _, name := range a.ourLoadedModules() {
		if name == keep {
			continue
		}
		if err := a.kpatch("unload", name); err != nil {
			// 교체되어 livepatch 목록에서 빠진 모듈은 kpatch unload 가 실패할 수 있음 → rmmod 로 한 번 더
			if out, rerr := exec.Command("rmmod", name).CombinedOutput(); rerr != nil && a.moduleLoaded(name) {
				errs = append(errs, fmt.Sprintf("%s 내리기 실패: %v / rmmod: %s", name, err, strings.TrimSpace(string(out))))
				failedUnload[name] = true
				continue
			}
		}
	}
	var stillInstalled []string
	for _, name := range a.st.Installed {
		if name == keep || failedUnload[name] {
			stillInstalled = append(stillInstalled, name)
			continue
		}
		// uninstall 직후 상태 저장 전에 중단됐어도 이미 지운 파일은 다시 지우지 않습니다.
		_, err := os.Stat(a.installedModulePath(name))
		if err == nil {
			err = a.kpatch("uninstall", name)
		}
		if err != nil && !os.IsNotExist(err) {
			errs = append(errs, err.Error())
			stillInstalled = append(stillInstalled, name)
			continue
		}
		os.Remove(filepath.Join(a.cfg.StateDir, "modules", name+".ko"))
	}
	a.st.Installed = stillInstalled
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

// ── 도우미 ──

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func shortHash(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

func appendUnique(list []string, v string) []string {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}
