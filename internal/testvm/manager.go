// 이 파일: VM 수명 관리, 보안 부팅·서명 거부·교체·롤백 시험과 독립 정리.
package testvm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"kpctl/internal/model"
	"kpctl/internal/remote"
)

type Instance struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	JobID    int    `json:"job_id"`
	Firmware string `json:"firmware"`
}

type Endpoint struct {
	Host string `json:"host"`
	Port int    `json:"port"`
	ID   string `json:"id"`
}

// Registry persists the intent before create_cmd runs, so a restart can clean up
// even when the command never returned an ID. Missing IDs must be safe to delete.
type Registry interface {
	Remember(Instance) error
	Forget(id string) error
}

type Runner interface {
	Run(context.Context, Endpoint, string, string) (string, error)
	Copy(context.Context, Endpoint, string, string) error
}

type SSHRunner struct{ Config Config }

func (s SSHRunner) ssh(e Endpoint) *remote.SSH {
	return &remote.SSH{User: s.Config.SSHUser, Port: e.Port, KeyFile: s.Config.SSHKey,
		Timeout: duration(s.Config.TestTimeout), Options: []string{
			"StrictHostKeyChecking=no", "UserKnownHostsFile=/dev/null", "LogLevel=ERROR"}}
}

func (s SSHRunner) Run(ctx context.Context, e Endpoint, command, stdin string) (string, error) {
	return s.ssh(e).RunContext(ctx, e.Host, command, stdin)
}

func (s SSHRunner) Copy(ctx context.Context, e Endpoint, path, dir string) error {
	return s.ssh(e).CopyContext(ctx, e.Host, []string{path}, dir)
}

type Manager struct {
	cfg      Config
	registry Registry
	runner   Runner
	slots    chan struct{}
	// One test at a time per fixed VM: a livepatch load is global guest state.
	fixedBusy map[string]chan struct{}
	logDir    string
	// PollInterval is configurable for deterministic tests; default is two seconds.
	PollInterval time.Duration
}

func New(cfg Config, registry Registry, runner Runner, logDir string) (*Manager, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if runner == nil {
		runner = SSHRunner{Config: cfg}
	}
	if registry == nil {
		return nil, fmt.Errorf("test_vm registry is required")
	}
	if err := os.MkdirAll(logDir, 0o750); err != nil {
		return nil, err
	}
	busy := map[string]chan struct{}{}
	for _, vms := range cfg.Fixed {
		for _, vm := range vms {
			busy[fixedEndpoint(vm).address()] = make(chan struct{}, 1)
		}
	}
	return &Manager{cfg: cfg, registry: registry, runner: runner, fixedBusy: busy,
		slots: make(chan struct{}, cfg.MaxConcurrent), logDir: logDir, PollInterval: 2 * time.Second}, nil
}

func (m *Manager) environment() []string {
	return append(os.Environ(),
		"KPCTL_TESTVM_ALLOW_TCG="+strconv.FormatBool(m.cfg.AllowTCG),
		"KPCTL_TESTVM_LISTEN_ADDR="+m.cfg.ListenAddr,
		"KPCTL_TESTVM_PORT_RANGE="+m.cfg.PortRange,
		"KPCTL_TESTVM_MAX_CONCURRENT="+strconv.Itoa(m.cfg.MaxConcurrent),
		"KPCTL_TESTVM_SEED_ISO="+strconv.FormatBool(m.cfg.SeedISO),
		"KPCTL_TESTVM_SSH_PUBLIC_KEY="+m.cfg.SSHPublicKey,
		"KPCTL_TESTVM_SSH_USER="+m.cfg.SSHUser)
}

func (m *Manager) command(parent context.Context, command []string, vars Variables) (string, error) {
	args, err := commandArgs(command, vars)
	if err != nil {
		return "", err
	}
	if len(args) == 0 {
		return "", fmt.Errorf("test_vm command is empty")
	}
	ctx, cancel := context.WithTimeout(parent, duration(m.cfg.CmdTimeout))
	defer cancel()
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Env = m.environment()
	// Killing the shell alone leaves local children running and holding stdout.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = time.Second
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err = cmd.Run()
	if ctx.Err() != nil {
		return stdout.String(), fmt.Errorf("%s timed out or canceled: %w", args[0], ctx.Err())
	}
	if err != nil {
		return stdout.String(), fmt.Errorf("%s failed: %w: %s", args[0], err, strings.TrimSpace(stderr.String()))
	}
	if stderr.Len() > 0 {
		log.Printf("test_vm %s: %s", args[0], strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}

func safeID(id string) bool {
	return len(id) > 0 && len(id) <= 256 && !strings.ContainsAny(id, "\r\n\x00") && strings.TrimSpace(id) == id
}

func parseEndpoint(out string) (Endpoint, error) {
	var e Endpoint
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &e); err != nil {
		return e, fmt.Errorf("create_cmd last stdout line must be JSON {host,port,id}: %w", err)
	}
	if e.Port == 0 {
		e.Port = 22
	}
	if !validHost(e.Host) || !safeID(e.ID) || e.Port < 1 || e.Port > 65535 {
		return e, fmt.Errorf("create_cmd returned invalid host, port, or id")
	}
	return e, nil
}

// Delete retries a timed-out command once and retains state if cleanup fails.
func (m *Manager) Delete(ctx context.Context, id string) error {
	if !safeID(id) {
		return fmt.Errorf("invalid test VM ID %q", id)
	}
	_, err := m.command(ctx, m.cfg.DeleteCmd, Variables{ID: id})
	if errors.Is(err, context.DeadlineExceeded) {
		_, err = m.command(ctx, m.cfg.DeleteCmd, Variables{ID: id})
	}
	if err != nil {
		return err
	}
	return m.registry.Forget(id)
}

// Recover removes the union of state.json IDs and externally listed orphan IDs.
// Cleanup is completed before the controller accepts new work.
func (m *Manager) Recover(ctx context.Context, recorded []Instance) error {
	// Fixed VMs are never created by the controller, so there is nothing to reap.
	if len(m.cfg.DeleteCmd) == 0 {
		return nil
	}
	ids := map[string]bool{}
	for _, vm := range recorded {
		if safeID(vm.ID) {
			ids[vm.ID] = true
		}
	}
	var out string
	var listErr error
	if len(m.cfg.ListCmd) > 0 {
		out, listErr = m.command(ctx, m.cfg.ListCmd, Variables{})
	}
	var errs []error
	if listErr != nil {
		errs = append(errs, fmt.Errorf("test_vm list_cmd: %w", listErr))
	}
	for _, id := range strings.Split(strings.TrimSpace(out), "\n") {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if !safeID(id) {
			errs = append(errs, fmt.Errorf("list_cmd returned invalid ID %q", id))
			continue
		}
		ids[id] = true
	}
	ordered := make([]string, 0, len(ids))
	for id := range ids {
		ordered = append(ordered, id)
	}
	sort.Strings(ordered)
	for _, id := range ordered {
		if err := m.Delete(ctx, id); err != nil {
			errs = append(errs, fmt.Errorf("delete test VM %s: %w", id, err))
		}
	}
	return errors.Join(errs...)
}

// ArtifactSet은 실제 배포 사본, 서명 전 원본과 같은 키의 이전 누적본입니다.
// KeyID는 모드별 로그 이름에도 넣어 여러 서명 키의 시험 증거를 덮어쓰지 않습니다.
type ArtifactSet struct {
	ModulePath   string
	UnsignedPath string
	PreviousPath string
	KeyID        string
}

type testRun struct {
	mode, key string
	steps     []model.VMTestStep
}

func (r *testRun) step(name, status, detail string) {
	for i := range r.steps {
		if r.steps[i].Name == name {
			r.steps[i].Status, r.steps[i].Detail = status, detail
			return
		}
	}
	r.steps = append(r.steps, model.VMTestStep{Mode: r.mode, KeyID: r.key, Name: name, Status: status, Detail: detail})
}

func (r *testRun) scriptSteps(out string, runErr error) error {
	for _, line := range strings.Split(out, "\n") {
		fields := strings.SplitN(line, "\t", 4)
		if len(fields) == 4 && fields[0] == "KPCTL_STEP" {
			r.step(fields[1], fields[2], fields[3])
		}
	}
	var incomplete []string
	for i := range r.steps {
		if r.steps[i].Status == "running" {
			r.steps[i].Status = "failed"
			r.steps[i].Detail = "시험 단계의 완료 증거가 없습니다"
			if runErr != nil {
				r.steps[i].Detail = runErr.Error()
			}
		}
		if r.steps[i].Status == "failed" {
			incomplete = append(incomplete, r.steps[i].Name)
		}
	}
	if len(incomplete) > 0 {
		return fmt.Errorf("VM module test has failed or incomplete stages: %s", strings.Join(incomplete, ", "))
	}
	return nil
}

// Run은 기존 호출자를 유지하는 단일 산출물 진입점입니다.
func (m *Manager) Run(ctx context.Context, jobID int, kernel, mode, modulePath string) error {
	_, err := m.RunWithArtifacts(ctx, jobID, kernel, mode, ArtifactSet{ModulePath: modulePath})
	return err
}

// RunWithArtifacts는 모드·키별 증거와 정리까지 끝난 결과를 반환합니다.
func (m *Manager) RunWithArtifacts(ctx context.Context, jobID int, kernel, mode string, artifacts ArtifactSet) ([]model.VMTestStep, error) {
	run := &testRun{mode: mode, key: artifacts.KeyID}
	if jobID < 1 || !validMode(mode) || (artifacts.KeyID != "" && !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`).MatchString(artifacts.KeyID)) {
		return nil, fmt.Errorf("invalid test VM job, firmware mode, or signing key")
	}
	name := fmt.Sprintf("kpctl-test-%d-%s", jobID, mode)
	if artifacts.KeyID != "" {
		name += "-" + artifacts.KeyID
	}
	var err error
	if fixed, ok := m.cfg.Fixed[kernel][mode]; ok {
		err = m.runFixed(ctx, kernel, mode, name, artifacts, fixed, run)
	} else {
		err = m.runDisposable(ctx, jobID, kernel, mode, name, artifacts, run)
	}
	return run.steps, err
}

func (m *Manager) runDisposable(ctx context.Context, jobID int, kernel, mode, name string, artifacts ArtifactSet, run *testRun) (resultErr error) {
	image, ok := m.cfg.Images[kernel][mode]
	if !ok {
		return fmt.Errorf("test_vm has no fixed VM or image for %s/%s", kernel, mode)
	}
	select {
	case m.slots <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-m.slots }()
	vm := Instance{ID: name, Name: name, JobID: jobID, Firmware: mode}
	if err := m.registry.Remember(vm); err != nil {
		return err
	}
	var externalTimeout bool
	defer func() {
		// 요청이 취소돼도 콘솔 증거와 VM 삭제는 독립된 수명으로 끝냅니다.
		cleanupCtx := context.Background()
		console, err := m.command(cleanupCtx, m.cfg.ConsoleLogCmd, Variables{ID: vm.ID})
		if err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("console_log_cmd: %w", err))
			console += "\nconsole_log_cmd: " + err.Error() + "\n"
			if errors.Is(err, context.DeadlineExceeded) {
				externalTimeout = true
			}
		}
		if logErr := os.WriteFile(filepath.Join(m.logDir, name+".console.log"), []byte(console), 0o640); logErr != nil {
			resultErr = errors.Join(resultErr, logErr)
		}
		if hasPanic(console) {
			resultErr = errors.Join(resultErr, fmt.Errorf("kernel panic/oops in VM console (see testlogs/%s.console.log)", name))
			run.step("kernel_log", "failed", "kernel panic/oops in VM console")
		}
		deleteErr := m.Delete(cleanupCtx, vm.ID)
		if externalTimeout {
			deleteErr = errors.Join(deleteErr, m.Delete(cleanupCtx, vm.ID))
		}
		if deleteErr != nil {
			run.step("cleanup", "failed", deleteErr.Error())
		}
		resultErr = errors.Join(resultErr, deleteErr)
	}()
	out, err := m.command(ctx, m.cfg.CreateCmd, Variables{Name: name, Disk: image.Disk, Vars: image.Vars, Firmware: mode, Memory: m.cfg.Memory, CPUs: m.cfg.CPUs})
	if err != nil {
		externalTimeout = errors.Is(err, context.DeadlineExceeded)
		return fmt.Errorf("create_cmd: %w", err)
	}
	e, err := parseEndpoint(out)
	if err != nil {
		if safeID(e.ID) && e.ID != vm.ID {
			err = errors.Join(err, m.Delete(context.Background(), e.ID))
		}
		return err
	}
	vm.ID = e.ID
	if err := m.registry.Remember(vm); err != nil {
		return err
	}
	if e.ID != name {
		if err := m.registry.Forget(name); err != nil {
			return err
		}
	}
	return m.runGuest(ctx, e, kernel, mode, name, artifacts, run, false)
}

func fixedEndpoint(vm FixedVM) Endpoint {
	e := Endpoint{Host: vm.Host, Port: vm.Port, ID: "fixed"}
	if e.Port == 0 {
		e.Port = 22
	}
	return e
}

func (e Endpoint) address() string { return net.JoinHostPort(e.Host, strconv.Itoa(e.Port)) }

func hasPanic(log string) bool {
	return strings.Contains(log, "Kernel panic") || strings.Contains(log, "Oops:")
}

func (m *Manager) runFixed(ctx context.Context, kernel, mode, name string, artifacts ArtifactSet, vm FixedVM, run *testRun) error {
	e := fixedEndpoint(vm)
	for _, wait := range []chan struct{}{m.slots, m.fixedBusy[e.address()]} {
		select {
		case wait <- struct{}{}:
			defer func() { <-wait }()
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return m.runGuest(ctx, e, kernel, mode, name, artifacts, run, true)
}

// runGuest는 fixed와 disposable에 같은 검사와 독립 정리를 적용합니다.
func (m *Manager) runGuest(ctx context.Context, e Endpoint, kernel, mode, name string, artifacts ArtifactSet, run *testRun, fixed bool) (resultErr error) {
	bootTimeout := duration(m.cfg.BootTimeout)
	if m.cfg.AllowTCG && !fixed {
		bootTimeout *= 4
	}
	if err := m.waitBoot(ctx, e, kernel, mode, bootTimeout); err != nil {
		run.step("boot", "failed", err.Error())
		return err
	}
	run.step("boot", "passed", "kernel/firmware/Secure Boot/lockdown/sig_enforce 확인")
	preCtx, cancel := context.WithTimeout(ctx, time.Minute)
	out, err := m.runner.Run(preCtx, e, "sudo -n sh -s", fixedPreScript)
	cancel()
	if err != nil {
		return fmt.Errorf("VM %s is not clean (reboot or repair it): %w: %s", e.address(), err, strings.TrimSpace(out))
	}
	bootID, baseline, _ := strings.Cut(out, "\n")
	bootID = strings.TrimSpace(bootID)
	if bootID == "" {
		return fmt.Errorf("VM boot ID and kernel log baseline are unavailable")
	}
	module := strings.TrimSuffix(filepath.Base(artifacts.ModulePath), ".ko")
	previous := ""
	if artifacts.PreviousPath != "" {
		previous = strings.TrimSuffix(filepath.Base(artifacts.PreviousPath), ".ko")
	}
	// 잘못된 이름은 cleanup의 경로나 외부 공급자를 건드리지 않도록 사전에 거부합니다.
	validModule := regexp.MustCompile(`^kpctl_[A-Za-z0-9_]+$`)
	if !validModule.MatchString(module) || (previous != "" && (!validModule.MatchString(previous) || previous == module)) {
		return fmt.Errorf("invalid kpctl test module name %q or previous %q", module, previous)
	}
	defer func() {
		// SSH 종료/시간 초과로 EXIT trap이 완료되지 못해도 알려진 두 모듈만 재정리합니다.
		postCtx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		command := "sudo -n sh -s -- " + shellQuote("/tmp/"+name) + " " + shellQuote(module) + " " + shellQuote(previous)
		afterOut, cleanupErr := m.runner.Run(postCtx, e, command, fixedPostScript)
		logName := name + ".kernel.log"
		if fixed {
			logName = name + ".console.log"
		}
		if logErr := os.WriteFile(filepath.Join(m.logDir, logName), []byte(afterOut), 0o640); logErr != nil {
			resultErr = errors.Join(resultErr, logErr)
		}
		afterID, afterLog, _ := strings.Cut(afterOut, "\n")
		if cleanupErr != nil {
			run.step("cleanup", "failed", cleanupErr.Error())
			resultErr = errors.Join(resultErr, fmt.Errorf("VM %s unreachable or dirty after the test (panic suspected; recover it manually): %w", e.address(), cleanupErr))
			return
		}
		run.step("cleanup", "passed", "시험 모듈과 작업 디렉터리 제거 확인")
		if strings.TrimSpace(afterID) != bootID {
			err := fmt.Errorf("VM %s rebooted during the test (panic suspected)", e.address())
			run.step("kernel_log", "failed", err.Error())
			resultErr = errors.Join(resultErr, err)
			return
		}
		if err := checkKernelLog(mode, baseline, afterLog, []string{module, previous}); err != nil {
			run.step("kernel_log", "failed", err.Error())
			resultErr = errors.Join(resultErr, err)
		} else {
			run.step("kernel_log", "passed", "시험 시작 후 새 커널 로그만 검사")
		}
	}()
	return m.testModule(ctx, e, name, artifacts, module, previous, mode, run)
}

func (m *Manager) testModule(ctx context.Context, e Endpoint, name string, artifacts ArtifactSet, module, previous, mode string, run *testRun) error {
	testCtx, cancel := context.WithTimeout(ctx, duration(m.cfg.TestTimeout))
	defer cancel()
	negative := mode == "sb_on" && (m.cfg.NegativeSigTest == nil || *m.cfg.NegativeSigTest)
	if negative && artifacts.UnsignedPath == "" {
		run.step("negative_signature", "failed", "서명 전 원본이 없어 서명 강제를 검증할 수 없음")
		return fmt.Errorf("서명 전 원본이 없어 sb_on negative signature test를 수행할 수 없습니다")
	}
	workDir := "/tmp/" + name
	out, err := m.runner.Run(testCtx, e, "sudo -n rm -rf -- "+shellQuote(workDir)+" && mkdir -m 700 -- "+shellQuote(workDir), "")
	if err != nil {
		return fmt.Errorf("VM test directory: %w: %s", err, out)
	}
	if err := m.runner.Copy(testCtx, e, artifacts.ModulePath, workDir); err != nil {
		return fmt.Errorf("VM copy module: %w", err)
	}
	unsignedFile, previousFile := "", ""
	for _, input := range []struct{ path, subdir, filename string }{
		{artifacts.UnsignedPath, "unsigned", module + ".ko"},
		{artifacts.PreviousPath, "previous", previous + ".ko"},
	} {
		if input.path == "" || (input.subdir == "unsigned" && !negative) {
			continue
		}
		dir := workDir + "/" + input.subdir
		if out, err := m.runner.Run(testCtx, e, "mkdir -m 700 -- "+shellQuote(dir), ""); err != nil {
			return fmt.Errorf("VM artifact directory: %w: %s", err, out)
		}
		if err := m.runner.Copy(testCtx, e, input.path, dir); err != nil {
			return fmt.Errorf("VM copy %s module: %w", input.subdir, err)
		}
		file := dir + "/" + input.filename
		if filepath.Base(input.path) != input.filename {
			if out, err := m.runner.Run(testCtx, e, "mv -- "+shellQuote(dir+"/"+filepath.Base(input.path))+" "+shellQuote(file), ""); err != nil {
				return fmt.Errorf("VM artifact name: %w: %s", err, out)
			}
		}
		if input.subdir == "unsigned" {
			unsignedFile = file
		} else {
			previousFile = file
		}
	}
	args := []string{workDir + "/" + filepath.Base(artifacts.ModulePath), module, unsignedFile, previousFile, previous, mode, strconv.FormatBool(negative)}
	args = append(args, m.cfg.SmokeCmd...)
	for i := range args {
		args[i] = shellQuote(args[i])
	}
	out, err = m.runner.Run(testCtx, e, "sudo -n sh -s -- "+strings.Join(args, " "), moduleTestScript)
	err = errors.Join(err, run.scriptSteps(out, err))
	if writeErr := os.WriteFile(filepath.Join(m.logDir, name+".test.log"), []byte(out), 0o640); writeErr != nil {
		return errors.Join(err, writeErr)
	}
	if err != nil {
		return fmt.Errorf("VM module test %s failed: %w: %s", mode, err, out)
	}
	return nil
}

// allowedKernelLog는 새 커널 로그 한 줄의 허용 여부를 결정합니다.
// 일반 livepatch(K) taint는 허용하지만 서명(E) taint는 시험한 모듈에만 한정합니다.
// 오류 표식은 단어 경계로 찾습니다. 대소문자 무시 때문에 "debug:" 같은 일반 줄이
// "BUG:"로 잘못 걸려 시험이 헛되이 실패하지 않게 하고, BUG()의 "kernel BUG at"도 실패로 봅니다.
var kernelLogFailure = regexp.MustCompile(`(?i)\bOops:|Kernel panic|\bBUG:|kernel BUG at|\bWARNING:|Call Trace|livepatch:.*failed`)

func allowedKernelLog(mode, line string, modules []string) bool {
	if kernelLogFailure.MatchString(line) {
		return false
	}
	if !strings.Contains(strings.ToLower(line), "module verification failed") {
		return true
	}
	if mode == "sb_on" {
		return false
	}
	text := strings.TrimSpace(line)
	if strings.HasPrefix(text, "[") {
		if _, rest, ok := strings.Cut(text, "]"); ok {
			text = strings.TrimSpace(rest)
		}
	}
	for _, module := range modules {
		if module != "" && strings.HasPrefix(text, module+":") {
			return true
		}
	}
	return false
}

func checkKernelLog(mode, before, after string, modules []string) error {
	// prefix가 사라지면 ring buffer 회전/로그 삭제로 증거가 유실된 것이므로 통과시키지 않습니다.
	if !strings.HasPrefix(after, before) {
		return fmt.Errorf("kernel log baseline changed or rotated; 새 로그의 연속성을 확인할 수 없습니다")
	}
	for _, line := range strings.Split(strings.TrimPrefix(after, before), "\n") {
		if !allowedKernelLog(mode, line, modules) {
			return fmt.Errorf("kernel panic/oops or disallowed new kernel log: %s", line)
		}
	}
	return nil
}

func (m *Manager) waitBoot(ctx context.Context, e Endpoint, kernel, mode string, timeout time.Duration) error {
	bootCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var last string
	for {
		probeCtx, probeCancel := context.WithTimeout(bootCtx, 15*time.Second)
		out, err := m.runner.Run(probeCtx, e, bootProbeScript, "")
		probeCancel()
		if err == nil {
			fields := strings.Fields(out)
			if len(fields) != 5 {
				return fmt.Errorf("VM boot probe must return kernel, firmware, secure_boot, lockdown, sig_enforce; got %q", out)
			}
			if fields[0] != kernel {
				return fmt.Errorf("VM kernel mismatch: got %s, want %s", fields[0], kernel)
			}
			wantFirmware, wantSB := "uefi", "off"
			if mode == "bios" {
				wantFirmware = "bios"
			}
			if mode == "sb_on" {
				wantSB = "on"
			}
			if fields[1] != wantFirmware || fields[2] != wantSB {
				return fmt.Errorf("VM firmware mismatch for %s: got %s/%s", mode, fields[1], fields[2])
			}
			// Ubuntu는 Secure Boot에서 외부 모듈 서명을 검증합니다:
			// https://documentation.ubuntu.com/security/security-features/platform-protections/secure-boot/
			// kernel/module/signing.c: module_sig_check는 sig_enforce 또는
			// security_locked_down(LOCKDOWN_MODULE_SIGNATURE)로 미서명 모듈을 거부합니다.
			if mode == "sb_on" && fields[3] != "integrity" && fields[3] != "confidentiality" && fields[4] != "on" {
				return fmt.Errorf("이미지 설정 오류: sb_on이지만 서명 강제가 꺼져 있습니다 (lockdown=%s sig_enforce=%s). 모듈 문제가 아닌 VM 이미지 설정 문제", fields[3], fields[4])
			}
			return nil
		}
		last = fmt.Sprintf("%v: %s", err, strings.TrimSpace(out))
		select {
		case <-bootCtx.Done():
			return fmt.Errorf("VM SSH boot timeout: %w (%s)", bootCtx.Err(), last)
		case <-time.After(m.PollInterval):
		}
	}
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'" }

const bootProbeScript = `set -eu
uname -r
if [ -d /sys/firmware/efi ]; then
  echo uefi
  state=$(LC_ALL=C mokutil --sb-state 2>/dev/null || true)
  case "$state" in
    *"SecureBoot enabled"*) echo on ;;
    *"SecureBoot disabled"*) echo off ;;
    *) echo unknown ;;
  esac
else
  echo bios
  echo off
fi
lockdown=$(cat /sys/kernel/security/lockdown 2>/dev/null || true)
case "$lockdown" in
  *"[integrity]"*) echo integrity ;;
  *"[confidentiality]"*) echo confidentiality ;;
  *"[none]"*) echo none ;;
  *) echo unknown ;;
esac
sig_enforce=$(cat /sys/module/module/parameters/sig_enforce 2>/dev/null || true)
case "$sig_enforce" in
  1|Y|y) echo on ;;
  0|N|n) echo off ;;
  *) echo unknown ;;
esac`

// load/unload는 저장소 deploy/kpatch/kpatch의 usage와 load_module,
// disable_patch_strict, remove_module을 확인한 계약입니다. --all은 쓰지 않습니다.
const moduleTestScript = `set -eu
module_file=$1
module_name=$2
unsigned_file=$3
previous_file=$4
previous_name=$5
mode=$6
negative=$7
shift 7
current_step=
emit() { printf 'KPCTL_STEP\t%s\t%s\t%s\n' "$1" "$2" "$3"; }
start() { current_step=$1; emit "$1" running "$2"; }
passed() { emit "$current_step" passed "$1"; current_step=; }
skipped() { emit "$1" skipped "$2"; }
cleanup() {
  status=$?
  trap - EXIT INT TERM
  if [ "$status" -ne 0 ] && [ -n "$current_step" ]; then
    emit "$current_step" failed "command failed (exit $status)"
  fi
  for patch in "$module_name" "$previous_name"; do
    [ -n "$patch" ] || continue
    if [ -d "/sys/module/$patch" ] || [ -d "/sys/kernel/livepatch/$patch" ]; then
      if ! kpatch unload "$patch"; then status=1; fi
    fi
  done
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT TERM
wait_active() {
  remaining=120
  while [ "$remaining" -gt 0 ]; do
    if [ "$(cat "/sys/kernel/livepatch/$1/enabled" 2>/dev/null)" = 1 ] &&
       [ "$(cat "/sys/kernel/livepatch/$1/transition" 2>/dev/null)" = 0 ]; then
      return 0
    fi
    remaining=$((remaining - 1))
    sleep 1
  done
  echo 'livepatch transition timed out' >&2
  return 1
}
inactive() {
  [ ! -d "/sys/kernel/livepatch/$1" ] || {
    [ "$(cat "/sys/kernel/livepatch/$1/enabled")" = 0 ] &&
    [ "$(cat "/sys/kernel/livepatch/$1/transition")" = 0 ]
  }
}
if [ "$negative" = true ]; then
  start negative_signature 'unsigned module rejection'
  if kpatch load "$unsigned_file"; then
    kpatch unload "$module_name" || true
    echo '서명 강제 미동작 — 이 VM 시험은 무의미' >&2
    exit 1
  fi
  if [ -d "/sys/module/$module_name" ] || [ -d "/sys/kernel/livepatch/$module_name" ]; then
    echo '서명 강제 미동작 — 거부 후에도 unsigned 모듈이 남음' >&2
    exit 1
  fi
  passed 'unsigned module rejected'
else
  skipped negative_signature 'sb_on only; optional test disabled or another mode'
fi
if [ -n "$previous_file" ]; then
  start load_previous 'load previous cumulative module'
  kpatch load "$previous_file"
  wait_active "$previous_name"
  passed 'previous module enabled; transition=0'
else
  skipped load_previous 'no previous released cumulative module'
fi
start load_new 'load/transition new cumulative module'
kpatch load "$module_file"
wait_active "$module_name"
passed 'new module enabled; transition=0'
if [ -n "$previous_file" ]; then
  start replace 'verify previous module inactive or removed'
  inactive "$previous_name"
  passed 'previous module inactive or removed; transition=0'
else
  skipped replace 'no previous released cumulative module'
fi
if [ "$#" -gt 0 ]; then
  start smoke 'run configured smoke command with new module active'
  "$@"
  passed 'smoke command exited zero'
else
  skipped smoke 'no smoke_cmd configured'
fi
if [ -n "$previous_file" ]; then
  start rollback 'reload previous cumulative module'
  kpatch load "$previous_file"
  wait_active "$previous_name"
  inactive "$module_name"
  passed 'previous module enabled; new module inactive or removed'
else
  skipped rollback 'no previous released cumulative module'
fi
`

// 첫 줄은 boot ID, 나머지는 원형 버퍼 전체입니다. 기존 오류 줄은 기준으로만 씁니다.
const fixedPreScript = `set -eu
if [ -n "$(ls -A /sys/kernel/livepatch 2>/dev/null)" ]; then
  echo "livepatch already loaded: $(ls /sys/kernel/livepatch | tr '\n' ' ')" >&2
  exit 1
fi
cat /proc/sys/kernel/random/boot_id
dmesg`

// 실패/시간 초과 뒤에도 독립 SSH 호출로 시험한 이름만 정리하고 잔존 모듈을 거부합니다.
// 다른 공급자의 모듈을 제거하거나 reboot해서 상태를 숨기지 않습니다.
const fixedPostScript = `set -eu
failed=0
for patch in "$2" "$3"; do
  [ -n "$patch" ] || continue
  if [ -d "/sys/module/$patch" ] || [ -d "/sys/kernel/livepatch/$patch" ]; then
    if ! kpatch unload "$patch" >/dev/null 2>&1; then failed=1; fi
  fi
done
rm -rf -- "$1" || failed=1
cat /proc/sys/kernel/random/boot_id
dmesg
if [ -n "$(ls -A /sys/kernel/livepatch 2>/dev/null)" ]; then
  echo 'livepatch still loaded after the test' >&2
  failed=1
fi
for patch in "$2" "$3"; do
  [ -n "$patch" ] || continue
  if [ -d "/sys/module/$patch" ]; then
    echo "test module still loaded after cleanup: $patch" >&2
    failed=1
  fi
done
exit "$failed"`
