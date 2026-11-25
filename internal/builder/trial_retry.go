// 이 파일: builder 패키지의 retryFileIdentity, trialEnvironmentFingerprint, retryDigest 구현·자료형.
package builder

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"kpctl/internal/model"
)

const trialEnvironmentRetry = 6 * time.Hour

type trialFailureRecord struct {
	Schema      int       `json:"schema"`
	Commit      string    `json:"commit"`
	Fingerprint string    `json:"fingerprint"`
	Kind        string    `json:"kind"`
	Error       string    `json:"error"`
	At          time.Time `json:"at"`
}

// Read the actual inputs, rather than paths alone. Missing files are inputs too:
// installing a formerly missing tool or debug image must invalidate a failure.
func retryFileIdentity(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if os.IsNotExist(err) {
		return "missing:" + path, nil
	}
	if err != nil {
		return "", err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("시험 입력이 일반 파일이 아닙니다: %s", path)
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return fmt.Sprintf("%s:%o:%x", path, info.Mode(), h.Sum(nil)), nil
}

// Computed once per discovery cycle. It never stores credentials or full input
// files, and a read failure disables suppression instead of hiding a new trial.
func (b *Builder) trialEnvironmentFingerprint(k KernelConfig, latest string) (string, error) {
	base, err := git(k.GitDir, "rev-parse", "--verify", k.BaseTag+"^{commit}")
	if err != nil {
		return "", err
	}
	tip, err := git(k.GitDir, "rev-parse", "--verify", latest+"^{commit}")
	if err != nil {
		return "", err
	}
	tools, err := b.klpTools(k)
	if err != nil {
		return "", err
	}
	files := []string{filepath.Join(b.cfg.BootDir, "config-"+k.Kernel), k.Vmlinux}
	headers := b.headersRoot
	if headers == "" {
		headers = "/usr/src"
	}
	files = append(files, filepath.Join(headers, "linux-headers-"+k.Kernel, "include/generated/compile.h"))
	files = append(files, filepath.Join(headers, "linux-headers-"+k.Kernel, "Module.symvers"),
		filepath.Join("/usr/src/linux-headers-"+k.Kernel, "Module.symvers"),
		filepath.Join("/lib/modules", k.Kernel, "build/Module.symvers"))
	if b.cfg.Sandbox != nil {
		profile, err := b.sandboxProfile(k.Kernel)
		if err != nil {
			return "", err
		}
		files = append(files, profile, b.cfg.Sandbox.Helper, b.cfg.Sandbox.WorkerBinary)
	} else {
		tool := b.cfg.KpatchBuild
		if resolved, err := exec.LookPath(tool); err == nil {
			tool = resolved
		}
		files = append(files, tool)
		files = append(files, filepath.Join(filepath.Dir(tool), "create-diff-object"),
			"/usr/local/libexec/kpatch/create-diff-object", "/usr/libexec/kpatch/create-diff-object")
		names := []string{"gcc", "ld", "make", "objcopy"}
		config, _ := os.ReadFile(filepath.Join(b.cfg.BootDir, "config-"+k.Kernel))
		for _, tool := range []string{"rustc", "bindgen"} {
			key := "CONFIG_RUSTC_VERSION_TEXT"
			if tool == "bindgen" {
				key = "CONFIG_BINDGEN_VERSION_TEXT"
			}
			fields := strings.Fields(configString(string(config), key))
			if len(fields) >= 2 {
				version := strings.Split(fields[1], ".")
				if len(version) >= 2 {
					names = append(names, tool+"-"+strings.Join(version[:2], "."))
				}
			}
			names = append(names, tool)
		}
		for _, name := range names {
			if path, err := exec.LookPath(name); err == nil {
				files = append(files, path)
			}
		}
	}
	if path, err := exec.LookPath("modinfo"); err == nil {
		files = append(files, path)
	}
	identities := make([]string, 0, len(files))
	for _, file := range files {
		id, err := retryFileIdentity(file)
		if err != nil {
			return "", err
		}
		identities = append(identities, id)
	}
	binary := b.selfSHA
	if binary == "" {
		binary = selfSHA256()
	}
	magic, magicErr := targetModuleVermagic(k.Kernel)
	if magicErr != nil {
		magic = "unavailable:" + magicErr.Error()
	}
	var environment []string
	if b.cfg.Sandbox == nil {
		for _, name := range []string{"PATH", "MAKEFLAGS", "CC", "CXX", "HOSTCC", "LD", "AR", "OBJCOPY", "CROSS_COMPILE", "LLVM", "RUSTC", "HOSTRUSTC", "BINDGEN"} {
			environment = append(environment, name+"="+os.Getenv(name))
		}
	}
	input := struct {
		Schema                     int
		Kernel                     KernelConfig
		Base, Latest, Tool, Binary string
		Tools                      *klpTools
		Files                      []string
		Vermagic                   string
		Environment                []string
		Jobs, Timeout, MaxPrereqs  int
		SkipTrial                  bool
	}{1, k, strings.TrimSpace(base), strings.TrimSpace(tip), b.cfg.buildTool(k.Kernel), binary,
		tools, identities, magic, environment, b.cfg.Jobs, b.cfg.BuildTimeoutMinutes, b.cfg.MaxPrereqs, b.cfg.SkipTrialBuild}
	return retryDigest(input), nil
}

func retryDigest(value any) string {
	data, _ := json.Marshal(value)
	return fmt.Sprintf("%x", sha256.Sum256(data))
}

func trialFingerprint(environment, content string, active []model.DiscoveredPatch, known []string) string {
	// Decisions can change without changing the tree or candidate. Sorting makes
	// map iteration in the controller irrelevant to the fingerprint.
	commits := append([]string(nil), known...)
	sort.Strings(commits)
	return retryDigest(struct {
		Environment, Content string
		Active               []model.DiscoveredPatch
		Known                []string
	}{environment, content, active, commits})
}

func (b *Builder) trialFailurePath(kernel string, prerelease ...bool) string {
	if !sandboxKernel.MatchString(kernel) {
		return ""
	}
	dir := filepath.Join(b.cfg.WorkDir, "trial-failures")
	if len(prerelease) > 0 && prerelease[0] {
		dir = filepath.Join(dir, "prerelease")
	}
	return filepath.Join(dir, kernel+".json")
}

func (b *Builder) previousTrialFailure(kernel, commit, fingerprint string, prerelease ...bool) error {
	path := b.trialFailurePath(kernel, prerelease...)
	if path == "" || fingerprint == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var record trialFailureRecord
	if json.Unmarshal(data, &record) != nil || record.Schema != 1 || record.Commit != commit || record.Fingerprint != fingerprint || record.Error == "" || record.At.IsZero() {
		return nil
	}
	switch record.Kind {
	case model.FailureEnvironment:
		if time.Since(record.At) >= trialEnvironmentRetry {
			return nil
		}
	case model.FailureUnsupported, model.FailureArtifact, model.FailureUnknown:
	default:
		return nil
	}
	return &buildFailure{record.Kind, errors.New(record.Error)}
}

func (b *Builder) saveTrialFailure(kernel, commit, fingerprint string, failure error, prerelease ...bool) error {
	path := b.trialFailurePath(kernel, prerelease...)
	if path == "" || fingerprint == "" || b.stopping() || errors.Is(failure, errBuildDeferred) {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(trialFailureRecord{1, commit, fingerprint, failureKind(failure, ""), failure.Error(), time.Now()})
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".trial-failure-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

func (b *Builder) clearTrialFailure(kernel string, prerelease ...bool) {
	if path := b.trialFailurePath(kernel, prerelease...); path != "" {
		_ = os.Remove(path)
	}
}
