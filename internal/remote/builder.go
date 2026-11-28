// 이 파일: remote 패키지의 빌드 서버 원격 설치 — 배포판별 빌더 묶음(OpenBuilderBundle), InstallBuilder 구현·자료형.
//
// kpctl install-builder 가 씁니다. 호스트 배포판에 맞는 전용 묶음(dist/builder/ubuntu 등)만 임시 디렉터리에 복사하고
// builder.json 을 표준 입력으로 넘긴 뒤 setup-builder.sh 를 실행합니다.
package remote

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"kpctl/internal/model"
)

// 빌더 묶음 종류. dist/builder/<종류>/ 가 그 배포판 전용 설치 묶음입니다 (Makefile 의 dist).
// Ubuntu 빌더(setup-builder.sh)와 Debian/Rocky 네이티브 빌더(setup-native-builder.sh)를 서로 다른 디렉터리로 나눠,
// 네이티브 빌더 파일이 바뀌어도 Ubuntu 빌드 서버에 복사되는 묶음은 바뀌지 않게 합니다.
const (
	FlavorUbuntu = "ubuntu"
	FlavorDebian = "debian"
	FlavorRocky  = "rocky"
)

// BuilderFlavors 는 지원하는 빌더 묶음 종류입니다 (표시 순서).
var BuilderFlavors = []string{FlavorUbuntu, FlavorDebian, FlavorRocky}

// builderFlavorMarker 는 묶음마다 들어 있는 종류 표식 파일입니다 (내용: ubuntu | debian | rocky).
// setup-native-builder.sh 는 이 값이 호스트 os-release 의 ID 와 다르면 설치를 거부합니다.
const builderFlavorMarker = "builder-flavor"

// ubuntuBuilderFiles 는 setup-builder.sh 가 같은 디렉터리에서 찾는 파일·디렉터리입니다 (dist/builder/ubuntu).
var ubuntuBuilderFiles = []string{
	"kpctl-builder",
	"setup-builder.sh",
	"kpctl-builder.service",
	"builder.example.json",
	"kpctl-kernel-debug.sh",
	"kpctl-kernel-inputs.py",
	"kpctl-kpatch-fixes.sh",
	"kpctl-kpatch-cold-test.py",
	"kpatch-fixes",
	"setup-build-environment.sh",
	"kpctl-build-environment.py",
	"build-environment",
	builderFlavorMarker,
}

// nativeBuilderFiles 는 setup-native-builder.sh 가 같은 디렉터리에서 찾는 파일·디렉터리입니다 (dist/builder/debian, dist/builder/rocky).
var nativeBuilderFiles = []string{
	"kpctl-builder", // -verify-distribution-module
	"setup-native-builder.sh",
	"kpctl-native-builder.py",
	"native_inputs.py",
	"kpctl-native-work.sh",
	"kpctl-native-builder.service",
	"kpctl-native-builder.timer",
	"kpctl-kpatch-fixes.sh", // Debian 12·Rocky 9 의 고정 kpatch
	"kpctl-kpatch-cold-test.py",
	"kpatch-fixes",
	builderFlavorMarker,
}

// BuilderBundleFiles 는 종류별 묶음에 있어야 하는 파일입니다.
func BuilderBundleFiles(flavor string) []string {
	if flavor == FlavorUbuntu {
		return ubuntuBuilderFiles
	}
	return nativeBuilderFiles
}

// BuilderBundles 는 dist/builder 전체입니다. 종류별 묶음은 Flavor 로 고릅니다.
type BuilderBundles struct {
	Root    string
	Arch    string             // kpctl-builder 의 아키텍처 (묶음 사이에 같아야 함)
	flavors map[string]*Bundle // 있는 종류만
}

// OpenBuilderBundle 은 dist/builder(Root) 아래 종류별 묶음을 열고, 파일이 다 있는지·표식이 맞는지·kpctl-builder 아키텍처를 확인합니다.
// 묶음이 하나도 없거나, 있는 묶음에 파일이 빠졌거나, 종류 사이 아키텍처가 다르면 오류입니다.
// 종류 디렉터리가 아예 없는 것은 오류가 아닙니다 (그 배포판 호스트를 만나면 Flavor 가 이유를 돌려줌).
func OpenBuilderBundle(root string) (*BuilderBundles, error) {
	bs := &BuilderBundles{Root: root, flavors: map[string]*Bundle{}}
	for _, flavor := range BuilderFlavors {
		dir := filepath.Join(root, flavor)
		if _, err := os.Stat(dir); errors.Is(err, os.ErrNotExist) {
			continue
		}
		for _, f := range BuilderBundleFiles(flavor) {
			if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
				return nil, fmt.Errorf("빌더 설치 묶음 %s 에 %s 가 없습니다 (make dist 로 만든 dist/controller 를 setup-controller.sh 로 다시 설치하거나 -bundle 로 dist/builder 를 지정하세요)", dir, f)
			}
		}
		marker, err := os.ReadFile(filepath.Join(dir, builderFlavorMarker))
		if err != nil {
			return nil, err
		}
		if got := strings.TrimSpace(string(marker)); got != flavor {
			return nil, fmt.Errorf("빌더 설치 묶음 %s 의 %s 가 %q 입니다 (%q 여야 함)", dir, builderFlavorMarker, got, flavor)
		}
		arch, err := binaryArch(filepath.Join(dir, "kpctl-builder"))
		if err != nil {
			return nil, err
		}
		if bs.Arch != "" && arch != bs.Arch {
			return nil, fmt.Errorf("빌더 설치 묶음 %s 의 kpctl-builder 아키텍처가 %s 로 다른 묶음(%s)과 다릅니다", dir, arch, bs.Arch)
		}
		bs.Arch = arch
		bs.flavors[flavor] = &Bundle{Dir: dir, Arch: arch}
	}
	if len(bs.flavors) == 0 {
		if _, err := os.Stat(filepath.Join(root, "setup-builder.sh")); err == nil {
			return nil, fmt.Errorf("빌더 설치 묶음 %s 는 배포판별로 나뉘기 전의 통합 묶음입니다. make dist 로 dist/builder/{ubuntu,debian,rocky} 를 다시 만드세요", root)
		}
		return nil, fmt.Errorf("빌더 설치 묶음 %s 에 ubuntu·debian·rocky 묶음이 없습니다 (make dist 로 만든 dist/builder 를 지정하세요)", root)
	}
	return bs, nil
}

// Flavor 는 그 종류의 전용 묶음입니다. 없으면 이유를 돌려줍니다.
func (bs *BuilderBundles) Flavor(flavor string) (*Bundle, error) {
	if b := bs.flavors[flavor]; b != nil {
		return b, nil
	}
	return nil, fmt.Errorf("빌더 설치 묶음 %s 에 %s 전용 묶음(%s/)이 없습니다 (make dist 로 다시 만드세요)", bs.Root, model.DistroLabel(flavor), flavor)
}

// Flavors 는 묶음에 있는 종류입니다 (BuilderFlavors 순서).
func (bs *BuilderBundles) Flavors() []string {
	var out []string
	for _, f := range BuilderFlavors {
		if bs.flavors[f] != nil {
			out = append(out, f)
		}
	}
	return out
}

// BuilderFlavor 는 os-release 의 ID 로 고른 이 호스트의 빌더 묶음 종류입니다. Ubuntu·Debian·Rocky 가 아니면 "".
// 지원 시리즈·릴리스 판정은 Preflight 가 따로 합니다.
func (f Facts) BuilderFlavor() string {
	switch f.Distro {
	case FlavorUbuntu, FlavorDebian, FlavorRocky:
		return f.Distro
	}
	return ""
}

// BuilderInstallOptions 는 빌드 서버 설치 값입니다.
type BuilderInstallOptions struct {
	ControllerURL string
	// Config 는 원격 /etc/kpctl/builder.json 의 바탕이 될 내용입니다 (토큰 포함, 표준 입력으로 전달).
	// 비우면 원격에 이미 있는 builder.json 을 그대로 씁니다.
	Config      []byte
	CAFile      string   // 로컬 CA 인증서 (선택) → /etc/kpctl/tls/ca.crt
	Kernels     []string // setup-builder.sh 에 넘길 대상 커널
	SetupArgs   []string // setup-builder.sh 에 그대로 넘길 추가 옵션 (--memory-mib 등)
	StopRunning bool     // 실행 중인 kpctl-builder 를 먼저 멈춤
}

// InstallBuilder 는 묶음을 복사하고 setup-builder.sh 를 실행합니다. Preflight(ForBuilder) 를 먼저 불러야 합니다.
// 설치 스크립트의 "■" 단계 줄은 OnStep 으로 바로 보여 줍니다 (커널 git·이미지 준비로 오래 걸리므로).
func (s *Session) InstallBuilder(b *Bundle, o BuilderInstallOptions) (err error) {
	s.step("임시 디렉터리 만들기")
	out, err := s.run("mktemp -d /tmp/kpctl-builder.XXXXXX", "")
	if err != nil {
		return err
	}
	dir := strings.TrimSpace(out)
	if !strings.HasPrefix(dir, "/tmp/kpctl-builder.") {
		return fmt.Errorf("임시 디렉터리 이름이 이상합니다: %q", dir)
	}
	defer func() {
		// 성공하든 실패하든 임시 파일(토큰이 든 설정 포함)은 지움
		if _, cerr := s.run(s.sudo()+"rm -rf "+shq(dir), ""); cerr != nil {
			err = errors.Join(err, fmt.Errorf("임시 디렉터리 %s 삭제 실패 (토큰이 든 설정이 남아 있을 수 있음): %w", dir, cerr))
		}
	}()

	s.step("빌더 묶음 복사")
	entries, err := os.ReadDir(b.Dir)
	if err != nil {
		return err
	}
	var paths []string
	for _, e := range entries {
		paths = append(paths, b.Path(e.Name()))
	}
	if o.CAFile != "" {
		if _, err := os.Stat(o.CAFile); err != nil {
			return fmt.Errorf("CA 파일: %w", err)
		}
	}
	fmt.Fprintf(&s.Log, "$ scp -r %s/* → %s\n", b.Dir, dir)
	if err := s.SSH.CopyTree(s.Target, paths, dir); err != nil {
		return err
	}
	ca := ""
	if o.CAFile != "" {
		// 묶음 파일과 이름이 겹치지 않게 하위 디렉터리로
		if _, err := s.run("mkdir -m 0700 "+shq(dir+"/ca"), ""); err != nil {
			return err
		}
		if err := s.SSH.Copy(s.Target, []string{o.CAFile}, dir+"/ca"); err != nil {
			return err
		}
		ca = dir + "/ca/" + baseName(o.CAFile)
	}
	if _, err := s.run("chmod 0755 "+shq(dir+"/kpctl-builder")+" "+shq(dir+"/setup-builder.sh"), ""); err != nil {
		return err
	}

	config := ""
	if len(o.Config) > 0 {
		s.step("빌더 설정 전달 (컨트롤러 주소·빌더 토큰)")
		config = dir + "/builder.json"
		if _, err := s.run("umask 077; cat > "+shq(config), string(o.Config)); err != nil {
			return err
		}
	}

	if e := s.Facts.HostsEntry(o.ControllerURL); e != "" {
		s.step("컨트롤러 이름 등록 (/etc/hosts: " + e + ")")
		if _, err := s.run(s.sudo()+"bash -s -- "+shq(e), hostsEntryScript); err != nil {
			return err
		}
	}

	if o.StopRunning && s.Facts.BuilderActive == "yes" {
		s.step("실행 중인 kpctl-builder 중지")
		if _, err := s.run(s.sudo()+"systemctl stop kpctl-builder", ""); err != nil {
			return err
		}
	}

	s.step("setup-builder.sh 실행 (커널 git·컴파일러 이미지 준비로 수십 분 걸릴 수 있음)")
	cmd := s.sudo() + "bash " + shq(dir+"/setup-builder.sh")
	if config != "" {
		cmd += " --config " + shq(config)
	}
	if ca != "" {
		cmd += " --ca-file " + shq(ca)
	}
	for _, a := range o.SetupArgs {
		cmd += " " + shq(a)
	}
	for _, k := range o.Kernels {
		cmd += " " + shq(k)
	}
	fmt.Fprintf(&s.Log, "$ %s\n", cmd)
	out, err = s.SSH.RunStream(s.Target, cmd, "", func(line string) {
		if strings.HasPrefix(line, "■") || strings.HasPrefix(line, "!!") || strings.HasPrefix(line, "경고") {
			if s.OnStep != nil {
				s.OnStep(s.Target, "  "+line)
			}
		}
	})
	s.Log.WriteString(out)
	if err != nil {
		fmt.Fprintf(&s.Log, "!! %v\n", err)
		return fmt.Errorf("%w\n%s", err, lastLines(out, 15))
	}
	return nil
}
