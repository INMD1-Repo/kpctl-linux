// Package agent 는 호스트(물리 노드)에서 도는 에이전트입니다.
//
// 하는 일:
//  1. 처음 한 번 등록 토큰으로 컨트롤러에 자기를 등록
//  2. 주기적으로 상태(커널, 올라간 패치, taint)를 보고
//  3. 컨트롤러가 알려준 버전과 다르면 패치 모듈을 받아 kpatch 로 적용 (또는 내림)
//  4. 관리자가 재부팅을 승인하면 재부팅 훅 스크립트를 실행
//
// 에이전트는 컨트롤러로 나가는 HTTPS 연결만 씁니다. 호스트 쪽 포트를 열 필요가 없습니다.
//
// 파일 안내:
//
//	config.go  ← 지금 파일. 설정
//	state.go   에이전트 로컬 상태 파일 (토큰, 적용한 버전)
//	kpatch.go  kpatch 명령과 /sys/kernel/livepatch 읽기
//	security.go 펌웨어·보안 신호와 서명 필요 판정
//	signing.go 공개 인증서 확인과 재부팅 없는 MOK 예약
//	agent.go   메인 루프와 패치 적용 로직
package agent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

type Config struct {
	ControllerURL string `json:"controller_url"`
	EnrollToken   string `json:"enroll_token"`
	CAFile        string `json:"ca_file"`

	StateDir        string `json:"state_dir"`        // 토큰과 받은 모듈을 둘 곳
	IntervalSeconds int    `json:"interval_seconds"` // 보고 주기

	KpatchBin        string `json:"kpatch_bin"`                // kpatch 명령
	KpatchInstallDir string `json:"kpatch_install_dir"`        // kpatch 가 부팅용 모듈을 설치하는 경로
	ModulePrefix     string `json:"module_prefix"`             // 우리가 만든 패치 모듈 이름 접두사. 이 접두사가 아닌 모듈은 절대 건드리지 않음
	RebootHook       string `json:"reboot_hook"`               // 재부팅 승인 시 실행할 스크립트
	MOKAutoImport    bool   `json:"mok_auto_import,omitempty"` // active 인증서 등록 예약 요청, 기본 꺼짐
	MokutilBin       string `json:"mokutil_bin,omitempty"`     // MOK 조회·예약 도구, 생략 시 mokutil

	// 아래는 테스트용으로 바꿀 수 있게 둔 경로입니다. 운영에서는 기본값 그대로 두세요.
	LivepatchSysfs    string   `json:"livepatch_sysfs"`               // /sys/kernel/livepatch
	ModuleSysfs       string   `json:"module_sysfs"`                  // /sys/module
	SysfsRoot         string   `json:"sysfs_root"`                    // /sys (펌웨어·서명 정책 보고)
	TaintedPath       string   `json:"tainted_path"`                  // /proc/sys/kernel/tainted
	DistroReleasePath string   `json:"distro_release_path,omitempty"` // os-release fixture override
	OSReleasePath     string   `json:"osrelease_path"`                // /proc/sys/kernel/osrelease (= uname -r)
	SignaturePath     string   `json:"signature_path"`                // /proc/version_signature (Ubuntu 패키지 버전)
	Hostname          string   `json:"hostname"`                      // 비우면 시스템 hostname
	BootIDPath        string   `json:"boot_id_path"`
	BootTargetPath    string   `json:"boot_target_path"`
	BootDir           string   `json:"boot_dir"`
	GrubConfig        string   `json:"grub_config"`
	GrubRebootBin     string   `json:"grub_reboot_bin"`
	GrubSetDefaultBin string   `json:"grub_set_default_bin"`
	GrubEditenvBin    string   `json:"grub_editenv_bin"`
	GrubEnv           string   `json:"grub_env"`
	ProcDir           string   `json:"proc_dir"`
	KernelPrepareLock string   `json:"kernel_prepare_lock"`
	PackageLocks      []string `json:"package_locks"`
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg, err := ParseConfig(data)
	if err != nil {
		return nil, fmt.Errorf("설정 파일 %s: %w", path, err)
	}
	return cfg, os.MkdirAll(cfg.StateDir, 0o700)
}

// ParseConfig는 실제 로더의 JSON·기본값·검증을 공유하며 디렉터리는 만들지 않습니다.
func ParseConfig(data []byte) (*Config, error) {
	cfg := &Config{}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(cfg); err != nil {
		return nil, fmt.Errorf("설정 JSON 해석 실패: %w", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return nil, fmt.Errorf("설정 JSON 뒤에는 추가 값이나 문자를 쓸 수 없습니다")
	}

	setDefault(&cfg.StateDir, "/var/lib/kpctl-agent")
	setDefault(&cfg.KpatchBin, "kpatch")
	setDefault(&cfg.KpatchInstallDir, "/var/lib/kpatch")
	setDefault(&cfg.ModulePrefix, "kpctl_")
	setDefault(&cfg.RebootHook, "/etc/kpctl/reboot-hook.sh")
	setDefault(&cfg.MokutilBin, "mokutil")
	setDefault(&cfg.LivepatchSysfs, "/sys/kernel/livepatch")
	setDefault(&cfg.ModuleSysfs, "/sys/module")
	setDefault(&cfg.SysfsRoot, "/sys")
	setDefault(&cfg.TaintedPath, "/proc/sys/kernel/tainted")
	setDefault(&cfg.OSReleasePath, "/proc/sys/kernel/osrelease")
	setDefault(&cfg.SignaturePath, "/proc/version_signature")
	setDefault(&cfg.BootIDPath, "/proc/sys/kernel/random/boot_id")
	setDefault(&cfg.BootTargetPath, cfg.StateDir+"/boot-target.json")
	setDefault(&cfg.BootDir, "/boot")
	setDefault(&cfg.GrubConfig, "/boot/grub/grub.cfg")
	setDefault(&cfg.GrubEnv, "/boot/grub/grubenv")
	setDefault(&cfg.GrubRebootBin, "grub-reboot")
	setDefault(&cfg.GrubSetDefaultBin, "grub-set-default")
	setDefault(&cfg.GrubEditenvBin, "grub-editenv")
	setDefault(&cfg.ProcDir, "/proc")
	setDefault(&cfg.KernelPrepareLock, "/run/lock/kpctl-kernel-prepare.lock")
	if cfg.PackageLocks == nil {
		cfg.PackageLocks = []string{"/var/lib/dpkg/lock-frontend", "/var/lib/dpkg/lock"}
	}
	if cfg.Hostname == "" {
		cfg.Hostname, _ = os.Hostname()
	}
	if cfg.IntervalSeconds == 0 {
		cfg.IntervalSeconds = 60
	}
	if cfg.ControllerURL == "" {
		return nil, fmt.Errorf("controller_url 은 꼭 넣어야 합니다")
	}
	return cfg, nil
}

func setDefault(p *string, v string) {
	if *p == "" {
		*p = v
	}
}
