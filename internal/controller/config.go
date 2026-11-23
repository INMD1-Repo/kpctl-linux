// 이 파일: controller 패키지의 soak, LoadConfig, ParseConfig 구현·자료형.
package controller

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"kpctl/internal/model"
	"kpctl/internal/testvm"
)

// EnrollToken 은 호스트 등록용 토큰입니다.
// 토큰마다 기본 링과 재부팅 정책을 정해 두면, 그 토큰으로 설치한 호스트에 자동으로 적용됩니다.
type EnrollToken struct {
	Name         string `json:"name"`
	Token        string `json:"token"`
	Ring         int    `json:"ring"`
	RebootPolicy string `json:"reboot_policy"`
}

// SchedulerConfig 는 네오클라우드 스케줄러와 연동하는 명령입니다.
// 각 항목은 실행할 명령과 인자 목록이며, "{host}" 는 호스트 이름으로 바뀝니다.
// 비워 두면 해당 기능을 쓰지 않습니다.
//
//	예) "cordon_command":   ["/usr/local/bin/scheduler-adapter", "cordon",   "{host}"]
//	    "vm_count_command": ["/usr/local/bin/scheduler-adapter", "vm-count", "{host}"]  ← 숫자 하나를 출력해야 함
type SchedulerConfig struct {
	CordonCommand   []string `json:"cordon_command"`
	UncordonCommand []string `json:"uncordon_command"`
	VMCountCommand  []string `json:"vm_count_command"`
}

// AutoRollout 은 사람 승인 없이 패치를 배포하는 설정입니다. 기본은 꺼져 있습니다.
// 무엇을 자동으로 하고 언제 멈추는지는 auto.go 를 보세요.
type AutoRollout struct {
	Enabled bool `json:"enabled"`
	// ApproveOnly: true 면 첫 번째 링(카나리)까지만 자동이고, 다음 링은 사람이 promote 합니다.
	ApproveOnly bool `json:"approve_only"`
	// SoakMinutes: 다음 링으로 넘어가기 전 이전 링에서 최소 몇 분 관찰할지. 비우면 1440(24시간).
	SoakMinutes *int `json:"soak_minutes"`
	// CheckSeconds: 확인 주기. 비우면 60.
	CheckSeconds int `json:"check_seconds"`
}

func (a AutoRollout) soak() int {
	if a.SoakMinutes == nil {
		return 1440
	}
	return *a.SoakMinutes
}

// Config 는 컨트롤러 설정 파일(JSON) 구조입니다. 예시는 configs/controller.example.json 을 보세요.
type Config struct {
	Listen  string `json:"listen"`
	TLSCert string `json:"tls_cert"`
	TLSKey  string `json:"tls_key"`
	DataDir string `json:"data_dir"`

	AdminTokens  map[string]string `json:"admin_tokens"` // 관리자 이름 → 토큰 (감사 로그에 이름이 남음)
	BuilderToken string            `json:"builder_token"`
	EnrollTokens []EnrollToken     `json:"enroll_tokens"`

	// AllowSelfEnroll: 컨트롤러 자신도 호스트로 등록하게 둡니다. 한 머신에서 돌리는 테스트 전용입니다.
	AllowSelfEnroll bool `json:"allow_self_enroll"`

	// AgentBundleDir 는 VM 이 스스로 등록할 때 내려받는 에이전트 설치 묶음입니다. 비우면 setup-controller.sh 가 까는 곳.
	AgentBundleDir string `json:"agent_bundle_dir"`

	// BuilderBinary 는 빌드 서버가 스스로 업데이트할 때 받아 가는 kpctl-builder 실행 파일입니다.
	// 비우면 setup-controller.sh 가 까는 곳. 파일이 없으면 빌드 서버 자동 업데이트를 하지 않습니다.
	BuilderBinary string `json:"builder_binary"`

	// Rings 는 배포 순서입니다. approve 하면 첫 번째 링에 배포되고,
	// kpctl promote 로 다음 링에 차례로 배포합니다.
	Rings []int `json:"rings"`
	// MinSoakMinutes[링] = 이 링으로 promote 하기 전에 이전 링에서 최소 몇 분 관찰할지
	MinSoakMinutes map[int]int `json:"min_soak_minutes"`
	AutoRollout    AutoRollout `json:"auto_rollout"`
	// AutoPrepareKernel: 명시한 빌더 범위 밖 호스트에 공식 GA 커널 준비를 요청합니다.
	// 기존 설치의 동작을 유지하도록 기본은 꺼짐이며, 재부팅 승인과는 별개입니다.
	AutoPrepareKernel bool `json:"auto_prepare_kernel"`
	// AutoJumpKernelHosts 는 미리 cordon 한 전용 호스트만 공식 커널로 자동 재부팅합니다.
	// 비어 있으면 자동 승인을 하지 않습니다. 호스트 이름 대신 정확한 등록 ID 를 적습니다.
	AutoJumpKernelHosts []string `json:"auto_jump_kernel_hosts"`

	JobTimeoutMinutes int `json:"job_timeout_minutes"` // 빌드가 이 시간 넘게 끝나지 않으면 다시 대기열로
	HostStaleMinutes  int `json:"host_stale_minutes"`  // 이 시간 넘게 보고가 없으면 "연락 끊김"

	// SignCommand 는 승인 시 모듈에 서명하는 명령입니다. "{module}" 은 .ko 파일 경로로 바뀝니다.
	// Secure Boot, lockdown, sig_enforce 등으로 서명이 필요한 호스트에는 반드시 설정합니다.
	SignCommand []string       `json:"sign_command"`
	Signing     *SigningConfig `json:"signing,omitempty"`

	// TestVM is an optional approval gate, implemented by external VM commands.
	TestVM testvm.Config `json:"test_vm"`

	Scheduler         SchedulerConfig `json:"scheduler"`
	DrainCheckSeconds int             `json:"drain_check_seconds"`
}

// LoadConfig 는 설정 파일을 읽고 기본값을 채운 뒤 검사합니다.
// 모르는 필드가 있으면 오류를 내서 오타를 바로 알 수 있게 합니다.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg, err := ParseConfig(data)
	if err != nil {
		return nil, fmt.Errorf("설정 파일 %s: %w", path, err)
	}
	return cfg, nil
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

	// 기본값
	if cfg.Listen == "" {
		cfg.Listen = ":8443"
	}
	if cfg.DataDir == "" {
		cfg.DataDir = "/var/lib/kpctl"
	}
	if cfg.AgentBundleDir == "" {
		cfg.AgentBundleDir = "/usr/local/share/kpctl/agent"
	}
	if cfg.BuilderBinary == "" {
		cfg.BuilderBinary = "/usr/local/share/kpctl/builder/kpctl-builder"
	}
	if len(cfg.Rings) == 0 {
		cfg.Rings = []int{1, 2}
	}
	if cfg.JobTimeoutMinutes == 0 {
		cfg.JobTimeoutMinutes = 180
	}
	if cfg.HostStaleMinutes == 0 {
		cfg.HostStaleMinutes = 10
	}
	if cfg.DrainCheckSeconds == 0 {
		cfg.DrainCheckSeconds = 300
	}
	if cfg.AutoRollout.CheckSeconds == 0 {
		cfg.AutoRollout.CheckSeconds = 60
	}

	return cfg, cfg.validate()
}

func (c *Config) validate() error {
	if len(c.AdminTokens) == 0 {
		return fmt.Errorf("admin_tokens 에 관리자를 한 명 이상 넣어야 합니다")
	}
	for name, tok := range c.AdminTokens {
		if len(tok) < 16 {
			return fmt.Errorf("관리자 %q 의 토큰이 너무 짧습니다 (16자 이상)", name)
		}
	}
	if len(c.BuilderToken) < 16 {
		return fmt.Errorf("builder_token 은 16자 이상이어야 합니다")
	}
	seenJumpHosts := map[string]bool{}
	for _, id := range c.AutoJumpKernelHosts {
		if id == "" || len(id) > 128 || strings.TrimSpace(id) != id {
			return fmt.Errorf("auto_jump_kernel_hosts 에 정확한 호스트 ID 를 적어야 합니다")
		}
		for _, ch := range id {
			if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '-' || ch == '_' || ch == '.') {
				return fmt.Errorf("auto_jump_kernel_hosts 의 호스트 ID %q 가 잘못됐습니다", id)
			}
		}
		if seenJumpHosts[id] {
			return fmt.Errorf("auto_jump_kernel_hosts 에 호스트 ID %q 가 중복됐습니다", id)
		}
		seenJumpHosts[id] = true
	}
	if !sort.IntsAreSorted(c.Rings) {
		return fmt.Errorf("rings 는 작은 수부터 순서대로 적어야 합니다: %v", c.Rings)
	}
	for i := 1; i < len(c.Rings); i++ {
		if c.Rings[i] == c.Rings[i-1] {
			return fmt.Errorf("rings 에 같은 번호가 두 번 있습니다: %v", c.Rings)
		}
	}
	for _, e := range c.EnrollTokens {
		if len(e.Token) < 16 {
			return fmt.Errorf("등록 토큰 %q 이 너무 짧습니다 (16자 이상)", e.Name)
		}
		if !c.hasRing(e.Ring) {
			return fmt.Errorf("등록 토큰 %q 의 ring %d 이 rings 목록에 없습니다", e.Name, e.Ring)
		}
		if !validRebootPolicy(e.RebootPolicy) {
			return fmt.Errorf("등록 토큰 %q 의 reboot_policy %q 가 잘못됐습니다 (drain 또는 never)", e.Name, e.RebootPolicy)
		}
	}
	if c.AutoRollout.soak() < 0 || c.AutoRollout.CheckSeconds < 0 {
		return fmt.Errorf("auto_rollout 의 soak_minutes, check_seconds 는 음수일 수 없습니다")
	}
	if (c.TLSCert == "") != (c.TLSKey == "") {
		return fmt.Errorf("tls_cert 와 tls_key 는 둘 다 넣거나 둘 다 비워야 합니다")
	}
	if err := c.validateSigning(); err != nil {
		return err
	}
	return c.TestVM.Validate()
}

func (c *Config) hasRing(r int) bool {
	for _, x := range c.Rings {
		if x == r {
			return true
		}
	}
	return false
}

func validRebootPolicy(p string) bool {
	return p == model.RebootDrain || p == model.RebootNever
}
