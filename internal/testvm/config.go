// Package testvm tests modules in disposable VMs through an external command contract.
// It deliberately has no knowledge of QEMU, OpenStack, or another hypervisor API.
package testvm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"text/template"
	"time"

	"kpctl/internal/model"
)

var AllModes = []string{"sb_on", "sb_off", "bios"}

// Modes accepts "auto" or an explicit JSON array such as ["sb_on", "bios"].
type Modes []string

func (m *Modes) UnmarshalJSON(b []byte) error {
	if string(b) == `"auto"` {
		*m = nil
		return nil
	}
	var modes []string
	if err := json.Unmarshal(b, &modes); err != nil {
		return fmt.Errorf("modes must be \"auto\" or an array of firmware modes")
	}
	*m = modes
	return nil
}

type Image struct {
	Disk string `json:"disk"`
	Vars string `json:"vars,omitempty"`
}

// FixedVM is an always-on guest prepared by the operator. It is never created
// or deleted; tests log in over SSH and must leave it in its original state.
type FixedVM struct {
	Host string `json:"host"`
	Port int    `json:"port,omitempty"`
}

type Config struct {
	Enabled         bool                          `json:"enabled"`
	Modes           Modes                         `json:"modes"`
	Fixed           map[string]map[string]FixedVM `json:"fixed"`
	Images          map[string]map[string]Image   `json:"images"`
	CreateCmd       []string                      `json:"create_cmd"`
	DeleteCmd       []string                      `json:"delete_cmd"`
	ConsoleLogCmd   []string                      `json:"console_log_cmd"`
	ListCmd         []string                      `json:"list_cmd"`
	CmdTimeout      string                        `json:"cmd_timeout"`
	BootTimeout     string                        `json:"boot_timeout"`
	TestTimeout     string                        `json:"test_timeout"`
	Memory          int                           `json:"memory"`
	CPUs            int                           `json:"cpus"`
	MaxConcurrent   int                           `json:"max_concurrent"`
	AllowTCG        bool                          `json:"allow_tcg"`
	ListenAddr      string                        `json:"listen_addr"`
	PortRange       string                        `json:"port_range"`
	SeedISO         bool                          `json:"seed_iso"`
	SSHUser         string                        `json:"ssh_user"`
	SSHKey          string                        `json:"ssh_key"`
	SSHPublicKey    string                        `json:"ssh_public_key"`
	NegativeSigTest *bool                         `json:"negative_sig_test,omitempty"`
	SmokeCmd        []string                      `json:"smoke_cmd,omitempty"`
}

func (c *Config) Defaults() {
	if c.CmdTimeout == "" {
		c.CmdTimeout = "3m"
	}
	if c.BootTimeout == "" {
		c.BootTimeout = "3m"
	}
	if c.TestTimeout == "" {
		c.TestTimeout = "5m"
	}
	if c.Memory == 0 {
		c.Memory = 4096
	}
	if c.CPUs == 0 {
		c.CPUs = 2
	}
	if c.MaxConcurrent == 0 {
		c.MaxConcurrent = 2
	}
	if c.ListenAddr == "" {
		c.ListenAddr = "127.0.0.1"
	}
	if c.PortRange == "" {
		c.PortRange = "2200-2299"
	}
	if c.SSHUser == "" {
		c.SSHUser = "ubuntu"
	}
}

func validMode(mode string) bool {
	return mode == "sb_on" || mode == "sb_off" || mode == "bios"
}

func (c *Config) Validate() error {
	c.Defaults()
	if len(c.SmokeCmd) > 0 {
		if strings.TrimSpace(c.SmokeCmd[0]) == "" {
			return fmt.Errorf("test_vm.smoke_cmd executable is empty")
		}
		for _, arg := range c.SmokeCmd {
			if strings.ContainsRune(arg, '\x00') {
				return fmt.Errorf("test_vm.smoke_cmd contains a NUL byte")
			}
		}
	}
	for name, value := range map[string]string{"cmd_timeout": c.CmdTimeout, "boot_timeout": c.BootTimeout, "test_timeout": c.TestTimeout} {
		d, err := time.ParseDuration(value)
		if err != nil || d <= 0 || d > 24*time.Hour {
			return fmt.Errorf("test_vm.%s must be a positive duration up to 24h", name)
		}
	}
	if c.Memory < 128 || c.CPUs < 1 || c.MaxConcurrent < 1 {
		return fmt.Errorf("test_vm memory must be >= 128, cpus and max_concurrent must be >= 1")
	}
	seen := map[string]bool{}
	for _, mode := range c.Modes {
		if !validMode(mode) || seen[mode] {
			return fmt.Errorf("test_vm.modes has invalid or duplicate mode %q", mode)
		}
		seen[mode] = true
	}
	ports := strings.Split(c.PortRange, "-")
	if len(ports) != 2 {
		return fmt.Errorf("test_vm.port_range must be START-END")
	}
	lo, err1 := strconv.Atoi(ports[0])
	hi, err2 := strconv.Atoi(ports[1])
	if err1 != nil || err2 != nil || lo < 1 || hi > 65535 || hi < lo {
		return fmt.Errorf("test_vm.port_range must be within 1-65535")
	}
	if !regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_-]*\$?$`).MatchString(c.SSHUser) {
		return fmt.Errorf("test_vm.ssh_user is invalid")
	}
	for kernel, images := range c.Images {
		if kernel == "" || len(images) == 0 {
			return fmt.Errorf("test_vm.images must specify a kernel and firmware images")
		}
		for mode, img := range images {
			if !validMode(mode) {
				return fmt.Errorf("test_vm.images[%s]: unknown firmware %q", kernel, mode)
			}
			if mode != "bios" && img.Vars == "" {
				return fmt.Errorf("test_vm.images[%s].%s.vars is required (disk and NVRAM are a pair)", kernel, mode)
			}
			if mode == "bios" && img.Vars != "" {
				return fmt.Errorf("test_vm.images[%s].bios.vars must be absent", kernel)
			}
			for name, path := range map[string]string{"disk": img.Disk, "vars": img.Vars} {
				if name == "vars" && mode == "bios" {
					continue
				}
				if err := regularFile(path); err != nil {
					return fmt.Errorf("test_vm.images[%s].%s.%s: %w", kernel, mode, name, err)
				}
			}
		}
	}
	for kernel, vms := range c.Fixed {
		if kernel == "" || len(vms) == 0 {
			return fmt.Errorf("test_vm.fixed must specify a kernel and firmware modes")
		}
		for mode, vm := range vms {
			if !validMode(mode) {
				return fmt.Errorf("test_vm.fixed[%s]: unknown firmware %q", kernel, mode)
			}
			if !validHost(vm.Host) || vm.Port < 0 || vm.Port > 65535 {
				return fmt.Errorf("test_vm.fixed[%s].%s: invalid host or port", kernel, mode)
			}
			if _, both := c.Images[kernel][mode]; both {
				return fmt.Errorf("test_vm: %s/%s is in both fixed and images; choose one", kernel, mode)
			}
		}
	}
	for name, cmd := range map[string][]string{"create_cmd": c.CreateCmd, "delete_cmd": c.DeleteCmd, "console_log_cmd": c.ConsoleLogCmd, "list_cmd": c.ListCmd} {
		if len(cmd) == 0 {
			// The external commands serve only disposable (images) VMs.
			if c.Enabled && len(c.Images) > 0 {
				return fmt.Errorf("test_vm.%s is required", name)
			}
			continue
		}
		if strings.TrimSpace(cmd[0]) == "" {
			return fmt.Errorf("test_vm.%s executable is empty", name)
		}
		if _, err := commandArgs(cmd, Variables{}); err != nil {
			return fmt.Errorf("test_vm.%s: %w", name, err)
		}
	}
	if c.Enabled {
		if len(c.Images) == 0 && len(c.Fixed) == 0 {
			return fmt.Errorf("test_vm.fixed or test_vm.images is required")
		}
		if err := regularFile(c.SSHKey); err != nil {
			return fmt.Errorf("test_vm.ssh_key: %w", err)
		}
		if c.SeedISO {
			if err := regularFile(c.SSHPublicKey); err != nil {
				return fmt.Errorf("test_vm.ssh_public_key: %w", err)
			}
		}
	}
	return nil
}

func validHost(host string) bool {
	return net.ParseIP(host) != nil || regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]*$`).MatchString(host)
}

func regularFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("file %q: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%q is not a regular file", path)
	}
	return nil
}

// SelectModes uses every host with this kernel, including stale reports. Unknown
// firmware or Secure Boot state requires all modes, as does an empty fleet.
func SelectModes(configured Modes, fleet []model.HostStatus) []string {
	if len(configured) > 0 {
		return append([]string(nil), configured...)
	}
	needed := map[string]bool{}
	for _, h := range fleet {
		switch h.Firmware {
		case "bios":
			needed["bios"] = true
		case "uefi":
			switch h.SecureBoot {
			case "on":
				needed["sb_on"] = true
			case "off":
				needed["sb_off"] = true
			default:
				return append([]string(nil), AllModes...)
			}
		default:
			return append([]string(nil), AllModes...)
		}
	}
	if len(needed) == 0 {
		return append([]string(nil), AllModes...)
	}
	var modes []string
	for _, mode := range AllModes {
		if needed[mode] {
			modes = append(modes, mode)
		}
	}
	return modes
}

// Variables are substituted in each argv entry, never passed through a shell.
type Variables struct {
	Name, Disk, Vars, Firmware, ID string
	Memory, CPUs                   int
}

func commandArgs(command []string, vars Variables) ([]string, error) {
	args := make([]string, len(command))
	for i, arg := range command {
		t, err := template.New("argument").Option("missingkey=error").Parse(arg)
		if err != nil {
			return nil, err
		}
		var buf bytes.Buffer
		if err := t.Execute(&buf, vars); err != nil {
			return nil, err
		}
		args[i] = buf.String()
	}
	return args, nil
}

func duration(value string) time.Duration {
	d, _ := time.ParseDuration(value)
	return d
}
