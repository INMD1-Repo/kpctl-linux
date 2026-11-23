// 이 파일: testvm 패키지의 TestSecurityOptionsAreOptionalAndStrictlyDecoded, TestConfigDefaults, TestConfigRejectsInvalidImagePairs 회귀 시험.
package testvm

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"kpctl/internal/model"
)

func TestSecurityOptionsAreOptionalAndStrictlyDecoded(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		wantError  bool
	}{
		{"생략", `{}`, false},
		{"음성시험 끄기", `{"negative_sig_test":false}`, false},
		{"smoke argv", `{"smoke_cmd":["sh","-c","true"]}`, false},
		{"음성시험 타입 오류", `{"negative_sig_test":"false"}`, true},
		{"smoke 타입 오류", `{"smoke_cmd":"true"}`, true},
		{"음성시험 오타", `{"negative_signature_test":false}`, true},
		{"smoke 실행 파일 없음", `{"smoke_cmd":[" "]}`, true},
		{"smoke NUL", `{"smoke_cmd":["echo","\u0000"]}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var cfg Config
			decoder := json.NewDecoder(bytes.NewBufferString(tc.body))
			decoder.DisallowUnknownFields()
			err := decoder.Decode(&cfg)
			if err == nil {
				err = cfg.Validate()
			}
			if (err != nil) != tc.wantError {
				t.Fatalf("오류=%v, want 오류=%v", err, tc.wantError)
			}
			if tc.name == "음성시험 끄기" && (cfg.NegativeSigTest == nil || *cfg.NegativeSigTest) {
				t.Fatal("명시적으로 끈 부정시험 설정이 보존되지 않음")
			}
		})
	}
}

func validTestConfig(t *testing.T) Config {
	t.Helper()
	root := t.TempDir()
	disk, vars, key := filepath.Join(root, "disk.qcow2"), filepath.Join(root, "vars.fd"), filepath.Join(root, "ssh-key")
	for _, path := range []string{disk, vars, key} {
		if err := os.WriteFile(path, []byte("fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return Config{
		Enabled: true,
		Images: map[string]map[string]Image{"6.8.0-85-generic": {
			"sb_on": {Disk: disk, Vars: vars}, "sb_off": {Disk: disk, Vars: vars}, "bios": {Disk: disk},
		}},
		CreateCmd: []string{"/bin/true", "{{.Name}}", "{{.Disk}}", "{{.Vars}}", "{{.Firmware}}", "{{.Memory}}", "{{.CPUs}}"},
		DeleteCmd: []string{"/bin/true", "{{.ID}}"}, ConsoleLogCmd: []string{"/bin/true", "{{.ID}}"}, ListCmd: []string{"/bin/true"},
		SSHKey: key,
	}
}

func TestConfigDefaults(t *testing.T) {
	cfg := validTestConfig(t)
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.CmdTimeout != "3m" || cfg.Memory != 4096 || cfg.CPUs != 2 || cfg.MaxConcurrent != 2 || cfg.ListenAddr != "127.0.0.1" || cfg.PortRange != "2200-2299" {
		t.Fatalf("unexpected VM defaults: %+v", cfg)
	}
	if cfg.AllowTCG || cfg.SeedISO {
		t.Fatal("TCG and seed ISO must require explicit configuration")
	}
	var disabled Config
	if err := disabled.Validate(); err != nil {
		t.Fatalf("unconfigured optional test VM feature: %v", err)
	}
}

func TestConfigRejectsInvalidImagePairs(t *testing.T) {
	for _, tc := range []struct {
		name string
		mode string
		edit func(Image) Image
		want string
	}{
		{"Secure Boot requires NVRAM", "sb_on", func(i Image) Image { i.Vars = ""; return i }, "sb_on.vars"},
		{"UEFI requires NVRAM", "sb_off", func(i Image) Image { i.Vars = ""; return i }, "sb_off.vars"},
		{"BIOS forbids NVRAM", "bios", func(i Image) Image { i.Vars = i.Disk; return i }, "bios.vars"},
		{"missing disk", "bios", func(i Image) Image { i.Disk += ".missing"; return i }, "bios.disk"},
		{"missing NVRAM", "sb_on", func(i Image) Image { i.Vars += ".missing"; return i }, "sb_on.vars"},
		{"empty disk", "bios", func(i Image) Image { i.Disk = ""; return i }, "bios.disk"},
		{"directory instead of disk", "bios", func(i Image) Image { i.Disk = filepath.Dir(i.Disk); return i }, "bios.disk"},
		{"directory instead of NVRAM", "sb_off", func(i Image) Image { i.Vars = filepath.Dir(i.Vars); return i }, "sb_off.vars"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validTestConfig(t)
			images := cfg.Images["6.8.0-85-generic"]
			images[tc.mode] = tc.edit(images[tc.mode])
			err := cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want explicit %q error, got %v", tc.want, err)
			}
		})
	}
}

func TestConfigRejectsMalformedCommandTemplates(t *testing.T) {
	for _, cmd := range [][]string{{"create", "{{.Name"}, {"create", "{{.Unknown}}"}, {" "}} {
		cfg := validTestConfig(t)
		cfg.CreateCmd = cmd
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "create_cmd") {
			t.Fatalf("command %q: want create_cmd error, got %v", cmd, err)
		}
	}
}

func TestCommandTemplatesPreserveArgumentBoundaries(t *testing.T) {
	vars := Variables{Name: "kpctl-test-job-bios", Disk: "/images/base with spaces; touch injected.qcow2", Firmware: "bios", Memory: 4096, CPUs: 2}
	got, err := commandArgs([]string{"create", "{{.Name}}", "{{.Disk}}", "{{.Vars}}", "{{.Firmware}}", "{{.Memory}}", "{{.CPUs}}"}, vars)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"create", vars.Name, vars.Disk, "", "bios", "4096", "2"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("arguments changed: got %q want %q", got, want)
	}
}

func TestModesJSONAndFleetSelection(t *testing.T) {
	for _, tc := range []struct {
		name       string
		configured string
		fleet      []model.HostStatus
		want       []string
	}{
		{"BIOS fleet", `"auto"`, []model.HostStatus{{Firmware: "bios"}, {Firmware: "bios", SigEnforce: "on"}}, []string{"bios"}},
		{"Secure Boot fleet", `"auto"`, []model.HostStatus{{Firmware: "uefi", SecureBoot: "on"}}, []string{"sb_on"}},
		{"UEFI off fleet", `"auto"`, []model.HostStatus{{Firmware: "uefi", SecureBoot: "off"}}, []string{"sb_off"}},
		{"mixed firmware", `"auto"`, []model.HostStatus{{Firmware: "bios"}, {Firmware: "uefi", SecureBoot: "off"}}, []string{"sb_off", "bios"}},
		{"unknown firmware mixed in", `"auto"`, []model.HostStatus{{Firmware: "bios"}, {Firmware: "unknown"}}, []string{"sb_on", "sb_off", "bios"}},
		{"old agent", `"auto"`, []model.HostStatus{{}}, []string{"sb_on", "sb_off", "bios"}},
		{"unknown Secure Boot", `"auto"`, []model.HostStatus{{Firmware: "uefi", SecureBoot: "unknown"}}, []string{"sb_on", "sb_off", "bios"}},
		{"empty fleet", `"auto"`, nil, []string{"sb_on", "sb_off", "bios"}},
		{"explicit modes", `["bios","sb_on"]`, []model.HostStatus{{Firmware: "uefi", SecureBoot: "off"}}, []string{"bios", "sb_on"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var modes Modes
			if err := json.Unmarshal([]byte(tc.configured), &modes); err != nil {
				t.Fatal(err)
			}
			if got := SelectModes(modes, tc.fleet); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
	for _, invalid := range []string{`"bios"`, `{"bios":true}`, `42`} {
		var modes Modes
		if err := json.Unmarshal([]byte(invalid), &modes); err == nil {
			t.Fatalf("accepted invalid modes %s", invalid)
		}
	}
}

func TestConfigRejectsInvalidResourcesAndModes(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*Config)
	}{
		{"invalid mode", func(c *Config) { c.Modes = Modes{"uefi"} }},
		{"duplicate mode", func(c *Config) { c.Modes = Modes{"bios", "bios"} }},
		{"negative concurrency", func(c *Config) { c.MaxConcurrent = -1 }},
		{"invalid memory", func(c *Config) { c.Memory = 64 }},
		{"negative CPUs", func(c *Config) { c.CPUs = -1 }},
		{"invalid timeout", func(c *Config) { c.CmdTimeout = "3minutes" }},
		{"zero timeout", func(c *Config) { c.CmdTimeout = "0s" }},
		{"inverted ports", func(c *Config) { c.PortRange = "2299-2200" }},
		{"out of range ports", func(c *Config) { c.PortRange = "0-70000" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validTestConfig(t)
			tc.edit(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatal("invalid configuration accepted")
			}
		})
	}
}
