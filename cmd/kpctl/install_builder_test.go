// 이 파일: main 패키지의 TestSplitBuilderArgs, TestKernelsForSeries, TestBuilderConfig 회귀 시험.
package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"kpctl/internal/model"
	"kpctl/internal/remote"
)

func TestSplitBuilderArgs(t *testing.T) {
	hosts, kernels, setup, err := splitBuilderArgs([]string{"build-a", "6.8.0-136-generic", "build-b", "6.8.0-136-generic", "--", "--memory-mib", "16384"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(hosts, []string{"build-a", "build-b"}) || !reflect.DeepEqual(kernels, []string{"6.8.0-136-generic"}) ||
		!reflect.DeepEqual(setup, []string{"--memory-mib", "16384"}) {
		t.Fatalf("hosts=%v kernels=%v setup=%v", hosts, kernels, setup)
	}
	for _, bad := range [][]string{{"build-a", "-check"}, {"build-a", "--", "--config", "x"}, {"build-a", "--", "--plan"}} {
		if _, _, _, err := splitBuilderArgs(bad); err == nil {
			t.Errorf("%v: 오류여야 합니다", bad)
		}
	}
}

func TestKernelsForSeries(t *testing.T) {
	in := []string{"5.15.0-160-generic", "6.8.0-136-generic", "6.8.0-1030-aws"}
	if got := kernelsForSeries(in, "noble"); !reflect.DeepEqual(got, []string{"6.8.0-136-generic", "6.8.0-1030-aws"}) {
		t.Fatalf("noble: %v", got)
	}
	st := &model.StatusResponse{Hosts: []*model.Host{
		{Status: model.HostStatus{Kernel: "6.8.0-136-generic"}}, {Status: model.HostStatus{Kernel: "6.8.0-136-generic"}},
		{Status: model.HostStatus{Kernel: "5.15.0-160-generic"}}, {Status: model.HostStatus{Kernel: "6.8.0-1030-aws"}},
	}}
	if got := registeredKernels(st); !reflect.DeepEqual(got, []string{"5.15.0-160-generic", "6.8.0-136-generic"}) {
		t.Fatalf("registeredKernels: %v", got)
	}
}

func TestBuilderConfig(t *testing.T) {
	dir := t.TempDir()
	example, err := os.ReadFile("../../configs/builder.example.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "builder.example.json"), example, 0o644); err != nil {
		t.Fatal(err)
	}
	data, err := builderConfig(&remote.Bundle{Dir: dir}, "https://ctl:8443", "builder-token-0123456789", "/etc/kpctl/tls/ca.crt")
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg["controller_url"] != "https://ctl:8443" || cfg["token"] != "builder-token-0123456789" ||
		cfg["ca_file"] != "/etc/kpctl/tls/ca.crt" || cfg["series"] != "" || cfg["max_kernels"] != float64(2) {
		t.Fatalf("설정: %v", cfg)
	}
	data, _ = builderConfig(&remote.Bundle{Dir: dir}, "https://ctl:8443", "builder-token-0123456789", "")
	cfg = nil
	_ = json.Unmarshal(data, &cfg)
	if _, ok := cfg["ca_file"]; ok {
		t.Error("CA 없이 ca_file 이 남았습니다")
	}
}

func TestSplitBuilderArgsRejectsUserPassthrough(t *testing.T) {
	if _, _, _, err := splitBuilderArgs([]string{"build-a", "--", "--user", "x"}); err == nil {
		t.Fatal("--user 는 -build-user 로만 받아야 합니다")
	}
	for name, ok := range map[string]bool{"kpbuild": true, "builder_2": true, "Root": false, "a b": false, "-x": false} {
		if buildUserName.MatchString(name) != ok {
			t.Errorf("%q: %v", name, !ok)
		}
	}
}
