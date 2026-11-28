// 이 파일: main 패키지의 TestSplitBuilderArgs, TestKernelsForSeries, TestBuilderConfig 회귀 시험.
package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
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

// Rocky·Debian 커널을 호스트로 오인해 SSH 로 접속하지 않고, 접속 전에 네이티브 빌더 안내로 거부해야 합니다.
func TestSplitBuilderArgsRejectsDistributionKernels(t *testing.T) {
	for kernel, label := range map[string]string{
		"6.12.0-264.21.1.el10_3.x86_64": "Rocky 10 배포판 커널",
		"5.14.0-741.27.1.el9_9.x86_64":  "Rocky 9 배포판 커널",
		"6.1.0-57-amd64":                "Debian 12 배포판 커널",
		"6.12.118+deb13-amd64":          "Debian 13 배포판 커널",
		"4.18.0-553.el8_10.x86_64":      "Ubuntu 가 아닌 배포판 커널",
		"5.14.0-427.el9.ppc64le":        "Ubuntu 가 아닌 배포판 커널",
		"6.1.0-57-686-pae":              "Ubuntu 가 아닌 배포판 커널",
	} {
		hosts, kernels, _, err := splitBuilderArgs([]string{"10.0.0.175", kernel})
		if err == nil {
			t.Fatalf("%s: 오류여야 합니다 (hosts=%v kernels=%v)", kernel, hosts, kernels)
		}
		msg := err.Error()
		if !strings.Contains(msg, kernel+" 는 "+label) || !strings.Contains(msg, "kpctl-native-builder.py") || !strings.Contains(msg, "distribution-kernels.md") {
			t.Errorf("%s: 안내가 부족합니다: %v", kernel, err)
		}
	}
	// 같은 커널을 두 번 줘도 안내는 한 번
	_, _, _, err := splitBuilderArgs([]string{"b", "6.1.0-57-amd64", "6.1.0-57-amd64"})
	if err == nil || strings.Count(err.Error(), "6.1.0-57-amd64") != 1 {
		t.Errorf("중복 안내: %v", err)
	}
	// IP 주소·Ubuntu 커널은 그대로
	hosts, kernels, _, err := splitBuilderArgs([]string{"10.0.0.175", "6.8.0-136-generic", "build-rocky.example.test", "10.0.0-build-amd64"})
	if err != nil || !reflect.DeepEqual(hosts, []string{"10.0.0.175", "build-rocky.example.test", "10.0.0-build-amd64"}) || !reflect.DeepEqual(kernels, []string{"6.8.0-136-generic"}) {
		t.Fatalf("hosts=%v kernels=%v err=%v", hosts, kernels, err)
	}
}

func TestKernelsForSeriesDropsDistributionKernels(t *testing.T) {
	in := []string{"6.8.0-136-generic", "6.12.0-264.21.1.el10_3.x86_64", "6.1.0-57-amd64", "6.8.0-1030-aws"}
	if got := kernelsForSeries(in, "noble"); !reflect.DeepEqual(got, []string{"6.8.0-136-generic", "6.8.0-1030-aws"}) {
		t.Fatalf("noble: %v", got)
	}
	st := &model.StatusResponse{Hosts: []*model.Host{
		{Status: model.HostStatus{Kernel: "6.12.0-264.21.1.el10_3.x86_64"}}, {Status: model.HostStatus{Kernel: "6.1.0-57-amd64"}},
	}}
	if got := registeredKernels(st); len(got) != 0 {
		t.Fatalf("Rocky/Debian 등록 호스트 커널이 Ubuntu 빌더 대상으로 골라졌습니다: %v", got)
	}
	if exampleKernel("jammy") != "5.15.0-160-generic" || exampleKernel("resolute") != "6.8.0-136-generic" || kernelShape("resolute") != "7.0.0-번호-generic" {
		t.Error("exampleKernel/kernelShape")
	}
}

// -force 로도 Rocky 빌드 서버에는 설치 단계(임시 디렉터리·묶음 복사·토큰 설정 전송·서비스 중지)로 넘어가지 않아야 합니다.
func TestInstallBuilderForceRefusesNonUbuntuHost(t *testing.T) {
	dir := t.TempDir()
	bin, bundle, calls := filepath.Join(dir, "bin"), filepath.Join(dir, "bundle"), filepath.Join(dir, "ssh-calls")
	for _, d := range []string{bin, filepath.Join(bundle, "kpatch-fixes"), filepath.Join(bundle, "build-environment")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{"setup-builder.sh", "kpctl-builder.service", "kpctl-kernel-debug.sh", "kpctl-kernel-inputs.py", "kpctl-kpatch-fixes.sh",
		"kpctl-kpatch-cold-test.py", "setup-build-environment.sh", "kpctl-build-environment.py"} {
		if err := os.WriteFile(filepath.Join(bundle, f), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	exe, err := os.Executable() // ELF 아키텍처만 읽으므로 시험 바이너리로 대신합니다
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	example, err := os.ReadFile("../../configs/builder.example.json")
	if err != nil {
		t.Fatal(err)
	}
	token, key := filepath.Join(dir, "builder.token"), filepath.Join(dir, "id_test")
	for p, body := range map[string][]byte{filepath.Join(bundle, "kpctl-builder"): data, filepath.Join(bundle, "builder.example.json"): example,
		token: []byte("builder-token-0123456789abcdef\n"), key: nil} {
		if err := os.WriteFile(p, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	arch, err := remote.OpenBuilderBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	fake := "#!/bin/bash\necho \"${@: -1}\" >> " + calls + "\ncat >/dev/null\ncat <<'FACTS'\nhostname=rocky10-host\nuid=0\narch=" + arch.Arch +
		"\nkernel=6.12.0-264.21.1.el10_3.x86_64\nsudo=ok\ncontroller=200\nnameresolves=yes\nagent=none\nrole=host\ndistro=rocky\nrelease=10.1\ncodename=\nbuilderactive=yes\nbuilderconfig=no\nFACTS\n"
	if err := os.WriteFile(filepath.Join(bin, "ssh"), []byte(fake), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("KPCTL_SSH_KEY", key)
	t.Setenv("KPCTL_BUILDER_BUNDLE", bundle)

	results, err := runBuilderInstall(nil, []string{"-force", "-stop-running", "-builder-token-file", token, "-log-dir", filepath.Join(dir, "logs"),
		"-controller-url", "https://ctl:8443", "10.0.0.175", "6.8.0-136-generic"})
	if err == nil || len(results) != 1 || results[0].ok || results[0].result != "점검 실패" || !strings.Contains(results[0].note, "Rocky 10.1 호스트입니다") {
		t.Fatalf("results=%+v err=%v", results, err)
	}
	got, _ := os.ReadFile(calls)
	if n := strings.Count(string(got), "\n"); n != 1 || !strings.HasPrefix(string(got), "bash -s -- ") {
		t.Fatalf("사전 점검 외의 원격 명령이 실행됐습니다:\n%s", got)
	}
}
