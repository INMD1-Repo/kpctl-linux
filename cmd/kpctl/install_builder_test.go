// 이 파일: main 패키지의 TestSplitBuilderArgs, TestKernelsForSeries, TestBuilderConfig 회귀 시험.
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"kpctl/internal/client"
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

// Debian 12·Rocky 9·10 커널은 호스트로 오인하지 않고 커널로 받습니다 (네이티브 빌더 대상).
// 빌드할 수 없는 배포판 커널(Debian 13 IBT, 지원 프로필 밖)은 SSH 접속 전에 이유와 함께 거부합니다.
func TestSplitBuilderArgsDistributionKernels(t *testing.T) {
	hosts, kernels, _, err := splitBuilderArgs([]string{"10.0.0.176", "6.12.0-264.21.1.el10_3.x86_64", "5.14.0-741.27.1.el9_9.x86_64", "6.1.0-57-amd64", "6.8.0-136-generic"})
	if err != nil || !reflect.DeepEqual(hosts, []string{"10.0.0.176"}) ||
		!reflect.DeepEqual(kernels, []string{"6.12.0-264.21.1.el10_3.x86_64", "5.14.0-741.27.1.el9_9.x86_64", "6.1.0-57-amd64", "6.8.0-136-generic"}) {
		t.Fatalf("hosts=%v kernels=%v err=%v", hosts, kernels, err)
	}
	for kernel, want := range map[string]string{
		"6.12.118+deb13-amd64":     "IBT",
		"4.18.0-553.el8_10.x86_64": "지원하지 않는 배포판 커널",
		"5.14.0-427.el9.ppc64le":   "지원하지 않는 배포판 커널",
		"6.1.0-57-686-pae":         "지원하지 않는 배포판 커널",
	} {
		_, _, _, err := splitBuilderArgs([]string{"10.0.0.176", kernel})
		if err == nil || !strings.Contains(err.Error(), kernel) || !strings.Contains(err.Error(), want) || !strings.Contains(err.Error(), "Debian 12, Rocky 9·10") {
			t.Errorf("%s: %v", kernel, err)
		}
	}
	// 같은 커널을 두 번 줘도 안내는 한 번
	_, _, _, err = splitBuilderArgs([]string{"b", "6.12.118+deb13-amd64", "6.12.118+deb13-amd64"})
	if err == nil || strings.Count(err.Error(), "6.12.118+deb13-amd64 는") != 1 {
		t.Errorf("중복 안내: %v", err)
	}
	hosts, kernels, _, err = splitBuilderArgs([]string{"10.0.0.175", "6.8.0-136-generic", "build-rocky.example.test", "10.0.0-build-amd64"})
	if err != nil || !reflect.DeepEqual(hosts, []string{"10.0.0.175", "build-rocky.example.test", "10.0.0-build-amd64"}) || !reflect.DeepEqual(kernels, []string{"6.8.0-136-generic"}) {
		t.Fatalf("hosts=%v kernels=%v err=%v", hosts, kernels, err)
	}
}

func nativeKernel(distro, release, abi, version, id string) model.DistributionKernel {
	return model.DistributionKernel{Distro: distro, Release: release, Arch: "amd64", ABI: abi, Version: version, BuildID: strings.Repeat(id, 40)}
}

func TestNativeTargetsFor(t *testing.T) {
	r10 := nativeKernel("rocky", "10", "6.12.0-264.21.1.el10_3.x86_64", "6.12.0-264.21.1.el10_3", "a")
	r10b := nativeKernel("rocky", "10", "6.12.0-264.21.1.el10_3.x86_64", "6.12.0-264.21.1.el10_3", "b") // 같은 ABI 다른 빌드
	r9 := nativeKernel("rocky", "9", "5.14.0-741.27.1.el9_9.x86_64", "5.14.0-741.27.1.el9_9", "c")
	d12 := nativeKernel("debian", "12", "6.1.0-57-amd64", "6.1.192-3", "d")
	st := &model.StatusResponse{}
	for _, k := range []model.DistributionKernel{r10, r10b, r9, d12, r10} {
		k := k
		st.Hosts = append(st.Hosts, &model.Host{Status: model.HostStatus{Kernel: k.ABI, Distribution: &k}})
	}
	trixie := nativeKernel("debian", "13", "6.12.118+deb13-amd64", "6.12.118-1", "e")
	st.Hosts = append(st.Hosts, &model.Host{Status: model.HostStatus{Kernel: trixie.ABI, Distribution: &trixie}},
		&model.Host{Status: model.HostStatus{Kernel: "6.8.0-136-generic"}})
	reg := registeredNativeKernels(st)
	if len(reg) != 4 {
		t.Fatalf("등록 커널(중복·Debian 13·Ubuntu 제외): %+v", reg)
	}
	// 커널 생략: 같은 릴리스의 등록 커널 전부, 같은 ABI 의 다른 빌드도 각각
	got := nativeTargetsFor(nil, reg, "rocky", "10")
	if len(got) != 2 || got[0].ABI != r10.ABI || got[1].ABI != r10.ABI || got[0].Track == got[1].Track || got[0].Track == "" {
		t.Fatalf("rocky10 자동: %+v", got)
	}
	// 지정: 같은 릴리스만, 등록 안 된 ABI 는 track 없이
	got = nativeTargetsFor([]string{"5.14.0-741.27.1.el9_9.x86_64", "5.14.0-742.1.1.el9_9.x86_64", "6.1.0-57-amd64"}, reg, "rocky", "9")
	want := []remote.NativeTarget{{ABI: r9.ABI, Track: r9.Track()}, {ABI: "5.14.0-742.1.1.el9_9.x86_64"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("rocky9 지정: %+v", got)
	}
	if got[0].Arg() != r9.ABI+"="+r9.Track() || got[1].Arg() != "5.14.0-742.1.1.el9_9.x86_64" {
		t.Fatalf("Arg: %s %s", got[0].Arg(), got[1].Arg())
	}
	if got := nativeTargetsFor(nil, reg, "debian", "13"); len(got) != 0 {
		t.Fatalf("Debian 13: %+v", got)
	}
}

func TestNativeWorkerConfig(t *testing.T) {
	data, err := nativeWorkerConfig("https://ctl:8443", "/local/ca.crt", "rocky10-build")
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]string
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(cfg, map[string]string{"controller_url": "https://ctl:8443", "ca_file": "/etc/kpctl/tls/ca.crt",
		"token_file": "/etc/kpctl/native-builder/token", "builder": "rocky10-build"}) {
		t.Fatalf("worker.json: %v", cfg)
	}
	if strings.Contains(string(data), "token\": \"") && !strings.Contains(string(data), "token_file") {
		t.Fatal("토큰 원문이 worker.json 에 들어갔습니다")
	}
}

// 설치 후 안내: 승인 핀은 독립 환경에서 만든다는 것과 track 을 보여야 합니다 (codex 구현).
func TestNativeProofHint(t *testing.T) {
	r10 := nativeKernel("rocky", "10", "6.12.0-264.21.1.el10_3.x86_64", "6.12.0-264.21.1.el10_3", "a")
	hint := nativeProofHint([]remote.NativeTarget{{ABI: r10.ABI, Track: r10.Track()}, {ABI: "6.12.0-265.1.1.el10_3.x86_64"}})
	for _, want := range []string{r10.Track(), "distribution-proofs/", "독립", "/var/lib/kpctl-native/tracks/", "collect", "kpctl-agent -identify"} {
		if !strings.Contains(hint, want) {
			t.Errorf("안내에 %q 없음:\n%s", want, hint)
		}
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

// writeBuilderBundles 는 root/<종류>/ 에 배포판별 빌더 묶음(make dist 의 dist/builder)을 만듭니다.
// kpctl-builder 는 ELF 아키텍처만 읽으므로 시험 바이너리로 대신합니다.
func writeBuilderBundles(t *testing.T, root string, flavors ...string) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	elfData, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	example, err := os.ReadFile("../../configs/builder.example.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, flavor := range flavors {
		dir := filepath.Join(root, flavor)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		for _, f := range remote.BuilderBundleFiles(flavor) {
			var body []byte
			switch f {
			case "kpatch-fixes", "build-environment":
				if err := os.MkdirAll(filepath.Join(dir, f), 0o755); err != nil {
					t.Fatal(err)
				}
				continue
			case "kpctl-builder":
				body = elfData
			case "builder.example.json":
				body = example
			case "builder-flavor":
				body = []byte(flavor + "\n")
			}
			if err := os.WriteFile(filepath.Join(dir, f), body, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestKernelFlavor(t *testing.T) {
	for k, want := range map[string]string{
		"6.8.0-136-generic":             remote.FlavorUbuntu,
		"5.15.0-140-generic":            remote.FlavorUbuntu,
		"6.8.0-1020-aws":                remote.FlavorUbuntu,
		"6.1.0-57-amd64":                remote.FlavorDebian,
		"6.12.118+deb13-amd64":          remote.FlavorDebian,
		"6.12.0-264.21.1.el10_3.x86_64": remote.FlavorRocky,
		"5.14.0-570.12.1.el9_6.x86_64":  remote.FlavorRocky,
		"4.18.0-553.el8_10.x86_64":      remote.FlavorRocky, // 지원 밖이어도 RHEL 계열 모양이면 rocky 빌더용
		"build-01":                      "",
	} {
		if got := kernelFlavor(k); got != want {
			t.Errorf("kernelFlavor(%s) = %q, want %q", k, got, want)
		}
	}
	ks := []string{"6.12.0-264.21.1.el10_3.x86_64", "6.8.0-136-generic", "6.1.0-57-amd64"}
	if got := flavorSummary(ks); got != "Ubuntu 빌더 6.8.0-136-generic · Debian 빌더 6.1.0-57-amd64 · Rocky 빌더 6.12.0-264.21.1.el10_3.x86_64" {
		t.Errorf("flavorSummary = %q", got)
	}
	if m := flavorMismatch(ks, remote.FlavorDebian, "Debian 12"); m != "" {
		t.Errorf("Debian 커널이 하나라도 있으면 불일치가 아님: %q", m)
	}
	if m := flavorMismatch(nil, remote.FlavorDebian, "Debian 12"); m != "" {
		t.Errorf("커널 생략은 불일치가 아님: %q", m)
	}
	if m := flavorMismatch([]string{"6.8.0-136-generic"}, remote.FlavorRocky, "Rocky 10"); !strings.Contains(m, "Ubuntu 빌더 6.8.0-136-generic 용인데 이 호스트는 Rocky 10") {
		t.Errorf("flavorMismatch = %q", m)
	}
}

// fakeBuilderHost 는 사전 점검(bash -s) 명령에 주어진 사실을 돌려주고 받은 원격 명령을 calls 에 적는 가짜 ssh 를 PATH 앞에 둡니다.
func fakeBuilderHost(t *testing.T, dir, facts string) (calls string) {
	t.Helper()
	bin := filepath.Join(dir, "bin")
	calls = filepath.Join(dir, "ssh-calls")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	fake := "#!/bin/bash\necho \"${@: -1}\" >> " + calls + "\ncat >/dev/null\ncat <<'FACTS'\n" + facts + "FACTS\n"
	if err := os.WriteFile(filepath.Join(bin, "ssh"), []byte(fake), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	return calls
}

func onlyPreflight(t *testing.T, calls string) {
	t.Helper()
	got, _ := os.ReadFile(calls)
	if n := strings.Count(string(got), "\n"); n != 1 || !strings.HasPrefix(string(got), "bash -s -- ") {
		t.Fatalf("사전 점검 외의 원격 명령이 실행됐습니다:\n%s", got)
	}
}

func builderTestClient(t *testing.T) *client.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"hosts":[],"builders":{}}`)) }))
	t.Cleanup(srv.Close)
	c, err := client.New(srv.URL, "admin-token-0123456789", "")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

const rocky10Facts = "hostname=rocky10-host\nuid=0\narch=%s\nkernel=6.12.0-264.21.1.el10_3.x86_64\nsudo=ok\ncontroller=200\nnameresolves=yes\nagent=%s\nrole=host\ndistro=rocky\nrelease=10.1\ncodename=\nrelease_type=stable\nx86v3=yes\nvirt=kvm\ncontainer=none\nsystemd=yes\nvarfree=209715200\nnativebuilderactive=yes\nnativebuilderconfig=no\n"

// 대상 커널 이름이 다른 배포판용이거나, 호스트 배포판 전용 묶음이 없으면 -force 로도 복사·설치 단계로 넘어가지 않습니다.
func TestInstallBuilderPicksBundleByKernelName(t *testing.T) {
	for _, tc := range []struct {
		name    string
		flavors []string
		kernel  string
		want    string
	}{
		{"Ubuntu 커널을 Rocky 호스트에", []string{"ubuntu", "debian", "rocky"}, "6.8.0-136-generic", "Ubuntu 빌더 6.8.0-136-generic 용인데 이 호스트는 Rocky"},
		{"Debian 커널을 Rocky 호스트에", []string{"ubuntu", "debian", "rocky"}, "6.1.0-57-amd64", "Debian 빌더 6.1.0-57-amd64 용인데 이 호스트는 Rocky"},
		{"Rocky 묶음 없음", []string{"ubuntu", "debian"}, "6.12.0-264.21.1.el10_3.x86_64", "Rocky 전용 묶음(rocky/)이 없습니다"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			bundle, token, key := filepath.Join(dir, "bundle"), filepath.Join(dir, "builder.token"), filepath.Join(dir, "id_test")
			writeBuilderBundles(t, bundle, tc.flavors...)
			for p, body := range map[string]string{token: "builder-token-0123456789abcdef\n", key: ""} {
				if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			bs, err := remote.OpenBuilderBundle(bundle)
			if err != nil {
				t.Fatal(err)
			}
			calls := fakeBuilderHost(t, dir, fmt.Sprintf(rocky10Facts, bs.Arch, "none"))
			t.Setenv("KPCTL_SSH_KEY", key)
			t.Setenv("KPCTL_BUILDER_BUNDLE", bundle)
			results, err := runBuilderInstall(builderTestClient(t), []string{"-force", "-stop-running", "-builder-token-file", token, "-log-dir", filepath.Join(dir, "logs"),
				"-controller-url", "https://ctl:8443", "10.0.0.175", tc.kernel})
			if err == nil || len(results) != 1 || results[0].ok || results[0].result != "점검 실패" || !strings.Contains(results[0].note, tc.want) {
				t.Fatalf("results=%+v err=%v", results, err)
			}
			onlyPreflight(t, calls)
		})
	}
}

// 에이전트가 설치된 Rocky 운영 호스트에는 -force 로도 설치 단계(임시 디렉터리·묶음 복사·토큰 설정 전송·서비스 중지)로
// 넘어가지 않아야 합니다 (NativeBuilderHardBlock).
func TestInstallBuilderForceRefusesNativeAgentHost(t *testing.T) {
	dir := t.TempDir()
	bundle, token, key := filepath.Join(dir, "bundle"), filepath.Join(dir, "builder.token"), filepath.Join(dir, "id_test")
	writeBuilderBundles(t, bundle, remote.BuilderFlavors...)
	for p, body := range map[string]string{token: "builder-token-0123456789abcdef\n", key: ""} {
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	bs, err := remote.OpenBuilderBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	calls := fakeBuilderHost(t, dir, fmt.Sprintf(rocky10Facts, bs.Arch, "installed"))
	t.Setenv("KPCTL_SSH_KEY", key)
	t.Setenv("KPCTL_BUILDER_BUNDLE", bundle)

	// 커널을 지정해도 등록 호스트 track 대조를 위해 컨트롤러 상태를 읽습니다
	results, err := runBuilderInstall(builderTestClient(t), []string{"-force", "-stop-running", "-builder-token-file", token, "-log-dir", filepath.Join(dir, "logs"),
		"-controller-url", "https://ctl:8443", "10.0.0.175", "6.12.0-264.21.1.el10_3.x86_64"})
	if err == nil || len(results) != 1 || results[0].ok || results[0].result != "점검 실패" || !strings.Contains(results[0].note, "-force 로도 넘길 수 없음") {
		t.Fatalf("results=%+v err=%v", results, err)
	}
	onlyPreflight(t, calls)
}
