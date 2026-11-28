package model

import (
	"strings"
	"testing"
)

func TestDistributionTrackSeparation(t *testing.T) {
	k := DistributionKernel{"debian", "12", "amd64", "6.1.0-57-amd64", "6.1.192-1", strings.Repeat("a", 40)}
	original := k.Track()
	if original == "" {
		t.Fatal("unrecognized Debian track")
	}
	k.Version = "6.1.192-2"
	if k.Track() == original || NativeModuleName(k.Track(), 1) == NativeModuleName(original, 1) {
		t.Fatal("identical ABI confused two package revisions")
	}
	k.Version = "6.1.192-2~deb12u1"
	other, ok := DistributionTrack(k.Track())
	if !ok || other != k {
		t.Fatal("version escaping failed")
	}
	for _, change := range []func(*DistributionKernel){func(k *DistributionKernel) { k.Arch = "arm64" }, func(k *DistributionKernel) { k.Distro = "debian1"; k.Release = "2" }, func(k *DistributionKernel) { k.ABI = "6.1.0-57-rt-amd64" }, func(k *DistributionKernel) { k.Version = "6.1.192-1~bpo12+1" }, func(k *DistributionKernel) { k.Release = "14" }} {
		v := k
		change(&v)
		if v.Track() != "" {
			t.Fatalf("unsupported target %+v", v)
		}
	}
	if !SupportsDistributionABI("debian", "13", "x86_64", "6.12.118+deb13.1-amd64") {
		t.Fatal("Debian ABI update")
	}
}

func TestDistributionKernelNames(t *testing.T) {
	for abi, want := range map[string][2]string{
		"6.12.0-264.21.1.el10_3.x86_64": {"rocky", "10"},
		"5.14.0-741.27.1.el9_9.x86_64":  {"rocky", "9"},
		"6.1.0-57-amd64":                {"debian", "12"},
		"6.12.118+deb13-amd64":          {"debian", "13"},
		"6.12.118+deb13.1-amd64":        {"debian", "13"},
		"4.18.0-553.el8_10.x86_64":      {"", ""}, // Rocky 8: 모양은 배포판 커널이지만 지원 프로필 밖
		"6.1.0-57-arm64":                {"", ""},
		"6.8.0-136-generic":             {"", ""},
	} {
		d, r := DistributionForABI(abi)
		if d != want[0] || r != want[1] {
			t.Errorf("DistributionForABI(%q) = %q %q, want %q %q", abi, d, r, want[0], want[1])
		}
	}
	for name, native := range map[string]bool{
		"6.12.0-264.21.1.el10_3.x86_64": true, "6.12.118+deb13-amd64": true, "6.1.0-57-amd64": true,
		"4.18.0-553.el8_10.x86_64": true, "6.1.0-57-arm64": true, "6.12.0-55.el10.aarch64": true,
		"5.14.0-427.el9.ppc64le": true, "5.14.0-427.el9.s390x": true, "4.18.0-553.el8_10.x86_64+debug": true,
		"6.1.0-57-686-pae": true, "6.1.0-57-rt-amd64": true, "6.1.0-57-cloud-arm64": true, "6.12.118+deb13.1-cloud-amd64": true,
		"6.8.0-136-generic": false, "6.8.0-1030-aws": false, "5.15.0-160-lowlatency": false, "6.8.0-1015-raspi": false,
		"10.0.0.175": false, "build-rocky": false, "rocky10.example.test": false, "x86_64": false,
		"10.0.0-build-amd64": false, "10.0.0-rack.x86_64": false, "1.2.3-db-arm64": false,
	} {
		if IsDistributionKernelName(name) != native {
			t.Errorf("IsDistributionKernelName(%q) = %v", name, !native)
		}
	}
	if DistroLabel("rocky") != "Rocky" || DistroLabel("") != "알 수 없는 OS" || DistroLabel("alpine") != "alpine" {
		t.Error("DistroLabel")
	}
}
