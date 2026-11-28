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
