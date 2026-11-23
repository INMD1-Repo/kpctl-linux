// 이 파일: model 패키지의 TestBootTargetIDMatchesKernelPreparationRecord 회귀 시험.
package model

import (
	"strings"
	"testing"
)

func TestBootTargetIDMatchesKernelPreparationRecord(t *testing.T) {
	// Shared protocol vector with test/kernel_prepare_test.py.
	target := BootTarget{
		Kernel: "6.8.0-86-generic", PackageVersion: "6.8.0-86.86",
		Entry:         "gnulinux-advanced-abc>gnulinux-6.8.0-86-generic-advanced-abc",
		FallbackEntry: "gnulinux-advanced-abc>gnulinux-6.8.0-85-generic-advanced-abc",
		ImageSHA256:   strings.Repeat("a", 64), InitrdSHA256: strings.Repeat("b", 64),
		ConfigSHA256: strings.Repeat("c", 64), GrubSHA256: strings.Repeat("d", 64),
	}
	const expected = "0a3008930c2a6f3c644d9e3e99bf9473b9a374a19cd739c67eaf175c71ef6878"
	if got := BootTargetID(target); got != expected {
		t.Fatalf("boot target ID = %s, want preparation protocol ID %s", got, expected)
	}
}
