// 이 파일: model 패키지의 NewerGAKernel, BootTargetID, ValidBootTarget 구현·자료형.
package model

import (
	"crypto/sha256"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var gaRelease = regexp.MustCompile(`^(5\.15\.0|6\.8\.0|7\.0\.0)-([0-9]+)-generic$`)
var digest256 = regexp.MustCompile(`^[a-f0-9]{64}$`)

func NewerGAKernel(current, target string) bool {
	a, b := gaRelease.FindStringSubmatch(current), gaRelease.FindStringSubmatch(target)
	if a == nil || b == nil || a[1] != b[1] {
		return false
	}
	ai, e1 := strconv.Atoi(a[2])
	bi, e2 := strconv.Atoi(b[2])
	return e1 == nil && e2 == nil && bi > ai
}
func BootTargetID(t BootTarget) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(strings.Join([]string{t.Kernel, t.PackageVersion, t.Entry, t.FallbackEntry, t.ImageSHA256, t.InitrdSHA256, t.ConfigSHA256, t.GrubSHA256}, "\n"))))
}
func ValidBootTarget(current string, t *BootTarget) bool {
	if t == nil || !NewerGAKernel(current, t.Kernel) || t.ID != BootTargetID(*t) {
		return false
	}
	for _, h := range []string{t.ImageSHA256, t.InitrdSHA256, t.ConfigSHA256, t.GrubSHA256} {
		if !digest256.MatchString(h) {
			return false
		}
	}
	return strings.HasPrefix(t.PackageVersion, KernelABI(t.Kernel)+".") && regexp.MustCompile(`^gnulinux-advanced-[a-fA-F0-9-]+>gnulinux-`+regexp.QuoteMeta(t.Kernel)+`-advanced-[a-fA-F0-9-]+$`).MatchString(t.Entry) && regexp.MustCompile(`^gnulinux-advanced-[a-fA-F0-9-]+>gnulinux-`+regexp.QuoteMeta(current)+`-advanced-[a-fA-F0-9-]+$`).MatchString(t.FallbackEntry)
}
