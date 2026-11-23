// 이 파일: model 패키지의 KernelInputNames 구현·자료형.
package model

import (
	"fmt"
	"regexp"
)

var inputKernelRE = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+-[0-9]+-generic$`)

// KernelInputNames limits the controller cache to exact Ubuntu input packages.
// Neither a caller-selected upstream URL nor an arbitrary filesystem path is accepted.
func KernelInputNames(kernel, version, arch string) ([]string, error) {
	if !inputKernelRE.MatchString(kernel) || !regexp.MustCompile(`^`+regexp.QuoteMeta(KernelABI(kernel))+`\.[0-9]+$`).MatchString(version) {
		return nil, fmt.Errorf("커널·패키지 버전이 일치하지 않습니다")
	}
	if arch != "amd64" && arch != "arm64" {
		return nil, fmt.Errorf("지원하지 않는 패키지 아키텍처: %q", arch)
	}
	suffix := "_" + version + "_" + arch
	return []string{
		"linux-image-" + kernel + suffix + ".deb",
		"linux-image-unsigned-" + kernel + suffix + ".deb",
		"linux-modules-" + kernel + suffix + ".deb",
		"linux-headers-" + kernel + suffix + ".deb",
		"linux-headers-" + KernelABI(kernel) + "_" + version + "_all.deb",
		"linux-image-unsigned-" + kernel + "-dbgsym" + suffix + ".ddeb",
		"linux-image-" + kernel + "-dbgsym" + suffix + ".ddeb",
	}, nil
}
