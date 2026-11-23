// 이 파일: builder 패키지의 deb822Records, officialPackageIndex, publishedKernelVersion 구현·자료형.
package builder

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"kpctl/internal/model"
)

// deb822Records 는 APT 메타데이터를 한 문단씩 읽습니다. 긴 설명의 이어지는 줄은 쓰지 않습니다.
func deb822Records(r io.Reader, visit func(map[string]string) error) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	record := map[string]string{}
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			if len(record) > 0 {
				if err := visit(record); err != nil {
					return err
				}
				record = map[string]string{}
			}
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if ok {
			record[key] = strings.TrimSpace(value)
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if len(record) > 0 {
		return visit(record)
	}
	return nil
}

func officialPackageIndex(r map[string]string, series, arch string) bool {
	suite := r["Suite"]
	return r["Origin"] == "Ubuntu" && r["Label"] == "Ubuntu" && r["Trusted"] == "yes" &&
		r["Codename"] == series && r["Architecture"] == arch && r["Component"] == "main" &&
		r["Identifier"] == "Packages" && r["Filename"] != "" &&
		(suite == series || suite == series+"-updates" || suite == series+"-security")
}

// publishedKernelVersion 은 APT가 신뢰하는 정식 배포 색인에 실제 존재하는 GA 커널의
// linux 소스 버전을 고릅니다. 메타패키지 버전과 개발용 Git 태그는 기준으로 쓰지 않습니다.
func publishedKernelVersion(ctx context.Context, series, kernel string) (string, error) {
	archOut, err := exec.CommandContext(ctx, "dpkg", "--print-architecture").Output()
	if err != nil {
		return "", fmt.Errorf("APT 아키텍처 확인 실패: %w", err)
	}
	arch := strings.TrimSpace(string(archOut))
	indexes, err := exec.CommandContext(ctx, "apt-get", "indextargets").Output()
	if err != nil {
		return "", fmt.Errorf("APT 배포 색인 확인 실패: %w", err)
	}
	var files []string
	seen := map[string]bool{}
	err = deb822Records(bytes.NewReader(indexes), func(r map[string]string) error {
		if officialPackageIndex(r, series, arch) && !seen[r["Filename"]] {
			seen[r["Filename"]] = true
			files = append(files, r["Filename"])
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	helper, err := exec.LookPath("apt-helper")
	if err != nil {
		helper = "/usr/lib/apt/apt-helper"
	}
	image := regexp.MustCompile(`^linux-image-unsigned-` + regexp.QuoteMeta(kernel) + `-[0-9]+-generic$`)
	versions := map[string]bool{}
	for _, file := range files {
		cmd := exec.CommandContext(ctx, helper, "cat-file", file)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			return "", err
		}
		if err := cmd.Start(); err != nil {
			return "", err
		}
		parseErr := deb822Records(stdout, func(r map[string]string) error {
			if !image.MatchString(r["Package"]) || r["Architecture"] != arch {
				return nil
			}
			source := strings.Fields(r["Source"])
			if len(source) == 0 || source[0] != "linux" {
				return nil
			}
			version := r["Version"]
			if len(source) == 2 {
				version = strings.Trim(source[1], "()")
			}
			if strings.HasPrefix(version, kernel+"-") {
				versions[version] = true
			}
			return nil
		})
		if parseErr != nil {
			_ = cmd.Process.Kill()
		}
		runErr := cmd.Wait()
		if parseErr != nil || runErr != nil {
			return "", fmt.Errorf("APT 색인 읽기 실패 (%s): 파싱=%v 실행=%v %s", file, parseErr, runErr, strings.TrimSpace(stderr.String()))
		}
	}
	var latest string
	for version := range versions {
		if latest == "" {
			latest = version
			continue
		}
		err := exec.CommandContext(ctx, "dpkg", "--compare-versions", version, "gt", latest).Run()
		if err == nil {
			latest = version
		} else if ee, ok := err.(*exec.ExitError); !ok || ee.ExitCode() != 1 {
			return "", fmt.Errorf("Ubuntu 커널 버전 비교 실패: %w", err)
		}
	}
	if latest == "" {
		return "", fmt.Errorf("%s 정식 APT 색인에서 %s generic 커널을 확인하지 못했습니다 (APT 색인·저장소 설정 확인)", series, kernel)
	}
	return latest, nil
}

// latestTargetTag 는 자동 모드에서 정식 배포 버전과 정확히 일치하는 태그만 허용합니다.
// 직접 지정한 파생 커널은 관리자가 정한 Git 범위를 유지합니다.
func (b *Builder) latestTargetTag(k KernelConfig, remote bool) (string, error) {
	// 출시 전 채널을 켠 직접 지정 커널도 공식 수집이 개발 태그를 먼저 삼키지 않도록
	// APT 상한을 공유합니다. 기능 생략/꺼짐의 기존 직접 지정 동작은 그대로 둡니다.
	if !b.cfg.autoKernels() && (k.Prerelease == nil || !k.Prerelease.Enabled) {
		if remote {
			return remoteLatestTag(k.GitDir, k.TagGlob)
		}
		return latestTag(k.GitDir, k.TagGlob)
	}
	return b.officialTargetTag(k, remote)
}

// officialTargetTag는 직접 지정한 출시 전 수집에도 APT 정식 상한을 강제합니다.
// 기존 직접 지정 수집의 latestTargetTag 동작은 변경하지 않습니다.
func (b *Builder) officialTargetTag(k KernelConfig, remote bool) (string, error) {
	s := model.LTSForKernel(k.Kernel)
	if s == nil || (b.cfg.autoKernels() && s.Codename != b.cfg.Series) || (b.cfg.Series != "" && s.Codename != b.cfg.Series) {
		return "", fmt.Errorf("%s 의 정식 GA 커널 배포 계열을 확인하지 못했습니다", k.Kernel)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	version, err := publishedKernelVersion(ctx, s.Codename, s.Kernel)
	if err != nil {
		return "", err
	}
	tag := "Ubuntu-" + version
	var args []string
	if remote {
		args = []string{"-C", k.GitDir, "ls-remote", "--tags", "--refs", "origin", "refs/tags/" + tag}
	} else {
		args = []string{"-C", k.GitDir, "tag", "-l", tag}
	}
	out, err := exec.CommandContext(ctx, "git", args...).Output()
	if err != nil {
		return "", fmt.Errorf("정식 배포 %s 의 Git 태그 확인 실패: %w", version, err)
	}
	if strings.TrimSpace(string(out)) == "" {
		return "", fmt.Errorf("정식 배포 %s 에 대응하는 Git 태그가 없습니다", version)
	}
	return tag, nil
}
