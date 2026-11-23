// 이 파일: model 패키지의 NewTaskPatch, Validate, Validate 구현·자료형.
package model

import (
	"crypto/sha256"
	"fmt"
	"regexp"
	"strings"
)

var taskPatchID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]*$`)

// NewTaskPatch computes file metadata from the exact bytes being sent.
func NewTaskPatch(id string, content []byte) TaskPatch {
	return TaskPatch{
		ID: id, Content: string(content), Filename: id + ".patch",
		Size: int64(len(content)), SHA256: fmt.Sprintf("%x", sha256.Sum256(content)),
	}
}

// Validate accepts legacy tasks without metadata, but never partial metadata.
func (p TaskPatch) Validate() error {
	if !taskPatchID.MatchString(p.ID) {
		return fmt.Errorf("패치 ID가 잘못됐습니다: %q", p.ID)
	}
	if p.Filename == "" && p.Size == 0 && p.SHA256 == "" {
		return nil
	}
	if p.Filename != p.ID+".patch" {
		return fmt.Errorf("패치 %s 파일명이 일치하지 않습니다: %q", p.ID, p.Filename)
	}
	if p.Size != int64(len(p.Content)) {
		return fmt.Errorf("패치 %s 크기 불일치: 받은 본문 %d, 컨트롤러 %d", p.ID, len(p.Content), p.Size)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256([]byte(p.Content))); p.SHA256 != got {
		return fmt.Errorf("패치 %s SHA-256 불일치", p.ID)
	}
	return nil
}

// Validate binds the package version and source tag to this exact GA ABI.
func (k BuildKernelInfo) Validate(kernel string) error {
	if k.Kernel != kernel || !strings.HasSuffix(kernel, "-generic") {
		return fmt.Errorf("작업과 커널 기준 정보가 일치하지 않습니다: %q / %q", kernel, k.Kernel)
	}
	versionRE := regexp.MustCompile(`^` + regexp.QuoteMeta(KernelABI(kernel)) + `\.[0-9]+$`)
	if !versionRE.MatchString(k.PackageVersion) || SignatureVersion(k.Signature) != k.PackageVersion ||
		k.BaseTag != "Ubuntu-"+k.PackageVersion {
		return fmt.Errorf("커널 %s의 서명·패키지 버전·기준 태그가 일치하지 않습니다", kernel)
	}
	fields := strings.Fields(k.Signature)
	if fields[1] != k.PackageVersion+"-generic" {
		return fmt.Errorf("커널 %s의 서명 변형이 일치하지 않습니다", kernel)
	}
	return nil
}
