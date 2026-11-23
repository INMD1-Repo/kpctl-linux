// 이 파일: model 패키지의 TestTaskPatchMetadataRoundTrip, TestTaskPatchRejectsCorruptionAndUnsafeNames, TestBuildKernelInfoMatchesExactABI 회귀 시험.
package model

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestTaskPatchMetadataRoundTrip(t *testing.T) {
	content := []byte("--- a\n+++ b\n@@\n+커널 수정\n")
	p := NewTaskPatch("p0001", content)
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var got TaskPatch
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got.Filename != "p0001.patch" || got.Size != int64(len(content)) || len(got.SHA256) != 64 {
		t.Fatalf("missing file metadata: %+v", got)
	}
	if err := got.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := (TaskPatch{ID: "p0001", Content: string(content)}).Validate(); err != nil {
		t.Fatalf("legacy controller must remain compatible: %v", err)
	}
	if err := NewTaskPatch("p0001", nil).Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestTaskPatchRejectsCorruptionAndUnsafeNames(t *testing.T) {
	for name, change := range map[string]func(*TaskPatch){
		"content":            func(p *TaskPatch) { p.Content = "other" },
		"size":               func(p *TaskPatch) { p.Size++ },
		"negative size":      func(p *TaskPatch) { p.Size = -1 },
		"hash":               func(p *TaskPatch) { p.SHA256 = strings.Repeat("0", 64) },
		"missing hash":       func(p *TaskPatch) { p.SHA256 = "" },
		"missing filename":   func(p *TaskPatch) { p.Filename = "" },
		"filename traversal": func(p *TaskPatch) { p.Filename = "../p0001.patch" },
		"id traversal":       func(p *TaskPatch) { p.ID = "../../escape" },
	} {
		t.Run(name, func(t *testing.T) {
			p := NewTaskPatch("p0001", []byte("patch"))
			change(&p)
			if err := p.Validate(); err == nil {
				t.Fatal("invalid task file accepted")
			}
		})
	}
	if err := (TaskPatch{ID: "../../escape"}).Validate(); err == nil {
		t.Fatal("legacy IDs must also be safe")
	}
}

func TestBuildKernelInfoMatchesExactABI(t *testing.T) {
	base := BuildKernelInfo{Kernel: "6.8.0-85-generic", Signature: "Ubuntu 6.8.0-85.85-generic 6.8.12",
		PackageVersion: "6.8.0-85.85", BaseTag: "Ubuntu-6.8.0-85.85"}
	if err := base.Validate(base.Kernel); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*BuildKernelInfo){
		"kernel":            func(k *BuildKernelInfo) { k.Kernel = "6.8.0-86-generic" },
		"version":           func(k *BuildKernelInfo) { k.PackageVersion = "6.8.0-86.86" },
		"tag":               func(k *BuildKernelInfo) { k.BaseTag = "Ubuntu-6.8.0-86.86" },
		"signature":         func(k *BuildKernelInfo) { k.Signature = "Ubuntu 6.8.0-86.86-generic 6.8.12" },
		"flavour":           func(k *BuildKernelInfo) { k.Signature = "Ubuntu 6.8.0-85.85-lowlatency 6.8.12" },
		"missing signature": func(k *BuildKernelInfo) { k.Signature = "" },
		"hwe": func(k *BuildKernelInfo) {
			k.PackageVersion = "6.8.0-85.85~22.04.1"
			k.Signature = "Ubuntu " + k.PackageVersion + "-generic 6.8.12"
			k.BaseTag = "Ubuntu-" + k.PackageVersion
		},
	} {
		t.Run(name, func(t *testing.T) {
			k := base
			change(&k)
			if err := k.Validate(base.Kernel); err == nil {
				t.Fatal("mismatched kernel inputs accepted")
			}
		})
	}
}
