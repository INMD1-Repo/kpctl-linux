// 이 파일: builder 패키지의 TestAdaptationScope, TestAdaptationRejectsMovedBaseTag, TestKVMAdaptationPreservesLogicAndFollowingLocations 회귀 시험.
package builder

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestAdaptationScope(t *testing.T) {
	for _, commit := range []string{
		"25e02a1564bb0cd0cb9fc926e9ddde4ece8ce800",
		"8c3fb26c9d258976db78d7fe1e4a996e22770373",
	} {
		t.Run(commit[:12], func(t *testing.T) {
			k := KernelConfig{Kernel: "6.8.0-136-generic", BaseTag: "Ubuntu-6.8.0-136.136"}
			if runtime.GOARCH != "amd64" {
				if selectAdaptation(k, commit) != nil {
					t.Fatal("unreviewed architecture selected")
				}
				return
			}
			if selectAdaptation(k, commit) == nil {
				t.Fatal("reviewed exact target missing")
			}
			for _, target := range []KernelConfig{
				{Kernel: "6.8.0-137-generic", BaseTag: k.BaseTag},
				{Kernel: k.Kernel, BaseTag: "Ubuntu-6.8.0-137.137"},
				{Kernel: "7.0.0-28-generic", BaseTag: "Ubuntu-7.0.0-28.28"},
			} {
				if selectAdaptation(target, commit) != nil {
					t.Fatal("unreviewed ABI/base selected")
				}
			}
			if selectAdaptation(k, commit[:12]) != nil || selectAdaptation(k, strings.Repeat("f", 40)) != nil {
				t.Fatal("abbreviated/other commit selected")
			}
		})
	}
}

func TestAdaptationRejectsMovedBaseTag(t *testing.T) {
	repo := t.TempDir()
	file := filepath.Join(repo, "source.c")
	if err := os.WriteFile(file, []byte("original\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	run(t, repo, "init", "-q")
	run(t, repo, "add", ".")
	run(t, repo, "commit", "-qm", "original")
	run(t, repo, "tag", "reviewed-base")
	sha, err := git(repo, "rev-parse", "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	a := patchAdaptation{baseCommit: strings.TrimSpace(sha), patch: "reviewed diff", name: "test"}
	k := KernelConfig{GitDir: repo, BaseTag: "reviewed-base"}
	if got, err := a.verifiedContent(k); err != nil || got != a.patch {
		t.Fatalf("correct base: %q %v", got, err)
	}
	if err := os.WriteFile(file, []byte("different\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	run(t, repo, "commit", "-qam", "different")
	run(t, repo, "tag", "-f", "reviewed-base")
	if _, err := a.verifiedContent(k); err == nil {
		t.Fatal("moved base tag accepted")
	}
	k.BaseTag = "absent"
	if _, err := a.verifiedContent(k); err == nil {
		t.Fatal("missing base accepted")
	}
}

func TestKVMAdaptationPreservesLogicAndFollowingLocations(t *testing.T) {
	before := `static struct kvm_mmu_page *kvm_mmu_get_child_sp(struct kvm_vcpu *vcpu,
						 u64 *sptep, gfn_t gfn,
						 bool direct, unsigned int access)
{
	union kvm_mmu_page_role role;

	if (is_shadow_present_pte(*sptep) && !is_large_pte(*sptep) &&
	    spte_to_child_sp(*sptep) && spte_to_child_sp(*sptep)->gfn == gfn)
		return ERR_PTR(-EEXIST);

	role = kvm_mmu_child_role(sptep, direct, access);
	return kvm_mmu_get_shadow_page(vcpu, gfn, role);
}

int unrelated_location = __LINE__;
`
	canonical := strings.Replace(before, "union kvm_mmu_page_role role;",
		"union kvm_mmu_page_role role = kvm_mmu_child_role(sptep, direct, access);", 1)
	canonical = strings.Replace(canonical,
		"\t    spte_to_child_sp(*sptep) && spte_to_child_sp(*sptep)->gfn == gfn)",
		"\t    spte_to_child_sp(*sptep) && spte_to_child_sp(*sptep)->gfn == gfn &&\n\t    spte_to_child_sp(*sptep)->role.word == role.word)", 1)
	canonical = strings.Replace(canonical, "\trole = kvm_mmu_child_role(sptep, direct, access);\n", "", 1)
	repo := t.TempDir()
	file := filepath.Join(repo, "arch/x86/kvm/mmu/mmu.c")
	if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte(before), 0o600); err != nil {
		t.Fatal(err)
	}
	patch := filepath.Join(repo, "reviewed.patch")
	if err := os.WriteFile(patch, []byte(kvmChildRolePatch), 0o600); err != nil {
		t.Fatal(err)
	}
	run(t, repo, "init", "-q")
	run(t, repo, "apply", "--check", patch)
	run(t, repo, "apply", patch)
	after, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(strings.Fields(string(after)), "") != strings.Join(strings.Fields(canonical), "") {
		t.Fatal("adaptation differs from the upstream role check beyond whitespace")
	}
	location := func(source string) int {
		return strings.Count(strings.Split(source, "int unrelated_location")[0], "\n")
	}
	if location(before) != location(string(after)) {
		t.Fatal("unrelated following source location moved")
	}
}
