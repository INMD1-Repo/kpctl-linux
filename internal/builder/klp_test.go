// 이 파일: builder 패키지의 TestBuildToolSelection, TestKLPBuildArgs, TestBuildToolConfigValidation 회귀 시험.
package builder

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestBuildToolSelection(t *testing.T) {
	boot := t.TempDir()
	write := func(kernel, body string) {
		if err := os.WriteFile(filepath.Join(boot, "config-"+kernel), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("7.0.0-38-generic", "CONFIG_LIVEPATCH=y\nCONFIG_KLP_BUILD=y\n")
	write("6.8.0-147-generic", "CONFIG_LIVEPATCH=y\n# CONFIG_KLP_BUILD is not set\n")

	tests := []struct{ tool, kernel, want string }{
		{"", "7.0.0-38-generic", BuildToolKLP},
		{BuildToolAuto, "7.0.0-38-generic", BuildToolKLP},
		{BuildToolAuto, "6.8.0-147-generic", BuildToolKpatch},
		{BuildToolAuto, "9.9.9-missing", BuildToolKpatch},
		{BuildToolKpatch, "7.0.0-38-generic", BuildToolKpatch},
		{BuildToolKLP, "6.8.0-147-generic", BuildToolKLP},
	}
	for _, tt := range tests {
		c := &Config{BuildTool: tt.tool, BootDir: boot}
		if got := c.buildTool(tt.kernel); got != tt.want {
			t.Errorf("tool=%q kernel=%s: %s, 기대 %s", tt.tool, tt.kernel, got, tt.want)
		}
	}
}

func TestKLPBuildArgs(t *testing.T) {
	got := klpBuildArgs(6, "/o/kpctl_x_v1.ko", []string{"/p/1.patch", "/p/2.patch"})
	want := []string{"-o", "/o/kpctl_x_v1.ko", "-j", "6", "/p/1.patch", "/p/2.patch"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("인자 %v", got)
	}
	if got := klpBuildArgs(0, "/o/a.ko", nil); !reflect.DeepEqual(got, []string{"-o", "/o/a.ko"}) {
		t.Fatalf("jobs 0 인자 %v", got)
	}
}

func TestBuildToolConfigValidation(t *testing.T) {
	body := `{"controller_url": "https://c", "token": "t", "work_dir": "` + t.TempDir() + `", "series": "noble", "build_tool": "wrong"}`
	if _, err := LoadConfig(writeConfig(t, body)); err == nil || !strings.Contains(err.Error(), "build_tool") {
		t.Fatalf("잘못된 build_tool 은 거부해야 함: %v", err)
	}
}
