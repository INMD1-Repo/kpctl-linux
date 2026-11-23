// 이 파일: builder 패키지의 TestExampleConfigParses, TestRemovedMinKernelsIsIgnoredButOtherUnknownKeysAreRejected, TestAutoModeRejectsUnsupportedSeries 회귀 시험.
package builder

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "builder.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestExampleConfigParses(t *testing.T) {
	data, err := os.ReadFile("../../configs/builder.example.json")
	if err != nil {
		t.Fatal(err)
	}
	// 예시는 series 를 비워 os-release 를 따르므로, 테스트에서는 시리즈와 작업 디렉터리만 바꿉니다.
	body := strings.Replace(string(data), `"series": ""`, `"series": "noble"`, 1)
	body = strings.Replace(body, `"/var/lib/kpctl-builder"`, `"`+t.TempDir()+`"`, 1)
	cfg, err := LoadConfig(writeConfig(t, body))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.autoKernels() || cfg.Series != "noble" {
		t.Fatalf("자동 모드여야 함: auto=%v series=%q", cfg.autoKernels(), cfg.Series)
	}
}

func TestRemovedMinKernelsIsIgnoredButOtherUnknownKeysAreRejected(t *testing.T) {
	base := `{"controller_url":"https://c","token":"t","series":"noble","work_dir":"` + t.TempDir() + `"`
	if _, err := LoadConfig(writeConfig(t, base+`,"min_kernels":2}`)); err != nil {
		t.Fatalf("기존 설정 호환: %v", err)
	}
	if _, err := LoadConfig(writeConfig(t, base+`,"min_kernel_typo":2}`)); err == nil {
		t.Fatal("다른 알 수 없는 키는 계속 거부")
	}
}

func TestAutoModeRejectsUnsupportedSeries(t *testing.T) {
	body := `{"controller_url": "https://c", "token": "t", "work_dir": "` + t.TempDir() + `", "series": "focal"}`
	if _, err := LoadConfig(writeConfig(t, body)); err == nil || !strings.Contains(err.Error(), "지원 LTS") {
		t.Fatalf("지원하지 않는 시리즈는 거부해야 함: %v", err)
	}
}

func TestExplicitKernelsKeepWorking(t *testing.T) {
	body := `{"controller_url": "https://c", "token": "t", "work_dir": "` + t.TempDir() + `", "debug_dir": "/dbg",
	  "kernels": [{"kernel": "6.8.0-1020-nvidia", "git_dir": "/srv/x", "base_tag": "b", "tag_glob": "g"}]}`
	cfg, err := LoadConfig(writeConfig(t, body))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.autoKernels() || cfg.Series != "" {
		t.Fatalf("kernels 를 적으면 자동 모드가 아니고 시리즈도 추측하지 않음: series=%q", cfg.Series)
	}
	if got := cfg.Kernels[0].Vmlinux; got != "/dbg/vmlinux-6.8.0-1020-nvidia" {
		t.Fatalf("vmlinux 기본 경로: %q", got)
	}
}

func TestOSCodename(t *testing.T) {
	p := writeConfig(t, "NAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\nVERSION_CODENAME=noble\n")
	if got := osCodename(p); got != "noble" {
		t.Fatalf("osCodename = %q", got)
	}
}

func TestPathsOverride(t *testing.T) {
	base := `{"controller_url":"http://x","token":"t","series":"noble","work_dir":"` + t.TempDir() + `"`
	cfg, err := LoadConfig(writeConfig(t, base+`}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.kernelConfig("6.8.0-85-generic").paths(); strings.Join(got, ",") != strings.Join(DefaultPaths, ",") {
		t.Errorf("기본 경로: %v", got)
	}

	cfg, err = LoadConfig(writeConfig(t, base+`,"paths":["net/"],"kernels":[
		{"kernel":"a","git_dir":"/g","base_tag":"t","tag_glob":"g"},
		{"kernel":"b","git_dir":"/g","base_tag":"t","tag_glob":"g","paths":["mm/"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Kernels[0].paths(); len(got) != 1 || got[0] != "net/" {
		t.Errorf("전체 paths 적용: %v", got)
	}
	if got := cfg.Kernels[1].paths(); len(got) != 1 || got[0] != "mm/" {
		t.Errorf("커널별 paths 우선: %v", got)
	}
}

func TestDefaultPathsAreForCPUServers(t *testing.T) {
	joined := strings.Join(DefaultPaths, " ")
	for _, want := range []string{"kernel/", "mm/", "fs/", "net/"} {
		if !strings.Contains(joined, want) {
			t.Errorf("%s 빠짐: %v", want, DefaultPaths)
		}
	}
	if strings.Contains(joined, "drivers/") {
		t.Errorf("하드웨어 드라이버는 기본 대상이 아님: %v", DefaultPaths)
	}
}
