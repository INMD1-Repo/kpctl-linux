// 이 파일: main 패키지의 TestBootWarnings 회귀 시험.
package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBootWarnings(t *testing.T) {
	etc := t.TempDir()
	state := map[string]string{"kpctl-controller.service": "disabled"}
	get := func(u string) string {
		if s, ok := state[u]; ok {
			return s
		}
		return "enabled"
	}
	if w := bootWarnings(etc, get); w != nil {
		t.Fatalf("컨트롤러가 아닌 곳에서 경고: %v", w)
	}
	os.WriteFile(filepath.Join(etc, "controller.json"), []byte("{}"), 0o600)
	w := bootWarnings(etc, get)
	if len(w) != 1 || !strings.Contains(w[0], "kpctl-controller.service(disabled)") || !strings.Contains(w[0], "systemctl enable kpctl-controller.service") {
		t.Fatalf("경고: %v", w)
	}
	state["kpctl-controller.service"] = "enabled"
	if w := bootWarnings(etc, get); w != nil {
		t.Fatalf("모두 켜졌는데 경고: %v", w)
	}
	// systemctl 이 없으면(빈 값) 검사하지 않음
	if w := bootWarnings(etc, func(string) string { return "" }); w != nil {
		t.Fatalf("systemctl 없음: %v", w)
	}
}
