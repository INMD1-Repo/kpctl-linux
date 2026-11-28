// 이 파일: version 패키지의 버전 문자열·짧은 커밋·라벨 포맷 회귀 시험.
package version

import "testing"

func TestShortAndLabel(t *testing.T) {
	if got := Short("0123456789abcdef"); got != "0123456" {
		t.Fatalf("Short=%q, want 0123456", got)
	}
	if got := Short("abc"); got != "abc" {
		t.Fatalf("Short(short)=%q, want abc", got)
	}
	if got := Label("v1.2.0", "0123456789abcdef", "main"); got != "v1.2.0 (0123456, main)" {
		t.Fatalf("Label(tag)=%q", got)
	}
	if got := Label("0123456", "0123456789abcdef", "Dev"); got != "0123456 (Dev)" {
		t.Fatalf("Label(short)=%q", got)
	}
	if got := Label("v1.2.0-3-g0123456", "0123456789abcdef", "main"); got != "v1.2.0-3-g0123456 (main)" {
		t.Fatalf("Label(describe)=%q", got)
	}
	if got := Label("", "0123456789abcdef", "HEAD"); got != "0123456" {
		t.Fatalf("Label(detached)=%q", got)
	}
}
