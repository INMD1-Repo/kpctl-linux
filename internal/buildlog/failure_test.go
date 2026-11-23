// 이 파일: buildlog 패키지의 TestUnsupportedNativeDiagnostic, TestSummaryShowsCauseWithoutChangingClassification, TestUnpatchableRequiresExplicitDiagnostic 회귀 시험.
package buildlog

import "testing"

func TestUnsupportedNativeDiagnostic(t *testing.T) {
	log := "rpcrdma.o: objtool: unexpected klp reloc for new symbol xprt_add_backlog_noncongested"
	if !Unsupported(log) || Summary(log) != log {
		t.Fatalf("명시적 objtool 진단·요약: %q", Summary(log))
	}
	if Unsupported("+const char *text = \"objtool: unexpected klp reloc for new symbol\";") {
		t.Fatal("소스에 있는 진단 문구를 도구 거부로 판단하면 안 됨")
	}
	if Unsupported("foo.c: error: unknown type name") {
		t.Fatal("표에 없는 실패는 unknown")
	}
}

func TestSummaryShowsCauseWithoutChangingClassification(t *testing.T) {
	for _, tc := range []struct{ log, want string }{
		{"warning: frame size\nerror: patch failed: net/sctp/sm_make_chunk.c:1731\nerror: klp-build: line 353: git apply", "error: patch failed: net/sctp/sm_make_chunk.c:1731"},
		{"error: klp-build: line 528: make\nmake[3]: *** No rule to make target 'debian/canonical-certs.pem'. Stop.", "make[3]: *** No rule to make target 'debian/canonical-certs.pem'. Stop."},
		{"create-diff-object: ERROR: failed to correlate static local variable", "create-diff-object: ERROR: failed to correlate static local variable"},
		{"foo.c:12:4: fatal error: missing.h: No such file or directory", "foo.c:12:4: fatal error: missing.h: No such file or directory"},
		{"patching file foo.c\nHunk #1 FAILED at 1731.", "Hunk #1 FAILED at 1731."},
		{"warning only\nexit status 1", ""},
		{"ERROR: Version disagreement for symbol clean_acked_data_enable\nERROR: t4_hw.o: reference to static local variable was removed\ncreate-diff-object: unreconcilable difference", "ERROR: t4_hw.o: reference to static local variable was removed"},
		{"ERROR: Version disagreement for symbol clean_acked_data_enable", "ERROR: Version disagreement for symbol clean_acked_data_enable"},
		{"ERROR: Version disagreement for symbol clean_acked_data_enable\nld: final link failed: No space left on device", "ld: final link failed: No space left on device"},
	} {
		if got := Summary(tc.log); got != tc.want {
			t.Errorf("Summary=%q want=%q", got, tc.want)
		}
		if Unpatchable(tc.log) {
			t.Errorf("원인 요약만으로 불가 판정하면 안 됨: %s", tc.log)
		}
	}
}

func TestUnpatchableRequiresExplicitDiagnostic(t *testing.T) {
	for _, tc := range []struct {
		name, log string
		want      bool
	}{
		{"데이터 변경", "ERROR: changed data section .data (fake)", true},
		{"지원하지 않는 변경", "ERROR: Unsupported changes detected", true},
		{"심볼 버전 변경", "ERROR: Patch module referencing altered exported kernel symbols cannot be loaded", true},
		{"kpatch 실제 섹션 진단", "ERROR: net/core/dev.o: 1 unsupported section change(s)", true},
		{"도구 접두사", "create-diff-object: ERROR: net/core/dev.o: 1 unsupported section change(s)", true},
		{"실제 점프 라벨 제약", "create-diff-object: ERROR: net/ipv6/ioam6.o: Found 2 unsupported jump label(s) in the patched code. Use static_key_enabled() instead.", true},
		{"점프 라벨과 환경 실패", "ERROR: Found 2 unsupported jump label(s)\nNo space left on device", false},
		{"정상 인증서 컴파일 출력", "CC certs/system_keyring.o\nERROR: changed data section .data", true},
		{"정상 패치 적용 출력", "Hunk #1 succeeded at 20 (offset 2 lines)\nERROR: changed data section .data", true},
		{"내용에 문구만 있음", "+const char *s = \"changed data section\";", false},
		{"인증서 준비 실패", "make[2]: *** [scripts/Makefile.build:548: certs] Error 2", false},
		{"의존 수정 누락", "net/sctp/sm_make_chunk.c: patch does not apply", false},
		{"일반 컴파일 오류", "foo.c: error: implicit declaration of function bar", false},
		{"출력 없는 실패", "", false},
		{"실행 중 종료", "signal: killed\nERROR: changed data section .data", false},
		{"환경 오류가 섞임", "ERROR: changed data section .data\nNo space left on device", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Unpatchable(tc.log); got != tc.want {
				t.Fatalf("Unpatchable = %v, want %v", got, tc.want)
			}
		})
	}
}
