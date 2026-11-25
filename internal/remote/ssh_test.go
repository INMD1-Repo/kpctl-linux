// 이 파일: remote 패키지의 TestSSHAndSCPUseCustomPort, TestSSHAndSCPHonorCallerDeadline, TestSCPFormatsIPv6Destination 회귀 시험.
package remote

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSSHAndSCPUseCustomPort(t *testing.T) {
	root := t.TempDir()
	bin, log := filepath.Join(root, "fake-ssh"), filepath.Join(root, "args")
	t.Setenv("KPCTL_SSH_TEST_ARGS", log)
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$KPCTL_SSH_TEST_ARGS\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	s := &SSH{User: "ubuntu", Port: 2201, KeyFile: "/keys/test", SSHBin: bin, SCPBin: bin, Timeout: time.Second}
	if _, err := s.Run("127.0.0.1", "uname -r", ""); err != nil {
		t.Fatal(err)
	}
	args, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(args), "\n-p\n2201\n") || !strings.Contains(string(args), "\nubuntu@127.0.0.1\nuname -r\n") {
		t.Fatalf("SSH ignored endpoint port: %q", args)
	}
	if err := s.Copy("127.0.0.1", []string{"/tmp/module.ko"}, "/tmp/testvm"); err != nil {
		t.Fatal(err)
	}
	args, err = os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(args), "\n-P\n2201\n") || !strings.Contains(string(args), "\nubuntu@127.0.0.1:/tmp/testvm/\n") {
		t.Fatalf("SCP ignored endpoint port: %q", args)
	}
}

func TestSSHAndSCPHonorCallerDeadline(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "waiting-ssh")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nexec sleep 30\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	s := &SSH{SSHBin: bin, SCPBin: bin, Timeout: time.Minute}
	for _, method := range []string{"ssh", "scp"} {
		t.Run(method, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
			defer cancel()
			started := time.Now()
			var err error
			if method == "ssh" {
				_, err = s.RunContext(ctx, "127.0.0.1", "true", "")
			} else {
				err = s.CopyContext(ctx, "127.0.0.1", []string{"/tmp/module.ko"}, "/tmp/testvm")
			}
			if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "시간 초과") || time.Since(started) > time.Second {
				t.Fatalf("caller deadline did not stop %s: %v", method, err)
			}
		})
	}
}

func TestSSHAndSCPReportExitStatus(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "fake-client")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nprintf 'package index returned 503\\n' >&2\nexit \"$TEST_EXIT_CODE\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	s := &SSH{SSHBin: bin, SCPBin: bin}
	for _, tc := range []struct{ method, code, want string }{
		{"ssh", "1", "원격 명령 실패"},
		{"ssh-stream", "100", "원격 명령 실패"},
		{"ssh", "255", "SSH 연결 또는 세션 실패"},
		{"scp", "1", "SCP 파일 전송 실패"},
		{"scp-tree", "255", "SCP 파일 전송 실패"},
	} {
		t.Run(tc.method+"-"+tc.code, func(t *testing.T) {
			t.Setenv("TEST_EXIT_CODE", tc.code)
			var out string
			var err error
			switch tc.method {
			case "ssh":
				out, err = s.Run("test", "install", "")
			case "ssh-stream":
				var line string
				out, err = s.RunStream("test", "install", "", func(s string) { line = s })
				if line != "package index returned 503" {
					t.Fatalf("streamed diagnostic = %q", line)
				}
			case "scp":
				err = s.Copy("test", []string{"file"}, "/tmp/test")
			case "scp-tree":
				err = s.CopyTree("test", []string{"dir"}, "/tmp/test")
			}
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) || !strings.HasPrefix(err.Error(), tc.want) ||
				!strings.Contains(err.Error(), "exit status "+tc.code) {
				t.Fatalf("expected %q and wrapped exit status %s, got %v", tc.want, tc.code, err)
			}
			if strings.HasPrefix(tc.method, "ssh") && out != "package index returned 503\n" {
				t.Fatalf("raw diagnostic = %q", out)
			}
		})
	}
}

func TestSSHClientLaunchAndCancellation(t *testing.T) {
	s := &SSH{SSHBin: filepath.Join(t.TempDir(), "missing")}
	if _, err := s.Run("test", "install", ""); !errors.Is(err, os.ErrNotExist) || !strings.Contains(err.Error(), "클라이언트 실행 실패") {
		t.Fatalf("expected missing local executable, got %v", err)
	}
	s.SSHBin = "/bin/sh"
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.RunContext(ctx, "test", "install", ""); !errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), "취소") {
		t.Fatalf("expected canceled operation, got %v", err)
	}
}

func TestSCPFormatsIPv6Destination(t *testing.T) {
	for _, tc := range []struct{ user, host, want string }{
		{"ubuntu", "::1", "ubuntu@[::1]"},
		{"", "ubuntu@2001:db8::1", "ubuntu@[2001:db8::1]"},
		{"", "::1", "[::1]"},
		{"ubuntu", "127.0.0.1", "ubuntu@127.0.0.1"},
	} {
		if got := (&SSH{User: tc.user}).scpDest(tc.host); got != tc.want {
			t.Errorf("scp destination %q: got %q want %q", tc.host, got, tc.want)
		}
	}
}
