// 이 파일: remote 패키지의 TestSSHAndSCPUseCustomPort, TestSSHAndSCPHonorCallerDeadline, TestSCPFormatsIPv6Destination 회귀 시험.
package remote

import (
	"context"
	"os"
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
			if err == nil || time.Since(started) > time.Second {
				t.Fatalf("caller deadline did not stop %s: %v", method, err)
			}
		})
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
