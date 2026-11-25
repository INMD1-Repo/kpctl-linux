// Package remote 는 SSH 로 에이전트를 설치·제거하고 일회용 VM 시험에 접속합니다.
//
// 시스템의 ssh, scp 명령을 그대로 실행합니다. 그래서 ~/.ssh/config, ssh-agent, ProxyJump(점프 호스트),
// known_hosts 등 평소 쓰던 SSH 설정이 그대로 적용됩니다.
//
// 운영 호스트는 설치 후 에이전트가 컨트롤러로 HTTPS 연결합니다.
// 시험 VM 접속에는 별도 테스트 키와 생성 명령이 반환한 SSH 포트를 씁니다.
//
// 파일 안내:
//
//	ssh.go      ← 지금 파일. ssh/scp 실행
//	steps.go    점검(preflight) → 설치 / 제거 단계
//	bundle.go   설치에 필요한 파일 묶음 확인
//	builder.go  빌드 서버 원격 설치 (kpctl install-builder)
package remote

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// SSH 는 접속 설정입니다. 비워 둔 값은 ~/.ssh/config 와 ssh 기본값을 따릅니다.
type SSH struct {
	User    string // 호스트에 user@ 가 없을 때 쓸 사용자
	Port    int    // 0 이면 기본(22 또는 ~/.ssh/config)
	KeyFile string // 개인키 파일 (-i)
	// ExtraKeys: KeyFile 다음에 차례로 시도할 개인키들 (관리자가 kpctl ssh-key add 로 저장한 키)
	ExtraKeys []string
	Options   []string      // 추가 ssh -o 옵션. 예: "ProxyJump=bastion"
	Timeout   time.Duration // 명령 하나의 최대 시간
	SSHBin    string        // 기본 "ssh"
	SCPBin    string        // 기본 "scp"

	// Interactive 가 true 면 비밀번호·호스트 키 확인을 터미널에서 물어봅니다.
	// (kpctl ssh-key copy 처럼 처음 한 번 사람이 직접 로그인할 때만 사용)
	Interactive bool
}

// commonArgs 는 ssh 와 scp 에 공통으로 붙는 옵션입니다.
// BatchMode=yes: 비밀번호나 호스트 키 확인을 묻지 않고 바로 실패합니다 (여러 대를 자동으로 돌리므로).
func (s *SSH) commonArgs(portFlag string) []string {
	args := []string{"-o", "ConnectTimeout=10"}
	if !s.Interactive {
		args = append(args, "-o", "BatchMode=yes")
	}
	if s.Port > 0 {
		args = append(args, portFlag, strconv.Itoa(s.Port))
	}
	if keys := s.Keys(); len(keys) > 0 {
		// 지정한 키만 사용 (ssh-agent 에 있는 다른 키로 로그인되는 일이 없도록). ssh 는 -i 순서대로 시도합니다.
		for _, k := range keys {
			args = append(args, "-i", k)
		}
		args = append(args, "-o", "IdentitiesOnly=yes")
	}
	for _, o := range s.Options {
		args = append(args, "-o", o)
	}
	return args
}

// Keys 는 시도할 개인키 목록입니다 (KeyFile 먼저, 중복 제거).
func (s *SSH) Keys() []string {
	var out []string
	seen := map[string]bool{}
	for _, k := range append([]string{s.KeyFile}, s.ExtraKeys...) {
		if k != "" && !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	return out
}

// dest 는 "user@host" 형태로 만듭니다. 이미 @ 가 있으면 그대로.
func (s *SSH) dest(host string) string {
	if s.User != "" && !strings.Contains(host, "@") {
		return s.User + "@" + host
	}
	return host
}

// scp uses a colon to separate a host from its path; IPv6 needs brackets.
func (s *SSH) scpDest(host string) string {
	user, hostname, hasUser := strings.Cut(s.dest(host), "@")
	if !hasUser {
		hostname, user = user, ""
	}
	if strings.Contains(hostname, ":") && !strings.HasPrefix(hostname, "[") {
		hostname = "[" + hostname + "]"
	}
	if hasUser {
		return user + "@" + hostname
	}
	return hostname
}

// Run 은 원격 호스트에서 셸 명령을 실행하고 출력(stdout+stderr)을 돌려줍니다.
// stdin 을 주면 원격 명령의 표준 입력으로 보냅니다 (비밀값을 명령줄에 남기지 않을 때 사용).
func (s *SSH) Run(host, command, stdin string) (string, error) {
	return s.RunContext(context.Background(), host, command, stdin)
}

// RunContext also bounds SSH with the caller's lifetime (for disposable VM tests).
func (s *SSH) RunContext(ctx context.Context, host, command, stdin string) (string, error) {
	args := append(s.commonArgs("-p"), s.dest(host), command)
	return s.execStream(ctx, "ssh", s.SSHBin, args, stdin, nil)
}

// Copy 는 로컬 파일들을 원격 디렉터리에 복사합니다.
func (s *SSH) Copy(host string, files []string, remoteDir string) error {
	return s.CopyContext(context.Background(), host, files, remoteDir)
}

// CopyContext copies files using the same port and deadline as RunContext.
func (s *SSH) CopyContext(ctx context.Context, host string, files []string, remoteDir string) error {
	args := append(s.commonArgs("-P"), "-q")
	args = append(args, files...)
	args = append(args, s.scpDest(host)+":"+remoteDir+"/")
	_, err := s.execStream(ctx, "scp", s.SCPBin, args, "", nil)
	return err
}

// RunStream 은 Run 과 같지만, 출력이 한 줄씩 나올 때마다 onLine 을 부릅니다 (오래 걸리는 설치의 진행 표시용).
func (s *SSH) RunStream(host, command, stdin string, onLine func(string)) (string, error) {
	args := append(s.commonArgs("-p"), s.dest(host), command)
	return s.execStream(context.Background(), "ssh", s.SSHBin, args, stdin, onLine)
}

// CopyTree 는 로컬 파일·디렉터리들을 원격 디렉터리에 하위 디렉터리까지 복사합니다 (scp -r).
func (s *SSH) CopyTree(host string, paths []string, remoteDir string) error {
	args := append(s.commonArgs("-P"), "-q", "-r")
	args = append(args, paths...)
	args = append(args, s.scpDest(host)+":"+remoteDir+"/")
	_, err := s.execStream(context.Background(), "scp", s.SCPBin, args, "", nil)
	return err
}

// lineWriter 는 받은 바이트를 줄 단위로 끊어 fn 에 넘깁니다.
type lineWriter struct {
	fn  func(string)
	buf []byte
}

func (w *lineWriter) Write(p []byte) (int, error) {
	w.buf = append(w.buf, p...)
	for {
		i := bytes.IndexByte(w.buf, '\n')
		if i < 0 {
			return len(p), nil
		}
		w.fn(strings.TrimRight(string(w.buf[:i]), "\r"))
		w.buf = w.buf[i+1:]
	}
}

func (w *lineWriter) flush() {
	if len(w.buf) > 0 {
		w.fn(string(w.buf))
		w.buf = nil
	}
}

func (s *SSH) execStream(parent context.Context, tool, bin string, args []string, stdin string, onLine func(string)) (string, error) {
	timeout := s.Timeout
	if timeout == 0 {
		timeout = 30 * time.Minute
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	if bin == "" {
		bin = tool
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.WaitDelay = time.Second
	cmd.Stdin = strings.NewReader(stdin)
	var out bytes.Buffer
	var sink io.Writer = &out
	var lines *lineWriter
	if onLine != nil {
		lines = &lineWriter{fn: onLine}
		sink = io.MultiWriter(&out, lines)
	}
	cmd.Stdout = sink
	cmd.Stderr = sink
	err := cmd.Run()
	if lines != nil {
		lines.flush()
	}
	if err == nil {
		return out.String(), nil
	}
	switch ctx.Err() {
	case context.DeadlineExceeded:
		return out.String(), fmt.Errorf("%s 시간 초과: %w", tool, ctx.Err())
	case context.Canceled:
		return out.String(), fmt.Errorf("%s 실행 취소: %w", tool, ctx.Err())
	}
	var exitErr *exec.ExitError
	switch {
	case !errors.As(err, &exitErr) || exitErr.ExitCode() < 0:
		return out.String(), fmt.Errorf("%s 클라이언트 실행 실패: %w", tool, err)
	case tool == "scp":
		return out.String(), fmt.Errorf("SCP 파일 전송 실패: %w", err)
	case exitErr.ExitCode() == 255:
		return out.String(), fmt.Errorf("SSH 연결 또는 세션 실패: %w", err)
	default:
		return out.String(), fmt.Errorf("원격 명령 실패: %w", err)
	}
}

// shq 는 문자열을 셸에서 안전하게 쓸 수 있도록 작은따옴표로 감쌉니다.
//
//	shq("a b")   → 'a b'
//	shq("it's")  → 'it'\''s'
func shq(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
