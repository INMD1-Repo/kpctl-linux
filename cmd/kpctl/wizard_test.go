// 이 파일: main 패키지의 질문형 설치 회귀 시험 (정해 둔 답으로 만든 명령줄과 점검·설치 순서).
package main

import (
	"bufio"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"kpctl/internal/client"
)

func scripted(answers ...string) (*prompter, *strings.Builder) {
	out := &strings.Builder{}
	return &prompter{in: bufio.NewReader(strings.NewReader(strings.Join(answers, "\n") + "\n")), out: out}, out
}

func TestBuilderWizardBuildsCommand(t *testing.T) {
	t.Setenv("KPCTL_SSH_KEY", "")
	p, out := scripted(
		"build-noble",         // 빌드 서버
		"root",                // SSH 계정
		"Bad User", "builder", // 빌드 계정: 잘못된 값은 다시 물음
		"6.8.0-x", "6.8.0-136-generic", // 커널: 형식 틀리면 다시 물음
		"16384",    // 메모리
		"5", "360", // 이미지 제한 시간: 범위 밖이면 다시 물음
		"n",          // ccache 끔
		"y", "", "n", // 업그레이드: 멈춤(기본 예), 설정 유지
	)
	w, err := askBuilderPlan(p)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	got := shellJoin(w.args(false))
	want := "-ssh-user root -build-user builder -stop-running build-noble 6.8.0-136-generic -- --memory-mib 16384 --image-timeout-minutes 360 --no-cache"
	if got != want {
		t.Fatalf("명령줄\n got %s\nwant %s", got, want)
	}
	if !reflect.DeepEqual(w.copyArgs(), []string{"copy", "-ssh-user", "root", "build-noble"}) {
		t.Fatalf("키 등록 인자: %v", w.copyArgs())
	}
	if !strings.Contains(out.String(), "root 는 안 됩니다") || !strings.Contains(out.String(), "커널 이름 형식이 아닙니다") {
		t.Errorf("잘못된 답 안내가 없습니다:\n%s", out)
	}
}

func TestBuilderWizardDefaults(t *testing.T) {
	p, _ := scripted("build-a build-b", "", "", "", "", "", "", "")
	w, err := askBuilderPlan(p)
	if err != nil {
		t.Fatal(err)
	}
	if got := shellJoin(w.args(true)); got != "-check build-a build-b" {
		t.Fatalf("기본값 명령줄: %s", got)
	}
}

func TestAgentWizardBuildsCommand(t *testing.T) {
	dir := t.TempDir()
	for _, g := range []string{"canary", "server"} {
		if err := os.WriteFile(filepath.Join(dir, "enroll-"+g+".token"), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("KPCTL_TOKEN_DIR", dir)

	p, out := scripted("", "node-01 node-02", "", "")
	w, err := askAgentPlan(p, false)
	if err != nil {
		t.Fatal(err)
	}
	if got := shellJoin(w.args(false)); got != "-group canary node-01 node-02" {
		t.Fatalf("기본(카나리) 명령줄: %s\n%s", got, out)
	}

	p, _ = scripted("3", "ubuntu", "2")
	if w, err = askAgentPlan(p, true); err != nil {
		t.Fatal(err)
	}
	if got := shellJoin(w.args(false)); got != "-from-dhcp -ssh-user ubuntu -group server" {
		t.Fatalf("DHCP 명령줄: %s", got)
	}
	if !reflect.DeepEqual(w.copyArgs(), []string{"copy", "-ssh-user", "ubuntu", "-from-dhcp"}) {
		t.Fatalf("키 등록 인자: %v", w.copyArgs())
	}

	p, _ = scripted("1", "")
	if _, err := askAgentPlan(p, false); err == nil {
		t.Fatal("입력이 끝나면 멈춰야 합니다")
	}
}

func TestRunWizardChecksThenInstalls(t *testing.T) {
	w := &wizardPlan{command: "install", flags: []string{"-group", "canary"}, hosts: []string{"node-01"}}
	var calls []string
	fails := 1
	run := func(_ *client.Client, args []string) error {
		calls = append(calls, "run "+strings.Join(args, " "))
		if args[0] == "-check" && fails > 0 {
			fails--
			return errors.New("1대 중 1대 실패")
		}
		return nil
	}
	sshKey := func(_ *client.Client, args []string) error {
		calls = append(calls, "ssh-key "+strings.Join(args, " "))
		return nil
	}
	p, out := scripted("y", "") // 키 등록 후 재점검 → 설치 확인(기본 예)
	if err := runWizard(nil, p, w, run, sshKey); err != nil {
		t.Fatal(err)
	}
	want := []string{"run -check -group canary node-01", "ssh-key copy node-01", "run -check -group canary node-01", "run -group canary node-01"}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("순서\n got %q\nwant %q", calls, want)
	}
	if !strings.Contains(out.String(), "sudo kpctl install -group canary node-01") {
		t.Errorf("다시 쓸 명령줄이 없습니다:\n%s", out)
	}

	// 점검 실패 후 키 등록을 거절하면 설치하지 않음
	calls, fails = nil, 1
	p, _ = scripted("n")
	if err := runWizard(nil, p, w, run, sshKey); err == nil || len(calls) != 1 {
		t.Fatalf("err=%v calls=%q", err, calls)
	}
	// 설치 확인에서 아니오
	calls, fails = nil, 0
	p, _ = scripted("n")
	if err := runWizard(nil, p, w, run, sshKey); err != nil || len(calls) != 1 {
		t.Fatalf("err=%v calls=%q", err, calls)
	}
}
