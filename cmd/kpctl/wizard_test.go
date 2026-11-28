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
	run := func(_ *client.Client, args []string) ([]hostResult, error) {
		calls = append(calls, "run "+strings.Join(args, " "))
		if args[0] == "-check" && fails > 0 {
			fails--
			return []hostResult{{target: "node-01", result: "접속 실패"}}, errors.New("1대 중 1대 실패")
		}
		return []hostResult{{target: "node-01", ok: true}}, nil
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

	// 통과한 서버가 한 대도 없으면 설치하지 않음
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

func TestRunWizardInstallsOnlyHostsThatPassed(t *testing.T) {
	const kernel = "6.8.0-136-generic"
	for _, tt := range []struct {
		name        string
		plan        wizardPlan
		partial     bool
		confirm     string
		wantInstall []string
	}{
		{
			name:    "DHCP 일부 접속 실패",
			plan:    wizardPlan{command: "install", source: []string{"-from-dhcp"}, flags: []string{"-group", "server"}},
			partial: true, confirm: "Y", wantInstall: []string{"-group", "server", "10.0.0.8"},
		},
		{
			name:    "목록 파일에서 모두 통과",
			plan:    wizardPlan{command: "install", source: []string{"-hosts-file", "hosts.txt"}, flags: []string{"-group", "canary"}},
			confirm: "Y", wantInstall: []string{"-group", "canary", "10.0.0.8", "ops@node-02"},
		},
		{
			name: "빌더 일부 접속 실패",
			plan: wizardPlan{command: "install-builder", hosts: []string{"10.0.0.8", "ops@node-02", "node-03"},
				kernels: []string{kernel}, setup: []string{"--memory-mib", "16384"}},
			partial: true, confirm: "Y", wantInstall: []string{"10.0.0.8", kernel, "--", "--memory-mib", "16384"},
		},
		{
			name: "일부 통과 후 설치 취소",
			plan: wizardPlan{command: "install", source: []string{"-from-dhcp"}}, partial: true, confirm: "N",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			results := []hostResult{{target: "10.0.0.8", hostname: "node-01", ok: true}, {target: "ops@node-02", hostname: "node-02", ok: true}}
			var checkErr error
			answers := []string{tt.confirm}
			if tt.partial {
				results[1] = hostResult{target: "ops@node-02", result: "접속 실패"}
				results = append(results, hostResult{target: "node-03", result: "점검 실패"})
				checkErr = errors.New("3대 중 2대 실패")
				answers = []string{"N", tt.confirm}
			}
			var calls [][]string
			wantCalls := [][]string{tt.plan.args(true)}
			if tt.wantInstall != nil {
				wantCalls = append(wantCalls, tt.wantInstall)
			}
			p, _ := scripted(answers...)
			run := func(_ *client.Client, args []string) ([]hostResult, error) {
				calls = append(calls, append([]string(nil), args...))
				if args[0] == "-check" {
					return results, checkErr
				}
				return nil, nil
			}
			sshKey := func(_ *client.Client, args []string) error {
				t.Fatalf("키 등록을 요청하지 않았습니다: %v", args)
				return nil
			}
			if err := runWizard(nil, p, &tt.plan, run, sshKey); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(calls, wantCalls) {
				t.Fatalf("명령줄\n got %q\nwant %q", calls, wantCalls)
			}
		})
	}
}

func TestRunWizardWithoutCheckedHosts(t *testing.T) {
	for _, checkErr := range []error{nil, errors.New("예약 파일 읽기 실패")} {
		plan := &wizardPlan{command: "install", source: []string{"-from-dhcp"}}
		p, _ := scripted("Y")
		calls := 0
		run := func(_ *client.Client, args []string) ([]hostResult, error) {
			calls++
			if calls != 1 || args[0] != "-check" {
				t.Fatalf("설치 대상이 없습니다: %v", args)
			}
			return nil, checkErr
		}
		sshKey := func(_ *client.Client, args []string) error {
			t.Fatalf("키 등록 대상이 없습니다: %v", args)
			return nil
		}
		if err := runWizard(nil, p, plan, run, sshKey); !errors.Is(err, checkErr) || calls != 1 {
			t.Fatalf("err=%v, want=%v, calls=%d", err, checkErr, calls)
		}
		if answer, _ := p.in.ReadString('\n'); answer != "Y\n" {
			t.Fatalf("점검 결과가 비어 있는데 확인 입력을 소비했습니다")
		}
	}
}

// 질문형 설치: Rocky 10 커널은 호스트 칸에서는 거부하고 커널 칸에서는 받습니다.
// 빌드할 수 없는 Debian 13 커널은 커널 칸에서 이유와 함께 중단합니다.
func TestBuilderWizardDistributionKernels(t *testing.T) {
	p, _ := scripted("10.0.0.176 6.12.0-264.21.1.el10_3.x86_64")
	if _, err := askBuilderPlan(p); err == nil || !strings.Contains(err.Error(), "호스트 주소가 아닙니다") {
		t.Fatalf("호스트 칸: %v", err)
	}
	p, out := scripted("build-rocky10", "", "", "6.12.0-264.21.1.el10_3.x86_64", "", "", "", "", "")
	w, err := askBuilderPlan(p)
	if err != nil || !reflect.DeepEqual(w.kernels, []string{"6.12.0-264.21.1.el10_3.x86_64"}) {
		t.Fatalf("커널 칸: %v %v\n%s", w, err, out)
	}
	p, out = scripted("build-trixie", "", "", "6.12.118+deb13-amd64", "", "", "", "", "")
	if _, err := askBuilderPlan(p); err == nil || !strings.Contains(err.Error(), "IBT") {
		t.Fatalf("Debian 13: %v\n%s", err, out)
	}
	// 호스트 이름이 -amd64 로 끝나도 커널로 오인하지 않음
	p, _ = scripted("10.0.0-build-amd64", "", "", "", "", "", "", "")
	if w, err := askBuilderPlan(p); err != nil || !reflect.DeepEqual(w.hosts, []string{"10.0.0-build-amd64"}) {
		t.Fatalf("호스트 이름: %v %v", w, err)
	}
}
