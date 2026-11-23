// 이 파일: remote 패키지의 TestShippedMirrorsList, TestParseMirrorsRejects, TestPreflightTriesMirrorsInOrder 회귀 시험.
package remote

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

// 저장소의 deploy/mirrors.list 가 그대로 설치 묶음에 들어가므로 실제 파일을 검사합니다.
func TestShippedMirrorsList(t *testing.T) {
	data, err := os.ReadFile("../../deploy/mirrors.list")
	if err != nil {
		t.Fatal(err)
	}
	ms, err := ParseMirrors(string(data))
	if err != nil {
		t.Fatal(err)
	}
	var order []string
	for _, m := range ms {
		if m.Arch == "amd64" {
			order = append(order, m.Name)
		}
	}
	if strings.Join(order, " ") != "official kaist kakao" {
		t.Fatalf("amd64 순서 = %v", order)
	}
	if ms[0].Security != "http://security.ubuntu.com/ubuntu" || ms[2].Security != ms[2].Archive {
		t.Fatalf("보안 주소: %+v", ms)
	}
}

func TestParseMirrorsRejects(t *testing.T) {
	ok := "official amd64 http://a/ubuntu\nofficial arm64 http://a/ports\n"
	for name, text := range map[string]string{
		"칸 부족":        ok + "kaist amd64\n",
		"모르는 아키텍처":    ok + "kaist i386 http://k/ubuntu\n",
		"주소 형식":       ok + "kaist amd64 ftp.kaist.ac.kr/ubuntu\n",
		"대문자 이름":      ok + "KAIST amd64 http://k/ubuntu\n",
		"중복":          ok + "official amd64 http://b/ubuntu\n",
		"official 없음": "kaist amd64 http://k/ubuntu\nkaist arm64 http://k/ports\n",
	} {
		if _, err := ParseMirrors(text); err == nil {
			t.Errorf("%s: 통과하면 안 됩니다", name)
		}
	}
	if ms, err := ParseMirrors("# 주석\n\n" + ok); err != nil || len(ms) != 2 {
		t.Fatalf("주석·빈 줄: %v %v", ms, err)
	}
}

// 공식 미러가 응답하지 않으면 목록의 다음 미러를 씁니다. 다른 아키텍처 줄은 건너뜁니다.
func TestPreflightTriesMirrorsInOrder(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("amd64 에서만 확인")
	}
	for _, c := range []string{"bash", "curl"} {
		if _, err := exec.LookPath(c); err != nil {
			t.Skip(c + " 없음")
		}
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	run := func(list string) map[string]string {
		out, err := exec.Command("bash", "-c", preflightScript, "preflight", "", "", "", list).CombinedOutput()
		if err != nil {
			t.Fatalf("스크립트 실패: %v\n%s", err, out)
		}
		kv := map[string]string{}
		for _, l := range strings.Split(string(out), "\n") {
			if k, v, ok := strings.Cut(l, "="); ok {
				kv[k] = v
			}
		}
		return kv
	}
	dead := "http://127.0.0.1:1/ubuntu" // 연결 거부
	kv := run("official amd64 " + dead + "\nlocal arm64 " + srv.URL + "\nkaist amd64 " + srv.URL + "\n")
	if kv["archive"] != "200" || kv["archivemirror"] != "kaist" {
		t.Fatalf("다음 미러로 넘어가지 않음: %v", kv)
	}
	kv = run("official amd64 " + dead + "\n")
	if kv["archive"] != "000" || kv["archivemirror"] != "official" {
		t.Fatalf("모두 실패: %v", kv)
	}
	if _, ok := run("")["archive"]; ok {
		t.Fatal("목록이 없으면 저장소 확인을 하지 않아야 합니다")
	}
}
