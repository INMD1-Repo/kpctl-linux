// 이 파일: builder 패키지의 TestSelfUpdate 회귀 시험.
package builder

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"kpctl/internal/client"
	"kpctl/internal/model"
)

// 가짜 컨트롤러: /bin/true 를 "새 kpctl-builder" 로 내려줌 (-h 로 실행 시험을 통과함)
func fakeUpdateServer(t *testing.T, binary string, sum string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/builder/update":
			var req model.BuilderUpdateRequest
			json.NewDecoder(r.Body).Decode(&req)
			resp := model.BuilderUpdateResponse{}
			if req.SHA256 != sum {
				resp = model.BuilderUpdateResponse{Update: true, SHA256: sum}
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		case "/api/builder/binary":
			http.ServeFile(w, r, binary)
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestSelfUpdate(t *testing.T) {
	bin := "/bin/true"
	sum := fileSHA256(bin)
	if sum == "" {
		t.Skip("/bin/true 없음")
	}
	srv := fakeUpdateServer(t, bin, sum)
	defer srv.Close()
	c, _ := client.New(srv.URL, "x", "")
	on := true
	dest := filepath.Join(t.TempDir(), "update", "kpctl-builder")

	b := &Builder{cfg: &Config{SelfUpdate: &on}, c: c, selfSHA: "old"}
	// 서비스 파일에 경로가 없으면(예전 유닛) 받지 않음
	t.Setenv("KPCTL_BUILDER_UPDATE_PATH", "")
	if b.CheckUpdate() {
		t.Fatal("경로가 없으면 업데이트하면 안 됨")
	}
	t.Setenv("KPCTL_BUILDER_UPDATE_PATH", dest)
	if !b.CheckUpdate() {
		t.Fatal("새 버전을 받아야 함")
	}
	if fileSHA256(dest) != sum {
		t.Fatal("받은 파일 sha256 이 다름")
	}
	if _, err := os.Stat(dest + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("임시 파일이 남음")
	}

	// 같은 버전이면 받지 않음
	os.Remove(dest)
	b.selfSHA = sum
	if b.CheckUpdate() {
		t.Fatal("같은 버전이면 받으면 안 됨")
	}

	// sha256 이 다르면 거부
	bad := fakeUpdateServer(t, bin, "deadbeef")
	defer bad.Close()
	c2, _ := client.New(bad.URL, "x", "")
	b2 := &Builder{cfg: &Config{SelfUpdate: &on}, c: c2, selfSHA: "old"}
	if b2.CheckUpdate() {
		t.Fatal("sha256 이 안 맞으면 거부해야 함")
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Fatal("거부한 파일이 남음")
	}
}
