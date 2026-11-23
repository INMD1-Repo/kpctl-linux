// 이 파일: 미게시 키 사본 비노출과 승인된 파일 descriptor의 SHA256 검증.
package controller

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"kpctl/internal/model"
)

func TestSigningDownloadRequiresReleasedMetadataAndMatchingBytes(t *testing.T) {
	s := newAutoServer(t, AutoRollout{})
	id := addBuilt(t, s, "manual")
	var module string
	s.store.View(func(st *State) { module = st.job(id).ModuleName })
	path := s.signingArtifactFile(testKernel, module, "next")
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("verified-next-key"), 0o640); err != nil {
		t.Fatal(err)
	}
	sum, err := fileSHA256(path)
	if err != nil {
		t.Fatal(err)
	}
	url := "/artifacts/" + testKernel + "/" + module + ".ko?key=next"
	callAPI(t, s, "GET", url, "", http.StatusNotFound)
	if err := s.store.Update(func(st *State) error {
		st.job(id).SigningArtifacts = map[string]model.SigningArtifact{"next": {KeyID: "next", SHA256: sum, Signed: true}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	callAPI(t, s, "GET", url, "", http.StatusNotFound)
	// 기존 기본 URL은 기존 클라이언트와 같은 계약을 유지합니다.
	callAPI(t, s, "GET", "/artifacts/"+testKernel+"/"+module+".ko", "", http.StatusOK)
	if err := s.store.Update(func(st *State) error { st.job(id).Status = model.JobReleased; return nil }); err != nil {
		t.Fatal(err)
	}
	if got := callAPI(t, s, "GET", url, "", http.StatusOK); got != "verified-next-key" {
		t.Fatalf("다른 바이트 제공: %q", got)
	}
	if err := os.WriteFile(path, []byte("changed"), 0o640); err != nil {
		t.Fatal(err)
	}
	callAPI(t, s, "GET", url, "", http.StatusConflict)
}
