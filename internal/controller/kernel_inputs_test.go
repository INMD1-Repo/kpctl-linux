// 이 파일: controller 패키지의 TestControllerTransfersAndCachesKernelInputBytes, TestKernelInputFailuresNeverPublishPartialCache, TestKernelInputRejectsUnlistedPackagesAndVersions 회귀 시험.
package controller

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"kpctl/internal/model"
)

type kernelInputTransport func(*http.Request) (*http.Response, error)

func (f kernelInputTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func inputRequest(t *testing.T, s *Server, path, token string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, path, nil)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, r)
	return w
}

func TestControllerTransfersAndCachesKernelInputBytes(t *testing.T) {
	s := newAutoServer(t, AutoRollout{})
	content := "actual kernel package bytes\x00\xff"
	calls := 0
	names, err := model.KernelInputNames(testKernel, "6.8.0-85.85", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	s.kernelInputsClient = &http.Client{Transport: kernelInputTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.String() != kernelInputUpstream+names[0] || r.Header.Get("Authorization") != "" {
			t.Fatalf("must fetch only fixed official URL without controller credentials: %s", r.URL)
		}
		return &http.Response{StatusCode: 200, ContentLength: int64(len(content)), Body: io.NopCloser(strings.NewReader(content)), Header: make(http.Header)}, nil
	})}
	path := "/api/builder/kernel-inputs/" + testKernel + "/6.8.0-85.85/amd64/" + names[0]
	for i := 0; i < 2; i++ {
		w := inputRequest(t, s, path, s.cfg.BuilderToken)
		if w.Code != 200 || w.Body.String() != content || w.Header().Get("X-Checksum-Sha256") != fmt.Sprintf("%x", sha256.Sum256([]byte(content))) || w.Header().Get("Content-Length") != fmt.Sprint(len(content)) {
			t.Fatalf("invalid byte transfer or file metadata: %d %s %v", w.Code, w.Body.String(), w.Header())
		}
	}
	if calls != 1 {
		t.Fatalf("builders must share the completed cache: fetched %d times", calls)
	}
	w := inputRequest(t, s, path, "")
	if w.Code != http.StatusUnauthorized || calls != 1 {
		t.Fatal("input cache requires builder authentication")
	}
	w = inputRequest(t, s, path, testAdmin)
	if w.Code != http.StatusUnauthorized {
		t.Fatal("admin token must not serve as a builder token")
	}
}

func TestKernelInputFailuresNeverPublishPartialCache(t *testing.T) {
	for _, kind := range []string{"missing", "upstream", "oversized", "truncated", "empty", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			s := newAutoServer(t, AutoRollout{})
			s.kernelInputsClient = &http.Client{Transport: kernelInputTransport(func(r *http.Request) (*http.Response, error) {
				response := &http.Response{StatusCode: 200, ContentLength: 4, Body: io.NopCloser(strings.NewReader("data")), Header: make(http.Header)}
				switch kind {
				case "missing":
					response.StatusCode = 404
				case "upstream":
					response.StatusCode = 503
				case "oversized":
					response.ContentLength = kernelInputLimit + 1
				case "truncated":
					response.ContentLength++
				case "empty":
					response.ContentLength, response.Body = 0, io.NopCloser(strings.NewReader(""))
				case "cancelled":
					return nil, context.Canceled
				}
				return response, nil
			})}
			names, _ := model.KernelInputNames(testKernel, "6.8.0-85.85", "amd64")
			url := "/api/builder/kernel-inputs/" + testKernel + "/6.8.0-85.85/amd64/" + names[0]
			w := inputRequest(t, s, url, s.cfg.BuilderToken)
			want := http.StatusBadGateway
			if kind == "missing" {
				want = http.StatusNotFound
			}
			if w.Code != want {
				t.Fatalf("status=%d, want %d: %s", w.Code, want, w.Body.String())
			}
			dir := filepath.Join(s.cfg.DataDir, "kernel-inputs", testKernel, "6.8.0-85.85", "amd64")
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 0 {
				t.Fatalf("partial download published: %v %v", entries, err)
			}
		})
	}
}

func TestKernelInputRejectsUnlistedPackagesAndVersions(t *testing.T) {
	s := newAutoServer(t, AutoRollout{})
	s.kernelInputsClient = &http.Client{Transport: kernelInputTransport(func(r *http.Request) (*http.Response, error) {
		t.Fatal("invalid request reached upstream")
		return nil, nil
	})}
	for _, suffix := range []string{
		"6.8.0-85.85/amd64/other.deb",
		"6.8.0-86.86/amd64/linux-image-6.8.0-85-generic_6.8.0-86.86_amd64.deb",
		"6.8.0-85.85~22.04.1/amd64/linux-image-6.8.0-85-generic_6.8.0-85.85~22.04.1_amd64.deb",
		"6.8.0-85.85/unknown/linux-image-6.8.0-85-generic_6.8.0-85.85_unknown.deb",
	} {
		w := inputRequest(t, s, "/api/builder/kernel-inputs/"+testKernel+"/"+suffix, s.cfg.BuilderToken)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("invalid package accepted: %s: %d", suffix, w.Code)
		}
	}
}
