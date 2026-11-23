// Package client 는 컨트롤러 HTTP API 를 부르는 작은 클라이언트입니다.
// 빌드 서버, 에이전트, kpctl 이 모두 이 패키지를 씁니다.
package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// ErrNoContent 는 서버가 204(내용 없음)를 돌려줬다는 뜻입니다.
// 예: 빌드 서버가 작업을 요청했는데 대기 중인 작업이 없을 때.
var ErrNoContent = errors.New("no content")

// HTTPError 는 컨트롤러가 응답한 오류 상태입니다. 4xx 는 다시 보내도 같은 결과라 재시도하지 않습니다.
type HTTPError struct {
	Status int
	msg    string
}

func (e *HTTPError) Error() string { return e.msg }

// Retryable 은 연결 실패·시간 초과·5xx 처럼 다시 보내면 성공할 수 있는 오류인지 알려 줍니다.
func Retryable(err error) bool {
	if err == nil || errors.Is(err, ErrNoContent) {
		return false
	}
	var h *HTTPError
	if errors.As(err, &h) {
		return h.Status >= 500 || h.Status == http.StatusTooManyRequests
	}
	return true
}

type Client struct {
	base  string
	token string
	hc    *http.Client
}

// New 는 클라이언트를 만듭니다.
// caFile 을 주면 그 CA 인증서로 컨트롤러 TLS 인증서를 검증합니다 (사설 CA 사용 시).
func New(baseURL, token, caFile string) (*Client, error) {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	// 컨트롤러는 항상 내부(관리망)에 있으므로 HTTPS_PROXY 같은 프록시 설정을 쓰지 않습니다.
	// (서버에 외부용 프록시가 설정돼 있으면 내부 컨트롤러 요청까지 프록시로 빠져 실패함)
	tr.Proxy = nil
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("CA 파일 읽기 실패: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("CA 파일에서 인증서를 찾지 못했습니다: %s", caFile)
		}
		tr.TLSClientConfig = &tls.Config{RootCAs: pool}
	}
	return &Client{
		base:  strings.TrimRight(baseURL, "/"),
		token: token,
		hc:    &http.Client{Transport: tr, Timeout: 10 * time.Minute},
	}, nil
}

// SetToken 은 인증 토큰을 바꿉니다 (에이전트가 등록 후 호스트 토큰으로 바꿀 때).
func (c *Client) SetToken(token string) { c.token = token }

// Do 는 JSON 요청을 보내고 JSON 응답을 out 에 채웁니다.
//   - in 이 nil 이면 본문 없이 보냅니다.
//   - out 이 *string 이면 응답 본문을 문자열 그대로 넣습니다.
//   - out 이 nil 이면 응답 본문을 버립니다.
func (c *Client) Do(method, path string, in, out any) error {
	return c.DoContext(context.Background(), method, path, in, out)
}

// DoContext lets independent status reports time out without blocking a build.
func (c *Client) DoContext(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent {
		return ErrNoContent
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(data, &e) == nil && e.Error != "" {
			return &HTTPError{Status: resp.StatusCode, msg: fmt.Sprintf("%s (HTTP %d)", e.Error, resp.StatusCode)}
		}
		return &HTTPError{Status: resp.StatusCode, msg: fmt.Sprintf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))}
	}
	if out == nil {
		return nil
	}
	if s, ok := out.(*string); ok {
		*s = string(data)
		return nil
	}
	return json.Unmarshal(data, out)
}

// Download 는 path 의 파일을 받아 dest 에 저장합니다.
func (c *Client) Download(path, dest string) error {
	req, err := http.NewRequest(http.MethodGet, c.base+path, nil)
	if err != nil {
		return err
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("다운로드 실패 HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
