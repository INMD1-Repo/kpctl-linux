// 이 파일: controller 패키지의 Error, fail, readJSON 구현·자료형.
package controller

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"time"
)

// ── HTTP 오류 ──

// httpError 는 "이 오류는 HTTP 몇 번으로 돌려줘라"는 뜻의 오류입니다.
// Update 함수 안에서 fail(...) 을 돌려주면 해당 상태 코드로 응답됩니다.
type httpError struct {
	code int
	msg  string
}

func (e *httpError) Error() string { return e.msg }

func fail(code int, format string, args ...any) error {
	return &httpError{code: code, msg: fmt.Sprintf(format, args...)}
}

// ── JSON 도우미 ──

const maxBody = 64 << 20 // 64MB (빌드 결과 모듈이 base64 로 들어오므로 넉넉하게)

func readJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, maxBody))
	if err := dec.Decode(v); err != nil {
		return fail(http.StatusBadRequest, "요청 JSON 해석 실패: %v", err)
	}
	return nil
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeRaw(w http.ResponseWriter, code int, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write(body)
}

// writeErr 는 오류를 {"error": "..."} 형태로 돌려줍니다.
func writeErr(w http.ResponseWriter, err error) {
	var he *httpError
	if errors.As(err, &he) {
		writeJSON(w, he.code, map[string]string{"error": he.msg})
		return
	}
	writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// ── 이름 검사 (경로 조작 방지) ──

var (
	kernelRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]*$`)
	moduleRe = regexp.MustCompile(`^[a-z0-9_]{1,55}$`)
	cveRe    = regexp.MustCompile(`(?i)CVE-\d{4}-\d{4,}`)
)

func validKernel(k string) bool { return kernelRe.MatchString(k) && !strings.Contains(k, "..") }
func validModule(m string) bool { return moduleRe.MatchString(m) }

// normalizeCVEs 는 CVE 목록을 대문자로 맞추고 중복을 없앱니다.
func normalizeCVEs(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, c := range in {
		for _, m := range cveRe.FindAllString(c, -1) {
			m = strings.ToUpper(m)
			if !seen[m] {
				seen[m] = true
				out = append(out, m)
			}
		}
	}
	sort.Strings(out)
	return out
}

// looksLikePatch 는 내용이 diff 형식처럼 보이는지 간단히 확인합니다.
func looksLikePatch(s string) bool {
	return strings.Contains(s, "--- ") && strings.Contains(s, "+++ ") && strings.Contains(s, "@@")
}

// ── 토큰 ──

func randHex(nBytes int) string {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// sameSecret 은 시간 차이로 토큰이 새지 않도록 비교합니다.
func sameSecret(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ── 외부 명령 실행 ──

// runCommand 는 설정 파일에 적힌 명령을 실행합니다.
// 인자 안의 "{이름}" 은 vars 값으로 바뀝니다. 예: {"host": "server-01"} → "{host}" 가 "server-01" 로.
// 셸을 거치지 않으므로 호스트 이름에 특수문자가 있어도 안전합니다.
func runCommand(tmpl []string, vars map[string]string, timeout time.Duration) (string, error) {
	if len(tmpl) == 0 {
		return "", errors.New("명령이 비어 있습니다")
	}
	args := make([]string, len(tmpl))
	for i, a := range tmpl {
		for k, v := range vars {
			a = strings.ReplaceAll(a, "{"+k+"}", v)
		}
		args[i] = a
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, args[0], args[1:]...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s 실행 실패: %w", args[0], err)
	}
	return string(out), nil
}
