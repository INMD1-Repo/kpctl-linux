// 이 파일: controller 패키지의 handleWeb 구현·자료형.
package controller

import (
	"embed"
	"mime"
	"net/http"
	"path"
)

// 이 파일: 관리자 웹 화면
//
// web/은 web/src의 React 화면을 Vite로 빌드한 결과입니다.
// 번들은 컨트롤러에 내장되므로 운영 중 Node.js나 외부 CDN이 필요하지 않습니다.
// 화면에는 비밀이 없고, 데이터는 관리자 토큰으로 /api/... 를 불러 가져옵니다.
// 쿠키를 쓰지 않으므로 다른 사이트에서 요청을 위조해도 인증되지 않습니다.

//go:embed web/*
var webFiles embed.FS

// GET /, GET /ui/{file}
func (s *Server) handleWeb(w http.ResponseWriter, r *http.Request) {
	file := r.PathValue("file")
	if file == "" {
		file = "index.html"
	}
	data, err := webFiles.ReadFile("web/" + file)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	h := w.Header()
	if contentType := mime.TypeByExtension(path.Ext(file)); contentType != "" {
		h.Set("Content-Type", contentType)
	}
	// 패치 제목, 호스트 이름처럼 밖에서 온 값이 화면에 나오므로 내장 파일 외의 스크립트는 막습니다.
	h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; connect-src 'self'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cache-Control", "no-cache")
	_, _ = w.Write(data)
}
