// 이 파일: 현재 문서의 상대 파일 링크·Markdown/HTML 앵커·소스 줄 번호 검사.
package docscheck

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

var inlineLink = regexp.MustCompile(`!?\[[^\]\n]*\]\(([^)\n]+)\)`)
var explicitID = regexp.MustCompile(`(?i)\bid\s*=\s*["']([^"']+)["']`)
var heading = regexp.MustCompile(`^ {0,3}#{1,6}[\t ]+(.+)$`)
var sourceLine = regexp.MustCompile(`^L([1-9][0-9]*)(?:-L([1-9][0-9]*))?$`)
var htmlTag = regexp.MustCompile(`<[^>]+>`)

func anchors(body string) map[string]bool {
	result := map[string]bool{}
	repeats := map[string]int{}
	fenced := false
	for _, match := range explicitID.FindAllStringSubmatch(body, -1) {
		result[match[1]] = true
	}
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "```") {
			fenced = !fenced
			continue
		}
		if fenced {
			continue
		}
		match := heading.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		text := strings.TrimSpace(strings.TrimRight(match[1], "#"))
		text = htmlTag.ReplaceAllString(text, "")
		var slug strings.Builder
		for _, r := range strings.ToLower(text) {
			switch {
			case unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '-':
				slug.WriteRune(r)
			case unicode.IsSpace(r):
				slug.WriteByte('-')
			}
		}
		id := slug.String()
		count := repeats[id]
		repeats[id]++
		if count > 0 {
			id += "-" + strconv.Itoa(count)
		}
		result[id] = true
	}
	return result
}

func checkLinks(root, document, body string) (int, error) {
	count := 0
	for _, match := range inlineLink.FindAllStringSubmatch(body, -1) {
		target := strings.TrimSpace(match[1])
		if target == "" {
			return count, fmt.Errorf("비어 있는 상대 링크")
		}
		if strings.HasPrefix(target, "<") {
			if end := strings.Index(target, ">"); end >= 0 {
				target = target[1:end]
			}
		} else {
			target = strings.Fields(target)[0]
		}
		parsed, err := url.Parse(target)
		if err != nil {
			return count, fmt.Errorf("잘못된 링크 %q", target)
		}
		if parsed.Scheme != "" || parsed.Host != "" || strings.HasPrefix(target, "/") {
			continue
		}
		count++
		path := document
		if parsed.Path != "" {
			path = filepath.Clean(filepath.Join(filepath.Dir(document), filepath.FromSlash(parsed.Path)))
		}
		rel, err := filepath.Rel(root, path)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return count, fmt.Errorf("저장소 밖 상대 링크 %q", target)
		}
		info, err := os.Stat(path)
		if err != nil {
			return count, fmt.Errorf("없는 상대 링크 %q", target)
		}
		if parsed.Fragment == "" {
			continue
		}
		if info.IsDir() {
			path = filepath.Join(path, "README.md")
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return count, fmt.Errorf("앵커 대상 읽기 실패 %q", target)
		}
		if lines := sourceLine.FindStringSubmatch(parsed.Fragment); lines != nil && !strings.HasSuffix(path, ".md") {
			last := lines[1]
			if lines[2] != "" {
				last = lines[2]
			}
			number, _ := strconv.Atoi(last)
			if number <= len(strings.Split(string(data), "\n")) {
				continue
			}
		} else if anchors(string(data))[parsed.Fragment] {
			continue
		}
		return count, fmt.Errorf("없는 앵커 %q", target)
	}
	return count, nil
}
