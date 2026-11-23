// 이 파일: Go 선언의 실제 이름·줄 번호로 코드 지도를 만들고 오래된 참조를 검출합니다.
package docscheck

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type sourceSymbol struct {
	Name string
	Line int
}

func receiverName(expression ast.Expr) string {
	switch value := expression.(type) {
	case *ast.Ident:
		return value.Name
	case *ast.StarExpr:
		return receiverName(value.X)
	case *ast.IndexExpr:
		return receiverName(value.X)
	case *ast.IndexListExpr:
		return receiverName(value.X)
	}
	return ""
}
func symbolsAt(path string) ([]sourceSymbol, string, error) {
	set := token.NewFileSet()
	file, err := parser.ParseFile(set, path, nil, parser.ParseComments)
	if err != nil {
		return nil, "", err
	}
	var result []sourceSymbol
	for _, decl := range file.Decls {
		if function, ok := decl.(*ast.FuncDecl); ok {
			name := function.Name.Name
			if function.Recv != nil && len(function.Recv.List) > 0 {
				name = receiverName(function.Recv.List[0].Type) + "." + name
			}
			result = append(result, sourceSymbol{name, set.Position(function.Pos()).Line})
		}
		if group, ok := decl.(*ast.GenDecl); ok && group.Tok == token.TYPE {
			for _, spec := range group.Specs {
				if value, ok := spec.(*ast.TypeSpec); ok {
					result = append(result, sourceSymbol{value.Name.Name, set.Position(value.Pos()).Line})
				}
			}
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Line < result[j].Line })
	guide := file.Name.Name + " 패키지 선언"
	if len(file.Comments) > 0 && file.Comments[0].Pos() < file.Package {
		guide = strings.Split(strings.TrimSpace(file.Comments[0].Text()), "\n")[0]
	}
	guide = strings.TrimPrefix(guide, "이 파일: ")
	guide = strings.ReplaceAll(guide, "|", "\\|")
	return result, guide, nil
}

var symbolReference = regexp.MustCompile(`\[([A-Za-z_][A-Za-z0-9_.]*)\]\(([^)\n]+\.go)#L([0-9]+)\)`)

func checkSourceSymbols(document, body string) error {
	cache := map[string]map[string]int{}
	for _, match := range symbolReference.FindAllStringSubmatch(body, -1) {
		path := filepath.Clean(filepath.Join(filepath.Dir(document), filepath.FromSlash(match[2])))
		symbols, found := cache[path]
		if !found {
			declarations, _, err := symbolsAt(path)
			if err != nil {
				return err
			}
			symbols = map[string]int{}
			for _, decl := range declarations {
				symbols[decl.Name] = decl.Line
			}
			cache[path] = symbols
		}
		line, _ := strconv.Atoi(match[3])
		if symbols[match[1]] != line {
			return fmt.Errorf("코드 지도 선언 위치 불일치: %s (%s:%d)", match[1], match[2], line)
		}
	}
	return nil
}

func GenerateCodeMap(root string) (string, error) {
	var files []string
	for _, directory := range []string{"cmd", "internal", "tools"} {
		err := filepath.WalkDir(filepath.Join(root, directory), func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !entry.IsDir() && strings.HasSuffix(path, ".go") {
				files = append(files, path)
			}
			return nil
		})
		if err != nil {
			return "", err
		}
	}
	sort.Strings(files)
	var output strings.Builder
	output.WriteString("# 코드 위치 지도\n\n[문서 목차](../README.md) · [기능 명세](../features/README.md)\n\n실제 Go 선언 이름과 줄 번호를 읽어 만든 목록입니다. 파일 안내 주석의 역할과 선언 링크를 함께 봅니다. 코드가 이동하면 `go run ./tools/code-map > docs/development/code-map.md`로 다시 만들고 `make docs-check`로 이름·위치를 확인합니다.\n\n<!-- code-map: declarations -->\n")
	for _, tests := range []bool{false, true} {
		if tests {
			output.WriteString("\n## Go 회귀 시험\n\n")
		} else {
			output.WriteString("\n## Go 실행 코드와 공유 자료형\n\n")
		}
		output.WriteString("| 파일 | 역할 | 실제 선언 |\n|---|---|---|\n")
		for _, file := range files {
			if strings.HasSuffix(file, "_test.go") != tests {
				continue
			}
			symbols, guide, err := symbolsAt(file)
			if err != nil {
				return "", err
			}
			relative, err := filepath.Rel(root, file)
			if err != nil {
				return "", err
			}
			relative = filepath.ToSlash(relative)
			var links []string
			for _, symbol := range symbols {
				links = append(links, fmt.Sprintf("[%s](../../%s#L%d)", symbol.Name, relative, symbol.Line))
			}
			fmt.Fprintf(&output, "| [%s](../../%s) | %s | %s |\n", relative, relative, guide, strings.Join(links, ", "))
		}
	}
	output.WriteString("\n## 웹과 실행 스크립트\n\n| 경로 | 역할 |\n|---|---|\n")
	for _, entry := range []struct{ path, role string }{
		{"web/src/pages/Hosts.jsx", "HostSecurity와 호스트·커널 조작"}, {"web/src/pages/Jobs.jsx", "작업과 VM 시험 증거"}, {"web/src/pages/Patches.jsx", "패치 상태·관련 VM 증거"}, {"web/src/pages/Settings.jsx", "운영 설정과 공개 서명 키"}, {"web/src/ui.jsx", "VMTestEvidence와 공통 상호작용"}, {"web/src/selectors.js", "목표·보안 상태 표시"}, {"web/dev/store.js", "격리된 가상 API"}, {"deploy/", "설치·공식 입력·빌드 환경·CVE 자료와 VM adapter"}, {"test/", "Python·셸·가짜 도구 및 선택적 실제 커널 시험"},
	} {
		if _, err := os.Stat(filepath.Join(root, entry.path)); err != nil {
			return "", err
		}
		fmt.Fprintf(&output, "| [%s](../../%s) | %s |\n", entry.path, entry.path, entry.role)
	}
	return output.String(), nil
}
