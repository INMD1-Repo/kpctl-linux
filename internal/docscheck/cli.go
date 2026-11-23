// 이 파일: 실제 관리자 CLI의 commands 등록과 인자 dispatch AST에서 명령 목록을 읽습니다.
package docscheck

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

type commandCatalog map[string]map[string]bool

func indexZero(expr ast.Expr) bool {
	if paren, ok := expr.(*ast.ParenExpr); ok {
		return indexZero(paren.X)
	}
	index, ok := expr.(*ast.IndexExpr)
	if !ok {
		return false
	}
	name, ok := index.X.(*ast.Ident)
	if !ok || name.Name != "args" {
		return false
	}
	value, ok := index.Index.(*ast.BasicLit)
	return ok && value.Kind == token.INT && value.Value == "0"
}
func selector(expr ast.Expr, aliases map[string]bool) bool {
	if indexZero(expr) {
		return true
	}
	name, ok := expr.(*ast.Ident)
	return ok && aliases[name.Name]
}
func literal(expr ast.Expr) (string, bool) {
	value, ok := expr.(*ast.BasicLit)
	if !ok || value.Kind != token.STRING {
		return "", false
	}
	text, err := strconv.Unquote(value.Value)
	return text, err == nil && text != ""
}

func loadCommands(root string) (commandCatalog, error) {
	dir := filepath.Join(root, "cmd", "kpctl")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	functions := map[string]*ast.FuncDecl{}
	roots := map[string]string{}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(dir, entry.Name()), nil, 0)
		if err != nil {
			return nil, err
		}
		for _, decl := range file.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil {
				functions[fn.Name.Name] = fn
			}
			ast.Inspect(decl, func(node ast.Node) bool {
				value, ok := node.(*ast.ValueSpec)
				if !ok {
					return true
				}
				for i, name := range value.Names {
					if name.Name != "commands" || i >= len(value.Values) {
						continue
					}
					composite, ok := value.Values[i].(*ast.CompositeLit)
					if !ok {
						continue
					}
					for _, element := range composite.Elts {
						kv, ok := element.(*ast.KeyValueExpr)
						if !ok {
							continue
						}
						name, ok := literal(kv.Key)
						if !ok {
							continue
						}
						value, ok := kv.Value.(*ast.CompositeLit)
						if !ok || len(value.Elts) == 0 {
							continue
						}
						run := value.Elts[len(value.Elts)-1]
						if pair, ok := run.(*ast.KeyValueExpr); ok {
							run = pair.Value
						}
						function, ok := run.(*ast.Ident)
						if !ok {
							continue
						}
						roots[name] = function.Name
					}
				}
				return true
			})
		}
	}
	if len(roots) == 0 {
		return nil, fmt.Errorf("실제 CLI commands 등록을 찾지 못했습니다")
	}
	result := commandCatalog{}
	for name, run := range roots {
		fn := functions[run]
		if fn == nil {
			return nil, fmt.Errorf("CLI %s의 실제 함수 %s가 없습니다", name, run)
		}
		sub := map[string]bool{}
		aliases := map[string]bool{}
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			assignment, ok := node.(*ast.AssignStmt)
			if !ok {
				return true
			}
			for i, right := range assignment.Rhs {
				if indexZero(right) && i < len(assignment.Lhs) {
					if id, ok := assignment.Lhs[i].(*ast.Ident); ok {
						aliases[id.Name] = true
					}
				}
			}
			return true
		})
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			if comparison, ok := node.(*ast.BinaryExpr); ok && (comparison.Op == token.EQL || comparison.Op == token.NEQ) {
				if selector(comparison.X, aliases) {
					if value, ok := literal(comparison.Y); ok {
						sub[value] = true
					}
				}
				if selector(comparison.Y, aliases) {
					if value, ok := literal(comparison.X); ok {
						sub[value] = true
					}
				}
			}
			if branch, ok := node.(*ast.SwitchStmt); ok && branch.Tag != nil && selector(branch.Tag, aliases) {
				for _, statement := range branch.Body.List {
					if clause, ok := statement.(*ast.CaseClause); ok {
						for _, expr := range clause.List {
							if value, ok := literal(expr); ok {
								sub[value] = true
							}
						}
					}
				}
			}
			return true
		})
		result[name] = sub
	}
	return result, nil
}

var cliReference = regexp.MustCompile(`\bkpctl[\t ]+([a-z][a-z0-9-]*)(?:[\t ]+([a-z][a-z0-9-]*))?`)

func checkCommands(body string, catalog commandCatalog) (int, error) {
	references := cliReference.FindAllStringSubmatch(body, -1)
	for _, reference := range references {
		sub, exists := catalog[reference[1]]
		if !exists {
			return 0, fmt.Errorf("실제 CLI에 없는 명령: kpctl %s", reference[1])
		}
		if reference[2] != "" && len(sub) > 0 && !sub[reference[2]] {
			return 0, fmt.Errorf("실제 CLI에 없는 하위 명령: kpctl %s %s", reference[1], reference[2])
		}
	}
	return len(references), nil
}
