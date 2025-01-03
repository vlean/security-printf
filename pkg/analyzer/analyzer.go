package analyzer

import (
	"fmt"
	"go/ast"
	"go/token"
	"strings"

	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"

	"golang.org/x/tools/go/analysis"
)

var Analyzer = &analysis.Analyzer{
	Name:     "securityprintf",
	Doc:      "Checks for log printf to avoid security field show in log",
	Run:      run,
	Requires: []*analysis.Analyzer{inspect.Analyzer},
}

var (
	sensitiveFields = map[string]bool{}
	sensitive       = []string{}
)

func init() {
	for _, k := range sensitive {
		sensitiveFields[strings.ToLower(k)] = true
	}
}

func run(pass *analysis.Pass) (interface{}, error) {
	inspector := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector)
	nodeFilter := []ast.Node{
		(*ast.CallExpr)(nil),
	}

	inspector.Preorder(nodeFilter, func(node ast.Node) {
		callExpr := node.(*ast.CallExpr)

		// 检查是否是格式化打印函数
		funcType := isLoggerFunction(callExpr)
		if funcType == funcOther {
			return
		}
		if funcType == funcPrint {
			_, ok := getStringLiteral(callExpr.Args, 0)
			if !ok {
				pass.Reportf(node.Pos(), "cannot determine format string for %v", callExpr.Args[0])
			}
			return
		}

		// 检查参数
		if len(callExpr.Args) > 0 {
			// 获取格式化字符串
			fmtStr, ok := getStringLiteral(callExpr.Args, 0)
			if !ok {
				return
			}

			_ = fmtStr
			// 检查对应的参数
			for _, arg := range callExpr.Args[1:] {
				if fail := checkArgs(arg, pass, node); fail {
					return
				}
			}
		}
	})

	return nil, nil
}

func checkArgs(arg any, pass *analysis.Pass, node ast.Node) (fail bool) {
	fail = true
	switch v := arg.(type) {
	case *ast.CompositeLit:
		if v.Type != nil {
			switch t := v.Type.(type) {
			case *ast.StructType:
				pass.Reportf(node.Pos(), "direct struct type printing is not allowed, please specify fields explicitly")
				return
			case *ast.MapType:
				pass.Reportf(node.Pos(), "direct map type printing is not allowed, please specify fields explicitly")
				return
			case *ast.ArrayType:
				if fail = checkArgs(t.Elt, pass, node); fail {
					return
				}
			case *ast.Ident:
				if t.Obj != nil && t.Obj.Decl != nil {
					if typeSpec, ok := t.Obj.Decl.(*ast.TypeSpec); ok {
						if _, ok := typeSpec.Type.(*ast.StructType); ok {
							pass.Reportf(node.Pos(), "direct struct type printing is not allowed, please specify fields explicitly")
							return
						}
						if _, ok := typeSpec.Type.(*ast.MapType); ok {
							pass.Reportf(node.Pos(), "direct map type printing is not allowed, please specify fields explicitly")
							return
						}
					}
				}
			}
		}
		for _, elt := range v.Elts {
			if fail = checkArgs(elt, pass, node); fail {
				return
			}
		}
	case *ast.SelectorExpr:
		if err := checkIdentifier(v.Sel); err != nil {
			pass.Reportf(node.Pos(), "%v", err)
			return
		}
		return checkArgs(v.Sel.Obj, pass, node)
	case *ast.Ident:
		if v.Obj != nil {
			switch decl := v.Obj.Decl.(type) {
			case *ast.TypeSpec:
				if _, ok := decl.Type.(*ast.StructType); ok {
					pass.Reportf(node.Pos(), "direct struct type printing is not allowed, please specify fields explicitly")
					return
				}
				if _, ok := decl.Type.(*ast.MapType); ok {
					pass.Reportf(node.Pos(), "direct map type printing is not allowed, please specify fields explicitly")
					return
				}
			case *ast.ValueSpec:
				for _, value := range decl.Values {
					if fail = checkArgs(value, pass, node); fail {
						return
					}
				}
			case *ast.AssignStmt:
				if decl.Rhs != nil && len(decl.Rhs) > 0 {
					for _, rh := range decl.Rhs {
						if fail = checkArgs(rh, pass, node); fail {
							return
						}
					}
				}
			}
		}
		if err := checkIdentifier(v); err != nil {
			pass.Reportf(node.Pos(), "%v", err)
			return
		}
	case *ast.IndexExpr:
		// 检查 map 访问
		if key, ok := v.Index.(*ast.BasicLit); ok {
			if key.Kind == token.STRING {
				keyStr := strings.Trim(key.Value, `"`)
				if _, ok = sensitiveFields[strings.ToLower(keyStr)]; ok {
					err := fmt.Errorf("potentially sensitive field '%s' should not be logged", keyStr)
					pass.Reportf(node.Pos(), "%v", err)
					return
				}
			}
		}
		if fail = checkArgs(v.X, pass, node); fail {
			return
		}
	case *ast.ArrayType:
		return checkArgs(v.Elt, pass, node)
	case *ast.SliceExpr:
		return checkArgs(v.X, pass, node)
	case *ast.StarExpr:
		return checkArgs(v.X, pass, node)
	case *ast.UnaryExpr:
		return checkArgs(v.X, pass, node)
	case *ast.BinaryExpr: // 忽略表达式调用
	case *ast.CallExpr: // 忽略函数调用
	}
	return false
}

const (
	funcPrint = iota
	funcPrintf
	funcOther
)

// isLoggerFunction checks if a call expression is a printf-style function
func isLoggerFunction(call *ast.CallExpr) int {
	fun, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return funcOther
	}
	switch fun.Sel.Name {
	case "Debug", "Info", "Warn", "Trace", "Fatal", "Error", "Println":
		return funcPrint
	case "Debugf", "Infof", "Printf", "Warnf", "Tracef", "Fatalf", "Errorf":
		return funcPrintf
	}
	return funcOther
}

// getStringLiteral attempts to get a string literal from a list of expressions at a given index
func getStringLiteral(args []ast.Expr, index int) (string, bool) {
	if index >= len(args) {
		return "", false
	}

	switch arg := args[index].(type) {
	case *ast.BasicLit:
		if arg.Kind == token.STRING {
			// 移除字符串的引号
			return strings.Trim(arg.Value, `"`), true
		}
	case *ast.Ident:
		if arg.Obj != nil {
			switch decl := arg.Obj.Decl.(type) {
			case *ast.ValueSpec:
				if len(decl.Values) > 0 {
					if lit, ok := decl.Values[0].(*ast.BasicLit); ok && lit.Kind == token.STRING {
						return strings.Trim(lit.Value, `"`), true
					}
				}
			}
		}
	}
	return "", false
}

// checkIdentifier checks if an identifier is safe to print
func checkIdentifier(id *ast.Ident) error {
	// 检查标识符名称是否包含敏感字段
	if _, ok := sensitiveFields[strings.ToLower(id.Name)]; ok {
		return fmt.Errorf("potentially sensitive field '%s' should not be logged", id.Name)
	}
	return nil
}

func extractNames(sel *ast.SelectorExpr) (name []string) {
	switch t := sel.X.(type) {
	case *ast.SelectorExpr:
		name = extractNames(t)
	case *ast.CallExpr:
		if ident, ok := t.Fun.(*ast.Ident); ok {
			name = append(name, ident.Name)
		}
		if ident, ok := t.Fun.(*ast.SelectorExpr); ok {
			name = append(name, extractNames(ident)...)
		}
	case *ast.Ident:
		name = []string{t.Name}
	}
	return append(name, sel.Sel.Name)
}
