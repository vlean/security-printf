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
	loggerPrintfReg = map[string]struct{}{
		"tracef":   {},
		"debugf":   {},
		"infof":    {},
		"warnf":    {},
		"printf":   {},
		"errorf":   {},
		"fatalf":   {},
		"warningf": {},
	}

	sensitiveFields = map[string]bool{
		"password":     true,
		"passwd":       true,
		"secret":       true,
		"key":          true,
		"auth":         true,
		"token":        true,
		"credential":   true,
		"credentials":  true,
		"userpassword": true,
		"authtoken":    true,
	}
)

func run(pass *analysis.Pass) (interface{}, error) {
	inspector := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector)
	nodeFilter := []ast.Node{
		(*ast.CallExpr)(nil),
	}

	inspector.Preorder(nodeFilter, func(node ast.Node) {
		callExpr := node.(*ast.CallExpr)

		// 检查是否是格式化打印函数
		if !isPrintfFunction(callExpr) {
			return
		}

		// 检查参数
		if len(callExpr.Args) > 0 {
			// 获取格式化字符串
			fmtStr, ok := getStringLiteral(callExpr.Args, 0)
			if !ok {
				// 如果无法获取格式化字符串，检查所有参数
				//for _, arg := range callExpr.Args {
				//	if err := checkArgument(arg); err != nil {
				//		pass.Reportf(node.Pos(), "%v", err)
				//		return
				//	}
				//}
				return
			}

			_ = fmtStr
			// 检查格式化字符串中是否有 %v, %+v, %#v 等通用格式化动词
			//if strings.Contains(fmtStr, "%v") || strings.Contains(fmtStr, "%+v") || strings.Contains(fmtStr, "%#v") {
			// 检查对应的参数
			for _, arg := range callExpr.Args[1:] {
				if fail := checkArgs(arg, pass, node); fail {
					return
				}
			}
			//}
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
				if decl.Type != nil {
					if _, ok := decl.Type.(*ast.StructType); ok {
						pass.Reportf(node.Pos(), "direct struct type printing is not allowed, please specify fields explicitly")
						return
					}
					if _, ok := decl.Type.(*ast.MapType); ok {
						pass.Reportf(node.Pos(), "direct map type printing is not allowed, please specify fields explicitly")
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

// isPrintfFunction checks if a call expression is a printf-style function
func isPrintfFunction(call *ast.CallExpr) bool {
	// 检查调用表达式
	switch fun := call.Fun.(type) {
	case *ast.SelectorExpr:
		// 检查包名和函数名
		pkg, name, ok := extractPackageAndName(fun)
		if !ok {
			return false
		}

		// 检查指定日志函数
		if _, ok = loggerPrintfReg[strings.ToLower(name)]; ok {
			return true
		}

		// 检查是否是常见的日志包
		switch pkg {
		case "log", "glog", "logrus", "klog", "zap", "logger", "logx":
			// 检查函数名是否以 'f' 结尾
			if strings.HasSuffix(name, "f") {
				return true
			}
		}

	}
	return false
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

func extractPackageAndName(sel *ast.SelectorExpr) (pkg string, name string, ok bool) {
	ident, ok := sel.X.(*ast.Ident)
	if !ok {
		return "", "", false
	}
	return ident.Name, sel.Sel.Name, true
}
