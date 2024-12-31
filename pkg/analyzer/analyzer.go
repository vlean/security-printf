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
				for _, arg := range callExpr.Args {
					if err := checkArgument(arg); err != nil {
						pass.Reportf(node.Pos(), "%v", err)
						return
					}
				}
				return
			}

			// 检查格式化字符串中是否有 %v, %+v, %#v 等通用格式化动词
			if strings.Contains(fmtStr, "%v") || strings.Contains(fmtStr, "%+v") || strings.Contains(fmtStr, "%#v") {
				// 检查对应的参数
				for _, arg := range callExpr.Args[1:] {
					if fail := checkArgs(arg, pass, node); fail {
						return
					}
					//if err := checkArgument(arg); err != nil {
					//	pass.Reportf(node.Pos(), "%v", err)
					//	return
					//}
				}
			} else {
				// 检查其他参数
				for _, arg := range callExpr.Args[1:] {
					if err := checkArgument(arg); err != nil {
						pass.Reportf(node.Pos(), "%v", err)
						return
					}
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

		// 检查是否是常见的日志包
		switch pkg {
		case "fmt", "log", "glog", "logrus", "klog", "zap", "logger":
			// 检查函数名是否以 'f' 结尾
			if strings.HasSuffix(name, "f") {
				return true
			}
			// 检查其他常见的日志函数名
			switch name {
			case "Print", "Printf", "Println", "Fatal", "Fatalf", "Fatalln",
				"Panic", "Panicf", "Panicln", "Error", "Errorf", "Errorln",
				"Info", "Infof", "Infoln", "Warn", "Warnf", "Warnln",
				"Debug", "Debugf", "Debugln", "Trace", "Tracef", "Traceln":
				return true
			}
		}
	}
	return false
}

func getCallExprFunction(callExpr *ast.CallExpr) (pkg string, fn string, result bool) {
	selector, ok := callExpr.Fun.(*ast.SelectorExpr)
	if !ok {
		return "", "", false
	}
	gopkg, ok := selector.X.(*ast.Ident)
	if !ok {
		return "", "", false
	}
	return gopkg.Name, selector.Sel.Name, true
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

func checkSecurityConstruction(printf *ast.CallExpr) error {
	// 跳过第一个参数（格式字符串）
	if len(printf.Args) <= 1 {
		return nil
	}

	// 检查每个参数
	for _, arg := range printf.Args[1:] {
		// 检查参数类型
		switch v := arg.(type) {
		case *ast.CompositeLit:
			// 直接检查复合字面量
			return checkCompositeLit(v)
		case *ast.Ident:
			// 检查标识符
			if v.Obj != nil {
				switch decl := v.Obj.Decl.(type) {
				case *ast.ValueSpec:
					// 检查变量声明
					if len(decl.Values) > 0 {
						if cl, ok := decl.Values[0].(*ast.CompositeLit); ok {
							return checkCompositeLit(cl)
						}
					}
				}
			}
		}

		// 检查参数的安全性
		if err := checkArgument(arg); err != nil {
			return err
		}
	}

	return nil
}

// checkArgument checks if an argument is safe to print
func checkArgument(arg ast.Expr) error {
	switch v := arg.(type) {
	case *ast.BasicLit:
		return nil // 基本类型是安全的
	case *ast.Ident:
		// 检查标识符
		if v.Obj != nil {
			switch decl := v.Obj.Decl.(type) {
			case *ast.TypeSpec:
				// 检查类型定义
				if _, ok := decl.Type.(*ast.StructType); ok {
					return fmt.Errorf("direct struct type printing is not allowed, please specify fields explicitly")
				}
				if _, ok := decl.Type.(*ast.MapType); ok {
					return fmt.Errorf("direct map type printing is not allowed, please specify fields explicitly")
				}
			case *ast.ValueSpec:
				// 检查变量声明
				if decl.Type != nil {
					if _, ok := decl.Type.(*ast.StructType); ok {
						return fmt.Errorf("direct struct type printing is not allowed, please specify fields explicitly")
					}
					if _, ok := decl.Type.(*ast.MapType); ok {
						return fmt.Errorf("direct map type printing is not allowed, please specify fields explicitly")
					}
				}
				// 检查变量的值
				if len(decl.Values) > 0 {
					switch val := decl.Values[0].(type) {
					case *ast.CompositeLit:
						if _, ok := val.Type.(*ast.StructType); ok {
							return fmt.Errorf("direct struct type printing is not allowed, please specify fields explicitly")
						}
						if _, ok := val.Type.(*ast.MapType); ok {
							return fmt.Errorf("direct map type printing is not allowed, please specify fields explicitly")
						}
					case *ast.UnaryExpr:
						return checkArgument(val.X)
					case *ast.CallExpr:
						// 检查函数调用的返回值
						if sel, ok := val.Fun.(*ast.SelectorExpr); ok {
							if sel.Sel.Name == "new" {
								return fmt.Errorf("direct struct type printing is not allowed, please specify fields explicitly")
							}
						}
					}
				}
			}
		}
		return checkIdentifier(v)
	case *ast.SelectorExpr:
		return checkSelector(v)
	case *ast.CompositeLit:
		// 检查复合字面量的类型
		if v.Type != nil {
			switch t := v.Type.(type) {
			case *ast.StructType:
				return fmt.Errorf("direct struct type printing is not allowed, please specify fields explicitly")
			case *ast.MapType:
				return fmt.Errorf("direct map type printing is not allowed, please specify fields explicitly")
			case *ast.ArrayType:
				if _, ok := t.Elt.(*ast.StructType); ok {
					return fmt.Errorf("direct struct type printing is not allowed, please specify fields explicitly")
				}
				if _, ok := t.Elt.(*ast.MapType); ok {
					return fmt.Errorf("direct map type printing is not allowed, please specify fields explicitly")
				}
			case *ast.Ident:
				if t.Obj != nil && t.Obj.Decl != nil {
					if typeSpec, ok := t.Obj.Decl.(*ast.TypeSpec); ok {
						if _, ok := typeSpec.Type.(*ast.StructType); ok {
							return fmt.Errorf("direct struct type printing is not allowed, please specify fields explicitly")
						}
						if _, ok := typeSpec.Type.(*ast.MapType); ok {
							return fmt.Errorf("direct map type printing is not allowed, please specify fields explicitly")
						}
					}
				}
			}
		}
		// 检查每个元素
		for _, elt := range v.Elts {
			if err := checkArgument(elt); err != nil {
				return err
			}
		}
	case *ast.UnaryExpr:
		return checkArgument(v.X)
	case *ast.BinaryExpr:
		if err := checkArgument(v.X); err != nil {
			return err
		}
		return checkArgument(v.Y)
	case *ast.IndexExpr:
		// 检查 map 访问
		if key, ok := v.Index.(*ast.BasicLit); ok {
			if key.Kind == token.STRING {
				keyStr := strings.Trim(key.Value, `"`)
				if _, ok := sensitiveFields[strings.ToLower(keyStr)]; ok {
					return fmt.Errorf("potentially sensitive field '%s' should not be logged", keyStr)
				}
			}
		}
		return checkArgument(v.X)
	case *ast.CallExpr:
		// 检查函数调用的参数
		for _, arg := range v.Args {
			if err := checkArgument(arg); err != nil {
				return err
			}
		}
		return nil
	case *ast.TypeAssertExpr:
		return checkArgument(v.X)
	case *ast.StarExpr:
		return checkArgument(v.X)
	case *ast.SliceExpr:
		return checkArgument(v.X)
	case *ast.ArrayType:
		if err := checkArgument(v.Elt); err != nil {
			return err
		}
		return nil
	case *ast.StructType:
		return fmt.Errorf("direct struct type printing is not allowed, please specify fields explicitly")
	case *ast.MapType:
		return fmt.Errorf("direct map type printing is not allowed, please specify fields explicitly")
	}
	return nil
}

// checkIdentifier checks if an identifier is safe to print
func checkIdentifier(id *ast.Ident) error {
	// 检查标识符名称是否包含敏感字段
	if _, ok := sensitiveFields[strings.ToLower(id.Name)]; ok {
		return fmt.Errorf("potentially sensitive field '%s' should not be logged", id.Name)
	}

	// 检查标识符的类型
	if id.Obj != nil {
		switch decl := id.Obj.Decl.(type) {
		case *ast.TypeSpec:
			// 检查类型定义
			if _, ok := decl.Type.(*ast.StructType); ok {
				return fmt.Errorf("direct struct type printing is not allowed, please specify fields explicitly")
			}
			if _, ok := decl.Type.(*ast.MapType); ok {
				return fmt.Errorf("direct map type printing is not allowed, please specify fields explicitly")
			}
		case *ast.ValueSpec:
			// 检查变量声明
			if decl.Type != nil {
				if _, ok := decl.Type.(*ast.StructType); ok {
					return fmt.Errorf("direct struct type printing is not allowed, please specify fields explicitly")
				}
				if _, ok := decl.Type.(*ast.MapType); ok {
					return fmt.Errorf("direct map type printing is not allowed, please specify fields explicitly")
				}
			}
			// 检查变量的值
			if len(decl.Values) > 0 {
				switch val := decl.Values[0].(type) {
				case *ast.CompositeLit:
					if _, ok := val.Type.(*ast.StructType); ok {
						return fmt.Errorf("direct struct type printing is not allowed, please specify fields explicitly")
					}
					if _, ok := val.Type.(*ast.MapType); ok {
						return fmt.Errorf("direct map type printing is not allowed, please specify fields explicitly")
					}
				case *ast.UnaryExpr:
					return checkArgument(val.X)
				case *ast.CallExpr:
					// 检查函数调用的返回值
					if sel, ok := val.Fun.(*ast.SelectorExpr); ok {
						if sel.Sel.Name == "new" {
							return fmt.Errorf("direct struct type printing is not allowed, please specify fields explicitly")
						}
					}
				}
			}
		case *ast.Field:
			// 检查字段类型
			if _, ok := decl.Type.(*ast.StructType); ok {
				return fmt.Errorf("direct struct type printing is not allowed, please specify fields explicitly")
			}
			if _, ok := decl.Type.(*ast.MapType); ok {
				return fmt.Errorf("direct map type printing is not allowed, please specify fields explicitly")
			}
		}
	}

	return nil
}

// checkSelector checks if a selector expression accesses sensitive fields
func checkSelector(sel *ast.SelectorExpr) error {
	// 检查选择器字段名
	if err := checkIdentifier(sel.Sel); err != nil {
		return err
	}

	// 检查基础对象
	switch x := sel.X.(type) {
	case *ast.Ident:
		if x.Obj != nil {
			switch decl := x.Obj.Decl.(type) {
			case *ast.Field:
				// 检查字段类型
				if _, ok := decl.Type.(*ast.StructType); ok {
					return fmt.Errorf("direct struct type printing is not allowed, please specify fields explicitly")
				}
				if _, ok := decl.Type.(*ast.MapType); ok {
					return fmt.Errorf("direct map type printing is not allowed, please specify fields explicitly")
				}
			case *ast.ValueSpec:
				// 检查变量声明
				if decl.Type != nil {
					if _, ok := decl.Type.(*ast.StructType); ok {
						return fmt.Errorf("direct struct type printing is not allowed, please specify fields explicitly")
					}
					if _, ok := decl.Type.(*ast.MapType); ok {
						return fmt.Errorf("direct map type printing is not allowed, please specify fields explicitly")
					}
				}
				// 检查变量的值
				if len(decl.Values) > 0 {
					switch v := decl.Values[0].(type) {
					case *ast.CompositeLit:
						if _, ok := v.Type.(*ast.StructType); ok {
							return fmt.Errorf("direct struct type printing is not allowed, please specify fields explicitly")
						}
						if _, ok := v.Type.(*ast.MapType); ok {
							return fmt.Errorf("direct map type printing is not allowed, please specify fields explicitly")
						}
					}
				}
			case *ast.TypeSpec:
				// 检查类型定义
				if _, ok := decl.Type.(*ast.StructType); ok {
					return fmt.Errorf("direct struct type printing is not allowed, please specify fields explicitly")
				}
				if _, ok := decl.Type.(*ast.MapType); ok {
					return fmt.Errorf("direct map type printing is not allowed, please specify fields explicitly")
				}
			}
		}
		return checkIdentifier(x)
	case *ast.SelectorExpr:
		return checkSelector(x)
	case *ast.CallExpr:
		// 检查函数调用的返回值
		for _, arg := range x.Args {
			if err := checkArgument(arg); err != nil {
				return err
			}
		}
		if sel, ok := x.Fun.(*ast.SelectorExpr); ok {
			return checkSelector(sel)
		}
	}
	return nil
}

// checkCompositeLit checks composite literals (structs, maps, etc)
func checkCompositeLit(cl *ast.CompositeLit) error {
	// 检查类型
	if cl.Type != nil {
		switch t := cl.Type.(type) {
		case *ast.StructType:
			return fmt.Errorf("direct struct type printing is not allowed, please specify fields explicitly")
		case *ast.MapType:
			return fmt.Errorf("direct map type printing is not allowed, please specify fields explicitly")
		case *ast.ArrayType:
			if _, ok := t.Elt.(*ast.StructType); ok {
				return fmt.Errorf("direct struct type printing is not allowed, please specify fields explicitly")
			}
			if _, ok := t.Elt.(*ast.MapType); ok {
				return fmt.Errorf("direct map type printing is not allowed, please specify fields explicitly")
			}
		case *ast.Ident:
			if t.Obj != nil && t.Obj.Decl != nil {
				if typeSpec, ok := t.Obj.Decl.(*ast.TypeSpec); ok {
					if _, ok := typeSpec.Type.(*ast.StructType); ok {
						return fmt.Errorf("direct struct type printing is not allowed, please specify fields explicitly")
					}
					if _, ok := typeSpec.Type.(*ast.MapType); ok {
						return fmt.Errorf("direct map type printing is not allowed, please specify fields explicitly")
					}
				}
			}
		}
	} else {
		// 如果没有显式类型，检查第一个元素的类型
		if len(cl.Elts) > 0 {
			if _, ok := cl.Elts[0].(*ast.CompositeLit); ok {
				return fmt.Errorf("direct struct type printing is not allowed, please specify fields explicitly")
			}
		}
	}

	// 检查每个元素
	for _, elt := range cl.Elts {
		if err := checkArgument(elt); err != nil {
			return err
		}
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
