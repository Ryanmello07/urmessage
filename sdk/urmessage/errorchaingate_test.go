package urmessage

import (
	"go/ast"
	"go/constant"
	"go/parser"
	"go/token"
	"go/types"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// NO ERROR IN THIS PACKAGE IS FORMATTED WITHOUT ITS CHAIN (R29, the second review's W1). A
// `fmt.Errorf` that binds an error to `%v` or `%s` writes its text and drops its value: errors.Is
// and errors.As no longer reach it, and [classifyRead] reads the errno of a failed read through
// exactly that chain. One such site, SentRecords' listing of the `sent` directory, made a held
// directory "damage" under the fail-open rule, and an owner's group was erased unasked. The erase
// is fail-closed now, so a lost errno no longer erases anything -- but it makes a group that is
// truly damaged unleavable (it reads as unproven), which is R12's leavability lost by one verb.
//
// THE RULE AND ITS CLASS, said because the class is what this gate can see. In every production
// source of this package, whatever GOOS it is constrained to, every `fmt.Errorf` whose format is a
// constant is parsed verb by verb, and an argument bound to `%v` or `%s` is a violation when it is
// ERROR-TYPED, which is decided two ways, either one enough:
//   - by type: a go/types check of this package with NO imports resolves the argument to the
//     universe `error` type -- a parameter, a field, a variable declared `error`, the result of a
//     function of this package;
//   - by name, for what that check cannot resolve (a value an imported function returned, whose
//     type is unknown to a check with no imports): an identifier, or a selector's last name, that
//     is `err` or ends in `Err` or `err`; or a call of `.Error()`, which is the same chain dropped by
//     hand.
//
// IT IS BLIND to an error value under another name whose type only an import knows (a
// `cause := os.Remove(x)` formatted with %v), to a non-constant format, and to every formatter but
// fmt.Errorf. THE CONTROL is a planted source with one violation of each kind it does see and two
// clean calls: the checker must flag exactly the three.
func TestNoErrorInThisPackageIsFormattedWithoutItsChain(t *testing.T) {
	// THE CONTROL FIRST: a checker that flags nothing would pass the package by blindness
	planted := `package planted

import (
	"errors"
	"fmt"
	"os"
)

var ErrPlanted = errors.New("planted")

func byName(path string) error {
	_, err := os.ReadDir(path)
	return fmt.Errorf("%w: %s could not be read: %v", ErrPlanted, path, err)
}

func byType(cause error) error {
	return fmt.Errorf("planted: %s", cause)
}

func byText(path string) error {
	_, statErr := os.Stat(path)
	return fmt.Errorf("planted: %v", statErr.Error())
}

func clean(path string) error {
	_, err := os.Stat(path)
	return fmt.Errorf("%w: %s: %w", ErrPlanted, path, err)
}

func alsoClean(count int, name string) error {
	return fmt.Errorf("planted: %d %s %v", count, name, count)
}
`
	plantedSet := token.NewFileSet()
	plantedFile, err := parser.ParseFile(plantedSet, "planted.go", planted, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parsing the planted source: %v", err)
	}
	flagged, _, _ := errorChainViolations(plantedSet, []*ast.File{plantedFile})
	wantPlanted := []string{"byName: err", "byText: statErr.Error()", "byType: cause"}
	if strings.Join(flagged, "\n") != strings.Join(wantPlanted, "\n") {
		t.Fatalf("CONTROL FAILED: over the planted source the checker flagged %q, want exactly %q", flagged, wantPlanted)
	}

	fileSet, files := headGateParsePackage(t)
	violations, where, judged := errorChainViolations(fileSet, files)
	t.Logf("read %d production source(s); %d argument(s) bound to %%v or %%s were judged NOT error-typed, and so are not held:", len(files), len(judged))
	for _, one := range judged {
		t.Logf("  %s", one)
	}
	for _, one := range violations {
		t.Errorf("an error is formatted without its chain: %s -- use %%w", one)
	}
	for _, one := range where {
		t.Logf("  the violation's format: %s", one)
	}
}

// errorChainViolations answers every `fmt.Errorf` argument in files that binds an error-typed value
// to %v or %s, as "function: argument"; where each one's format literal stands, and which argument
// of it is the error; and every other argument bound to those verbs, which is what the rule judged
// not error-typed: the complement, printed so that a narrowing is seen.
func errorChainViolations(fileSet *token.FileSet, files []*ast.File) ([]string, []string, []string) {
	config := &types.Config{
		Importer:                 headGateNoImports{},
		Error:                    func(error) {},
		DisableUnusedImportCheck: true,
	}
	info := &types.Info{Types: map[ast.Expr]types.TypeAndValue{}}
	config.Check("errorchaingate", fileSet, files, info)
	errorType := types.Universe.Lookup("error").Type()
	violations := []string{}
	where := []string{}
	judged := []string{}
	for _, file := range files {
		for _, decl := range file.Decls {
			function, isFunction := decl.(*ast.FuncDecl)
			if !isFunction || function.Body == nil {
				continue
			}
			ast.Inspect(function.Body, func(node ast.Node) bool {
				call, isCall := node.(*ast.CallExpr)
				if !isCall || !errorChainIsErrorf(call) || len(call.Args) == 0 {
					return true
				}
				format, isConstant := errorChainFormat(info, call.Args[0])
				if !isConstant {
					return true
				}
				for index, verb := range errorChainVerbs(format) {
					if verb != 'v' && verb != 's' {
						continue
					}
					at := 1 + index
					if at >= len(call.Args) {
						continue
					}
					argument := call.Args[at]
					name := errorChainSpelling(argument)
					callAt := fileSet.Position(call.Pos())
					site := function.Name.Name + ": " + name
					typed := false
					if tv, known := info.Types[argument]; known && tv.Type != nil && types.Identical(tv.Type, errorType) {
						typed = true
					}
					if typed || errorChainNamedLikeAnError(argument) {
						violations = append(violations, site)
						literal := fileSet.Position(call.Args[0].Pos())
						where = append(where, literal.Filename+":"+strconv.Itoa(literal.Line)+":"+
							strconv.Itoa(literal.Column)+":"+strconv.Itoa(index)+": "+site)
					} else {
						judged = append(judged, site+" at "+callAt.Filename+":"+strconv.Itoa(callAt.Line))
					}
				}
				return true
			})
		}
	}
	sort.Strings(violations)
	sort.Strings(where)
	sort.Strings(judged)
	return violations, where, judged
}

func errorChainIsErrorf(call *ast.CallExpr) bool {
	selector, isSelector := call.Fun.(*ast.SelectorExpr)
	if !isSelector || selector.Sel.Name != "Errorf" {
		return false
	}
	pkg, isIdent := selector.X.(*ast.Ident)
	return isIdent && pkg.Name == "fmt"
}

func errorChainFormat(info *types.Info, expression ast.Expr) (string, bool) {
	if literal, isLiteral := expression.(*ast.BasicLit); isLiteral && literal.Kind == token.STRING {
		value, err := strconv.Unquote(literal.Value)
		return value, err == nil
	}
	if tv, known := info.Types[expression]; known && tv.Value != nil && tv.Value.Kind() == constant.String {
		return constant.StringVal(tv.Value), true
	}
	return "", false
}

// errorChainVerbs is the verb each argument of a format is bound to, in argument order. A `*` width
// or precision consumes an argument of its own, and is bound to the pseudo-verb '*'. An explicit
// index is not supported and ends the parse: no format in this package uses one.
func errorChainVerbs(format string) []rune {
	verbs := []rune{}
	for at := 0; at < len(format); at += 1 {
		if format[at] != '%' {
			continue
		}
		at += 1
		if at < len(format) && format[at] == '%' {
			continue
		}
		for at < len(format) && strings.ContainsRune("+-# 0", rune(format[at])) {
			at += 1
		}
		for at < len(format) && (format[at] == '*' || format[at] == '.' || ('0' <= format[at] && format[at] <= '9')) {
			if format[at] == '*' {
				verbs = append(verbs, '*')
			}
			at += 1
		}
		if at < len(format) && format[at] == '[' {
			return verbs
		}
		if at < len(format) {
			verbs = append(verbs, rune(format[at]))
		}
	}
	return verbs
}

func errorChainSpelling(expression ast.Expr) string {
	switch one := expression.(type) {
	case *ast.Ident:
		return one.Name
	case *ast.SelectorExpr:
		return errorChainSpelling(one.X) + "." + one.Sel.Name
	case *ast.CallExpr:
		return errorChainSpelling(one.Fun) + "()"
	}
	return "an expression"
}

func errorChainNamedLikeAnError(expression ast.Expr) bool {
	errorName := func(name string) bool {
		return name == "err" || strings.HasSuffix(name, "Err") || strings.HasSuffix(name, "err")
	}
	switch one := expression.(type) {
	case *ast.Ident:
		return errorName(one.Name)
	case *ast.SelectorExpr:
		return errorName(one.Sel.Name)
	case *ast.CallExpr:
		if selector, isSelector := one.Fun.(*ast.SelectorExpr); isSelector && selector.Sel.Name == "Error" && len(one.Args) == 0 {
			return true
		}
	}
	return false
}
