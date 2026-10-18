package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
)

// Two gates over sdk/cgo's messaging exports, read as source: what a kind-answering export answers
// when a panic is recovered inside it (LRI R84 item 3; review X-LIB-1), and what the exports that
// carry the recovery words keep of them (LRI R84 item 10; review G-2).

// messageExportsSource parses sdk/cgo's exports_message.go.
func messageExportsSource(t *testing.T) (*token.FileSet, *ast.File) {
	t.Helper()
	path := filepath.Join(filepath.Dir(testingGenDir(t)), "exports_message.go")
	source, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return parseExportsSource(t, path, source)
}

func parseExportsSource(t *testing.T, path string, source []byte) (*token.FileSet, *ast.File) {
	t.Helper()
	fileSet := token.NewFileSet()
	parsed, err := parser.ParseFile(fileSet, path, source, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return fileSet, parsed
}

// exportedFunctions is every function of a file that carries an //export line, by name.
func exportedFunctions(parsed *ast.File) map[string]*ast.FuncDecl {
	exported := map[string]*ast.FuncDecl{}
	for _, declaration := range parsed.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Doc == nil {
			continue
		}
		for _, comment := range function.Doc.List {
			if strings.HasPrefix(comment.Text, "//export ") {
				exported[function.Name.Name] = function
			}
		}
	}
	return exported
}

func expressionText(fileSet *token.FileSet, node ast.Node) string {
	var out strings.Builder
	printer.Fprint(&out, fileSet, node)
	return out.String()
}

// ── a panic inside a kind-answering export ───────────────────────────────────────────────────

// kindAnsweringExports is every export whose int32 result is a kind -- a state a caller acts on --
// with the failure its result is preset to. cgoGuard recovers a panic, and an unnamed result then
// answers its zero value, which for each of these is a success: OK for the words, the commit verbs
// and a leave, and "the subscription is current" for ensure_subscribed.
var kindAnsweringExports = map[string]string{
	"urnet_message_device_confirm_words":     "messageWordsFailed",
	"urnet_message_device_forget_group":      "messageForgetFailed",
	"urnet_message_group_set_role":           "messageCommitFailed",
	"urnet_message_group_transfer_ownership": "messageCommitFailed",
	"urnet_message_group_remove_member":      "messageCommitFailed",
	"urnet_message_group_ensure_subscribed":  "-1",
}

// countAnsweringExports is every export whose int32 result is a count, where a recovered panic's
// zero is "none", which is what a caller reads of a list it cannot see.
var countAnsweringExports = map[string]string{
	"urnet_message_group_list_count":    "how many groups a list handle holds",
	"urnet_message_list_count":          "how many messages a list handle holds",
	"urnet_message_list_reaction_count": "how many reactions one message carries",
	"urnet_message_member_list_count":   "how many members a list handle holds",
}

// presetFailureProblems answers what is wrong with one kind-answering export: a result that is not
// named, a first statement that does not preset it to the failure, or a second that does not defer
// cgoGuard.
func presetFailureProblems(fileSet *token.FileSet, function *ast.FuncDecl, failure string) []string {
	name := function.Name.Name
	results := function.Type.Results
	if results == nil || len(results.List) != 1 || len(results.List[0].Names) != 1 {
		return []string{fmt.Sprintf("%s answers an unnamed result: a panic cgoGuard recovers answers its zero value", name)}
	}
	result := results.List[0].Names[0].Name
	body := function.Body.List
	if len(body) < 2 {
		return []string{fmt.Sprintf("%s's body is too short to preset its result and defer cgoGuard", name)}
	}
	problems := []string{}
	preset, isAssign := body[0].(*ast.AssignStmt)
	if !isAssign || len(preset.Lhs) != 1 || len(preset.Rhs) != 1 || preset.Tok != token.ASSIGN ||
		expressionText(fileSet, preset.Lhs[0]) != result ||
		!strings.Contains(expressionText(fileSet, preset.Rhs[0]), failure) {
		problems = append(problems, fmt.Sprintf("%s's first statement does not set %s to %s", name, result, failure))
	}
	deferred, isDefer := body[1].(*ast.DeferStmt)
	if !isDefer || !strings.HasPrefix(expressionText(fileSet, deferred.Call), "cgoGuard(") {
		problems = append(problems, fmt.Sprintf("%s's second statement does not defer cgoGuard", name))
	}
	return problems
}

// EVERY KIND-ANSWERING EXPORT ANSWERS ITS FAILURE WHEN A PANIC IS RECOVERED INSIDE IT. Its result is
// named and preset to the failure before cgoGuard is deferred, so a recovered panic answers that and
// never a success. The int32 exports are held both ways: each is a kind, with its failure, or a count,
// with what it counts, and nothing else. sdk/cgo's own tests drive a real panic inside the two the
// tests can reach without a server (confirm_words and ensure_subscribed); this holds every one.
//
// THE CONTROL: the same reading over the shape before the fix, an unnamed result, is refused.
func TestEveryKindAnsweringExportPresetsItsFailure(t *testing.T) {
	fileSet, parsed := messageExportsSource(t)
	exported := exportedFunctions(parsed)
	int32s := []string{}
	for name, function := range exported {
		results := function.Type.Results
		if results != nil && len(results.List) == 1 && expressionText(fileSet, results.List[0].Type) == "C.int32_t" {
			int32s = append(int32s, name)
		}
	}
	sort.Strings(int32s)
	for _, name := range int32s {
		_, kind := kindAnsweringExports[name]
		_, count := countAnsweringExports[name]
		if !kind && !count {
			t.Errorf("%s answers an int32 and is neither a kind nor a count here: say which, and a kind's failure", name)
		}
	}
	for name, failure := range kindAnsweringExports {
		function, found := exported[name]
		if !found {
			t.Errorf("%s is named here and no export has that name", name)
			continue
		}
		for _, problem := range presetFailureProblems(fileSet, function, failure) {
			t.Error(problem)
		}
	}
	for name := range countAnsweringExports {
		if !slices.Contains(int32s, name) {
			t.Errorf("%s is named a count here and no int32 export has that name", name)
		}
	}
	t.Logf("%d int32 exports: %d kinds, each preset to its failure, and %d counts: %v",
		len(int32s), len(kindAnsweringExports), len(countAnsweringExports), int32s)

	// THE CONTROL: an unnamed result, the shape the finding was about, is refused
	controlSet, control := parseExportsSource(t, "control.go", []byte(`package main

//export urnet_message_device_confirm_words
func urnet_message_device_confirm_words() C.int32_t {
	defer cgoGuard("urnet_message_device_confirm_words")
	return C.int32_t(messageWordsFailed)
}
`))
	if problems := presetFailureProblems(controlSet, exportedFunctions(control)["urnet_message_device_confirm_words"],
		"messageWordsFailed"); len(problems) == 0 {
		t.Error("CONTROL FAILED: an export with an unnamed result passed the reading")
	}
}

// ── the words at the C boundary ──────────────────────────────────────────────────────────────

// wordsExports is every function of the exports that holds the recovery words, the shown or the
// typed, and the helper that writes the shown words out.
var wordsExports = []string{
	"urnet_message_device_create_identity",
	"urnet_message_device_confirm_words",
	"urnet_message_device_check_word",
	"copyWordsOut",
}

// wordsCopyProblems answers how one function could keep a copy of the words past the call: an
// assignment to anything that is not its own (a package variable, a field or an element of
// something it did not make), a goroutine, or a copy it took and did not clear. What it owns is its
// parameters, its named results and what it declared; writing through a pointer it was handed is the
// buffer-out pattern's answer, and stands.
func wordsCopyProblems(fileSet *token.FileSet, function *ast.FuncDecl) []string {
	name := function.Name.Name
	own := map[string]bool{}
	for _, fields := range []*ast.FieldList{function.Type.Params, function.Type.Results} {
		if fields == nil {
			continue
		}
		for _, field := range fields.List {
			for _, one := range field.Names {
				own[one.Name] = true
			}
		}
	}
	ast.Inspect(function.Body, func(node ast.Node) bool {
		switch shape := node.(type) {
		case *ast.AssignStmt:
			if shape.Tok == token.DEFINE {
				for _, left := range shape.Lhs {
					if ident, ok := left.(*ast.Ident); ok {
						own[ident.Name] = true
					}
				}
			}
		case *ast.ValueSpec:
			for _, one := range shape.Names {
				own[one.Name] = true
			}
		case *ast.RangeStmt:
			for _, one := range []ast.Expr{shape.Key, shape.Value} {
				if ident, ok := one.(*ast.Ident); ok {
					own[ident.Name] = true
				}
			}
		}
		return true
	})
	// the base a write lands in: the identifier under any selectors, indexes and slices
	var base func(expression ast.Expr) (string, bool)
	base = func(expression ast.Expr) (string, bool) {
		switch shape := expression.(type) {
		case *ast.Ident:
			return shape.Name, false
		case *ast.SelectorExpr:
			name, _ := base(shape.X)
			return name, true
		case *ast.IndexExpr:
			name, _ := base(shape.X)
			return name, false
		case *ast.SliceExpr:
			name, _ := base(shape.X)
			return name, false
		case *ast.StarExpr:
			name, _ := base(shape.X)
			return name, false
		case *ast.ParenExpr:
			return base(shape.X)
		}
		return "", true
	}
	problems := []string{}
	cleared := map[string]bool{}
	taken := map[string]string{}
	ast.Inspect(function.Body, func(node ast.Node) bool {
		switch shape := node.(type) {
		case *ast.AssignStmt:
			for _, left := range shape.Lhs {
				written, field := base(left)
				if written == "_" {
					continue
				}
				if field || !own[written] {
					problems = append(problems, fmt.Sprintf("%s writes %s, which is not its own: a copy of the words could outlive the call there",
						name, expressionText(fileSet, left)))
				}
			}
			// the copies a call takes: the typed octets, and the shown words
			if len(shape.Rhs) == 1 {
				if call, ok := shape.Rhs[0].(*ast.CallExpr); ok {
					callee := expressionText(fileSet, call.Fun)
					if callee == "goBytes" || strings.HasSuffix(callee, ".CreateIdentity") {
						if ident, ok := shape.Lhs[0].(*ast.Ident); ok {
							taken[ident.Name] = callee
						}
					}
				}
			}
		case *ast.IncDecStmt:
			if written, field := base(shape.X); field || !own[written] {
				problems = append(problems, fmt.Sprintf("%s writes %s, which is not its own", name, expressionText(fileSet, shape.X)))
			}
		case *ast.GoStmt:
			problems = append(problems, fmt.Sprintf("%s starts a goroutine, which could hold the words past the call", name))
		case *ast.DeferStmt:
			if expressionText(fileSet, shape.Call.Fun) == "clear" && len(shape.Call.Args) == 1 {
				cleared[expressionText(fileSet, shape.Call.Args[0])] = true
			}
		}
		return true
	})
	for copyName, callee := range taken {
		if !cleared[copyName] {
			problems = append(problems, fmt.Sprintf("%s takes %s from %s and does not defer its clear", name, copyName, callee))
		}
	}
	sort.Strings(problems)
	return problems
}

// THE EXPORTS THAT CARRY THE WORDS KEEP NO COPY PAST THE CALL (LRI R84 item 10; review G-2). No
// census of sdk/urmessage or messagegroup reads this package, so this holds the C boundary's half:
// create_identity, confirm_words and check_word, and the helper that writes the shown words out,
// write nothing that is not their own, start no goroutine, and clear every copy of the words they
// take. What stays is the residual Spec A section 8.4a states: confirm_words and check_word read the
// typed octets as a Go string, which is not erased.
//
// THE CONTROL: a package variable that keeps the typed octets -- the review's mutant G2 -- and a
// clear left out are each refused, and the real exports pass.
func TestTheWordsExportsKeepNoCopyPastTheCall(t *testing.T) {
	fileSet, parsed := messageExportsSource(t)
	functions := map[string]*ast.FuncDecl{}
	for _, declaration := range parsed.Decls {
		if function, ok := declaration.(*ast.FuncDecl); ok && function.Recv == nil {
			functions[function.Name.Name] = function
		}
	}
	for _, name := range wordsExports {
		function, found := functions[name]
		if !found {
			t.Errorf("%s is named here and the exports declare no such function", name)
			continue
		}
		for _, problem := range wordsCopyProblems(fileSet, function) {
			t.Error(problem)
		}
	}

	// THE CONTROLS
	controlSet, control := parseExportsSource(t, "control.go", []byte(`package main

var messageLastTyped []byte

func keepsTheTyped(typed *C.uint8_t, typedLen C.int32_t) {
	octets := goBytes(typed, typedLen)
	defer clear(octets)
	messageLastTyped = append(messageLastTyped[:0], octets...)
}

func clearsNothing(typed *C.uint8_t, typedLen C.int32_t) bool {
	octets := goBytes(typed, typedLen)
	return len(octets) != 0
}
`))
	for _, declaration := range control.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if problems := wordsCopyProblems(controlSet, function); len(problems) == 0 {
			t.Errorf("CONTROL FAILED: %s passed the reading", function.Name.Name)
		}
	}
}
