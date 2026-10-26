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
// when a panic is recovered inside it (LRI R84 item 3, R89 item 6; review X-LIB-1, X-D2-2, X2-4), and
// what the exports that carry the recovery words do with them (LRI R84 item 10, R89 item 5; review
// G-2, X-D2-1, X2-1, G-D3).

// messageExportFiles parses every hand-written .go file of sdk/cgo that is in a shipped build, as gen
// reads them for the .def (messagingExports): not a test, not a file a compose laid here from the core,
// and not a file no shipped build compiles. It answers them by name.
func messageExportFiles(t *testing.T) (*token.FileSet, map[string]*ast.File) {
	t.Helper()
	dir := filepath.Dir(testingGenDir(t))
	composed := map[string]bool{}
	if record, err := os.ReadFile(filepath.Join(dir, ".composed")); err == nil {
		for _, line := range strings.Split(strings.ReplaceAll(string(record), "\r\n", "\n"), "\n") {
			if line != "" && !strings.HasPrefix(line, "#") {
				composed[line] = true
			}
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	fileSet := token.NewFileSet()
	files := map[string]*ast.File{}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") || composed[name] {
			continue
		}
		source, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if !inAnyShippedBuild(string(source)) {
			continue
		}
		parsed, err := parser.ParseFile(fileSet, name, source, parser.ParseComments)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		files[name] = parsed
	}
	// THE CONTROL ON THE CONTROL: the file the gates are about is among them
	if files["exports_message.go"] == nil {
		t.Fatalf("the hand-written export files read are %v, and exports_message.go is not among them", sortedFileNames(files))
	}
	return fileSet, files
}

func sortedFileNames(files map[string]*ast.File) []string {
	names := []string{}
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
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

// exportedFunctions is every function of the files that carries an //export line, by name.
func exportedFunctions(files ...*ast.File) map[string]*ast.FuncDecl {
	exported := map[string]*ast.FuncDecl{}
	for _, parsed := range files {
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
// and a leave, "the subscription is current" for ensure_subscribed, and NONE for the identity's state.
var kindAnsweringExports = map[string]string{
	"urnet_message_device_confirm_words":     "messageWordsFailed",
	"urnet_message_device_forget_group":      "messageForgetUnknown",
	"urnet_message_device_identity_state":    "messageIdentityFailed",
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
// named, a first statement that does not preset it to the failure, a second that does not defer
// cgoGuard, or ANY OTHER WRITE OF THE RESULT anywhere in its body (R89 item 6; review X-D2-2's
// KIND-LATE-OK): a success set before a later panic would be what a recovered panic answers. Its
// answers are its return statements, which a recovered panic never reaches.
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
	writes := func(expression ast.Expr) bool {
		for {
			switch shape := expression.(type) {
			case *ast.ParenExpr:
				expression = shape.X
				continue
			case *ast.StarExpr:
				expression = shape.X
				continue
			case *ast.Ident:
				return shape.Name == result
			}
			return false
		}
	}
	ast.Inspect(function.Body, func(node ast.Node) bool {
		switch shape := node.(type) {
		case *ast.AssignStmt:
			if shape == preset {
				return true
			}
			for _, left := range shape.Lhs {
				if writes(left) {
					problems = append(problems, fmt.Sprintf("%s writes its result %s at %s, after the preset: a panic after that answers what was written",
						name, result, fileSet.Position(shape.Pos())))
				}
			}
		case *ast.IncDecStmt:
			if writes(shape.X) {
				problems = append(problems, fmt.Sprintf("%s writes its result %s at %s, after the preset", name, result, fileSet.Position(shape.Pos())))
			}
		case *ast.UnaryExpr:
			if shape.Op == token.AND && writes(shape.X) {
				problems = append(problems, fmt.Sprintf("%s hands out its result's address at %s", name, fileSet.Position(shape.Pos())))
			}
		}
		return true
	})
	return problems
}

// kindGateProblems answers the kind gate over a set of files: every int32 export is a kind or a count
// named above, every kind is preset to its failure and written nowhere else, and every name above is
// an export. It also answers the int32 exports it found.
func kindGateProblems(fileSet *token.FileSet, files []*ast.File) ([]string, []string) {
	exported := exportedFunctions(files...)
	int32s := []string{}
	for name, function := range exported {
		results := function.Type.Results
		if results != nil && len(results.List) == 1 && expressionText(fileSet, results.List[0].Type) == "C.int32_t" {
			int32s = append(int32s, name)
		}
	}
	sort.Strings(int32s)
	problems := []string{}
	for _, name := range int32s {
		_, kind := kindAnsweringExports[name]
		_, count := countAnsweringExports[name]
		if !kind && !count {
			problems = append(problems, fmt.Sprintf("%s answers an int32 and is neither a kind nor a count here: say which, and a kind's failure", name))
		}
	}
	for name, failure := range kindAnsweringExports {
		function, found := exported[name]
		if !found {
			problems = append(problems, fmt.Sprintf("%s is named here and no export has that name", name))
			continue
		}
		problems = append(problems, presetFailureProblems(fileSet, function, failure)...)
	}
	for name := range countAnsweringExports {
		if !slices.Contains(int32s, name) {
			problems = append(problems, fmt.Sprintf("%s is named a count here and no int32 export has that name", name))
		}
	}
	sort.Strings(problems)
	return problems, int32s
}

// EVERY KIND-ANSWERING EXPORT ANSWERS ITS FAILURE WHEN A PANIC IS RECOVERED INSIDE IT. Its result is
// named and preset to the failure before cgoGuard is deferred, and written nowhere else, so a
// recovered panic answers that and never a success. The int32 exports of EVERY hand-written export
// file are held both ways: each is a kind, with its failure, or a count, with what it counts, and
// nothing else. sdk/cgo's own tests drive a real panic inside the ones they can reach without a server
// (confirm_words, ensure_subscribed, forget_group and identity_state); this holds every one.
//
// THE CONTROLS, each refused for its own reason: an unnamed result, the shape the first finding was
// about; KIND-LATE-OK, a success written after the preset (review X-D2-2); and KIND-NEW-FILE, a kind
// export in a file of its own that nothing classifies (review X2-4).
func TestEveryKindAnsweringExportPresetsItsFailure(t *testing.T) {
	fileSet, files := messageExportFiles(t)
	all := []*ast.File{}
	for _, name := range sortedFileNames(files) {
		all = append(all, files[name])
	}
	problems, int32s := kindGateProblems(fileSet, all)
	for _, problem := range problems {
		t.Error(problem)
	}
	t.Logf("files read: %v; %d int32 exports: %d kinds, each preset to its failure and written nowhere else, and %d counts: %v",
		sortedFileNames(files), len(int32s), len(kindAnsweringExports), len(countAnsweringExports), int32s)

	controls := []struct {
		name   string
		source string
		want   string
	}{
		{"UNNAMED", `package main

//export urnet_message_device_confirm_words
func urnet_message_device_confirm_words() C.int32_t {
	defer cgoGuard("urnet_message_device_confirm_words")
	return C.int32_t(messageWordsFailed)
}
`, "answers an unnamed result"},
		{"KIND-LATE-OK", `package main

//export urnet_message_group_set_role
func urnet_message_group_set_role(self C.uint64_t) (kind C.int32_t) {
	kind = C.int32_t(messageCommitFailed)
	defer cgoGuard("urnet_message_group_set_role")
	kind = C.int32_t(messageCommitOk)
	work()
	return kind
}
`, "writes its result kind"},
		{"KIND-NEW-FILE", `package main

//export urnet_message_device_new_kind
func urnet_message_device_new_kind(self C.uint64_t) C.int32_t {
	defer cgoGuard("urnet_message_device_new_kind")
	return 0
}
`, "urnet_message_device_new_kind answers an int32 and is neither a kind nor a count"},
	}
	for _, control := range controls {
		controlSet, parsed := parseExportsSource(t, "control_"+control.name+".go", []byte(control.source))
		var found []string
		if control.name == "KIND-NEW-FILE" {
			// the control file stands beside the real ones, in a set read as one
			found, _ = kindGateProblems(controlSet, []*ast.File{parsed})
		} else {
			exported := exportedFunctions(parsed)
			for name, function := range exported {
				found = append(found, presetFailureProblems(controlSet, function, kindAnsweringExports[name])...)
			}
		}
		fired := false
		for _, problem := range found {
			if strings.Contains(problem, control.want) {
				fired = true
			}
		}
		if !fired {
			t.Errorf("CONTROL FAILED: %s was not refused for its reason (%q): %v", control.name, control.want, found)
		}
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

// wordsConsumers are the calls the words may be handed to, which keep nothing of them past the call
// and answer no copy of them: their results carry no word.
var wordsConsumers = map[string]bool{
	"clear": true, "len": true, "cap": true, "copyWordsOut": true, "messagegroup.CheckRecoveryPhraseWord": true,
}

// wordsSources are the calls whose results are the words themselves, a copy this function owns and must
// clear: the typed octets, and the shown words.
func wordsSource(callee string) bool {
	return callee == "goBytes" || strings.HasSuffix(callee, ".CreateIdentity")
}

// wordsCopyProblems answers how one function could keep or leak the words past the call (R89 item 5;
// review X-D2-1, X2-1, G-D3). It follows the words -- what a source call answers, a parameter named
// words, and every value made from them -- and judges every WRITE and every CALL that takes them, not
// statement kinds:
//   - an assignment that carries the words may land only in a variable this function declared, which
//     then carries them too: never a package variable, a field, an element of something it did not
//     make, or anything through a pointer it was handed -- out_error among those;
//   - copy() may copy them only into a variable this function declared, the buffer-out pattern's
//     buffer among those, which then carries them;
//   - a call that takes them must be a consumer (clear, len, cap, copyWordsOut, ConfirmWords,
//     CheckRecoveryPhraseWord, the string conversion directly inside ConfirmWords or
//     CheckRecoveryPhraseWord), or a source's own clear; any other call -- a helper, a method, fmt --
//     is refused, since what it does with them is out of this reading;
//   - no channel send and no goroutine, whatever they carry;
//   - every copy taken from a source is cleared by a deferred clear.
//
// Writing a value that carries no word -- a length, a position -- through a pointer it was handed is
// the buffer-out pattern's answer, and stands.
func wordsCopyProblems(fileSet *token.FileSet, function *ast.FuncDecl) []string {
	name := function.Name.Name
	declared := map[string]bool{}
	tainted := map[string]bool{}
	if function.Type.Params != nil {
		for _, field := range function.Type.Params.List {
			for _, one := range field.Names {
				if one.Name == "words" {
					tainted[one.Name] = true
				}
			}
		}
	}
	// its named results are its own, as what it declared is
	if function.Type.Results != nil {
		for _, field := range function.Type.Results.List {
			for _, one := range field.Names {
				declared[one.Name] = true
			}
		}
	}
	ast.Inspect(function.Body, func(node ast.Node) bool {
		switch shape := node.(type) {
		case *ast.AssignStmt:
			if shape.Tok == token.DEFINE {
				for _, left := range shape.Lhs {
					if ident, ok := left.(*ast.Ident); ok {
						declared[ident.Name] = true
					}
				}
			}
		case *ast.ValueSpec:
			for _, one := range shape.Names {
				declared[one.Name] = true
			}
		case *ast.RangeStmt:
			for _, one := range []ast.Expr{shape.Key, shape.Value} {
				if ident, ok := one.(*ast.Ident); ok {
					declared[ident.Name] = true
				}
			}
		}
		return true
	})
	// the identifier a write lands in, under any selectors, indexes, slices and dereferences, and
	// whether it lands in a variable this function declared
	var base func(expression ast.Expr) (string, bool)
	base = func(expression ast.Expr) (string, bool) {
		switch shape := expression.(type) {
		case *ast.Ident:
			return shape.Name, declared[shape.Name]
		case *ast.SelectorExpr:
			name, _ := base(shape.X)
			return name, false
		case *ast.IndexExpr:
			return base(shape.X)
		case *ast.SliceExpr:
			return base(shape.X)
		case *ast.StarExpr:
			name, _ := base(shape.X)
			return name, false
		case *ast.ParenExpr:
			return base(shape.X)
		}
		return "", false
	}
	calleeOf := func(call *ast.CallExpr) string {
		return expressionText(fileSet, call.Fun)
	}
	isConsumer := func(callee string) bool {
		return wordsConsumers[callee] || strings.HasSuffix(callee, ".ConfirmWords")
	}
	// carries answers whether an expression carries the words: it names a tainted variable outside the
	// arguments of a consumer, whose answer is no copy of them
	var carries func(expression ast.Node) bool
	carries = func(expression ast.Node) bool {
		found := false
		ast.Inspect(expression, func(node ast.Node) bool {
			if found {
				return false
			}
			switch shape := node.(type) {
			case *ast.CallExpr:
				// a consumer's answer, and copy's count, are no copy of the words
				if isConsumer(calleeOf(shape)) || calleeOf(shape) == "copy" {
					return false
				}
				if wordsSource(calleeOf(shape)) {
					found = true
					return false
				}
			case *ast.FuncLit:
				return false
			case *ast.Ident:
				if tainted[shape.Name] {
					found = true
				}
			}
			return true
		})
		return found
	}
	problems := []string{}
	cleared := map[string]bool{}
	taken := map[string]string{}
	// the taint is carried to a fixpoint before the rules are read, so an order of statements cannot
	// hide a write behind a later definition
	for grown := true; grown; {
		grown = false
		ast.Inspect(function.Body, func(node ast.Node) bool {
			switch shape := node.(type) {
			case *ast.AssignStmt:
				for at, left := range shape.Lhs {
					right := shape.Rhs[0]
					if len(shape.Rhs) == len(shape.Lhs) {
						right = shape.Rhs[at]
					} else if at > 0 {
						// a tuple: the words are a call's first answer, and its error is not them
						continue
					}
					if written, own := base(left); own && written != "_" && !tainted[written] && carries(right) {
						tainted[written] = true
						grown = true
					}
				}
			case *ast.RangeStmt:
				if carries(shape.X) {
					if ident, ok := shape.Value.(*ast.Ident); ok && ident.Name != "_" && !tainted[ident.Name] {
						tainted[ident.Name] = true
						grown = true
					}
				}
			case *ast.CallExpr:
				if calleeOf(shape) == "copy" && len(shape.Args) == 2 && carries(shape.Args[1]) {
					if written, own := base(shape.Args[0]); own && !tainted[written] {
						tainted[written] = true
						grown = true
					}
				}
			}
			return true
		})
	}
	var walk func(node ast.Node, parent ast.Node)
	walk = func(node ast.Node, parent ast.Node) {
		if node == nil {
			return
		}
		switch shape := node.(type) {
		case *ast.AssignStmt:
			for at, left := range shape.Lhs {
				right := shape.Rhs[0]
				if len(shape.Rhs) == len(shape.Lhs) {
					right = shape.Rhs[at]
				} else if at > 0 {
					right = &ast.BasicLit{}
				}
				written, own := base(left)
				if written == "_" {
					continue
				}
				if carries(right) && !own {
					problems = append(problems, fmt.Sprintf("%s writes the words into %s, which is not a variable it declared: a copy could outlive the call there",
						name, expressionText(fileSet, left)))
				}
				if !own && !strings.HasPrefix(expressionText(fileSet, left), "*") {
					problems = append(problems, fmt.Sprintf("%s writes %s, which is not its own", name, expressionText(fileSet, left)))
				}
			}
			if len(shape.Rhs) == 1 && len(shape.Lhs) >= 1 {
				if call, ok := shape.Rhs[0].(*ast.CallExpr); ok && wordsSource(calleeOf(call)) {
					if ident, ok := shape.Lhs[0].(*ast.Ident); ok {
						taken[ident.Name] = calleeOf(call)
					}
				}
			}
		case *ast.IncDecStmt:
			if _, own := base(shape.X); !own {
				problems = append(problems, fmt.Sprintf("%s writes %s, which is not its own", name, expressionText(fileSet, shape.X)))
			}
		case *ast.SendStmt:
			problems = append(problems, fmt.Sprintf("%s sends on a channel at %s: a receiver could keep what it sends past the call", name, fileSet.Position(shape.Pos())))
		case *ast.GoStmt:
			problems = append(problems, fmt.Sprintf("%s starts a goroutine, which could hold the words past the call", name))
		case *ast.DeferStmt:
			if calleeOf(shape.Call) == "clear" && len(shape.Call.Args) == 1 {
				cleared[expressionText(fileSet, shape.Call.Args[0])] = true
			}
		case *ast.CallExpr:
			callee := calleeOf(shape)
			takesWords := false
			for _, argument := range shape.Args {
				if carries(argument) {
					takesWords = true
				}
			}
			switch {
			case !takesWords:
			case callee == "copy":
				if written, own := base(shape.Args[0]); !own {
					problems = append(problems, fmt.Sprintf("%s copies the words into %s, which is not a variable it declared", name, written))
				}
			case callee == "string":
				parentCall, ok := parent.(*ast.CallExpr)
				if !ok || !(strings.HasSuffix(calleeOf(parentCall), ".ConfirmWords") || calleeOf(parentCall) == "messagegroup.CheckRecoveryPhraseWord") {
					problems = append(problems, fmt.Sprintf("%s makes a string of the words at %s other than as the argument of ConfirmWords or CheckRecoveryPhraseWord", name, fileSet.Position(shape.Pos())))
				}
			case isConsumer(callee):
			default:
				problems = append(problems, fmt.Sprintf("%s hands the words to %s, which is not a consumer of them: what it keeps is out of this reading", name, callee))
			}
		}
		ast.Inspect(node, func(child ast.Node) bool {
			if child == node {
				return true
			}
			if child != nil {
				walk(child, node)
			}
			return false
		})
	}
	walk(function.Body, nil)
	for copyName, callee := range taken {
		if !cleared[copyName] {
			problems = append(problems, fmt.Sprintf("%s takes %s from %s and does not defer its clear", name, copyName, callee))
		}
	}
	sort.Strings(problems)
	return slices.Compact(problems)
}

// THE EXPORTS THAT CARRY THE WORDS KEEP AND LEAK NO COPY OF THEM (LRI R84 item 10, R89 item 5; review
// G-2, X-D2-1, X2-1, G-D3). No census of sdk/urmessage or messagegroup reads this package, so this
// holds the C boundary's half: create_identity, confirm_words and check_word, and the helper that
// writes the shown words out, keep no copy past the call and hand the words only to their consumers --
// never to a helper, a channel, a package variable or out_error -- and clear every copy they take. What
// stays is the residual Spec A section 8.4a states: confirm_words and check_word read the typed octets
// as a Go string, which is not erased.
//
// THE CONTROLS, each refused for its own reason: the review's G2 (a package slice keeps the typed
// octets); COPY-TYPED and COPY-SHOWN (copy() into a package array of the typed and the shown words);
// SEND-TYPED (a channel send); HELPER-TYPED (a helper that keeps them); OUT-ERROR (the typed text
// wrapped into the error out_error carries, and written through out_error); and a clear left out. The
// real exports pass.
func TestTheWordsExportsKeepNoCopyPastTheCall(t *testing.T) {
	fileSet, files := messageExportFiles(t)
	functions := map[string]*ast.FuncDecl{}
	for _, parsed := range files {
		for _, declaration := range parsed.Decls {
			if function, ok := declaration.(*ast.FuncDecl); ok && function.Recv == nil {
				functions[function.Name.Name] = function
			}
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

	controls := map[string]string{
		"G2": `func g2(typed *C.uint8_t, typedLen C.int32_t) {
	octets := goBytes(typed, typedLen)
	defer clear(octets)
	messageLastTyped = append(messageLastTyped[:0], octets...)
}`,
		"COPY-TYPED": `func copyTyped(typed *C.uint8_t, typedLen C.int32_t) {
	octets := goBytes(typed, typedLen)
	defer clear(octets)
	copy(messageTypedKept[:], octets)
}`,
		"COPY-SHOWN": `func copyShown(self_ *urmessage.Device) {
	words, err := self_.CreateIdentity()
	if err != nil {
		return
	}
	defer clear(words)
	copy(messageShownKept[:], words)
}`,
		"SEND-TYPED": `func sendTyped(typed *C.uint8_t, typedLen C.int32_t) {
	octets := goBytes(typed, typedLen)
	defer clear(octets)
	select {
	case messageTypedQueue <- len(octets):
	default:
	}
}`,
		"HELPER-TYPED": `func helperTyped(typed *C.uint8_t, typedLen C.int32_t) {
	octets := goBytes(typed, typedLen)
	defer clear(octets)
	rememberTyped(octets)
}`,
		"OUT-ERROR": `func outError(ctx_ context.Context, self_ *urmessage.Device, typed *C.uint8_t, typedLen C.int32_t, outError **C.char) {
	octets := goBytes(typed, typedLen)
	defer clear(octets)
	err := self_.ConfirmWords(ctx_, string(octets))
	if err != nil {
		err = fmt.Errorf("%w: typed %s", err, octets)
		*outError = C.CString(string(octets))
	}
}`,
		"NO-CLEAR": `func noClear(typed *C.uint8_t, typedLen C.int32_t) bool {
	octets := goBytes(typed, typedLen)
	return len(octets) != 0
}`,
	}
	reasons := map[string]string{
		"G2": "writes the words into messageLastTyped", "COPY-TYPED": "copies the words into messageTypedKept",
		"COPY-SHOWN": "copies the words into messageShownKept", "SEND-TYPED": "sends on a channel",
		"HELPER-TYPED": "hands the words to rememberTyped", "OUT-ERROR": "hands the words to fmt.Errorf",
		"NO-CLEAR": "does not defer its clear",
	}
	for control, source := range controls {
		controlSet, parsed := parseExportsSource(t, "control_"+control+".go", []byte("package main\n\n"+source+"\n"))
		fired := false
		found := []string{}
		for _, declaration := range parsed.Decls {
			if function, ok := declaration.(*ast.FuncDecl); ok {
				found = append(found, wordsCopyProblems(controlSet, function)...)
			}
		}
		for _, problem := range found {
			if strings.Contains(problem, reasons[control]) {
				fired = true
			}
		}
		if !fired {
			t.Errorf("CONTROL FAILED: %s was not refused for its reason (%q): %v", control, reasons[control], found)
		}
	}
	// OUT-ERROR's second write, through out_error itself, is refused on its own too
	controlSet, parsed := parseExportsSource(t, "control_OUT-ERROR-WRITE.go", []byte(`package main

func outErrorWrite(typed *C.uint8_t, typedLen C.int32_t, outError **C.char) {
	octets := goBytes(typed, typedLen)
	defer clear(octets)
	text := string(octets)
	*outError = C.CString(text)
}
`))
	fired := false
	for _, declaration := range parsed.Decls {
		if function, ok := declaration.(*ast.FuncDecl); ok {
			for _, problem := range wordsCopyProblems(controlSet, function) {
				if strings.Contains(problem, "writes the words into *outError") {
					fired = true
				}
			}
		}
	}
	if !fired {
		t.Error("CONTROL FAILED: the words written through out_error were not refused for that reason")
	}
}
