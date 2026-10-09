package mls

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// Every scan this package's gates make, and the scope each one is handed.
//
// In connect the codec sat beneath this package as mls/syntax, so a recursive scan of "." read it
// whatever list a gate passed. As a peer it is read only when a scan is handed urmessageScanRoots(),
// so the scope became an ARGUMENT at every call site, and an argument is one edit away from
// forbiddenScanRoots: that still type-checks, still runs, and still passes every gate whose banned
// shape the codec happens not to hold -- which, measured with testdata/forbidden/violations.go
// planted in the codec, is ten of the sixteen. So this holds the argument rather than the outcome:
// every call of the two scan helpers is handed the whole scope, the control fixture, or a narrower
// root this map declares with its reason. A call the map does not name fails, and so does a row
// nothing uses.
var scanScopeDispositions = map[string]string{
	`crypto_forbidden_test.go:mustScanSources:roots`:                    "the helper itself, which every gate calls",
	`crypto_forbidden_test.go:TestScanRefusesARootItCannotCover:roots`:  "the refusal table: every row is a bad root on purpose",
	`framing_group_seams_test.go:theContentTypeConstants:[]string{"."}`: "mls's own ContentType constants; the codec declares none and cannot",
}

const (
	scanScopeWhole   = "urmessageScanRoots()"
	scanScopeControl = "[]string{forbiddenControlRoot}"
)

type scanScopeCall struct{ file, decl, argument string }

func (self scanScopeCall) key() string { return self.file + ":" + self.decl + ":" + self.argument }

// The scope argument of every call of mustScanSources or scanSources in the given files, keyed by
// the top-level declaration it sits in, so a line number moving does not move the key.
func scanScopeCalls(t *testing.T, fileSet *token.FileSet, files map[string]*ast.File) []scanScopeCall {
	t.Helper()
	calls := []scanScopeCall{}
	for _, name := range slices.Sorted(maps.Keys(files)) {
		for _, decl := range files[name].Decls {
			owner := ""
			switch typed := decl.(type) {
			case *ast.FuncDecl:
				owner = typed.Name.Name
			case *ast.GenDecl:
				names := []string{}
				for _, spec := range typed.Specs {
					if value, ok := spec.(*ast.ValueSpec); ok {
						for _, ident := range value.Names {
							names = append(names, ident.Name)
						}
					}
				}
				owner = strings.Join(names, ",")
			}
			ast.Inspect(decl, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				ident, ok := call.Fun.(*ast.Ident)
				if !ok {
					return true
				}
				index := -1
				switch ident.Name {
				case "mustScanSources":
					index = 1
				case "scanSources":
					index = 0
				}
				if index < 0 || len(call.Args) <= index {
					return true
				}
				var text bytes.Buffer
				if err := printer.Fprint(&text, fileSet, call.Args[index]); err != nil {
					t.Fatalf("print the scope argument of a scan in %s: %v", name, err)
				}
				calls = append(calls, scanScopeCall{file: name, decl: owner, argument: text.String()})
				return true
			})
		}
	}
	return calls
}

// What the calls owe: undeclared narrow scopes, and rows of the map nothing used.
func scanScopeVerdict(calls []scanScopeCall, dispositions map[string]string) (whole int, control int, undeclared []string, unused []string) {
	used := map[string]bool{}
	for _, call := range calls {
		switch {
		case call.argument == scanScopeWhole:
			whole++
		case call.argument == scanScopeControl:
			control++
		case dispositions[call.key()] != "":
			used[call.key()] = true
		default:
			undeclared = append(undeclared, call.key())
		}
	}
	for key := range dispositions {
		if !used[key] {
			unused = append(unused, key)
		}
	}
	slices.Sort(undeclared)
	slices.Sort(unused)
	return whole, control, undeclared, unused
}

func TestEveryScanOfThisPackageIsHandedTheWholeScope(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	fileSet := token.NewFileSet()
	files := map[string]*ast.File{}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".go" {
			continue
		}
		parsed, err := parser.ParseFile(fileSet, entry.Name(), nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", entry.Name(), err)
		}
		files[entry.Name()] = parsed
	}
	calls := scanScopeCalls(t, fileSet, files)
	whole, control, undeclared, unused := scanScopeVerdict(calls, scanScopeDispositions)
	t.Logf("%d scan calls in %d files: %d handed %s, %d handed %s, %d declared narrower",
		len(calls), len(files), whole, scanScopeWhole, control, scanScopeControl, len(calls)-whole-control-len(undeclared))
	if whole == 0 {
		t.Fatalf("no call is handed %s, so this read no gate at all", scanScopeWhole)
	}
	for _, key := range undeclared {
		t.Errorf("%s: a scan handed less than %s and not declared narrower with a reason; the codec is read only through that argument", key, scanScopeWhole)
	}
	for _, key := range unused {
		t.Errorf("%s: declared narrower and no call uses the declaration", key)
	}
}

// The control: the edit this exists for, written down, has to be reported; the whole scope and the
// control fixture have to pass; and a row nothing uses has to be reported.
func TestTheScanScopeGateReportsANarrowedCall(t *testing.T) {
	const fixture = `package mls

import "testing"

func TestWide(t *testing.T) { _ = mustScanSources(t, urmessageScanRoots()) }
func TestControl(t *testing.T) { _ = mustScanSources(t, []string{forbiddenControlRoot}) }
func TestNarrowed(t *testing.T) { _ = mustScanSources(t, forbiddenScanRoots) }
`
	fileSet := token.NewFileSet()
	parsed, err := parser.ParseFile(fileSet, "fixture_test.go", fixture, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	calls := scanScopeCalls(t, fileSet, map[string]*ast.File{"fixture_test.go": parsed})
	whole, control, undeclared, unused := scanScopeVerdict(calls, map[string]string{"fixture_test.go:TestGone:x": "a row nothing uses"})
	if whole != 1 || control != 1 {
		t.Errorf("the fixture's whole and control calls counted %d and %d, want 1 and 1", whole, control)
	}
	if want := []string{"fixture_test.go:TestNarrowed:forbiddenScanRoots"}; !slices.Equal(undeclared, want) {
		t.Errorf("the narrowed call was reported as %v, want %v", undeclared, want)
	}
	if want := []string{"fixture_test.go:TestGone:x"}; !slices.Equal(unused, want) {
		t.Errorf("the unused row was reported as %v, want %v", unused, want)
	}
}
