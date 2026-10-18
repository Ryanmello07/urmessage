package sdk

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/urnetwork/message/messagegroup"
)

// THE TEST SEAM'S STRETCH IS NAMED BY NO PRODUCTION SOURCE OF THIS MODULE (LRI R76 item 10).
//
// messagegroup.FastPhraseStretchForTests is the one way to the test seam's Argon2id parameters from
// outside messagegroup. Tests use it so that a suite's hundreds of identities do not cost 256 MiB
// and the better part of a second each. A device that runs it in production would make an identity
// whose keys anyone could search for with a laptop. messagegroup's
// TestProductionStretchesWithTheFrozenParametersOnly holds that package, and this holds the module
// that uses the door. It reads every .go file of this module, every directory, build constraints
// ignored, the loopback harness a build overlay compiles included. It refuses any production file
// whose code -- not its comments -- names the door, under any qualifier. Test files may, and are
// printed: the complement.
//
// THE NEEDLE IS THE FUNCTION'S OWN NAME, read off the function this file links against. A rename
// moves the needle with it, rather than leaving this gate searching for a name nothing has.

// sdkStretchScan is what one walk read.
type sdkStretchScan struct {
	// namers is every production file whose code names the door.
	namers []string
	// production is the number of production files read.
	production int
	// testNamers is the complement of the production narrowing: the test files that name it.
	testNamers []string
	// overlaid is the production files read under a directory named testdata that a build overlay
	// compiles.
	overlaid []string
}

// sdkTestStretchName is the name the door is declared under, off the linked function.
func sdkTestStretchName(t *testing.T) string {
	t.Helper()
	function := runtime.FuncForPC(reflect.ValueOf(messagegroup.FastPhraseStretchForTests).Pointer())
	if function == nil {
		t.Fatal("the door's function is not one the runtime can name")
	}
	full := function.Name()
	name := full[strings.LastIndex(full, ".")+1:]
	if !strings.HasPrefix(full, "github.com/urnetwork/message/messagegroup.") || name == "" {
		t.Fatalf("the door is %q, which is not messagegroup's", full)
	}
	return name
}

// sdkStretchNamesIn reads every .go file of fsys and answers which production files' code names
// needle: an identifier spelled so, alone or after a qualifier.
func sdkStretchNamesIn(t *testing.T, fsys fs.FS, overlaid []string, needle string) sdkStretchScan {
	t.Helper()
	scan := sdkStretchScan{}
	fileSet := token.NewFileSet()
	err := fs.WalkDir(fsys, ".", func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			base := entry.Name()
			if base == "testdata" && slices.Contains(overlaid, name) {
				return nil
			}
			if name != "." && (base == "testdata" || base == "vendor" || strings.HasPrefix(base, ".")) {
				return fs.SkipDir
			}
			return nil
		}
		if path.Ext(name) != ".go" {
			return nil
		}
		source, readErr := fs.ReadFile(fsys, name)
		if readErr != nil {
			return readErr
		}
		file, parseErr := parser.ParseFile(fileSet, name, source, 0)
		if parseErr != nil {
			return fmt.Errorf("parsing %s: %w", name, parseErr)
		}
		names := false
		ast.Inspect(file, func(node ast.Node) bool {
			if identifier, isName := node.(*ast.Ident); isName && identifier.Name == needle {
				names = true
			}
			return !names
		})
		if strings.HasSuffix(name, "_test.go") {
			if names {
				scan.testNamers = append(scan.testNamers, name)
			}
			return nil
		}
		scan.production += 1
		if slices.Contains(overlaid, path.Dir(name)) {
			scan.overlaid = append(scan.overlaid, name)
		}
		if names {
			scan.namers = append(scan.namers, name)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking for the test stretch: %v", err)
	}
	slices.Sort(scan.namers)
	slices.Sort(scan.testNamers)
	slices.Sort(scan.overlaid)
	return scan
}

func TestNoProductionSourceOfTheSdkNamesTheTestStretch(t *testing.T) {
	needle := sdkTestStretchName(t)

	// ── THE CONTROLS, FIRST, ON A FIXTURE TREE, EACH FIRING FOR ITS OWN REASON ───────────────────
	fixture := fstest.MapFS{
		"qualified.go":                  {Data: []byte("package p\n\nimport mg \"github.com/urnetwork/message/messagegroup\"\n\nvar s = mg." + needle + "()\n")},
		"dotted.go":                     {Data: []byte("//go:build windows\n\npackage p\n\nimport . \"github.com/urnetwork/message/messagegroup\"\n\nvar s = " + needle + "()\n")},
		"comment.go":                    {Data: []byte("package p\n\n// " + needle + " is named in a comment and nowhere else\nvar s = 1\n")},
		"zero.go":                       {Data: []byte("package p\n\nimport \"github.com/urnetwork/message/messagegroup\"\n\nvar s messagegroup.PhraseStretch\n")},
		"uses_test.go":                  {Data: []byte("package p\n\nimport \"github.com/urnetwork/message/messagegroup\"\n\nvar s = messagegroup." + needle + "()\n")},
		"testdata/planted.go":           {Data: []byte("package p\n\nvar s = x." + needle + "()\n")},
		"cgo/ctest/testdata/harness.go": {Data: []byte("package p\n\nvar s = x." + needle + "()\n")},
	}
	fixtureScan := sdkStretchNamesIn(t, fixture, []string{"cgo/ctest/testdata"}, needle)
	if want := []string{"cgo/ctest/testdata/harness.go", "dotted.go", "qualified.go"}; !slices.Equal(fixtureScan.namers, want) {
		t.Fatalf("CONTROL FAILED: the fixture's production namers are %v, want %v: a qualified name, a dot import's, and the "+
			"harness a build overlay compiles, and not a comment, the zero value or a test", fixtureScan.namers, want)
	}
	if fixtureScan.production != 5 || !slices.Equal(fixtureScan.testNamers, []string{"uses_test.go"}) {
		t.Fatalf("CONTROL FAILED: the fixture walk read %d production file(s) and %v test namer(s); want 5 and the one test file",
			fixtureScan.production, fixtureScan.testNamers)
	}

	// ── THE PROPERTY, OVER THIS MODULE ────────────────────────────────────────────────────────
	scan := sdkStretchNamesIn(t, os.DirFS("."), sdkOverlaidSourceDirs, needle)
	t.Logf("the door: messagegroup.%s; %d production file(s) read, the overlaid harness among them: %v",
		needle, scan.production, scan.overlaid)
	t.Logf("COMPLEMENT, not held: %d test file(s) name it: %v", len(scan.testNamers), scan.testNamers)
	if scan.production < 30 || len(scan.overlaid) == 0 {
		t.Fatalf("CONTROL FAILED: the walk read %d production file(s) and the overlaid harness %v, which is not this module",
			scan.production, scan.overlaid)
	}
	// the needle is spelled as the tests spell it: an absence over production means something only
	// because the same search finds it where it is used
	if len(scan.testNamers) == 0 {
		t.Fatalf("CONTROL FAILED: no test file of this module names %s, so this search finds nothing anywhere", needle)
	}
	for _, name := range scan.namers {
		t.Errorf("%s names messagegroup.%s, the test seam's stretch: production stretches under the frozen parameters "+
			"alone, and DeviceConfig.PhraseStretch's zero value is them", name, needle)
	}
}
