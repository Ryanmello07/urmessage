// Package layering holds the message repository's dependency boundary as a test. It has no
// source of its own and nothing imports it.
//
// MESSAGEREVIEW.md (connect 13ced4c8) sets the boundary, and its rules are what this file
// checks, against the import declarations of every Go file in the repository: tests and
// platform-specific files included, build constraints deliberately not applied (a forbidden
// import in a _windows.go file is still a forbidden import), aliased, blank and dot imports
// included.
//
//   - Every package directory has a row in layeringRules naming the packages of this
//     repository it may import, exactly, and the modules beyond the standard library it may
//     import. A package with no row fails, and so does a row with no package: the map is a
//     disposition of the whole tree, checked both ways.
//   - No package imports its own descendant (CODESTYLE.md, "Package layering"): the six
//     immediate packages are peers, and a parent facade importing sdk/urmessage would be the
//     violation the promotion of mls/syntax to syntax removed.
//   - The root module never imports connect or the core SDK: the five foundational packages
//     (message, messagegroup, mls, syntax, protocol) build without either.
//   - The server-safe closure, message, syntax and protocol, reaches neither mls nor
//     messagegroup, directly or transitively, nor anything of the sdk module, connect or the
//     core SDK. The server-safe paths are named one by one; the subtree
//     github.com/urnetwork/message is never allowed as a whole.
//   - No Go file names connect's old paths for the moved packages
//     (github.com/urnetwork/connect/{mls,message,messagegroup}) except where staleLiteralUses
//     says why. Once anything here requires connect, a go/importer or go/types fixture spelled
//     that way type-checks connect's frozen copy without failing, so a stale spelling is a
//     gate quietly judging the wrong code.
//
// Nested modules are judged by their own rows, like every other package; what makes them a
// separate module is their go.mod, which this file does not need to read to check imports.
//
// It replaces connect's TestSubpackagesDoNotImportBack, whose rules for mls, the codec,
// message and messagegroup are rows below. Fixture controls at the bottom fire every rule.
package layering

import (
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

const modulePath = "github.com/urnetwork/message"

// What a package may import beyond the standard library.
type layeringRule struct {
	// packages of this repository, as repository-relative directories, exactly
	module []string
	// modules or packages outside it, each allowing its own subtree (a path boundary applies)
	external []string
	reason   string
}

var layeringRules = map[string]layeringRule{
	"syntax": {
		reason: "spec A section 2.3: the codec is standard library only, so it can be audited and fuzzed with nothing else in the graph",
	},
	"message": {
		module: []string{"syntax"},
		reason: "server-safe: the record half links no MLS parser and does not depend on the client half (spec B section 2.2)",
	},
	"mls": {
		module:   []string{"syntax"},
		external: []string{"golang.org/x/crypto", "golang.org/x/sys/cpu"},
		reason:   "the protocol core: linkable without the record layer, the group sessions or any transport",
	},
	"messagegroup": {
		module:   []string{"message", "mls", "syntax"},
		external: []string{"golang.org/x/crypto"},
		reason:   "the client half: it holds the group, so it may import the record layer and mls, never the reverse",
	},
	"internal/layering": {
		reason: "this gate: standard library only",
	},
	"internal/repository": {
		reason: "the repository-wide checks (NOTICE coverage): standard library only",
	},
}

// The server-safe packages, named one by one (MESSAGEREVIEW.md, "Preserve the server and
// client boundary"), and what their closure must never reach.
var (
	serverSafePackages     = []string{"message", "syntax"}
	serverSafeForbidden    = []string{"mls", "messagegroup", "sdk"}
	coreRepositoryPrefixes = []string{"github.com/urnetwork/connect", "github.com/urnetwork/sdk"}
)

// The stale spellings, and the files allowed to name them with the reason.
var (
	staleLiterals = []string{
		"github.com/urnetwork/connect/mls",
		"github.com/urnetwork/connect/message",
	}
	staleLiteralUses = map[string]string{
		"message/record_test.go":             "names the record layer's old import paths as patterns its sdk complement check detects in OTHER code; nothing is imported or type-checked under them",
		"internal/layering/layering_test.go": "this gate: the stale spellings are its patterns, and its fixture plants them",
	}
)

type importRecord struct {
	file string // repository-relative, slash separated
	path string // the import path
}

type repositoryScan struct {
	packages map[string][]importRecord // package directory -> its imports, every file
	files    map[string][]string       // package directory -> its Go files
	modules  map[string]string         // directory holding a go.mod -> its module path
	sources  map[string][]byte         // every .go file, testdata included -> its bytes
}

func isStandardLibrary(path string) bool {
	first, _, _ := strings.Cut(path, "/")
	return !strings.Contains(first, ".")
}

func underPath(path string, prefix string) bool {
	return path == prefix || strings.HasPrefix(path, prefix+"/")
}

// The repository root, found from this package's directory and checked by its module line.
func repositoryRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	goMod, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatalf("read the repository's go.mod: %v", err)
	}
	if modulePathOf(goMod) != modulePath {
		t.Fatalf("%s/go.mod declares %q, want %q: this gate is not where it thinks it is", root, modulePathOf(goMod), modulePath)
	}
	return root
}

func modulePathOf(goMod []byte) string {
	for _, line := range strings.Split(string(goMod), "\n") {
		if after, found := strings.CutPrefix(strings.TrimSpace(line), "module "); found {
			return strings.Trim(strings.TrimSpace(after), `"`)
		}
	}
	return ""
}

// Every Go file under root. Directories named testdata hold fixtures, not packages: their
// files are read for the stale-literal rule and judged by no row. Hidden directories and
// those starting with an underscore are skipped, as the go tool skips them.
func scanRepository(t *testing.T, root string) repositoryScan {
	t.Helper()
	scan := repositoryScan{packages: map[string][]importRecord{}, files: map[string][]string{}, modules: map[string]string{}, sources: map[string][]byte{}}
	fileSet := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if entry.IsDir() {
			name := entry.Name()
			if path != root && (strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") || name == "vendor") {
				return filepath.SkipDir
			}
			if goMod, err := os.ReadFile(filepath.Join(path, "go.mod")); err == nil {
				scan.modules[relative] = modulePathOf(goMod)
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		source, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		scan.sources[relative] = source
		if relative == "testdata" || strings.HasPrefix(relative, "testdata/") || strings.Contains(relative, "/testdata/") {
			return nil
		}
		parsed, err := parser.ParseFile(fileSet, path, source, parser.ImportsOnly)
		if err != nil {
			return fmt.Errorf("parse %s: %w", relative, err)
		}
		dir := filepath.ToSlash(filepath.Dir(relative))
		scan.files[dir] = append(scan.files[dir], relative)
		records := scan.packages[dir]
		for _, spec := range parsed.Imports {
			imported, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				return fmt.Errorf("%s: import %s: %w", relative, spec.Path.Value, err)
			}
			records = append(records, importRecord{file: relative, path: imported})
		}
		scan.packages[dir] = records
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	if len(scan.files) == 0 {
		t.Fatalf("found no Go package under %s, so every rule below would hold vacuously", root)
	}
	return scan
}

// The repository-relative directory of an import path inside this repository's modules.
func repositoryPackage(imported string) (string, bool) {
	if imported == modulePath {
		return ".", true
	}
	return strings.CutPrefix(imported, modulePath+"/")
}

// Whether a package directory belongs to the root module (no nested go.mod above it).
func inRootModule(scan repositoryScan, dir string) bool {
	for nested := range scan.modules {
		if nested != "." && (dir == nested || strings.HasPrefix(dir, nested+"/")) {
			return false
		}
	}
	return true
}

// Every violation of the rules, sorted. rules, serverSafe and the stale-literal uses are
// arguments so the fixture controls run the same function.
func layeringViolations(scan repositoryScan, rules map[string]layeringRule, serverSafe []string, staleUses map[string]string) []string {
	violations := []string{}
	report := func(format string, args ...any) {
		violations = append(violations, fmt.Sprintf(format, args...))
	}
	if files, found := scan.files["."]; found {
		report("the repository root holds Go source (%s); it holds module metadata, documentation and CI only", strings.Join(files, ", "))
	}
	for dir := range rules {
		if _, found := scan.files[dir]; !found {
			report("%s has a row and holds no Go source: a row nothing uses", dir)
		}
	}
	edges := map[string][]string{}
	externals := map[string][]importRecord{}
	for _, dir := range sortedKeys(scan.files) {
		rule, found := rules[dir]
		if dir != "." && !found {
			report("%s holds Go source and has no row: every package's imports are a disposition", dir)
		}
		for _, record := range scan.packages[dir] {
			if isStandardLibrary(record.path) {
				continue
			}
			if target, inside := repositoryPackage(record.path); inside {
				if target == dir {
					continue // an external test package importing the package it tests
				}
				edges[dir] = append(edges[dir], target)
				if strings.HasPrefix(target, dir+"/") {
					report("%s imports its own descendant %s (%s): a package may import a peer, never a descendant", dir, target, record.file)
				}
				if found && !slices.Contains(rule.module, target) {
					report("%s imports %s (%s), which its row does not allow", dir, target, record.file)
				}
				continue
			}
			externals[dir] = append(externals[dir], record)
			if inRootModule(scan, dir) {
				for _, prefix := range coreRepositoryPrefixes {
					if underPath(record.path, prefix) {
						report("%s is in the root module and imports %s (%s): the foundational packages build without connect and the core SDK", dir, record.path, record.file)
					}
				}
			}
			if !found {
				continue
			}
			allowed := false
			for _, prefix := range rule.external {
				if underPath(record.path, prefix) {
					allowed = true
				}
			}
			if !allowed {
				report("%s imports %s (%s), outside the standard library and its row", dir, record.path, record.file)
			}
		}
	}
	// the server-safe closure, over every file's imports
	reached := map[string]string{}
	frontier := []string{}
	for _, dir := range serverSafe {
		reached[dir] = dir
		frontier = append(frontier, dir)
	}
	for len(frontier) > 0 {
		at := frontier[len(frontier)-1]
		frontier = frontier[:len(frontier)-1]
		for _, next := range edges[at] {
			if _, seen := reached[next]; !seen {
				reached[next] = at
				frontier = append(frontier, next)
			}
		}
	}
	for _, dir := range sortedKeys(reached) {
		for _, forbidden := range serverSafeForbidden {
			if dir == forbidden || strings.HasPrefix(dir, forbidden+"/") {
				report("the server-safe closure %v reaches %s (through %s)", serverSafe, dir, reached[dir])
			}
		}
		for _, record := range externals[dir] {
			for _, prefix := range coreRepositoryPrefixes {
				if underPath(record.path, prefix) {
					report("the server-safe closure %v reaches %s through %s (%s)", serverSafe, record.path, dir, record.file)
				}
			}
		}
	}
	// stale spellings of the moved packages
	used := map[string]bool{}
	for _, file := range sortedKeys(scan.sources) {
		for _, literal := range staleLiterals {
			if !strings.Contains(string(scan.sources[file]), literal) {
				continue
			}
			if staleUses[file] != "" {
				used[file] = true
				continue
			}
			report("%s names %s, connect's old path for a package that lives here now", file, literal)
		}
	}
	for file := range staleUses {
		if !used[file] {
			report("%s is allowed to name a stale path and names none: a disposition nothing uses", file)
		}
	}
	slices.Sort(violations)
	return slices.Compact(violations)
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}

func TestEveryPackageImportsOnlyWhatItsRowAllows(t *testing.T) {
	scan := scanRepository(t, repositoryRoot(t))
	files, imports := 0, 0
	for _, dir := range sortedKeys(scan.packages) {
		imports += len(scan.packages[dir])
	}
	files = len(scan.sources)
	t.Logf("%d Go files read (testdata included), %d packages, %d import declarations, modules %v",
		files, len(scan.files), imports, scan.modules)
	for _, violation := range layeringViolations(scan, layeringRules, serverSafePackages, staleLiteralUses) {
		t.Error(violation)
	}
}

// Every rule above, fired on a fixture repository: each planted violation must be reported,
// and a clean package must not be.
func TestTheLayeringRulesFireOnAFixtureRepository(t *testing.T) {
	root := t.TempDir()
	write := func(relative string, body string) {
		path := filepath.Join(root, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module "+modulePath+"\n")
	write("syntax/codec.go", "package syntax\n\nimport \"strings\"\n\nvar _ = strings.TrimSpace\n")
	write("mls/mls.go", "package mls\n\nimport _ \""+modulePath+"/syntax\"\n")
	write("message/plain.go", "package message\n\nimport \""+modulePath+"/mls\"\n")
	write("message/alias.go", "package message\n\nimport group \""+modulePath+"/messagegroup/inner\"\n")
	write("message/blank_windows.go", "package message\n\nimport _ \"github.com/urnetwork/connect\"\n")
	write("message/dot_test.go", "package message\n\nimport . \""+modulePath+"/relay\"\n")
	write("relay/relay.go", "package relay\n\nimport _ \""+modulePath+"/messagegroup\"\n")
	write("messagegroup/group.go", "package messagegroup\n\nimport _ \""+modulePath+"/messagegroup/inner\"\n")
	write("messagegroup/inner/inner.go", "package inner\n")
	write("stray/stray.go", "package stray\n")
	write("boundary/boundary.go", "package boundary\n\nimport (\n\t_ \"golang.org/x/crypto/sha3\"\n\t_ \"golang.org/x/cryptographer\"\n)\n")
	write("syntax/stale.go", "package syntax\n\nconst stale = \"github.com/urnetwork/connect/mls\"\n")
	write("syntax/testdata/fixture.go", "package fixture\n\nimport _ \"github.com/urnetwork/connect/message\"\n")
	write("facade.go", "package message\n")
	rules := map[string]layeringRule{
		"syntax":             {},
		"mls":                {module: []string{"syntax"}},
		"message":            {module: []string{"syntax"}},
		"relay":              {module: []string{"messagegroup"}},
		"messagegroup":       {module: []string{"messagegroup/inner"}},
		"messagegroup/inner": {},
		"ghost":              {},
		"boundary":           {external: []string{"golang.org/x/crypto"}},
	}
	violations := layeringViolations(scanRepository(t, root), rules, []string{"message", "syntax"}, map[string]string{"never.go": "a use nothing makes"})
	wants := []string{
		"message imports mls (message/plain.go), which its row does not allow",
		"message imports messagegroup/inner (message/alias.go), which its row does not allow",
		"message imports relay (message/dot_test.go), which its row does not allow",
		"message is in the root module and imports github.com/urnetwork/connect (message/blank_windows.go)",
		"message imports github.com/urnetwork/connect (message/blank_windows.go), outside the standard library and its row",
		"the server-safe closure [message syntax] reaches github.com/urnetwork/connect through message (message/blank_windows.go)",
		"the server-safe closure [message syntax] reaches mls (through message)",
		"the server-safe closure [message syntax] reaches messagegroup/inner (through message)",
		// reachable only through relay: transitivity, not a direct import, is what reports it
		"the server-safe closure [message syntax] reaches messagegroup (through relay)",
		"messagegroup imports its own descendant messagegroup/inner (messagegroup/group.go)",
		"stray holds Go source and has no row",
		"boundary imports golang.org/x/cryptographer (boundary/boundary.go), outside the standard library and its row",
		"ghost has a row and holds no Go source",
		"syntax/stale.go names github.com/urnetwork/connect/mls",
		"syntax/testdata/fixture.go names github.com/urnetwork/connect/message",
		"never.go is allowed to name a stale path and names none",
		"the repository root holds Go source (facade.go)",
	}
	for _, want := range wants {
		reported := false
		for _, violation := range violations {
			if strings.HasPrefix(violation, want) {
				reported = true
			}
		}
		if !reported {
			t.Errorf("the fixture's planted violation was not reported: %q\nreported: %q", want, violations)
		}
	}
	// the dot import in a _test.go file and the blank import in a _windows.go file were read
	for _, file := range []string{"message/dot_test.go", "message/blank_windows.go"} {
		if !strings.Contains(strings.Join(violations, "\n"), file) {
			t.Errorf("%s was not read: build constraints and test files must not hide an import", file)
		}
	}
	for _, violation := range violations {
		if strings.HasPrefix(violation, "mls ") || strings.HasPrefix(violation, "syntax imports") {
			t.Errorf("a clean package was reported: %s", violation)
		}
	}
	if len(violations) != len(wants) {
		t.Errorf("the fixture plants %d violations and %d were reported: %q", len(wants), len(violations), violations)
	}
}
