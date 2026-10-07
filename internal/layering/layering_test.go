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
//   - No Go file names the old paths of the moved packages (connect's
//     github.com/urnetwork/connect/{mls,message,messagegroup} and the core SDK's
//     github.com/urnetwork/sdk/urmessage) except where staleLiteralUses says why. Once anything here requires connect, a go/importer or go/types fixture spelled
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
	"encoding/json"
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"path"
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
	"protocol": {
		external: []string{"google.golang.org/protobuf"},
		reason:   "the messaging schema: server-safe, generated code plus its checks; it imports no package of this repository and no transport",
	},
	"internal/layering": {
		reason: "this gate: standard library only",
	},
	"internal/repository": {
		reason: "the repository-wide checks (NOTICE coverage, the root go.mod's boundary): standard library only",
	},

	// THE SDK MODULE (github.com/urnetwork/message/sdk) and the modules nested in it. Each package
	// has its row like any other; none of the foundational rows above names any of them, so no
	// foundational package may import the SDK, and serverSafeForbidden keeps the whole subtree out
	// of the server-safe closure. One row names the core SDK (github.com/urnetwork/sdk), the
	// composition module's gen, whose parity test links both SDKs; the messaging SDK itself does
	// not depend on it. The core's own cgo files, which compose.sh lays under sdk/cgo for a build,
	// are the core's and are not judged here (composedRecord).
	"sdk": {
		module:   []string{"message", "messagegroup", "mls", "protocol"},
		external: []string{"github.com/urnetwork/connect", "github.com/gorilla/websocket", "github.com/gopacket/gopacket", "google.golang.org/protobuf"},
		reason:   "the messaging SDK: the message-server binding, the route client, the stream store and the tunnel. It reaches the server through connect, so it imports connect and the client half; gopacket is its tunnel tests' packet helper",
	},
	"sdk/urmessage": {
		module:   []string{"message", "messagegroup", "mls", "protocol", "sdk", "syntax"},
		external: []string{"github.com/urnetwork/connect", "google.golang.org/protobuf"},
		reason:   "the device and group orchestration over the SDK's transport and stores",
	},
	"sdk/cgo": {
		module:   []string{"messagegroup", "protocol", "sdk", "sdk/urmessage"},
		external: []string{"github.com/urnetwork/connect", "github.com/urnetwork/message-server"},
		reason:   "the messaging half of the native C ABI, built laid over the core SDK's cgo package main by the composition build; the loopback harness (ctest/testdata/loopback_test_world.go, laid into this package by a build overlay, with its own modfile) runs a message server in-process",
	},
	"sdk/cgo/gen": {
		module:   []string{"sdk", "sdk/urmessage"},
		external: []string{"github.com/urnetwork/sdk"},
		reason:   "the composed library's .def generator and its tests: the C header's text limits against urmessage's, and the one test that links both SDKs, MessageServiceUrls against the core SDK's ServiceUrl",
	},
	"sdk/cp3b": {
		module:   []string{"message", "messagegroup", "mls", "protocol", "sdk", "sdk/urmessage"},
		external: []string{"github.com/urnetwork/connect", "github.com/urnetwork/message-server", "google.golang.org/protobuf"},
		reason:   "the cross-process suite: devices against a real message server and its store",
	},
	"sdk/livepeer": {
		module:   []string{"protocol", "sdk", "sdk/urmessage"},
		external: []string{"github.com/urnetwork/connect"},
		reason:   "the live peer command: one device on a real network",
	},
	"sdk/liveprobe": {
		module:   []string{"messagegroup", "mls", "protocol", "sdk", "sdk/urmessage"},
		external: []string{"github.com/urnetwork/connect"},
		reason:   "the live probe command: a group's round trips against a deployment",
	},
}

// The server-safe packages, named one by one (MESSAGEREVIEW.md, "Preserve the server and
// client boundary"), and what their closure must never reach.
var (
	serverSafePackages     = []string{"message", "protocol", "syntax"}
	serverSafeForbidden    = []string{"mls", "messagegroup", "sdk"}
	coreRepositoryPrefixes = []string{"github.com/urnetwork/connect", "github.com/urnetwork/sdk"}
)

// The stale spellings, and the files allowed to name them with the reason.
var (
	staleLiterals = []string{
		"github.com/urnetwork/connect/mls",
		"github.com/urnetwork/connect/message",
		// the core SDK's path for the URmessage client, which lives here as sdk/urmessage
		"github.com/urnetwork/sdk/urmessage",
	}
	staleLiteralUses = map[string]string{
		"internal/layering/layering_test.go": "this gate: the stale spellings are its patterns, and its fixture plants them",
	}
)

// THE BUILD OVERLAYS: each file the go command is handed with -overlay, and the directory the command
// runs in when it is (an overlay's paths are relative to that directory). An overlay lays a file
// into a package for one build without the file being in the package's directory. There is one: the
// loopback harness. urnetwork/sdk a7b5db77 moved it from the cgo package's directory to
// ctest/testdata/, where go mod tidy does not read it, and the test library is built with
// -overlay=ctest/loopback-overlay.json, which compiles it into sdk/cgo's package main.
//
// A testdata directory holds fixtures: no build compiles them and no row judges them. A file an
// overlay lays into a package is the exception. It is that package's source, so it is judged by
// that package's row, as the harness was while it sat in sdk/cgo. The map is held both ways: an
// overlay named here is in the tree and lays at least one Go file, each of them a file under a
// testdata directory; and a JSON file anywhere in the tree that is a build overlay (a top-level
// "Replace" object) and is not named here fails, so a second overlay cannot put source into a
// package unjudged.
var buildOverlays = map[string]string{
	"sdk/cgo/ctest/loopback-overlay.json": "sdk/cgo",
}

// The testdata directories that hold overlaid source, held to what the overlays lay down, both
// ways. THE OTHER GATES THAT SKIP testdata READ THESE DIRECTORIES BY NAME, since a walk that skips
// every testdata directory stops reading the harness the day it moves into one: the record gate and
// the constant-time importer walk (message), the attestation walk (protocol), the SDK's crypto-scope
// map (sdk), the citation, doc-link and dark-group gates (sdk/urmessage), the .def's harness test
// (sdk/cgo/gen) and test.sh's gofmt step. A source laid from anywhere else fails here until this
// list, and each of them, says where it is.
var overlaidSourceDirectories = []string{"sdk/cgo/ctest/testdata"}

// The go command's overlay file: the path a build sees, to the file on disk that stands in for it.
type buildOverlay struct {
	Replace map[string]string
}

type importRecord struct {
	file string // repository-relative, slash separated
	path string // the import path
}

type repositoryScan struct {
	packages map[string][]importRecord // package directory -> its imports, every file
	files    map[string][]string       // package directory -> its Go files
	modules  map[string]string         // directory holding a go.mod -> its module path
	sources  map[string][]byte         // every .go file, testdata included -> its bytes
	composed []string                  // the core SDK's files sdk/cgo/compose.sh laid in, not read
	// a file under testdata that a build overlay lays into a package -> that package's directory
	overlaid map[string]string
	// what is wrong with the overlays themselves: a declared one that is gone or lays nothing, a
	// source that is not a Go file under testdata, an overlay in the tree that is not declared
	overlayProblems []string
	// the .go files under testdata that no overlay lays anywhere: fixtures, judged by no row
	fixtures int
}

// The sources the declared overlays lay into packages, and what is wrong with the declarations.
func readBuildOverlays(root string, declared map[string]string) (map[string]string, []string) {
	overlaid := map[string]string{}
	problems := []string{}
	for _, overlayPath := range sortedKeys(declared) {
		base := declared[overlayPath]
		body, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(overlayPath)))
		if err != nil {
			problems = append(problems, fmt.Sprintf("the build overlay %s is declared and cannot be read (%v): a row nothing uses", overlayPath, err))
			continue
		}
		overlay := buildOverlay{}
		if err := json.Unmarshal(body, &overlay); err != nil {
			problems = append(problems, fmt.Sprintf("the build overlay %s is not an overlay file: %v", overlayPath, err))
			continue
		}
		laid := 0
		for _, target := range sortedKeys(overlay.Replace) {
			source := overlay.Replace[target]
			if source == "" || path.IsAbs(source) || path.IsAbs(target) || strings.ContainsAny(source+target, `\:`) {
				problems = append(problems, fmt.Sprintf("the build overlay %s maps %q to %q: only a relative, slash-separated path to another is read here", overlayPath, target, source))
				continue
			}
			from := path.Join(base, source)
			into := path.Dir(path.Join(base, target))
			if !strings.HasSuffix(from, ".go") || !underTestdata(from) {
				problems = append(problems, fmt.Sprintf("the build overlay %s lays %s into %s: an overlaid source is a .go file under a testdata directory, where no package reads it a second time", overlayPath, from, into))
				continue
			}
			if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(from))); err != nil {
				problems = append(problems, fmt.Sprintf("the build overlay %s lays %s, which is not in the tree (%v)", overlayPath, from, err))
				continue
			}
			if earlier, twice := overlaid[from]; twice {
				problems = append(problems, fmt.Sprintf("%s is laid into both %s and %s", from, earlier, into))
				continue
			}
			overlaid[from] = into
			laid++
		}
		if laid == 0 {
			problems = append(problems, fmt.Sprintf("the build overlay %s lays no Go source into any package: a row nothing uses", overlayPath))
		}
	}
	return overlaid, problems
}

func underTestdata(relative string) bool {
	return relative == "testdata" || strings.HasPrefix(relative, "testdata/") || strings.Contains(relative, "/testdata/")
}

// The record sdk/cgo/compose.sh writes while the core SDK's cgo package main is laid under sdk/cgo:
// one name per line, relative to sdk/cgo. Those files are the core's source, judged by the core's
// own gates, and are in the tree only for a build; compose.sh --clean removes them and the record. It
// is gitignored, so it exists only in a working tree that was composed.
const composedRecord = "sdk/cgo/.composed"

// The repository-relative paths composedRecord names, if it is there.
func composedFiles(t *testing.T, root string) map[string]bool {
	t.Helper()
	composed := map[string]bool{}
	record, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(composedRecord)))
	if os.IsNotExist(err) {
		return composed
	}
	if err != nil {
		t.Fatalf("read %s: %v", composedRecord, err)
	}
	for _, line := range strings.Split(strings.ReplaceAll(string(record), "\r\n", "\n"), "\n") {
		if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
			composed["sdk/cgo/"+line] = true
		}
	}
	return composed
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
// files are read for the stale-literal rule and judged by no row, except a file a build overlay
// lays into a package (overlays, as buildOverlays declares them), which is judged by that package's
// row. Hidden directories and those starting with an underscore are skipped, as the go tool skips
// them, and so are the core SDK's files a compose laid under sdk/cgo (composedRecord), which
// scan.composed names.
func scanRepository(t *testing.T, root string, overlays map[string]string) repositoryScan {
	t.Helper()
	scan := repositoryScan{packages: map[string][]importRecord{}, files: map[string][]string{}, modules: map[string]string{}, sources: map[string][]byte{}}
	scan.overlaid, scan.overlayProblems = readBuildOverlays(root, overlays)
	composed := composedFiles(t, root)
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
		if strings.HasSuffix(path, ".json") {
			// an overlay nobody declared: whatever it lays into a package is judged by no row
			if _, declared := overlays[relative]; declared {
				return nil
			}
			body, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			overlay := buildOverlay{}
			if json.Unmarshal(body, &overlay) == nil && overlay.Replace != nil {
				scan.overlayProblems = append(scan.overlayProblems, fmt.Sprintf("%s is a build overlay (a top-level Replace object) and buildOverlays does not name it: the source it lays into a package would be judged by no row", relative))
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		if composed[relative] {
			scan.composed = append(scan.composed, relative)
			return nil
		}
		source, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		scan.sources[relative] = source
		dir := filepath.ToSlash(filepath.Dir(relative))
		if underTestdata(relative) {
			into, laid := scan.overlaid[relative]
			if !laid {
				scan.fixtures++
				return nil
			}
			// the package the overlay compiles it into, not the directory it sits in
			dir = into
		}
		parsed, err := parser.ParseFile(fileSet, path, source, parser.ImportsOnly)
		if err != nil {
			return fmt.Errorf("parse %s: %w", relative, err)
		}
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
		report("the repository root holds Go source (%s); it holds module metadata, documentation and test.sh only", strings.Join(files, ", "))
	}
	for _, problem := range scan.overlayProblems {
		report("%s", problem)
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
			report("%s names %s, an old path (connect's or the core SDK's) for a package that lives here now", file, literal)
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

// The directories the overlaid sources sit in, held to the declared list both ways.
func overlaidDirectoryProblems(overlaid map[string]string, declared []string) []string {
	problems := []string{}
	holding := map[string]bool{}
	for _, source := range sortedKeys(overlaid) {
		holding[path.Dir(source)] = true
	}
	for _, dir := range sortedKeys(holding) {
		if !slices.Contains(declared, dir) {
			problems = append(problems, fmt.Sprintf("%s holds source a build overlay lays into a package, and overlaidSourceDirectories does not name it: every gate that skips testdata (listed there) has to read it by name first", dir))
		}
	}
	for _, dir := range declared {
		if !holding[dir] {
			problems = append(problems, fmt.Sprintf("overlaidSourceDirectories names %s, and no build overlay lays a source from it: a row nothing uses", dir))
		}
	}
	return problems
}

func TestEveryPackageImportsOnlyWhatItsRowAllows(t *testing.T) {
	scan := scanRepository(t, repositoryRoot(t), buildOverlays)
	files, imports := 0, 0
	for _, dir := range sortedKeys(scan.packages) {
		imports += len(scan.packages[dir])
	}
	files = len(scan.sources)
	t.Logf("%d Go files read (testdata included), %d packages, %d import declarations, modules %v",
		files, len(scan.files), imports, scan.modules)
	// the testdata narrowing, printed: what no row judges, and what an overlay puts back under one
	t.Logf("UNDER testdata: %d fixture file(s) no row judges; %d file(s) a build overlay lays into a package, judged by that package's row: %v",
		scan.fixtures, len(scan.overlaid), scan.overlaid)
	if len(scan.composed) > 0 {
		t.Logf("NOT READ: %d file(s) of the core SDK's cgo package main that %s says a compose laid under sdk/cgo: %v",
			len(scan.composed), composedRecord, scan.composed)
	}
	for _, violation := range layeringViolations(scan, layeringRules, serverSafePackages, staleLiteralUses) {
		t.Error(violation)
	}
	for _, problem := range overlaidDirectoryProblems(scan.overlaid, overlaidSourceDirectories) {
		t.Error(problem)
	}
}

// The overlay rule on a fixture, each case for its own reason. A file under testdata that a declared
// overlay lays into a package is judged by that package's row, and the fixture beside it by none.
// With testdata skipped whole, which is the rule before the harness moved there, the same import
// goes unjudged, and the one thing reported is the overlay nobody declared.
func TestAnOverlaidSourceIsJudgedByThePackageItIsLaidInto(t *testing.T) {
	root := t.TempDir()
	write := func(relative string, body string) {
		at := filepath.Join(root, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(at), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(at, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	const overlayPath = "sdk/cgo/ctest/overlay.json"
	const harness = "sdk/cgo/ctest/testdata/harness.go"
	write("go.mod", "module "+modulePath+"\n")
	write("sdk/cgo/go.mod", "module "+modulePath+"/sdk/cgo\n")
	write("sdk/cgo/own.go", "package main\n\nimport _ \"github.com/urnetwork/connect\"\n")
	write(overlayPath, "{\r\n  \"Replace\": {\"harness.go\": \"ctest/testdata/harness.go\"}\r\n}\r\n")
	write(harness, "//go:build harness\n\npackage main\n\nimport _ \"github.com/urnetwork/sdk\"\n")
	write("sdk/cgo/ctest/testdata/fixture.go", "package fixture\n\nimport _ \"github.com/urnetwork/sdk\"\n")
	rules := map[string]layeringRule{"sdk/cgo": {external: []string{"github.com/urnetwork/connect"}}}
	overlays := map[string]string{overlayPath: "sdk/cgo"}
	judged := "sdk/cgo imports github.com/urnetwork/sdk (" + harness + "), outside the standard library and its row"

	scan := scanRepository(t, root, overlays)
	if got := layeringViolations(scan, rules, nil, map[string]string{}); !slices.Equal(got, []string{judged}) {
		t.Errorf("a declared overlay's source must be judged by the row of the package it is laid into, and nothing else reported: %q", got)
	}
	if scan.fixtures != 1 || len(scan.overlaid) != 1 || scan.overlaid[harness] != "sdk/cgo" {
		t.Errorf("fixtures %d, overlaid %v: want the one fixture unjudged and the harness laid into sdk/cgo", scan.fixtures, scan.overlaid)
	}

	// the rejected design: nothing under testdata is judged
	got := layeringViolations(scanRepository(t, root, nil), rules, nil, map[string]string{})
	if len(got) != 1 || !strings.HasPrefix(got[0], overlayPath+" is a build overlay") {
		t.Errorf("with no overlay declared the harness's import is unjudged, and the undeclared overlay is what is reported: %q", got)
	}

	// the declarations, each refused for its own reason
	for _, c := range []struct {
		name    string
		overlay string
		want    string
	}{
		{"a source outside testdata", `{"Replace": {"harness.go": "own.go"}}`, "an overlaid source is a .go file under a testdata directory"},
		{"a source that is not Go", `{"Replace": {"harness.go": "ctest/testdata/harness.txt"}}`, "an overlaid source is a .go file under a testdata directory"},
		{"a source that is not there", `{"Replace": {"harness.go": "ctest/testdata/gone.go"}}`, "which is not in the tree"},
		{"an absolute source", `{"Replace": {"harness.go": "/ctest/testdata/harness.go"}}`, "only a relative, slash-separated path"},
		{"a deleted file", `{"Replace": {"own.go": ""}}`, "only a relative, slash-separated path"},
		{"nothing laid", `{"Replace": {}}`, "lays no Go source into any package"},
		{"not an overlay", `[1, 2]`, "is not an overlay file"},
	} {
		write(overlayPath, c.overlay)
		problems := scanRepository(t, root, overlays).overlayProblems
		if len(problems) == 0 || !strings.Contains(strings.Join(problems, "\n"), c.want) {
			t.Errorf("%s: want a problem holding %q, got %q", c.name, c.want, problems)
		}
	}
	if err := os.Remove(filepath.Join(root, filepath.FromSlash(overlayPath))); err != nil {
		t.Fatal(err)
	}
	if problems := scanRepository(t, root, overlays).overlayProblems; len(problems) != 1 || !strings.Contains(problems[0], "is declared and cannot be read") {
		t.Errorf("a declared overlay that is gone: %q", problems)
	}

	// the directories, both ways
	laid := map[string]string{harness: "sdk/cgo"}
	if problems := overlaidDirectoryProblems(laid, []string{"sdk/cgo/ctest/testdata"}); len(problems) != 0 {
		t.Errorf("the declared directory was refused: %q", problems)
	}
	if problems := overlaidDirectoryProblems(laid, nil); len(problems) != 1 || !strings.Contains(problems[0], "overlaidSourceDirectories does not name it") {
		t.Errorf("an overlaid source in an undeclared directory: %q", problems)
	}
	if problems := overlaidDirectoryProblems(nil, []string{"sdk/cgo/ctest/testdata"}); len(problems) != 1 || !strings.Contains(problems[0], "a row nothing uses") {
		t.Errorf("a declared directory no overlay uses: %q", problems)
	}
}

// A composed tree, on a fixture: the files the compose record names are the core's and are not
// judged, and are named; a file the record does not name, beside them, is judged as ever.
func TestTheComposedCoreFilesAreLeftToTheCoreAndNamed(t *testing.T) {
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
	write("sdk/cgo/go.mod", "module "+modulePath+"/sdk/cgo\n")
	write("sdk/cgo/handles.go", "package main\n\nimport _ \"github.com/urnetwork/sdk\"\n")
	write("sdk/cgo/own.go", "package main\n\nimport _ \"github.com/urnetwork/sdk\"\n")
	write("sdk/cgo/.composed", "# composed by sdk/cgo/compose.sh from the fixture\nhandles.go\r\n")
	rules := map[string]layeringRule{"sdk/cgo": {external: []string{"github.com/urnetwork/connect"}}}
	scan := scanRepository(t, root, nil)
	if !slices.Equal(scan.composed, []string{"sdk/cgo/handles.go"}) {
		t.Errorf("the composed files named: %v, want [sdk/cgo/handles.go]", scan.composed)
	}
	violations := layeringViolations(scan, rules, nil, map[string]string{})
	if len(violations) != 1 || !strings.HasPrefix(violations[0], "sdk/cgo imports github.com/urnetwork/sdk (sdk/cgo/own.go)") {
		t.Errorf("the file the record does not name must be judged, and only it: %q", violations)
	}
	// and without the record, both are judged
	if err := os.Remove(filepath.Join(root, "sdk", "cgo", ".composed")); err != nil {
		t.Fatal(err)
	}
	if violations := layeringViolations(scanRepository(t, root, nil), rules, nil, map[string]string{}); len(violations) != 2 {
		t.Errorf("with no compose record both files are this repository's and both are judged: %q", violations)
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
	violations := layeringViolations(scanRepository(t, root, nil), rules, []string{"message", "syntax"}, map[string]string{"never.go": "a use nothing makes"})
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
