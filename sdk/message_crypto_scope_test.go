package sdk

import (
	"fmt"
	"go/parser"
	"go/token"
	"io/fs"
	"maps"
	"os"
	"path"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"
)

// ══════════════════════════════════════════════════════════════════════════════════════════════
// THE CRYPTOGRAPHY THIS MODULE IMPORTS IS EXACTLY THE DECLARED SET, IN BOTH DIRECTIONS
// ══════════════════════════════════════════════════════════════════════════════════════════════
//
// WHY THIS IS HERE. The repository's cryptographic rules are held in mls: its derivation
// (mls/crypto_forbidden_test.go) finds every package connected to the cryptographic packages, scans
// them for forbidden primitives, and holds the result to a `go list` floor. Its subject is the root
// module, whose packages it can list and type-check, and its walk stops at a nested go.mod. This
// module is nested under the repository root, so it is outside that walk -- as it was in
// urnetwork/sdk, where connect's scan roots excluded the SDK. What the SDK may do with cryptography
// is therefore held HERE, at the narrowest place it can be read: the standard library's crypto
// packages and golang.org/x/crypto, as each production file imports them.
//
// THE MAP IS DECLARED, AND IT IS HELD BOTH WAYS. A production file that imports a crypto package
// its row does not declare -- an hkdf, an aes, an ed25519 -- fails here until the row says why it
// needs it, which is the review that import deserves. A row that declares an import its file no
// longer makes fails too, because an excuse for something that is gone is an excuse nothing
// checks. Today the set is sha256, subtle, tls and rand.
//
// THE NARROWINGS ARE PRINTED. Test files are not production and are not held (their crypto
// imports are listed in the log, with their count); testdata, vendor and dot directories are not
// compiled and are skipped (their .go files are counted). Everything else under this module's root
// is read, NESTED MODULES INCLUDED -- cgo, cp3b, livepeer and liveprobe -- because the mls walk stops
// at their go.mod files too, and BUILD CONSTRAINTS ARE IGNORED, because a file only one platform
// compiles still ships on that platform.
//
// WHAT IT CANNOT SEE, stated rather than implied: cryptography reached through another package's
// API -- connect's, or this repository's root module's -- is not an import of a crypto package
// here. That is the mls derivation's subject, in the module that declares it.

// sdkCryptoImport is one production file's crypto imports and why it makes them.
type sdkCryptoImport struct {
	imports []string
	why     string
}

// sdkCryptoImports is the declared map: production file, relative to this module's root, to the
// crypto packages it imports.
var sdkCryptoImports = map[string]sdkCryptoImport{
	"cgo/loopback_test_world.go": {[]string{"crypto/rand"},
		"the loopback harness's peer connections draw on crypto/rand.Reader"},
	"livepeer/main.go": {[]string{"crypto/rand"},
		"a fresh group id"},
	"liveprobe/main.go": {[]string{"crypto/rand"},
		"a fresh group id, and the reader messagegroup.XwingGenerateKey draws a key pair from"},
	"message_route.go": {[]string{"crypto/sha256", "crypto/subtle", "crypto/tls"},
		"the route client's pin: the SHA-256 of the server's public key, compared in constant time, " +
			"inside a TLS 1.3 configuration"},
	"message_stream_store.go": {[]string{"crypto/sha256"},
		"the stream store's row identities and key-shape digests"},
	"urmessage/device.go": {[]string{"crypto/rand"},
		"the device's randomness when the caller hands it none"},
	"urmessage/group.go": {[]string{"crypto/sha256"},
		"pq secret witnesses, group-context hashes and a sealed body's hash check"},
	"urmessage/invite.go": {[]string{"crypto/sha256"},
		"an invite's checksum"},
	"urmessage/pqepoch.go": {[]string{"crypto/sha256", "crypto/subtle"},
		"pq secret witnesses, compared in constant time"},
	"urmessage/restore.go": {[]string{"crypto/sha256"},
		"the width of a restored witness row"},
	"urmessage/statestore_durable.go": {[]string{"crypto/sha256"},
		"the durable state store's witness rows and its file checksum"},
}

// sdkIsCryptoImport is the class: the standard library's crypto packages and golang.org/x/crypto,
// each matched at a path boundary, so "cryptox" or "golang.org/x/cryptography" is not in it.
func sdkIsCryptoImport(importPath string) bool {
	for _, root := range []string{"crypto", "golang.org/x/crypto"} {
		if importPath == root || strings.HasPrefix(importPath, root+"/") {
			return true
		}
	}
	return false
}

// sdkCryptoScan is what one walk read.
type sdkCryptoScan struct {
	// found is every production file that imports a crypto package, to those packages, sorted.
	found map[string][]string
	// production is the number of production files read.
	production int
	// testImporters is the complement of the production narrowing: test files with crypto imports.
	testImporters []string
	// skipped is the .go files under testdata, vendor and dot directories, which were not read.
	skipped []string
}

// sdkCryptoImportsIn reads every .go file of fsys -- every directory, build constraints ignored --
// and answers the crypto imports of the production ones.
func sdkCryptoImportsIn(t *testing.T, fsys fs.FS) sdkCryptoScan {
	t.Helper()
	scan := sdkCryptoScan{found: map[string][]string{}}
	fileSet := token.NewFileSet()
	err := fs.WalkDir(fsys, ".", func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			base := entry.Name()
			if name != "." && (base == "testdata" || base == "vendor" || strings.HasPrefix(base, ".")) {
				// counted, so that what the skip removed is printed beside what was read
				fs.WalkDir(fsys, name, func(inner string, innerEntry fs.DirEntry, innerErr error) error {
					if innerErr == nil && !innerEntry.IsDir() && strings.HasSuffix(inner, ".go") {
						scan.skipped = append(scan.skipped, inner)
					}
					return nil
				})
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
		file, parseErr := parser.ParseFile(fileSet, name, source, parser.ImportsOnly)
		if parseErr != nil {
			return fmt.Errorf("parsing %s: %w", name, parseErr)
		}
		imports := []string{}
		for _, spec := range file.Imports {
			imported, unquoteErr := strconv.Unquote(spec.Path.Value)
			if unquoteErr != nil {
				return fmt.Errorf("%s imports %s, which is not a quoted path: %w", name, spec.Path.Value, unquoteErr)
			}
			if sdkIsCryptoImport(imported) {
				imports = append(imports, imported)
			}
		}
		sort.Strings(imports)
		imports = slices.Compact(imports)
		if strings.HasSuffix(name, "_test.go") {
			if 0 < len(imports) {
				scan.testImporters = append(scan.testImporters, fmt.Sprintf("%s %v", name, imports))
			}
			return nil
		}
		scan.production += 1
		if 0 < len(imports) {
			scan.found[name] = imports
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking for crypto imports: %v", err)
	}
	sort.Strings(scan.testImporters)
	sort.Strings(scan.skipped)
	return scan
}

// sdkCryptoScopeProblems holds what a walk found against a declared map, both ways.
func sdkCryptoScopeProblems(found map[string][]string, declared map[string]sdkCryptoImport) []string {
	problems := []string{}
	for _, name := range slices.Sorted(maps.Keys(found)) {
		row, ok := declared[name]
		if !ok {
			problems = append(problems, fmt.Sprintf("%s imports %v and has no row: declare each crypto "+
				"package it needs, with the reason, in sdkCryptoImports", name, found[name]))
			continue
		}
		want := slices.Clone(row.imports)
		sort.Strings(want)
		if !slices.Equal(want, found[name]) {
			problems = append(problems, fmt.Sprintf("%s imports %v and its row declares %v", name, found[name], want))
		}
	}
	for _, name := range slices.Sorted(maps.Keys(declared)) {
		if _, ok := found[name]; !ok {
			problems = append(problems, fmt.Sprintf("the row for %s declares %v and that file imports no "+
				"crypto package (or is gone): an excuse for an import that is not there is an excuse "+
				"nothing checks; delete the row", name, declared[name].imports))
		}
	}
	return problems
}

func TestThisModulesProductionCryptoImportsAreTheDeclaredOnes(t *testing.T) {
	// ── THE CONTROLS, FIRST, ON A FIXTURE TREE, EACH FIRING FOR ITS OWN REASON ───────────────────
	fixture := fstest.MapFS{
		"declared.go":           {Data: []byte("package p\n\nimport \"crypto/sha256\"\n")},
		"hkdf.go":               {Data: []byte("package p\n\nimport derive \"crypto/hkdf\"\n")},
		"xhkdf.go":              {Data: []byte("package p\n\nimport _ \"golang.org/x/crypto/hkdf\"\n")},
		"nested/module/aead.go": {Data: []byte("//go:build windows\n\npackage inner\n\nimport . \"crypto/aes\"\n")},
		"boundary.go":           {Data: []byte("package p\n\nimport \"cryptox/notcrypto\"\n")},
		"declared_test.go":      {Data: []byte("package p\n\nimport \"crypto/ed25519\"\n")},
		"testdata/planted.go":   {Data: []byte("package p\n\nimport \"crypto/des\"\n")},
	}
	fixtureDeclared := map[string]sdkCryptoImport{
		"declared.go": {[]string{"crypto/sha256"}, "the fixture's one honest row"},
		"gone.go":     {[]string{"crypto/rand"}, "a row whose file is gone"},
	}
	fixtureScan := sdkCryptoImportsIn(t, fixture)
	got := sdkCryptoScopeProblems(fixtureScan.found, fixtureDeclared)
	// in the order the check reports them: undeclared imports by file name, then stale rows
	wantFragments := []string{
		"hkdf.go imports [crypto/hkdf] and has no row",
		"nested/module/aead.go imports [crypto/aes] and has no row",
		"xhkdf.go imports [golang.org/x/crypto/hkdf] and has no row",
		"the row for gone.go declares [crypto/rand]",
	}
	if len(got) != len(wantFragments) {
		t.Fatalf("CONTROL FAILED: the fixture planted %d problems and the check reported %d: %v",
			len(wantFragments), len(got), got)
	}
	for index, fragment := range wantFragments {
		if !strings.Contains(got[index], fragment) {
			t.Fatalf("CONTROL FAILED: problem %d is %q, want one containing %q (all: %v)", index, got[index], fragment, got)
		}
	}
	if fixtureScan.production != 5 || len(fixtureScan.testImporters) != 1 || len(fixtureScan.skipped) != 1 {
		t.Fatalf("CONTROL FAILED: the fixture walk read %d production file(s), %v test importer(s) and "+
			"skipped %v; want 5, the one test file and the one testdata file",
			fixtureScan.production, fixtureScan.testImporters, fixtureScan.skipped)
	}

	// ── THE PROPERTY, OVER THIS MODULE ────────────────────────────────────────────────────────
	scan := sdkCryptoImportsIn(t, os.DirFS("."))
	if scan.production < 30 {
		t.Fatalf("CONTROL FAILED: the walk read %d production file(s) under this module's root, which is "+
			"not this module; an empty answer would mean the walk is wrong and not that the module is clean",
			scan.production)
	}
	if _, ok := scan.found["message_route.go"]; !ok {
		t.Fatalf("CONTROL FAILED: message_route.go's TLS and pin imports were not found, so the walk is " +
			"not reading this module's own files")
	}
	if _, ok := scan.found["liveprobe/main.go"]; !ok {
		t.Fatalf("CONTROL FAILED: liveprobe/main.go's import was not found, so the walk stopped at the " +
			"nested module's go.mod")
	}
	for _, name := range slices.Sorted(maps.Keys(scan.found)) {
		t.Logf("  %-34s %v", name, scan.found[name])
	}
	t.Logf("%d production file(s) read, %d of them import a crypto package", scan.production, len(scan.found))
	t.Logf("COMPLEMENT, not held: %d test file(s) import crypto packages: %v", len(scan.testImporters), scan.testImporters)
	t.Logf("COMPLEMENT, not read: %d .go file(s) under testdata, vendor or dot directories: %v", len(scan.skipped), scan.skipped)
	if problems := sdkCryptoScopeProblems(scan.found, sdkCryptoImports); len(problems) != 0 {
		t.Fatalf("this module's production crypto imports are not the declared set:\n%s", strings.Join(problems, "\n"))
	}
}
