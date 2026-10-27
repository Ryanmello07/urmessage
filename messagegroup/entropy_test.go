// The refusal of a nil entropy source, held where mls cannot hold it.
//
// mls owns the equivalent rule for its own package and derives the class off io.Reader with the
// type checker, but mls may not import this package, so a function declared here that takes an
// entropy source is outside every gate over there that can CALL one. That gap is not left as a
// sentence: mls's TestNoEntropyTakingFunctionLivesWhereThisGateCannotCallIt derives the class
// over this directory by type, requires a row naming the test that holds each member's refusal,
// and resolves that name against this package's own declarations. So the join between the two
// packages is itself a gate, and this file is what that gate points at.
//
// What is being refused matters more than it looks. A nil reader filled in from the process
// source produces a GOOD key -- every behavioural test passes, every round trip works, every
// vector matches -- while every randomness parameter above it becomes decorative, which is
// exactly the defect mls.X25519GenerateKey's own comment records having shipped once: a provider
// built over a nil reader sealed twice under two different ephemeral keys because the draw
// underneath it silently fell back. A fallback onto a deterministic source is the same defect
// with the opposite symptom, and in a key encapsulation it is the worse one.
package messagegroup

import (
	"bytes"
	"crypto/rand"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/message/mls"
)

// The type expression an entropy source is written as in this package's source.
const entropySourceExpression = "io.Reader"

// Every function of this package's own non test source that takes an entropy source.
//
// The class is read off the parameter's TYPE EXPRESSION rather than off the type, which is a
// weaker reading than mls's and is weaker on purpose rather than by oversight: mls's derivation
// is type checked, and it is declared in a _test.go file of that package, so nothing here can
// call it. The two are joined by mls's gate rather than by this comment -- it derives the same
// class over this directory BY TYPE and fails on any member this file has no row for -- so a
// function this reading misses still fails, over there, on the commit that declares it.
//
// A file that does not parse and a directory holding no non test source are both fatal, because
// either one yields an empty class, and an empty class clears every function in the package.
func entropyTakingFunctionsOfThisPackage(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read this package's directory: %v", err)
	}
	fileSet := token.NewFileSet()
	taking := []string{}
	read := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.ToSlash(filepath.Join(".", name))
		parsed, err := parser.ParseFile(fileSet, path, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		read++
		// io under any name would be an alias this reading cannot follow, so it is refused
		// rather than read past
		for _, spec := range parsed.Imports {
			if spec.Path.Value == `"io"` && spec.Name != nil {
				t.Fatalf("%s imports io under the name %s, and this class is read off the expression %q, so it would miss a parameter written any other way",
					path, spec.Name.Name, entropySourceExpression)
			}
		}
		for _, declaration := range parsed.Decls {
			function, isFunction := declaration.(*ast.FuncDecl)
			if !isFunction || function.Type.Params == nil {
				continue
			}
			for _, parameter := range function.Type.Params.List {
				if entropyExpressionText(fileSet, parameter.Type) != entropySourceExpression {
					continue
				}
				taking = append(taking, entropyDeclaredName(function))
				break
			}
		}
	}
	if read == 0 {
		t.Fatal("no non test go file was read out of this package, so the class below is empty and every function in it is cleared")
	}
	slices.Sort(taking)
	return slices.Compact(taking)
}

// The name one declaration is keyed by, in the spelling mls's own gate prints so that a failure
// there and a row here name the same thing.
func entropyDeclaredName(function *ast.FuncDecl) string {
	if function.Recv == nil || len(function.Recv.List) == 0 {
		return function.Name.Name
	}
	return "(" + entropyReceiverName(function.Recv.List[0].Type) + ")." + function.Name.Name
}

func entropyReceiverName(expr ast.Expr) string {
	switch typed := expr.(type) {
	case *ast.Ident:
		return typed.Name
	case *ast.StarExpr:
		return "*" + entropyReceiverName(typed.X)
	case *ast.IndexExpr:
		return entropyReceiverName(typed.X)
	}
	return "?"
}

func entropyExpressionText(fileSet *token.FileSet, expr ast.Expr) string {
	selector, isSelector := expr.(*ast.SelectorExpr)
	if !isSelector {
		return ""
	}
	qualifier, isIdent := selector.X.(*ast.Ident)
	if !isIdent {
		return ""
	}
	return qualifier.Name + "." + selector.Sel.Name
}

// One member of the class, called with the source under test in the entropy position and every
// other argument valid.
//
// The probe is what stops a row being a label: a row asserting that a declaration refuses a nil
// source, on a declaration that panics on one, has to fail, and it does, because the probe runs
// the call.
var entropyRefusalProbes = map[string]func(t *testing.T, random io.Reader) error{
	"NewPqSecret": func(t *testing.T, random io.Reader) error {
		t.Helper()
		_, err := NewPqSecret(random)
		return err
	},
	// eph_root's draw, and the row landed because the class above went and found it: this
	// gate failed on the commit that declared NewEphRoot, naming it as a member with no
	// probe. That is the whole reason the class is derived off the syntax tree -- MASTER
	// section 8.1 calls a derived eph_root "the most easily broken property here", and a
	// draw that silently accepted a nil or an exhausted source would answer thirty two zero
	// octets that every member of the group agrees on.
	"NewEphRoot": func(t *testing.T, random io.Reader) error {
		t.Helper()
		_, err := NewEphRoot(random)
		return err
	},
	"XwingGenerateKey": func(t *testing.T, random io.Reader) error {
		t.Helper()
		_, err := XwingGenerateKey(random)
		return err
	},
	"XwingEncapsulate": func(t *testing.T, random io.Reader) error {
		t.Helper()
		priv, err := XwingGenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("generate a key to encapsulate to: %v", err)
		}
		_, _, err = XwingEncapsulate(random, priv.Public())
		return err
	},
	// The device wrap's two sealing doors. Neither DRAWS -- both hand the reader straight to
	// XwingEncapsulate, which is the row above -- and both are members of this class anyway,
	// because the class is derived from the signature and the hazard is the caller's: a door
	// that reached crypto/rand when the reader it was handed ran dry would seal a wrap whose
	// randomness parameter is decoration, which is the substitution xwing.go's own refusal
	// argues at length. The rows exist so that a later body which drew its own entropy rather
	// than delegating is judged here on the commit that writes it.
	"SealWrapBody": func(t *testing.T, random io.Reader) error {
		t.Helper()
		priv, err := XwingGenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("generate a key to seal to: %v", err)
		}
		_, err = SealWrapBody(random, priv.Public(),
			WrapEnvelope{FormatVersion: WrapFormatVersion, TargetType: 1, PayloadType: 1, ContentEpoch: 1},
			bytes.Repeat([]byte{0x21}, 32), bytes.Repeat([]byte{0x71}, 16), bytes.Repeat([]byte{0x11}, 32))
		return err
	},
	"SealDeviceWraps": func(t *testing.T, random io.Reader) error {
		t.Helper()
		priv, err := XwingGenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("generate a key to seal to: %v", err)
		}
		_, _, err = SealDeviceWraps(random, priv.Public(), 1, 1,
			bytes.Repeat([]byte{0x21}, 32), bytes.Repeat([]byte{0x71}, 16),
			1, bytes.Repeat([]byte{0x11}, 32), 2, bytes.Repeat([]byte{0x22}, 32))
		return err
	},
}

// TestEveryEntropyTakingFunctionOfThisPackageRefusesANilSource is the test mls's residual table
// names, and it holds the probes above to the derived class in both directions first, because a
// probe table that has fallen behind the package is a gate reporting a clean bill over a
// function nobody runs.
func TestEveryEntropyTakingFunctionOfThisPackageRefusesANilSource(t *testing.T) {
	declared := entropyTakingFunctionsOfThisPackage(t)
	if len(declared) == 0 {
		t.Fatal("this package declares no function taking an entropy source, so mls's residual table has rows for a tree that no longer exists and this test holds nothing")
	}
	probed := slices.Sorted(maps.Keys(entropyRefusalProbes))
	if !slices.Equal(declared, probed) {
		t.Fatalf("this package declares %v taking an entropy source and this file probes %v; every member of the class has to be run, and a probe with no declaration is describing a tree that no longer exists",
			declared, probed)
	}

	for _, name := range probed {
		// nil, which without a guard is a nil interface dereference rather than a refusal
		err := entropyRefusalProbes[name](t, nil)
		if err == nil {
			t.Errorf("%s accepted a nil entropy source; a key drawn from the process source behind the caller's back is a good key, which is why nothing else would notice",
				name)
			continue
		}
		if !errors.Is(err, mls.ErrNilRandomSource) {
			t.Errorf("%s refused a nil entropy source with %v, want mls.ErrNilRandomSource; one condition gets one sentinel so a caller can match it with one errors.Is",
				name, err)
		}
	}
}

// The other shape of the same substitution: a source that is present and empty. A function that
// answered a read failure by falling back would pass the rule above, because the key it produced
// would be a good key.
func TestEveryEntropyTakingFunctionOfThisPackageRefusesAnExhaustedSource(t *testing.T) {
	declared := entropyTakingFunctionsOfThisPackage(t)
	probed := slices.Sorted(maps.Keys(entropyRefusalProbes))
	if !slices.Equal(declared, probed) {
		t.Fatalf("this package declares %v taking an entropy source and this file probes %v", declared, probed)
	}
	for _, name := range probed {
		if err := entropyRefusalProbes[name](t, bytes.NewReader(nil)); err == nil {
			t.Errorf("%s drew from an exhausted source and produced a result anyway, so it reached some other source when the caller's ran dry", name)
		}
	}
}

// The control on the class reader, so a matcher that stopped matching fails here rather than
// reporting a package with no entropy taking function in it.
//
// It is run over synthetic source rather than over this package, for the reason mls's own
// control is: a reader that found the two real functions because it found everything would pass
// a test that only counted them.
func TestTheEntropyClassReaderSeparatesTheControlShapes(t *testing.T) {
	const control = `package control

import (
	"io"
	"bytes"
)

type holder struct{}

func TakesOne(random io.Reader) error { return nil }

func (self *holder) AlsoTakesOne(a int, random io.Reader) error { return nil }

func TakesNone(b *bytes.Buffer) error { return nil }

func TakesAWriter(w io.Writer) error { return nil }
`
	fileSet := token.NewFileSet()
	parsed, err := parser.ParseFile(fileSet, "control.go", control, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse the control: %v", err)
	}
	found := []string{}
	for _, declaration := range parsed.Decls {
		function, isFunction := declaration.(*ast.FuncDecl)
		if !isFunction || function.Type.Params == nil {
			continue
		}
		for _, parameter := range function.Type.Params.List {
			if entropyExpressionText(fileSet, parameter.Type) != entropySourceExpression {
				continue
			}
			found = append(found, entropyDeclaredName(function))
			break
		}
	}
	slices.Sort(found)
	if want := []string{"(*holder).AlsoTakesOne", "TakesOne"}; !slices.Equal(found, want) {
		t.Errorf("the class read %v out of the control, want %v; io.Writer and a concrete reader are not entropy sources and a method taking one is", found, want)
	}
}

// ══════════════════════════════════════════════════════════════════════════════════════════════
// THE PROCESS-ENTROPY DRAWS: EXACTLY ONE, THE RECOVERY PHRASE'S
// ══════════════════════════════════════════════════════════════════════════════════════════════
//
// Every draw this package makes takes an injected io.Reader -- the class above -- but one.
// NewRecoveryPhrase draws P34 from the process source, because MASTER section 5.1 says no call
// takes its entropy from its caller (LRI R65 item 2 accepted the design; the review of identity
// phase 1's Tasks 8 to 10, L2-09, found no gate holding it). This package does not import
// crypto/rand -- the import gate's ban, whose reason names this one exception -- so a draw from
// the process source can only come through a provider mls builds over it: mls.NewCryptoProvider.
//
// THE CLASS IS DERIVED. A process provider is a name this package's production source binds to
// mls.NewCryptoProvider's answer, package level or local, or to the answer of a function of this
// package that returns one (mustPhraseDraw, mustKeyScheduleCrypto). A DRAW is a call that makes
// such a provider read its source: Random, SignatureKeyPair or HpkeSeal, the three methods of mls's
// provider that read it (mls/crypto.go and mls/crypto_labels.go). A HAND-OFF is such a provider
// passed to any function, which may draw where this file cannot see. Both sets are held, both
// ways, against the tables below; the second draw the review's mutants made -- spelled Random in a
// new function, and SignatureKeyPair in withPhraseKeys -- is each a draw outside the table.
// TestTheProcessEntropyReadingSeparatesTheControlShapes is the reading's control.

// The functions that draw from the process source, with what they draw.
var processEntropyDraws = map[string]string{
	"NewRecoveryPhrase": "P34, 34 octets of MASTER section 5.1's only source of P: a recovery phrase takes no " +
		"entropy from its caller, so no caller can hand it a weak source",
}

// The hand-offs of a process provider, by enclosing function and callee, with why each draws
// nothing.
var processEntropyHandoffs = map[string]string{
	"peekWithGroupSecrets|mls.PeekPrivateMessageSender": "a provider for the suite of a group context, " +
		"handed to mls to decrypt a frame's sender data; it opens and verifies, and draws nothing",
}

// The three methods of mls's provider that read its source.
var processEntropyDrawingMethods = map[string]bool{"Random": true, "SignatureKeyPair": true, "HpkeSeal": true}

// processEntropyReading reads the draws and hand-offs out of parsed production files: draws as
// "<function>" -> the calls, hand-offs as "<function>|<callee>" -> the calls.
func processEntropyReading(files []*ast.File) (map[string][]string, map[string][]string) {
	constructs := func(call *ast.CallExpr) bool {
		selector, qualified := call.Fun.(*ast.SelectorExpr)
		if !qualified {
			return false
		}
		root, named := selector.X.(*ast.Ident)
		return named && root.Name == "mls" && selector.Sel.Name == "NewCryptoProvider"
	}
	// the names a function body binds to a provider's construction
	boundIn := func(body ast.Node, builders map[string]bool) map[string]bool {
		bound := map[string]bool{}
		bind := func(targets []ast.Expr, values []ast.Expr) {
			if len(values) != 1 {
				return
			}
			call, isCall := values[0].(*ast.CallExpr)
			if !isCall {
				return
			}
			builder, bare := call.Fun.(*ast.Ident)
			if !constructs(call) && !(bare && builders[builder.Name]) {
				return
			}
			if 0 < len(targets) {
				if name, ok := targets[0].(*ast.Ident); ok {
					bound[name.Name] = true
				}
			}
		}
		ast.Inspect(body, func(node ast.Node) bool {
			switch shape := node.(type) {
			case *ast.AssignStmt:
				bind(shape.Lhs, shape.Rhs)
			case *ast.ValueSpec:
				targets := []ast.Expr{}
				for _, name := range shape.Names {
					targets = append(targets, name)
				}
				bind(targets, shape.Values)
			}
			return true
		})
		return bound
	}
	// the functions of this package that answer a provider they built
	builders := map[string]bool{}
	for _, file := range files {
		for _, declaration := range file.Decls {
			function, isFunction := declaration.(*ast.FuncDecl)
			if !isFunction || function.Body == nil {
				continue
			}
			locals := boundIn(function.Body, nil)
			ast.Inspect(function.Body, func(node ast.Node) bool {
				answer, isReturn := node.(*ast.ReturnStmt)
				if !isReturn || len(answer.Results) == 0 {
					return true
				}
				if name, ok := answer.Results[0].(*ast.Ident); ok && locals[name.Name] {
					builders[function.Name.Name] = true
				}
				return true
			})
		}
	}
	// the package-level providers
	global := map[string]bool{}
	for _, file := range files {
		for _, declaration := range file.Decls {
			general, isGeneral := declaration.(*ast.GenDecl)
			if !isGeneral || general.Tok != token.VAR {
				continue
			}
			for name := range boundIn(general, builders) {
				global[name] = true
			}
		}
	}
	draws, handoffs := map[string][]string{}, map[string][]string{}
	for _, file := range files {
		for _, declaration := range file.Decls {
			function, isFunction := declaration.(*ast.FuncDecl)
			if !isFunction || function.Body == nil {
				continue
			}
			providers := boundIn(function.Body, builders)
			for name := range global {
				providers[name] = true
			}
			where := function.Name.Name
			ast.Inspect(function.Body, func(node ast.Node) bool {
				call, isCall := node.(*ast.CallExpr)
				if !isCall {
					return true
				}
				if selector, isMethod := call.Fun.(*ast.SelectorExpr); isMethod {
					if receiver, named := selector.X.(*ast.Ident); named && providers[receiver.Name] &&
						processEntropyDrawingMethods[selector.Sel.Name] {
						draws[where] = append(draws[where], receiver.Name+"."+selector.Sel.Name)
					}
				}
				for _, argument := range call.Args {
					if name, named := argument.(*ast.Ident); named && providers[name.Name] {
						callee := censusSpelling(call.Fun)
						handoffs[where+"|"+callee] = append(handoffs[where+"|"+callee], name.Name)
					}
				}
				return true
			})
		}
	}
	return draws, handoffs
}

func TestThisPackagesOnlyProcessEntropyDrawIsTheRecoveryPhrases(t *testing.T) {
	_, sources := messagegroupProductionSources(t)
	files := []*ast.File{}
	for _, source := range sources {
		files = append(files, source.parsed)
	}
	draws, handoffs := processEntropyReading(files)
	t.Logf("process-entropy draws: %v; hand-offs of a process provider: %v", draws, handoffs)
	for where := range draws {
		if _, listed := processEntropyDraws[where]; !listed {
			t.Errorf("%s draws from the process source (%v) and processEntropyDraws does not list it: every draw here takes an injected io.Reader but NewRecoveryPhrase's", where, draws[where])
		}
	}
	for where := range processEntropyDraws {
		if _, found := draws[where]; !found {
			t.Errorf("processEntropyDraws lists %s and it draws from the process source nowhere: the draw moved or the reading has gone blind", where)
		}
	}
	for site := range handoffs {
		if _, listed := processEntropyHandoffs[site]; !listed {
			t.Errorf("%s hands a process provider to a function (%v) and processEntropyHandoffs does not list it: it may draw where this file cannot see", site, handoffs[site])
		}
	}
	for site := range processEntropyHandoffs {
		if _, found := handoffs[site]; !found {
			t.Errorf("processEntropyHandoffs lists %s and the reading does not find it", site)
		}
	}
}

// The reading's control: a provider built through a function, a draw in NewRecoveryPhrase, a
// second draw spelled SignatureKeyPair, a local provider handed to mls, and a provider built over
// a caller's reader, which is no process provider and draws nothing this gate owns.
const processEntropyControl = `package control

var draw = mustDraw()

func mustDraw() mls.CryptoProvider {
	crypto, err := mls.NewCryptoProvider(1)
	if err != nil {
		panic(err)
	}
	return crypto
}

func NewRecoveryPhrase() []byte { return draw.Random(34) }

func other() { _, _, _ = draw.SignatureKeyPair() }

func handed(frame []byte) {
	local, _ := mls.NewCryptoProvider(1)
	_, _ = mls.Open(local, frame)
}

func injected(random io.Reader) []byte {
	provider, _ := mls.NewCryptoProviderWithRandom(1, random)
	return provider.Random(4)
}
`

func TestTheProcessEntropyReadingSeparatesTheControlShapes(t *testing.T) {
	parsed, err := parser.ParseFile(token.NewFileSet(), "control.go", processEntropyControl, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	draws, handoffs := processEntropyReading([]*ast.File{parsed})
	if got := slices.Sorted(maps.Keys(draws)); !slices.Equal(got, []string{"NewRecoveryPhrase", "other"}) {
		t.Errorf("the reading found draws in %v over the control; want NewRecoveryPhrase and other, the second spelled SignatureKeyPair", got)
	}
	if got := slices.Sorted(maps.Keys(handoffs)); !slices.Equal(got, []string{"handed|mls.Open"}) {
		t.Errorf("the reading found hand-offs %v over the control; want the local provider handed to mls.Open", got)
	}
}
