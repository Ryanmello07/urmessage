package urmessage

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strings"
	"testing"
)

// ══════════════════════════════════════════════════════════════════════════════════════════════
// THE CENSUS ENGINE THE KEY-MATERIAL GATES IN THIS PACKAGE SHARE
// ══════════════════════════════════════════════════════════════════════════════════════════════
//
// WHY THIS FILE EXISTS, AND IT IS THE SAME FINDING TWICE. This package now holds three dataflow
// censuses over three different kinds of key material -- the epoch keys, the device's X-Wing seed,
// and `pq_secret` -- and the first two were written by COPYING the predicate out of the one before
// it. The wrap-seed gate's own header says so in as many words: "its scar is copied here rather
// than relearned". A third hand-copy is a third chance to copy a scar WRONG, and a scar copied
// wrong is a gate that passes by asking a narrower question than the one it prints.
//
// SO THE PREDICATE IS ONE FUNCTION AND THE NETS ARE THREE. [censusBorneBy] takes the producer net
// as an argument instead of reading a package-level map, which is the whole of the change; every
// clause inside it, and every scar below, is the wrap-seed gate's verbatim.
//
// THE THREE SCARS, each of which was a gate defeated in this repository and none of which is
// hypothetical:
//
//   - A CENSUS MUST MATCH THE VALUE AND NOT THE FIELD NAME. A nested type that spelled the epoch
//     keys `wk`/`rk` walked past a gate keyed on strings.
//   - EVERY LANDING PLACE IS ASKED FOR AN EXPRESSION AND NEVER FOR AN *ast.Ident. `x = writeKey[:]`
//     was censused as NOTHING AT ALL -- not refused, absent -- because the sink clause read a bare
//     identifier and a slice expression is not one.
//   - EVERY BINDING FORM THE LANGUAGE HAS. `var leaked = writeKey` bound nothing while the
//     fixpoint read *ast.AssignStmt alone, so the taint stopped at the first `var`.
//
// AND ONE PROPERTY OF THE ENGINE ITSELF, which is why [censusHold] refuses an EMPTY census: a
// search that has stopped reading its own subject finds nothing, refuses nothing, and reports
// success. Every gate below is held both ways against a written-down disposition for the same
// reason -- a site with no entry is a value nobody weighed, and an entry with no site is the gate
// having gone blind.
//
// A SECOND COPY, AND A TEST THAT HOLDS THE TWO AS ONE (LRI R68). messagegroup/census_test.go
// carries this engine for the phrase-secret census -- a _test.go file cannot be imported across
// packages -- and from censusHold to the end of runCensus the two are identical but for two
// renames: stateTestProductionSources and epochKeyExpr are censusProductionSources and
// censusSpelling there. messagegroup's TestTheTwoCensusEnginesAreOneEngine holds that, so a change
// to this region is a change to both, made in one commit.

// censusHold is the both-directions assertion every census in this package shares.
func censusHold(t *testing.T, what string, found map[string][]string,
	disposition map[string]string, why string) {

	t.Helper()
	if len(found) == 0 {
		t.Errorf("this gate found no %s at all in %d production files. An empty census passes every "+
			"refusal below by having nothing to refuse, which is how a search that has stopped "+
			"reading its own subject reports success.", what, len(stateTestProductionSources(t)))
	}
	for site := range found {
		reason, dispositioned := disposition[site]
		if !dispositioned {
			t.Errorf("%s %q has no entry in the disposition.\n%s", what, site, why)
			continue
		}
		t.Logf("    %s %s is allowed: %s", what, site, reason)
	}
	for site := range disposition {
		if _, ok := found[site]; !ok {
			t.Errorf("the disposition says %s %q is allowed and the census does not find it.\n%s",
				what, site, why)
		}
	}
}

// censusHoldOccurrences is the third direction a sink is held in: its OCCURRENCES, each spelled the
// way the source spells the value that landed there and without its line, as a multiset, against the
// ones its disposition lists. Both ways, so an occurrence added and an occurrence gone both fail.
//
// THE SITE AND ITS CARRIED SET WERE NOT ENOUGH, and the difference was measured (the review of
// identity phase 1's Tasks 8 to 10, L2-01). A sink is keyed by its function and its callee, and its
// carried set is a union, so a second copy of P34 into package storage, in a function that already
// copied P34 once, changed neither: the census and both packages passed while P34 outlived Erase. An
// occurrence count is what moves.
//
// A site this disposition does not hold is censusHold's to report, not this function's.
func censusHoldOccurrences(t *testing.T, found map[string][]string, listed map[string][]string, why string) {
	t.Helper()
	for site, occurrences := range found {
		want, dispositioned := listed[site]
		if !dispositioned {
			continue
		}
		got := append([]string(nil), occurrences...)
		wanted := append([]string(nil), want...)
		sort.Strings(got)
		sort.Strings(wanted)
		if strings.Join(got, "\x00") != strings.Join(wanted, "\x00") {
			t.Errorf("sink site %q occurs as %q and its disposition lists %q. A sink holds its "+
				"occurrences, not only its key and the union of what it carries: an occurrence that "+
				"arrived is a value landing there again, and one that went is a fix nobody wrote down.\n%s",
				site, got, wanted, why)
		}
	}
}

// censusScope is what the one predicate needs to know about the function an expression is in.
type censusScope struct {
	// every name the function declares, for the `len` exclusion's shadowing question
	local map[string]bool
	// the gate's producer net
	producers map[string]bool
	// the package's own map types, by name
	mapTypes map[string]bool
	// each composite literal's type, the one it spells or the one its enclosing literal implies
	literalTypes map[*ast.CompositeLit]ast.Expr
}

// censusBorneBy is THE ONE QUESTION a census asks of an expression: which values from `producers`
// does it bear? It answers the tainted identifiers, the producer calls and the producer field
// reads anywhere inside the expression, spelled the way the source spells them, and the taint step
// and every sink clause run it.
//
// ONE PREDICATE ASKED IN EVERY POSITION IS THE POINT. The defect the epoch-key gate took at
// 4fde7ad was two positions asking a narrower question than the taint step did, so a value the
// walk was following landed somewhere the walk did not count.
//
// `producers` IS A PARAMETER AND USED TO BE A PACKAGE-LEVEL MAP. That is what lets the gates share
// the scars instead of each copying them.
//
// A MAP LITERAL'S KEYS ARE VALUES, and a struct literal's keys are field names. A key that is a bare
// identifier was skipped as a field name everywhere until the review of identity phase 1's Tasks 8
// to 10 kept a typed word's index as the key of a map literal and the census passed (L2-02); so a
// literal whose type, spelled or implied by the literal around it, is a map has its keys asked too.
func censusBorneBy(expression ast.Expr, tainted map[string]bool, intoLiterals bool,
	scope censusScope) []string {

	if expression == nil {
		return nil
	}
	borne := []string{}
	seen := map[string]bool{}
	carry := func(spelled string) {
		if !seen[spelled] {
			seen[spelled] = true
			borne = append(borne, spelled)
		}
	}
	recurse := func(inner ast.Expr) {
		for _, spelled := range censusBorneBy(inner, tainted, intoLiterals, scope) {
			carry(spelled)
		}
	}
	ast.Inspect(expression, func(node ast.Node) bool {
		switch shape := node.(type) {
		case *ast.CallExpr:
			if censusIsBuiltinLen(shape, scope.local) {
				return false
			}
			named := censusCalleeName(shape.Fun)
			if named != "" && scope.producers[named] {
				carry(censusExpr(shape.Fun))
				// the callee is the producer's own name; only its arguments are values
				for _, argument := range shape.Args {
					recurse(argument)
				}
				return false
			}
		case *ast.SelectorExpr:
			if scope.producers[shape.Sel.Name] {
				carry(censusExpr(shape))
			}
			recurse(shape.X)
			return false
		case *ast.KeyValueExpr:
			if _, named := shape.Key.(*ast.Ident); named {
				recurse(shape.Value)
				return false
			}
		case *ast.CompositeLit:
			if !intoLiterals {
				return false
			}
			if censusIsMapType(scope.literalTypes[shape], scope.mapTypes) {
				for _, element := range shape.Elts {
					if pair, isPair := element.(*ast.KeyValueExpr); isPair {
						recurse(pair.Key)
						recurse(pair.Value)
						continue
					}
					recurse(element)
				}
				return false
			}
		case *ast.FuncLit:
			if !intoLiterals {
				return false
			}
		case *ast.Ident:
			if tainted[shape.Name] {
				carry(shape.Name)
			}
		}
		return true
	})
	sort.Strings(borne)
	return borne
}

// censusIsMapType answers whether a type expression is a map: spelled as one, or naming one of the
// package's own map types.
func censusIsMapType(spelled ast.Expr, mapTypes map[string]bool) bool {
	switch shape := spelled.(type) {
	case *ast.MapType:
		return true
	case *ast.Ident:
		return mapTypes[shape.Name]
	case *ast.ParenExpr:
		return censusIsMapType(shape.X, mapTypes)
	}
	return false
}

// censusMapTypeNames is every map type the package declares by name.
func censusMapTypeNames(files []censusFile) map[string]bool {
	names := map[string]bool{}
	for _, file := range files {
		for _, declaration := range file.parsed.Decls {
			general, isGeneral := declaration.(*ast.GenDecl)
			if !isGeneral || general.Tok != token.TYPE {
				continue
			}
			for _, spec := range general.Specs {
				if named, isType := spec.(*ast.TypeSpec); isType && censusIsMapType(named.Type, nil) {
					names[named.Name.Name] = true
				}
			}
		}
	}
	return names
}

// censusLiteralTypes is each composite literal's type within one body: the one it spells, or, for
// a literal written without one, the one the literal around it implies -- a map's key or value
// type, a slice's or an array's element type. A literal whose type can be neither read nor implied
// answers nil, and is read as a struct's.
func censusLiteralTypes(root ast.Node) map[*ast.CompositeLit]ast.Expr {
	effective := map[*ast.CompositeLit]ast.Expr{}
	if root == nil {
		return effective
	}
	ast.Inspect(root, func(node ast.Node) bool {
		literal, isLiteral := node.(*ast.CompositeLit)
		if !isLiteral {
			return true
		}
		own := literal.Type
		if own == nil {
			own = effective[literal]
		}
		effective[literal] = own
		var keyType, elementType ast.Expr
		switch shape := own.(type) {
		case *ast.MapType:
			keyType, elementType = shape.Key, shape.Value
		case *ast.ArrayType:
			elementType = shape.Elt
		}
		imply := func(expression ast.Expr, implied ast.Expr) {
			if unary, isUnary := expression.(*ast.UnaryExpr); isUnary {
				expression = unary.X
			}
			if inner, isInner := expression.(*ast.CompositeLit); isInner && inner.Type == nil && implied != nil {
				if star, isStar := implied.(*ast.StarExpr); isStar {
					implied = star.X
				}
				effective[inner] = implied
			}
		}
		for _, element := range literal.Elts {
			if pair, isPair := element.(*ast.KeyValueExpr); isPair {
				imply(pair.Key, keyType)
				imply(pair.Value, elementType)
				continue
			}
			imply(element, elementType)
		}
		return true
	})
	return effective
}

// censusIsBuiltinLen answers whether this call is the builtin `len` and not some local of that
// name. A function that declared `len` would otherwise turn the one exclusion of [censusBorneBy]
// into a hole, from inside the source the gate inspects.
func censusIsBuiltinLen(call *ast.CallExpr, local map[string]bool) bool {
	identifier, bare := call.Fun.(*ast.Ident)
	return bare && identifier.Name == "len" && !local["len"] && len(call.Args) == 1
}

// censusCalleeName is the last name of a callee, bare or qualified: `deviceIdentity` and
// `xwing.Seed` both answer their own final name. A net that read selectors alone could not see a
// package-local helper called by its bare name.
func censusCalleeName(callee ast.Expr) string {
	switch shape := callee.(type) {
	case *ast.Ident:
		return shape.Name
	case *ast.SelectorExpr:
		return shape.Sel.Name
	case *ast.ParenExpr:
		return censusCalleeName(shape.X)
	}
	return ""
}

// censusRootName is the identifier an expression is rooted at, or "" for an expression with no
// single root -- a call, a literal, an arithmetic. It is what the producer-function seeding binds:
// `parts[3]` is rooted at `parts` and `leafKeys.ExtensionData` at `leafKeys`. A SELECTOR whose
// field is itself in the producer net has no root here, because the field read is a producer in
// its own right and seeding its receiver would taint the whole of `self`.
func censusRootName(expression ast.Expr, producers map[string]bool) string {
	switch shape := expression.(type) {
	case *ast.Ident:
		return shape.Name
	case *ast.ParenExpr:
		return censusRootName(shape.X, producers)
	case *ast.IndexExpr:
		return censusRootName(shape.X, producers)
	case *ast.SliceExpr:
		return censusRootName(shape.X, producers)
	case *ast.StarExpr:
		return censusRootName(shape.X, producers)
	case *ast.UnaryExpr:
		return censusRootName(shape.X, producers)
	case *ast.SelectorExpr:
		if producers[shape.Sel.Name] {
			return ""
		}
		return censusRootName(shape.X, producers)
	}
	return ""
}

// censusExpr spells an expression the way the source does, so a census entry reads as the code
// reads. It is [epochKeyExpr] with the INDEX kept -- `parts[3]` rather than `parts` -- because a
// store's read path spells a key as one part of a generic record, and a census that printed
// `parts` four times over would name the same site for four different values.
func censusExpr(expression ast.Expr) string {
	if index, ok := expression.(*ast.IndexExpr); ok {
		return censusExpr(index.X) + "[" + censusExpr(index.Index) + "]"
	}
	return epochKeyExpr(expression)
}

// censusImportNames is the identifiers a FILE qualifies a package by, so that `fmt.Errorf` and
// `messagegroup.XwingKeyGenFromSeed` are told apart from `temp.Write` by reading the file's
// imports rather than by guessing at a spelling. An aliased import answers its alias; anything
// else answers the last element of its path, which is what the language resolves the qualifier to.
func censusImportNames(parsed *ast.File) map[string]bool {
	names := map[string]bool{}
	for _, one := range parsed.Imports {
		if one.Name != nil {
			names[one.Name.Name] = true
			continue
		}
		path := strings.Trim(one.Path.Value, "\"")
		if at := strings.LastIndex(path, "/"); 0 <= at {
			path = path[at+1:]
		}
		names[path] = true
	}
	return names
}

// censusReseedingFunctions is every function this package DECLARES whose own parameters or named
// results carry a name in `producers` -- which is to say, every function a taint walk starts again
// inside rather than stopping at.
//
// IT IS READ OFF THE SIGNATURES AND NOT LISTED, because a list would be a second spelling of the
// producer net and would drift from it silently.
func censusReseedingFunctions(t *testing.T, producers map[string]bool) map[string]bool {
	t.Helper()
	reseeds := map[string]bool{}
	fileSet := token.NewFileSet()
	for _, name := range stateTestProductionSources(t) {
		parsed, err := parser.ParseFile(fileSet, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, declaration := range parsed.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok {
				continue
			}
			for _, fields := range []*ast.FieldList{function.Type.Params, function.Type.Results} {
				if fields == nil {
					continue
				}
				for _, field := range fields.List {
					for _, target := range field.Names {
						if producers[target.Name] {
							reseeds[function.Name.Name] = true
						}
					}
				}
			}
		}
	}
	if len(reseeds) == 0 {
		t.Fatal("no production function in this package re-seeds this walk, so a horizon census " +
			"would call every call into this package's own store a stopping place")
	}
	return reseeds
}

// censusLocalNames is every name a function declares: its receiver, its parameters, its named
// results, and every `:=`, `var` and `range` binding in its body.
//
// TWO CLAUSES NEED IT AND THEY NEED IT FOR OPPOSITE REASONS. A bare name on the left of an
// assignment is a REBINDING when this function declared it and a SINK when it did not, because a
// name that outlives the call parks a key for the lifetime of whatever holds it. And the `len`
// exclusion asks this map whether the builtin has been SHADOWED, because a local named `len` would
// turn one clause of every gate off from inside the source it inspects.
func censusLocalNames(function *ast.FuncDecl) (map[string]bool, string) {
	local := map[string]bool{"_": true}
	receiver := ""
	declare := func(fields *ast.FieldList) {
		if fields == nil {
			return
		}
		for _, field := range fields.List {
			for _, target := range field.Names {
				local[target.Name] = true
			}
		}
	}
	declare(function.Recv)
	if function.Recv != nil && 0 < len(function.Recv.List) &&
		0 < len(function.Recv.List[0].Names) {
		receiver = function.Recv.List[0].Names[0].Name
	}
	declare(function.Type.Params)
	declare(function.Type.Results)
	ast.Inspect(function.Body, func(node ast.Node) bool {
		switch shape := node.(type) {
		case *ast.AssignStmt:
			if shape.Tok == token.DEFINE {
				for _, target := range shape.Lhs {
					if identifier, ok := target.(*ast.Ident); ok {
						local[identifier.Name] = true
					}
				}
			}
		case *ast.ValueSpec:
			for _, target := range shape.Names {
				local[target.Name] = true
			}
		case *ast.RangeStmt:
			if shape.Tok == token.DEFINE {
				for _, target := range []ast.Expr{shape.Key, shape.Value} {
					if identifier, ok := target.(*ast.Ident); ok {
						local[identifier.Name] = true
					}
				}
			}
		case *ast.FuncLit:
			declare(shape.Type.Params)
			declare(shape.Type.Results)
		}
		return true
	})
	return local, receiver
}

// censusFile is one production file, parsed once for the whole walk.
type censusFile struct {
	name     string
	fileSet  *token.FileSet
	parsed   *ast.File
	imported map[string]bool
}

// censusParameterNames is a declaration's parameters by position, a variadic last one standing
// for every position from its own on. A parameter written _ or with no name answers "".
func censusParameterNames(function *ast.FuncDecl) ([]string, bool) {
	names := []string{}
	variadic := false
	if function.Type.Params == nil {
		return names, variadic
	}
	for _, field := range function.Type.Params.List {
		_, variadic = field.Type.(*ast.Ellipsis)
		if len(field.Names) == 0 {
			names = append(names, "")
			continue
		}
		for _, name := range field.Names {
			if name.Name == "_" {
				names = append(names, "")
				continue
			}
			names = append(names, name.Name)
		}
	}
	return names, variadic
}

// censusResult is everything one run of [runCensus] saw, in the shapes the gates assert against:
// where the value is BORN, where it LANDS, what it carries there and each time it lands, what the
// one narrowing REMOVED, where the walk STOPS KNOWING, and which tainted names reached nothing.
type censusResult struct {
	sources []string

	// "<enclosing function>|<site>" -> the file:line list, for each of the five censuses.
	producers   map[string][]string
	sinks       map[string][]string
	counted     map[string][]string
	accumulated map[string][]string

	// per sink site, the VALUE SPELLINGS that landed there. A disposition keyed on the site alone
	// excuses the site FOREVER, whatever turns up there later, so every gate holds this too.
	carried map[string]map[string]bool

	// per sink site, each OCCURRENCE, spelled as the value that landed and without its line: a
	// second landing of a value the site already carries moves this and nothing else
	// (censusHoldOccurrences).
	occurrences map[string][]string

	// tainted names that reached no sink in their own function, printed as the honest complement:
	// excluded is not the same as absent.
	unspent map[string][]string
}

// runCensus is the taint walk the key-material gates in this package share.
//
// WHAT IT IS AND WHAT IT IS NOT. It is a four-producer, fixpoint, expression-level walk over every
// production source in this package, and it decides NOTHING: it collects the censuses and hands
// them back, and every refusal is the caller's, held against that gate's own written-down
// disposition. A gate is its NET and its DISPOSITIONS; this function is the machinery under them.
//
// WHY IT IS ONE FUNCTION. The first two gates were written by copying the predicate out of the one
// before -- see [censusBorneBy] for the three scars that copy carries -- and the third would have
// been a third copy. Three copies of a walk is three chances to weaken one of them silently, and
// the wrap-seed gate's own mutation table is what proves this walk still kills what it killed.
//
// IT FOLLOWS A VALUE INTO THIS PACKAGE'S OWN FUNCTIONS. A walk that started again only inside a
// function whose parameter NAMES were in the net was blind inside every other one: a phrase secret
// handed to keyScheduleExtract, keyScheduleExpand or zeroize, whose parameters are ikm, prk and
// secret, was a sink at the call and nothing at all inside, so a copy kept there passed (the review
// of identity phase 1's Tasks 8 to 10, L1-1, with three one-line mutants and every gate green). So a
// call of a function or method this package declares, handed a value the walk follows, taints the
// parameter at that position, and the callee is walked with it, to a fixpoint across the package.
// Such a parameter is a producer site of its callee, "parameter <name>", as a net-named one is.
//
// THE EXAMPLES IN THE COMMENTS BELOW ARE THE SEED GATE'S, because that is the gate this body was
// lifted from and a generic example would say less. They are illustrations of the CLAUSE, never a
// statement that the seed's net is the only one.
func runCensus(t *testing.T, net map[string]bool) censusResult {
	t.Helper()
	producers := map[string][]string{}
	sinks := map[string][]string{}
	carried := map[string]map[string]bool{}
	occurrences := map[string][]string{}
	counted := map[string][]string{}
	accumulated := map[string][]string{}
	unspent := map[string][]string{}

	// the functions the walk STARTS AGAIN inside, read off their own signatures rather than
	// listed: this is what tells the horizon census below that `self.writeRecord(…, wrapSeed)` is
	// not a place the walk stops.
	reseeds := censusReseedingFunctions(t, net)

	sources := stateTestProductionSources(t)
	files := []censusFile{}
	for _, name := range sources {
		content, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		fileSet := token.NewFileSet()
		parsed, err := parser.ParseFile(fileSet, name, content, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		files = append(files, censusFile{name: name, fileSet: fileSet, parsed: parsed, imported: censusImportNames(parsed)})
	}
	mapTypes := censusMapTypeNames(files)

	// every function and method this package declares, by name, with its parameters by position:
	// what a call this walk follows lands in
	declared := map[string][]*ast.FuncDecl{}
	for _, file := range files {
		for _, declaration := range file.parsed.Decls {
			if function, ok := declaration.(*ast.FuncDecl); ok && function.Body != nil {
				declared[function.Name.Name] = append(declared[function.Name.Name], function)
			}
		}
	}

	// THE TAINT OF ONE FUNCTION: its seeds, and every binding form the language has, to a
	// fixpoint. `var x = wrapSeed` and `for _, b := range wrapSeed` bind here exactly as
	// `x := wrapSeed` does: the epoch-key gate was defeated by the first of those three spellings
	// and its scar is copied here rather than relearned. Seeded by a parameter the net names, a
	// parameter a tainted argument reaches (handed), and a result of a function the net names.
	type censusSeed struct {
		site string
		at   ast.Node
	}
	taintOf := func(function *ast.FuncDecl, handed map[string]map[string]bool, scope censusScope,
		receiver string) (map[string]bool, map[string]censusSeed) {

		tainted := map[string]bool{}
		seeds := map[string]censusSeed{}
		where := function.Name.Name
		for _, fields := range []*ast.FieldList{function.Type.Params, function.Type.Results} {
			if fields == nil {
				continue
			}
			for _, field := range fields.List {
				for _, target := range field.Names {
					if net[target.Name] || handed[where][target.Name] {
						tainted[target.Name] = true
						seeds[target.Name] = censusSeed{site: "parameter " + target.Name, at: target}
					}
				}
			}
		}
		if net[where] {
			ast.Inspect(function.Body, func(node ast.Node) bool {
				statement, ok := node.(*ast.ReturnStmt)
				if !ok {
					return true
				}
				for _, result := range statement.Results {
					root := censusRootName(result, net)
					if root == "" || root == "_" || root == "err" || root == "nil" ||
						root == receiver || !scope.local[root] {
						continue
					}
					tainted[root] = true
					if _, seen := seeds["result "+root]; !seen {
						seeds["result "+root] = censusSeed{site: "result " + root, at: result}
					}
				}
				return true
			})
		}
		for spin := 0; spin < 16; spin += 1 {
			grew := false
			bind := func(targets []ast.Expr, values []ast.Expr) {
				carries := false
				for _, value := range values {
					if 0 < len(censusBorneBy(value, tainted, true, scope)) {
						carries = true
					}
				}
				if !carries {
					return
				}
				for _, target := range targets {
					identifier, ok := target.(*ast.Ident)
					if !ok || identifier.Name == "_" || identifier.Name == "err" {
						continue
					}
					if !tainted[identifier.Name] {
						tainted[identifier.Name] = true
						grew = true
					}
				}
			}
			ast.Inspect(function.Body, func(node ast.Node) bool {
				switch shape := node.(type) {
				case *ast.AssignStmt:
					bind(shape.Lhs, shape.Rhs)
				case *ast.ValueSpec:
					names := []ast.Expr{}
					for _, target := range shape.Names {
						names = append(names, target)
					}
					bind(names, shape.Values)
				case *ast.RangeStmt:
					bind([]ast.Expr{shape.Key, shape.Value}, []ast.Expr{shape.X})
				}
				return true
			})
			if !grew {
				break
			}
		}
		return tainted, seeds
	}
	scopeOf := func(function *ast.FuncDecl) (censusScope, string) {
		local, receiver := censusLocalNames(function)
		return censusScope{local: local, producers: net, mapTypes: mapTypes,
			literalTypes: censusLiteralTypes(function.Body)}, receiver
	}

	// THE HANDED PARAMETERS, to a fixpoint across the package: every call of a function or method
	// this package declares, not qualified by an import, whose argument bears a value the walk
	// follows, taints the parameter it lands in.
	handed := map[string]map[string]bool{}
	for pass := 0; pass < 64; pass += 1 {
		grew := false
		for _, file := range files {
			for _, declaration := range file.parsed.Decls {
				function, ok := declaration.(*ast.FuncDecl)
				if !ok || function.Body == nil {
					continue
				}
				scope, receiver := scopeOf(function)
				tainted, _ := taintOf(function, handed, scope, receiver)
				ast.Inspect(function.Body, func(node ast.Node) bool {
					call, isCall := node.(*ast.CallExpr)
					if !isCall {
						return true
					}
					if selector, qualified := call.Fun.(*ast.SelectorExpr); qualified {
						if root, named := selector.X.(*ast.Ident); named && file.imported[root.Name] {
							return true
						}
					}
					callees := declared[censusCalleeName(call.Fun)]
					if len(callees) == 0 {
						return true
					}
					for position, argument := range call.Args {
						if len(censusBorneBy(argument, tainted, true, scope)) == 0 {
							continue
						}
						for _, callee := range callees {
							names, variadic := censusParameterNames(callee)
							at := position
							if len(names) <= at {
								if !variadic || len(names) == 0 {
									continue
								}
								at = len(names) - 1
							}
							if names[at] == "" {
								continue
							}
							if handed[callee.Name.Name] == nil {
								handed[callee.Name.Name] = map[string]bool{}
							}
							if !handed[callee.Name.Name][names[at]] {
								handed[callee.Name.Name][names[at]] = true
								grew = true
							}
						}
					}
					return true
				})
			}
		}
		if !grew {
			break
		}
	}

	for _, file := range files {
		name, fileSet, parsed, imported := file.name, file.fileSet, file.parsed, file.imported
		for _, declaration := range parsed.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Body == nil {
				continue
			}
			where := function.Name.Name
			at := func(node ast.Node) string {
				return fmt.Sprintf("%s:%d", name, fileSet.Position(node.Pos()).Line)
			}
			scope, receiver := scopeOf(function)
			local := scope.local
			bears := func(expression ast.Expr, tainted map[string]bool, intoLiterals bool) []string {
				return censusBorneBy(expression, tainted, intoLiterals, scope)
			}

			// PRODUCERS ONE AND TWO: a PARAMETER carrying a producer's name, or handed a value the
			// walk follows, and each RESULT root of a producer-named function. The store's write
			// path -- `PutDeviceIdentity(…, wrapSeed []byte)` -- is the first; inside
			// `GetDeviceIdentity` the seed is `parts[3]`, a generic record part, and the second.
			tainted, seeds := taintOf(function, handed, scope, receiver)
			for _, seed := range seeds {
				site := where + "|" + seed.site
				producers[site] = append(producers[site], at(seed.at))
			}

			// PRODUCER THREE: a CALL whose callee's final name is in the net, spelled bare
			// (`deviceIdentity(...)`) or qualified (`xwing.Seed()`, `store.GetDeviceIdentity()`).
			callee := map[ast.Node]bool{}
			ast.Inspect(function.Body, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				named := censusCalleeName(call.Fun)
				if named == "" || !net[named] {
					return true
				}
				callee[call.Fun] = true
				site := where + "|" + censusExpr(call.Fun)
				producers[site] = append(producers[site], at(call))
				return true
			})

			// PRODUCER FOUR: a bare FIELD READ, `self.wrapSeed`, which is how the one field this
			// step added is spelled everywhere it is used. Not counted twice when the same
			// selector was already spent as a callee.
			ast.Inspect(function.Body, func(node ast.Node) bool {
				selector, ok := node.(*ast.SelectorExpr)
				if !ok || callee[selector] || !net[selector.Sel.Name] {
					return true
				}
				site := where + "|" + censusExpr(selector)
				producers[site] = append(producers[site], at(selector)+" field")
				return true
			})

			// THE NARROWING'S CENSUS, taken BEFORE the sinks and independently of them: every
			// `len(...)` of a seed-bearing expression. [censusBorneBy] will decline to look
			// through these, so this is the only place they are seen, and they are ASSERTED
			// against a written-down list rather than dropped.
			ast.Inspect(function.Body, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok || !censusIsBuiltinLen(call, local) {
					return true
				}
				for _, argument := range call.Args {
					borne := bears(argument, tainted, true)
					if len(borne) == 0 {
						continue
					}
					site := where + "|len " + censusExpr(argument)
					counted[site] = append(counted[site], at(call)+" "+fmt.Sprint(borne))
				}
				return true
			})

			// THE HORIZON CENSUS, taken with the narrowing's own census and for the same reason:
			// every call at which a seed-bearing value is handed to a METHOD ON A VALUE this walk
			// does not follow. It is where the census ends, and where it ends is asserted below
			// against each gate's own accumulator disposition rather than left to be inferred from the
			// absence of entries.
			ast.Inspect(function.Body, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok || censusIsBuiltinLen(call, local) {
					return true
				}
				selector, method := call.Fun.(*ast.SelectorExpr)
				if !method {
					return true // a bare call has no receiver to accumulate into
				}
				root := censusRootName(selector.X, net)
				switch {
				case root == "":
					return true // a receiver with no single root -- a literal, a call
				case imported[root]:
					return true // a package-qualified call is not a method on a value
				case tainted[root]:
					return true // a receiver the walk already follows is a sink, not a horizon
				case reseeds[selector.Sel.Name]:
					return true // the walk starts again inside it; see [censusReseedingFunctions]
				}
				borne := []string{}
				for _, argument := range call.Args {
					borne = append(borne, bears(argument, tainted, false)...)
				}
				if len(borne) == 0 {
					return true
				}
				site := where + "|accumulate " + censusExpr(selector)
				accumulated[site] = append(accumulated[site], at(call)+" "+fmt.Sprint(borne))
				return true
			})

			if len(tainted) == 0 && len(producers) == 0 {
				continue
			}

			// THE SINKS. Every clause asks an EXPRESSION and not a node class, which is the
			// epoch-key gate's second scar: `x = wrapSeed[:]`, `(wrapSeed)`, `[]byte(wrapSeed)`
			// and `any(wrapSeed).([]byte)` are ONE site rather than four holes. Each landing is
			// also an OCCURRENCE, spelled as the value that landed, so a second landing of a value
			// a site already carries is seen (censusHoldOccurrences).
			landed := map[string]bool{}
			record := func(site string, node ast.Node, spelled string, borne []string) {
				sinks[site] = append(sinks[site], at(node)+" "+spelled)
				occurrences[site] = append(occurrences[site], spelled)
				if carried[site] == nil {
					carried[site] = map[string]bool{}
				}
				for _, value := range borne {
					carried[site][value] = true
					if tainted[value] {
						landed[value] = true
					}
				}
			}
			// what a target's own indices bear: a map written at a key the walk follows, or a slice
			// at an index, carries that key wherever the value written is from (L2-02)
			indexed := func(target ast.Expr) []string {
				borne := []string{}
				ast.Inspect(target, func(node ast.Node) bool {
					if index, isIndex := node.(*ast.IndexExpr); isIndex {
						borne = append(borne, bears(index.Index, tainted, false)...)
					}
					return true
				})
				return borne
			}
			union := func(parts ...[]string) []string {
				seen := map[string]bool{}
				all := []string{}
				for _, part := range parts {
					for _, value := range part {
						if !seen[value] {
							seen[value] = true
							all = append(all, value)
						}
					}
				}
				sort.Strings(all)
				return all
			}
			ast.Inspect(function.Body, func(node ast.Node) bool {
				switch shape := node.(type) {
				case *ast.CompositeLit:
					spelled := censusExpr(shape.Type)
					literalType := scope.literalTypes[shape]
					isMap := censusIsMapType(literalType, mapTypes)
					for index, element := range shape.Elts {
						value := element
						field := fmt.Sprintf("element %d", index)
						var key ast.Expr
						if pair, ok := element.(*ast.KeyValueExpr); ok {
							value = pair.Value
							field = censusExpr(pair.Key)
							if isMap {
								key = pair.Key
							}
						}
						borne := bears(value, tainted, false)
						occurrence := censusExpr(value)
						if key != nil {
							borne = union(borne, bears(key, tainted, false))
							occurrence = censusExpr(key) + ": " + occurrence
						}
						if len(borne) == 0 {
							continue
						}
						record(fmt.Sprintf("%s|literal %s.%s", where, spelled, field),
							element, occurrence, borne)
					}
				case *ast.CallExpr:
					// the builtin `len` is not a sink: it is the narrowing, and it has a census
					// of its own two clauses up.
					if censusIsBuiltinLen(shape, local) {
						return true
					}
					for _, argument := range shape.Args {
						borne := bears(argument, tainted, false)
						if len(borne) == 0 {
							continue
						}
						record(fmt.Sprintf("%s|call %s", where, censusExpr(shape.Fun)),
							shape, censusExpr(argument), borne)
					}
				case *ast.AssignStmt:
					for index, target := range shape.Lhs {
						if identifier, bare := target.(*ast.Ident); bare && local[identifier.Name] {
							continue
						}
						var source ast.Expr
						switch {
						case len(shape.Lhs) == len(shape.Rhs):
							source = shape.Rhs[index]
						case len(shape.Rhs) == 1:
							source = shape.Rhs[0]
						default:
							continue
						}
						borne := union(bears(source, tainted, false), indexed(target))
						if len(borne) == 0 {
							continue
						}
						record(fmt.Sprintf("%s|assign %s", where, censusExpr(target)),
							shape, censusExpr(source), borne)
					}
				case *ast.IncDecStmt:
					if identifier, bare := shape.X.(*ast.Ident); bare && local[identifier.Name] {
						return true
					}
					borne := indexed(shape.X)
					if 0 < len(borne) {
						record(fmt.Sprintf("%s|assign %s", where, censusExpr(shape.X)),
							shape, censusExpr(shape.X)+shape.Tok.String(), borne)
					}
				case *ast.ReturnStmt:
					for _, result := range shape.Results {
						borne := bears(result, tainted, false)
						if len(borne) == 0 {
							continue
						}
						record(where+"|return", shape, censusExpr(result), borne)
					}
				case *ast.SendStmt:
					borne := bears(shape.Value, tainted, false)
					if 0 < len(borne) {
						record(fmt.Sprintf("%s|send %s", where, censusExpr(shape.Chan)),
							shape, censusExpr(shape.Value), borne)
					}
				}
				return true
			})
			for identifier := range tainted {
				if !landed[identifier] {
					unspent[where] = append(unspent[where], identifier)
				}
			}
		}
	}

	return censusResult{
		sources:     sources,
		producers:   producers,
		sinks:       sinks,
		carried:     carried,
		occurrences: occurrences,
		counted:     counted,
		accumulated: accumulated,
		unspent:     unspent,
	}
}
