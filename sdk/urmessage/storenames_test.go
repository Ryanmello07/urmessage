package urmessage

import (
	"bytes"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// EVERY PATH THIS STORE KEEPS IN A GROUP'S FOLDER IS ONE OF ITS OWN NAMES, AND THE NAMES ARE SPELLED
// ONCE (R34, item 9). The readers that decide on a missing record ask whether a folder holds any of
// the store's own names ([stateGroupNames]); a name the store wrote and the set did not list would
// make a live group's folder read as "nothing of a group is here". So:
//   - every path helper's last element is in the set, and the helper's path is in the group's own
//     folder;
//   - every name in the set is some helper's, so the set lists nothing the store never writes;
//   - in this store's source, each name is spelled as a string literal exactly once, in its constant,
//     so no second spelling can drift from the set.
//
// THE CONTROL: a folder holding only a file the store did not write and an unfinished write holds
// none of the names, and the same folder with any one of them in it holds one.
func TestEveryGroupPathIsOneOfTheStoresOwnNames(t *testing.T) {
	store := openTestStore(t, t.TempDir())
	groupId := bytes.Repeat([]byte{0x74}, GroupIdBytes)
	helpers := map[string]string{
		"groupRecordPath": store.groupRecordPath(groupId),
		"epochDir":        store.epochDir(groupId),
		"sentDir":         store.sentDir(groupId),
		"peerHeadsPath":   store.peerHeadsPath(groupId),
		"forgettingPath":  store.forgettingPath(groupId),
		"pendingPath":     store.pendingPath(groupId),
		"recordedPath":    store.recordedPath(groupId),
	}
	named := map[string]bool{}
	for _, name := range stateGroupNames {
		if named[name] {
			t.Errorf("%q is listed twice among the store's own names", name)
		}
		named[name] = true
	}
	produced := map[string]bool{}
	for helper, path := range helpers {
		if filepath.Dir(path) != store.groupDir(groupId) {
			t.Errorf("%s answers %s, which is not in the group's own folder", helper, path)
		}
		name := filepath.Base(path)
		if !named[name] {
			t.Errorf("%s writes %q into the group's folder, and it is not among the store's own names", helper, name)
		}
		produced[name] = true
	}
	for name := range named {
		if !produced[name] {
			t.Errorf("%q is among the store's own names and no path helper writes it", name)
		}
	}

	// each name spelled once, in its constant
	const source = "statestore_durable.go"
	parsed, err := parser.ParseFile(token.NewFileSet(), source, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", source, err)
	}
	spelled := map[string]int{}
	ast.Inspect(parsed, func(node ast.Node) bool {
		if literal, ok := node.(*ast.BasicLit); ok && literal.Kind == token.STRING {
			if value, err := strconv.Unquote(literal.Value); err == nil && named[value] {
				spelled[value] += 1
			}
		}
		return true
	})
	for name := range named {
		if spelled[name] != 1 {
			t.Errorf("%q is spelled as a string %d time(s) in %s, want once, in its constant", name, spelled[name], source)
		}
	}

	// THE CONTROL
	dir := t.TempDir()
	for _, stray := range []string{"desktop.ini", stateTempPrefix + "12345"} {
		if err := os.WriteFile(filepath.Join(dir, stray), []byte("not the store's"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if holds, err := stateFolderHoldsOwnNames(dir); err != nil || holds {
		t.Fatalf("CONTROL FAILED: a folder holding only a stray file and an unfinished write answered %v, %v, want none of the store's names", holds, err)
	}
	for _, name := range stateGroupNames {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if holds, err := stateFolderHoldsOwnNames(dir); err != nil || !holds {
			t.Errorf("a folder holding %q answered %v, %v, want one of the store's names", name, holds, err)
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
}

// EVERY PATH THIS STORE WRITES AT ITS ROOT IS ONE OF THE ROOT'S OWN NAMES, AND A STRAY AT THE ROOT IS
// NEVER READ AS ONE (identity phase 1's Task 12, Property 5). The root holds the device's records and
// the identity layer's three beside them (Spec A A-36 section 8.1), and the reader that decides on them
// -- [DurableStateStore.PutDeviceIdentity]'s guard, which refuses a device key beside an identity that
// would not name it -- asks which of the root's own names stand ([stateRootNamesHeld]). So:
//   - every path helper's first element below the data directory is in the set, and every name in
//     the set is some helper's, so the set lists nothing the store never writes;
//   - in this store's source, every path joined onto the data directory takes one of the set's
//     constants as its next element, and the data directory's other uses are the two the
//     disposition below names, printed;
//   - each name is spelled as a string literal exactly once, in its constant.
//
// THE CONTROL: a root holding only strays -- another program's file, an unfinished write, and names
// that only begin or end like the store's -- holds none of the names, and the same root with any one
// of them in it, in either case, holds that one and no other.
func TestEveryRootPathIsOneOfTheStoresOwnNames(t *testing.T) {
	store := openTestStore(t, t.TempDir())
	key := bytes.Repeat([]byte{0x75}, 32)
	helpers := map[string]string{
		"privatePath":        store.privatePath(key),
		"keyPackagePath":     store.keyPackagePath(key),
		"identityPath":       store.identityPath(),
		"identityRecordPath": store.identityRecordPath(),
		"identityHeadsPath":  store.identityHeadsPath(),
		"phraseKeyPath":      store.phraseKeyPath(),
		"groupDir":           store.groupDir(bytes.Repeat([]byte{0x76}, GroupIdBytes)),
	}
	named := map[string]bool{}
	for _, name := range stateRootNames {
		if named[name] {
			t.Errorf("%q is listed twice among the root's own names", name)
		}
		named[name] = true
	}
	produced := map[string]bool{}
	for helper, path := range helpers {
		relative, err := filepath.Rel(store.dataDir, path)
		if err != nil || relative == "." || strings.HasPrefix(relative, "..") {
			t.Errorf("%s answers %s, which is not below the data directory %s", helper, path, store.dataDir)
			continue
		}
		first := strings.Split(filepath.ToSlash(relative), "/")[0]
		if !named[first] {
			t.Errorf("%s writes %q at the store's root, and it is not among the root's own names", helper, first)
		}
		produced[first] = true
	}
	for name := range named {
		if !produced[name] {
			t.Errorf("%q is among the root's own names and no path helper writes it", name)
		}
	}

	// every join onto the data directory names one of the set's constants next, and the data
	// directory's other uses are the disposition's
	const source = "statestore_durable.go"
	parsed, err := parser.ParseFile(token.NewFileSet(), source, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", source, err)
	}
	constants := map[string]string{}
	for _, declaration := range parsed.Decls {
		general, ok := declaration.(*ast.GenDecl)
		if !ok || general.Tok != token.CONST {
			continue
		}
		for _, spec := range general.Specs {
			value := spec.(*ast.ValueSpec)
			for at, name := range value.Names {
				if at < len(value.Values) {
					if literal, ok := value.Values[at].(*ast.BasicLit); ok && literal.Kind == token.STRING {
						if unquoted, err := strconv.Unquote(literal.Value); err == nil && named[unquoted] {
							constants[name.Name] = unquoted
						}
					}
				}
			}
		}
	}
	if len(constants) != len(named) {
		t.Errorf("the root's own names are the values of %d constants in %s, want one constant for each of %d", len(constants), source, len(named))
	}
	isDataDir := func(expression ast.Expr) bool {
		selector, ok := expression.(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != "dataDir" {
			return false
		}
		receiver, ok := selector.X.(*ast.Ident)
		return ok && receiver.Name == "self"
	}
	joins, otherUses := 0, map[string]int{}
	for _, declaration := range parsed.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Body == nil {
			continue
		}
		joined := map[ast.Expr]bool{}
		ast.Inspect(function.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok || len(call.Args) == 0 || !isDataDir(call.Args[0]) {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || selector.Sel.Name != "Join" {
				return true
			}
			joined[call.Args[0]] = true
			joins += 1
			if len(call.Args) < 2 {
				t.Errorf("%s joins the data directory onto nothing", function.Name.Name)
				return true
			}
			next, ok := call.Args[1].(*ast.Ident)
			if !ok || constants[next.Name] == "" {
				t.Errorf("%s joins the data directory with a next element that is not one of the root's own names' constants", function.Name.Name)
			}
			return true
		})
		ast.Inspect(function.Body, func(node ast.Node) bool {
			if expression, ok := node.(ast.Expr); ok && isDataDir(expression) && !joined[expression] {
				otherUses[function.Name.Name] += 1
			}
			return true
		})
	}
	// THE DISPOSITION of the data directory's uses that are not a join, each with its reason, held
	// both ways: a use the map does not name fails, and so does a name the source no longer has
	disposition := map[string]string{
		"wrongTypeStands":   "the store's own top, which the walk up from a name compares against and never writes",
		"PutDeviceIdentity": "the root listing, stateRootNamesHeld, which reads only the root's own names",
	}
	t.Logf("%d joins onto the data directory; its other uses: %v", joins, otherUses)
	if joins < len(named) {
		t.Errorf("CONTROL FAILED: %d joins onto the data directory were found in %s, fewer than the %d names it writes", joins, source, len(named))
	}
	for function, count := range otherUses {
		if disposition[function] == "" || count != 1 {
			t.Errorf("%s uses the data directory %d time(s) other than in a join, and the disposition names no such use", function, count)
		}
	}
	for function := range disposition {
		if otherUses[function] != 1 {
			t.Errorf("the disposition names %s's use of the data directory, and %s has %d", function, source, otherUses[function])
		}
	}

	// each name spelled once, in its constant
	spelled := map[string]int{}
	ast.Inspect(parsed, func(node ast.Node) bool {
		if literal, ok := node.(*ast.BasicLit); ok && literal.Kind == token.STRING {
			if value, err := strconv.Unquote(literal.Value); err == nil && named[value] {
				spelled[value] += 1
			}
		}
		return true
	})
	for name := range named {
		if spelled[name] != 1 {
			t.Errorf("%q is spelled as a string %d time(s) in %s, want once, in its constant", name, spelled[name], source)
		}
	}

	// THE CONTROL
	dir := t.TempDir()
	strays := []string{"desktop.ini", stateTempPrefix + "12345", "identity.old", "identity-heads-1",
		"old-phrase-key", "groups", "kp2", "device.bak", "privs"}
	for _, stray := range strays {
		if err := os.WriteFile(filepath.Join(dir, stray), []byte("not the store's"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if held, err := stateRootNamesHeld(dir); err != nil || len(held) != 0 {
		t.Fatalf("CONTROL FAILED: a root holding only %v answered %v, %v, want none of the root's names", strays, held, err)
	}
	for _, name := range stateRootNames {
		for _, spelling := range []string{name, strings.ToUpper(name)} {
			path := filepath.Join(dir, spelling)
			if err := os.WriteFile(path, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if held, err := stateRootNamesHeld(dir); err != nil || !slices.Equal(held, []string{name}) {
				t.Errorf("a root holding %q answered %v, %v, want %q alone", spelling, held, err, name)
			}
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := stateRootNamesHeld(filepath.Join(dir, "nothing stands here")); !errors.Is(err, ErrStateStoreState) {
		t.Errorf("a root that cannot be listed answered %v, want ErrStateStoreState", err)
	}
}

// AN EMPTY STORE FOLDER HOLDS NOTHING OF A GROUP (R36, item 3: the round-5 review's Z3, the store half,
// on every platform). A group's `epoch` and `sent` folders count as the store's own only when they hold
// an entry named the way the store names its entries: an empty one, or one holding only an unfinished
// write and a stray, holds nothing. So a group folder left holding only such a folder is "nothing is
// here": the gate's and ForgetGroup's reading is groupFolderNothing, ForgetGroup answers that this
// device holds no such group, and a state written into it is marked as a creation.
//
// THE CONTROLS: the same folders holding one entry named as the store names its entries count, and a
// path of another type standing at either name counts too -- present, not absent.
//
// WHAT WOULD GO RED: an empty `epoch` counted as one of the store's names, which refused every re-join
// of a group whose leave another program's open handle stopped from removing that folder.
func TestAnEmptyStoreFolderHoldsNothingOfAGroup(t *testing.T) {
	store := openTestStore(t, t.TempDir())
	device := newAnsweringDeviceOver(t, store, []byte("the device's nonce"))
	groupId := bytes.Repeat([]byte{0x78}, GroupIdBytes)
	dir := store.groupDir(groupId)
	for _, name := range []string{stateGroupEpochsName, stateGroupSentName} {
		folder := filepath.Join(dir, name)
		if err := os.MkdirAll(folder, 0o700); err != nil {
			t.Fatal(err)
		}
		// empty, and then holding only an unfinished write and a stray
		for _, round := range []string{"empty", "an unfinished write and a stray"} {
			if round != "empty" {
				for _, stray := range []string{stateTempPrefix + "12345", "desktop.ini"} {
					if err := os.WriteFile(filepath.Join(folder, stray), []byte("not a value"), 0o600); err != nil {
						t.Fatal(err)
					}
				}
			}
			if holds, err := stateFolderHoldsOwnNames(dir); err != nil || holds {
				t.Errorf("a group folder whose %s folder is %s answered %v, %v, want nothing of a group", name, round, holds, err)
			}
			if got := store.groupFolder(groupId); got != groupFolderNothing {
				t.Errorf("a group folder whose %s folder is %s reads as %d, want groupFolderNothing", name, round, got)
			}
			if err := device.ForgetGroup(groupId); !errors.Is(err, ErrGroupNotHeld) || errors.Is(err, ErrGroupReadUnproven) {
				t.Errorf("the leave over a group folder whose %s folder is %s answered %v, want ErrGroupNotHeld", name, round, err)
			}
		}
		// THE CONTROL: one entry named as the store names its entries counts
		entry := filepath.Join(folder, stateEpochName(3))
		if err := os.WriteFile(entry, []byte("an entry"), 0o600); err != nil {
			t.Fatal(err)
		}
		if holds, err := stateFolderHoldsOwnNames(dir); err != nil || !holds {
			t.Errorf("CONTROL FAILED: a %s folder holding %s answered %v, %v, want one of the store's names", name, stateEpochName(3), holds, err)
		}
		if err := os.RemoveAll(folder); err != nil {
			t.Fatal(err)
		}
		// AND A PATH OF ANOTHER TYPE AT ITS NAME counts: it is present, not absent
		if err := os.WriteFile(folder, []byte("a file where a folder goes"), 0o600); err != nil {
			t.Fatal(err)
		}
		if holds, err := stateFolderHoldsOwnNames(dir); err != nil || !holds {
			t.Errorf("CONTROL FAILED: a file standing where the %s folder goes answered %v, %v, want one of the store's names", name, holds, err)
		}
		if err := os.Remove(folder); err != nil {
			t.Fatal(err)
		}
	}
	// a state written into a group folder holding only an empty `epoch` folder is marked as a creation
	if err := os.MkdirAll(store.epochDir(groupId), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := store.PutGroupState(groupId, 3, testState); err != nil {
		t.Fatalf("PutGroupState: %v", err)
	}
	if _, err := os.Stat(store.pendingPath(groupId)); err != nil {
		t.Errorf("a state written into a folder holding only an empty epoch folder is not marked as a creation: %v", err)
	}
}
