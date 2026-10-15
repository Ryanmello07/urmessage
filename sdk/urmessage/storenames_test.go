package urmessage

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
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
