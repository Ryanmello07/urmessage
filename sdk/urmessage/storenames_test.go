package urmessage

import (
	"bytes"
	"errors"
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
