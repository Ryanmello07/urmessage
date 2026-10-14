package urmessage

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// EVERY ERASE NAMES ITS AUTHORITY (R33 (3)). The property this package holds about a group's files
// is not "an erase needs proof the group can never be read" -- the round-3 review broke that a
// fourth time, with a file an antivirus quarantine moved away -- but that THE LIBRARY ERASES A
// GROUP'S FILES ONLY FOR A REASON IT CAN NAME, FROM A FACT IT WROTE ITSELF OR BYTES IT READ AND
// FOUND WRONG. This gate holds that at its subject, which is the call that erases. It reads the
// source of every production package in this repository, whatever GOOS a file is constrained to,
// finds every call site of an erase, and asserts that the set of sites EQUALS an allow-list in
// which each site names its authority:
//
//	(a) a leave mark already written: a leave decided with the owner's question, or on a proven
//	    verdict, and finished whatever state it stopped in;
//	(b) a FRESH proven-permanent verdict at the person's leave ([Device.restoreForLeave]), with the
//	    mark written first;
//	(c) the store's own `pending` mark ([DurableStateStore.pendingPath]);
//	(d) a failed admission erasing what it wrote itself ([Device.abandonJoined]);
//	(e) THE EPOCH WINDOW: mls discarding the states of epochs a group has moved PastEpochWindow
//	    past, on the commit that moved it (RFC 9420 section 5.12). It is not in R33's list, and it
//	    is an erase of a group's files all the same, decided on an epoch this library committed
//	    itself; so it is named here rather than left out.
//
// WHAT AN ERASE IS, AND WHY THE LIST OF THEM IS DERIVED. The primitives are package os's Remove,
// RemoveAll and Truncate, and any Truncate method. A function with a site this list calls a STEP --
// an erase whose authority is its caller's, such as removeLocked, or DeleteGroupRecord's own
// removals -- is an erase itself, so every call of it, under its name and whatever its receiver,
// is a site too, to a fixed point. A helper that wraps an erase therefore cannot hide its callers:
// they are sites, and each needs a sentence. A site whose entry says NOT A GROUP'S FILE (a
// temporary file, a private key, a join code, the creation mark, an empty directory) does not make
// its function an erase.
//
// IT IS NOT A COUNT. A site's key is its file, its enclosing function, the erase it calls WITH THE
// ARGUMENTS AS WRITTEN, and its ordinal among that function's identical calls: a removal moved to
// another path is another key. A site with no entry is an erase nobody weighed; an entry with no
// site is a sentence that has stopped describing the code. Both are refused, and the whole
// classification is printed, the complement included. The planted-call control is the next case.
func TestEveryEraseInThisRepositoryNamesItsAuthority(t *testing.T) {
	files := eraseGateSources(t)
	found, tracked := eraseGateScan(files)
	eraseGatePrint(t, found, tracked)
	for _, problem := range eraseGateProblems(found) {
		t.Error(problem)
	}
}

// THE CONTROL: AN ERASE PLANTED WITH NO AUTHORITY IS FOUND, AND IT ALONE (R33 (3)). The same scan,
// over the same sources and one planted file whose one function leaves a group by calling the
// store's DeleteGroupRecord -- the erase every leave goes through, and not a primitive: it is an
// erase only because the derivation finds the steps inside it -- with no mark, no verdict and no
// creation mark behind it. The gate must report that site as one that names no authority, and
// nothing else, so that it fires for the planted call's own reason and not because some other row
// came back.
func TestTheEraseGateFindsAPlantedEraseAndOnlyIt(t *testing.T) {
	files := eraseGateSources(t)
	clean, _ := eraseGateScan(files)
	if problems := eraseGateProblems(clean); len(problems) != 0 {
		t.Fatalf("CONTROL FAILED: the scan without the planted file already reports %d problem(s), so the planted one could not be told apart: %v", len(problems), problems)
	}
	const plantedName = "sdk/urmessage/zz_planted_erase.go"
	planted, err := parser.ParseFile(token.NewFileSet(), plantedName, `package urmessage

func (self *Device) plantedLeave(store DeviceStore, groupId []byte) error {
	return store.DeleteGroupRecord(groupId)
}
`, 0)
	if err != nil {
		t.Fatalf("CONTROL FAILED: the planted source does not parse: %v", err)
	}
	files[plantedName] = planted
	found, _ := eraseGateScan(files)
	problems := eraseGateProblems(found)
	const want = "sdk/urmessage/zz_planted_erase.go|Device.plantedLeave|DeleteGroupRecord(groupId)#1"
	if len(problems) != 1 || !strings.Contains(problems[0], want) || !strings.Contains(problems[0], "names no authority") {
		t.Fatalf("the gate over a planted erase with no authority reported %d problem(s), want exactly the planted site %s: %v", len(problems), want, problems)
	}
	t.Logf("the planted erase is reported, and it alone: %s", problems[0])
}

const (
	eraseLeaveMark   = "(a) a leave mark already written"
	eraseFreshProof  = "(b) a fresh proven-permanent verdict at the person's leave"
	eraseOwnMark     = "(c) the store's own pending mark"
	eraseOwnAdmitted = "(d) a failed admission erasing what it wrote itself"
	eraseWindow      = "(e) the epoch window"
	eraseStep        = "a step of an erase, whose authority is its caller's"
	eraseNotGroup    = "not a group's file"
)

// eraseGateEntry is what one site is, by the allow-list, and the sentence that says why.
type eraseGateEntry struct {
	class string
	why   string
}

// eraseGateAllowList is every erase site in this repository's production source, by
// "file|function|erase(arguments)#ordinal", and what authorizes it.
var eraseGateAllowList = map[string]eraseGateEntry{
	"sdk/urmessage/forget.go|Device.ForgetGroup|DeleteGroupRecord(groupId)#1":                                                                               {eraseLeaveMark, "a leave already under way: the mark stands, so the leave was decided when it went down, and is finished whatever state it stopped in."},
	"sdk/urmessage/forget.go|Device.ForgetGroup|DeleteGroupRecord(groupId)#2":                                                                               {eraseLeaveMark, "the leave of a live group, after closeToForget asked the owner's question and wrote the mark."},
	"sdk/urmessage/forget.go|Device.forgetUnrestored|DeleteGroupRecord(groupId)#1":                                                                          {eraseFreshProof, "a group whose restore this leave tried again and found proven-permanently unreadable, or whose record this leave read and found damaged (R9, R30); the mark is written first, so an interrupted erase is finished as (a)."},
	"sdk/urmessage/forget.go|Device.finishLeaveBefore|DeleteGroupRecord(groupId)#1":                                                                         {eraseLeaveMark, "a standing leave mark, finished before a Join or a CreateGroup writes anything beside it."},
	"sdk/urmessage/restore.go|Device.Restore|DeleteGroupRecord(groupId)#1":                                                                                  {eraseLeaveMark, "every group a standing leave mark names (GroupsBeingForgotten), finished before anything is restored."},
	"sdk/urmessage/restore.go|Device.Restore|eraseGroupsWithNoRecord(self.heldGroupIds())#1":                                                                {eraseOwnMark, "the sweep, which erases a directory only when it holds the store's own pending mark and no record (R33 (2))."},
	"sdk/urmessage/group.go|Device.abandonJoined|DeleteGroupRecord(group.id)#1":                                                                             {eraseOwnAdmitted, "a join that failed after its commit, when it was not a re-add: the record it may have landed, in a directory the gate said held nothing else of the group (Task 57, F3; R26, V4b)."},
	"sdk/urmessage/group.go|Device.eraseJoinedState|deleteGroupStateAt(groupId, epoch)#1":                                                                   {eraseOwnAdmitted, "the one epoch state a failed join committed, and no other."},
	"sdk/urmessage/group.go|Device.eraseJoinedState|DeleteGroupStateBefore(groupId, epoch + 1)#1":                                                           {eraseOwnAdmitted, "the same on a store with no single-epoch erase, and only when the join was not a re-add: everything below the joined epoch's successor, which is all that join wrote."},
	"mls/group.go|Group.MergePendingCommit|DeleteGroupStateBefore(cloneBytes(self.context.GroupId), cutoff)#1":                                              {eraseWindow, "the states of epochs this group has moved PastEpochWindow past, on the commit that moved it: section 5.12's discard, decided on the epoch the library committed itself."},
	"sdk/urmessage/joinstage.go|joinStage.DeleteGroupStateBefore|DeleteGroupStateBefore(groupId, epoch)#1":                                                  {eraseStep, "the stage forwarding (e), and (d) through eraseJoinedState, to the store; for the group being joined it erases nothing."},
	"sdk/urmessage/statestore_durable.go|DurableStateStore.DeleteGroupStateBefore|deleteEpochsLocked(groupId, epoch)#1":                                     {eraseStep, "the store's half of (e), and of eraseJoinedState's (d)."},
	"sdk/urmessage/statestore_durable.go|DurableStateStore.deleteEpochsLocked|os.Remove(filepath.Join(dir, entry.Name()))#1":                                {eraseStep, "an unfinished write in the epoch directory, discarded with the epochs it stands among: section 5.12 has no half erase."},
	"sdk/urmessage/statestore_durable.go|DurableStateStore.deleteEpochsLocked|os.Remove(filepath.Join(dir, entry.Name()))#2":                                {eraseStep, "one epoch below the caller's cutoff."},
	"sdk/urmessage/statestore_durable.go|DurableStateStore.deleteGroupStateAt|removeLocked(filepath.Join(self.epochDir(groupId), stateEpochName(epoch)))#1": {eraseStep, "the one epoch (d) names."},
	"sdk/urmessage/statestore_durable.go|DurableStateStore.eraseGroupsWithNoRecord|removeLocked(filepath.Join(epochDir, epoch.Name()))#1":                   {eraseStep, "each epoch state of a directory (c) authorizes."},
	"sdk/urmessage/statestore_durable.go|DurableStateStore.DeleteGroupRecord|deleteEpochsLocked(groupId, ^uint64(0))#1":                                     {eraseStep, "every epoch state of the group, first."},
	"sdk/urmessage/statestore_durable.go|DurableStateStore.DeleteGroupRecord|deleteSentLocked(groupId)#1":                                                   {eraseStep, "the copies of what this device said, second."},
	"sdk/urmessage/statestore_durable.go|DurableStateStore.DeleteGroupRecord|removeLocked(self.peerHeadsPath(groupId))#1":                                   {eraseStep, "the peer-head table."},
	"sdk/urmessage/statestore_durable.go|DurableStateStore.DeleteGroupRecord|removeLocked(self.groupRecordPath(groupId))#1":                                 {eraseStep, "the group's record."},
	"sdk/urmessage/statestore_durable.go|DurableStateStore.DeleteGroupRecord|removeLocked(self.forgettingPath(groupId))#1":                                  {eraseStep, "the leave mark, last, so an interrupted erase is finished as (a)."},
	"sdk/urmessage/statestore_durable.go|DurableStateStore.deleteSentLocked|removeLocked(dir)#1":                                                            {eraseStep, "a non-directory standing where the group's copies go."},
	"sdk/urmessage/statestore_durable.go|DurableStateStore.deleteSentLocked|os.Remove(filepath.Join(dir, entry.Name()))#1":                                  {eraseStep, "one copy of a line this device sent."},
	"sdk/urmessage/statestore_durable.go|DurableStateStore.removeLocked|os.Remove(path)#1":                                                                  {eraseStep, "the store's one removal, which each site that calls it decides."},
	"sdk/urmessage/statestore_durable.go|DurableStateStore.clearPendingLocked|removeLocked(self.pendingPath(groupId))#1":                                    {eraseNotGroup, "the creation mark: the store's note about its own write, and with it gone nothing of the directory is ever swept."},
	"sdk/urmessage/statestore_durable.go|DurableStateStore.DeleteGroupRecord|os.Remove(self.epochDir(groupId))#1":                                           {eraseNotGroup, "the epoch directory, empty by then: os.Remove refuses a directory with anything in it."},
	"sdk/urmessage/statestore_durable.go|DurableStateStore.DeleteGroupRecord|os.Remove(self.sentDir(groupId))#1":                                            {eraseNotGroup, "the sent directory, empty by then."},
	"sdk/urmessage/statestore_durable.go|DurableStateStore.DeleteGroupRecord|os.Remove(self.groupDir(groupId))#1":                                           {eraseNotGroup, "the group directory, empty by then."},
	"sdk/urmessage/statestore_durable.go|DurableStateStore.deleteGroupStateAt|os.Remove(self.epochDir(groupId))#1":                                          {eraseNotGroup, "the epoch directory, only when empty."},
	"sdk/urmessage/statestore_durable.go|DurableStateStore.deleteGroupStateAt|os.Remove(self.groupDir(groupId))#1":                                          {eraseNotGroup, "the group directory, only when empty."},
	"sdk/urmessage/statestore_durable.go|DurableStateStore.eraseGroupsWithNoRecord|os.Remove(epochDir)#1":                                                   {eraseNotGroup, "the epoch directory, only when empty."},
	"sdk/urmessage/statestore_durable.go|DurableStateStore.eraseGroupsWithNoRecord|os.Remove(dir)#1":                                                        {eraseNotGroup, "the group directory, only when empty."},
	"sdk/urmessage/statestore_durable.go|DurableStateStore.DeletePrivateKey|removeLocked(self.privatePath(pub))#1":                                          {eraseNotGroup, "one MLS private key, at mls's own request through mls.StateStore (J1-12: nothing calls it today)."},
	"sdk/urmessage/statestore_durable.go|DurableStateStore.TakeKeyPackage|removeLocked(path)#1":                                                             {eraseNotGroup, "a join code, single use by mls.StateStore's contract: the take removes it."},
	"sdk/urmessage/statestore_durable.go|DurableStateStore.writeRecord|os.Remove(tempPath)#1":                                                               {eraseNotGroup, "this call's own temporary file, when the write did not finish: never a named value."},
	"sdk/urmessage/statestore_durable.go|sweepStateTempFiles|os.Remove(path)#1":                                                                             {eraseNotGroup, "an unfinished write a killed process left, swept at open: never a named value."},
	"sdk/message_stream_store.go|StreamStore.repairRow|Truncate(truncateTo)#1":                                                                              {eraseNotGroup, "the stream store's torn-tail repair of one fixed-width row: a reserver's file, not a group's."},
	"sdk/livepeer/main.go|main|os.Remove(*keyPackagePath)#1":                                                                                                {eraseNotGroup, "the live-peer probe binary's own key-package hand-off file, consumed: not a store's file."},
	"sdk/livepeer/main.go|writeSecret|os.Remove(temp)#1":                                                                                                    {eraseNotGroup, "the live-peer probe binary's own partial write, after a failed rename: not a store's file."},
}

// eraseGateSources is every production .go file of this repository, whatever GOOS it is
// constrained to, by its path from the repository's root. A testdata directory is not production
// source, and neither is a test file.
func eraseGateSources(t *testing.T) map[string]*ast.File {
	t.Helper()
	root := filepath.Join("..", "..")
	files := map[string]*ast.File{}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if name := entry.Name(); path != root && (name == "testdata" || strings.HasPrefix(name, ".")) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), path, content, 0)
		if err != nil {
			return err
		}
		files[filepath.ToSlash(relative)] = parsed
		return nil
	})
	if err != nil {
		t.Fatalf("reading this repository's production source: %v", err)
	}
	// THE CONTROL ON THE CONTROL: the files this gate is about. A walk that silently stopped
	// reading one of them would go green by blindness.
	for _, needed := range []string{
		"sdk/urmessage/statestore_durable.go", "sdk/urmessage/statestore_platform_windows.go",
		"sdk/urmessage/statestore_platform_unix.go", "sdk/urmessage/forget.go", "sdk/urmessage/restore.go",
		"sdk/urmessage/group.go", "sdk/urmessage/joinstage.go", "sdk/urmessage/statestore.go",
		"mls/group.go", "messagegroup/engine.go", "sdk/cgo/exports_message.go", "sdk/message_stream_store.go",
	} {
		if files[needed] == nil {
			t.Fatalf("this gate did not read %s, so it is not holding the file it is about (%d file(s) read)", needed, len(files))
		}
	}
	return files
}

// eraseGateScan is every erase site in the files, and the names the derivation made erases. It
// starts from the primitives and adds the enclosing function of every site that is a STEP, or that
// no entry classifies, until nothing is added.
func eraseGateScan(files map[string]*ast.File) (map[string]bool, []string) {
	tracked := map[string]bool{"Truncate": true}
	for {
		found := eraseGateSites(files, tracked)
		grown := false
		for key, function := range found {
			entry, listed := eraseGateAllowList[key]
			if function != "" && (!listed || entry.class == eraseStep) && !tracked[function] {
				tracked[function] = true
				grown = true
			}
		}
		if !grown {
			keys := map[string]bool{}
			for key := range found {
				keys[key] = true
			}
			names := []string{}
			for name := range tracked {
				names = append(names, name)
			}
			sort.Strings(names)
			return keys, names
		}
	}
}

// eraseGateSites is every reference to an erase, by key, with the simple name of the function it
// stands in. A reference is a call or a method value: a selector naming package os's Remove,
// RemoveAll or Truncate under whatever name the file imports os as, or naming a tracked erase
// whatever its receiver. A declaration and an interface's method spec are not references.
func eraseGateSites(files map[string]*ast.File, tracked map[string]bool) map[string]string {
	found := map[string]string{}
	names := []string{}
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		file := files[name]
		osName := "os"
		for _, spec := range file.Imports {
			if path, err := strconv.Unquote(spec.Path.Value); err == nil && path == "os" && spec.Name != nil {
				osName = spec.Name.Name
			}
		}
		ordinals := map[string]map[string]int{}
		visit := func(function string, simple string, body ast.Node) {
			if ordinals[function] == nil {
				ordinals[function] = map[string]int{}
			}
			ordinal := ordinals[function]
			calls := map[*ast.SelectorExpr]*ast.CallExpr{}
			ast.Inspect(body, func(node ast.Node) bool {
				if call, ok := node.(*ast.CallExpr); ok {
					if selector, ok := call.Fun.(*ast.SelectorExpr); ok {
						calls[selector] = call
					}
				}
				return true
			})
			ast.Inspect(body, func(node ast.Node) bool {
				selector, ok := node.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				callee := selector.Sel.Name
				if ident, isIdent := selector.X.(*ast.Ident); isIdent && ident.Name == osName {
					if callee != "Remove" && callee != "RemoveAll" && callee != "Truncate" {
						return true
					}
					callee = "os." + callee
				} else if !tracked[callee] {
					return true
				}
				arguments := "(method value)"
				if call := calls[selector]; call != nil {
					rendered := []string{}
					for _, argument := range call.Args {
						var out bytes.Buffer
						printer.Fprint(&out, token.NewFileSet(), argument)
						rendered = append(rendered, out.String())
					}
					arguments = "(" + strings.Join(rendered, ", ") + ")"
				}
				site := callee + arguments
				ordinal[site] += 1
				found[fmt.Sprintf("%s|%s|%s#%d", name, function, site, ordinal[site])] = simple
				return true
			})
		}
		for _, declaration := range file.Decls {
			switch one := declaration.(type) {
			case *ast.FuncDecl:
				if one.Body != nil {
					visit(eraseGateFunctionName(one), one.Name.Name, one.Body)
				}
			case *ast.GenDecl:
				visit("(package level)", "", one)
			}
		}
	}
	return found
}

// eraseGateFunctionName is a function's name, with its receiver's type for a method.
func eraseGateFunctionName(function *ast.FuncDecl) string {
	if function.Recv == nil || len(function.Recv.List) == 0 {
		return function.Name.Name
	}
	receiver := function.Recv.List[0].Type
	if star, ok := receiver.(*ast.StarExpr); ok {
		receiver = star.X
	}
	if ident, ok := receiver.(*ast.Ident); ok {
		return ident.Name + "." + function.Name.Name
	}
	return "?." + function.Name.Name
}

// eraseGateProblems holds the sites found against the allow-list, both ways.
func eraseGateProblems(found map[string]bool) []string {
	problems := []string{}
	for _, key := range eraseGateSorted(found) {
		if _, listed := eraseGateAllowList[key]; !listed {
			problems = append(problems, fmt.Sprintf("the erase at %s names no authority: no entry of the allow-list says which of (a) a leave mark, (b) a fresh proven verdict at the leave, (c) the store's pending mark, (d) a failed admission's own write or (e) the epoch window it erases on, or that it is a step of one, or not a group's file", key))
		}
	}
	listed := map[string]bool{}
	for key := range eraseGateAllowList {
		listed[key] = true
	}
	for _, key := range eraseGateSorted(listed) {
		if !found[key] {
			problems = append(problems, fmt.Sprintf("the allow-list names an erase at %s and the source has none there: the entry has stopped describing the code", key))
		}
	}
	return problems
}

// eraseGatePrint prints every site found, by class, the complement included, and the erases the
// derivation tracked by name.
func eraseGatePrint(t *testing.T, found map[string]bool, tracked []string) {
	t.Helper()
	t.Logf("erases tracked by name, the primitives and what the derivation added: %v", tracked)
	byClass := map[string][]string{}
	for _, key := range eraseGateSorted(found) {
		entry, listed := eraseGateAllowList[key]
		class := entry.class
		if !listed {
			class = "UNLISTED"
		}
		byClass[class] = append(byClass[class], key+"  -- "+entry.why)
	}
	for _, class := range []string{eraseLeaveMark, eraseFreshProof, eraseOwnMark, eraseOwnAdmitted, eraseWindow,
		eraseStep, eraseNotGroup, "UNLISTED"} {
		heading := "THE GROUP ERASES, by authority"
		if class == eraseStep || class == eraseNotGroup || class == "UNLISTED" {
			heading = "THE COMPLEMENT, which is no group erase of its own"
		}
		t.Logf("%s: %s (%d):", heading, class, len(byClass[class]))
		for _, line := range byClass[class] {
			t.Logf("    %s", line)
		}
	}
}

func eraseGateSorted(keys map[string]bool) []string {
	sorted := []string{}
	for key := range keys {
		sorted = append(sorted, key)
	}
	sort.Strings(sorted)
	return sorted
}
