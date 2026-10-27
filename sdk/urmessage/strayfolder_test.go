package urmessage

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A STRAY NEVER ENTERS A VERDICT, IN ANY LISTING (R38, item 1). These cases hold the three listings
// of the groups' root that decide anything: the list of records a Restore restores, the list of
// leaves a Restore finishes, and the sweep. Each is shown a folder another program left in the root --
// a copy of a group's folder renamed as a sync tool or the shell renames one, "<name> - Copy" --
// holding one of the store's own files, and each answers as though it were not there, while the
// same file in a folder named as the store names a group's is still read and still decided on.
// (SentRecords' own listing is held by TestASentCopyMovedUnderAnotherIndexIsRefusedAndAStrangerBesideItIsSkipped,
// and the owner's leave over a stray in it by sdk/cp3b.)

// strayCopyOf copies one file of a group's folder into a folder beside it named as the shell names
// a copy, and answers that folder.
func strayCopyOf(t *testing.T, store *DurableStateStore, groupId []byte, name string, octets []byte) string {
	t.Helper()
	stray := filepath.Join(store.dataDir, "group", stateNameOf(groupId)+" - Copy")
	if err := os.MkdirAll(filepath.Dir(filepath.Join(stray, name)), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stray, name), octets, 0o600); err != nil {
		t.Fatal(err)
	}
	return stray
}

// A FOLDER IN THE GROUPS' ROOT NOT NAMED AS THE STORE NAMES A GROUP'S IS NO RECORD AND NO DAMAGE. A
// group's record copied into a renamed copy of its folder used to be read, found not to name the
// folder it sits in, and reported as a record that does not read -- damage, which is a verdict. Now
// the list answers the group alone and reports nothing. THE CONTROL: the same record in a folder
// named as the store names ANOTHER group's is read, and is damage.
//
// WHAT WOULD GO RED: the root's listing reading every folder again.
func TestAStrayFolderInTheGroupsRootIsNoRecordAndNoDamage(t *testing.T) {
	store := openTestStore(t, t.TempDir())
	groupId := bytes.Repeat([]byte{0x7A}, GroupIdBytes)
	if err := store.PutGroupRecord(&GroupRecord{
		GroupId: groupId, PqSecret: bytes.Repeat([]byte{0x2A}, 32), GroupHandleKey: bytes.Repeat([]byte{0x5C}, 32), Epoch: 1, Opened: true,
	}); err != nil {
		t.Fatalf("PutGroupRecord: %v", err)
	}
	record, err := os.ReadFile(store.groupRecordPath(groupId))
	if err != nil {
		t.Fatal(err)
	}
	strayCopyOf(t, store, groupId, stateGroupRecordName, record)
	records, err := store.GroupRecords()
	if err != nil || len(records) != 1 || !bytes.Equal(records[0].GroupId, groupId) {
		t.Errorf("beside a stray folder holding a copy of the record the list answered %d record(s), %v, want the group alone and no report", len(records), err)
	}
	// THE CONTROL
	other := bytes.Repeat([]byte{0x7B}, GroupIdBytes)
	if err := os.MkdirAll(store.groupDir(other), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(store.groupRecordPath(other), record, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GroupRecords(); !errors.Is(err, ErrGroupRecordDamaged) {
		t.Errorf("CONTROL FAILED: a record in a folder named as another group's answered %v, want it reported as damage", err)
	}
}

// A FOLDER IN THE GROUPS' ROOT NOT NAMED AS THE STORE NAMES A GROUP'S IS NO LEAVE UNDER WAY. A leave
// mark copied into a renamed copy of its group's folder used to be read, found not to name the folder
// it sits in, and reported beside the list of leaves to finish, which a Restore answers. Now the list
// is empty and reports nothing. THE CONTROL: the same mark in a folder named as another group's is
// read and reported.
//
// WHAT WOULD GO RED: the root's listing reading every folder's mark again.
func TestAStrayFolderInTheGroupsRootIsNoLeaveUnderWay(t *testing.T) {
	store := openTestStore(t, t.TempDir())
	groupId := bytes.Repeat([]byte{0x7C}, GroupIdBytes)
	if err := store.PutGroupState(groupId, 1, testState); err != nil {
		t.Fatalf("PutGroupState: %v", err)
	}
	if err := store.MarkGroupForgetting(groupId); err != nil {
		t.Fatalf("MarkGroupForgetting: %v", err)
	}
	mark, err := os.ReadFile(store.forgettingPath(groupId))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteGroupRecord(groupId); err != nil {
		t.Fatalf("CONTROL FAILED: the leave: %v", err)
	}
	strayCopyOf(t, store, groupId, stateGroupForgettingName, mark)
	if leaving, err := store.GroupsBeingForgotten(); err != nil || len(leaving) != 0 {
		t.Errorf("beside a stray folder holding a copy of a leave mark the list answered %d group(s), %v, want none and no report", len(leaving), err)
	}
	// THE CONTROL
	other := bytes.Repeat([]byte{0x7D}, GroupIdBytes)
	if err := os.MkdirAll(store.groupDir(other), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(store.forgettingPath(other), mark, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GroupsBeingForgotten(); !errors.Is(err, ErrStateStoreFormat) {
		t.Errorf("CONTROL FAILED: a mark in a folder named as another group's answered %v, want it reported", err)
	}
}

// A FOLDER IN THE GROUPS' ROOT NOT NAMED AS THE STORE NAMES A GROUP'S IS NOTHING THE SWEEP DECIDES ON.
// A creation that never finished -- its mark and an epoch state, no record -- stands beside a renamed
// copy of its folder. The sweep erases the creation, which is its own, and answers no error; the copy
// is not asked, and its files stay. It used to be asked, its mark found not to name the folder it
// sits in, and the sweep's answer carried that refusal.
//
// WHAT WOULD GO RED: the sweep's listing of the root reading every folder again.
func TestAStrayFolderInTheGroupsRootIsNothingTheSweepDecidesOn(t *testing.T) {
	store := openTestStore(t, t.TempDir())
	groupId := bytes.Repeat([]byte{0x7E}, GroupIdBytes)
	if err := store.PutGroupState(groupId, 1, testState); err != nil {
		t.Fatalf("PutGroupState: %v", err)
	}
	mark, err := os.ReadFile(store.pendingPath(groupId))
	if err != nil {
		t.Fatalf("CONTROL FAILED: the creation has no mark: %v", err)
	}
	state, err := os.ReadFile(filepath.Join(store.epochDir(groupId), stateEpochName(1)))
	if err != nil {
		t.Fatal(err)
	}
	stray := strayCopyOf(t, store, groupId, stateGroupPendingName, mark)
	strayCopyOf(t, store, groupId, filepath.Join(stateGroupEpochsName, stateEpochName(1)), state)
	erased, err := store.eraseGroupsWithNoRecord(nil)
	if err != nil || len(erased) != 1 || erased[0] != stateNameOf(groupId) {
		t.Errorf("the sweep beside a stray folder answered %v, %v, want the creation alone and no error", erased, err)
	}
	for _, name := range []string{stateGroupPendingName, filepath.Join(stateGroupEpochsName, stateEpochName(1))} {
		if _, err := os.Stat(filepath.Join(stray, name)); err != nil {
			t.Errorf("%s of the stray folder went: %v", name, err)
		}
	}
}

// A STRAY COPY FOLDER IN THE GROUPS' ROOT IS NOT REPORTED BY RESTORE (R39, item 3: the round-6
// review's baseline for R38's listing map, through the device). A joined group's record is copied into
// a renamed copy of its folder, "<name> - Copy", as the shell makes one. Restore brings the group back
// and reports nothing: the copy's name is not one the store gives a group, so it is skipped. It used
// to be reported as a DAMAGED group -- no erase followed, because a folder's name is not an id, but
// the report was a verdict about a group from a folder no group owns.
//
// WHAT WOULD GO RED: the root's listing reading every folder again, and Restore reporting
// ErrGroupRecordDamaged for the copy.
func TestAStrayCopyFolderInTheGroupsRootIsNotReportedByRestore(t *testing.T) {
	dir, groupId := failClosedScene(t)
	store := openTestStore(t, dir)
	record, err := os.ReadFile(store.groupRecordPath(groupId))
	if err != nil {
		t.Fatal(err)
	}
	strayCopyOf(t, store, groupId, stateGroupRecordName, record)
	device := newAnsweringDeviceOver(t, store, []byte("the restarted device's nonce"))
	testIdentify(t, device)
	restored, err := device.Restore(context.Background())
	t.Logf("Restore beside a stray copy folder: %d group(s), %v", len(restored), err)
	if errors.Is(err, ErrGroupRecordDamaged) {
		t.Errorf("Restore reported a stray copy folder as a damaged group: %v", err)
	}
	if err != nil || len(restored) != 1 || !bytes.Equal(restored[0].Id(), groupId) {
		t.Errorf("Restore beside a stray copy folder answered %d group(s), %v, want the group back and nothing reported", len(restored), err)
	}
}

// upperCaseFolderOf renames one group's folder to upper case, as a sync tool from a case-sensitive
// source or the shell can rename one, and answers its new path.
func upperCaseFolderOf(t *testing.T, store *DurableStateStore, groupId []byte) string {
	t.Helper()
	upper := filepath.Join(store.dataDir, "group", strings.ToUpper(stateNameOf(groupId)))
	if err := os.Rename(store.groupDir(groupId), upper); err != nil {
		t.Fatalf("renaming the group's folder to upper case: %v", err)
	}
	return upper
}

// lstatAnswering makes the store's injected Lstat answer, for one path, the Lstat of another, and
// the real one for every other path.
func lstatAnswering(store *DurableStateStore, path string, instead string) {
	store.lstat = func(name string) (os.FileInfo, error) {
		if filepath.Clean(name) == filepath.Clean(path) {
			return os.Lstat(instead)
		}
		return os.Lstat(name)
	}
}

// AN UPPER-CASE FOLDER THAT IS NOT THE SAME FILE AS THE GROUP'S OWN IS A STRAY TO EVERY LISTING OF THE
// ROOT (R42, item 1, the other half: portable, through the store's injected Lstat, and with real
// folders where the filesystem keeps two names that differ only in case apart). The store's own name
// reaches ONE folder; on a case-sensitive filesystem a name equal to it in another case is a
// different folder, and two folders must never be read as one group.
//   - THROUGH THE INJECTED LSTAT, on every platform: a group's folder is renamed to upper case, and the
//     Lstat of its lowercase name answers ANOTHER folder, as a case-sensitive filesystem holding a
//     different folder under that name answers. Whatever the renamed folder holds -- a record, a leave
//     mark, a creation with its state -- it is a stray: the list answers the other group alone and
//     reports nothing, no leave is finished in it, the sweep decides nothing in it, and its files stay.
//   - WITH REAL FOLDERS, where the filesystem keeps the two names apart (it is skipped where it folds
//     them): an upper-case copy of a group's folder beside the real one is a stray, and the group is
//     listed once.
//
// THE CONTROL: with the Lstat of the lowercase name answering the renamed folder itself -- the SAME
// file -- the rule takes the folder, under its lowercase name.
//
// WHAT WOULD GO RED: a name in either case accepted without the same-file check, which reads two
// folders as one group; and the lowercase-only rule, which the control's own answer refuses.
func TestAnUpperCaseFolderThatIsNotTheGroupsOwnFileIsAStray(t *testing.T) {
	record := func(groupId []byte) *GroupRecord {
		return &GroupRecord{GroupId: groupId, PqSecret: bytes.Repeat([]byte{0x2A}, 32), GroupHandleKey: bytes.Repeat([]byte{0x5C}, 32), Epoch: 1, Opened: true}
	}
	kept := bytes.Repeat([]byte{0x91}, GroupIdBytes)
	renamed := bytes.Repeat([]byte{0x92}, GroupIdBytes)
	t.Run("the list of records", func(t *testing.T) {
		store := openTestStore(t, t.TempDir())
		for _, groupId := range [][]byte{kept, renamed} {
			if err := store.PutGroupRecord(record(groupId)); err != nil {
				t.Fatalf("PutGroupRecord: %v", err)
			}
		}
		upper := upperCaseFolderOf(t, store, renamed)
		lstatAnswering(store, store.groupDir(renamed), store.groupDir(kept))
		records, err := store.GroupRecords()
		store.lstat = nil
		if err != nil || len(records) != 1 || !bytes.Equal(records[0].GroupId, kept) {
			t.Errorf("beside an upper-case folder that is not the same file the list answered %d record(s), %v, want the other group alone and no report", len(records), err)
		}
		if _, err := os.Stat(filepath.Join(upper, stateGroupRecordName)); err != nil {
			t.Errorf("the stray folder's record went: %v", err)
		}
	})
	t.Run("the list of leaves", func(t *testing.T) {
		store := openTestStore(t, t.TempDir())
		if err := store.PutGroupState(renamed, 1, testState); err != nil {
			t.Fatalf("PutGroupState: %v", err)
		}
		if err := store.MarkGroupForgetting(renamed); err != nil {
			t.Fatalf("MarkGroupForgetting: %v", err)
		}
		if err := store.PutGroupRecord(record(kept)); err != nil {
			t.Fatalf("PutGroupRecord: %v", err)
		}
		upper := upperCaseFolderOf(t, store, renamed)
		lstatAnswering(store, store.groupDir(renamed), store.groupDir(kept))
		leaving, err := store.GroupsBeingForgotten()
		store.lstat = nil
		if err != nil || len(leaving) != 0 {
			t.Errorf("beside an upper-case folder that is not the same file the list of leaves answered %d group(s), %v, want none and no report", len(leaving), err)
		}
		if _, err := os.Stat(filepath.Join(upper, stateGroupForgettingName)); err != nil {
			t.Errorf("the stray folder's mark went: %v", err)
		}
	})
	t.Run("the sweep", func(t *testing.T) {
		store := openTestStore(t, t.TempDir())
		if err := store.PutGroupState(renamed, 1, testState); err != nil {
			t.Fatalf("PutGroupState: %v", err)
		}
		if err := store.PutGroupRecord(record(kept)); err != nil {
			t.Fatalf("PutGroupRecord: %v", err)
		}
		upper := upperCaseFolderOf(t, store, renamed)
		lstatAnswering(store, store.groupDir(renamed), store.groupDir(kept))
		erased, err := store.eraseGroupsWithNoRecord(nil)
		store.lstat = nil
		if err != nil || len(erased) != 0 {
			t.Errorf("beside an upper-case folder that is not the same file the sweep answered %v, %v, want nothing erased and no error", erased, err)
		}
		if _, err := os.Stat(filepath.Join(upper, stateGroupEpochsName, stateEpochName(1))); err != nil {
			t.Errorf("the stray folder's state went: %v", err)
		}
	})
	t.Run("the control: the same file", func(t *testing.T) {
		store := openTestStore(t, t.TempDir())
		if err := store.PutGroupRecord(record(renamed)); err != nil {
			t.Fatalf("PutGroupRecord: %v", err)
		}
		upper := upperCaseFolderOf(t, store, renamed)
		lstatAnswering(store, store.groupDir(renamed), upper)
		defer func() { store.lstat = nil }()
		root := filepath.Join(store.dataDir, "group")
		entries, err := os.ReadDir(root)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, entry := range entries {
			if entry.Name() != filepath.Base(upper) {
				continue
			}
			found = true
			if name, named := store.groupFolderNameOf(root, entry); !named || name != stateNameOf(renamed) {
				t.Errorf("CONTROL FAILED: the upper-case folder that IS the same file answered %q, %v, want its lowercase name", name, named)
			}
		}
		if !found {
			t.Fatalf("CONTROL FAILED: the root does not list the upper-case folder")
		}
	})
	t.Run("real folders, where the filesystem keeps the two names apart", func(t *testing.T) {
		store := openTestStore(t, t.TempDir())
		if err := store.PutGroupRecord(record(renamed)); err != nil {
			t.Fatalf("PutGroupRecord: %v", err)
		}
		upper := filepath.Join(store.dataDir, "group", strings.ToUpper(stateNameOf(renamed)))
		if err := os.Mkdir(upper, 0o700); err != nil {
			if errors.Is(err, os.ErrExist) {
				t.Skipf("this filesystem folds case, so an upper-case copy cannot stand beside the folder; the injected Lstat holds this half here")
			}
			t.Fatal(err)
		}
		octets, err := os.ReadFile(store.groupRecordPath(renamed))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(upper, stateGroupRecordName), octets, 0o600); err != nil {
			t.Fatal(err)
		}
		records, err := store.GroupRecords()
		if err != nil || len(records) != 1 || !bytes.Equal(records[0].GroupId, renamed) {
			t.Errorf("beside a real upper-case copy of its folder the group answered %d record(s), %v, want it listed once and no report", len(records), err)
		}
	})
}
