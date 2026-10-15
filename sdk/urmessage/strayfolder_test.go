package urmessage

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
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
	restored, err := device.Restore(context.Background())
	t.Logf("Restore beside a stray copy folder: %d group(s), %v", len(restored), err)
	if errors.Is(err, ErrGroupRecordDamaged) {
		t.Errorf("Restore reported a stray copy folder as a damaged group: %v", err)
	}
	if err != nil || len(restored) != 1 || !bytes.Equal(restored[0].Id(), groupId) {
		t.Errorf("Restore beside a stray copy folder answered %d group(s), %v, want the group back and nothing reported", len(restored), err)
	}
}
