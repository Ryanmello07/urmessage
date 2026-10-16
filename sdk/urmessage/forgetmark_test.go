package urmessage

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// filesUnder is every regular file under one directory, relative to it.
func filesUnder(t *testing.T, dir string) []string {
	t.Helper()
	out := []string{}
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			return err
		}
		if info.Mode().IsRegular() {
			rel, _ := filepath.Rel(dir, path)
			out = append(out, rel)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", dir, err)
	}
	return out
}

// A LEAVE THAT STOPS PART WAY IS FINISHED, NOT LOST (msgrepo ledger §7, 2026-10-03, review H1). The
// store half, on every platform: the erase stops after the epoch states and before everything
// else, which is what a file another process holds open, or a crash, leaves behind. Without the
// mark that group was refused by every restore after it and named by nothing.
//
// WHAT WOULD GO RED: a GroupRecords that answers a marked group (the restore that fails at every
// launch), and a store that cannot list the groups being left (nothing finishes them). An erase
// that removes the mark FIRST is not caught here, because this case never interrupts
// DeleteGroupRecord itself: cp3b's held-open test catches it, on Windows only.
func TestAnEraseThatStopsAfterTheKeysIsFinishedAndNeverRestored(t *testing.T) {
	dir := t.TempDir()
	store := openTestStore(t, dir)
	for epoch := uint64(0); epoch < 3; epoch += 1 {
		if err := store.PutGroupState(testGroupId, epoch, testState); err != nil {
			t.Fatalf("PutGroupState %d: %v", epoch, err)
		}
	}
	if err := store.PutGroupRecord(&GroupRecord{
		GroupId: testGroupId, PqSecret: testPriv, GroupHandleKey: testPub, Epoch: 2, Opened: true,
	}); err != nil {
		t.Fatalf("PutGroupRecord: %v", err)
	}
	if err := store.PutSentRecord(testGroupId, testSentRecord(1, "a line this device sent")); err != nil {
		t.Fatalf("PutSentRecord: %v", err)
	}
	groupDir := store.groupDir(testGroupId)
	if records, err := store.GroupRecords(); err != nil || len(records) != 1 {
		t.Fatalf("CONTROL FAILED: before any mark the store answers %d record(s), %v", len(records), err)
	}

	if err := store.MarkGroupForgetting(testGroupId); err != nil {
		t.Fatalf("MarkGroupForgetting: %v", err)
	}
	// THE ERASE STOPS HERE: the keys are gone, and the sent copy, the record and the mark are not
	store.lock.Lock()
	err := store.deleteEpochsLocked(testGroupId, ^uint64(0))
	store.lock.Unlock()
	if err != nil {
		t.Fatalf("deleteEpochsLocked: %v", err)
	}
	if len(filesUnder(t, groupDir)) == 0 {
		t.Fatalf("CONTROL FAILED: the interrupted erase left nothing to finish")
	}

	records, err := store.GroupRecords()
	if err != nil {
		t.Fatalf("GroupRecords: %v", err)
	}
	if len(records) != 0 {
		t.Errorf("a group being left was answered as a group to restore, and its keys are gone")
	}
	marked, err := store.GroupBeingForgotten(testGroupId)
	if err != nil || !marked {
		t.Errorf("GroupBeingForgotten answered %v, %v for a marked group", marked, err)
	}
	leaving, err := store.GroupsBeingForgotten()
	if err != nil || len(leaving) != 1 || string(leaving[0]) != string(testGroupId) {
		t.Fatalf("GroupsBeingForgotten answered %d id(s), %v", len(leaving), err)
	}

	if err := store.DeleteGroupRecord(leaving[0]); err != nil {
		t.Fatalf("finishing the erase: %v", err)
	}
	if left := filesUnder(t, groupDir); len(left) != 0 {
		t.Errorf("the finished erase left %v", left)
	}
	if leaving, err := store.GroupsBeingForgotten(); err != nil || len(leaving) != 0 {
		t.Errorf("after the erase, %d group(s) are still being left, %v", len(leaving), err)
	}
}

// A GROUP WITH EPOCH STATES AND NO RECORD -- founded and never opened -- is marked and erased like
// any other: its epoch states are key material. And a mark copied into another group's directory
// is refused rather than obeyed: it would send the erase to a group nobody left.
func TestAMarkNeedsNoRecordAndMustNameTheDirectoryItSitsIn(t *testing.T) {
	store := openTestStore(t, t.TempDir())
	// a group founded and never opened, so it has no record
	lone := bytes.Repeat([]byte{0x5A}, GroupIdBytes)
	if err := store.PutGroupState(lone, 0, testState); err != nil {
		t.Fatalf("PutGroupState: %v", err)
	}
	if err := store.MarkGroupForgetting(lone); err != nil {
		t.Fatalf("marking a group with no record: %v", err)
	}
	if err := store.DeleteGroupRecord(lone); err != nil {
		t.Fatalf("erasing it: %v", err)
	}
	if left := filesUnder(t, store.groupDir(lone)); len(left) != 0 {
		t.Errorf("the erase of a group with no record left %v", left)
	}
	for _, groupId := range [][]byte{testGroupId, testGroupId2} {
		if err := store.PutGroupRecord(&GroupRecord{
			GroupId: groupId, PqSecret: testPriv, GroupHandleKey: testPub, Epoch: 1, Opened: true,
		}); err != nil {
			t.Fatalf("PutGroupRecord: %v", err)
		}
	}
	if err := store.MarkGroupForgetting(testGroupId); err != nil {
		t.Fatalf("MarkGroupForgetting: %v", err)
	}
	if leaving, err := store.GroupsBeingForgotten(); err != nil || len(leaving) != 1 {
		t.Fatalf("CONTROL FAILED: one honest mark answered %d, %v", len(leaving), err)
	}
	source, err := os.Open(store.forgettingPath(testGroupId))
	if err != nil {
		t.Fatalf("opening the mark: %v", err)
	}
	raw, err := io.ReadAll(source)
	source.Close()
	if err != nil {
		t.Fatalf("reading the mark: %v", err)
	}
	if err := os.WriteFile(store.forgettingPath(testGroupId2), raw, 0o600); err != nil {
		t.Fatalf("copying the mark: %v", err)
	}
	if _, err := store.GroupsBeingForgotten(); !errors.Is(err, ErrStateStoreFormat) {
		t.Errorf("a mark naming another group's directory answered %v, want ErrStateStoreFormat", err)
	}
}

// A LEAVE MARK NAMES THE JOIN OF THE GROUP IT DECIDED ON, AND FINISHES ONLY THAT ONE (R36, item 2: the
// round-5 review's Z2, the store half, on every platform). A device holds a group at epochs 1 to 3,
// its record at 2, and leaves it: the mark carries the group id and 3, the highest epoch held, and
// the leave finishes. The device joins the group again, at epoch 6, and the OLD mark is put back:
//   - it is no instruction: no group is being left, the mark is gone, and the record reads;
//   - put back again, the erase itself holds it against what stands, and erases nothing;
//   - the same with only a later epoch state standing, as a join that died before its record leaves;
//   - a mark that names no epoch decides nothing: the leave refuses it as unproven, and nothing goes.
//
// WHAT WOULD GO RED: a mark finished on its group id alone -- the round-5 review emptied a live
// re-joined group's folder on a mark put back, at 93cc0af.
func TestALeaveMarkNamesTheJoinItDecidedOn(t *testing.T) {
	store := openTestStore(t, t.TempDir())
	groupId := bytes.Repeat([]byte{0x5B}, GroupIdBytes)
	record := func(epoch uint64) *GroupRecord {
		return &GroupRecord{GroupId: groupId, PqSecret: testPriv, GroupHandleKey: testPub, Epoch: epoch, Opened: true}
	}
	groupDir := store.groupDir(groupId)
	for epoch := uint64(1); epoch <= 3; epoch++ {
		if err := store.PutGroupState(groupId, epoch, testState); err != nil {
			t.Fatalf("PutGroupState %d: %v", epoch, err)
		}
	}
	if err := store.PutGroupRecord(record(2)); err != nil {
		t.Fatalf("PutGroupRecord: %v", err)
	}
	if err := store.MarkGroupForgetting(groupId); err != nil {
		t.Fatalf("MarkGroupForgetting: %v", err)
	}
	parts, err := store.readRecord(store.forgettingPath(groupId), stateKindForgetting)
	if err != nil || len(parts) != 2 || !bytes.Equal(parts[0], groupId) || len(parts[1]) != 8 || binary.BigEndian.Uint64(parts[1]) != 3 {
		t.Fatalf("the leave mark reads %d part(s), %v, want the group id and epoch 3, the highest this device held", len(parts), err)
	}
	old, err := os.ReadFile(store.forgettingPath(groupId))
	if err != nil {
		t.Fatal(err)
	}
	// THE CONTROL: the mark finishes the join it decided on
	if marked, err := store.GroupBeingForgotten(groupId); err != nil || !marked {
		t.Fatalf("CONTROL FAILED: the mark of the join it decided on answered %v, %v", marked, err)
	}
	if err := store.DeleteGroupRecord(groupId); err != nil {
		t.Fatalf("CONTROL FAILED: the leave of the join it decided on: %v", err)
	}
	if left := filesUnder(t, groupDir); len(left) != 0 {
		t.Fatalf("CONTROL FAILED: the finished leave left %v", left)
	}

	// THE LATER JOIN, and the old mark put back
	if err := store.PutGroupState(groupId, 6, testState); err != nil {
		t.Fatalf("PutGroupState 6: %v", err)
	}
	if err := store.PutGroupRecord(record(6)); err != nil {
		t.Fatalf("PutGroupRecord 6: %v", err)
	}
	before := filesUnder(t, groupDir)
	putBack := func() {
		t.Helper()
		if err := os.WriteFile(store.forgettingPath(groupId), old, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	putBack()
	if leaving, err := store.GroupsBeingForgotten(); err != nil || len(leaving) != 0 {
		t.Errorf("an old mark put back over a later join answered %d group(s) being left, %v, want none", len(leaving), err)
	}
	if _, err := os.Stat(store.forgettingPath(groupId)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the stale mark still stands: %v", err)
	}
	if records, err := store.GroupRecords(); err != nil || len(records) != 1 || records[0].Epoch != 6 {
		t.Errorf("the later join's record answered %d record(s), %v, want the one at epoch 6", len(records), err)
	}
	putBack()
	if marked, err := store.GroupBeingForgotten(groupId); err != nil || marked {
		t.Errorf("the one-id question over an old mark answered %v, %v, want no leave under way", marked, err)
	}
	putBack()
	if err := store.DeleteGroupRecord(groupId); !errors.Is(err, errLeaveMarkStale) {
		t.Errorf("the erase over an old mark answered %v, want errLeaveMarkStale", err)
	}
	if after := filesUnder(t, groupDir); len(after) != len(before) {
		t.Errorf("the later join's files went %d to %d: %v", len(before), len(after), after)
	}

	// A LATER EPOCH STATE ALONE, as a join that died between its commit and its record leaves
	for _, name := range []string{store.groupRecordPath(groupId), store.recordedPath(groupId)} {
		if err := os.Remove(name); err != nil {
			t.Fatal(err)
		}
	}
	putBack()
	if err := store.DeleteGroupRecord(groupId); !errors.Is(err, errLeaveMarkStale) {
		t.Errorf("the erase over an old mark beside a later epoch state answered %v, want errLeaveMarkStale", err)
	}
	if _, err := store.GetGroupState(groupId, 6); err != nil {
		t.Errorf("the later epoch state went: %v", err)
	}

	// A MARK THAT NAMES NO EPOCH DECIDES NOTHING
	if err := store.writeRecord(store.forgettingPath(groupId), stateKindForgetting, groupId); err != nil {
		t.Fatal(err)
	}
	if marked, err := store.GroupBeingForgotten(groupId); marked || !errors.Is(err, ErrGroupReadUnproven) {
		t.Errorf("a mark that names no epoch answered %v, %v, want it refused as unproven", marked, err)
	}
	if err := store.DeleteGroupRecord(groupId); !errors.Is(err, ErrGroupReadUnproven) {
		t.Errorf("the erase over a mark that names no epoch answered %v, want it refused as unproven", err)
	}
	if leaving, err := store.GroupsBeingForgotten(); len(leaving) != 0 || !errors.Is(err, ErrGroupReadUnproven) {
		t.Errorf("the list over a mark that names no epoch answered %d group(s), %v, want none and the unproven report", len(leaving), err)
	}
	if _, err := store.GetGroupState(groupId, 6); err != nil {
		t.Errorf("the epoch state beside a mark that names no epoch went: %v", err)
	}
}
