package urmessage

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"
)

// NO EPOCH STATE OUTLIVES A JOIN THAT FAILED AFTER ITS COMMIT (Task 57, F3). The joined state is
// the joined leaf's private keys; with no record beside it nothing restores it, lists it or leaves
// it, while the adder's group keeps the leaf. A join whose record cannot be written answers
// [ErrJoinCodeSpent], and then the store holds nothing of the group at all.
//
// WHAT WOULD GO RED: leave the committed state where the commit put it, and a disk holds the
// private keys of a leaf in a group the person was told they never joined.
func TestAJoinThatFailsAfterItsCommitLeavesNoEpochStateBehind(t *testing.T) {
	ctx := context.Background()
	durable := openTestStore(t, t.TempDir())
	store := &recordSink{DurableStateStore: durable}
	joiner := newAnsweringDeviceOver(t, store, []byte("the joiner's nonce"))
	honest, groupId := windowInvite(t, joiner)
	store.armed = true
	_, err := joiner.Join(ctx, honest)
	if !errors.Is(err, ErrJoinCodeSpent) {
		t.Fatalf("a join whose record could not be written answered %v, want ErrJoinCodeSpent", err)
	}
	if store.statesPut == 0 {
		t.Fatalf("CONTROL FAILED: the join wrote no state, so it did not fail past its commit")
	}
	if _, err := durable.GetGroupState(groupId, 1); !errors.Is(err, ErrStateNotFound) {
		t.Errorf("the joined epoch's state is still in the store after the join failed: %v", err)
	}
	if _, err := os.Stat(durable.groupDir(groupId)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the group's directory is still on the disk after the join failed: %v", err)
	}
}

// RESTORE ERASES EPOCH STATE THAT NO RECORD STANDS BESIDE, AND NOTHING ELSE (Task 57, F3). A crash
// between a join's commit and its record leaves exactly that: one epoch state of a group, and no
// record. The next start's Restore erases it, says so in
// [DurableStateStore.ErasedWithNoRecord], and refuses nothing for it.
//
// THE CONTROLS are what it must not touch: a group founded in this process and not yet opened,
// whose epoch-zero state has no record by design; and a group whose record does not read.
//
// WHAT WOULD GO RED: no sweep, and the orphan's leaf keys stay on the disk for good; a sweep that
// does not skip the held group, and a founder loses its group at the next Restore.
func TestRestoreErasesEpochStateNoRecordStandsBesideAndNothingElse(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, t.TempDir())
	orphan := bytes.Repeat([]byte{0x61}, GroupIdBytes)
	damaged := bytes.Repeat([]byte{0x62}, GroupIdBytes)
	founded := bytes.Repeat([]byte{0x64}, GroupIdBytes)
	state := bytes.Repeat([]byte{0x7E}, 64)
	for _, groupId := range [][]byte{orphan, damaged} {
		if err := store.PutGroupState(groupId, 1, state); err != nil {
			t.Fatalf("PutGroupState: %v", err)
		}
	}
	// the damaged group's record is there, and does not read
	if err := store.PutGroupRecord(&GroupRecord{
		GroupId: damaged, PqSecret: bytes.Repeat([]byte{0x2A}, 32), GroupHandleKey: bytes.Repeat([]byte{0x5C}, 32), Epoch: 1, Opened: true,
	}); err != nil {
		t.Fatalf("PutGroupRecord: %v", err)
	}
	octets, err := os.ReadFile(store.groupRecordPath(damaged))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(store.groupRecordPath(damaged), octets[:len(octets)/2], 0o600); err != nil {
		t.Fatal(err)
	}
	device := newAnsweringDeviceOver(t, store, []byte("the device's nonce"))
	if _, err := device.CreateGroup(ctx, founded); err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if _, err := store.GetGroupState(founded, 0); err != nil {
		t.Fatalf("CONTROL FAILED: the founded group has no epoch-zero state on the disk: %v", err)
	}

	_, err = device.Restore(ctx)
	if !errors.Is(err, ErrGroupRecordDamaged) {
		t.Errorf("Restore answered %v, want the damaged record reported and nothing else refused", err)
	}
	if _, err := store.GetGroupState(orphan, 1); !errors.Is(err, ErrStateNotFound) {
		t.Errorf("the epoch state with no record beside it is still on the disk after Restore: %v", err)
	}
	if _, err := os.Stat(store.groupDir(orphan)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the orphan's directory is still on the disk after Restore: %v", err)
	}
	if erased := store.ErasedWithNoRecord(); len(erased) != 1 || erased[0] != stateNameOf(orphan) {
		t.Errorf("the store says it erased %v, want the orphan's directory alone", erased)
	}
	// THE CONTROLS
	if _, err := store.GetGroupState(founded, 0); err != nil {
		t.Errorf("Restore erased the epoch-zero state of a group this device founded and holds: %v", err)
	}
	if _, err := store.GetGroupState(damaged, 1); err != nil {
		t.Errorf("Restore erased the epoch state of a group whose record does not read: %v", err)
	}
}

// landedRecordSink is a durable store whose group-record write, once armed, LANDS and then
// reports a failure, as a rename that succeeded before its directory sync failed does.
type landedRecordSink struct {
	*DurableStateStore
	armed bool
}

func (self *landedRecordSink) PutGroupRecord(record *GroupRecord) error {
	if err := self.DurableStateStore.PutGroupRecord(record); err != nil {
		return err
	}
	if self.armed {
		return errors.New("the store this test sits on wrote the record and then could not sync its directory")
	}
	return nil
}

// A JOIN WHOSE RECORD LANDED AND THEN FAILED LEAVES NO RECORD BEHIND (R26, the fix review's V4b).
// The record a failed join wrote holds the joined epoch's pq_secret and the group's handle key,
// with no state behind it. Off a re-add, the failed join takes it with the state.
//
// WHAT WOULD GO RED: erase the state and not the record, and the disk holds a record of a group
// the person was told they never joined, with its secrets in it.
func TestAJoinWhoseRecordLandedAndThenFailedLeavesNoRecordBehind(t *testing.T) {
	ctx := context.Background()
	durable := openTestStore(t, t.TempDir())
	store := &landedRecordSink{DurableStateStore: durable}
	joiner := newAnsweringDeviceOver(t, store, []byte("the joiner's nonce"))
	honest, groupId := windowInvite(t, joiner)
	store.armed = true
	if _, err := joiner.Join(ctx, honest); !errors.Is(err, ErrJoinCodeSpent) {
		t.Fatalf("a join whose record landed and then failed answered %v, want ErrJoinCodeSpent", err)
	}
	if _, err := durable.GroupRecord(groupId); !errors.Is(err, ErrStateNotFound) {
		t.Errorf("the failed join's record is still on the disk: %v", err)
	}
	if _, err := os.Stat(durable.groupDir(groupId)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the failed join's group directory is still on the disk: %v", err)
	}
}
