package urmessage

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
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
	testIdentify(t, joiner)
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
// [DurableStateStore.ErasedWithNoRecord], and refuses nothing for it. It is erased on the store's
// own `pending` mark, which the state's write put down when it created the directory (R33); this
// case is kept green through that mark, and the case after the next holds the mark itself.
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
	testIdentify(t, device)
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

// THE SWEEP ERASES ON ITS OWN MARK, AND A STALE MARK GOES (R33 (2), the crash-shaped pair). The
// store marks a group directory `pending` when a call creates it, before the first epoch state, and
// takes the mark away once the group's record is synced. Two crashes leave the two shapes a mark is
// ever found in:
//   - between the first epoch state and the record: the mark and the state, and no record. The
//     next Restore erases the directory, as F3 rules;
//   - between the record and the mark's removal: the mark beside a record that reads. The next
//     Restore erases nothing, and takes the stale mark away, so that the directory's fate is the
//     record's -- a record that goes missing LATER is then no mark's to sweep.
//
// WHAT WOULD GO RED: a sweep that keeps a stale mark beside a record, or that erases a directory
// holding a record; and a store that does not mark the directory it creates, so F3's orphan stays.
func TestTheSweepErasesOnItsOwnMarkAndAStaleMarkGoes(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, t.TempDir())
	orphan := bytes.Repeat([]byte{0x71}, GroupIdBytes)
	recorded := bytes.Repeat([]byte{0x72}, GroupIdBytes)
	state := bytes.Repeat([]byte{0x7E}, 64)
	for _, groupId := range [][]byte{orphan, recorded} {
		if err := store.PutGroupState(groupId, 1, state); err != nil {
			t.Fatalf("PutGroupState: %v", err)
		}
		if _, err := os.Stat(store.pendingPath(groupId)); err != nil {
			t.Fatalf("the store did not mark the directory its first state created: %v", err)
		}
	}
	// THE SECOND CRASH: the record is synced, and the mark stands beside it as a crash before its
	// removal leaves it
	mark, err := os.ReadFile(store.pendingPath(recorded))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PutGroupRecord(&GroupRecord{
		GroupId: recorded, PqSecret: bytes.Repeat([]byte{0x2A}, 32), GroupHandleKey: bytes.Repeat([]byte{0x5C}, 32), Epoch: 1, Opened: true,
	}); err != nil {
		t.Fatalf("PutGroupRecord: %v", err)
	}
	if _, err := os.Stat(store.pendingPath(recorded)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("PutGroupRecord left the mark beside the record it wrote: %v", err)
	}
	if err := os.WriteFile(store.pendingPath(recorded), mark, 0o600); err != nil {
		t.Fatal(err)
	}

	device := newAnsweringDeviceOver(t, store, []byte("the device's nonce"))
	testIdentify(t, device)
	_, err = device.Restore(ctx)
	t.Logf("Restore: %v", err)
	// THE FIRST SHAPE IS ERASED
	if _, err := os.Stat(store.groupDir(orphan)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the marked directory with a state and no record is still on the disk after Restore: %v", err)
	}
	if erased := store.ErasedWithNoRecord(); len(erased) != 1 || erased[0] != stateNameOf(orphan) {
		t.Errorf("the store says it erased %v, want the marked orphan's directory alone", erased)
	}
	// THE SECOND IS NOT, AND ITS STALE MARK IS GONE
	if _, err := store.GetGroupState(recorded, 1); err != nil {
		t.Errorf("Restore erased the state of a group whose record reads: %v", err)
	}
	if _, err := store.GroupRecord(recorded); err != nil {
		t.Errorf("the record beside the stale mark does not read after Restore: %v", err)
	}
	if _, err := os.Stat(store.pendingPath(recorded)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Restore left the stale mark beside a record that reads: %v", err)
	}
}

// A CREATION MARK RETRACTED BY `recorded` IS NOT A CREATION, AND A RECORD THAT READS TAKES THE MARK
// AWAY AND KEEPS ITS RETRACTION (R34, items 4 to 6; R36, item 1). The shape a mark whose removal
// failed leaves, built by the store's own writes: the mark, its retraction and an epoch state, with
// the record moved out of the folder. The Restore erases nothing: the folder is not in the creating
// state. With the record put back, the next Restore reads it and takes `pending` away, and `recorded`
// stays, for the group's life.
//
// THIS CASE WAS CHANGED BY R36, TRUTHFULLY: it held that the Restore took `recorded` away too, and a
// retraction taken away whenever the mark is not in its place is undone by a mark that was only
// elsewhere (the round-5 review's Z1).
//
// WHAT WOULD GO RED: a sweep that asks for the mark and not for its retraction -- the owner's group
// whose record a quarantine holds, erased on a mark that stopped being true when the record landed --
// and a sweep that takes the retraction away again.
func TestARetractedCreationMarkIsNotSweptAndARecordThatReadsKeepsItsRetraction(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, t.TempDir())
	groupId := bytes.Repeat([]byte{0x73}, GroupIdBytes)
	state := bytes.Repeat([]byte{0x7E}, 64)
	if err := store.PutGroupState(groupId, 1, state); err != nil {
		t.Fatalf("PutGroupState: %v", err)
	}
	mark, err := os.ReadFile(store.pendingPath(groupId))
	if err != nil {
		t.Fatalf("CONTROL FAILED: the store did not mark the directory its first state created: %v", err)
	}
	if err := store.PutGroupRecord(&GroupRecord{
		GroupId: groupId, PqSecret: bytes.Repeat([]byte{0x2A}, 32), GroupHandleKey: bytes.Repeat([]byte{0x5C}, 32), Epoch: 1, Opened: true,
	}); err != nil {
		t.Fatalf("PutGroupRecord: %v", err)
	}
	// THE SHAPE A FAILED REMOVAL LEAVES: the mark, and the retraction PutGroupRecord writes then
	if err := os.WriteFile(store.pendingPath(groupId), mark, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.writeRecord(store.recordedPath(groupId), stateKindRecorded, groupId); err != nil {
		t.Fatal(err)
	}
	aside := filepath.Join(t.TempDir(), "meta")
	if err := os.Rename(store.groupRecordPath(groupId), aside); err != nil {
		t.Fatal(err)
	}

	device := newAnsweringDeviceOver(t, store, []byte("the device's nonce"))
	testIdentify(t, device)
	_, err = device.Restore(ctx)
	t.Logf("Restore with the record away: %v", err)
	if erased := store.ErasedWithNoRecord(); len(erased) != 0 {
		t.Errorf("the sweep erased %v, a folder whose mark its record had retracted", erased)
	}
	if _, err := store.GetGroupState(groupId, 1); err != nil {
		t.Errorf("the epoch state does not read after the Restore: %v", err)
	}

	if err := os.Rename(aside, store.groupRecordPath(groupId)); err != nil {
		t.Fatal(err)
	}
	_, err = device.Restore(ctx)
	t.Logf("Restore with the record back: %v", err)
	if _, err := os.Stat(store.pendingPath(groupId)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the creation mark stands beside a record that read: %v", err)
	}
	if _, err := os.Stat(store.recordedPath(groupId)); err != nil {
		t.Errorf("the Restore that read the record took its retraction away: %v", err)
	}
}

// THE CREATION'S RETRACTION IS KEPT FOR THE GROUP'S LIFE, AND ONLY A LEAVE TAKES IT (R36, item 1: the
// round-5 review's Z1, on every platform, with the store's own writes and plain moves). The record
// lands and `recorded` is written beside it, with the mark gone. Then, one move at a time:
//   - a second record write keeps it;
//   - the creation mark put back and the record moved out of the folder: the Restore erases nothing,
//     because the folder still holds the retraction;
//   - the record put back: the Restore takes the mark away again and keeps the retraction;
//   - the retraction itself moved away: the Restore that reads the record writes it again;
//   - the leave: DeleteGroupRecord takes it, with the group.
//
// WHAT WOULD GO RED: `recorded` taken away whenever the mark's removal answered -- a mark that was
// only elsewhere answers too -- and the sweep then takes a live group on the mark put back; or a
// Restore that takes the retraction away after the mark.
func TestTheCreationsRetractionIsKeptForTheGroupsLife(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, t.TempDir())
	groupId := bytes.Repeat([]byte{0x77}, GroupIdBytes)
	if err := store.PutGroupState(groupId, 1, bytes.Repeat([]byte{0x7E}, 64)); err != nil {
		t.Fatalf("PutGroupState: %v", err)
	}
	mark, err := os.ReadFile(store.pendingPath(groupId))
	if err != nil {
		t.Fatalf("CONTROL FAILED: the store did not mark the directory its first state created: %v", err)
	}
	record := &GroupRecord{
		GroupId: groupId, PqSecret: bytes.Repeat([]byte{0x2A}, 32), GroupHandleKey: bytes.Repeat([]byte{0x5C}, 32), Epoch: 1, Opened: true,
	}
	for round := 1; round <= 2; round++ {
		if err := store.PutGroupRecord(record); err != nil {
			t.Fatalf("PutGroupRecord, round %d: %v", round, err)
		}
		if _, err := os.Stat(store.recordedPath(groupId)); err != nil {
			t.Fatalf("after record write %d no retraction stands beside the record: %v", round, err)
		}
		if _, err := os.Stat(store.pendingPath(groupId)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("after record write %d the creation mark stands: %v", round, err)
		}
	}
	device := newAnsweringDeviceOver(t, store, []byte("the device's nonce"))
	testIdentify(t, device)

	// the mark put back, and the record moved away
	if err := os.WriteFile(store.pendingPath(groupId), mark, 0o600); err != nil {
		t.Fatal(err)
	}
	aside := filepath.Join(t.TempDir(), "meta")
	if err := os.Rename(store.groupRecordPath(groupId), aside); err != nil {
		t.Fatal(err)
	}
	_, err = device.Restore(ctx)
	t.Logf("Restore with the mark put back and the record away: %v", err)
	if erased := store.ErasedWithNoRecord(); len(erased) != 0 {
		t.Fatalf("the sweep erased %v: a live group, on a creation mark put back beside its retraction", erased)
	}
	if _, err := store.GetGroupState(groupId, 1); err != nil {
		t.Fatalf("the epoch state does not read after that Restore: %v", err)
	}

	// the record put back (the state is the case's own octets, so the group itself does not restore,
	// and nothing holds it: every Restore below sweeps its folder)
	if err := os.Rename(aside, store.groupRecordPath(groupId)); err != nil {
		t.Fatal(err)
	}
	_, err = device.Restore(ctx)
	t.Logf("Restore with the record back: %v", err)
	if erased := store.ErasedWithNoRecord(); len(erased) != 0 {
		t.Fatalf("the sweep erased %v, a folder whose record reads", erased)
	}
	if _, err := os.Stat(store.pendingPath(groupId)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the creation mark stands beside a record that read: %v", err)
	}
	if _, err := os.Stat(store.recordedPath(groupId)); err != nil {
		t.Errorf("the Restore that read the record took its retraction away: %v", err)
	}

	// the retraction moved away: a Restore that reads the record writes it again
	if err := os.Rename(store.recordedPath(groupId), filepath.Join(t.TempDir(), "recorded")); err != nil {
		t.Fatal(err)
	}
	_, err = device.Restore(ctx)
	t.Logf("the Restore with the retraction away: %v", err)
	if _, err := os.Stat(store.recordedPath(groupId)); err != nil {
		t.Errorf("the Restore that read the record did not write its missing retraction again: %v", err)
	}

	// the leave takes it, with the group
	if err := store.DeleteGroupRecord(groupId); err != nil {
		t.Fatalf("DeleteGroupRecord: %v", err)
	}
	if _, err := os.Stat(store.recordedPath(groupId)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the retraction outlived the leave: %v", err)
	}
}

// THE SWEEP TAKES ONLY THE STORE'S OWN ENTRIES OF A CREATION THAT NEVER FINISHED (R34, item 10, the
// table's cell (c)4: a stray file left in the folder). A creation's folder holds the store's mark, an
// epoch state, and a file the store did not write in the epoch directory, as a sync tool's conflicted
// copy is. The Restore erases the epoch state and leaves the stray file, and the mark beside it: the
// mark's reason is true of what the store wrote and of nothing else. A second Restore takes nothing
// more and names nothing more.
//
// WHAT WOULD GO RED: the sweep removing every entry of the epoch directory, the stray file with it,
// on a mark whose reason says nothing of a file the store did not write.
func TestTheSweepTakesOnlyTheStoresOwnEntriesOfACreation(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, t.TempDir())
	groupId := bytes.Repeat([]byte{0x76}, GroupIdBytes)
	if err := store.PutGroupState(groupId, 1, bytes.Repeat([]byte{0x7E}, 64)); err != nil {
		t.Fatalf("PutGroupState: %v", err)
	}
	stray := filepath.Join(store.epochDir(groupId), "0000000000000001 (conflicted copy).bin")
	if err := os.WriteFile(stray, []byte("not the store's"), 0o600); err != nil {
		t.Fatal(err)
	}
	device := newAnsweringDeviceOver(t, store, []byte("the device's nonce"))
	testIdentify(t, device)
	if _, err := device.Restore(ctx); err != nil {
		t.Logf("Restore: %v", err)
	}
	if _, err := store.GetGroupState(groupId, 1); !errors.Is(err, ErrStateNotFound) {
		t.Errorf("the creation's epoch state is still on the disk after the sweep: %v", err)
	}
	if _, err := os.Stat(stray); err != nil {
		t.Errorf("the sweep took a file the store did not write: %v", err)
	}
	if _, err := os.Stat(store.pendingPath(groupId)); err != nil {
		t.Errorf("the mark beside the file the sweep left went: %v", err)
	}
	if erased := store.ErasedWithNoRecord(); len(erased) != 1 || erased[0] != stateNameOf(groupId) {
		t.Errorf("the store says it erased %v, want the creation's folder once", erased)
	}
	if _, err := device.Restore(ctx); err != nil {
		t.Logf("the second Restore: %v", err)
	}
	if erased := store.ErasedWithNoRecord(); len(erased) != 1 {
		t.Errorf("the second Restore erased more: %v", erased)
	}
	if _, err := os.Stat(stray); err != nil {
		t.Errorf("the second Restore took the stray file: %v", err)
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
	testIdentify(t, joiner)
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
