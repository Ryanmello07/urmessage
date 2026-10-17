package urmessage

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/urnetwork/message/mls"
)

// AN INVITE INTO A GROUP WHOSE RECORD IS MISSING FROM A FOLDER WHERE THE STORE'S FILES STAND IS REFUSED
// AS UNPROVEN, BEFORE ANYTHING IS WRITTEN (R34, item 1). A joiner holds a group on its disk; at its
// restart the group's record is out of the folder, as a quarantine leaves it, with the epoch state
// still there. An invite into the same group is refused with the not-read form an app maps by class
// -- ErrGroupReadUnproven, "its directory stands and its record is not in it" -- and NOT with
// ErrGroupAlreadyHeld; nothing of the folder changes, and the join code is still on the disk.
//
// WHAT WOULD GO RED: the gate's absence read as "not held" again -- the join then writes into a folder
// that is not its own, and a failure after its commit takes its scope from that answer.
func TestAnInviteIntoAGroupWhoseRecordIsMissingIsRefusedAsUnproven(t *testing.T) {
	ctx := context.Background()
	dir, groupId := failClosedScene(t)
	store := openTestStore(t, dir)
	aside := filepath.Join(t.TempDir(), "meta")
	if err := os.Rename(store.groupRecordPath(groupId), aside); err != nil {
		t.Fatal(err)
	}
	before := failClosedFiles(t, store, groupId)
	device := newAnsweringDeviceOver(t, store, []byte("the restarted device's nonce"))
	testIdentify(t, device)
	invite, inviteId := windowInvite(t, device)
	if !bytes.Equal(inviteId, groupId) {
		t.Fatalf("CONTROL FAILED: the invite is into group %x and the folder is group %x's", inviteId, groupId)
	}
	_, err := device.Join(ctx, invite)
	t.Logf("the invite into the group whose record is missing: %v", err)
	if !errors.Is(err, ErrGroupReadUnproven) || errors.Is(err, ErrGroupAlreadyHeld) || errors.Is(err, ErrJoinCodeSpent) ||
		!strings.Contains(err.Error(), "its directory stands and its record is not in it") {
		t.Errorf("the invite answered %v, want the gate's unproven refusal and neither ErrGroupAlreadyHeld nor ErrJoinCodeSpent", err)
	}
	after := failClosedFiles(t, store, groupId)
	if len(after) != len(before) {
		t.Errorf("the refused invite changed the group's folder: %d file(s) before, %d after", len(before), len(after))
	}
	for name, content := range before {
		if after[name] != content {
			t.Errorf("%s of the group changed or went", name)
		}
	}
	if held := len(device.Groups()); held != 0 {
		t.Errorf("the refused invite left the device holding %d group(s)", held)
	}
}

// A FAILED JOIN OVER A CREATION THAT NEVER FINISHED ERASES ONLY WHAT IT WROTE (R34, item 2), on every
// platform. The folder holds what a join that died between its commit and its record leaves: the
// creation mark and an epoch state, at an epoch the new join does not use. The gate reads it as a
// group nobody holds yet, and the new join's record write is refused after its commit. The failed
// join takes its own epoch state and nothing else: the earlier state and the creation mark stand,
// for the sweep. (sdk/cp3b holds the same with a real deny, on Windows.)
//
// WHAT WOULD GO RED: abandonJoined's scope back to DeleteGroupRecord, which takes the earlier state
// too, under "a failed admission erasing what it wrote itself".
func TestAFailedJoinOverAnUnfinishedCreationErasesOnlyWhatItWrote(t *testing.T) {
	ctx := context.Background()
	durable := openTestStore(t, t.TempDir())
	store := &recordSink{DurableStateStore: durable}
	joiner := newAnsweringDeviceOver(t, store, []byte("the joiner's nonce"))
	testIdentify(t, joiner)
	honest, groupId := windowInvite(t, joiner)
	earlier := bytes.Repeat([]byte{0x7E}, 64)
	if err := durable.PutGroupState(groupId, 9, earlier); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(durable.pendingPath(groupId)); err != nil {
		t.Fatalf("CONTROL FAILED: the earlier creation has no mark: %v", err)
	}
	store.armed = true
	if _, err := joiner.Join(ctx, honest); !errors.Is(err, ErrJoinCodeSpent) {
		t.Fatalf("CONTROL FAILED: the join answered %v, want its record write refused after its commit", err)
	}
	if store.statesPut == 0 {
		t.Fatalf("CONTROL FAILED: the join wrote no state, so it did not fail past its commit")
	}
	if state, err := durable.GetGroupState(groupId, 9); err != nil || !bytes.Equal(state, earlier) {
		t.Errorf("the failed join took the earlier creation's state, which it did not write: %v", err)
	}
	if _, err := os.Stat(durable.pendingPath(groupId)); err != nil {
		t.Errorf("the failed join took the earlier creation's mark beside its state: %v", err)
	}
	if _, err := durable.GetGroupState(groupId, 1); !errors.Is(err, ErrStateNotFound) {
		t.Errorf("the joined epoch's state is still on the disk after the join failed: %v", err)
	}
}

// A FAILED JOIN OVER A FOLDER KEPT BY A STRAY FILE TAKES ONLY WHAT IT WROTE (R34, item 10, the table's
// cell (d)4). A group's folder outlived its erase, kept by a file the store did not write; the gate
// reads it as holding nothing of a group, the join's first state marks it as a creation, and the
// join's record write is refused after its commit. The failed join takes its state, its mark and
// its folder's store names, and the stray file stays: the folder then holds nothing of a group again.
//
// WHAT WOULD GO RED: a failed join's erase that walked the folder instead of naming what it wrote.
func TestAFailedJoinOverAFolderKeptByAStrayFileTakesOnlyWhatItWrote(t *testing.T) {
	ctx := context.Background()
	durable := openTestStore(t, t.TempDir())
	store := &recordSink{DurableStateStore: durable}
	joiner := newAnsweringDeviceOver(t, store, []byte("the joiner's nonce"))
	testIdentify(t, joiner)
	honest, groupId := windowInvite(t, joiner)
	if err := os.MkdirAll(durable.groupDir(groupId), 0o700); err != nil {
		t.Fatal(err)
	}
	stray := filepath.Join(durable.groupDir(groupId), "desktop.ini")
	if err := os.WriteFile(stray, []byte("[.ShellClassInfo]"), 0o600); err != nil {
		t.Fatal(err)
	}
	store.armed = true
	if _, err := joiner.Join(ctx, honest); !errors.Is(err, ErrJoinCodeSpent) {
		t.Fatalf("CONTROL FAILED: the join answered %v, want its record write refused after its commit", err)
	}
	if store.statesPut == 0 {
		t.Fatalf("CONTROL FAILED: the join wrote no state, so it did not fail past its commit")
	}
	if _, err := os.Stat(stray); err != nil {
		t.Errorf("the failed join took a file the store did not write: %v", err)
	}
	if holds, err := stateFolderHoldsOwnNames(durable.groupDir(groupId)); err != nil || holds {
		t.Errorf("after the failed join the folder holds the store's names (%v, %v): what it wrote is not all gone", holds, err)
	}
}

// plainStateStore is an mls.StateStore and nothing else: a store with no single-epoch erase.
type plainStateStore struct {
	mls.StateStore
}

// A STORE WITH NO SINGLE-EPOCH ERASE IS REFUSED, AND EVERY STATE STAYS (R34, item 2). A failed join
// over such a store used to be answered with everything below the joined epoch's successor erased
// whenever it was not a re-add, which is more than the join wrote whenever anything else stands for
// the group. Now the erase is refused, and both states stand.
//
// WHAT WOULD GO RED: the DeleteGroupStateBefore fallback put back -- the state at the epoch below the
// joined one, which the join did not write, erased.
func TestAStoreWithNoSingleEpochEraseIsRefusedAndKeepsEveryState(t *testing.T) {
	store := &plainStateStore{StateStore: NewMemoryStateStore()}
	device := newAnsweringDeviceOver(t, store, []byte("the device's nonce"))
	testIdentify(t, device)
	groupId := bytes.Repeat([]byte{0x75}, GroupIdBytes)
	for _, epoch := range []uint64{1, 2} {
		if err := store.PutGroupState(groupId, epoch, bytes.Repeat([]byte{byte(epoch)}, 32)); err != nil {
			t.Fatal(err)
		}
	}
	err := device.eraseJoinedState(groupId, 2)
	t.Logf("the erase over a store with no single-epoch erase: %v", err)
	if err == nil || !strings.Contains(err.Error(), "cannot erase one epoch's state") {
		t.Errorf("the erase answered %v, want it refused", err)
	}
	for _, epoch := range []uint64{1, 2} {
		if _, err := store.GetGroupState(groupId, epoch); err != nil {
			t.Errorf("the state at epoch %d went: %v", epoch, err)
		}
	}
}
