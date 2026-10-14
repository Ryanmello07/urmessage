package urmessage

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"github.com/urnetwork/message/messagegroup"
	"github.com/urnetwork/message/syntax"
)

// THE ERASE WITHOUT THE OWNER'S QUESTION IS FAIL-CLOSED (R29). [Device.ForgetGroup] leaves a group
// that failed to restore WITHOUT the owner's question only on PROOF that this build can never read
// it. The cases here hold that at its subject -- the group's restore -- with a store that fails one
// group's epoch-state read with an error of the case's choosing, on every platform.

// failClosedScene is a durable store directory holding ONE group a device joined, its record and
// its joined epoch's state, with that device and the store closed: a disk a restart restores.
func failClosedScene(t *testing.T) (string, []byte) {
	t.Helper()
	dir := t.TempDir()
	durable, err := OpenDurableStateStore(dir)
	if err != nil {
		t.Fatalf("OpenDurableStateStore: %v", err)
	}
	joiner := newAnsweringDeviceOver(t, durable, []byte("the joiner's nonce"))
	honest, groupId := windowInvite(t, joiner)
	if _, err := joiner.Join(context.Background(), honest); err != nil {
		t.Fatalf("the honest join: %v", err)
	}
	joiner.Close()
	if err := durable.Close(); err != nil {
		t.Fatalf("closing the store before the restart: %v", err)
	}
	return dir, groupId
}

// failingStore is a durable store whose read of one group's epoch state answers, while it is
// armed, the error it is armed with.
type failingStore struct {
	*DurableStateStore
	groupId  []byte
	failWith error
}

func (self *failingStore) GetGroupState(groupId []byte, epoch uint64) ([]byte, error) {
	if self.failWith != nil && bytes.Equal(groupId, self.groupId) {
		return nil, self.failWith
	}
	return self.DurableStateStore.GetGroupState(groupId, epoch)
}

// failClosedRestart starts a NEW device over the scene's directory, through a [failingStore].
func failClosedRestart(t *testing.T, dir string, groupId []byte, failWith error) (*failingStore, *Device) {
	t.Helper()
	store := &failingStore{DurableStateStore: openTestStore(t, dir), groupId: groupId, failWith: failWith}
	return store, newAnsweringDeviceOver(t, store, []byte("the restarted device's nonce"))
}

// failClosedFiles is every file under one group's directory, by its path inside it, with its
// octets: what "the files unchanged" is held against.
func failClosedFiles(t *testing.T, store *DurableStateStore, groupId []byte) map[string]string {
	t.Helper()
	root := store.groupDir(groupId)
	files := map[string]string{}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		octets, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		relative, _ := filepath.Rel(root, path)
		files[filepath.ToSlash(relative)] = string(octets)
		return nil
	})
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("listing the group's files: %v", err)
	}
	return files
}

// asStoreRead is an OS error as the durable store wraps one: its own sentinel, and the error.
func asStoreRead(errno syscall.Errno) error {
	return fmt.Errorf("%w: epoch/0000000000000001 could not be read: %w", ErrStateStoreState,
		&os.PathError{Op: "open", Path: "epoch/0000000000000001", Err: errno})
}

// tooManyOpenFiles is this platform's errno for a process out of file handles.
func tooManyOpenFiles() syscall.Errno {
	if runtime.GOOS == "windows" {
		return syscall.Errno(4) // ERROR_TOO_MANY_OPEN_FILES
	}
	return syscall.EMFILE
}

// ONLY AN ALLOW-LISTED FAILURE IS PROVEN PERMANENT, AND ONLY A FACT ABOUT THE DATA IS ON THE LIST
// (R29, amended by R30 and R33). [classifyRead] is held over its three classes, both ways, against
// lists written out here and not read from the code: R33's proven-permanent errnos (a path of the
// wrong type, unambiguously) and sentinels are permanent; R26's sharing and lock violations are
// transient; and everything else is UNPROVEN -- an absence, a permission refused and the medium,
// which are facts about the environment, a store error with no errno, an errno in neither list (too
// many open files, out of memory, no system resources), a permanent-looking errno the store did not
// carry, a cancelled context, an engine refusal, nil.
//
// THIS CASE WAS CHANGED TWICE, TRUTHFULLY. R30 moved EACCES, EPERM, EIO and Windows 5, 23, 27 and 30
// from proven permanent to unproven. R33 moved an absence there too: ErrStateNotFound, ENOENT,
// Windows 2, 3 (which is also package syscall's ENOTDIR on Windows) and 53.
//
// WHAT WOULD GO RED: a classifier that answers "permanent" by default, which is the fail-open rule
// that leaked three times; one that drops a class R30 proves permanent, and that group can no longer
// be left; or one that calls a refused permission damage, and intact data is erased because of the
// environment.
func TestOnlyAnAllowListedFailureIsProvenPermanent(t *testing.T) {
	permanentByErrno := []syscall.Errno{syscall.EISDIR, syscall.ELOOP}
	unprovenByErrno := []syscall.Errno{syscall.EMFILE, syscall.ENFILE, syscall.ENOMEM,
		syscall.EACCES, syscall.EPERM, syscall.EIO, syscall.ENOENT}
	if runtime.GOOS == "windows" {
		permanentByErrno = append(permanentByErrno, 1, 267, 1921)
		// too many open files, no memory, no resources, not ready; access denied; the medium; the
		// three absences (ENOTDIR is 3 here, and so is a missing path)
		unprovenByErrno = append(unprovenByErrno, 4, 8, 1450, 21, 5, 23, 27, 30, 2, 3, 53, syscall.ENOTDIR)
	} else {
		permanentByErrno = append(permanentByErrno, syscall.ENOTDIR)
	}
	for _, errno := range permanentByErrno {
		if got := classifyRead(asStoreRead(errno)); got != readPermanent {
			t.Errorf("errno %d (%v), carried by the store, is classed %d, want proven permanent", uint(errno), errno, got)
		}
		if got := classifyRead(&os.PathError{Op: "open", Path: "x", Err: errno}); got != readUnproven {
			t.Errorf("errno %d NOT carried by the store is classed %d, want unproven: an errno anybody else carried proves nothing about this disk", uint(errno), got)
		}
	}
	for _, errno := range transientErrnos {
		if got := classifyRead(asStoreRead(errno)); got != readTransient {
			t.Errorf("errno %d (%v) is a sharing or lock violation and is classed %d, want transient", uint(errno), errno, got)
		}
	}
	for _, errno := range unprovenByErrno {
		if got := classifyRead(asStoreRead(errno)); got != readUnproven {
			t.Errorf("errno %d (%v) is in neither list and is classed %d, want unproven", uint(errno), errno, got)
		}
	}
	for _, one := range []struct {
		name string
		err  error
		want readClass
	}{
		{"a checksum or format verdict", fmt.Errorf("%w: the record's checksum is not the hash of the record", ErrStateStoreFormat), readPermanent},
		{"a record that does not name its group", fmt.Errorf("%w: %w: the record in x does not name its own group", ErrGroupRecordDamaged, ErrStateStoreFormat), readPermanent},
		{"a required file absent", fmt.Errorf("%w: 0000000000000001", ErrStateNotFound), readUnproven},
		{"an epoch state that does not decode", fmt.Errorf("mls: the state: %w", syntax.ErrTruncated), readPermanent},
		{"an epoch state with bytes after it", fmt.Errorf("mls: the state: %w", syntax.ErrTrailingBytes), readPermanent},
		{"a group founded before the join seal", fmt.Errorf("%w: group x at epoch 1: %w", ErrRestore, ErrGroupPredatesJoinSeal), readPermanent},
		{"a store error with no errno", fmt.Errorf("%w: this store is closed", ErrStateStoreState), readUnproven},
		{"a cancelled context", fmt.Errorf("the engine could not load the group: %w", context.Canceled), readUnproven},
		{"an engine refusal that is not on the list", fmt.Errorf("%w: group x", messagegroup.ErrEngineLoadedEpoch), readUnproven},
		{"a plain error", errors.New("something nobody classified"), readUnproven},
		{"nil", nil, readUnproven},
	} {
		if got := classifyRead(one.err); got != one.want {
			t.Errorf("%s is classed %d, want %d: %v", one.name, got, one.want, one.err)
		}
	}
}

// A RESTORE FAILURE THIS BUILD CANNOT CLASSIFY IS NOT NOTED, AND THE LEAVE IS REFUSED (R29, (a) to
// (c); R30, (e) and (f); R33, (g) and (h)). Failures of one group's epoch-state read, none of which
// proves the group can never be read: (a) a store error that carries no errno, (b) this platform's
// too-many-open-files errno, (c) a failure that is not the store's at all, (e) a permission refused
// and (f) the medium, the two R30 took off the proven list because they are facts about the
// environment, and (g) the store's "holds no such value" and (h) the platform's not-found errno, the
// absences R33 took off it because a file moved away can come back. For each, the failure lasting
// through the leave's own fresh attempt: Restore reports the group under
// [ErrGroupReadUnproven] and not as damage, notes it nowhere as a group that will not come back,
// and the leave of it is refused with that same sentence and "so nothing was left", with every
// file of the group unchanged.
//
// WHAT WOULD GO RED: the fail-open rule -- damage unless proven transient -- and each of these is
// erased without the owner's question, which is the erase the three leaks made.
func TestARestoreFailureThisBuildCannotClassifyIsNotNotedAndTheLeaveIsRefused(t *testing.T) {
	ctx := context.Background()
	for _, one := range []struct {
		name     string
		failWith error
	}{
		{"(a) a store error with no errno", fmt.Errorf("%w: the epoch state could not be read, and the read carried no errno", ErrStateStoreState)},
		{"(b) too many open files", asStoreRead(tooManyOpenFiles())},
		{"(c) a failure that is not the store's", fmt.Errorf("the engine could not load the group: %w", context.Canceled)},
		{"(e) a permission refused", asStoreRead(syscall.EACCES)},
		{"(f) the medium", asStoreRead(syscall.EIO)},
		{"(g) the store holds no such value", fmt.Errorf("%w: 0000000000000001", ErrStateNotFound)},
		{"(h) the platform's not-found errno", asStoreRead(syscall.ENOENT)},
	} {
		dir, groupId := failClosedScene(t)
		store, device := failClosedRestart(t, dir, groupId, one.failWith)
		before := failClosedFiles(t, store.DurableStateStore, groupId)
		if len(before) == 0 {
			t.Fatalf("CONTROL FAILED: %s: the scene holds no file of the group", one.name)
		}
		restored, err := device.Restore(ctx)
		if len(restored) != 0 || !errors.Is(err, ErrRestore) || !errors.Is(err, ErrGroupReadUnproven) ||
			errors.Is(err, ErrGroupRecordDamaged) {
			t.Errorf("%s: Restore answered %d group(s), %v, want none, ErrRestore and ErrGroupReadUnproven, and not damage", one.name, len(restored), err)
		}
		if device.didNotRestore(groupId) {
			t.Errorf("%s: Restore noted the group as one that will not come back", one.name)
		}
		err = device.ForgetGroup(groupId)
		t.Logf("%s: the leave answered: %v", one.name, err)
		if !errors.Is(err, ErrGroupReadUnproven) || !strings.Contains(err.Error(), "so nothing was left") ||
			errors.Is(err, ErrForgetUnfinished) {
			t.Errorf("%s: the leave answered %v, want ErrGroupReadUnproven and that nothing was left", one.name, err)
		}
		if marked, markErr := store.GroupBeingForgotten(groupId); markErr != nil || marked {
			t.Errorf("%s: the refused leave left a leave mark: %v, %v", one.name, marked, markErr)
		}
		after := failClosedFiles(t, store.DurableStateStore, groupId)
		if len(after) != len(before) {
			t.Errorf("%s: the group's files went %d to %d", one.name, len(before), len(after))
		}
		for name, octets := range before {
			if after[name] != octets {
				t.Errorf("%s: %s of the group changed or went", one.name, name)
			}
		}
	}
}

// EVERY PROVEN-PERMANENT RESTORE FAILURE IS STILL LEFT (R29, (d), the control). R9's choice stands
// for proof: the same scene, failing the same read with each of the proven-permanent classes -- a
// format verdict, an epoch state that does not decode, a group founded before the join seal, and
// every errno on this platform's allow-list -- is noted as a group that will not come back, and the
// leave of it goes through without the owner's question and takes the group's directory.
//
// THIS CASE WAS CHANGED BY R33, TRUTHFULLY: it held "a required file absent" as proven, and an
// absence is no longer proof of anything. That row is (g) of the unproven case above now.
//
// WHAT WOULD GO RED: a classifier that drops a proven class, and that group can never be left,
// restored or joined again.
func TestEveryProvenPermanentRestoreFailureIsStillLeft(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name     string
		failWith error
	}{
		{"a format verdict", fmt.Errorf("%w: the record's checksum is not the hash of the record", ErrStateStoreFormat)},
		{"an epoch state that does not decode", fmt.Errorf("mls: the persisted state: %w", syntax.ErrTruncated)},
		{"a group founded before the join seal", fmt.Errorf("urmessage: the group's context: %w", ErrGroupPredatesJoinSeal)},
	}
	for _, errno := range permanentErrnos {
		cases = append(cases, struct {
			name     string
			failWith error
		}{fmt.Sprintf("errno %d (%v)", uint(errno), errno), asStoreRead(errno)})
	}
	for _, one := range cases {
		dir, groupId := failClosedScene(t)
		store, device := failClosedRestart(t, dir, groupId, one.failWith)
		restored, err := device.Restore(ctx)
		if len(restored) != 0 || !errors.Is(err, ErrRestore) {
			t.Errorf("%s: Restore answered %d group(s), %v, want none and ErrRestore", one.name, len(restored), err)
			continue
		}
		if !device.didNotRestore(groupId) {
			t.Errorf("%s: Restore did not note the group as one that will not come back", one.name)
		}
		if err := device.ForgetGroup(groupId); err != nil {
			t.Errorf("%s: the leave of a group whose restore failed for good answered %v, want it left", one.name, err)
		}
		if _, err := store.GroupRecord(groupId); !errors.Is(err, ErrStateNotFound) {
			t.Errorf("%s: the group's record is still on the disk after the leave: %v", one.name, err)
		}
	}
	t.Logf("%d proven-permanent case(s) held, %d of them this platform's errnos", len(cases), len(permanentErrnos))
}

// WHILE A FAILURE LASTS, THE LEAVE SAYS THE TRUE THING EVERY ROUND (R29, the second review's W2).
// The library's own remedy for a group that did not come back used to be "call Restore, and if it
// does not come back, ForgetGroup leaves it" -- and while the failure lasted, Restore did not bring
// it back and ForgetGroup said the same thing again, for ever. Two rounds of the app's order
// (restore, then leave) over a failure that does not pass: both times the leave is refused with the
// sentence Restore reported and "so nothing was left", and the group's files are unchanged. Once
// the failure passes, the next Restore brings the group back.
//
// WHAT WOULD GO RED: answer [ErrGroupNotRestored] for a group the last Restore could not read, and
// its remedy loops; or erase it, and the fail-closed rule is gone.
func TestWhileAFailureLastsTheLeaveSaysTheTrueThingEveryRound(t *testing.T) {
	ctx := context.Background()
	dir, groupId := failClosedScene(t)
	store, device := failClosedRestart(t, dir, groupId,
		fmt.Errorf("%w: the epoch state could not be read, and the read carried no errno", ErrStateStoreState))
	before := failClosedFiles(t, store.DurableStateStore, groupId)
	for round := 1; round <= 2; round++ {
		restored, err := device.Restore(ctx)
		if len(restored) != 0 || !errors.Is(err, ErrGroupReadUnproven) {
			t.Errorf("round %d: Restore answered %d group(s), %v, want none and ErrGroupReadUnproven", round, len(restored), err)
		}
		err = device.ForgetGroup(groupId)
		t.Logf("round %d: the leave answered: %v", round, err)
		if !errors.Is(err, ErrGroupReadUnproven) || errors.Is(err, ErrGroupNotRestored) ||
			!strings.Contains(err.Error(), "so nothing was left") {
			t.Errorf("round %d: the leave answered %v, want ErrGroupReadUnproven, that nothing was left, and not ErrGroupNotRestored", round, err)
		}
		if after := failClosedFiles(t, store.DurableStateStore, groupId); len(after) != len(before) {
			t.Fatalf("round %d: the group's files went %d to %d", round, len(before), len(after))
		}
	}
	store.failWith = nil
	if restored, err := device.Restore(ctx); err != nil || len(restored) != 1 {
		t.Fatalf("once the failure passed, Restore answered %d group(s), %v, want the group back", len(restored), err)
	}
}

// EVERY RESTORE RE-DECIDES THE NOTE IT LEAVES (R30). The note a restore leaves on a group it could not
// bring back -- "will not come back" for a proven-permanent failure, "could not read" for a transient
// or unproven one -- is the LATEST attempt's and no other's, and a success clears both. One scene,
// four Restores over a disk that changes between them: a format verdict, then a sharing violation,
// then a store error with no errno, then nothing in the way.
//
// WHAT WOULD GO RED: a note that keeps an earlier attempt's class, or a transient failure noted as a
// group that will not come back -- the note R30 found deciding an erase.
func TestEveryRestoreRedecidesTheNoteItLeaves(t *testing.T) {
	ctx := context.Background()
	dir, groupId := failClosedScene(t)
	store, device := failClosedRestart(t, dir, groupId, nil)
	for _, one := range []struct {
		name       string
		failWith   error
		unrestored bool
		notRead    bool
	}{
		{"a format verdict", fmt.Errorf("%w: the record's checksum is not the hash of the record", ErrStateStoreFormat), true, false},
		{"a sharing violation", asStoreRead(transientErrnos[0]), false, true},
		{"a store error with no errno", fmt.Errorf("%w: the epoch state could not be read, and the read carried no errno", ErrStateStoreState), false, true},
		{"nothing in the way", nil, false, false},
	} {
		store.failWith = one.failWith
		restored, err := device.Restore(ctx)
		t.Logf("after %s: %d group(s), %v", one.name, len(restored), err)
		if (one.failWith == nil) != (len(restored) == 1) {
			t.Fatalf("after %s the Restore answered %d group(s), %v", one.name, len(restored), err)
		}
		if got := device.didNotRestore(groupId); got != one.unrestored {
			t.Errorf("after %s the group is noted as one that will not come back: %v, want %v", one.name, got, one.unrestored)
		}
		if got := device.lastRestoreCouldNotRead(groupId); got != one.notRead {
			t.Errorf("after %s the group is noted as one that could not be read: %v, want %v", one.name, got, one.notRead)
		}
	}
}
