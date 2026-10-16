//go:build windows

package cp3b

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"unsafe"

	"github.com/urnetwork/message/sdk/urmessage"
)

// transientRecordPath is the path of one group's record under a persona's state directory.
func transientRecordPath(t *testing.T, stateDir string, groupId []byte) string {
	t.Helper()
	sum := sha256.Sum256(groupId)
	name := hex.EncodeToString(sum[:])
	found := ""
	filepath.WalkDir(stateDir, func(path string, entry os.DirEntry, err error) error {
		if err == nil && !entry.IsDir() && filepath.Base(path) == "meta" && filepath.Base(filepath.Dir(path)) == name {
			found = path
		}
		return nil
	})
	if found == "" {
		t.Fatalf("CONTROL FAILED: no record of the group is on the disk under %s", stateDir)
	}
	return found
}

// transientLockFileEx is kernel32's LockFileEx, which package syscall does not carry.
var transientLockFileEx = syscall.NewLazyDLL("kernel32.dll").NewProc("LockFileEx")

// transientHold holds one file as a scanner or a backup tool does, until the answered release is
// called: it is opened with share mode 0, and the whole of it is locked exclusively on that handle,
// so a read fails whichever of the two a host enforces. THE CONTROL is that a plain read of the file
// fails while it is held, for a reason that is not "not found": a hold that did not take would make
// every assertion below a statement about an ordinary read.
func transientHold(t *testing.T, path string) func() {
	t.Helper()
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := syscall.CreateFile(name, syscall.GENERIC_READ, 0, nil, syscall.OPEN_EXISTING,
		syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatalf("holding %s: %v", path, err)
	}
	const lockExclusive = 0x2 // LOCKFILE_EXCLUSIVE_LOCK
	var overlapped syscall.Overlapped
	if locked, _, lockErr := transientLockFileEx.Call(uintptr(handle), lockExclusive, 0, 0xFFFFFFFF, 0xFFFFFFFF,
		uintptr(unsafe.Pointer(&overlapped))); locked == 0 {
		syscall.CloseHandle(handle)
		t.Fatalf("locking %s: %v", path, lockErr)
	}
	if _, readErr := os.ReadFile(path); readErr == nil || errors.Is(readErr, os.ErrNotExist) {
		syscall.CloseHandle(handle)
		t.Fatalf("CONTROL FAILED: a plain read of %s while it is held answered %v, so the hold did not take", path, readErr)
	}
	released := false
	release := func() {
		if !released {
			released = true
			syscall.CloseHandle(handle)
		}
	}
	t.Cleanup(release)
	return release
}

// transientOwnerPair is alice, the OWNER of a group bob is in, restarted and connected and not yet
// restored: the case the owner's question exists for.
func transientOwnerPair(t *testing.T) (*persona, []byte) {
	t.Helper()
	world := newWorld(t)
	alice := world.newPersona(t, "alice")
	bob := world.newPersona(t, "bob")
	for _, who := range []*persona{alice, bob} {
		if err := who.device.Connect(t.Context()); err != nil {
			t.Fatalf("%s's Connect: %v", who.name, err)
		}
	}
	groupId := newGroupId(t)
	openPair(t, t.Context(), alice, bob, groupId)
	alice = world.restart(t, alice)
	if err := alice.device.Connect(t.Context()); err != nil {
		t.Fatalf("the restarted alice's Connect: %v", err)
	}
	return alice, groupId
}

// A RECORD ANOTHER PROCESS HOLDS OPEN IS NOT DAMAGE, AND THE OWNER IS STILL ASKED (Task 57, F1; the
// red team's measurement, kept as the regression it found). Alice owns a group bob is in. She
// restarts, and her record of the group is held open by another process with no read sharing, as a
// scanner or a backup tool holds it. Driven in both orders a person can meet it in: a leave while
// the file is held, and the app's own order, a Restore while it is held and the leave after.
//
// THE CONTROL is the same pair with no file held: not restored, the leave is refused; restored, it
// is the owner's question.
//
// WHAT WOULD GO RED: read a failed read as damage, and the leave made while the file is held marks
// the group and starts its erase, and the next Restore finishes it -- the owner's group, with bob in
// it, is gone from her disk without the owner's question ever being asked. That was measured, 3
// files to 0, on the build before this.
func TestARecordAnotherProcessHoldsIsNotDamageAndTheOwnerIsStillAsked(t *testing.T) {
	ctx := t.Context()

	// THE CONTROL
	{
		alice, groupId := transientOwnerPair(t)
		if err := alice.device.ForgetGroup(groupId); !errors.Is(err, urmessage.ErrGroupNotRestored) {
			t.Fatalf("CONTROL FAILED: the leave before any Restore answered %v, want ErrGroupNotRestored", err)
		}
		if restored, err := alice.device.Restore(ctx); err != nil || len(restored) != 1 {
			t.Fatalf("CONTROL FAILED: Restore answered %d group(s), %v", len(restored), err)
		}
		if err := alice.device.ForgetGroup(groupId); !errors.Is(err, urmessage.ErrOwnerMustTransfer) {
			t.Fatalf("CONTROL FAILED: the restored owner's leave answered %v, want ErrOwnerMustTransfer", err)
		}
	}

	// A LEAVE WHILE THE FILE IS HELD
	{
		alice, groupId := transientOwnerPair(t)
		before := len(advGroupFiles(t, alice.stateDir, groupId))
		release := transientHold(t, transientRecordPath(t, alice.stateDir, groupId))
		_, readErr := alice.stateStore.GroupRecord(groupId)
		if !errors.Is(readErr, urmessage.ErrStateStoreState) || errors.Is(readErr, urmessage.ErrGroupRecordDamaged) {
			t.Errorf("the one-id read of a record another process holds answered %v, want ErrStateStoreState and not ErrGroupRecordDamaged", readErr)
		}
		err := alice.device.ForgetGroup(groupId)
		t.Logf("the leave while the record is held: %v", err)
		if err == nil || errors.Is(err, urmessage.ErrForgetUnfinished) || errors.Is(err, urmessage.ErrGroupRecordDamaged) {
			t.Errorf("the leave while the record is held answered %v, want a refusal that changed nothing", err)
		}
		release()
		if marked, err := alice.stateStore.GroupBeingForgotten(groupId); err != nil || marked {
			t.Errorf("the refused leave left a leave mark: %v, %v", marked, err)
		}
		if after := len(advGroupFiles(t, alice.stateDir, groupId)); after != before {
			t.Errorf("the refused leave changed the group's files: %d before, %d after", before, after)
		}
		if restored, err := alice.device.Restore(ctx); err != nil || len(restored) != 1 {
			t.Fatalf("the Restore after the release answered %d group(s), %v, want the group back", len(restored), err)
		}
		if err := alice.device.ForgetGroup(groupId); !errors.Is(err, urmessage.ErrOwnerMustTransfer) {
			t.Errorf("the owner's leave once the record reads again answered %v, want ErrOwnerMustTransfer", err)
		}
	}

	// THE APP'S ORDER: a Restore while the file is held, then the leave once it is released
	{
		alice, groupId := transientOwnerPair(t)
		before := len(advGroupFiles(t, alice.stateDir, groupId))
		release := transientHold(t, transientRecordPath(t, alice.stateDir, groupId))
		restored, err := alice.device.Restore(ctx)
		t.Logf("the Restore while the record is held: %d group(s), %v", len(restored), err)
		if len(restored) != 0 || !errors.Is(err, urmessage.ErrRestore) || !errors.Is(err, urmessage.ErrGroupRecordNotReadNow) ||
			errors.Is(err, urmessage.ErrGroupRecordDamaged) {
			t.Errorf("the Restore while the record is held answered %d group(s), %v, want none, ErrRestore and ErrGroupRecordNotReadNow, and not ErrGroupRecordDamaged", len(restored), err)
		}
		release()
		if err := alice.device.ForgetGroup(groupId); !errors.Is(err, urmessage.ErrGroupNotRestored) {
			t.Errorf("the leave once the record reads again answered %v, want ErrGroupNotRestored", err)
		}
		if after := len(advGroupFiles(t, alice.stateDir, groupId)); after != before {
			t.Errorf("the group's files changed: %d before, %d after", before, after)
		}
		if restored, err := alice.device.Restore(ctx); err != nil || len(restored) != 1 {
			t.Fatalf("the next Restore answered %d group(s), %v, want the group back", len(restored), err)
		}
		if err := alice.device.ForgetGroup(groupId); !errors.Is(err, urmessage.ErrOwnerMustTransfer) {
			t.Errorf("the restored owner's leave answered %v, want ErrOwnerMustTransfer", err)
		}
	}
}

// AN EPOCH STATE ANOTHER PROCESS HOLDS DURING A RESTORE IS NOT DAMAGE EITHER, AND THE OWNER IS STILL
// ASKED (R26, the fix review's V1; the reviewer's probe, kept as the regression it found). F1's
// promise is about the group's restore, whichever of its files failed: here every epoch state of
// alice's group is held while she restores, in the app's own order (restore, then leave). The
// Restore reports the group as not read now; once the files are released, the leave tries the
// group's restore again (R30), which brings it back, and the leave is the ordinary one: the owner's
// question is asked and nothing is written. THIS CASE HAS CHANGED THREE TIMES, each time
// truthfully: it first asserted ErrGroupNotRestored after the release, whose remedy looped while a
// hold lasted (R29's W2 replaced it with the not-read refusal); R30's fresh attempt then replaced
// that with the owner's question itself; and R33's X2 replaced "the group is live and held after
// the refused leave" with what is true now: it is not held, and the next Restore hands it back.
//
// WHAT WOULD GO RED: note any restore failure as "will not come back", and the leave after the
// release erases the owner's group, with bob in it, unasked -- measured, 3 files to 0.
func TestAnEpochStateAnotherProcessHoldsDuringRestoreIsNotDamageAndTheOwnerIsStillAsked(t *testing.T) {
	ctx := t.Context()
	alice, groupId := transientOwnerPair(t)
	sum := sha256.Sum256(groupId)
	name := hex.EncodeToString(sum[:])
	epochFiles := []string{}
	filepath.WalkDir(alice.stateDir, func(path string, entry os.DirEntry, err error) error {
		if err == nil && !entry.IsDir() && filepath.Base(filepath.Dir(path)) == "epoch" &&
			filepath.Base(filepath.Dir(filepath.Dir(path))) == name {
			epochFiles = append(epochFiles, path)
		}
		return nil
	})
	if len(epochFiles) == 0 {
		t.Fatalf("CONTROL FAILED: no epoch state of the group is on alice's disk")
	}
	before := len(advGroupFiles(t, alice.stateDir, groupId))
	releases := []func(){}
	for _, path := range epochFiles {
		releases = append(releases, transientHold(t, path))
	}
	restored, err := alice.device.Restore(ctx)
	t.Logf("the Restore while the epoch states are held: %d group(s), %v", len(restored), err)
	if len(restored) != 0 || !errors.Is(err, urmessage.ErrRestore) || !errors.Is(err, urmessage.ErrGroupRecordNotReadNow) {
		t.Errorf("the Restore while the epoch states are held answered %d group(s), %v, want none, ErrRestore and ErrGroupRecordNotReadNow", len(restored), err)
	}
	for _, release := range releases {
		release()
	}
	err = alice.device.ForgetGroup(groupId)
	if !errors.Is(err, urmessage.ErrOwnerMustTransfer) {
		t.Errorf("the owner's leave after the release answered %v, want the owner's question: the leave's fresh restore brings the group back", err)
	}
	if after := len(advGroupFiles(t, alice.stateDir, groupId)); after != before {
		t.Fatalf("the owner's group lost files: %d before, %d after", before, after)
	}
	if held := len(alice.device.Groups()); held != 0 {
		t.Errorf("after the refused leave alice holds %d group(s), and she held none before it", held)
	}
	if restored, err := alice.device.Restore(ctx); err != nil || len(restored) != 1 {
		t.Errorf("the Restore after the refused leave answered %d group(s), %v, want the group handed back", len(restored), err)
	}
}
