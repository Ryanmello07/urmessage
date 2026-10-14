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

// transientHold opens one file with share mode 0, which is what a scanner or a backup tool does: no
// other open of it succeeds, a read included, until the answered release is called.
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
