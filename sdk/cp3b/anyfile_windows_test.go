//go:build windows

package cp3b

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"

	"github.com/urnetwork/message/sdk/urmessage"
)

// anyFileGroupDir is the directory one group's files live in, under a persona's state directory.
func anyFileGroupDir(t *testing.T, stateDir string, groupId []byte) string {
	t.Helper()
	sum := sha256.Sum256(groupId)
	name := hex.EncodeToString(sum[:])
	found := ""
	filepath.WalkDir(stateDir, func(path string, entry os.DirEntry, err error) error {
		if err == nil && entry.IsDir() && entry.Name() == name {
			found = path
		}
		return nil
	})
	if found == "" {
		t.Fatalf("CONTROL FAILED: no directory of the group is under %s", stateDir)
	}
	return found
}

// anyFileHoldDir holds one DIRECTORY as another process can: opened with share mode 0 and backup
// semantics. THE CONTROL is that a listing of it fails while it is held, and not as not-found.
func anyFileHoldDir(t *testing.T, path string) func() {
	t.Helper()
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	const backupSemantics = 0x02000000 // FILE_FLAG_BACKUP_SEMANTICS
	handle, err := syscall.CreateFile(name, syscall.GENERIC_READ, 0, nil, syscall.OPEN_EXISTING, backupSemantics, 0)
	if err != nil {
		t.Fatalf("holding the directory %s: %v", path, err)
	}
	if _, listErr := os.ReadDir(path); listErr == nil || errors.Is(listErr, os.ErrNotExist) {
		syscall.CloseHandle(handle)
		t.Fatalf("CONTROL FAILED: a listing of %s while it is held answered %v, so the hold did not take", path, listErr)
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

// anyFileTalkingOwnerPair is [transientOwnerPair] after a line each way, so the owner's group
// directory holds everything a group's layout can: its record, its epoch states, its head table
// and a sent copy.
func anyFileTalkingOwnerPair(t *testing.T) (*persona, []byte) {
	t.Helper()
	ctx := t.Context()
	world := newWorld(t)
	alice := world.newPersona(t, "alice")
	bob := world.newPersona(t, "bob")
	for _, who := range []*persona{alice, bob} {
		if err := who.device.Connect(ctx); err != nil {
			t.Fatalf("%s's Connect: %v", who.name, err)
		}
	}
	groupId := newGroupId(t)
	aliceGroup, bobGroup := openPair(t, ctx, alice, bob, groupId)
	if _, err := aliceGroup.Send(ctx, "a line from alice"); err != nil {
		t.Fatalf("alice's Send: %v", err)
	}
	if _, err := bobGroup.Receive(ctx); err != nil {
		t.Fatalf("bob's Receive: %v", err)
	}
	if _, err := bobGroup.Send(ctx, "a line from bob"); err != nil {
		t.Fatalf("bob's Send: %v", err)
	}
	if _, err := aliceGroup.Receive(ctx); err != nil {
		t.Fatalf("alice's Receive: %v", err)
	}
	alice = world.restart(t, alice)
	if err := alice.device.Connect(ctx); err != nil {
		t.Fatalf("the restarted alice's Connect: %v", err)
	}
	return alice, groupId
}

// NO FILE OF A GROUP, HELD FOR A MOMENT DURING A RESTORE, GETS AN OWNER'S GROUP ERASED UNASKED (R29;
// the second review's probe, kept as the regression it found). The property is over the group's
// WHOLE LAYOUT, and the layout is ENUMERATED AT RUN TIME from a real owner's directory -- every
// file and every directory under it, the directory itself included -- not listed here, so a file a
// later build adds is held too. For each one, on a fresh owner pair: it is held while alice
// restores, then released. Nothing of the group may change, the leave after the release must not
// erase it, and the next Restore brings it back and asks the owner's question.
//
// WHAT WOULD GO RED: a restore failure on any file that is noted as "will not come back" without
// proof -- measured on the `sent` directory, whose read had dropped its errno: files 5 to 0.
func TestAnyFileOfTheGroupHeldDuringRestoreIsNotLeftUnasked(t *testing.T) {
	ctx := t.Context()
	first, firstId := anyFileTalkingOwnerPair(t)
	root := anyFileGroupDir(t, first.stateDir, firstId)
	type target struct {
		relative string
		dir      bool
	}
	targets := []target{}
	filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		relative, _ := filepath.Rel(root, path)
		targets = append(targets, target{relative: relative, dir: entry.IsDir()})
		return nil
	})
	sort.Slice(targets, func(a, b int) bool { return targets[a].relative < targets[b].relative })
	kinds := map[string]bool{}
	for _, one := range targets {
		t.Logf("the layout: %s (directory=%v)", filepath.ToSlash(one.relative), one.dir)
		kinds[strings.Split(filepath.ToSlash(one.relative), "/")[0]] = true
	}
	for _, needed := range []string{".", "meta", "epoch", "heads", "sent"} {
		if !kinds[needed] {
			t.Fatalf("CONTROL FAILED: the layout has no %q, so this case does not hold the whole of a group", needed)
		}
	}
	for _, one := range targets {
		t.Run(filepath.ToSlash(one.relative), func(t *testing.T) {
			alice, groupId := anyFileTalkingOwnerPair(t)
			path := filepath.Join(anyFileGroupDir(t, alice.stateDir, groupId), one.relative)
			before := advGroupFiles(t, alice.stateDir, groupId)
			var release func()
			if one.dir {
				release = anyFileHoldDir(t, path)
			} else {
				release = transientHold(t, path)
			}
			restored, err := alice.device.Restore(ctx)
			t.Logf("the Restore while it is held: %d group(s), %v", len(restored), err)
			release()
			if len(restored) == 0 {
				err := alice.device.ForgetGroup(groupId)
				t.Logf("the owner's leave after the release: %v", err)
				if err == nil || errors.Is(err, urmessage.ErrForgetUnfinished) {
					t.Errorf("the owner's leave after the release answered %v: the group was left without the owner's question", err)
				} else if !errors.Is(err, urmessage.ErrGroupRecordNotReadNow) && !errors.Is(err, urmessage.ErrGroupReadUnproven) &&
					!errors.Is(err, urmessage.ErrGroupNotRestored) {
					t.Errorf("the owner's leave after the release answered %v, want a not-read refusal or ErrGroupNotRestored", err)
				}
				after := advGroupFiles(t, alice.stateDir, groupId)
				if len(after) != len(before) {
					t.Fatalf("the group's files went %d to %d", len(before), len(after))
				}
				for name, content := range before {
					if !bytes.Equal(after[name], content) {
						t.Errorf("%s of the group changed or went", name)
					}
				}
				if restored, err := alice.device.Restore(ctx); err != nil || len(restored) != 1 {
					t.Fatalf("the next Restore answered %d group(s), %v, want the group back", len(restored), err)
				}
			}
			if err := alice.device.ForgetGroup(groupId); !errors.Is(err, urmessage.ErrOwnerMustTransfer) {
				t.Errorf("the restored owner's leave answered %v, want ErrOwnerMustTransfer", err)
			}
		})
	}
}

// WHILE A HOLD LASTS, THE LEAVE SAYS THE TRUE THING EVERY ROUND (R29, the second review's W2; its
// probe, kept). An epoch state of alice's group stays held across two rounds of the app's order,
// restore then leave. Both times the leave is refused with the sentence the Restore reported -- the
// file could not be read just now -- and "so nothing was left", and nothing of the group changes.
// It used to answer ErrGroupNotRestored, "call Restore", both times, which while the hold lasted
// was a loop. After the release, the next Restore brings the group back and the owner is asked.
func TestWhileAHoldLastsTheLeaveSaysTheTrueThingEveryRound(t *testing.T) {
	ctx := t.Context()
	alice, groupId := transientOwnerPair(t)
	held := filepath.Join(anyFileGroupDir(t, alice.stateDir, groupId), "epoch", "0000000000000001")
	before := advGroupFiles(t, alice.stateDir, groupId)
	release := transientHold(t, held)
	for round := 1; round <= 2; round++ {
		restored, err := alice.device.Restore(ctx)
		if len(restored) != 0 || !errors.Is(err, urmessage.ErrGroupRecordNotReadNow) {
			t.Errorf("round %d: the Restore answered %d group(s), %v, want none and ErrGroupRecordNotReadNow", round, len(restored), err)
		}
		err = alice.device.ForgetGroup(groupId)
		t.Logf("round %d: the leave answered: %v", round, err)
		if !errors.Is(err, urmessage.ErrGroupRecordNotReadNow) || errors.Is(err, urmessage.ErrGroupNotRestored) ||
			!strings.Contains(err.Error(), "so nothing was left") {
			t.Errorf("round %d: the leave answered %v, want ErrGroupRecordNotReadNow, that nothing was left, and not ErrGroupNotRestored", round, err)
		}
	}
	release()
	if after := advGroupFiles(t, alice.stateDir, groupId); len(after) != len(before) {
		t.Fatalf("the group's files went %d to %d", len(before), len(after))
	}
	if restored, err := alice.device.Restore(ctx); err != nil || len(restored) != 1 {
		t.Fatalf("after the release, the Restore answered %d group(s), %v, want the group back", len(restored), err)
	}
	if err := alice.device.ForgetGroup(groupId); !errors.Is(err, urmessage.ErrOwnerMustTransfer) {
		t.Errorf("the restored owner's leave answered %v, want ErrOwnerMustTransfer", err)
	}
}
