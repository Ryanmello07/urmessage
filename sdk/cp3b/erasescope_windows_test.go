//go:build windows

package cp3b

import (
	"errors"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"

	"github.com/urnetwork/message/sdk/urmessage"
)

// erasescopeDenyAddFile denies this process's user the right to ADD A FILE to one directory, as a
// controlled-folder or backup lock-down does, with icacls, and answers the function that lifts it.
// The deny applies to that directory alone: its subdirectories still take new files. THE CONTROL:
// a file cannot be created in the directory while the deny stands, and the answer is access denied.
// The process's backup privilege is disabled for the case first, so the deny holds on a runner.
func erasescopeDenyAddFile(t *testing.T, dir string) func() {
	t.Helper()
	freshLeaveWithoutBackupPrivilege(t)
	me, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	icacls := func(args ...string) error {
		output, err := exec.Command("icacls", args...).CombinedOutput()
		if err != nil {
			return errors.New(strings.TrimSpace(string(output)) + ": " + err.Error())
		}
		return nil
	}
	if err := icacls(dir, "/deny", "*"+me.Uid+":(WD)"); err != nil {
		t.Fatalf("denying add-file on %s: %v", dir, err)
	}
	lifted := false
	lift := func() {
		if lifted {
			return
		}
		lifted = true
		if _, err := os.Stat(dir); err != nil {
			return
		}
		if err := icacls(dir, "/remove:d", "*"+me.Uid); err != nil {
			t.Errorf("lifting the deny on %s: %v", dir, err)
		}
	}
	t.Cleanup(lift)
	if probe, err := os.CreateTemp(dir, "erasescope-control-*"); err == nil {
		probe.Close()
		os.Remove(probe.Name())
		t.Fatalf("CONTROL FAILED: a file could be created in %s under the deny", dir)
	} else {
		var errno syscall.Errno
		if !errors.As(err, &errno) || errno != 5 {
			t.Fatalf("CONTROL FAILED: creating a file under the deny answered %v, want access denied (5)", err)
		}
	}
	return lift
}

// erasescopeLost is every file of before that is not in after.
func erasescopeLost(before map[string][]byte, after map[string][]byte) []string {
	lost := []string{}
	for name := range before {
		if _, kept := after[name]; !kept {
			lost = append(lost, name)
		}
	}
	sort.Strings(lost)
	return lost
}

// A CREATION MARK WHOSE REMOVAL FAILED IS RETRACTED BY A FACT, AND THE SWEEP DOES NOT TAKE A LIVE
// GROUP ON IT (R34, items 3 to 6: the round-4 review's probe of Y2, made a real test). Alice founds a
// group. While Open writes its record, a scanner holds the store's `pending` mark with share mode 0
// and a lock, so the mark's removal fails and the record is written. Bob joins. At the next start
// alice's record is moved out of its folder: the Restore erases nothing, because the folder holds the
// mark's retraction, `recorded`, and so is not in the creating state. With the record put back the
// group comes back, the Restore that read the record took the stale mark away and KEPT the
// retraction, for the group's life (R36, item 1), and alice's leave is the owner's question.
//
// WHAT WOULD GO RED: the mark cleared best effort and nothing written when that failed -- measured
// at fdc1b0a: the Restore with the record away erased the owner's live group, files 4 to 0, and the
// record put back named states that were gone.
func TestT1V4AMarkWhoseRemovalFailed(t *testing.T) {
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
	aliceGroup, err := alice.device.CreateGroup(ctx, groupId)
	if err != nil {
		t.Fatal(err)
	}
	dir := erasescopeFolder(alice.stateDir, groupId)
	pending := filepath.Join(dir, "pending")
	if _, err := os.Stat(pending); err != nil {
		t.Fatalf("CONTROL FAILED: no creation mark after CreateGroup: %v", err)
	}
	keyPackage, err := bob.device.KeyPackage()
	if err != nil {
		t.Fatal(err)
	}
	invite, err := aliceGroup.AddMember(keyPackage)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := invite.Encode()
	if err != nil {
		t.Fatal(err)
	}
	release := transientHold(t, pending)
	if err := aliceGroup.Open(ctx); err != nil {
		t.Fatalf("alice's Open while the mark is held: %v", err)
	}
	release()
	if _, err := os.Stat(pending); err != nil {
		t.Fatalf("CONTROL FAILED: the mark is gone after Open, so its removal did not fail: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "recorded")); err != nil {
		t.Fatalf("the record was written and the mark's removal failed, and no retraction was written: %v", err)
	}
	carried, err := urmessage.ParseInvite(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bob.device.Join(ctx, carried); err != nil {
		t.Fatalf("bob's Join: %v", err)
	}

	alice = world.restart(t, alice)
	if err := alice.device.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	before := advGroupFiles(t, alice.stateDir, groupId)
	putBack := quarantine(t, dir, "meta")
	restored, err := alice.device.Restore(ctx)
	t.Logf("the next start's Restore with the record away: %d group(s), %v; erased %v",
		len(restored), err, alice.stateStore.ErasedWithNoRecord())
	if erased := alice.stateStore.ErasedWithNoRecord(); len(erased) != 0 {
		t.Errorf("the sweep erased %v: the owner's live group, on a mark its record had retracted", erased)
	}
	quarantineUnchanged(t, alice, groupId, before, "meta")

	putBack()
	restored, err = alice.device.Restore(ctx)
	t.Logf("Restore with the record back: %d group(s), %v", len(restored), err)
	if err != nil || len(restored) != 1 {
		t.Fatalf("Restore with the record back answered %d group(s), %v, want the owner's live group", len(restored), err)
	}
	// THE RESTORE THAT READ THE RECORD TOOK THE STALE MARK AWAY AND KEPT ITS RETRACTION (R34, item 5;
	// R36, item 1)
	if _, err := os.Stat(filepath.Join(dir, "pending")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the creation mark stands beside a record that read: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "recorded")); err != nil {
		t.Errorf("the Restore that read the record took the retraction away: %v", err)
	}
	if err := alice.device.ForgetGroup(groupId); !errors.Is(err, urmessage.ErrOwnerMustTransfer) {
		t.Errorf("the owner's leave answered %v, want the owner's question", err)
	}
}

// A RE-ADD OVER A RECORD MOVED AWAY IS REFUSED BEFORE IT WRITES, AND A FAILED JOIN NEVER TAKES WHAT
// IT DID NOT WRITE (R34, items 1 and 2: the round-4 review's probe of Y1, the fifth leak, made a real
// test). Carol is in alice's group and sends a line; alice removes her; carol restarts. Alice re-adds
// her, and a real deny on adding a file to carol's group folder makes the re-add's record write fail
// after its commit.
//   - THE CONTROL, the record in place: the gate reads it as the removed group's, the re-add's write
//     fails after the commit, and nothing of the removed group goes.
//   - The record moved out of the folder: the gate refuses the invite as unproven -- the folder holds
//     the store's own files and no record -- before anything is written, the join code is not spent,
//     and nothing goes. Put back, the removed group restores.
//
// WHAT WOULD GO RED, measured at fdc1b0a: the gate read the missing record as "not held", the failed
// join then took the whole folder on "a failed admission erasing what it wrote itself", and the
// removed group's epoch state and carol's own sent line were erased.
func TestT1V4AReaddOverARecordMovedAway(t *testing.T) {
	for _, moved := range []bool{false, true} {
		name := "the control: the record stands"
		if moved {
			name = "the record moved away"
		}
		t.Run(name, func(t *testing.T) {
			scene := advFounding(t, true)
			ctx := scene.ctx
			carol := scene.world.newPersona(t, "carol")
			carolGroup := hsAddAndJoin(t, ctx, scene.aliceGroup, carol)
			if _, err := carolGroup.Receive(ctx); err != nil {
				t.Fatalf("carol's Receive: %v", err)
			}
			if _, err := carolGroup.Send(ctx, "a line carol wrote herself"); err != nil {
				t.Fatalf("carol's Send: %v", err)
			}
			if err := scene.aliceGroup.RemoveMember(ctx, rolesIdentityOf(t, carolGroup)); err != nil {
				t.Fatalf("alice's RemoveMember of carol: %v", err)
			}
			if _, err := carolGroup.Receive(ctx); !errors.Is(err, urmessage.ErrRemovedFromGroup) {
				t.Fatalf("CONTROL FAILED: carol's Receive answered %v, want ErrRemovedFromGroup", err)
			}
			carol = scene.world.restart(t, carol)
			if err := carol.device.Connect(ctx); err != nil {
				t.Fatalf("carol's Connect after the restart: %v", err)
			}
			dir := erasescopeFolder(carol.stateDir, scene.groupId)
			before := advGroupFiles(t, carol.stateDir, scene.groupId)
			if _, sent := before["sent/0000000000000001"]; !sent || len(before["meta"]) == 0 {
				t.Fatalf("CONTROL FAILED: carol's folder holds %d file(s), and not her record and her own line", len(before))
			}
			var putBack func()
			if moved {
				putBack = quarantine(t, dir, "meta")
			}
			restored, err := carol.device.Restore(ctx)
			t.Logf("carol's Restore: %d group(s), %v", len(restored), err)
			keyPackage, err := carol.device.KeyPackage()
			if err != nil {
				t.Fatal(err)
			}
			invite, err := scene.aliceGroup.AddMemberAndPublish(ctx, keyPackage)
			if err != nil {
				t.Fatalf("alice's re-add of carol: %v", err)
			}
			lift := erasescopeDenyAddFile(t, dir)
			_, err = carol.device.Join(ctx, gcReencodeInvite(t, invite))
			t.Logf("carol's join while her group's folder takes no new file: %v", err)
			lift()
			if moved {
				if !errors.Is(err, urmessage.ErrGroupReadUnproven) || errors.Is(err, urmessage.ErrJoinCodeSpent) ||
					errors.Is(err, urmessage.ErrGroupAlreadyHeld) || !strings.Contains(err.Error(), "its directory stands and its record is not in it") {
					t.Errorf("the re-add over a record moved away answered %v, want the gate's unproven refusal, before anything was written", err)
				}
				putBack()
			} else if !errors.Is(err, urmessage.ErrJoinCodeSpent) {
				t.Errorf("CONTROL FAILED: the re-add with the record in place answered %v, want the record write refused after the commit", err)
			}
			after := advGroupFiles(t, carol.stateDir, scene.groupId)
			if lost := erasescopeLost(before, after); len(lost) != 0 {
				t.Errorf("the refused or failed join erased %d file(s) it did not write: %v", len(lost), lost)
			}
			if moved {
				restored, err := carol.device.Restore(ctx)
				t.Logf("carol's Restore with the record back: %d group(s), %v", len(restored), err)
				if err != nil || len(restored) != 1 {
					t.Errorf("with the record back the removed group answered %d group(s), %v, want it restored", len(restored), err)
				}
			}
		})
	}
}

// A FAILED JOIN OVER A CREATION THAT NEVER FINISHED TAKES ONLY WHAT IT WROTE (R34, item 2), and the
// earlier creation is the sweep's. Bob's folder for a group holds what a join that died between its
// commit and its record leaves: the creation mark and an epoch state (here the store's own writes,
// at an epoch the new join does not use). The gate reads that folder as a group nobody holds yet,
// and Bob joins; a real deny on adding a file to the folder makes the join's record write fail after
// its commit. The failed join takes its own epoch state and nothing else: the earlier state and the
// creation mark stand. At the next start the sweep erases that creation on its own authority.
//
// WHAT WOULD GO RED: the failed join's scope back to the whole folder -- the earlier state erased
// under "a failed admission erasing what it wrote itself", which it did not write.
func TestAFailedJoinOverAnUnfinishedCreationTakesOnlyWhatItWrote(t *testing.T) {
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
	aliceGroup, err := alice.device.CreateGroup(ctx, groupId)
	if err != nil {
		t.Fatal(err)
	}
	keyPackage, err := bob.device.KeyPackage()
	if err != nil {
		t.Fatal(err)
	}
	invite, err := aliceGroup.AddMember(keyPackage)
	if err != nil {
		t.Fatal(err)
	}
	if err := aliceGroup.Open(ctx); err != nil {
		t.Fatal(err)
	}
	// the earlier creation, which never finished
	if err := bob.stateStore.PutGroupState(groupId, 7, []byte("an earlier join's leaf keys")); err != nil {
		t.Fatal(err)
	}
	dir := erasescopeFolder(bob.stateDir, groupId)
	before := advGroupFiles(t, bob.stateDir, groupId)
	if _, marked := before["pending"]; !marked || len(before) != 2 {
		t.Fatalf("CONTROL FAILED: bob's folder holds %v, want the creation mark and one epoch state", erasescopeLost(before, nil))
	}
	lift := erasescopeDenyAddFile(t, dir)
	_, err = bob.device.Join(ctx, gcReencodeInvite(t, invite))
	t.Logf("bob's join while his group's folder takes no new file: %v", err)
	lift()
	if !errors.Is(err, urmessage.ErrJoinCodeSpent) {
		t.Fatalf("CONTROL FAILED: the join answered %v, want its record write refused after the commit", err)
	}
	after := advGroupFiles(t, bob.stateDir, groupId)
	if lost := erasescopeLost(before, after); len(lost) != 0 {
		t.Errorf("the failed join erased %v, which it did not write", lost)
	}
	if len(after) != len(before) {
		t.Errorf("the failed join left %d file(s) where %d stood: what it wrote is not all gone", len(after), len(before))
	}
	bob = world.restart(t, bob)
	if err := bob.device.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	restored, err := bob.device.Restore(ctx)
	t.Logf("the next Restore: %d group(s), %v; erased %v", len(restored), err, bob.stateStore.ErasedWithNoRecord())
	if files := advGroupFiles(t, bob.stateDir, groupId); len(files) != 0 {
		t.Errorf("the sweep left %d file(s) of the creation that never finished", len(files))
	}
}
