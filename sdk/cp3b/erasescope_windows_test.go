//go:build windows

package cp3b

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/urnetwork/message/sdk/urmessage"
)

// A CREATION MARK WHOSE REMOVAL FAILED IS RETRACTED BY A FACT, AND THE SWEEP DOES NOT TAKE A LIVE
// GROUP ON IT (R34, items 3 to 6: the round-4 review's probe of Y2, made a real test). Alice founds a
// group. While Open writes its record, a scanner holds the store's `pending` mark with share mode 0
// and a lock, so the mark's removal fails and the record is written. Bob joins. At the next start
// alice's record is moved out of its folder: the Restore erases nothing, because the folder holds the
// mark's retraction, `recorded`, and so is not in the creating state. With the record put back the
// group comes back, the Restore that read the record took both marks away, and alice's leave is the
// owner's question.
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
	// THE RESTORE THAT READ THE RECORD TOOK BOTH MARKS AWAY (R34, item 5)
	for _, mark := range []string{"pending", "recorded"} {
		if _, err := os.Stat(filepath.Join(dir, mark)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s stands beside a record that read: %v", mark, err)
		}
	}
	if err := alice.device.ForgetGroup(groupId); !errors.Is(err, urmessage.ErrOwnerMustTransfer) {
		t.Errorf("the owner's leave answered %v, want the owner's question", err)
	}
}
