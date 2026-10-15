//go:build windows

package cp3b

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/urnetwork/message/sdk/urmessage"
)

// A RETRACTION IS NOT UNDONE BY A CREATION MARK THAT WAS AWAY WHILE A RESTORE READ THE RECORD (R36,
// item 1: the round-5 review's Z1, form B). Alice founds a group, and while Open writes its record a
// scanner holds the creation mark with share mode 0 and a lock: the mark's removal fails, and the
// retraction is written beside it. At her next start the mark is out of the folder while the Restore
// reads the record: the retraction stays, for the group's life. The mark is put back.
//
// WHAT WOULD GO RED, measured at 93cc0af: that Restore took the retraction away, because the missing
// mark read as removed; with the mark back and the record away at the following start, her leave
// answered "this device holds no such group" for her live group, the Restore erased the folder, and
// with the record back the group never came back.
func TestT1V5ARetractionUndoneByAMarkAway(t *testing.T) {
	ctx := t.Context()
	world, alice, bob, aliceGroup, groupId, dir := putBackFounding(t)
	release := transientHold(t, filepath.Join(dir, "pending"))
	putBackAddBobAndOpen(t, aliceGroup, bob)
	release()
	t.Logf("after Open with the mark held: %v", putBackListing(dir))
	for _, name := range []string{"pending", "recorded"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("CONTROL FAILED: %s does not stand after Open with the mark held: %v", name, err)
		}
	}
	alice = world.restart(t, alice)
	if err := alice.device.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	putBackMark := putBackAway(t, dir, "pending")
	restored, err := alice.device.Restore(ctx)
	t.Logf("a Restore that reads the record while the mark is away: %d group(s), %v; the folder now: %v",
		len(restored), err, putBackListing(dir))
	if err != nil || len(restored) != 1 {
		t.Fatalf("the Restore with the mark away answered %d group(s), %v, want the group", len(restored), err)
	}
	if _, err := os.Stat(filepath.Join(dir, "recorded")); err != nil {
		t.Errorf("the Restore that read the record took the retraction away while the mark was elsewhere: %v", err)
	}
	putBackMark()
	t.Logf("the mark put back: %v", putBackListing(dir))
	putBackRecordAwayAtTheNextStart(t, world, alice, groupId, dir)
}

// A LEAVE MARK PUT BACK AFTER A RE-JOIN IS NO INSTRUCTION, AND WHILE THE RECORD BESIDE IT CANNOT BE READ
// IT DECIDES NOTHING (R36, item 2: the round-5 review's Z2, made a real test). Bob's leave stops on an
// epoch state a scanner holds, and his leave mark is moved away. His leave then answers that the group
// has not been restored, Restore brings it back -- a quarantined mark undoes a leave, which MG-15
// names -- and his second leave finishes. Alice removes him and adds him again, and he joins (epoch
// 3). The OLD mark, which names epoch 1, is put back.
//   - At his next start his record is held with share mode 0 and a lock: the Restore finishes nothing
//     and erases nothing, and reports the mark as not decided now, by the not-read-now class.
//   - Released, the next Restore removes the old mark and brings his live group back.
//
// WHAT WOULD GO RED, measured at 93cc0af: the Restore finished the old mark, on its group id alone, and
// emptied his live re-joined group's folder.
func TestT1V5ALeaveMarkPutBackAfterARejoin(t *testing.T) {
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
	aliceGroup, _ := openPair(t, ctx, alice, bob, groupId)
	dir := erasescopeFolder(bob.stateDir, groupId)
	t.Logf("bob's folder: %v", putBackListing(dir))
	release := transientHold(t, filepath.Join(dir, "epoch", "0000000000000001"))
	err := bob.device.ForgetGroup(groupId)
	release()
	t.Logf("bob's leave while an epoch state is held: %v; the folder: %v", err, putBackListing(dir))
	if !errors.Is(err, urmessage.ErrForgetUnfinished) {
		t.Fatalf("CONTROL FAILED: bob's leave with an epoch state held answered %v, want it unfinished", err)
	}
	putBackMark := putBackAway(t, dir, "forgetting")
	err = bob.device.ForgetGroup(groupId)
	t.Logf("bob's leave asked again with the mark away: %v", err)
	if !errors.Is(err, urmessage.ErrGroupNotRestored) {
		t.Fatalf("CONTROL FAILED: the leave with the mark away answered %v, want the group not restored (MG-15: a quarantined mark undoes a leave)", err)
	}
	restored, err := bob.device.Restore(ctx)
	t.Logf("bob's Restore with the mark away: %d group(s), %v", len(restored), err)
	if len(restored) != 1 {
		t.Fatalf("CONTROL FAILED: the group whose leave mark is away did not come back")
	}
	if err := bob.device.ForgetGroup(groupId); err != nil {
		t.Fatalf("CONTROL FAILED: bob's leave of the restored group: %v", err)
	}
	t.Logf("bob's second leave finished; the folder: %v", putBackListing(dir))
	members, err := aliceGroup.Members()
	if err != nil {
		t.Fatal(err)
	}
	var bobIdentity []byte
	for _, member := range members {
		if !member.Mine {
			bobIdentity = member.IdentityPub
		}
	}
	if err := aliceGroup.RemoveMember(ctx, bobIdentity); err != nil {
		t.Fatalf("alice's RemoveMember of bob: %v", err)
	}
	keyPackage, err := bob.device.KeyPackage()
	if err != nil {
		t.Fatal(err)
	}
	invite, err := aliceGroup.AddMemberAndPublish(ctx, keyPackage)
	if err != nil {
		t.Fatalf("alice's re-add of bob: %v", err)
	}
	if _, err := bob.device.Join(ctx, gcReencodeInvite(t, invite)); err != nil {
		t.Fatalf("bob's re-join: %v", err)
	}
	t.Logf("bob re-joined: his folder: %v", putBackListing(dir))
	putBackMark()
	t.Logf("the OLD leave mark put back: %v", putBackListing(dir))

	// HIS NEXT START, WITH HIS RECORD HELD: the old mark decides nothing
	bob = world.restart(t, bob)
	if err := bob.device.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	before := advGroupFiles(t, bob.stateDir, groupId)
	if _, marked := before["forgetting"]; !marked || len(before["meta"]) == 0 {
		t.Fatalf("CONTROL FAILED: bob's folder holds %v, not his record beside the old mark", putBackListing(dir))
	}
	releaseRecord := transientHold(t, filepath.Join(dir, "meta"))
	restored, err = bob.device.Restore(ctx)
	releaseRecord()
	t.Logf("bob's Restore with his record held: %d group(s), %v; his folder: %v", len(restored), err, putBackListing(dir))
	if !errors.Is(err, urmessage.ErrGroupRecordNotReadNow) || errors.Is(err, urmessage.ErrForgetUnfinished) {
		t.Errorf("the Restore over the old mark with the record held answered %v, want the mark reported as not decided now, by the not-read-now class", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "forgetting")); err != nil {
		t.Errorf("the old mark went while the record beside it could not be read: %v", err)
	}
	after := advGroupFiles(t, bob.stateDir, groupId)
	for name, content := range before {
		if !bytes.Equal(after[name], content) {
			t.Errorf("%s of bob's live group went or changed while the old mark decided nothing", name)
		}
	}

	// RELEASED: the old mark is removed, and the live group comes back
	restored, err = bob.device.Restore(ctx)
	t.Logf("bob's Restore with his record released: %d group(s), %v; his folder: %v", len(restored), err, putBackListing(dir))
	if err != nil || len(restored) != 1 {
		t.Errorf("bob's live re-joined group answered %d group(s), %v, want it restored", len(restored), err)
	}
	if _, err := os.Stat(filepath.Join(dir, "forgetting")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the old mark still stands beside the live group: %v", err)
	}
	after = advGroupFiles(t, bob.stateDir, groupId)
	for name := range before {
		if _, kept := after[name]; !kept && name != "forgetting" {
			t.Errorf("%s of bob's live group went", name)
		}
	}
}
