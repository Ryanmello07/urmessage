package cp3b

import (
	"errors"
	"testing"

	"github.com/urnetwork/message/messagegroup"
	"github.com/urnetwork/message/sdk/urmessage"
)

// OPEN ITEM MG-8, REPRODUCED. A device that is removed from a group and added back reads what is
// sent after the re-add, and its first Receive ALSO answers an authentication failure for history
// it cannot open by design.
//
// The device joined at the founding and sent there. A second member was added, the founder removed
// the first device and added it back, and the founder sent one line. The device still holds its
// files of the first membership. Its first Receive after the re-add hands back the founder's new
// line, and it also answers [urmessage.ErrRecordOpen] carrying [messagegroup.ErrRecordAeadOpen],
// "a record ciphertext did not authenticate", for a record sealed before the removal. That
// sentence is the signal for tampering, and nothing here was tampered with.
//
// THIS CASE HOLDS THE DEFECT AS IT IS, so that it cannot change shape unseen. It does not approve
// it: messagegroup/OPENITEMS.md files it as MG-8, and the healing track's plan takes it. WHEN IT
// IS REPAIRED THIS CASE FAILS, by name. It is then rewritten to hold the repair, and the row and
// the line of messagegroup/errors.go that cites it are deleted in the same commit.
//
// PART OF IT IS ALREADY HELD ONE MODULE OVER, AS A COST:
// urmessage.TestTheOnlyRepairTheRemovedSentinelNamesIsBeingAddedBackAndItCostsThreeWalksAndTheHistory
// holds that a re-added device's own earlier lines cost failed walks and are then lost. What this
// case adds is the two controls, which say where that cost comes from.
//
// THE CONTROLS are the same device with less of its first membership on its disk. In the first it
// left the group with ForgetGroup before it was added back, so nothing of the first membership is
// there. In the second, narrower one, ONLY the epoch states of the first membership are gone, and
// its record and everything else of it stay. In both the same history comes back as gaps and
// Receive answers no error. So the failure is not about a re-add as such, and it is not about the
// epoch: it is about an epoch state of the first membership found beside the re-add's own.
//
// WHAT WOULD GO RED: hand a record of an earlier epoch that does not authenticate back as a gap,
// and the first half reads "MG-8 has closed". That is the repair NOT to make: it is the tampering
// signal switched off for every past epoch.
func TestADeviceAddedBackAnswersAnAuthenticationFailureForHistoryItCannotOpen(t *testing.T) {
	for _, one := range []struct {
		name    string
		control string
	}{
		{"with its files of the first membership still on its disk", ""},
		{"THE CONTROL: having left the group with ForgetGroup before it was added back", "forgot"},
		{"THE NARROWER CONTROL: with only the epoch states of the first membership removed from its disk", "epochs"},
	} {
		scene := advFounding(t, true)
		carol := scene.world.newPersona(t, "carol")
		hsAddAndJoin(t, scene.ctx, scene.aliceGroup, carol)
		if err := scene.aliceGroup.RemoveMember(scene.ctx, rolesIdentityOf(t, scene.bobGroup)); err != nil {
			t.Fatalf("%s: alice's RemoveMember of bob: %v", one.name, err)
		}
		var err error
		for round := 0; round < 6; round += 1 {
			if _, err = scene.bobGroup.Receive(scene.ctx); errors.Is(err, urmessage.ErrRemovedFromGroup) {
				break
			}
		}
		removedAt, removal := scene.bobGroup.Removal()
		if removal == nil {
			t.Fatalf("%s: CONTROL FAILED: bob does not read as removed (his last Receive answered %v), so nothing below is about a re-add", one.name, err)
		}
		before := advGroupFiles(t, scene.bob.stateDir, scene.groupId)
		if _, held := before["epoch/0000000000000001"]; !held {
			t.Fatalf("%s: CONTROL FAILED: bob holds no state of the founding epoch, so he is not a device that held earlier epochs", one.name)
		}
		switch one.control {
		case "forgot":
			if err := scene.bob.device.ForgetGroup(scene.groupId); err != nil {
				t.Fatalf("%s: bob's ForgetGroup of the group he was removed from: %v", one.name, err)
			}
		case "epochs":
			if err := advRemoveEpochStates(scene.bob.stateDir, scene.groupId); err != nil {
				t.Fatalf("%s: removing the epoch states of the first membership: %v", one.name, err)
			}
			after := advGroupFiles(t, scene.bob.stateDir, scene.groupId)
			if len(after["meta"]) == 0 || len(after) >= len(before) {
				t.Fatalf("%s: CONTROL FAILED: %d file(s) before and %d after, and the record must be one of those left: this is not \"only the epoch states\"", one.name, len(before), len(after))
			}
		}
		rejoined := removalAdd(t, scene.ctx, "alice", scene.aliceGroup, scene.bob.device, "bob")
		if epoch := rejoined.Epoch(); epoch <= removedAt {
			t.Fatalf("%s: CONTROL FAILED: the re-add stands at epoch %d and the removal was at %d", one.name, epoch, removedAt)
		}
		canary := scene.say(t, "alice", scene.aliceGroup)
		received, err := rejoined.Receive(scene.ctx)
		read, gaps := false, 0
		for _, message := range received {
			switch {
			case message.Gap != "":
				gaps += 1
			case message.Text == canary:
				read = true
			}
		}
		t.Logf("%s: the first Receive after the re-add: %d message(s), %d of them gaps, the founder's new line read=%v, and %v", one.name, len(received), gaps, read, err)
		if !read {
			t.Fatalf("%s: the re-added device did not read what the founder sent after the re-add, which is not this open item: it is a re-add that does not work", one.name)
		}
		if one.control != "" {
			if err != nil || gaps == 0 {
				t.Fatalf("%s: Receive answered %d gap(s) and %v, want the history as gaps and no error", one.name, gaps, err)
			}
			continue
		}
		switch {
		case err == nil:
			t.Fatalf("OPEN ITEM MG-8 HAS CLOSED: the re-added device's first Receive answered no error (%d gap(s)). Rewrite this case to hold the repair, and delete the MG-8 row of messagegroup/OPENITEMS.md and the line of messagegroup/errors.go that cites it, in the same commit", gaps)
		case !errors.Is(err, urmessage.ErrRecordOpen) || !errors.Is(err, messagegroup.ErrRecordAeadOpen):
			t.Fatalf("OPEN ITEM MG-8 HAS MOVED: the re-added device's first Receive answered %v, and the row records urmessage.ErrRecordOpen carrying messagegroup.ErrRecordAeadOpen. Say what it is now in messagegroup/OPENITEMS.md", err)
		}
	}
}
