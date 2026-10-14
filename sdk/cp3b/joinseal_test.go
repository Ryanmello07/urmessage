package cp3b

import (
	"bytes"
	"errors"
	"testing"

	"github.com/urnetwork/message/sdk/urmessage"
)

// THE JOIN SEAL AGAINST THE REAL SERVER: what the unit cases in sdk/urmessage cannot hold, because
// each needs a group that is open and a commit the server takes.

// THE LIVE ADDER JUDGES A JOIN CODE BEFORE IT STAGES ANYTHING, AND NAMES THE REMEDY FOR A LEAF
// THAT STANDS. Three refusals on the live road, and after them the group is where it was: a
// damaged join code and octets that are no join code are told they are invalid, and the join code
// of an identity that already has a leaf is told so by [urmessage.ErrJoinerAlreadyHasALeaf]. The
// leaf that stands is the common one: an invitation that was made and never opened. Then the
// remedy that name's sentence gives is driven as written: the entry is removed, and the join code
// that was refused is added and joins.
//
// WHAT WOULD GO RED: hand the role model's refusal back under its own name, and the adder is told
// an identity is claimed with nothing saying what to do; or judge the join code after the commit
// is staged, and the honest add that follows is refused over what was left behind.
func TestTheLiveAdderJudgesAJoinCodeAndNamesTheRemedyForALeafThatStands(t *testing.T) {
	scene := advFounding(t, true)
	dave := scene.world.newPersona(t, "dave")
	if err := dave.device.Connect(scene.ctx); err != nil {
		t.Fatalf("dave's Connect: %v", err)
	}
	first, err := dave.device.KeyPackage()
	if err != nil {
		t.Fatalf("dave's first KeyPackage: %v", err)
	}
	second, err := dave.device.KeyPackage()
	if err != nil {
		t.Fatalf("dave's second KeyPackage: %v", err)
	}
	damaged := bytes.Clone(first)
	damaged[len(damaged)-1] ^= 0x01 // the last octet of its signature
	if _, err := scene.aliceGroup.AddMemberAndPublish(scene.ctx, damaged); !errors.Is(err, urmessage.ErrKeyPackageInvalid) {
		t.Errorf("a join code with one bit of its signature flipped answered %v, want ErrKeyPackageInvalid", err)
	}
	// the role model reads the join code before the adder's own check does, so octets that do not
	// decode are met there; they take the same name
	if _, err := scene.aliceGroup.AddMemberAndPublish(scene.ctx, []byte("not a key package")); !errors.Is(err, urmessage.ErrKeyPackageInvalid) {
		t.Errorf("octets that are not a key package answered %v, want ErrKeyPackageInvalid", err)
	}
	if epoch := scene.aliceGroup.Epoch(); epoch != 1 {
		t.Fatalf("the two refused adds left the group at epoch %d, want 1", epoch)
	}

	// NOTHING WAS LEFT STAGED: the honest add that follows is made, and lands at the next epoch.
	// Its invitation is never opened, so dave's leaf stands with nobody behind it.
	if _, err := scene.aliceGroup.AddMemberAndPublish(scene.ctx, first); err != nil {
		t.Fatalf("the honest add after two refused ones: %v", err)
	}
	if epoch := scene.aliceGroup.Epoch(); epoch != 2 {
		t.Fatalf("the honest add left the group at epoch %d, want 2", epoch)
	}
	_, err = scene.aliceGroup.AddMemberAndPublish(scene.ctx, second)
	if !errors.Is(err, urmessage.ErrJoinerAlreadyHasALeaf) {
		t.Fatalf("the join code of an identity whose leaf stands answered %v, want ErrJoinerAlreadyHasALeaf", err)
	}
	if epoch := scene.aliceGroup.Epoch(); epoch != 2 {
		t.Fatalf("the refused add left the group at epoch %d, want 2", epoch)
	}

	// THE REMEDY, AS THE SENTENCE GIVES IT: remove that entry, then add the new join code
	bobIdentity := rolesIdentityOf(t, scene.bobGroup)
	var daveIdentity []byte
	for _, member := range removalRoster(t, scene.aliceGroup) {
		if !member.Mine && !bytes.Equal(member.IdentityPub, bobIdentity) {
			daveIdentity = member.IdentityPub
		}
	}
	if daveIdentity == nil {
		t.Fatalf("alice's roster holds no entry for the invitation that was never opened")
	}
	if err := scene.aliceGroup.RemoveMember(scene.ctx, daveIdentity); err != nil {
		t.Fatalf("alice's RemoveMember of the entry nobody is behind: %v", err)
	}
	invite, err := scene.aliceGroup.AddMemberAndPublish(scene.ctx, second)
	if err != nil {
		t.Fatalf("the same join code after its identity's entry was removed: %v", err)
	}
	daveGroup, err := dave.device.Join(scene.ctx, gcReencodeInvite(t, invite))
	if err != nil {
		t.Fatalf("dave's Join over the join code that was refused before: %v", err)
	}
	canary := scene.say(t, "alice", scene.aliceGroup)
	gcReceiveText(t, scene.ctx, "dave", daveGroup, canary)
}
