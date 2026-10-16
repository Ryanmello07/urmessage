package cp3b

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"testing"
	"time"

	"github.com/urnetwork/message/messagegroup"
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

// jsSecondSpelling recomputes an invite's join_auth THE WAY A MEMBER THAT IS NOT THIS SDK WOULD,
// and holds it against the invite's fifth field. Nothing here calls urmessage: the key is the
// joined group's own exporter, asked for by the label and the context written out below, the
// preimage is assembled field by field, and the MAC is the standard library's HMAC-SHA-256.
//
// IT IS THE KNOWN ANSWER FOR THE KEY. The preimage has one in sdk/urmessage; the key cannot have a
// fixed one, because it comes out of a live group, so it is pinned by a second derivation instead.
// Three keys it must NOT be are tried as well, each of which no other case could tell from the
// right one: the storage exporter, which is what storage_root is extracted from; the join key
// with no leaf in its context; and the join key of another leaf.
func jsSecondSpelling(t *testing.T, road string, handle messagegroup.GroupHandle, invite *urmessage.Invite) {
	t.Helper()
	leaf, epoch := uint32(handle.OwnLeafIndex()), handle.Epoch()
	leafId := binary.BigEndian.AppendUint32(nil, leaf)
	preimage := []byte("URmessage/v1/joinauth")
	preimage = append(preimage, 0x00, 0x41) // alg_id: HMAC-SHA-256
	preimage = append(preimage, 0x00, 0x03) // invite version
	lengthPrefixed := func(octets []byte) {
		preimage = binary.BigEndian.AppendUint32(preimage, uint32(len(octets)))
		preimage = append(preimage, octets...)
	}
	lengthPrefixed(invite.GroupId)
	preimage = binary.BigEndian.AppendUint64(preimage, epoch)
	preimage = binary.BigEndian.AppendUint32(preimage, leaf)
	for _, part := range [][]byte{invite.Welcome, invite.RatchetTree, invite.JoinSeal} {
		sum := sha256.Sum256(part)
		lengthPrefixed(sum[:])
	}
	if len(preimage) != 181 {
		t.Fatalf("%s: the preimage written out here is %d octets, want 181", road, len(preimage))
	}
	under := func(key []byte) []byte {
		mac := hmac.New(sha256.New, key)
		mac.Write(preimage)
		return mac.Sum(nil)
	}
	export := func(label string, context []byte) []byte {
		key, err := handle.Export(label, context, 32)
		if err != nil {
			t.Fatalf("%s: Export(%q): %v", road, label, err)
		}
		return key
	}
	joinKey := export("URmessage/v1/joinkey", leafId)
	if !hmac.Equal(under(joinKey), invite.JoinAuth) {
		t.Fatalf("%s: join_auth is not HMAC-SHA-256 under Export(URmessage/v1/joinkey, u32(leaf %d), 32) at epoch %d over the preimage written out here", road, leaf, epoch)
	}
	for name, other := range map[string][]byte{
		"the storage exporter":                     export("URmessage/v1/storage", nil),
		"the join key with no leaf in its context": export("URmessage/v1/joinkey", nil),
		"the join key of the leaf beside this one": export("URmessage/v1/joinkey", binary.BigEndian.AppendUint32(nil, leaf+1)),
	} {
		if bytes.Equal(other, joinKey) || hmac.Equal(under(other), invite.JoinAuth) {
			t.Errorf("%s: join_auth verifies under %s", road, name)
		}
	}
}

// JOIN_AUTH IS THE JOIN EPOCH'S EXPORTER OVER THE PREIMAGE, ON BOTH ADDER ROADS. The joiner is a
// seam member, which opens the seal and never verifies the authenticator, so this is the only
// place the authenticator an adder makes is checked by code that shares nothing with the adder.
//
// WHAT WOULD GO RED: derive the key from a value that is not secret to the group, drop the leaf
// from its context, take it from the storage exporter, or change the preimage's field order on
// both sides at once. Each of those passes every case that only asks the sdk to agree with itself.
func TestJoinAuthIsTheJoinEpochsExporterOverThePreimageOnBothRoads(t *testing.T) {
	// THE FOUNDING ROAD: AddMember, off the staged commit that opens epoch one
	world := newWorld(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	alice := world.newPersona(t, "alice")
	if err := alice.device.Connect(ctx); err != nil {
		t.Fatalf("alice's Connect: %v", err)
	}
	laptop := world.seamMember(t, ctx, "laptop")
	founded, err := alice.device.CreateGroup(ctx, bytes.Repeat([]byte{0x47}, urmessage.GroupIdBytes))
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	invite, err := founded.AddMember(laptop.keyPackage(t))
	if err != nil {
		t.Fatalf("AddMember: %v", err)
	}
	if err := founded.Open(ctx); err != nil {
		t.Fatalf("Open: %v", err)
	}
	carried := gcReencodeInvite(t, invite)
	laptop.join(t, carried)
	if epoch := laptop.handle.Epoch(); epoch != 1 {
		t.Fatalf("the founding road joined at epoch %d, want 1", epoch)
	}
	jsSecondSpelling(t, "the founding road", laptop.handle, carried)

	// THE LIVE ROAD: AddMemberAndPublish, inside the publish, over the rotated secret's epoch
	scene := advFounding(t, true)
	tablet := scene.world.seamMember(t, scene.ctx, "tablet")
	invite, err = scene.aliceGroup.AddMemberAndPublish(scene.ctx, tablet.keyPackage(t))
	if err != nil {
		t.Fatalf("AddMemberAndPublish: %v", err)
	}
	carried = gcReencodeInvite(t, invite)
	tablet.join(t, carried)
	if epoch := tablet.handle.Epoch(); epoch != 2 {
		t.Fatalf("the live road joined at epoch %d, want 2", epoch)
	}
	jsSecondSpelling(t, "the live road", tablet.handle, carried)
}

// A GENUINE SEAL REPLAYED FROM ANOTHER EPOCH IS REFUSED BY THE AUTHENTICATOR. The seal's envelope
// carries a content epoch of zero, so that the epoch a member joined at is not in the clear, and
// the price is that the seal's own encryption no longer names its epoch: a seal made for one add
// of a device opens, as a wrap, under a later add of the same device at the same leaf. Here the
// device is added twice, at epochs 2 and 4, and the second invite is pasted carrying the FIRST
// invite's seal. It is refused as unauthenticated, the join code is not spent, and the honest
// second invite then joins.
func TestAGenuineSealReplayedFromAnotherEpochIsRefused(t *testing.T) {
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
	earlier, err := scene.aliceGroup.AddMemberAndPublish(scene.ctx, first)
	if err != nil {
		t.Fatalf("the first add: %v", err)
	}
	bobIdentity := rolesIdentityOf(t, scene.bobGroup)
	var daveIdentity []byte
	for _, member := range removalRoster(t, scene.aliceGroup) {
		if !member.Mine && !bytes.Equal(member.IdentityPub, bobIdentity) {
			daveIdentity = member.IdentityPub
		}
	}
	if err := scene.aliceGroup.RemoveMember(scene.ctx, daveIdentity); err != nil {
		t.Fatalf("removing the entry of the invitation that was never opened: %v", err)
	}
	later, err := scene.aliceGroup.AddMemberAndPublish(scene.ctx, second)
	if err != nil {
		t.Fatalf("the second add: %v", err)
	}
	if epoch := scene.aliceGroup.Epoch(); epoch != 4 {
		t.Fatalf("CONTROL FAILED: the group stands at epoch %d after an add, a removal and an add, want 4", epoch)
	}
	if bytes.Equal(earlier.JoinSeal, later.JoinSeal) {
		t.Fatalf("CONTROL FAILED: the two adds carry one seal, so nothing below is a replay")
	}
	replayed := gcReencodeInvite(t, &urmessage.Invite{
		GroupId:     later.GroupId,
		Welcome:     later.Welcome,
		RatchetTree: later.RatchetTree,
		JoinSeal:    earlier.JoinSeal,
		JoinAuth:    later.JoinAuth,
	})
	_, err = dave.device.Join(scene.ctx, replayed)
	if !errors.Is(err, urmessage.ErrJoinSealUnauthenticated) {
		t.Fatalf("the later invite carrying the earlier epoch's seal answered %v, want ErrJoinSealUnauthenticated", err)
	}
	if !errors.Is(err, urmessage.ErrJoinRefused) || errors.Is(err, urmessage.ErrJoinCodeSpent) {
		t.Errorf("that refusal is %v, which is not one made inside the window that leaves the join code", err)
	}
	daveGroup, err := dave.device.Join(scene.ctx, gcReencodeInvite(t, later))
	if err != nil {
		t.Fatalf("the honest later invite after the replay: %v", err)
	}
	canary := scene.say(t, "alice", scene.aliceGroup)
	gcReceiveText(t, scene.ctx, "dave", daveGroup, canary)
}
