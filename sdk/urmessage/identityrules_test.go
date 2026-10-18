package urmessage

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"testing"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/message/messagegroup"
	"github.com/urnetwork/message/mls"
	messageprotocol "github.com/urnetwork/message/protocol"
	"github.com/urnetwork/message/sdk"
	"github.com/urnetwork/message/syntax"
)

// THE IDENTITY LAYER'S BINDING RULES, ONE TABLE, NO DEVICE (identity phase 1's Task 13; MASTER §11 at
// Revision 10). [authorizeCommit] is pure over a [CommitAuthorization], so each new rule is a pair of
// rows here, one it allows and one it refuses: R6e, R6c-sig, R8-EQ, R8-CUR and R9, each refusal named
// by its own sentinel. The lists are real -- three identities made from words of their own, under the
// test seam's stretch, each base signed by the identity's phrase key and by its author -- and the
// leaves are devices of keys derived from their names.

// bindingLeaf is one leaf of a tree in the table: its credential, the device that stands there, and the
// 0xF005 it carries; a zero list carries none.
type bindingLeaf struct {
	leaf     uint32
	identity []byte
	device   string
	list     messagegroup.ExtensionBytes
}

// bindingRow is one commit against one tree, and the rule that answers it.
type bindingRow struct {
	name                    string
	committer               uint32
	before                  []bindingLeaf
	after                   []bindingLeaf
	added, removed, updated []uint32
	// the group's 0xF006, nil for a conversation
	purpose []byte
	// the epoch the commit opens; zero is 2
	opens uint64
	want  error
}

// bindingDeviceKey is the device key of a named device of the table.
func bindingDeviceKey(device string) []byte {
	_, public := testDeviceKey("the binding table's " + device)
	return public
}

// bindingDeviceSeed is the same device's seed, for a base it authors.
func bindingDeviceSeed(device string) mls.SignaturePrivateKey {
	seed, _ := testDeviceKey("the binding table's " + device)
	return seed
}

// bindingMembersOf is one tree as the ingest path would hand it over.
func bindingMembersOf(leaves []bindingLeaf, policy *mls.GroupPolicyExtension) []CommitMember {
	out := []CommitMember{}
	for _, one := range leaves {
		handle := make([]byte, 16)
		handle[0] = byte(one.leaf)
		member := CommitMember{
			Leaf:         one.leaf,
			SenderHandle: handle,
			IdentityPub:  bytes.Clone(one.identity),
			Role:         roleNameIn(policy, one.identity),
			HasLeafKeys:  true,
			SignatureKey: bindingDeviceKey(one.device),
		}
		if len(one.list.Data) != 0 {
			member.Extensions = []messagegroup.ExtensionBytes{{Type: one.list.Type, Data: bytes.Clone(one.list.Data)}}
		}
		out = append(out, member)
	}
	return out
}

// decision builds the value the ingest path would hand [authorizeCommit] for this row: the policy
// names the committer's identity as the owner on both sides, and the context carries 0x0003, the
// policy and, for a system group, its 0xF006.
func (self bindingRow) decision(t *testing.T) *CommitAuthorization {
	t.Helper()
	var committer []byte
	for _, one := range self.before {
		if one.leaf == self.committer {
			committer = one.identity
		}
	}
	if committer == nil {
		t.Fatalf("%s: no leaf %d before the commit", self.name, self.committer)
	}
	policy := &mls.GroupPolicyExtension{Roles: []mls.RoleEntry{{MemberId: bytes.Clone(committer), Role: mls.RoleOwner}}}
	if err := policy.Canonicalize(); err != nil {
		t.Fatal(err)
	}
	extensions := roleExtensionsOf(t, policy, roleCapabilities)
	if self.purpose != nil {
		extensions = append(extensions, messagegroup.ExtensionBytes{Type: uint16(mls.ExtensionTypeUrmessageGroupPurpose), Data: bytes.Clone(self.purpose)})
	}
	decoded, err := mls.GroupPolicyOf(mlsExtensionsOf(extensions))
	if err != nil {
		t.Fatalf("%s: the policy: %v", self.name, err)
	}
	opens := self.opens
	if opens == 0 {
		opens = 2
	}
	return &CommitAuthorization{
		GroupId:           make([]byte, GroupIdBytes),
		Epoch:             opens,
		CommitterLeaf:     self.committer,
		CommitterIdentity: bytes.Clone(committer),
		CommitterRole:     roleNameIn(decoded, committer),
		AddedLeaves:       self.added,
		RemovedLeaves:     self.removed,
		UpdatedLeaves:     self.updated,
		Members:           bindingMembersOf(self.before, decoded),
		MembersAfter:      bindingMembersOf(self.after, decoded),
		PolicyBefore:      decoded,
		PolicyAfter:       decoded,
		ExtensionsBefore:  extensions,
		ExtensionsAfter:   cloneExtensionBytes(extensions),
	}
}

// bindingIdentity is one identity of the table: its words and identity key.
type bindingIdentity struct {
	phrase *messagegroup.RecoveryPhrase
	key    []byte
}

func newBindingIdentity(t *testing.T) *bindingIdentity {
	t.Helper()
	phrase, err := messagegroup.NewRecoveryPhrase()
	if err != nil {
		t.Fatalf("a recovery phrase: %v", err)
	}
	t.Cleanup(phrase.Erase)
	return &bindingIdentity{phrase: phrase, key: testIdentityKeyOf(t, phrase)}
}

// list is one base of this identity naming the devices given, authored by the first.
func (self *bindingIdentity) list(t *testing.T, base uint64, devices ...string) messagegroup.ExtensionBytes {
	t.Helper()
	keys := [][]byte{}
	for _, device := range devices {
		keys = append(keys, bindingDeviceKey(device))
	}
	return testBaseList(t, self.phrase, base, bindingDeviceSeed(devices[0]), bindingDeviceKey(devices[0]), keys...)
}

// bindingPurpose is a 0xF006 body of a purpose and a root.
func bindingPurpose(t *testing.T, purpose uint8, root []byte) []byte {
	t.Helper()
	known := purpose
	if known != 1 && known != 2 {
		known = 1
	}
	encoded, err := (&messagegroup.GroupPurpose{Purpose: known, IdentityRoot: bytes.Clone(root)}).Encode()
	if err != nil {
		t.Fatalf("0xF006: %v", err)
	}
	body := bytes.Clone(encoded.Data)
	// a purpose this build does not know is written over the known one: version (2), then the purpose
	body[2] = purpose
	return body
}

func TestTheBindingRulesOverOneTable(t *testing.T) {
	alice, bob, carol := newBindingIdentity(t), newBindingIdentity(t), newBindingIdentity(t)
	a1 := alice.list(t, 1, "a1")
	a2 := alice.list(t, 2, "a1", "a2")
	a2fork := alice.list(t, 2, "a1", "a2", "a3")
	a3drop := alice.list(t, 3, "a1")
	a3add := alice.list(t, 3, "a1", "a2", "a3")
	b1 := bob.list(t, 1, "b1")
	b1other := bob.list(t, 1, "b2")
	c1 := carol.list(t, 1, "c1")
	selfGroup := bindingPurpose(t, 1, alice.key)
	linkGroup := bindingPurpose(t, 2, alice.key)
	unknownPurpose := bindingPurpose(t, 3, alice.key)
	// the new device of a link: profile 1, its credential its own key and no 0xF005
	n := bindingLeaf{1, bindingDeviceKey("n"), "n", messagegroup.ExtensionBytes{}}
	m := bindingLeaf{2, bindingDeviceKey("m"), "m", messagegroup.ExtensionBytes{}}

	A := func(leaf uint32, device string, list messagegroup.ExtensionBytes) bindingLeaf {
		return bindingLeaf{leaf, alice.key, device, list}
	}
	B := func(leaf uint32, device string, list messagegroup.ExtensionBytes) bindingLeaf {
		return bindingLeaf{leaf, bob.key, device, list}
	}

	rows := []bindingRow{
		// ── R6e: every leaf a commit adds or updates, and the committer's, is bound
		{name: "R6e allows an Add of a device its own list binds", committer: 0,
			before: []bindingLeaf{A(0, "a1", a1)}, after: []bindingLeaf{A(0, "a1", a1), B(1, "b1", b1)}, added: []uint32{1}},
		{name: "R6e refuses an Add of a leaf whose list does not name its key", committer: 0,
			before: []bindingLeaf{A(0, "a1", a1)}, after: []bindingLeaf{A(0, "a1", a1), B(1, "b1", b1other)}, added: []uint32{1},
			want: ErrCommitIdentityUnbound},
		{name: "R6e refuses an Add of a leaf whose credential its list's certificate does not name", committer: 0,
			before: []bindingLeaf{A(0, "a1", a1)}, after: []bindingLeaf{A(0, "a1", a1), {1, carol.key, "b1", b1}}, added: []uint32{1},
			want: ErrCommitIdentityUnbound},
		{name: "R6e refuses a committer whose post-commit leaf carries another root's list", committer: 0,
			before: []bindingLeaf{A(0, "a1", a1)}, after: []bindingLeaf{A(0, "a1", b1)},
			want: ErrCommitIdentityUnbound},
		{name: "R6e refuses an Update that drops 0xF005", committer: 0,
			before: []bindingLeaf{A(0, "a1", a2), A(1, "a2", a2)}, after: []bindingLeaf{A(0, "a1", a2), A(1, "a2", messagegroup.ExtensionBytes{})},
			updated: []uint32{1}, want: ErrCommitIdentityUnbound},

		// ── R6c-sig: every leaf that survives keeps its signature key
		{name: "R6c-sig allows a removed leaf's place filled by another device", committer: 0,
			before: []bindingLeaf{A(0, "a1", a1), B(1, "b1", b1)}, after: []bindingLeaf{A(0, "a1", a1), {1, carol.key, "c1", c1}},
			removed: []uint32{1}, added: []uint32{1}},
		{name: "R6c-sig refuses an Update that moves a kept leaf to another key", committer: 0,
			before: []bindingLeaf{A(0, "a1", a2), A(1, "a2", a2)}, after: []bindingLeaf{A(0, "a1", a2), A(1, "a3", a3add)},
			updated: []uint32{1}, want: ErrCommitSignatureKeyChanged},
		{name: "R6c-sig refuses a committer whose path moves its own leaf to another key", committer: 0,
			before: []bindingLeaf{A(0, "a1", a1)}, after: []bindingLeaf{A(0, "a3", a3add)},
			want: ErrCommitSignatureKeyChanged},

		// ── R8-EQ: two lists of one identity at one version are byte-identical
		{name: "R8-EQ allows two leaves of one identity carrying one list", committer: 0,
			before: []bindingLeaf{A(0, "a1", a2)}, after: []bindingLeaf{A(0, "a1", a2), A(1, "a2", a2)}, added: []uint32{1}},
		{name: "R8-EQ allows two leaves of one identity carrying two versions", committer: 0,
			before: []bindingLeaf{A(0, "a1", a1)}, after: []bindingLeaf{A(0, "a1", a1), A(1, "a2", a2)}, added: []uint32{1}},
		{name: "R8-EQ refuses two lists of one version that differ", committer: 0,
			before: []bindingLeaf{A(0, "a1", a2)}, after: []bindingLeaf{A(0, "a1", a2), A(1, "a2", a2fork)}, added: []uint32{1},
			want: ErrDeviceListEquivocation},

		// ── R8-CUR: a leaf the newest list does not name leaves in the commit that brings that list
		{name: "R8-CUR allows a list that drops a device, its leaf removed in the same commit", committer: 0,
			before: []bindingLeaf{A(0, "a1", a2), A(1, "a2", a2)}, after: []bindingLeaf{A(0, "a1", a3drop)},
			removed: []uint32{1}},
		{name: "R8-CUR refuses the same list with the device's leaf left standing", committer: 0,
			before: []bindingLeaf{A(0, "a1", a2), A(1, "a2", a2)}, after: []bindingLeaf{A(0, "a1", a3drop), A(1, "a2", a2)},
			want: ErrDeviceNotCurrent},
		{name: "R8-CUR refuses an Add whose list the tree's newest supersedes", committer: 0,
			before: []bindingLeaf{A(0, "a1", a3drop)}, after: []bindingLeaf{A(0, "a1", a3drop), A(1, "a2", a2)}, added: []uint32{1},
			want: ErrDeviceNotCurrent},
		{name: "R8-CUR leaves alone a leaf that was not current before and that the commit does not touch", committer: 0,
			before: []bindingLeaf{A(0, "a1", a3drop), A(1, "a2", a2)}, after: []bindingLeaf{A(0, "a1", a3drop), A(1, "a2", a2)}},

		// ── R9: a self group admits its own identity's leaves only
		{name: "R9 allows a device of a self group's own identity", committer: 0, purpose: selfGroup,
			before: []bindingLeaf{A(0, "a1", a1)}, after: []bindingLeaf{A(0, "a1", a1), A(1, "a2", a2)}, added: []uint32{1}},
		{name: "R9 refuses a stranger in a self group", committer: 0, purpose: selfGroup,
			before: []bindingLeaf{A(0, "a1", a1)}, after: []bindingLeaf{A(0, "a1", a1), B(1, "b1", b1)}, added: []uint32{1},
			want: ErrSystemGroupViolation},
		// ── R9: a link group holds one leaf of each profile, takes commits from its identity's leaf, at epoch 0
		{name: "R9 allows a link group's identity adding one profile-1 leaf at epoch 0", committer: 0, purpose: linkGroup, opens: 1,
			before: []bindingLeaf{A(0, "a1", a1)}, after: []bindingLeaf{A(0, "a1", a1), n}, added: []uint32{1}},
		{name: "R9 refuses a link group's second profile-1 leaf", committer: 0, purpose: linkGroup, opens: 1,
			before: []bindingLeaf{A(0, "a1", a1), n}, after: []bindingLeaf{A(0, "a1", a1), n, m}, added: []uint32{2},
			want: ErrSystemGroupViolation},
		{name: "R9 refuses a link group's commit at epoch 1", committer: 0, purpose: linkGroup, opens: 2,
			before: []bindingLeaf{A(0, "a1", a1), n}, after: []bindingLeaf{A(0, "a1", a1), n},
			want: ErrSystemGroupViolation},
		{name: "R9 refuses a link group's commit from its profile-1 leaf", committer: 1, purpose: linkGroup, opens: 1,
			before: []bindingLeaf{A(0, "a1", a1), n}, after: []bindingLeaf{A(0, "a1", a1), n},
			want: ErrSystemGroupViolation},
		{name: "R9 refuses a link group holding another identity's leaf", committer: 0, purpose: linkGroup, opens: 1,
			before: []bindingLeaf{A(0, "a1", a1)}, after: []bindingLeaf{A(0, "a1", a1), B(1, "b1", b1)}, added: []uint32{1},
			want: ErrSystemGroupViolation},
		{name: "R9 refuses a system group of a purpose this build does not know", committer: 0, purpose: unknownPurpose,
			before: []bindingLeaf{A(0, "a1", a1)}, after: []bindingLeaf{A(0, "a1", a1)},
			want: ErrSystemGroupViolation},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			err := authorizeCommit(row.decision(t))
			if row.want == nil {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			if !errors.Is(err, row.want) {
				t.Fatalf("answered %v, want %v", err, row.want)
			}
		})
	}
}

// A PROFILE-1 LEAF STANDS ONLY IN A LINK GROUP (Property 1; F1 section 2.3). A profile-1 leaf -- a
// credential that is its own signature key, and no 0xF005 -- is the one leaf a link group may hold
// beside its identity's, the new device's before it has an identity; anywhere else R6e refuses it,
// and the Join door and the Add door refuse it too. A leaf of the profile-1 shape that carries a 0xF005,
// and one that carries none under a credential that is not its key, bind to nothing anywhere.
func TestAProfileOneLeafStandsOnlyInALinkGroup(t *testing.T) {
	alice := newBindingIdentity(t)
	a1 := alice.list(t, 1, "a1")
	founder := bindingLeaf{0, alice.key, "a1", a1}
	profileOne := bindingLeaf{1, bindingDeviceKey("n"), "n", messagegroup.ExtensionBytes{}}
	// the profile-1 shape that carries a list naming its own key: the binding refuses a list whose
	// signature key is an identity key of the chain
	shapeWithList := bindingLeaf{1, bindingDeviceKey("a1"), "a1", a1}
	// no 0xF005, under a credential that is not the leaf's key
	unboundShape := bindingLeaf{1, alice.key, "n", messagegroup.ExtensionBytes{}}

	for _, row := range []struct {
		name    string
		purpose []byte
		leaf    bindingLeaf
		want    error
	}{
		{"a profile-1 leaf in a conversation is refused", nil, profileOne, ErrCommitIdentityUnbound},
		{"a profile-1 leaf in a self group is refused", bindingPurpose(t, 1, alice.key), profileOne, ErrCommitIdentityUnbound},
		{"a profile-1 leaf in a link group is allowed", bindingPurpose(t, 2, alice.key), profileOne, nil},
		{"the profile-1 shape carrying a 0xF005 is refused in a link group", bindingPurpose(t, 2, alice.key), shapeWithList, ErrCommitIdentityUnbound},
		{"a leaf with no 0xF005 under another credential is refused in a link group", bindingPurpose(t, 2, alice.key), unboundShape, ErrCommitIdentityUnbound},
	} {
		t.Run(row.name, func(t *testing.T) {
			decision := bindingRow{name: row.name, committer: 0, purpose: row.purpose, opens: 1,
				before: []bindingLeaf{founder}, after: []bindingLeaf{founder, row.leaf}, added: []uint32{1}}.decision(t)
			err := authorizeCommit(decision)
			if row.want == nil {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
			} else if !errors.Is(err, row.want) {
				t.Fatalf("answered %v, want %v", err, row.want)
			}
			// THE JOIN DOOR READS A WHOLE TREE THE SAME WAY: the profile-1 leaf stands only in a link group
			_, joinErr := checkTreeBinding(decision.MembersAfter, decision.ExtensionsAfter)
			if (row.want == nil) != (joinErr == nil) {
				t.Fatalf("the Join door's reading of the same tree answered %v, and the rules %v", joinErr, err)
			}
		})
	}
}

// claimIdentity makes a fixture device a further device of another identity: its leaves name that
// identity's key, and carry the list given.
func claimIdentity(t *testing.T, dev *crossProcessDevice, identityKey []byte, list messagegroup.ExtensionBytes) {
	t.Helper()
	engine, err := messagegroup.NewConnectMlsEngine(dev.crypto, dev.store, dev.signer, mls.BasicCredential(identityKey), dev.leafKeys)
	if err != nil {
		t.Fatalf("the claiming engine: %v", err)
	}
	dev.engine = engine
	dev.identityPub = bytes.Clone(identityKey)
	dev.extension = messagegroup.ExtensionBytes{Type: list.Type, Data: bytes.Clone(list.Data)}
}

// leafOfKey is the leaf a device key stands at in a member's tree.
func leafOfKey(t *testing.T, name string, handle messagegroup.GroupHandle, key []byte) uint32 {
	t.Helper()
	for at := 0; at < handle.MemberCount(); at += 1 {
		leaf, _, _, err := handle.MemberAt(at)
		if err != nil {
			t.Fatal(err)
		}
		view, err := handle.LeafAt(leaf)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(view.SignatureKey, key) {
			return leaf
		}
	}
	t.Fatalf("%s's tree holds no leaf of key %x", name, key)
	return 0
}

// ownLeafCommit is a member's commit through the seam that patches its own leaf with a list, removing
// the leaves given, merged and sealed as the record every other member walks.
func (self *roleWorld) ownLeafCommit(member *roleMember, list messagegroup.ExtensionBytes, removeLeaves ...uint32) *sealed {
	self.t.Helper()
	return self.commitAndPublish(member, "CommitOwnLeaf", func() ([]byte, []byte, []byte, error) {
		return member.handle.CommitOwnLeaf(messagegroup.OwnLeafPatch{Extensions: []messagegroup.ExtensionBytes{list}}, removeLeaves, nil)
	})
}

// A LEAF THE NEWEST LIST DOES NOT NAME IS REMOVED IN THE COMMIT THAT BRINGS IT, OR THE COMMIT IS
// REFUSED (Property 2; R8-CUR), through real devices and the seam's own commits, each rotated and
// fanned out as production publishes one. Alice adds her laptop under a list naming both, and every
// member follows. Then she brings a list that drops the laptop: with the laptop's leaf removed in the
// same commit every member follows it; with the leaf left standing every member refuses it, on R8-CUR's
// own sentinel, and stays where it was.
func TestALeafTheNewestListDoesNotNameIsRemovedInTheCommitThatBringsIt(t *testing.T) {
	for _, removed := range []bool{true, false} {
		t.Run(fmt.Sprintf("the laptop's leaf removed with the list: %v", removed), func(t *testing.T) {
			world := newRotWorld(t, "alice", "bob", "carol")
			alice, bob, carol := world.member("alice"), world.member("bob"), world.member("carol")
			laptop := claimingKeyPackage(t, world.rootOf("alice-laptop"), alice.dev.identityPub)
			added := world.rotate(alice, func() ([]byte, []byte, []byte, error) {
				return alice.handle.CommitAdd([][]byte{laptop})
			})
			for _, honest := range []*rotMember{bob, carol} {
				if err := world.deliver(honest, added.page()...); err != nil {
					t.Fatalf("%s refused the add of Alice's laptop: %v", honest.name, err)
				}
			}
			laptopLeaf := leafOfKey(t, alice.name, alice.handle, keyPackageSignatureKey(t, laptop))

			// the list that drops the laptop: Alice's next base, naming her alone
			alicePub := testPublicOf(alice.dev.signer)
			drop := testNextList(t, alice.dev.identityPub, alice.dev.signer, alicePub, alicePub)
			remove := []uint32{}
			if removed {
				remove = []uint32{laptopLeaf}
			}
			brought := world.rotate(alice, func() ([]byte, []byte, []byte, error) {
				return alice.handle.CommitOwnLeaf(messagegroup.OwnLeafPatch{Extensions: []messagegroup.ExtensionBytes{drop}}, remove, nil)
			})
			for _, honest := range []*rotMember{bob, carol} {
				epoch := honest.group.Epoch()
				err := world.deliver(honest, brought.page()...)
				if !removed {
					if !errors.Is(err, ErrCommitUnauthorized) || !errors.Is(err, ErrDeviceNotCurrent) {
						t.Fatalf("%s answered %v over the list that leaves the laptop standing, want R8-CUR's refusal", honest.name, err)
					}
					if got := honest.group.Epoch(); got != epoch {
						t.Fatalf("%s refused and stands at epoch %d, from %d", honest.name, got, epoch)
					}
					continue
				}
				if err != nil {
					t.Fatalf("%s refused the list with the laptop's leaf removed beside it: %v", honest.name, err)
				}
				if got := honest.group.Epoch(); got != epoch+1 {
					t.Fatalf("%s stands at epoch %d, from %d", honest.name, got, epoch)
				}
				for at := 0; at < honest.handle.MemberCount(); at += 1 {
					if leaf, _, _, err := honest.handle.MemberAt(at); err == nil && leaf == laptopLeaf {
						t.Fatalf("%s still holds the laptop's leaf %d", honest.name, laptopLeaf)
					}
				}
			}
		})
	}
}

// keyPackageSignatureKey is the signature key a key package's leaf names.
func keyPackageSignatureKey(t *testing.T, keyPackage []byte) []byte {
	t.Helper()
	decoded := &mls.KeyPackage{}
	if err := syntax.Unmarshal(keyPackage, decoded); err != nil {
		t.Fatalf("decoding a key package: %v", err)
	}
	return bytes.Clone(decoded.LeafNode.SignatureKey)
}

// TWO MEMBERS WHOSE LOCAL HEADS DIFFER DECIDE EVERY COMMIT ALIKE (Property 6; F1:337). Bob has seen a
// newer list of Alice's, which drops her laptop, in a group Carol is not in; Carol has not. The trees
// both hold carry no such list: by them Alice's laptop is current, and both follow the commit that adds
// it. Then Alice brings that newer list without removing the laptop, and both refuse it, by the trees,
// whatever Bob already knew. Validity reads the trees and nothing a member holds of its own.
func TestTwoMembersWithDifferentLocalHeadsAgreeOnEveryCommit(t *testing.T) {
	world := newRoleWorld(t, "alice", "bob", "carol")
	alice, bob, carol := world.member("alice"), world.member("bob"), world.member("carol")
	for _, member := range []*roleMember{bob, carol} {
		testHoldIdentity(t, member.group.device, member.dev.identityPub, member.dev.extension, member.dev.signer)
	}
	laptop := claimingKeyPackage(t, world.root+"/alice-laptop", alice.dev.identityPub)
	alicePub := testPublicOf(alice.dev.signer)
	newer := testNextList(t, alice.dev.identityPub, alice.dev.signer, alicePub, alicePub)
	verified, err := messagegroup.VerifyLeafBinding(alice.dev.identityPub, alicePub, []messagegroup.ExtensionBytes{newer})
	if err != nil {
		t.Fatalf("the newer list does not bind Alice: %v", err)
	}
	// BOB'S HEAD IS THE NEWER LIST; CAROL'S HOLDS NOTHING OF ALICE'S
	if err := bob.group.device.raiseHeadsFrom([]*messagegroup.VerifiedIdentity{verified}, false); err != nil {
		t.Fatalf("bob's heads: %v", err)
	}
	if head, _ := testHeadOf(t, bob.group.device, alice.dev.identityPub); !bytes.Equal(head, newer.Data) {
		t.Fatal("CONTROL FAILED: bob's head of Alice's is not the newer list")
	}
	if head, _ := testHeadOf(t, carol.group.device, alice.dev.identityPub); head != nil {
		t.Fatal("CONTROL FAILED: carol holds a head of Alice's")
	}

	// AN ADD THE TREES ALLOW, which Bob's head would refuse: both follow it
	record := world.commitAndPublish(alice, "CommitAdd of her laptop", func() ([]byte, []byte, []byte, error) {
		return alice.handle.CommitAdd([][]byte{laptop})
	})
	for _, member := range []*roleMember{bob, carol} {
		world.ingest(member, alice, record)
	}
	// A COMMIT THE TREES REFUSE, which Bob's head already holds: both refuse it, for the trees' reason
	record = world.ownLeafCommit(alice, newer)
	for _, member := range []*roleMember{bob, carol} {
		world.refuse(member, record, ErrDeviceNotCurrent)
	}
}

// AN OWN COMMIT EVERY RECEIVER WOULD REFUSE IS NEVER PUBLISHED (Property 8; REDTEAM H1). The sending
// side runs every rule over the would-be tree, with the committer's post-commit leaf, the own-leaf patch
// included. Three commits every receiver would refuse, each through a verb: a patch carrying another
// root's list (R6e); a patch carrying a list older than the tree's newest, which takes a device off it
// (R8-CUR); and an Add whose key package's list the tree's newest supersedes (R8-CUR). Each is answered
// with the receivers' own sentence, counted, and nothing is built or reaches the server; and afterwards
// every member still follows an honest commit, so none of them halts.
func TestAnOwnCommitEveryReceiverWouldRefuseIsNeverPublished(t *testing.T) {
	world := newRoleWorld(t, "alice", "bob", "carol")
	alice, bob, carol := world.member("alice"), world.member("bob"), world.member("carol")
	client := world.connect(alice)
	// FROM HERE NOTHING BUT A HELLO REACHES THE SERVER, and anything else is refused at once: a commit
	// sent despite the rules fails in the call that sent it, and is counted, fragments included
	// (LRI R84 item 2; review G-4)
	client.refuseAllButHello()
	ctx := t.Context()

	// THE TREE: Alice's laptop under base 2, and then Alice's own leaf under base 4, the newest
	laptop := claimingKeyPackage(t, world.root+"/alice-laptop", alice.dev.identityPub)
	record := world.commitAndPublish(alice, "CommitAdd of her laptop", func() ([]byte, []byte, []byte, error) {
		return alice.handle.CommitAdd([][]byte{laptop})
	})
	for _, member := range []*roleMember{bob, carol} {
		world.ingest(member, alice, record)
	}
	alicePub := testPublicOf(alice.dev.signer)
	laptopKey := keyPackageSignatureKey(t, laptop)
	stale := testNextList(t, alice.dev.identityPub, alice.dev.signer, alicePub, alicePub)             // base 3: Alice alone
	newest := testNextList(t, alice.dev.identityPub, alice.dev.signer, alicePub, alicePub, laptopKey) // base 4: both
	record = world.ownLeafCommit(alice, newest)
	for _, member := range []*roleMember{bob, carol} {
		world.ingest(member, alice, record)
	}
	// a third device of Alice's, whose key package carries base 3 with it, which base 4 does not name
	phoneSeed, phonePub := testDeviceKey("alice's phone, for the superseded add")
	phrase := testPhraseOf(t, alice.dev.identityPub)
	superseded := testBaseList(t, phrase, 3, phoneSeed, phonePub, alicePub, laptopKey, phonePub)
	phrase.Erase()
	phone := keyPackageOf(t, world, "alice-phone", alice.dev.identityPub, phoneSeed, superseded)

	for _, one := range []struct {
		name string
		do   func() error
		rule error
	}{
		{"a patch carrying another root's list", func() error {
			return alice.group.commitOwnLeaf(ctx, messagegroup.OwnLeafPatch{Extensions: []messagegroup.ExtensionBytes{bob.dev.extension}}, nil)
		}, ErrCommitIdentityUnbound},
		{"a patch carrying a list older than the tree's newest", func() error {
			return alice.group.commitOwnLeaf(ctx, messagegroup.OwnLeafPatch{Extensions: []messagegroup.ExtensionBytes{stale}}, nil)
		}, ErrDeviceNotCurrent},
		{"an Add whose key package's list the tree's newest supersedes", func() error {
			_, err := alice.group.AddMemberAndPublish(ctx, phone)
			return err
		}, ErrDeviceNotCurrent},
	} {
		epoch, handed, refused := alice.group.Epoch(), client.handed(), alice.group.Stats().CommitRefusedOwn
		err := one.do()
		if !errors.Is(err, ErrCommitUnauthorized) || !errors.Is(err, one.rule) {
			t.Errorf("%s answered %v, want ErrCommitUnauthorized wrapping %v", one.name, err, one.rule)
		}
		// EVERY FRAME, FRAGMENTS INCLUDED: a commit's submission goes out as fragments, which a count
		// of answered requests never saw
		if got := client.handed(); got != handed {
			t.Errorf("%s: %d frame(s) reached the server", one.name, got-handed)
		}
		if got := alice.group.Epoch(); got != epoch {
			t.Errorf("%s: alice stands at epoch %d, from %d", one.name, got, epoch)
		}
		if _, err := alice.handle.PendingEpoch(); err == nil {
			t.Errorf("%s left a commit staged", one.name)
			alice.handle.ClearPendingCommit()
		}
		if got := alice.group.Stats().CommitRefusedOwn; got != refused+1 {
			t.Errorf("%s: Stats.CommitRefusedOwn went %d -> %d, want one more", one.name, refused, got)
		}
	}

	// NO MEMBER HALTS: an honest commit after all three is followed by every member
	record = world.commitAndPublish(alice, "a bare commit", func() ([]byte, []byte, []byte, error) {
		return alice.handle.Commit([][]byte{})
	})
	for _, member := range []*roleMember{bob, carol} {
		world.ingest(member, alice, record)
	}
}

// connect gives one member of the role world a connection, so that its verbs can rebind: a transport
// over an answering client whose Hello has been answered. The client counts every request it answers,
// which is what reaching the server is here. The member's verbs run as a device's do from then on.
func (self *roleWorld) connect(member *roleMember) *answeringClient {
	self.t.Helper()
	client := &answeringClient{reason: messageprotocol.Reason_REASON_OK, nonce: []byte(member.name + "'s server nonce")}
	transport, err := sdk.NewMessageTransport(&sdk.MessageTransportConfig{
		Client:          client,
		Server:          connect.NewId(),
		ProtocolVersion: 1,
	})
	if err != nil {
		self.t.Fatalf("%s's transport: %v", member.name, err)
	}
	self.t.Cleanup(transport.Close)
	if reason, _, err := transport.Hello(context.Background()); err != nil || reason != messageprotocol.Reason_REASON_OK {
		self.t.Fatalf("%s's Hello: %v %v", member.name, reason, err)
	}
	member.group.device.transport = transport
	// and the crypto provider a verb judges a join code through, which a member built field by field
	// lacks
	member.group.device.crypto = member.dev.crypto
	return client
}

// keyPackageOf is a key package of a device of the seed given, under an identity key, carrying a list.
func keyPackageOf(t *testing.T, world *roleWorld, name string, identityKey []byte, seed mls.SignaturePrivateKey,
	list messagegroup.ExtensionBytes) []byte {

	t.Helper()
	dev := world.device(name)
	engine, err := messagegroup.NewConnectMlsEngine(dev.crypto, dev.store, seed, mls.BasicCredential(identityKey), dev.leafKeys)
	if err != nil {
		t.Fatalf("%s's engine: %v", name, err)
	}
	keyPackage, err := engine.NewBoundKeyPackage([]messagegroup.ExtensionBytes{list})
	if err != nil {
		t.Fatalf("%s's key package: %v", name, err)
	}
	return keyPackage
}

// R8-EQ REFUSES A FORK IN EVERY LEAF ORDER (LRI R84 item 7; review C-1). Two lists of one identity at
// one version that differ -- two bases of one number, or two additions at one index on one base --
// are a fork wherever they stand in a tree, and a strictly newer list of that identity standing
// between them hides nothing: R8-EQ compares every pair of one root's lists, and not each against
// the newest it has read so far. Every order of the three lists is refused, by the rule alone, by
// the Join door's reading of the whole tree, and by the commit that adds the last of them.
//
// THE CONTROLS: the two forking lists are one version and the library calls them a fork; and three
// lists that do not fork are admitted in every order, so the refusals are the fork's and not the
// tree's.
func TestR8EQRefusesAForkInEveryLeafOrder(t *testing.T) {
	alice := newBindingIdentity(t)
	author := ed25519.NewKeyFromSeed([]byte(bindingDeviceSeed("d1")))
	withAddition := func(base messagegroup.ExtensionBytes, device string) messagegroup.ExtensionBytes {
		t.Helper()
		identity, err := messagegroup.ParseUrmessageIdentity(base)
		if err != nil {
			t.Fatal(err)
		}
		amendment, err := messagegroup.NewAddition(identity, messagegroup.DeviceEntry{DeviceKey: bindingDeviceKey(device)}, author, 1)
		if err != nil {
			t.Fatalf("an addition of %s: %v", device, err)
		}
		identity.Amendments = append(identity.Amendments, *amendment)
		encoded, err := identity.Encode()
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	base1 := alice.list(t, 1, "d1")
	for _, shape := range []struct {
		name          string
		first, second messagegroup.ExtensionBytes
		newest        messagegroup.ExtensionBytes
		devices       [3]string
	}{
		{"two bases of one number", alice.list(t, 2, "a1", "a2"), alice.list(t, 2, "a1", "a2", "a3"),
			alice.list(t, 3, "a1", "a2", "a3"), [3]string{"a1", "a2", "a3"}},
		{"two additions at one index on one base", withAddition(base1, "d2"), withAddition(base1, "d3"),
			alice.list(t, 2, "d1", "d2", "d3"), [3]string{"d2", "d3", "d1"}},
	} {
		// THE CONTROL: one version, and a fork by the library's own reading
		first, err := messagegroup.ParseUrmessageIdentity(shape.first)
		if err != nil {
			t.Fatal(err)
		}
		second, err := messagegroup.ParseUrmessageIdentity(shape.second)
		if err != nil {
			t.Fatal(err)
		}
		if first.Version() != second.Version() {
			t.Fatalf("CONTROL FAILED: %s: the two lists are not one version", shape.name)
		}
		if _, err := messagegroup.VerifyDeviceList(first, second); !errors.Is(err, messagegroup.ErrDeviceListFork) {
			t.Fatalf("CONTROL FAILED: %s: VerifyDeviceList answered %v, want a fork", shape.name, err)
		}
		lists := map[string]messagegroup.ExtensionBytes{"first": shape.first, "second": shape.second, "newest": shape.newest}
		devices := map[string]string{"first": shape.devices[0], "second": shape.devices[1], "newest": shape.devices[2]}
		for _, order := range [][3]string{
			{"first", "second", "newest"}, {"second", "first", "newest"}, {"first", "newest", "second"},
			{"second", "newest", "first"}, {"newest", "first", "second"}, {"newest", "second", "first"},
		} {
			leaves := []bindingLeaf{}
			for at, name := range order {
				leaves = append(leaves, bindingLeaf{uint32(at), alice.key, devices[name], lists[name]})
			}
			members := bindingMembersOf(leaves, nil)
			if err := ruleNoListFork(boundLeavesOf(members)); !errors.Is(err, ErrDeviceListEquivocation) {
				t.Errorf("%s, leaves %v: R8-EQ answered %v, want ErrDeviceListEquivocation", shape.name, order, err)
			}
			if _, err := checkTreeBinding(members, nil); !errors.Is(err, ErrDeviceListEquivocation) {
				t.Errorf("%s, leaves %v: the Join door answered %v, want ErrDeviceListEquivocation", shape.name, order, err)
			}
			// the commit that adds the last of the three, by the first
			row := bindingRow{name: shape.name, committer: 0, before: leaves[:2], after: leaves, added: []uint32{2}}
			if err := authorizeCommit(row.decision(t)); !errors.Is(err, ErrDeviceListEquivocation) {
				t.Errorf("%s, leaves %v: the commit adding leaf 2 answered %v, want ErrDeviceListEquivocation", shape.name, order, err)
			}
		}
	}
	// THE CONTROL: lists that do not fork are admitted in every order
	older, newest := alice.list(t, 1, "a1", "a2", "a3"), alice.list(t, 2, "a1", "a2", "a3")
	lists := map[string]messagegroup.ExtensionBytes{"older": older, "newest": newest, "again": newest}
	devices := map[string]string{"older": "a1", "newest": "a2", "again": "a3"}
	for _, order := range [][3]string{
		{"older", "newest", "again"}, {"newest", "older", "again"}, {"again", "older", "newest"},
		{"older", "again", "newest"}, {"newest", "again", "older"}, {"again", "newest", "older"},
	} {
		leaves := []bindingLeaf{}
		for at, name := range order {
			leaves = append(leaves, bindingLeaf{uint32(at), alice.key, devices[name], lists[name]})
		}
		if err := ruleNoListFork(boundLeavesOf(bindingMembersOf(leaves, nil))); err != nil {
			t.Errorf("CONTROL FAILED: lists that do not fork, leaves %v, answered %v", order, err)
		}
	}
}

// chainedBindingList is a list of the identity key `to`, base 1 under key number 1 naming one phrase
// device, whose chain is one form-1 step from `from`'s identity key, signed by `from`'s words: the
// shape a leaf carries after a phrase change (MASTER section 5.5).
func chainedBindingList(t *testing.T, from *bindingIdentity, to *bindingIdentity, device string) messagegroup.ExtensionBytes {
	t.Helper()
	var step *messagegroup.IdentityStep
	if err := messagegroup.WithPhraseKeysUnder(messagegroup.FastPhraseStretchForTests(), from.phrase, []uint32{1},
		func(keys *messagegroup.PhraseKeys) error {
			var err error
			step, err = keys.SignIdentityStep(ed25519.PublicKey(bytes.Clone(to.key)))
			return err
		}); err != nil {
		t.Fatalf("the step: %v", err)
	}
	authorPub := bindingDeviceKey(device)
	author := ed25519.NewKeyFromSeed([]byte(bindingDeviceSeed(device)))
	var own *messagegroup.UrmessageIdentity
	if err := messagegroup.WithPhraseKeysUnder(messagegroup.FastPhraseStretchForTests(), to.phrase, []uint32{1},
		func(keys *messagegroup.PhraseKeys) error {
			cert, err := keys.SignIskCert(1)
			if err != nil {
				return err
			}
			base := &messagegroup.DeviceListBase{IdentityKey: keys.IdentityKey(), KeyNumber: 1, BaseNumber: 1, IssuedAtMs: 1,
				Devices:   []messagegroup.DeviceEntry{{DeviceKey: bytes.Clone(authorPub), Flags: messagegroup.DeviceFlagPhraseDevice}},
				AuthorKey: bytes.Clone(authorPub)}
			if err := messagegroup.SignBaseAuthor(base, author); err != nil {
				return err
			}
			if err := keys.SignBase(1, base); err != nil {
				return err
			}
			own = &messagegroup.UrmessageIdentity{IskCert: *cert, Base: *base, Chain: []messagegroup.IdentityStep{*step}}
			return nil
		}); err != nil {
		t.Fatalf("the chained list: %v", err)
	}
	encoded, err := own.Encode()
	if err != nil {
		t.Fatalf("the chained list's encoding: %v", err)
	}
	return encoded
}

// R9 READS A LINK GROUP BY THE CURRENT IDENTITY KEY AND A SELF GROUP BY THE ROOT (LRI R84 item 8;
// review C-2 and G-3). MASTER sections 5.3 and 5.4 and Spec A sections 3.4 and 7.5: 0xF006's
// identity_root is the identity's root in a self group, and its current identity key, IRK, in a link
// group, which E founds with {2, IRK}. Over an identity with a chain of one step -- root R, current
// key K -- a link group {2, K} takes E's Add of the new device, at E's send side and at the new
// device's Join door, and {2, R} takes neither; a self group {1, R} takes E's commit, and {1, K} does
// not.
//
// THE CONTROL: the chained list binds with root R and identity key K, which differ; and with no chain
// a link group {2, key} takes the Add, so the refusals are the chain's.
func TestR9ReadsALinkGroupByTheCurrentKeyAndASelfGroupByTheRoot(t *testing.T) {
	root, current := newBindingIdentity(t), newBindingIdentity(t)
	chained := chainedBindingList(t, root, current, "e1")
	verified, err := messagegroup.VerifyLeafBinding(current.key, bindingDeviceKey("e1"), []messagegroup.ExtensionBytes{chained})
	if err != nil {
		t.Fatalf("CONTROL FAILED: the chained list does not bind: %v", err)
	}
	if !bytes.Equal(verified.Root, root.key) || !bytes.Equal(verified.IdentityKey, current.key) || bytes.Equal(root.key, current.key) {
		t.Fatal("CONTROL FAILED: the chained list's root and current key are not the two keys, apart")
	}
	identityLeaf := bindingLeaf{0, current.key, "e1", chained}
	newDevice := bindingLeaf{1, bindingDeviceKey("n"), "n", messagegroup.ExtensionBytes{}}
	link := func(purpose []byte) (error, error) {
		row := bindingRow{name: "the link", committer: 0, purpose: purpose, opens: 1,
			before: []bindingLeaf{identityLeaf}, after: []bindingLeaf{identityLeaf, newDevice}, added: []uint32{1}}
		decision := row.decision(t)
		_, joinErr := checkTreeBinding(decision.MembersAfter, decision.ExtensionsAfter)
		return authorizeCommit(decision), joinErr
	}
	if commitErr, joinErr := link(bindingPurpose(t, 2, current.key)); commitErr != nil || joinErr != nil {
		t.Errorf("a link group {2, IRK} over a chained identity: E's Add answered %v and the Join door %v, want both taken", commitErr, joinErr)
	}
	if commitErr, joinErr := link(bindingPurpose(t, 2, root.key)); !errors.Is(commitErr, ErrSystemGroupViolation) || !errors.Is(joinErr, ErrSystemGroupViolation) {
		t.Errorf("a link group {2, root} over a chained identity: E's Add answered %v and the Join door %v, want R9 refusing both", commitErr, joinErr)
	}
	self := func(purpose []byte) error {
		return authorizeCommit(bindingRow{name: "the self group", committer: 0, purpose: purpose,
			before: []bindingLeaf{identityLeaf}, after: []bindingLeaf{identityLeaf}}.decision(t))
	}
	if err := self(bindingPurpose(t, 1, root.key)); err != nil {
		t.Errorf("a self group {1, root} over its chained identity: a bare commit answered %v, want taken", err)
	}
	if err := self(bindingPurpose(t, 1, current.key)); !errors.Is(err, ErrSystemGroupViolation) {
		t.Errorf("a self group {1, IRK} over its chained identity: a bare commit answered %v, want R9's refusal", err)
	}
	// THE CONTROL: with no chain the identity key is the root, and a link group of it takes the Add
	plain := newBindingIdentity(t)
	plainLeaf := bindingLeaf{0, plain.key, "p1", plain.list(t, 1, "p1")}
	if err := authorizeCommit(bindingRow{name: "the chainless link", committer: 0, purpose: bindingPurpose(t, 2, plain.key), opens: 1,
		before: []bindingLeaf{plainLeaf}, after: []bindingLeaf{plainLeaf, newDevice}, added: []uint32{1}}.decision(t)); err != nil {
		t.Fatalf("CONTROL FAILED: a link group over an identity with no chain refuses the Add: %v", err)
	}
}
