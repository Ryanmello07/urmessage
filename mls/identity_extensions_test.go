// The identity layer's two code points and the leaves that carry them (identity phase 1's plan,
// Task 9): 0xF005, urmessage_identity, which only a leaf may carry; 0xF006, urmessage_group_purpose,
// which only a group context may carry; leaves that keep every extension their caller set; and the
// own-leaf patch a committer makes in its own path leaf.
//
// mls carries both bodies OPAQUE. What a 0xF005 body says -- the certificate, the device list, the
// chain -- is messagegroup's, and none of its sizes is checked here; so every body below is a run of
// octets with no meaning, and what is asserted is that the octets a caller set are the octets every
// member reads back.
package mls

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/message/syntax"
)

// testIdentityBody is a 0xF005 body as mls sees one: octets it carries and never reads.
func testIdentityBody(who string) []byte {
	return []byte("the identity extension body of " + who + ", which mls carries and never reads")
}

// testCapabilitiesListing is testCapabilities with further extension types listed, which is what a
// leaf carrying one of them has to say of itself (RFC 9420 section 7.2).
func testCapabilitiesListing(types ...ExtensionType) Capabilities {
	caps := testCapabilities()
	caps.Extensions = append(slices.Clone(caps.Extensions), types...)
	return caps
}

// testExtensionsString is an extension vector as one comparable string: each entry's type and the
// hex of its body, in order. Order is part of what a caller set, so it is part of this.
func testExtensionsString(exts []Extension) string {
	parts := []string{}
	for _, ext := range exts {
		parts = append(parts, fmt.Sprintf("%#04x=%x", uint16(ext.ExtensionType), ext.ExtensionData))
	}
	return "[" + strings.Join(parts, " ") + "]"
}

// testJoinedPair founds a group on an owner and adds one joiner whose key package carries `exts`
// under `caps`, then joins it. It answers the owner's group, the joiner's, and the joiner.
func testJoinedPair(t *testing.T, crypto CryptoProvider, groupId string, caps Capabilities,
	exts func(*testMember) []Extension) (*Group, *Group, *testMember) {

	t.Helper()
	owner := testIdentity(t, crypto, "owner")
	group := testNewGroup(t, crypto, owner, groupId)
	bob := testIdentity(t, crypto, "bob")
	kp, initPriv, encPriv, err := NewKeyPackageWithSigner(crypto, crypto.Suite(), bob.SigPriv,
		BasicCredential(bob.IdentityPub), caps, exts(bob))
	if err != nil {
		t.Fatalf("bob's key package: %v", err)
	}
	encoded, err := syntax.Marshal(kp)
	if err != nil {
		t.Fatalf("encode bob's key package: %v", err)
	}
	if _, err := group.ProposeAdd(encoded); err != nil {
		t.Fatalf("the owner's ProposeAdd of bob: %v", err)
	}
	result, err := group.CreateCommit(nil, nil, nil)
	if err != nil {
		t.Fatalf("the owner's commit adding bob: %v", err)
	}
	if err := group.MergePendingCommit(); err != nil {
		t.Fatalf("the owner's merge: %v", err)
	}
	joined, err := JoinFromWelcome(testGroupConfig(t, crypto, bob, groupId), result.Welcome, result.RatchetTree,
		&JoinKeyMaterial{KeyPackage: *kp, InitPrivate: initPriv, EncryptPrivate: encPriv, SignPrivate: bob.SigPriv})
	if err != nil {
		t.Fatalf("bob's JoinFromWelcome: %v", err)
	}
	return group, joined, bob
}

// testFollow has `receiver` process one commit message and apply it, and holds the two members to
// one epoch afterwards: the epoch authenticator is DeriveSecret(epoch_secret, "authentication"),
// and the epoch secret is expanded over the group context, whose tree hash covers every leaf. So
// two members that agree on it agree on every leaf of the tree, the committer's included.
func testFollow(t *testing.T, receiver *Group, committer *Group, message []byte) {
	t.Helper()
	processed, err := receiver.ProcessMessage(message)
	if err != nil {
		t.Fatalf("ProcessMessage over the commit: %v", err)
	}
	if processed.Kind != ProcessedCommit {
		t.Fatalf("the message processed as kind %d, not a commit", processed.Kind)
	}
	if err := receiver.ApplyCommit(processed); err != nil {
		t.Fatalf("ApplyCommit: %v", err)
	}
	if receiver.Epoch() != committer.Epoch() || !bytes.Equal(receiver.EpochAuthenticator(), committer.EpochAuthenticator()) {
		t.Fatalf("the receiver stands at epoch %d and the committer at %d, or their epoch authenticators differ: the two do not hold one tree",
			receiver.Epoch(), committer.Epoch())
	}
}

// AN UPDATE, A PATH LEAF, A KEY PACKAGE'S LEAF AND A FOUNDER'S LEAF CARRY EXACTLY THE EXTENSIONS
// THEIR CALLER SET, AND AN UPDATE KEEPS THE REPLACED LEAF'S (Property 1).
//
// THE UPDATE IS THE ARM THAT WAS FALSE, and it is first for that reason. (*Group).ProposeUpdate
// built its leaf with urmessage_leaf_keys alone, so a member whose leaf carried the identity
// extension lost it at its first Update, and with it the binding every member checks. Keeping is
// the rule because an Update replaces one key: the leaf's other facts are the member's, and a
// refresh is not the place to drop them.
//
// The other three are held beside it because "carries what its caller set" is one property over
// four constructions, and the three that were already true are the controls that the first was the
// one false thing: a key package's leaf is its caller's vector, in order; a path leaf with no patch
// is the committer's own leaf with a fresh key; a founder's leaf is urmessage_leaf_keys followed by
// GroupConfig.LeafExtensions.
func TestAnUpdateKeepsEveryExtensionOfTheLeafItReplaces(t *testing.T) {
	crypto := testCrypto(t)
	caps := testCapabilitiesListing(ExtensionTypeUrmessageIdentity)
	withIdentity := func(m *testMember) []Extension {
		return []Extension{testLeafKeys(t, m), {ExtensionType: ExtensionTypeUrmessageIdentity, ExtensionData: testIdentityBody(m.Name)}}
	}
	group, joined, bob := testJoinedPair(t, crypto, "an-update-keeps-every-extension", caps, withIdentity)
	replaced := joined.OwnLeafNodeCopy()
	if got, want := testExtensionsString(replaced.Extensions), testExtensionsString(withIdentity(bob)); got != want {
		t.Fatalf("bob's leaf in the tree carries %s and his key package was minted with %s: the key package's leaf is not what its caller set", got, want)
	}

	// THE UPDATE, read off the proposal as the owner receives it
	proposal, err := joined.ProposeUpdate()
	if err != nil {
		t.Fatalf("bob's ProposeUpdate: %v", err)
	}
	processed, err := group.ProcessMessage(proposal)
	if err != nil {
		t.Fatalf("the owner's ProcessMessage over bob's Update: %v", err)
	}
	if processed.Kind != ProcessedProposal || processed.Proposal == nil || processed.Proposal.Update == nil {
		t.Fatalf("bob's Update processed as kind %d with no Update arm", processed.Kind)
	}
	update := processed.Proposal.Update.LeafNode
	if got, want := testExtensionsString(update.Extensions), testExtensionsString(replaced.Extensions); got != want {
		t.Errorf("bob's Update carries %s and the leaf it replaces carries %s: an Update dropped what the member's leaf held", got, want)
	}
	if !bytes.Equal(update.Credential.Identity, replaced.Credential.Identity) {
		t.Errorf("bob's Update names identity %x and the leaf it replaces %x", update.Credential.Identity, replaced.Credential.Identity)
	}
	if bytes.Equal(update.EncryptionKey, replaced.EncryptionKey) {
		t.Errorf("bob's Update republishes the encryption key it replaces, so it refreshed nothing")
	}
	// and it goes through: the owner commits it, bob follows, and both trees hold bob's leaf as the Update has it
	result, err := group.CreateCommit(nil, nil, nil)
	if err != nil {
		t.Fatalf("the owner's commit over bob's Update: %v", err)
	}
	if err := group.MergePendingCommit(); err != nil {
		t.Fatalf("the owner's merge: %v", err)
	}
	testFollow(t, joined, group, result.Commit)
	for name, member := range map[string]*Group{"the owner": group, "bob": joined} {
		if got, want := testExtensionsString(member.tree.Leaf(joined.OwnLeafIndex()).Extensions), testExtensionsString(replaced.Extensions); got != want {
			t.Errorf("after the Update %s's tree holds bob's leaf with %s, want %s", name, got, want)
		}
	}

	// THE PATH LEAF: bob commits with a path and no patch, and his path leaf is his leaf with a fresh key
	before := joined.OwnLeafNodeCopy()
	result, err = joined.CreateCommit(nil, nil, &CommitOptions{Force: true})
	if err != nil {
		t.Fatalf("bob's commit with a path: %v", err)
	}
	if err := joined.MergePendingCommit(); err != nil {
		t.Fatalf("bob's merge: %v", err)
	}
	testFollow(t, group, joined, result.Commit)
	path := group.tree.Leaf(joined.OwnLeafIndex())
	if path.LeafNodeSource != LeafNodeSourceCommit {
		t.Fatalf("bob's leaf after his own path commit has source %d, not commit", path.LeafNodeSource)
	}
	if got, want := testExtensionsString(path.Extensions), testExtensionsString(before.Extensions); got != want {
		t.Errorf("bob's path leaf carries %s and the leaf it replaced %s", got, want)
	}

	// THE FOUNDER'S LEAF: urmessage_leaf_keys, then exactly the caller's LeafExtensions
	carol := testIdentity(t, crypto, "carol")
	cfg := testGroupConfig(t, crypto, carol, "a-founder-leaf-carries-its-caller's-extensions")
	identity := Extension{ExtensionType: ExtensionTypeUrmessageIdentity, ExtensionData: testIdentityBody("carol")}
	cfg.LeafExtensions = []Extension{identity}
	founded, err := NewGroup(cfg, carol.SigPriv, BasicCredential(carol.IdentityPub))
	if err != nil {
		t.Errorf("NewGroup with GroupConfig.LeafExtensions answered %v", err)
	} else {
		want := testExtensionsString([]Extension{testLeafKeys(t, carol), identity})
		if got := testExtensionsString(founded.OwnLeafNodeCopy().Extensions); got != want {
			t.Errorf("the founder's leaf carries %s, want %s", got, want)
		}
	}
	// and a LeafExtensions entry of the type the founder's leaf keys already take is a second
	// entry of one type, which no lookup of that type reads: refused as the repeat it is
	cfg = testGroupConfig(t, crypto, carol, "a-founder-leaf-cannot-carry-two-leaf-keys")
	cfg.LeafExtensions = []Extension{testLeafKeys(t, carol)}
	if _, err := NewGroup(cfg, carol.SigPriv, BasicCredential(carol.IdentityPub)); !errors.Is(err, ErrMalformedExtension) {
		t.Errorf("NewGroup with a LeafExtensions entry of urmessage_leaf_keys answered %v, want ErrMalformedExtension", err)
	}
}

// 0xF005 STANDS ONLY IN A LEAF AND 0xF006 ONLY IN A GROUP CONTEXT (Property 2's first half).
//
// The group-context half is groupExtensionProfile's row for each, read through every door that
// judges a group context extension: the profile itself, a founding, and a proposal of a new set. The
// leaf half is (*LeafNode).Validate's, and it is new: until 0xF006 no type this profile placed in a
// group context had a reason to be refused in a leaf as well, and a leaf that claimed to be a group's
// purpose is a member speaking for the group.
//
// THE CONTROLS ARE THE OTHER TYPE AT EACH POSITION: 0xF005 is accepted in a leaf and 0xF006 in a
// group context, through the same doors, so neither refusal is a door that refuses everything.
func TestTheProfileClassifiesTheIdentityExtensionsByWhereTheyMayStand(t *testing.T) {
	crypto := testCrypto(t)
	active := defaultProfile()

	// THE GROUP CONTEXT: the profile's own answer
	if err := active.checkGroupExtension(ExtensionTypeUrmessageIdentity); !errors.Is(err, errProfileGroupExtension) {
		t.Errorf("the profile answers %v for urmessage_identity in a group context, want errProfileGroupExtension", err)
	}
	if err := active.checkGroupExtension(ExtensionTypeUrmessageGroupPurpose); err != nil {
		t.Errorf("CONTROL: the profile refuses urmessage_group_purpose in a group context: %v", err)
	}

	// and through a founding and a proposal, the two doors a caller reaches it by
	owner := testIdentity(t, crypto, "owner")
	purpose := Extension{ExtensionType: ExtensionTypeUrmessageGroupPurpose, ExtensionData: []byte("a group purpose body")}
	identity := Extension{ExtensionType: ExtensionTypeUrmessageIdentity, ExtensionData: testIdentityBody("owner")}
	cfg := testGroupConfig(t, crypto, owner, "urmessage-identity-in-a-group-context")
	cfg.Extensions = append(cfg.Extensions, identity)
	if _, err := NewGroup(cfg, owner.SigPriv, BasicCredential(owner.IdentityPub)); !errors.Is(err, errProfileGroupExtension) {
		t.Errorf("a founding whose context carries urmessage_identity answered %v, want errProfileGroupExtension", err)
	}
	cfg = testGroupConfig(t, crypto, owner, "urmessage-group-purpose-in-a-group-context")
	cfg.Extensions = append(cfg.Extensions, purpose)
	group, err := NewGroup(cfg, owner.SigPriv, BasicCredential(owner.IdentityPub))
	if err != nil {
		t.Fatalf("CONTROL: a founding whose context carries urmessage_group_purpose answered %v", err)
	}
	set := append(slices.Clone(testGroupContextOf(t, group).Extensions), identity)
	if _, err := group.ProposeGroupContextExtensions(set); !errors.Is(err, errProfileGroupExtension) {
		t.Errorf("a proposal of a context carrying urmessage_identity answered %v, want errProfileGroupExtension", err)
	}

	// THE LEAF: Validate, and the two constructions whose leaves it judges
	caps := testCapabilitiesListing(ExtensionTypeUrmessageIdentity, ExtensionTypeUrmessageGroupPurpose)
	leafCarrying := func(ext Extension) *LeafNode {
		_, encPub, err := crypto.DeriveKeyPair(crypto.Random(crypto.HashSize()))
		if err != nil {
			t.Fatalf("DeriveKeyPair: %v", err)
		}
		leaf, err := NewLeafNode(crypto, owner.SigPriv, BasicCredential(owner.IdentityPub), encPub, caps,
			[]Extension{testLeafKeys(t, owner), ext})
		if err != nil {
			t.Fatalf("NewLeafNode carrying %#04x: %v", uint16(ext.ExtensionType), err)
		}
		return leaf
	}
	if err := leafCarrying(purpose).Validate(testLeafValidation(crypto)); !errors.Is(err, errProfileLeafExtension) {
		t.Errorf("a leaf carrying urmessage_group_purpose, which it lists, validated as %v, want errProfileLeafExtension", err)
	}
	if err := leafCarrying(identity).Validate(testLeafValidation(crypto)); err != nil {
		t.Errorf("CONTROL: a leaf carrying urmessage_identity, which it lists, did not validate: %v", err)
	}
	// a key package whose leaf carries the group purpose is refused at the Add
	bob := testIdentity(t, crypto, "bob")
	kp, _, _, err := NewKeyPackageWithSigner(crypto, crypto.Suite(), bob.SigPriv, BasicCredential(bob.IdentityPub), caps,
		[]Extension{testLeafKeys(t, bob), purpose})
	if err != nil {
		t.Fatalf("bob's key package carrying urmessage_group_purpose: %v", err)
	}
	encoded, err := syntax.Marshal(kp)
	if err != nil {
		t.Fatalf("encode it: %v", err)
	}
	if _, err := group.ProposeAdd(encoded); !errors.Is(err, errProfileLeafExtension) {
		t.Errorf("an Add of a key package whose leaf carries urmessage_group_purpose answered %v, want errProfileLeafExtension", err)
	}
	// and a founder's leaf asked to carry it is refused before anything is founded
	cfg = testGroupConfig(t, crypto, owner, "urmessage-group-purpose-in-a-founder's-leaf")
	cfg.LeafExtensions = []Extension{purpose}
	if _, err := NewGroup(cfg, owner.SigPriv, BasicCredential(owner.IdentityPub)); !errors.Is(err, errProfileLeafExtension) {
		t.Errorf("a founding whose own leaf carries urmessage_group_purpose answered %v, want errProfileLeafExtension", err)
	}
}

// A GROUP THAT REQUIRES 0xF005 ADMITS NO KEY PACKAGE THAT DOES NOT LIST IT (Property 2's second half).
//
// The requirement is required_capabilities's, which this build already enforces at the Add; what
// is new is that the capability is one EVERY v1 leaf lists, so that the identity layer can require
// it of every member. That is what the control holds: a key package built with this build's own
// capabilities is admitted by the same group, by the same call. Without the listing, a group that
// required the identity extension could admit nobody this build makes.
func TestAGroupRequiringTheIdentityExtensionAdmitsNoKeyPackageWithoutIt(t *testing.T) {
	crypto := testCrypto(t)
	owner := testIdentity(t, crypto, "owner")
	cfg := testGroupConfig(t, crypto, owner, "a-group-requiring-urmessage-identity")
	cfg.RequiredCaps.ExtensionTypes = append(cfg.RequiredCaps.ExtensionTypes, ExtensionTypeUrmessageIdentity)
	group, err := NewGroup(cfg, owner.SigPriv, BasicCredential(owner.IdentityPub))
	if err != nil {
		t.Fatalf("NewGroup requiring urmessage_identity: %v", err)
	}
	if !group.OwnLeafNodeCopy().Capabilities.SupportsExtension(ExtensionTypeUrmessageIdentity) {
		t.Errorf("the founder's own leaf does not list urmessage_identity, so the group it founded requires of every member what its founder does not say of itself")
	}
	keyPackageListing := func(name string, caps Capabilities) []byte {
		m := testIdentity(t, crypto, name)
		kp, _, _, err := NewKeyPackageWithSigner(crypto, crypto.Suite(), m.SigPriv, BasicCredential(m.IdentityPub), caps,
			[]Extension{testLeafKeys(t, m)})
		if err != nil {
			t.Fatalf("%s's key package: %v", name, err)
		}
		encoded, err := syntax.Marshal(kp)
		if err != nil {
			t.Fatalf("encode %s's key package: %v", name, err)
		}
		return encoded
	}
	without := v1Capabilities()
	without.Extensions = slices.DeleteFunc(slices.Clone(without.Extensions), func(listed ExtensionType) bool {
		return listed == ExtensionTypeUrmessageIdentity
	})
	if _, err := group.ProposeAdd(keyPackageListing("dave", without)); !errors.Is(err, ErrAddMissingRequiredCapability) ||
		!strings.Contains(err.Error(), "extension type 0xf005") {
		t.Errorf("an Add of a key package that lists everything but urmessage_identity answered %v, want ErrAddMissingRequiredCapability naming 0xf005", err)
	}
	if _, err := group.PendingEpoch(); !errors.Is(err, ErrNoPendingCommit) {
		t.Errorf("the refused Add left something staged: %v", err)
	}

	// THE CONTROL: this build's own capabilities, admitted by the same group through the same call
	if _, err := group.ProposeAdd(keyPackageListing("erin", v1Capabilities())); err != nil {
		t.Fatalf("CONTROL FAILED: an Add of a key package with this build's own capabilities answered %v", err)
	}
	if _, err := group.CreateCommit(nil, nil, nil); err != nil {
		t.Fatalf("CONTROL FAILED: the commit adding it answered %v", err)
	}
	group.ClearPendingCommit()
}

// AN OWN-LEAF PATCH IS COVERED BY THE LEAF'S SIGNATURE AND BY THE TREE HASH, AND IS REFUSED WITHOUT A
// PATH (Property 3).
//
// The patch is how a committer changes what its own leaf says -- its credential, and the body of an
// extension it carries -- in the one leaf it may write, its path leaf. So it is applied before that
// leaf is signed and before the tree is hashed, and a receiver holds both: the receiver validates
// the leaf, which verifies the signature over the patched octets, and arrives at the committer's
// epoch, whose secret is expanded over a group context carrying the tree hash. A patch made after
// either is a commit no receiver takes.
//
// A commit with no path makes no leaf of its own, so there is nothing for a patch to be applied to:
// it is refused, with nothing staged, rather than dropped in silence.
func TestAnOwnLeafPatchIsSignedAndTreeHashedAndNeedsAPath(t *testing.T) {
	crypto := testCrypto(t)
	caps := testCapabilitiesListing(ExtensionTypeUrmessageIdentity)
	withIdentity := func(m *testMember) []Extension {
		return []Extension{testLeafKeys(t, m), {ExtensionType: ExtensionTypeUrmessageIdentity, ExtensionData: testIdentityBody(m.Name)}}
	}
	group, joined, bob := testJoinedPair(t, crypto, "an-own-leaf-patch-is-signed-and-tree-hashed", caps, withIdentity)

	// REFUSED WITHOUT A PATH: an Add-only commit carries none unless forced
	carol := testIdentity(t, crypto, "carol")
	carolPackage, _, _ := testKeyPackage(t, crypto, carol)
	add := Proposal{ProposalType: ProposalTypeAdd, Add: &Add{KeyPackage: *carolPackage}}
	patch := &OwnLeafPatch{Extensions: []Extension{{ExtensionType: ExtensionTypeUrmessageIdentity, ExtensionData: []byte("a second body")}}}
	if _, err := joined.CreateCommit([][]byte{}, []Proposal{add}, &CommitOptions{OwnLeafPatch: patch}); !errors.Is(err, errOwnLeafPatchWithoutPath) {
		t.Errorf("an own-leaf patch on an Add-only commit with no path answered %v, want errOwnLeafPatchWithoutPath", err)
	}
	if _, err := joined.PendingEpoch(); !errors.Is(err, ErrNoPendingCommit) {
		t.Errorf("the refused patch left a commit staged: %v", err)
	}

	// THE PATCH: a new credential and a new identity body, in bob's path leaf
	newIdentity := []byte("the identity bob's patch moves his leaf to")
	newBody := []byte("the identity extension body bob's patch writes")
	patch = &OwnLeafPatch{
		Credential: &Credential{CredentialType: CredentialTypeBasic, Identity: bytes.Clone(newIdentity)},
		Extensions: []Extension{{ExtensionType: ExtensionTypeUrmessageIdentity, ExtensionData: bytes.Clone(newBody)}},
	}
	result, err := joined.CreateCommit(nil, nil, &CommitOptions{Force: true, OwnLeafPatch: patch})
	if err != nil {
		t.Fatalf("bob's commit with an own-leaf patch: %v", err)
	}
	if err := joined.MergePendingCommit(); err != nil {
		t.Fatalf("bob's merge: %v", err)
	}
	// the receiver takes it, and so holds the patched octets under the leaf's signature and the tree hash
	testFollow(t, group, joined, result.Commit)
	patched := group.tree.Leaf(joined.OwnLeafIndex())
	want := testExtensionsString([]Extension{testLeafKeys(t, bob), {ExtensionType: ExtensionTypeUrmessageIdentity, ExtensionData: newBody}})
	if got := testExtensionsString(patched.Extensions); got != want {
		t.Errorf("the owner holds bob's patched leaf with %s, want %s: the patch replaces the entry of its type in place", got, want)
	}
	if !bytes.Equal(patched.Credential.Identity, newIdentity) {
		t.Errorf("the owner holds bob's patched leaf naming %x, want the patch's %x", patched.Credential.Identity, newIdentity)
	}
	context := testGroupContextOf(t, group)
	if err := patched.Validate(&LeafValidationContext{
		Crypto:          crypto,
		Suite:           context.CipherSuite,
		GroupId:         context.GroupId,
		LeafIndex:       joined.OwnLeafIndex(),
		ExpectedSource:  LeafNodeSourceCommit,
		GroupExtensions: context.Extensions,
		NowMs:           uint64(time.Now().UnixMilli()),
	}); err != nil {
		t.Errorf("bob's patched leaf, as the owner holds it, does not validate: %v", err)
	}
}

// AN UPDATE AFTER AN OWN-LEAF PATCH KEEPS THE PATCHED CREDENTIAL.
//
// The patch changes the credential in the member's own leaf, and a member also names itself with
// a credential of its own, which every leaf it makes afterwards is signed over: (*Group).
// ProposeUpdate builds its leaf on it. So MergePendingCommit has the member's own credential follow
// its own leaf, as LoadGroup already reads it there. Without that the member goes on naming itself
// with the credential it was founded or joined with, and its next Update puts that one back in
// every member's tree -- which is a phrase change (identity phase 1's Task 42) undone by the first
// Update after it.
//
// The leaf is read where a member reads it, in each member's own tree at the patched member's
// index, after the Update has been committed and followed; and the group's own credential is read
// too, which is the value the next leaf it makes is signed over.
func TestAnUpdateAfterAnOwnLeafPatchKeepsThePatchedCredential(t *testing.T) {
	crypto := testCrypto(t)
	caps := testCapabilitiesListing(ExtensionTypeUrmessageIdentity)
	withIdentity := func(m *testMember) []Extension {
		return []Extension{testLeafKeys(t, m), {ExtensionType: ExtensionTypeUrmessageIdentity, ExtensionData: testIdentityBody(m.Name)}}
	}
	group, joined, bob := testJoinedPair(t, crypto, "an-update-after-an-own-leaf-patch", caps, withIdentity)
	members := map[string]*Group{"the owner": group, "bob": joined}

	// THE PATCH: a new credential, in a commit with a path, merged and followed
	newIdentity := []byte("the identity bob's patch moves his leaf to, and his Update keeps")
	patch := &OwnLeafPatch{Credential: &Credential{CredentialType: CredentialTypeBasic, Identity: bytes.Clone(newIdentity)}}
	result, err := joined.CreateCommit(nil, nil, &CommitOptions{Force: true, OwnLeafPatch: patch})
	if err != nil {
		t.Fatalf("bob's commit with an own-leaf patch: %v", err)
	}
	if err := joined.MergePendingCommit(); err != nil {
		t.Fatalf("bob's merge: %v", err)
	}
	testFollow(t, group, joined, result.Commit)
	for name, member := range members {
		if got := member.tree.Leaf(joined.OwnLeafIndex()).Credential.Identity; !bytes.Equal(got, newIdentity) {
			t.Fatalf("after the patch %s's tree holds bob's leaf naming %x, want the patch's %x, so the case below would observe nothing", name, got, newIdentity)
		}
	}

	// THEN AN UPDATE: bob proposes it, the owner commits it, and both follow
	proposal, err := joined.ProposeUpdate()
	if err != nil {
		t.Fatalf("bob's ProposeUpdate after the patch: %v", err)
	}
	if _, err := group.ProcessMessage(proposal); err != nil {
		t.Fatalf("the owner's ProcessMessage over bob's Update: %v", err)
	}
	result, err = group.CreateCommit(nil, nil, nil)
	if err != nil {
		t.Fatalf("the owner's commit over bob's Update: %v", err)
	}
	if err := group.MergePendingCommit(); err != nil {
		t.Fatalf("the owner's merge: %v", err)
	}
	testFollow(t, joined, group, result.Commit)

	// EVERY MEMBER'S TREE HOLDS THE PATCHED CREDENTIAL AT BOB'S LEAF, and his own credential is it
	updated := group.tree.Leaf(joined.OwnLeafIndex())
	if updated.LeafNodeSource != LeafNodeSourceUpdate {
		t.Fatalf("bob's leaf after the owner's commit has source %d, not update, so it is not his Update's leaf", updated.LeafNodeSource)
	}
	for name, member := range members {
		if got := member.tree.Leaf(joined.OwnLeafIndex()).Credential.Identity; !bytes.Equal(got, newIdentity) {
			t.Errorf("after bob's Update %s's tree holds his leaf naming %x, want the patched %x: the Update put the old credential back",
				name, got, newIdentity)
		}
	}
	if !bytes.Equal(joined.cred.Identity, newIdentity) {
		t.Errorf("bob names himself %x after the patch and the Update, want the patched %x: the next leaf he makes is signed over the old credential",
			joined.cred.Identity, newIdentity)
	}
	if bytes.Equal(newIdentity, bob.IdentityPub) {
		t.Fatal("the patched identity is bob's original one, so this case cannot tell a kept credential from a restored one")
	}
}
