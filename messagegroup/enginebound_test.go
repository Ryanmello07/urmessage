package messagegroup

import (
	"bytes"
	"errors"
	"slices"
	"testing"

	"github.com/urnetwork/message/mls"
	"github.com/urnetwork/message/syntax"
)

// THE BOUND DOORS (Spec A A-36, section 6; identity phase 1's Task 12; LRI R64). NewBoundKeyPackage's
// leaf carries urmessage_leaf_keys and then exactly the extensions it is handed, in order, where
// NewKeyPackage's carries the first alone. CreateBoundGroup founds a group whose founder's leaf
// carries the same, whose context carries what it is handed beside 0x0003 and 0xF001, and which
// requires 0xF004 and 0xF005 of every member, and 0xF006 as well when its context carries it.
// LeafAt reads a leaf off the current tree, as the binding rules read it, and answers a copy.
//
// AND EVERY LEAF THIS ENGINE MAKES LISTS 0xF005 AND 0xF006 (LRI R68, the review's L3-8), which a
// bound key package needs before it is made: a group requiring 0xF005 admits this engine's own key
// packages, and refuses one listing everything else.
func TestTheBoundDoorsCarryTheIdentityLayersExtensionsAndRequireThem(t *testing.T) {
	founder := newTestEngine(t)
	joiner := newTestEngine(t)
	identity := ExtensionBytes{Type: uint16(mls.ExtensionTypeUrmessageIdentity), Data: []byte("the identity extension body this founder's leaf carries")}
	purpose, err := (&GroupPurpose{Purpose: 1, IdentityRoot: bytes.Repeat([]byte{0x2a}, 32)}).Encode()
	if err != nil {
		t.Fatalf("encode 0xF006: %v", err)
	}

	// THE KEY PACKAGES: the bound one carries the identity extension after the leaf keys, in order,
	// and the unbound one carries the leaf keys alone; both list 0xF005 and 0xF006
	bound, err := joiner.engine.NewBoundKeyPackage([]ExtensionBytes{identity})
	if err != nil {
		t.Fatalf("NewBoundKeyPackage: %v", err)
	}
	unbound, err := joiner.engine.NewKeyPackage()
	if err != nil {
		t.Fatalf("NewKeyPackage: %v", err)
	}
	for _, one := range []struct {
		name  string
		octet []byte
		want  []uint16
	}{
		{"the bound key package", bound, []uint16{uint16(mls.ExtensionTypeUrmessageLeafKeys), identity.Type}},
		{"the unbound key package", unbound, []uint16{uint16(mls.ExtensionTypeUrmessageLeafKeys)}},
	} {
		keyPackage := &mls.KeyPackage{}
		if err := syntax.Unmarshal(one.octet, keyPackage); err != nil {
			t.Fatalf("decode %s: %v", one.name, err)
		}
		got := []uint16{}
		for _, extension := range keyPackage.LeafNode.Extensions {
			got = append(got, uint16(extension.ExtensionType))
		}
		if !slices.Equal(got, one.want) {
			t.Errorf("%s's leaf carries %#04x, want %#04x", one.name, got, one.want)
		}
		for _, listed := range []mls.ExtensionType{mls.ExtensionTypeUrmessageIdentity, mls.ExtensionTypeUrmessageGroupPurpose} {
			if !slices.Contains(keyPackage.LeafNode.Capabilities.Extensions, listed) {
				t.Errorf("%s's leaf does not list %#04x in its capabilities", one.name, uint16(listed))
			}
		}
		if one.name == "the bound key package" {
			if _, entry, _ := findExtensionBytes(keyPackage.LeafNode.Extensions, identity.Type); !bytes.Equal(entry, identity.Data) {
				t.Errorf("the bound key package's identity extension is %q, want the body it was handed", entry)
			}
		}
	}

	policy := testOwnerPolicy(t, founder.identityPub)
	conversation, err := founder.engine.CreateBoundGroup(testGroupId("a-bound-conversation"), policy, founder.leafKeys,
		[]ExtensionBytes{identity}, nil)
	if err != nil {
		t.Fatalf("CreateBoundGroup, a conversation: %v", err)
	}
	t.Cleanup(func() { conversation.Close() })
	system, err := founder.engine.CreateBoundGroup(testGroupId("a-bound-system-group"), policy, founder.leafKeys,
		[]ExtensionBytes{identity}, []ExtensionBytes{purpose})
	if err != nil {
		t.Fatalf("CreateBoundGroup, a system group: %v", err)
	}
	t.Cleanup(func() { system.Close() })

	// THE REQUIREMENTS, read off each group's own context
	conversationRequires, conversationExtensions := testRequiredOf(t, conversation)
	systemRequires, systemExtensions := testRequiredOf(t, system)
	conversationWant := []mls.ExtensionType{mls.ExtensionTypeUrmessageGroupPolicy, mls.ExtensionTypeUrmessageLeafKeys,
		mls.ExtensionTypeUrmessageJoinSeal, mls.ExtensionTypeUrmessageIdentity}
	if !slices.Equal(conversationRequires, conversationWant) {
		t.Errorf("a conversation requires %#04x, want section 3.4's %#04x", conversationRequires, conversationWant)
	}
	if want := append(slices.Clone(conversationWant), mls.ExtensionTypeUrmessageGroupPurpose); !slices.Equal(systemRequires, want) {
		t.Errorf("a system group requires %#04x, want section 3.4's %#04x", systemRequires, want)
	}
	if _, found, _ := mls.FindExtension(conversationExtensions, mls.ExtensionTypeUrmessageGroupPurpose); found {
		t.Error("a conversation's context carries 0xF006")
	}
	if body, found, _ := mls.FindExtension(systemExtensions, mls.ExtensionTypeUrmessageGroupPurpose); !found || !bytes.Equal(body, purpose.Data) {
		t.Errorf("the system group's context carries 0xF006 %q (found %v), want the body it was handed", body, found)
	}

	// THE FOUNDER'S LEAF, through LeafAt: the engine's credential, its signer, and the extensions in order
	leaf, err := conversation.LeafAt(conversation.OwnLeafIndex())
	if err != nil {
		t.Fatalf("LeafAt(the founder): %v", err)
	}
	if !bytes.Equal(leaf.Credential, founder.identityPub) || !bytes.Equal(leaf.SignatureKey, founder.signerPub) {
		t.Errorf("LeafAt answers credential %x and key %x, want the engine's %x and %x", leaf.Credential, leaf.SignatureKey,
			founder.identityPub, founder.signerPub)
	}
	if got := []uint16{leaf.Extensions[0].Type, leaf.Extensions[len(leaf.Extensions)-1].Type}; len(leaf.Extensions) != 2 ||
		got[0] != uint16(mls.ExtensionTypeUrmessageLeafKeys) || got[1] != identity.Type || !bytes.Equal(leaf.Extensions[1].Data, identity.Data) {
		t.Errorf("the founder's leaf carries %v, want the leaf keys and then the identity extension it was founded with", leaf.Extensions)
	}
	leaf.SignatureKey[0] ^= 0xFF
	leaf.Extensions[1].Data[0] ^= 0xFF
	if again, _ := conversation.LeafAt(conversation.OwnLeafIndex()); !bytes.Equal(again.SignatureKey, founder.signerPub) || !bytes.Equal(again.Extensions[1].Data, identity.Data) {
		t.Error("writing into LeafAt's answer moved the tree")
	}
	if _, err := conversation.LeafAt(9); !errors.Is(err, ErrEngineMemberLeaf) {
		t.Errorf("LeafAt at a leaf no member stands at answered %v, want ErrEngineMemberLeaf", err)
	}

	// THE ADMISSION: the joiner's bound key package is admitted by both groups, and a key package
	// listing everything but 0xF005 by neither -- the requirement, measured
	for _, group := range []GroupHandle{conversation, system} {
		if _, _, _, err := group.CommitAdd([][]byte{bound}); err != nil {
			t.Errorf("a bound group refuses this engine's own bound key package: %v", err)
		}
		group.ClearPendingCommit()
		withoutIdentity := testKeyPackageListing(t, joiner, slices.DeleteFunc(slices.Clone(engineCapabilities().Extensions),
			func(extension mls.ExtensionType) bool { return extension == mls.ExtensionTypeUrmessageIdentity }))
		if _, _, _, err := group.CommitAdd([][]byte{withoutIdentity}); err == nil {
			t.Error("a bound group admits a key package that does not list 0xF005")
			group.ClearPendingCommit()
		}
	}
}

// testOwnerPolicy is a group policy naming one owner, encoded, as the founding helpers make it.
func testOwnerPolicy(t *testing.T, owner []byte) []byte {
	t.Helper()
	policy := &mls.GroupPolicyExtension{Roles: []mls.RoleEntry{{MemberId: owner, Role: mls.RoleOwner}}}
	if err := policy.Canonicalize(); err != nil {
		t.Fatalf("canonicalize the policy: %v", err)
	}
	encoded, err := policy.Encode()
	if err != nil {
		t.Fatalf("encode the policy: %v", err)
	}
	return encoded.ExtensionData
}

// testRequiredOf is a founded group's required_capabilities and its context's extensions, read off
// its own context.
func testRequiredOf(t *testing.T, group GroupHandle) ([]mls.ExtensionType, []mls.Extension) {
	t.Helper()
	contextBytes, err := group.GroupContextBytes()
	if err != nil {
		t.Fatalf("GroupContextBytes: %v", err)
	}
	context := &mls.GroupContext{}
	if err := syntax.Unmarshal(contextBytes, context); err != nil {
		t.Fatalf("decode the context: %v", err)
	}
	body, found, err := mls.FindExtension(context.Extensions, mls.ExtensionTypeRequiredCapabilities)
	if err != nil || !found {
		t.Fatalf("the context carries no required_capabilities (%v, %v)", found, err)
	}
	required := mls.RequiredCapabilities{}
	if err := syntax.Unmarshal(body, &required); err != nil {
		t.Fatalf("decode required_capabilities: %v", err)
	}
	return required.ExtensionTypes, context.Extensions
}

// testKeyPackageListing is a key package of the engine's own signer and leaf keys whose leaf lists
// exactly the extension types it is handed.
func testKeyPackageListing(t *testing.T, engine *testEngine, extensions []mls.ExtensionType) []byte {
	t.Helper()
	leafKeys, err := mls.ParseLeafKeysExtension(engine.leafKeys)
	if err != nil {
		t.Fatalf("the device's leaf keys body: %v", err)
	}
	leafKeysExtension, err := leafKeys.Encode()
	if err != nil {
		t.Fatalf("the leaf keys extension: %v", err)
	}
	capabilities := engineCapabilities()
	capabilities.Extensions = extensions
	keyPackage, initPrivate, encryptPrivate, err := mls.NewKeyPackageWithSigner(engine.crypto,
		engine.crypto.Suite(), engine.signer, mls.BasicCredential(engine.identityPub),
		capabilities, []mls.Extension{leafKeysExtension})
	if err != nil {
		t.Fatalf("a key package listing %v: %v", extensions, err)
	}
	defer keyPackage.Zeroize()
	defer zeroize(initPrivate)
	defer zeroize(encryptPrivate)
	encoded, err := syntax.Marshal(keyPackage)
	if err != nil {
		t.Fatalf("encode it: %v", err)
	}
	return encoded
}

// findExtensionBytes is mls.FindExtensionEntry over a leaf's extensions, answering the body.
func findExtensionBytes(extensions []mls.Extension, extensionType uint16) (bool, []byte, error) {
	entry, found, err := mls.FindExtensionEntry(extensions, mls.ExtensionType(extensionType))
	return found, entry.ExtensionData, err
}
