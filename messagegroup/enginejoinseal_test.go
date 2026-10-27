package messagegroup

import (
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/message/mls"
	"github.com/urnetwork/message/syntax"
)

// EVERY GROUP THIS ENGINE FOUNDS REQUIRES THE JOIN SEAL, AND ADMITS NO KEY PACKAGE WITHOUT IT. The
// capability is two things and both are held here: a leaf that lists it, which says its device
// opens a sealed invite, and a group that REQUIRES it, which is what makes connect/mls itself
// refuse a join code from a build that cannot. Only the first is visible in a join that works, so
// a founder that stopped requiring it would pass every suite that only joins.
//
// THE REQUIREMENT IS READ OFF THE GROUP'S OWN CONTEXT, and the refusal is driven with a real key
// package of a real device signer that carries its leaf keys and lists everything but 0xF004, so
// the only thing mls can refuse it for is the capability. THE CONTROL is the same construction
// with the capability listed, admitted by the same call.
//
// WHAT WOULD GO RED: take 0xF004 out of engineRequiredCapabilities and both halves fail; take it
// out of engineCapabilities alone and the control fails, because this engine's own key packages
// would no longer be admitted to its own groups.
func TestAFoundedGroupRequiresTheJoinSealAndAdmitsNoKeyPackageWithoutIt(t *testing.T) {
	chain := newCommitAddChain(t, "the-join-seal-is-required")
	contextBytes, err := chain.founded.GroupContextBytes()
	if err != nil {
		t.Fatalf("GroupContextBytes: %v", err)
	}
	context := &mls.GroupContext{}
	if err := syntax.Unmarshal(contextBytes, context); err != nil {
		t.Fatalf("decoding the founded group's context: %v", err)
	}
	body, found, err := mls.FindExtension(context.Extensions, mls.ExtensionTypeRequiredCapabilities)
	if err != nil || !found {
		t.Fatalf("the founded group's context carries no required_capabilities (found %v, %v), so it requires nothing of a joiner", found, err)
	}
	required := mls.RequiredCapabilities{}
	if err := syntax.Unmarshal(body, &required); err != nil {
		t.Fatalf("decoding required_capabilities: %v", err)
	}
	if !slices.Contains(required.ExtensionTypes, mls.ExtensionTypeUrmessageJoinSeal) {
		t.Fatalf("a group this engine founded requires %v of a joiner, and the join seal capability %#04x is not among them",
			required.ExtensionTypes, uint16(mls.ExtensionTypeUrmessageJoinSeal))
	}

	third := newTestEngine(t)
	listing := func(extensions []mls.ExtensionType) []byte {
		leafKeys, err := mls.ParseLeafKeysExtension(third.leafKeys)
		if err != nil {
			t.Fatalf("the device's leaf keys body: %v", err)
		}
		leafKeysExtension, err := leafKeys.Encode()
		if err != nil {
			t.Fatalf("the leaf keys extension: %v", err)
		}
		capabilities := engineCapabilities()
		capabilities.Extensions = extensions
		keyPackage, initPrivate, encryptPrivate, err := mls.NewKeyPackageWithSigner(third.crypto,
			third.crypto.Suite(), third.signer, mls.BasicCredential(third.identityPub),
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
	// the engine's own listing less the join seal, and then the engine's own listing: every other type
	// a founded group requires is listed by both (urmessage_identity among them since identity phase
	// 1's Task 12), so the one difference between the refusal and the control is the join seal's
	listed := engineCapabilities().Extensions
	without := listing(slices.DeleteFunc(slices.Clone(listed), func(extension mls.ExtensionType) bool {
		return extension == mls.ExtensionTypeUrmessageJoinSeal
	}))
	_, _, _, err = chain.founded.CommitAdd([][]byte{without})
	if err == nil {
		t.Fatalf("a key package that does not list the join seal capability was admitted to a group that requires it")
	}
	if !strings.Contains(err.Error(), "required capability: extension type 0xf004") {
		t.Errorf("the refusal does not name the capability it was made for: %v", err)
	}
	if _, pendingErr := chain.founded.PendingEpoch(); pendingErr == nil {
		t.Fatalf("the refused add left a commit staged on the founder")
	}

	// THE CONTROL: the same key package with the capability listed is admitted by the same call.
	with := listing(listed)
	if _, _, _, err := chain.founded.CommitAdd([][]byte{with}); err != nil {
		t.Fatalf("CONTROL FAILED: the same key package listing the capability answered %v", err)
	}
	chain.founded.ClearPendingCommit()
}
