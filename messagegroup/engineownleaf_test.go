package messagegroup

import (
	"bytes"
	"errors"
	"slices"
	"testing"

	"github.com/urnetwork/message/mls"
)

// THE OWN-LEAF COMMIT, AND THE STAGED TREE'S LEAVES AS THE BINDING RULES READ THEM (Spec A A-36,
// section 6; identity phase 1's Task 13). CommitOwnLeaf builds a commit with a path that removes the
// leaves it names and patches the committer's own path leaf: its extensions set by type, its credential
// when one is named. A receiver's Process answers, for every leaf of the staged tree, the signature key
// and the extensions the binding rules read, as copies, before anything is applied; and what it applies
// is what it read.
//
// THE CONTROL: before the patch, the founder's leaf carries no entry of the patch's type, so the entry
// the receiver reads after it can only have come from the patch.
func TestCommitOwnLeafPatchesThePathLeafAndTheStagedTreeCarriesIt(t *testing.T) {
	chain := newCommitAddChain(t, "own-leaf-patch")
	founderLeaf, joinerLeaf := chain.founded.OwnLeafIndex(), chain.joined.OwnLeafIndex()

	// A THIRD MEMBER, by an Add every member follows; the Add's staged tree names its key and its leaf's
	// extensions at the leaf it lands on
	third := newTestEngine(t)
	thirdPackage, err := third.engine.NewKeyPackage()
	if err != nil {
		t.Fatalf("the third's key package: %v", err)
	}
	commit, welcome, ratchetTree, err := chain.founded.CommitAdd([][]byte{thirdPackage})
	if err != nil {
		t.Fatalf("CommitAdd of the third: %v", err)
	}
	added, err := chain.joined.Process(commit)
	if err != nil {
		t.Fatalf("the joiner's Process of the Add: %v", err)
	}
	if len(added.AddedLeaves) != 1 {
		t.Fatalf("the Add landed %v, want one leaf", added.AddedLeaves)
	}
	thirdLeaf := added.AddedLeaves[0]
	if at := memberAtLeaf(t, "the Add", added.MembersAfter, thirdLeaf); !bytes.Equal(at.SignatureKey, third.signerPub) ||
		len(at.Extensions) != 1 || at.Extensions[0].Type != uint16(mls.ExtensionTypeUrmessageLeafKeys) {
		t.Fatalf("the Add's staged tree names key %x and extensions %v at the added leaf, want the third's %x and its leaf keys",
			at.SignatureKey, at.Extensions, third.signerPub)
	}
	if err := chain.joined.ApplyCommit(added); err != nil {
		t.Fatalf("the joiner's ApplyCommit of the Add: %v", err)
	}
	if err := chain.founded.MergePendingCommit(); err != nil {
		t.Fatalf("the founder's MergePendingCommit of the Add: %v", err)
	}
	thirdJoined, err := third.engine.JoinFromWelcome(welcome, ratchetTree)
	if err != nil {
		t.Fatalf("the third's JoinFromWelcome: %v", err)
	}
	t.Cleanup(func() { thirdJoined.Close() })

	// THE CONTROL: the founder's leaf carries no entry of the patch's type yet
	identityType := uint16(mls.ExtensionTypeUrmessageIdentity)
	before, err := chain.joined.LeafAt(founderLeaf)
	if err != nil {
		t.Fatalf("LeafAt(the founder), before: %v", err)
	}
	if slices.ContainsFunc(before.Extensions, func(entry ExtensionBytes) bool { return entry.Type == identityType }) {
		t.Fatalf("CONTROL FAILED: the founder's leaf already carries %#04x, so the patch's entry could not be told from it", identityType)
	}

	// (1) THE PATCH, WITH A REMOVAL IN THE SAME COMMIT
	first := []byte("the founder's next list, as a patch carries it")
	patch := OwnLeafPatch{Extensions: []ExtensionBytes{{Type: identityType, Data: bytes.Clone(first)}}}
	commit, _, _, err = chain.founded.CommitOwnLeaf(patch, []uint32{thirdLeaf}, nil)
	if err != nil {
		t.Fatalf("CommitOwnLeaf with a removal: %v", err)
	}
	// the patch's octets are the seam's own once the call has answered
	patch.Extensions[0].Data[0] ^= 0xFF
	processed, err := chain.joined.Process(commit)
	if err != nil {
		t.Fatalf("the joiner's Process of the own-leaf commit: %v", err)
	}
	if processed.CommitterLeaf != founderLeaf || !slices.Equal(processed.RemovedLeaves, []uint32{thirdLeaf}) {
		t.Fatalf("the commit is by leaf %d and removes %v, want the founder's %d and the third's %d",
			processed.CommitterLeaf, processed.RemovedLeaves, founderLeaf, thirdLeaf)
	}
	for _, member := range processed.MembersAfter {
		if member.Leaf == thirdLeaf {
			t.Fatalf("the staged tree still holds the removed leaf %d", thirdLeaf)
		}
	}
	committer := memberAtLeaf(t, "the own-leaf commit", processed.MembersAfter, founderLeaf)
	if !bytes.Equal(committer.SignatureKey, chain.founder.signerPub) {
		t.Fatalf("the committer's post-commit leaf names key %x, want the founder's %x: a path keeps the signature key",
			committer.SignatureKey, chain.founder.signerPub)
	}
	if _, body, _ := findExtensionBytesOf(committer.Extensions, identityType); !bytes.Equal(body, first) {
		t.Fatalf("the committer's post-commit leaf carries %#04x %q, want the patch's %q", identityType, body, first)
	}
	if committer.Extensions[0].Type != uint16(mls.ExtensionTypeUrmessageLeafKeys) {
		t.Fatalf("the patched leaf's extensions begin %#04x, want the leaf keys it carried, where they stood", committer.Extensions[0].Type)
	}
	joiner := memberAtLeaf(t, "the own-leaf commit", processed.MembersAfter, joinerLeaf)
	if !bytes.Equal(joiner.SignatureKey, chain.joiner.signerPub) || len(joiner.Extensions) != 1 {
		t.Fatalf("the joiner's own leaf reads key %x and %d extension(s) in the staged tree, want its own key and its leaf keys alone",
			joiner.SignatureKey, len(joiner.Extensions))
	}
	// THE TWO FIELDS ARE COPIES: writing into them moves nothing the receiver then applies
	committer.SignatureKey[0] ^= 0xFF
	committer.Extensions[len(committer.Extensions)-1].Data[0] ^= 0xFF
	if err := chain.joined.ApplyCommit(processed); err != nil {
		t.Fatalf("the joiner's ApplyCommit of the own-leaf commit: %v", err)
	}
	if err := chain.founded.MergePendingCommit(); err != nil {
		t.Fatalf("the founder's MergePendingCommit of the own-leaf commit: %v", err)
	}
	for name, handle := range map[string]GroupHandle{"the joiner": chain.joined, "the founder": chain.founded} {
		leaf, err := handle.LeafAt(founderLeaf)
		if err != nil {
			t.Fatalf("%s's LeafAt(the founder): %v", name, err)
		}
		if _, body, _ := findExtensionBytesOf(leaf.Extensions, identityType); !bytes.Equal(body, first) ||
			!bytes.Equal(leaf.SignatureKey, chain.founder.signerPub) {
			t.Errorf("%s holds the founder's leaf with %#04x %q and key %x after the commit, want the patch's %q and the founder's key",
				name, identityType, body, leaf.SignatureKey, first)
		}
	}
	assertSameEpochSecret(t, 3, map[string]GroupHandle{"the founder": chain.founded, "the joiner": chain.joined})

	// (2) SET BY TYPE: a second patch of the same type replaces the entry where it stands
	second := []byte("the founder's list after that")
	commit, _, _, err = chain.founded.CommitOwnLeaf(OwnLeafPatch{Extensions: []ExtensionBytes{{Type: identityType, Data: second}}}, nil, nil)
	if err != nil {
		t.Fatalf("CommitOwnLeaf, the second patch: %v", err)
	}
	processed, err = chain.joined.Process(commit)
	if err != nil {
		t.Fatalf("the joiner's Process of the second patch: %v", err)
	}
	committer = memberAtLeaf(t, "the second patch", processed.MembersAfter, founderLeaf)
	carried := 0
	for _, entry := range committer.Extensions {
		if entry.Type == identityType {
			carried += 1
			if !bytes.Equal(entry.Data, second) {
				t.Errorf("the second patch's leaf carries %#04x %q, want %q", identityType, entry.Data, second)
			}
		}
	}
	if carried != 1 || len(committer.Extensions) != 2 {
		t.Errorf("the second patch's leaf carries %d entries of %#04x among %d, want one, in place", carried, identityType, len(committer.Extensions))
	}
	if err := chain.joined.ApplyCommit(processed); err != nil {
		t.Fatalf("the joiner's ApplyCommit of the second patch: %v", err)
	}
	if err := chain.founded.MergePendingCommit(); err != nil {
		t.Fatalf("the founder's MergePendingCommit of the second patch: %v", err)
	}

	// (3) THE CREDENTIAL: a patch naming one replaces the leaf's, and the staged tree says so
	renamed := []byte("a credential the founder's path leaf names after its patch")
	commit, _, _, err = chain.founded.CommitOwnLeaf(OwnLeafPatch{Credential: renamed}, nil, nil)
	if err != nil {
		t.Fatalf("CommitOwnLeaf, the credential: %v", err)
	}
	processed, err = chain.joined.Process(commit)
	if err != nil {
		t.Fatalf("the joiner's Process of the credential patch: %v", err)
	}
	if at := memberAtLeaf(t, "the credential patch", processed.MembersAfter, founderLeaf); !bytes.Equal(at.Identity, renamed) ||
		!bytes.Equal(at.SignatureKey, chain.founder.signerPub) {
		t.Errorf("the credential patch's leaf names %q under key %x, want %q under the founder's key", at.Identity, at.SignatureKey, renamed)
	}
	if err := chain.joined.DiscardProcessed(processed); err != nil {
		t.Fatalf("DiscardProcessed: %v", err)
	}
	chain.founded.ClearPendingCommit()

	// (4) THE CONTEXT: an empty list that is not nil is refused, and stages nothing
	if _, _, _, err := chain.founded.CommitOwnLeaf(OwnLeafPatch{}, nil, []ExtensionBytes{}); !errors.Is(err, ErrEngineCommitContextExtensionsEmpty) {
		t.Fatalf("CommitOwnLeaf over an empty context list answered %v, want ErrEngineCommitContextExtensionsEmpty", err)
	}
	if _, err := chain.founded.PendingEpoch(); err == nil {
		t.Fatal("the refused own-leaf commit left a staged epoch behind")
	}
}

// findExtensionBytesOf answers the one entry of a type in a list as the seam spells it, and whether
// the list carries it.
func findExtensionBytesOf(extensions []ExtensionBytes, extensionType uint16) (int, []byte, bool) {
	for at, entry := range extensions {
		if entry.Type == extensionType {
			return at, entry.Data, true
		}
	}
	return -1, nil, false
}
