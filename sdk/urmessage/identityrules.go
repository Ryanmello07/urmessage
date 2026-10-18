package urmessage

import (
	"bytes"
	"fmt"
	"slices"

	"github.com/urnetwork/message/messagegroup"
	"github.com/urnetwork/message/mls"
)

// THE IDENTITY LAYER'S BINDING RULES (identity phase 1's Task 13; MASTER §11 at Revision 10; Spec A
// A-36). Every commit is judged by them, in one mode, on the sending side over the would-be tree as
// on every receiving side, so no device publishes a commit its own rules refuse. They run inside
// [authorizeCommit], after R6c and before R1, in F1's order less its legacy and succession steps
// (R9 runs where F1 runs it, after R7); the first refusal is the answer, and each names its own:
//
//	R6e      every leaf a commit adds or updates, and the committer's own post-commit leaf, carries
//	         a 0xF005 that verifies; a profile-1 leaf, which carries none, stands only in a link
//	         group ([ErrCommitIdentityUnbound])
//	R6c-sig  every leaf that survives a commit, the committer's included, keeps its signature key
//	         ([ErrCommitSignatureKeyChanged])
//	R8-EQ    two lists of one identity in the post-commit tree do not fork: two lists at one
//	         version are byte-identical ([ErrDeviceListEquivocation])
//	R8-CUR   a leaf the newest list in the tree does not name is removed in the commit that brings
//	         that list, or the commit is refused; the leaves a commit adds or updates, and the
//	         committer's, are current ([ErrDeviceNotCurrent])
//	R9       a self group admits leaves of its own identity only; a link group holds at most one
//	         leaf of each profile, only its identity's leaf commits, and it takes no commit at
//	         epoch 1 or above ([ErrSystemGroupViolation])
//
// VALIDITY READS ONLY THE TREES. Every rule reads the two trees the value carries and nothing a
// device holds of its own, so two members whose local heads differ decide every commit alike; the
// local heads drive the doors (heads.go), never validity (F1:337).

// leafBound is one leaf as the binding rules read it: the 0xF005 it carries, verified, or the
// reason it does not verify. A profile-1 leaf -- F1's shape, a credential that is the leaf's own
// signature key and no 0xF005 -- is answered with neither (F1 section 2.3); every other leaf without
// a 0xF005 that verifies is unbound.
type leafBound struct {
	leaf         uint32
	identity     []byte
	signatureKey []byte
	// the list the leaf carries, verified under its credential and signature key; nil for profile 1
	// and for a leaf whose 0xF005 does not verify
	verified *messagegroup.VerifiedIdentity
	// the 0xF005 body as the leaf carries it, which names one list: the encoding is canonical, so two
	// leaves carry one list exactly when their bodies are equal
	list []byte
	// why the leaf's 0xF005 does not verify, or why its extensions do not read
	unbound error
}

// profileOne answers whether the leaf is profile 1: no 0xF005, and its credential its signature key.
func (self *leafBound) profileOne() bool {
	return self.verified == nil && self.unbound == nil
}

// boundLeavesOf reads every leaf of one tree as the binding rules read it.
func boundLeavesOf(members []CommitMember) map[uint32]*leafBound {
	out := make(map[uint32]*leafBound, len(members))
	for _, member := range members {
		out[member.Leaf] = bindingOf(member.Leaf, member.IdentityPub, member.SignatureKey, member.Extensions)
	}
	return out
}

// bindingOf is one leaf's reading: profile 1 for a leaf whose credential is its signature key and
// which carries no 0xF005, and VerifyLeafBinding over its credential, its signature key and its
// extensions for every other, whose refusal is the reason it is unbound -- a leaf of any other shape
// that carries no 0xF005 among them (F1 section 2.3).
func bindingOf(leaf uint32, identity []byte, signatureKey []byte, extensions []messagegroup.ExtensionBytes) *leafBound {
	bound := &leafBound{leaf: leaf, identity: identity, signatureKey: signatureKey}
	body, carried, err := mls.FindExtension(mlsExtensionsOf(extensions), mls.ExtensionTypeUrmessageIdentity)
	if err != nil {
		bound.unbound = err
		return bound
	}
	bound.list = body
	if !carried && bytes.Equal(identity, signatureKey) {
		return bound
	}
	bound.verified, bound.unbound = messagegroup.VerifyLeafBinding(identity, signatureKey, extensions)
	return bound
}

// treeMembersOf is a group's tree as it stands, every occupied leaf as the binding rules read it: its
// credential identity, its signature key and its extensions, off the seam's LeafAt. The Join door, the
// restore and the heads read a tree through it.
func treeMembersOf(handle messagegroup.GroupHandle) ([]CommitMember, error) {
	members := make([]CommitMember, 0, handle.MemberCount())
	for at := 0; at < handle.MemberCount(); at++ {
		leaf, _, _, err := handle.MemberAt(at)
		if err != nil {
			return nil, fmt.Errorf("urmessage: the group's member %d: %w", at, err)
		}
		view, err := handle.LeafAt(leaf)
		if err != nil {
			return nil, fmt.Errorf("urmessage: the group's member %d at leaf %d: %w", at, leaf, err)
		}
		members = append(members, CommitMember{
			Leaf:         leaf,
			IdentityPub:  append([]byte(nil), view.Credential...),
			HasLeafKeys:  true,
			SignatureKey: append([]byte(nil), view.SignatureKey...),
			Extensions:   cloneExtensionBytes(view.Extensions),
		})
	}
	return members, nil
}

// groupPurposeIn answers a context's 0xF006, or nil for a conversation's, which carries none.
func groupPurposeIn(extensions []messagegroup.ExtensionBytes) (*messagegroup.GroupPurpose, error) {
	body, carried, err := mls.FindExtension(mlsExtensionsOf(extensions), mls.ExtensionTypeUrmessageGroupPurpose)
	if err != nil || !carried {
		return nil, err
	}
	return messagegroup.ParseGroupPurpose(messagegroup.ExtensionBytes{Type: uint16(mls.ExtensionTypeUrmessageGroupPurpose), Data: body})
}

// The purposes 0xF006 names (Spec A A-36 section 3.4).
const (
	groupPurposeSelf = 1
	groupPurposeLink = 2
)

// treeHeads is the newest list of every identity a tree holds, by root: head(X, T). Two lists of
// one root that fork answer the fork, which is R8-EQ's refusal.
//
// EVERY PAIR OF ONE ROOT'S LISTS IS COMPARED, IN ANY LEAF ORDER (LRI R84 item 7; review C-1). Each
// list a leaf carries is compared with every other list of its root the tree holds, and not only with
// the newest read so far: two lists that fork at one version are a fork whatever newer list of their
// identity stands between them in leaf order, and a reading that compared each with the running
// newest admitted them in four orders of six. Leaves that carry one list -- equal bodies, since the
// encoding is canonical -- are compared once, so a tree whose leaves of one identity carry one list
// costs what it did.
func treeHeads(bound map[uint32]*leafBound) (map[string]*messagegroup.VerifiedIdentity, error) {
	heads := map[string]*messagegroup.VerifiedIdentity{}
	// every distinct list of each root read so far, by its body, in the order first read
	distinct := map[string][]*leafBound{}
	for _, leaf := range sortedLeavesOf(bound) {
		one := bound[leaf]
		if one.verified == nil {
			continue
		}
		root := string(one.verified.Root)
		if slices.ContainsFunc(distinct[root], func(other *leafBound) bool { return bytes.Equal(other.list, one.list) }) {
			continue
		}
		held, seen := heads[root]
		newer := false
		for _, other := range distinct[root] {
			order, err := messagegroup.VerifyDeviceList(other.verified.Identity, one.verified.Identity)
			if err != nil {
				return nil, fmt.Errorf("leaf %d's list and leaf %d's, both of root %x: %w", leaf, other.leaf, one.verified.Root, err)
			}
			// the head is one of the lists read so far, so its order against this one is read here
			if other.verified == held && order == messagegroup.ListNewer {
				newer = true
			}
		}
		distinct[root] = append(distinct[root], one)
		if !seen || newer {
			heads[root] = one.verified
		}
	}
	return heads, nil
}

// currentIn answers whether a profile-2 leaf is current in a tree: the newest list of its identity
// there names its signature key. A profile-1 leaf has no list, and is not asked.
func currentIn(one *leafBound, heads map[string]*messagegroup.VerifiedIdentity) bool {
	if one.verified == nil {
		return true
	}
	head, held := heads[string(one.verified.Root)]
	if !held {
		return false
	}
	return slices.ContainsFunc(head.Devices, func(entry messagegroup.DeviceEntry) bool {
		return bytes.Equal(entry.DeviceKey, one.signatureKey)
	})
}

// sortedLeavesOf is a tree's leaves in order, so every rule walks a tree the same way.
func sortedLeavesOf(bound map[uint32]*leafBound) []uint32 {
	leaves := make([]uint32, 0, len(bound))
	for leaf := range bound {
		leaves = append(leaves, leaf)
	}
	slices.Sort(leaves)
	return leaves
}

// judgedLeavesOf is the leaves R6e and R8-CUR judge by name: every leaf the commit adds or updates,
// and the committer's own post-commit leaf.
func judgedLeavesOf(a *CommitAuthorization) []uint32 {
	judged := append(append([]uint32{a.CommitterLeaf}, a.AddedLeaves...), a.UpdatedLeaves...)
	slices.Sort(judged)
	return slices.Compact(judged)
}

// ruleLeavesBound is R6e. Every leaf a commit adds or updates, and the committer's own post-commit
// leaf, carries a 0xF005 that verifies, which binds the leaf's signature key to the identity its
// credential names (Spec A A-36 section 3.3). A profile-1 leaf, which carries none, stands only in
// a link group. Without the rule a credential that merely claims an identity is taken at its word,
// which is the gap Task 8's I1-unbound-key-package-admitted measured.
func ruleLeavesBound(a *CommitAuthorization, after map[uint32]*leafBound, purpose *messagegroup.GroupPurpose) error {
	link := purpose != nil && purpose.Purpose == groupPurposeLink
	for _, leaf := range judgedLeavesOf(a) {
		one, occupied := after[leaf]
		if !occupied {
			// a judged leaf the post-commit tree does not hold is R6c's refusal, already made
			continue
		}
		if one.unbound != nil {
			return fmt.Errorf("%w: leaf %d (%x): %w", ErrCommitIdentityUnbound, leaf, one.identity, one.unbound)
		}
		if one.profileOne() && !link {
			return fmt.Errorf("%w: leaf %d (%x) carries no urmessage_identity, and a profile-1 leaf stands only in a link group",
				ErrCommitIdentityUnbound, leaf, one.identity)
		}
	}
	return nil
}

// ruleSignatureKeysKept is R6c-sig. Every leaf that survives a commit, the committer's included,
// keeps its signature key: a leaf is a device, and the device is its signature key, which the lists
// name. Without it an Update, or the committer's own path, would move a listed device's leaf to a
// key no list names, past R8-CUR's reading of who is current. A leaf the commit removes, and one an
// Add fills again where a removal blanked it, survive nothing.
func ruleSignatureKeysKept(a *CommitAuthorization, before map[uint32]*leafBound, after map[uint32]*leafBound) error {
	removed := leafSetOf(a.RemovedLeaves)
	for _, leaf := range sortedLeavesOf(before) {
		if removed[leaf] {
			continue
		}
		now, still := after[leaf]
		if !still {
			continue
		}
		if !bytes.Equal(now.signatureKey, before[leaf].signatureKey) {
			return fmt.Errorf("%w: leaf %d (%x) was signed by %x and is signed by %x after the commit",
				ErrCommitSignatureKeyChanged, leaf, now.identity, before[leaf].signatureKey, now.signatureKey)
		}
	}
	return nil
}

// ruleNoListFork is R8-EQ. Two lists of one identity in the post-commit tree do not fork: two lists
// at one version are byte-identical, and the identity's chain, key numbers and bases agree
// (messagegroup.VerifyDeviceList's reading of a fork). A server that forks a self group -- two
// commits at one epoch, each served to a different device -- is caught where the two lists meet.
func ruleNoListFork(after map[uint32]*leafBound) error {
	if _, err := treeHeads(after); err != nil {
		return fmt.Errorf("%w: %w", ErrDeviceListEquivocation, err)
	}
	return nil
}

// ruleCurrentDevicesOnly is R8-CUR: noncurrent(T_post) is within noncurrent(T_pre) less what the
// commit removes. A leaf the newest list in the tree does not name is removed in the commit that
// brings that list, or the commit is refused; so a device a list drops leaves every tree that list
// reaches with the same commit. The leaves a commit adds or updates, and the committer's own, are
// current after it. A leaf that was already not current before, and that the commit leaves alone,
// is not this commit's to answer for.
func ruleCurrentDevicesOnly(a *CommitAuthorization, before map[uint32]*leafBound, after map[uint32]*leafBound) error {
	headsBefore, err := treeHeads(before)
	if err != nil {
		// a fork already standing before the commit: the pre-commit tree's own reading has no
		// newest list to judge currency by, and R8-EQ refuses any commit that keeps it
		headsBefore = map[string]*messagegroup.VerifiedIdentity{}
	}
	headsAfter, err := treeHeads(after)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrDeviceListEquivocation, err)
	}
	judged := leafSetOf(judgedLeavesOf(a))
	removed := leafSetOf(a.RemovedLeaves)
	for _, leaf := range sortedLeavesOf(after) {
		one := after[leaf]
		if currentIn(one, headsAfter) {
			continue
		}
		was, kept := before[leaf]
		alreadyNotCurrent := kept && !removed[leaf] && bytes.Equal(was.signatureKey, one.signatureKey) && !currentIn(was, headsBefore)
		if judged[leaf] || !alreadyNotCurrent {
			return fmt.Errorf("%w: leaf %d (%x) is not named by the newest list of its identity after the commit",
				ErrDeviceNotCurrent, leaf, one.identity)
		}
	}
	return nil
}

// ruleSystemGroup is R9, over a group whose context carries 0xF006 (Spec A A-36 section 3.4): its
// membership half over the post-commit tree ([systemGroupMembership]), and for a link group its
// commit half -- only the identity's leaf commits, and no commit is taken at a pre-commit epoch of
// 1 or above. A conversation carries no 0xF006, and the rule asks nothing of it.
func ruleSystemGroup(a *CommitAuthorization, before map[uint32]*leafBound, after map[uint32]*leafBound,
	purpose *messagegroup.GroupPurpose) error {

	if purpose == nil {
		return nil
	}
	if err := systemGroupMembership(after, purpose); err != nil {
		return err
	}
	if purpose.Purpose != groupPurposeLink {
		return nil
	}
	if 1 <= a.Epoch-1 {
		return fmt.Errorf("%w: a link group takes no commit at epoch %d", ErrSystemGroupViolation, a.Epoch-1)
	}
	committer, held := before[a.CommitterLeaf]
	if !held || committer.verified == nil || !bytes.Equal(committer.verified.IdentityKey, purpose.IdentityRoot) {
		return fmt.Errorf("%w: only the identity's leaf commits in a link group, and leaf %d is not it",
			ErrSystemGroupViolation, a.CommitterLeaf)
	}
	return nil
}

// systemGroupMembership is R9's membership half: who may stand in a system group's tree.
//
//   - A SELF GROUP (purpose 1) admits leaves of its own identity only: every leaf is profile 2
//     under the root 0xF006 names, read through the chain.
//   - A LINK GROUP (purpose 2) holds at most two leaves, one profile-2 leaf of the identity whose
//     CURRENT identity key 0xF006 names, and one profile-1 leaf.
//
// THE KEY 0xF006 NAMES IS THE ROOT IN A SELF GROUP AND THE CURRENT IDENTITY KEY, IRK, IN A LINK GROUP
// (MASTER sections 5.3 and 5.4; Spec A sections 3.4 and 7.5; LRI R84 item 8), and a link group is
// founded with {2, IRK}: once an identity has a chain, a leaf under the root, a retired key, is not
// its leaf in a link group.
//
// A purpose this build does not know is refused: a system group is never read as a conversation.
func systemGroupMembership(tree map[uint32]*leafBound, purpose *messagegroup.GroupPurpose) error {
	switch purpose.Purpose {
	case groupPurposeSelf:
		for _, leaf := range sortedLeavesOf(tree) {
			one := tree[leaf]
			if one.verified == nil || !bytes.Equal(one.verified.Root, purpose.IdentityRoot) {
				return fmt.Errorf("%w: a self group of %x holds leaf %d (%x), which is not of that identity",
					ErrSystemGroupViolation, purpose.IdentityRoot, leaf, one.identity)
			}
		}
		return nil
	case groupPurposeLink:
		ownLeaves, profileOneLeaves := 0, 0
		for _, leaf := range sortedLeavesOf(tree) {
			one := tree[leaf]
			switch {
			case one.profileOne():
				profileOneLeaves += 1
			case one.verified != nil && bytes.Equal(one.verified.IdentityKey, purpose.IdentityRoot):
				ownLeaves += 1
			default:
				return fmt.Errorf("%w: a link group of %x holds leaf %d (%x), which is neither its identity's nor profile 1",
					ErrSystemGroupViolation, purpose.IdentityRoot, leaf, one.identity)
			}
		}
		if 1 < ownLeaves || 1 < profileOneLeaves {
			return fmt.Errorf("%w: a link group holds %d leaves of its identity and %d of profile 1, and one of each at most",
				ErrSystemGroupViolation, ownLeaves, profileOneLeaves)
		}
		return nil
	default:
		return fmt.Errorf("%w: purpose %d, which this build does not know", ErrSystemGroupViolation, purpose.Purpose)
	}
}

// checkTreeBinding is the Join door's and the restore's reading of one whole tree (identity phase
// 1's Tasks 12 and 13): every leaf binds, or is the one profile-1 leaf a link group may hold; no two
// lists of one identity fork; and, where the context carries 0xF006, R9's membership half holds.
// It answers the verified lists, for the heads.
func checkTreeBinding(members []CommitMember, extensions []messagegroup.ExtensionBytes) ([]*messagegroup.VerifiedIdentity, error) {
	purpose, err := groupPurposeIn(extensions)
	if err != nil {
		return nil, fmt.Errorf("%w: the group's purpose: %w", ErrSystemGroupViolation, err)
	}
	bound := boundLeavesOf(members)
	link := purpose != nil && purpose.Purpose == groupPurposeLink
	verified := []*messagegroup.VerifiedIdentity{}
	for _, leaf := range sortedLeavesOf(bound) {
		one := bound[leaf]
		switch {
		case one.unbound != nil:
			return nil, fmt.Errorf("%w: leaf %d: %w", ErrGroupLeafUnbound, leaf, one.unbound)
		case one.profileOne() && !link:
			return nil, fmt.Errorf("%w: leaf %d carries no urmessage_identity, and a profile-1 leaf stands only in a link group",
				ErrGroupLeafUnbound, leaf)
		case one.verified != nil:
			verified = append(verified, one.verified)
		}
	}
	if _, err := treeHeads(bound); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDeviceListEquivocation, err)
	}
	if purpose != nil {
		if err := systemGroupMembership(bound, purpose); err != nil {
			return nil, err
		}
	}
	return verified, nil
}
