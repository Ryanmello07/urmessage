package cp3b

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/urnetwork/message-server/api"
	"github.com/urnetwork/message-server/peer"
	"github.com/urnetwork/message/messagegroup"
	"github.com/urnetwork/message/mls"
	"github.com/urnetwork/message/protocol"
	"github.com/urnetwork/message/sdk/urmessage"
)

// IDENTITY PHASE 1's THREE SCENARIOS OF LISTS AND SELF GROUPS (its plan's Task 13), each RED on Task
// 12's commit, where the rules that close them are absent, as gate 5 asks (REDTEAM L5):
//
//   - a stranger in the self group. A further device of Alice's, with an altered app, adds a stranger's
//     device to her self group, where her devices' secrets travel. R9 closes it.
//   - the server rolls back a list. Bob sees Alice's newer list, which drops a device of hers, and the
//     server then serves him a tree that still holds the older one. His stored head must not go back,
//     or his own Add door takes the dropped device. The heads' rule closes it: heads only rise.
//   - the server forks the self group. The server accepts two self-group commits at one epoch, each
//     bringing a list of Alice's at one version, and serves each to a different device of hers; the
//     two lists then meet in a conversation. R8-EQ closes it: no tree takes both.
//
// THE SELF GROUP IS REACHED AS THE DEVICE HOLDS IT. No verb answers a system group (Task 12), and the
// verbs that bring a second device into one are the link's (Task 23); so the harness takes Alice's
// self group off her device's own table and drives it through the group's own exported verbs, as the
// link will. A seam member's own-leaf commit is made on the live *mls.Group behind its handle, through
// mls's own-leaf option (Task 9), as a hostile build makes one, so that the scenarios run on the tree
// before Task 13 as well, which has no seam door for it.

// advSelfGroupOf is the self group a real device holds: the one group of its table that is a system
// group. The table is reached through the field urmessage keeps unexported, found by name and checked
// by type -- unsafe in a test and nowhere else, as urmessage's own liveGroupOf reaches mls's group --
// so a rename or a retype fails here with a sentence.
func advSelfGroupOf(t *testing.T, device *urmessage.Device) *urmessage.Group {
	t.Helper()
	field := reflect.ValueOf(device).Elem().FieldByName("groups")
	if !field.IsValid() || field.Type() != reflect.TypeOf(map[string]*urmessage.Group{}) {
		advHarness(t, "urmessage.Device holds no map[string]*Group named groups; the self group is reached through it, and this is the line to move")
	}
	groups := *(*map[string]*urmessage.Group)(unsafe.Pointer(field.UnsafeAddr()))
	var found *urmessage.Group
	for _, group := range groups {
		system := reflect.ValueOf(group).Elem().FieldByName("system")
		if !system.IsValid() || system.Kind() != reflect.Bool {
			advHarness(t, "urmessage.Group holds no bool named system; this is the line to move")
		}
		if system.Bool() {
			if found != nil {
				advHarness(t, "the device holds two system groups")
			}
			found = group
		}
	}
	if found == nil {
		advHarness(t, "the device holds no system group: its self group was not founded")
	}
	return found
}

// advLiveGroupOf is the *mls.Group behind a seam member's handle, reached as [advSelfGroupOf] reaches
// the device's table.
func advLiveGroupOf(t *testing.T, handle messagegroup.GroupHandle) *mls.Group {
	t.Helper()
	value := reflect.ValueOf(handle)
	if value.Kind() != reflect.Pointer || value.Type().String() != "*messagegroup.connectMlsHandle" {
		advHarness(t, "the handle is a %s, not connect/messagegroup's adapter over a live *mls.Group", value.Type())
	}
	field, found := value.Type().Elem().FieldByName("group")
	if !found || field.Type != reflect.TypeOf((*mls.Group)(nil)) {
		advHarness(t, "connect/messagegroup's adapter holds no *mls.Group named group; this is the line to move")
	}
	group := *(**mls.Group)(unsafe.Add(value.UnsafePointer(), field.Offset))
	if group == nil {
		advHarness(t, "the adapter holds no live group")
	}
	return group
}

// ownLeafCommit stages a commit with a path that patches this member's own leaf with a list: Spec A
// A-36's CommitOwnLeaf, made on the live group with mls's own option, as a hostile build makes it.
func (self *seamMember) ownLeafCommit(t *testing.T, list messagegroup.ExtensionBytes) []byte {
	t.Helper()
	result, err := advLiveGroupOf(t, self.handle).CreateCommit([][]byte{}, nil, &mls.CommitOptions{
		Force: true,
		OwnLeafPatch: &mls.OwnLeafPatch{Extensions: []mls.Extension{{
			ExtensionType: mls.ExtensionType(list.Type),
			ExtensionData: bytes.Clone(list.Data),
		}}},
	})
	if err != nil {
		advHarness(t, "%s's own-leaf commit: %v", self.name, err)
	}
	return result.Commit
}

// advBaseList is a list of a world identity under key number 1: the words' certificate and a base of
// the number given naming the devices given, signed by the phrase key and by its author, which it
// marks a phrase device.
func advBaseList(t *testing.T, claimed *worldIdentity, base uint64, author mls.SignaturePrivateKey, authorPub []byte,
	devices ...[]byte) messagegroup.ExtensionBytes {

	t.Helper()
	phrase, _, err := messagegroup.ParseRecoveryPhrase(claimed.words)
	if err != nil {
		advHarness(t, "%s's words do not read back: %v", claimed.name, err)
	}
	defer phrase.Erase()
	entries := []messagegroup.DeviceEntry{}
	for _, device := range devices {
		flags := uint8(0)
		if bytes.Equal(device, authorPub) {
			flags = messagegroup.DeviceFlagPhraseDevice
		}
		entries = append(entries, messagegroup.DeviceEntry{DeviceKey: bytes.Clone(device), Flags: flags})
	}
	slices.SortFunc(entries, func(a, b messagegroup.DeviceEntry) int { return bytes.Compare(a.DeviceKey, b.DeviceKey) })
	authorKey := ed25519.NewKeyFromSeed(author)
	defer clear(authorKey)
	var own *messagegroup.UrmessageIdentity
	if err := messagegroup.WithPhraseKeysUnder(messagegroup.FastPhraseStretchForTests(), phrase, []uint32{1}, func(keys *messagegroup.PhraseKeys) error {
		cert, err := keys.SignIskCert(1)
		if err != nil {
			return err
		}
		list := &messagegroup.DeviceListBase{
			IdentityKey: keys.IdentityKey(),
			KeyNumber:   1,
			BaseNumber:  base,
			IssuedAtMs:  uint64(time.Now().UnixMilli()),
			Devices:     entries,
			AuthorKey:   bytes.Clone(authorPub),
		}
		if err := messagegroup.SignBaseAuthor(list, authorKey); err != nil {
			return err
		}
		if err := keys.SignBase(1, list); err != nil {
			return err
		}
		own = &messagegroup.UrmessageIdentity{IskCert: *cert, Base: *list}
		return nil
	}); err != nil {
		advHarness(t, "%s's base %d: %v", claimed.name, base, err)
	}
	extension, err := own.Encode()
	if err != nil {
		advHarness(t, "%s's base %d's extension: %v", claimed.name, base, err)
	}
	return extension
}

// seamMemberUnder is a further device of a world identity whose leaves carry a list the scenario
// chooses: a base of the number given, naming the devices others answers -- given this member's own key
// -- and signed by this member as its author.
func (self *world) seamMemberUnder(t *testing.T, ctx context.Context, name string, claimed *worldIdentity, base uint64,
	others func(own []byte) [][]byte) *seamMember {

	t.Helper()
	return self.seamMemberMaking(t, ctx, name, func(signer mls.SignaturePrivateKey, signerPub []byte) ([]byte, messagegroup.ExtensionBytes) {
		return identityKeyOf(t, claimed.words), advBaseList(t, claimed, base, signer, signerPub, others(signerPub)...)
	})
}

// advForkingHandler is a server that forks one group. While it forks, every submission to that group
// is answered as taken and kept from the store: the member that sent it moves on to an epoch no other
// member is served, while the store goes on serving everyone else the history it holds.
type advForkingHandler struct {
	peer.Handler
	mutex   sync.Mutex
	groupId []byte
	kept    int
}

func (self *advForkingHandler) fork(groupId []byte) {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	self.groupId = bytes.Clone(groupId)
}

func (self *advForkingHandler) stop() int {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	self.groupId = nil
	return self.kept
}

func (self *advForkingHandler) Submit(ctx context.Context, conn *api.Connection,
	request *protocol.SubmitRequest) (protocol.Reason, *protocol.SubmitResponse, error) {

	self.mutex.Lock()
	forking := self.groupId != nil && bytes.Equal(request.GetGroupId(), self.groupId)
	if forking {
		self.kept += len(request.GetRecords())
	}
	self.mutex.Unlock()
	if !forking {
		return self.Handler.Submit(ctx, conn, request)
	}
	results := []*protocol.SubmitResult{}
	for at := range request.GetRecords() {
		results = append(results, &protocol.SubmitResult{Reason: protocol.Reason_REASON_OK, RecordId: uint64(1<<40 + at)})
	}
	return protocol.Reason_REASON_OK, &protocol.SubmitResponse{Results: results}, nil
}

// advSelfGroupWithSibling opens Alice's self group with one further device of hers, a seam member, in
// it: the group's own founding add and Open, and the seam's join, as the link will bring a device in.
func advSelfGroupWithSibling(t *testing.T, ctx context.Context, self *urmessage.Group, sibling *seamMember) {
	t.Helper()
	invite, err := self.AddMember(sibling.keyPackage(t))
	if err != nil {
		advHarness(t, "the self group's AddMember of %s: %v", sibling.name, err)
	}
	if err := self.Open(ctx); err != nil {
		advHarness(t, "the self group's Open: %v", err)
	}
	sibling.join(t, gcReencodeInvite(t, invite))
}

// ── 5. a stranger in the self group ──────────────────────────────────────────────────────────

// A FURTHER DEVICE OF ALICE'S ADDS A STRANGER TO HER SELF GROUP, AND HER DEVICE ADMITS IT. Her self
// group carries what her devices hand each other; a stranger in it reads it. The attacker is a seam
// member, a device of Alice's with an altered app, which skips the sending check; the stranger is a
// device of an identity of its own, bound to it, so that nothing but R9 stands in its way.
//
// THE CONTROL, FIRST, since a refused commit halts the group: the same attacker adds another device
// of Alice's own, and her device admits it under any rule.
func TestAdvSimAStrangerAddedToTheSelfGroupIsAdmitted(t *testing.T) {
	world := newWorld(t)
	ctx := context.Background()
	devices := advConnected(t, ctx, world, "alice")
	alice := devices["alice"]
	aliceId := identityKeyOf(t, world.identityClaimed(t, advIdentityOf(t, alice)).words)
	selfGroup := advSelfGroupOf(t, alice)
	attacker := world.seamMemberClaiming(t, ctx, "alice-tablet", aliceId)
	advSelfGroupWithSibling(t, ctx, selfGroup, attacker)
	advSettle(t, ctx, "alice", selfGroup, selfGroup.Epoch())
	words := [2]string{"admitted", "refused"}
	receivers := map[string]*urmessage.Group{"alice": selfGroup}

	// THE CONTROL: a further device of Alice's own
	phone := world.seamMemberClaiming(t, ctx, "alice-phone", aliceId)
	commit, _, _, err := attacker.handle.CommitAdd([][]byte{phone.keyPackage(t)})
	if err != nil {
		advHarness(t, "the attacker's CommitAdd of alice's phone: %v", err)
	}
	added := attacker.publishRotated(t, ctx, "the attacker's addition of alice's phone", commit)
	if len(added) != 1 {
		advHarness(t, "the addition of alice's phone added leaves %v, want one", added)
	}
	phoneLeaf := added[0]
	control := advVerdictOf(t, ctx, "the attacker's addition of alice's phone", words, receivers, "",
		func(reader string, members []urmessage.Member) bool { return advHoldsAt(members, phoneLeaf, aliceId) })
	if !slices.Equal(control, []string{"admitted"}) {
		advHarness(t, "CONTROL FAILED: a device of alice's own added to her self group was read as %v, want [admitted]", control)
	}
	t.Logf("CONTROL: a device of alice's own, added to her self group, was admitted")

	// THE SCENARIO: a stranger
	stranger := world.seamMember(t, ctx, "stranger")
	commit, _, _, err = attacker.handle.CommitAdd([][]byte{stranger.keyPackage(t)})
	if err != nil {
		advHarness(t, "the attacker's CommitAdd of the stranger: %v", err)
	}
	added = attacker.publishRotated(t, ctx, "the attacker's addition of a stranger to the self group", commit)
	if len(added) != 1 {
		advHarness(t, "the addition of the stranger added leaves %v, want one", added)
	}
	strangerLeaf := added[0]
	advJudge(t, "I1-stranger-in-self-group", advVerdictOf(t, ctx, "the attacker's addition of a stranger to the self group",
		words, receivers, "", func(reader string, members []urmessage.Member) bool {
			return advHoldsAt(members, strangerLeaf, stranger.identityPub)
		}))
}

// advIdentityOf is the identity key a real device's leaves name, read off its own key package.
func advIdentityOf(t *testing.T, device *urmessage.Device) []byte {
	t.Helper()
	keyPackage, err := device.KeyPackage()
	if err != nil {
		advHarness(t, "a KeyPackage: %v", err)
	}
	decoded, _, err := keyPackageIdentity(t, keyPackage)
	if err != nil {
		advHarness(t, "the device's key package does not bind: %v", err)
	}
	return bytes.Clone(decoded.LeafNode.Credential.Identity)
}

// seamDeviceOf is a further device of a world identity whose list the scenario sets on it before any
// key package is made: two devices that carry one list carry one octet string, which is what keeps them
// from forking.
func (self *world) seamDeviceOf(t *testing.T, ctx context.Context, name string, identityKey []byte) *seamMember {
	t.Helper()
	return self.seamMemberMaking(t, ctx, name, func(signer mls.SignaturePrivateKey, signerPub []byte) ([]byte, messagegroup.ExtensionBytes) {
		return bytes.Clone(identityKey), messagegroup.ExtensionBytes{}
	})
}

// ── 6. the server rolls back a list ──────────────────────────────────────────────────────────

// THE SERVER ROLLS BACK A LIST OF ALICE'S, AND BOB'S OWN ADD DOOR TAKES THE DEVICE IT DROPPED. Alice's
// base 2 names her laptop, which is in a group of Bob's; her base 3, brought into a conversation with
// Bob by her tablet, drops it. The server then serves Bob a commit in his group with the laptop, whose
// tree still holds base 2. A stored head that goes back to the last list seen lets Bob add a join code
// of the laptop's, which his head of base 3 refuses.
//
// THE CONTROL, BEFORE THE ROLLBACK: a join code of the tablet's carrying base 3, which base 3 names, is
// added by Bob. Each add is the founding add of a group of Bob's own, so that no tree but his own
// knowledge has anything to say about it.
func TestAdvSimTheServerRollsBackAListAndTheHeadFollowsIt(t *testing.T) {
	world := newWorld(t)
	ctx := context.Background()
	devices := advConnected(t, ctx, world, "alice", "bob")
	alice, bob := devices["alice"], devices["bob"]
	aliceKey := advIdentityOf(t, alice)
	claimed := world.identityClaimed(t, aliceKey)
	alicePub := advSignatureKeyOf(t, alice)

	// ALICE'S TABLET AND LAPTOP, BOTH UNDER BASE 2, WHICH NAMES THE LAPTOP; AND BASE 3, WHICH DOES NOT
	tablet := world.seamDeviceOf(t, ctx, "alice-tablet", aliceKey)
	laptop := world.seamDeviceOf(t, ctx, "alice-laptop", aliceKey)
	base2 := advBaseList(t, claimed, 2, tablet.signer, tablet.signerPub, alicePub, tablet.signerPub, laptop.signerPub)
	base3 := advBaseList(t, claimed, 3, tablet.signer, tablet.signerPub, alicePub, tablet.signerPub)
	tablet.identity, laptop.identity = base2, base2

	// BOB'S GROUP WITH THE LAPTOP, while Bob holds no newer list of Alice's
	withLaptop, err := bob.CreateGroup(ctx, newGroupId(t))
	if err != nil {
		advHarness(t, "bob's CreateGroup: %v", err)
	}
	invite, err := withLaptop.AddMember(laptop.keyPackage(t))
	if err != nil {
		advHarness(t, "bob's AddMember of alice's laptop: %v", err)
	}
	if err := withLaptop.Open(ctx); err != nil {
		advHarness(t, "bob's Open: %v", err)
	}
	laptop.join(t, gcReencodeInvite(t, invite))

	// THE CONVERSATION, WHERE THE TABLET BRINGS BASE 3
	groups := advConverse(t, ctx, advNamedDevice{"alice", alice}, advNamedDevice{"bob", bob})
	invite, err = groups["alice"].AddMemberAndPublish(ctx, tablet.keyPackage(t))
	if err != nil {
		advHarness(t, "alice's AddMemberAndPublish of her tablet: %v", err)
	}
	tablet.join(t, gcReencodeInvite(t, invite))
	advSettle(t, ctx, "bob", groups["bob"], groups["alice"].Epoch())
	tablet.publishRotated(t, ctx, "the tablet's base 3", tablet.ownLeafCommit(t, base3))
	for name, group := range groups {
		advSettle(t, ctx, name, group, tablet.handle.Epoch())
	}

	// THE CONTROL, BEFORE THE ROLLBACK: a join code of the tablet's, carrying base 3, is added. It is
	// made here because an add raises the heads from the tree it founds, and one made after the
	// rollback would carry base 3 back into Bob's heads and hide the rollback from the scenario
	tabletCode, err := tablet.engine.NewBoundKeyPackage([]messagegroup.ExtensionBytes{base3})
	if err != nil {
		advHarness(t, "the tablet's join code under base 3: %v", err)
	}
	control, err := bob.CreateGroup(ctx, newGroupId(t))
	if err != nil {
		advHarness(t, "bob's CreateGroup: %v", err)
	}
	if _, err := control.AddMember(tabletCode); err != nil {
		advHarness(t, "CONTROL FAILED: bob refused a join code base 3 names: %v", err)
	}
	t.Logf("CONTROL: a join code of a device base 3 names was added by bob")

	// THE ROLLBACK: the server serves Bob a commit in his group with the laptop, whose tree holds base 2
	laptop.publishRotated(t, ctx, "the laptop's bare commit", advBareCommit(t, laptop))
	advSettle(t, ctx, "bob", withLaptop, laptop.handle.Epoch())

	// THE SCENARIO: a join code of the laptop's, which base 3 drops
	scene, err := bob.CreateGroup(ctx, newGroupId(t))
	if err != nil {
		advHarness(t, "bob's CreateGroup: %v", err)
	}
	observed := []string{"add:admitted"}
	if _, err := scene.AddMember(laptop.keyPackage(t)); err != nil {
		t.Logf("bob's add of the laptop's join code was refused: %v", err)
		observed = []string{"add:refused"}
	}
	advJudge(t, "I1-server-rolls-back-a-list", observed)
}

// advBareCommit stages a commit with no proposal, the path every member may commit (ruling 12).
func advBareCommit(t *testing.T, member *seamMember) []byte {
	t.Helper()
	commit, _, _, err := member.handle.Commit([][]byte{})
	if err != nil {
		advHarness(t, "%s's bare commit: %v", member.name, err)
	}
	return commit
}

// ── 7. the server forks the self group ───────────────────────────────────────────────────────

// THE SERVER ACCEPTS TWO SELF-GROUP COMMITS AT ONE EPOCH AND SERVES EACH TO A DIFFERENT DEVICE OF
// ALICE'S, AND THE TWO LISTS THEY BROUGHT STAND SIDE BY SIDE IN A CONVERSATION. Alice's self group holds
// her device and her tablet. At one epoch, her device adds her laptop under a base 3, and the tablet
// brings another base 3 into its own leaf: the server takes both, the first into the history it serves
// Alice, the second into one it serves the tablet alone. The two bases name the same devices and differ
// in their octets, which is a fork and nothing else. Then the laptop, in a conversation with Bob, adds
// the phone under the second: the tree would hold two lists of Alice's at one version that differ.
// Every member admits it.
//
// THE CONTROL, FIRST: the laptop, under its base 3, is added to the conversation by Alice and followed
// by Bob, so a list of the fork stands alone in a tree.
func TestAdvSimAForkedSelfGroupsTwoListsStandInOneTree(t *testing.T) {
	var forking *advForkingHandler
	world := newWorldWith(t, worldOptions{wrapHandler: func(handler peer.Handler) peer.Handler {
		forking = &advForkingHandler{Handler: handler}
		return forking
	}})
	ctx := context.Background()
	devices := advConnected(t, ctx, world, "alice", "bob")
	alice, bob := devices["alice"], devices["bob"]
	aliceKey := advIdentityOf(t, alice)
	claimed := world.identityClaimed(t, aliceKey)
	alicePub := advSignatureKeyOf(t, alice)

	// THE SELF GROUP: Alice's device and her tablet, under base 2
	tablet := world.seamDeviceOf(t, ctx, "alice-tablet", aliceKey)
	tablet.identity = advBaseList(t, claimed, 2, tablet.signer, tablet.signerPub, alicePub, tablet.signerPub)
	selfGroup := advSelfGroupOf(t, alice)
	advSelfGroupWithSibling(t, ctx, selfGroup, tablet)
	forkEpoch := selfGroup.Epoch()

	// THE TWO LISTS AT ONE VERSION: two bases 3 naming the same four devices, one signed by the tablet
	// as its author and one by the phone, so that they differ in their octets and in nothing a rule of
	// currency reads -- only the refusal of a fork can tell them apart
	laptop := world.seamDeviceOf(t, ctx, "alice-laptop", aliceKey)
	phone := world.seamDeviceOf(t, ctx, "alice-phone", aliceKey)
	four := [][]byte{alicePub, tablet.signerPub, laptop.signerPub, phone.signerPub}
	laptop.identity = advBaseList(t, claimed, 3, tablet.signer, tablet.signerPub, four...)
	phone.identity = advBaseList(t, claimed, 3, phone.signer, phone.signerPub, four...)
	if bytes.Equal(laptop.identity.Data, phone.identity.Data) {
		advHarness(t, "the two bases 3 are one octet string, so there is no fork")
	}

	// THE FORK: Alice adds her laptop, and the server takes it into the history it serves her; the
	// tablet brings the phone's list at the same epoch, and the server takes that too, for the tablet
	if _, err := selfGroup.AddMemberAndPublish(ctx, laptop.keyPackage(t)); err != nil {
		advHarness(t, "alice's addition of her laptop to her self group: %v", err)
	}
	if tablet.handle.Epoch() != forkEpoch || selfGroup.Epoch() != forkEpoch+1 {
		advHarness(t, "the fork is not at one epoch: the tablet stands at %d and alice at %d", tablet.handle.Epoch(), selfGroup.Epoch())
	}
	forking.fork(selfGroup.Id())
	tablet.publishRotated(t, ctx, "the tablet's base 3 naming the phone", tablet.ownLeafCommit(t, phone.identity))
	if kept := forking.stop(); kept == 0 {
		advHarness(t, "the forking server kept none of the tablet's submissions")
	}
	if tablet.handle.Epoch() != forkEpoch+1 {
		advHarness(t, "the tablet stands at epoch %d after its own commit, want %d", tablet.handle.Epoch(), forkEpoch+1)
	}

	// THE CONVERSATION, AND THE CONTROL: the laptop, under its base 3, joins it
	groups := advConverse(t, ctx, advNamedDevice{"alice", alice}, advNamedDevice{"bob", bob})
	invite, err := groups["alice"].AddMemberAndPublish(ctx, laptop.keyPackage(t))
	if err != nil {
		advHarness(t, "CONTROL FAILED: alice's addition of her laptop to the conversation: %v", err)
	}
	laptop.join(t, gcReencodeInvite(t, invite))
	advSettle(t, ctx, "bob", groups["bob"], groups["alice"].Epoch())
	t.Logf("CONTROL: the laptop under the first base 3 joined the conversation, and bob followed")

	// THE SCENARIO: the laptop adds the phone, under the other base 3
	commit, _, _, err := laptop.handle.CommitAdd([][]byte{phone.keyPackage(t)})
	if err != nil {
		advHarness(t, "the laptop's CommitAdd of the phone: %v", err)
	}
	added := laptop.publishRotated(t, ctx, "the laptop's addition of the phone", commit)
	if len(added) != 1 {
		advHarness(t, "the addition of the phone added leaves %v, want one", added)
	}
	phoneLeaf := added[0]
	advJudge(t, "I1-server-forks-the-self-group", advVerdictOf(t, ctx, "the laptop's addition of the phone",
		[2]string{"admitted", "refused"}, groups, "", func(reader string, members []urmessage.Member) bool {
			return advHoldsAt(members, phoneLeaf, aliceKey)
		}))
}

// advSignatureKeyOf is the signature key a real device's leaves name.
func advSignatureKeyOf(t *testing.T, device *urmessage.Device) []byte {
	t.Helper()
	keyPackage, err := device.KeyPackage()
	if err != nil {
		advHarness(t, "a KeyPackage: %v", err)
	}
	decoded, _, err := keyPackageIdentity(t, keyPackage)
	if err != nil {
		advHarness(t, "the device's key package does not bind: %v", err)
	}
	return bytes.Clone(decoded.LeafNode.SignatureKey)
}

// advDeviceKey is a fresh device key pair.
func advDeviceKey(t *testing.T) (mls.SignaturePrivateKey, []byte) {
	t.Helper()
	crypto, err := mls.NewCryptoProvider(mls.CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		advHarness(t, "the crypto provider: %v", err)
	}
	signer, signerPub, err := crypto.SignatureKeyPair()
	if err != nil {
		advHarness(t, "a signature key pair: %v", err)
	}
	return signer, bytes.Clone(signerPub)
}
