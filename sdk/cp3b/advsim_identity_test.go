package cp3b

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/urnetwork/message/message"
	"github.com/urnetwork/message/messagegroup"
	"github.com/urnetwork/message/mls"
	"github.com/urnetwork/message/protocol"
	"github.com/urnetwork/message/sdk/urmessage"
)

// IDENTITY PHASE 1's FOUR GAPS, RED ON THE TREE THAT HAS NO IDENTITY LAYER (its plan's Task 8).
//
// Each scenario is a thing a person, or one adversary, does today whose answer the identity layer
// changes. Each runs on this tree's own mechanisms, so its RED is a measurement and not a
// prediction, and the commit that closes it has to edit the registry to say so:
//
//   - two devices of one person. Alice talks to Bob from two computers. Today a device IS an
//     identity ("THE CREDENTIAL IDENTITY IS THE SIGNER'S PUBLIC HALF", sdk/urmessage/device.go),
//     so Bob's roster reads three people, and a group. The plan's Task 26 closes it.
//   - a sibling evicts a sibling. A later leaf of Alice's identity removes her first device, which
//     nothing has dropped. R2 and R7 let an identity remove its own leaves (sdk/urmessage/roles.go),
//     so every receiver follows. Task 26 closes it, with R8-SIB.
//   - a copy adds a device unnoticed. A copy of Alice's folder adds a device under her identity.
//     The original follows the commit, holds the new device in its own roster, and says nothing.
//     Task 34 closes it, with the alarm.
//   - an unbound key package is admitted. The harness's attacker, which skips the Add door and the
//     sending check, adds a key package that names no identity, and every receiver admits it.
//     Task 13 closes it, with R6e.
//
// EACH HAS ITS CONTROL IN THE SAME TEST, read through the same reader, and each control is the act
// the closing task must NOT refuse: three real people are a group; a removal passes once a base
// has dropped its target; the original device's own addition raises no alarm; a bound key package
// is admitted. A control that does not hold is FAIL(HARNESS), never a verdict: the harness that
// could not see the right answer where it is right has measured nothing where it is wrong.
//
// TWO CONTROLS NAME A MECHANISM THIS TREE DOES NOT HAVE, and what each is here is said where it
// runs. This tree has no device list, so no base can drop the sibling the removal control
// removes: that arm is the removal with nothing in front of it, and Task 26 signs the base. And no
// key package is bound here: the bound-package control adds a real device's key package, which
// is bound from the commit that makes every device's key package carry the identity extension
// (Task 12), with no edit to this file.

// ── what a person sees of a roster ───────────────────────────────────────────────────────────

// advPeople is a roster as a person reads it, as facts: "identities:N", the number of people;
// "devices:<name>:K" for each person who holds several devices, named by the scene; and
// "kind:direct" or "kind:group", a group from three people up.
//
// THE KIND IS BY PEOPLE, AND THE LIBRARY DECIDES NO KIND. The one rule that tells a direct
// conversation from a group is the app's, and today it counts roster entries, one per LEAF: "A
// GROUP FROM THREE MEMBERS UP" (app Live/LiveWorld.cpp). Identity phase 1's scope has the app count
// people instead (its H6), where a person is an identity, so this reader counts identities with the
// app's threshold. On this tree, where every real device is an identity of its own, the two rules
// agree for every roster measured here; and a scenario that read leaves could never reach its goal,
// since Alice's two computers stay two leaves under any identity layer.
//
// A PERSON WITH ONE DEVICE GETS NO devices FACT, as the app shows "· N devices" only for several.
// A person who holds several and whom the scene does not name is "unnamed", which no registry
// entry expects, so it reads as a gap that moved.
func advPeople(members []urmessage.Member, names map[string][]byte) []string {
	leaves := map[string]int{}
	for _, member := range members {
		leaves[string(member.IdentityPub)] += 1
	}
	facts := []string{fmt.Sprintf("identities:%d", len(leaves))}
	for identity, held := range leaves {
		if held < 2 {
			continue
		}
		name := "unnamed"
		for who, named := range names {
			if bytes.Equal(named, []byte(identity)) {
				name = who
			}
		}
		facts = append(facts, fmt.Sprintf("devices:%s:%d", name, held))
	}
	kind := "direct"
	if 3 <= len(leaves) {
		kind = "group"
	}
	return advSet(append(facts, "kind:"+kind))
}

// advPeopleAtEveryReader reads one conversation's roster at each of its members, which must all
// say the same thing: they hold one tree at one epoch. It answers the facts once.
func advPeopleAtEveryReader(t *testing.T, groups map[string]*urmessage.Group, names map[string][]byte) []string {
	t.Helper()
	var agreed []string
	first := ""
	for reader, group := range groups {
		members, err := group.Members()
		if err != nil {
			advHarness(t, "%s's Members: %v", reader, err)
		}
		facts := advPeople(members, names)
		if agreed == nil {
			agreed, first = facts, reader
			continue
		}
		if fmt.Sprint(facts) != fmt.Sprint(agreed) {
			advHarness(t, "%s reads the roster as %v and %s as %v, at one tree", reader, facts, first, agreed)
		}
	}
	return agreed
}

// THE READER'S OWN CONTROL: every fact a goal names is one it can produce. A reader that could not
// say "direct" or "devices:alice:2" would hold the first scenario open for ever, and the commit that
// closed it would read as a regression.
func TestAdvSimThePeopleReaderReachesEveryFactItReports(t *testing.T) {
	alice, bob, carol := []byte("alice's identity"), []byte("bob's identity"), []byte("carol's identity")
	names := map[string][]byte{"alice": alice, "bob": bob}
	roster := func(identities ...[]byte) []urmessage.Member {
		members := []urmessage.Member{}
		for leaf, identity := range identities {
			members = append(members, urmessage.Member{LeafIndex: uint32(leaf), IdentityPub: identity})
		}
		return members
	}
	for _, one := range []struct {
		name    string
		members []urmessage.Member
		want    []string
	}{
		{"one person on two devices talking to another is direct", roster(alice, alice, bob),
			[]string{"devices:alice:2", "identities:2", "kind:direct"}},
		{"three people on one device each are a group", roster(alice, bob, carol),
			[]string{"identities:3", "kind:group"}},
		{"two people on one device each are direct", roster(alice, bob),
			[]string{"identities:2", "kind:direct"}},
		{"three devices of two people are not a group, which three leaves are to the app today", roster(alice, bob, bob),
			[]string{"devices:bob:2", "identities:2", "kind:direct"}},
		{"several devices of a person the scene does not name are said to be unnamed", roster(alice, carol, carol),
			[]string{"devices:unnamed:2", "identities:2", "kind:direct"}},
	} {
		if got := advPeople(one.members, names); fmt.Sprint(got) != fmt.Sprint(advSet(one.want)) {
			t.Errorf("%s: read %v, want %v", one.name, got, advSet(one.want))
		}
	}
}

// ── a conversation, founded through the verbs ────────────────────────────────────────────────

// advNamedDevice is one real device and the name a scene calls it by.
type advNamedDevice struct {
	name   string
	device *urmessage.Device
}

// advConverse founds a conversation on the first device and adds the others in order through the
// production verbs: the first through AddMember and Open, each later one through
// AddMemberAndPublish, which is today's join code. Every member is settled at the last epoch.
func advConverse(t *testing.T, ctx context.Context, members ...advNamedDevice) map[string]*urmessage.Group {
	t.Helper()
	if len(members) < 2 {
		advHarness(t, "a conversation needs two members and the scene named %d", len(members))
	}
	founder := members[0]
	founderGroup, err := founder.device.CreateGroup(ctx, newGroupId(t))
	if err != nil {
		advHarness(t, "%s's CreateGroup: %v", founder.name, err)
	}
	groups := map[string]*urmessage.Group{founder.name: founderGroup}
	for at, joiner := range members[1:] {
		keyPackage, err := joiner.device.KeyPackage()
		if err != nil {
			advHarness(t, "%s's KeyPackage: %v", joiner.name, err)
		}
		var invite *urmessage.Invite
		if at == 0 {
			if invite, err = founderGroup.AddMember(keyPackage); err != nil {
				advHarness(t, "%s's AddMember of %s: %v", founder.name, joiner.name, err)
			}
			if err := founderGroup.Open(ctx); err != nil {
				advHarness(t, "%s's Open: %v", founder.name, err)
			}
		} else if invite, err = founderGroup.AddMemberAndPublish(ctx, keyPackage); err != nil {
			advHarness(t, "%s's AddMemberAndPublish of %s: %v", founder.name, joiner.name, err)
		}
		joined, err := joiner.device.Join(ctx, gcReencodeInvite(t, invite))
		if err != nil {
			advHarness(t, "%s's Join: %v", joiner.name, err)
		}
		groups[joiner.name] = joined
	}
	for name, group := range groups {
		advSettle(t, ctx, name, group, founderGroup.Epoch())
	}
	return groups
}

// advConnected is one real device per name, each connected.
func advConnected(t *testing.T, ctx context.Context, world *world, names ...string) map[string]*urmessage.Device {
	t.Helper()
	devices := map[string]*urmessage.Device{}
	for _, name := range names {
		device, _, _ := world.device(t, name)
		if err := device.Connect(ctx); err != nil {
			advHarness(t, "%s's Connect: %v", name, err)
		}
		devices[name] = device
	}
	return devices
}

// ── 1. two devices of one person ─────────────────────────────────────────────────────────────

// ALICE TALKS TO BOB FROM TWO COMPUTERS. Her second computer comes in the one way this tree has:
// its own join code, added by her first. Each computer is an identity of its own, so every member,
// Bob first, reads three people and a group; the identity layer makes them one person with two
// devices, and the conversation direct.
//
// THE CONTROL: a third real person makes a conversation a group, and the reader says three people.
// That stays true under any identity layer, and it is what the reader must still say once Alice's
// two computers are one person.
func TestAdvSimTwoComputersOfOnePersonReadAsTwoPeople(t *testing.T) {
	world := newWorld(t)
	ctx := context.Background()
	devices := advConnected(t, ctx, world, "alice-pc1", "alice-pc2", "bob", "carol")

	control := advConverse(t, ctx,
		advNamedDevice{"alice-pc1", devices["alice-pc1"]},
		advNamedDevice{"bob", devices["bob"]},
		advNamedDevice{"carol", devices["carol"]})
	controlNames := map[string][]byte{
		"alice": rolesIdentityOf(t, control["alice-pc1"]),
		"bob":   rolesIdentityOf(t, control["bob"]),
		"carol": rolesIdentityOf(t, control["carol"]),
	}
	if got, want := advPeopleAtEveryReader(t, control, controlNames), advSet([]string{"identities:3", "kind:group"}); fmt.Sprint(got) != fmt.Sprint(want) {
		advHarness(t, "CONTROL FAILED: three real people read as %v, want %v", got, want)
	}
	t.Logf("CONTROL: three real people read as three people and a group, at all three readers")

	groups := advConverse(t, ctx,
		advNamedDevice{"alice-pc1", devices["alice-pc1"]},
		advNamedDevice{"bob", devices["bob"]},
		advNamedDevice{"alice-pc2", devices["alice-pc2"]})
	names := map[string][]byte{
		"alice": rolesIdentityOf(t, groups["alice-pc1"]),
		"bob":   rolesIdentityOf(t, groups["bob"]),
	}
	if leaves := len(removalRoster(t, groups["bob"])); leaves != 3 {
		advHarness(t, "bob reads %d leaves, and the scene is Alice's two computers and Bob", leaves)
	}
	advJudge(t, "I1-two-devices-one-person", advPeopleAtEveryReader(t, groups, names))
}

// ── the seam member, publishing as an honest client does ─────────────────────────────────────

// seamCompleteBody is the body of the marker that closes an epoch's fan-out, as sdk/urmessage
// seals it.
const seamCompleteBody = "urmessage/v1 alpha epoch complete"

// publishRotated publishes this member's staged commit the way an honest client's publish does,
// spelled from the public packages: a fresh pq_secret for the epoch it opens; one device wrap of
// it per leaf the commit keeps, ahead of the commit; the commit under a kind 0x0005 digest of the
// new epoch's keys, with the keys beside it on the request; the merge; and the marker. It is
// urmessage's publishCommitLocked, from (2a) to (5), with nothing checked first: what a hostile
// build of a member that holds every key sends.
//
// IT IS THE ONLY ROAD A REMOVAL HAS FROM A SEAM MEMBER. A removal carrying no digest, or one that
// rotates nothing, is refused by every honest receiver (ruling 41), so a seam member that sent
// one would measure that refusal and not the rule a scenario is about.
//
// It answers the leaves the commit added, read off this member's own tree after the merge.
func (self *seamMember) publishRotated(t *testing.T, ctx context.Context, what string, commit []byte) []uint32 {
	t.Helper()
	before := map[uint32]bool{}
	for at := 0; at < self.handle.MemberCount(); at += 1 {
		leaf, _, _, err := self.handle.MemberAt(at)
		if err != nil {
			advHarness(t, "%s's member %d: %v", self.name, at, err)
		}
		before[leaf] = true
	}
	pending, err := self.handle.PendingEpoch()
	if err != nil {
		self.handle.ClearPendingCommit()
		advHarness(t, "%s's staged epoch for %s: %v", self.name, what, err)
	}
	opens := pending.Epoch
	removed := map[uint32]bool{}
	for _, leaf := range pending.RemovedLeaves {
		removed[leaf] = true
	}
	pqNext, err := messagegroup.NewPqSecret(rand.Reader)
	if err != nil {
		advHarness(t, "%s's pq_secret for epoch %d: %v", self.name, opens, err)
	}
	// THE WRAPS, one per leaf of the live tree the commit keeps, at the epoch the group stands at
	wraps := 0
	for at := 0; at < self.handle.MemberCount(); at += 1 {
		leaf, _, leafKeys, err := self.handle.MemberAt(at)
		if err != nil {
			advHarness(t, "%s's member %d: %v", self.name, at, err)
		}
		if removed[leaf] {
			continue
		}
		parsed, err := mls.ParseLeafKeysExtension(leafKeys)
		if err != nil {
			advHarness(t, "leaf %d's leaf keys: %v", leaf, err)
		}
		target, err := messagegroup.ParseXwingPublicKey(parsed.DeviceXwingPub)
		if err != nil {
			advHarness(t, "leaf %d's x-wing key: %v", leaf, err)
		}
		handle := messagegroup.WrapTargetHandle(self.groupHandleKey, opens, leaf)
		body, err := messagegroup.SealWrapBody(rand.Reader, target, messagegroup.WrapEnvelope{
			FormatVersion: messagegroup.WrapFormatVersion,
			TargetType:    0x01,
			PayloadType:   0x01,
			ContentEpoch:  opens,
		}, self.groupId, handle[:], pqNext)
		if err != nil {
			advHarness(t, "%s sealing leaf %d's wrap: %v", self.name, leaf, err)
		}
		record, err := self.session.SealRecord(message.RetentionPermanent, 0, false, seamHead(), body, 0,
			&message.ServerAttachment{
				Kind: message.AttachmentWrap,
				Wrap: &message.WrapTag{WrapTargetHandle: append([]byte(nil), handle[:]...), Epoch: opens},
			})
		if err != nil {
			advHarness(t, "%s sealing leaf %d's wrap record: %v", self.name, leaf, err)
		}
		self.submit(t, ctx, "a wrap of "+what, record, nil)
		wraps += 1
	}
	// THE COMMIT, under the digest of the keys the new epoch opens with
	mlsSecret, err := self.handle.PendingExport("URmessage/v1/storage", nil, 32)
	if err != nil {
		advHarness(t, "%s's staged exporter: %v", self.name, err)
	}
	root := messagegroup.StorageRoot(mlsSecret, pqNext)
	writeKey, readKey := message.WriteKey(root), message.ReadKey(root)
	contextHash := sha256.Sum256(pending.GroupContext)
	digest, err := message.NewEpochDigestAttachment([urmessage.GroupIdBytes]byte(self.groupId), message.EpochDigestAttachment{
		Epoch:             opens,
		AlgId:             0x0031,
		GroupContextHash:  contextHash[:],
		ExpectedWrapCount: uint32(wraps),
	}, writeKey, readKey)
	if err != nil {
		advHarness(t, "%s's epoch digest: %v", self.name, err)
	}
	record, err := self.session.SealRecord(message.RetentionPermanent, 0, true, seamHead(), commit, 0,
		&message.ServerAttachment{Kind: message.AttachmentEpochDigest, EpochDigest: digest})
	if err != nil {
		advHarness(t, "%s sealing %s: %v", self.name, what, err)
	}
	self.submit(t, ctx, what, record, &protocol.EpochKeyDelivery{
		WriteKey: append([]byte(nil), writeKey...),
		ReadKey:  append([]byte(nil), readKey...),
	})
	if err := self.handle.MergePendingCommit(); err != nil {
		advHarness(t, "%s merging %s: %v", self.name, what, err)
	}
	if err := self.session.AdvanceEpoch(pqNext); err != nil {
		advHarness(t, "%s advancing its session: %v", self.name, err)
	}
	self.pqSecret = pqNext
	// THE MARKER, which makes the new epoch writable at the server
	marker, err := self.session.SealRecord(message.RetentionDurable, 0, false, seamHead(), []byte(seamCompleteBody), 0,
		&message.ServerAttachment{
			Kind:     message.AttachmentComplete,
			Complete: &message.EpochComplete{Epoch: self.handle.Epoch(), WrapCount: uint32(wraps)},
		})
	if err != nil {
		advHarness(t, "%s sealing the marker: %v", self.name, err)
	}
	self.submit(t, ctx, "the marker after "+what, marker, nil)
	added := []uint32{}
	for at := 0; at < self.handle.MemberCount(); at += 1 {
		leaf, _, _, err := self.handle.MemberAt(at)
		if err != nil {
			advHarness(t, "%s's member %d after the merge: %v", self.name, at, err)
		}
		if !before[leaf] {
			added = append(added, leaf)
		}
	}
	return added
}

// submit hands one sealed record to the server, with the epoch keys beside it when it is a commit
// whose attachment carries their digest, and fails the scene unless the server takes it.
func (self *seamMember) submit(t *testing.T, ctx context.Context, what string, record *message.Record,
	delivery *protocol.EpochKeyDelivery) {

	t.Helper()
	header := &record.Header
	retentionWire, err := message.RetentionClassWire(header.RetentionClass, header.EphBucket)
	if err != nil {
		advHarness(t, "%s's retention class for %s: %v", self.name, what, err)
	}
	recordBytes, err := message.EncodeRecord(record)
	if err != nil {
		advHarness(t, "%s encoding %s: %v", self.name, what, err)
	}
	request := &protocol.SubmitRequest{
		GroupId: self.groupId,
		Records: []*protocol.Record{{
			SenderHandle:   append([]byte{}, header.SenderHandle[:]...),
			Epoch:          header.Epoch,
			StreamIndex:    header.StreamIndex,
			IsCommit:       header.IsCommit,
			RetentionClass: uint32(retentionWire),
			SizeBucket:     uint32(header.SizeBucket),
			ExpireAtMs:     header.ExpireAt,
			BodyHash:       append([]byte{}, header.BodyHash[:]...),
			BlobId:         append([]byte{}, header.BlobId...),
			RecordBytes:    recordBytes,
		}},
	}
	// a wrap's target handle is a projection field too, which the server holds against the parse
	attachment, err := message.ParseServerAttachment(header.ServerAttachment)
	if err != nil {
		advHarness(t, "%s's attachment on %s: %v", self.name, what, err)
	}
	if attachment != nil && attachment.Wrap != nil {
		request.Records[0].WrapTargetHandle = append([]byte{}, attachment.Wrap.WrapTargetHandle...)
	}
	if delivery != nil {
		request.EpochKeys = []*protocol.EpochKeyDelivery{delivery}
	}
	response, err := self.transport.Call(ctx, request)
	if err != nil {
		advHarness(t, "%s submitting %s: %v", self.name, what, err)
	}
	if reason := response.GetReason(); reason != protocol.Reason_REASON_OK {
		advHarness(t, "%s's submit of %s was answered %v", self.name, what, reason)
	}
	if results := response.GetSubmit().GetResults(); len(results) != 1 || results[0].GetReason() != protocol.Reason_REASON_OK {
		advHarness(t, "%s's %s was answered %v; the server takes what it is handed", self.name, what, results)
	}
}

// seamHead is the nine octets of a record head: the version, then the time it was sealed.
func seamHead() []byte {
	head := make([]byte, 9)
	head[0] = 0x02
	binary.BigEndian.PutUint64(head[1:], uint64(time.Now().UnixMilli()))
	return head
}

// ── reading what the receivers did with one commit ───────────────────────────────────────────

// advVerdictOf is what every receiver did with the one commit just published, read off each: it
// FOLLOWED it, standing one epoch on with `followed` true of its roster; or it REFUSED it on a
// rule, standing where it was. The target of a removal follows by being removed, which is
// mls.ErrRemovedFromGroup. Anything else -- a receiver that failed for a reason that is no verdict
// on the commit -- is a harness failure, because it would read as a refusal that no rule made.
//
// When every receiver agrees the answer is one fact, `words[0]` for followed and `words[1]` for
// refused; when they do not, it is each receiver's own, "<word>@<receiver>", which no registry
// entry expects.
func advVerdictOf(t *testing.T, ctx context.Context, what string, words [2]string,
	receivers map[string]*urmessage.Group, target string,
	followed func(reader string, members []urmessage.Member) bool) []string {

	t.Helper()
	epochs := map[string]uint64{}
	for name, group := range receivers {
		epochs[name] = group.Epoch()
	}
	verdicts := map[string]string{}
	for name, group := range receivers {
		_, err := group.Receive(ctx)
		switch {
		case name == target && errors.Is(err, mls.ErrRemovedFromGroup):
			verdicts[name] = words[0]
		case err == nil:
			if got := group.Epoch(); got != epochs[name]+1 {
				advHarness(t, "%s answered nil over %s and stands at epoch %d, from %d: one commit was published", name, what, got, epochs[name])
			}
			if !followed(name, removalRoster(t, group)) {
				advHarness(t, "%s followed %s to epoch %d and its roster does not show what the commit did", name, what, group.Epoch())
			}
			verdicts[name] = words[0]
		case errors.Is(err, urmessage.ErrCommitUnauthorized):
			if got := group.Epoch(); got != epochs[name] {
				advHarness(t, "%s refused %s and stands at epoch %d, from %d", name, what, got, epochs[name])
			}
			verdicts[name] = words[1]
		default:
			advHarness(t, "%s's Receive over %s answered %v, which is no verdict on it", name, what, err)
		}
		t.Logf("%s: %s reads it as %s (%v)", what, name, verdicts[name], err)
	}
	agreed := ""
	for _, verdict := range verdicts {
		if agreed == "" {
			agreed = verdict
		} else if verdict != agreed {
			agreed = "split"
		}
	}
	if agreed != "split" {
		return []string{agreed}
	}
	facts := []string{}
	for name, verdict := range verdicts {
		facts = append(facts, verdict+"@"+name)
	}
	return advSet(facts)
}

// advHolds says whether a roster still holds a leaf.
func advHolds(members []urmessage.Member, leaf uint32) bool {
	for _, member := range members {
		if member.LeafIndex == leaf {
			return true
		}
	}
	return false
}

// advHoldsAt says whether a roster holds one identity at one leaf.
func advHoldsAt(members []urmessage.Member, leaf uint32, identity []byte) bool {
	for _, member := range members {
		if member.LeafIndex == leaf && bytes.Equal(member.IdentityPub, identity) {
			return true
		}
	}
	return false
}

// advOwnLeaf is the leaf a device holds in a group, off its own roster.
func advOwnLeaf(t *testing.T, group *urmessage.Group) uint32 {
	t.Helper()
	for _, member := range removalRoster(t, group) {
		if member.Mine {
			return member.LeafIndex
		}
	}
	advHarness(t, "the roster marks no leaf as this device's own")
	return 0
}

// advSiblingAdd has a real device add a further leaf of its OWN identity -- a seam member claiming
// it, which MASTER section 11's R6a and R7 let any member add -- and every member follow it.
func advSiblingAdd(t *testing.T, ctx context.Context, world *world, groups map[string]*urmessage.Group,
	by string, name string) *seamMember {

	t.Helper()
	sibling := world.seamMemberClaiming(t, ctx, name, rolesIdentityOf(t, groups[by]))
	invite, err := groups[by].AddMemberAndPublish(ctx, sibling.keyPackage(t))
	if err != nil {
		advHarness(t, "%s's AddMemberAndPublish of its own %s: %v", by, name, err)
	}
	sibling.join(t, gcReencodeInvite(t, invite))
	for reader, group := range groups {
		advSettle(t, ctx, reader, group, groups[by].Epoch())
	}
	return sibling
}

// ── 2. a sibling evicts a sibling ────────────────────────────────────────────────────────────

// A LATER LEAF OF ALICE'S IDENTITY REMOVES HER FIRST DEVICE, WHICH NOTHING HAS DROPPED. It is her
// laptop, a leaf she added herself, and its app is altered: the seam member, which skips the
// sending check and publishes a rotated removal of her first device's leaf. R2 and R7 let an
// identity remove its own leaves, so Bob and Carol follow it and Alice's first device is removed.
// Under R8-SIB a sibling's leaf is removed only once the newest list no longer names it, and every
// receiver refuses.
//
// THE CONTROL, FIRST, because the scenario's commit is the one that halts the group once it is
// refused: the same laptop removes Alice's phone, another leaf she added, and every member follows.
// It is a removal R8-SIB must let through once a base has dropped the phone. THIS TREE HAS NO
// DEVICE LIST, so nothing names the phone and nothing can drop it: the arm is the removal with
// nothing in front of it. Task 26, which brings R8-SIB, signs the base that drops the phone before
// it, and without that base this arm goes red there, which is what it is for.
func TestAdvSimASiblingRemovesASiblingTheListStillNames(t *testing.T) {
	world := newWorld(t)
	ctx := context.Background()
	devices := advConnected(t, ctx, world, "bob", "alice", "carol")
	groups := advConverse(t, ctx,
		advNamedDevice{"bob", devices["bob"]},
		advNamedDevice{"alice", devices["alice"]},
		advNamedDevice{"carol", devices["carol"]})
	aliceId := rolesIdentityOf(t, groups["alice"])
	aliceFirst := advOwnLeaf(t, groups["alice"])
	// the phone first and the laptop last, because a seam member follows no commit: the one that
	// acts is the one that joined at the epoch it acts at
	phone := advSiblingAdd(t, ctx, world, groups, "alice", "alice-phone")
	laptop := advSiblingAdd(t, ctx, world, groups, "alice", "alice-laptop")
	phoneLeaf := phone.handle.OwnLeafIndex()
	for reader, group := range groups {
		if held := removalLeavesOf(t, group, aliceId); len(held) != 3 {
			advHarness(t, "%s reads Alice's identity at %d leaves (%v), and the scene is her first device, her phone and her laptop", reader, len(held), held)
		}
	}
	words := [2]string{"removed:followed", "removed:refused"}

	// THE CONTROL: the laptop removes the phone
	commit, _, _, err := laptop.handle.CommitRemove([]uint32{phoneLeaf})
	if err != nil {
		advHarness(t, "the laptop's CommitRemove of the phone: %v", err)
	}
	laptop.publishRotated(t, ctx, "the laptop's removal of the phone", commit)
	control := advVerdictOf(t, ctx, "the laptop's removal of the phone", words, groups, "",
		func(reader string, members []urmessage.Member) bool {
			return !advHolds(members, phoneLeaf) && advHoldsAt(members, aliceFirst, aliceId)
		})
	if fmt.Sprint(control) != fmt.Sprint([]string{"removed:followed"}) {
		advHarness(t, "CONTROL FAILED: a sibling's removal of a sibling nothing names was read as %v, want [removed:followed]", control)
	}
	t.Logf("CONTROL: the laptop's removal of the phone was followed by Alice's first device, Bob and Carol")

	// THE SCENARIO: the laptop removes Alice's first device
	commit, _, _, err = laptop.handle.CommitRemove([]uint32{aliceFirst})
	if err != nil {
		advHarness(t, "the laptop's CommitRemove of Alice's first device: %v", err)
	}
	laptop.publishRotated(t, ctx, "the laptop's removal of Alice's first device", commit)
	advJudge(t, "I1-sibling-evicts-sibling", advVerdictOf(t, ctx, "the laptop's removal of Alice's first device",
		words, groups, "alice", func(reader string, members []urmessage.Member) bool {
			return !advHolds(members, aliceFirst) && len(removalLeavesOf(t, groups[reader], aliceId)) == 1
		}))
}

// ── 3. a copy adds a device unnoticed ────────────────────────────────────────────────────────

// advSaysOf is what one device says about a group after the commits in front of it, read off every
// surface this tree has for it, each as a fact: "noticed:receive-error" for a walk that answered
// an error, "noticed:identity-in-use" for the clone refusal ([urmessage.Group.IdentityInUse]), and
// "noticed:refused" for a commit it refused. A device that answers none of them is "alarm:none".
//
// THIS TREE HAS NO ALARM, and that is the gap. So the reading is of everything else the device
// could have said, and the commit that brings the alarm adds its own fact here.
//
// The precondition is that the addition REACHED it: its own roster holds `identity` at `leaf`, as
// another device's and not its own. A device that says nothing about a commit it never applied
// has said nothing about nothing.
func advSaysOf(t *testing.T, ctx context.Context, who string, group *urmessage.Group, refusedBefore uint64,
	leaf uint32, identity []byte) []string {

	t.Helper()
	facts := []string{}
	for round := 0; round < 16; round += 1 {
		before := group.Epoch()
		received, err := group.Receive(ctx)
		if err != nil {
			t.Logf("%s's Receive answered %v", who, err)
			facts = append(facts, "noticed:receive-error")
			break
		}
		if len(received) == 0 && group.Epoch() == before {
			break
		}
	}
	if group.IdentityInUse() != nil {
		facts = append(facts, "noticed:identity-in-use")
	}
	if group.Stats().CommitRefused != refusedBefore {
		facts = append(facts, "noticed:refused")
	}
	reached := false
	for _, member := range removalRoster(t, group) {
		if member.LeafIndex == leaf && bytes.Equal(member.IdentityPub, identity) && !member.Mine {
			reached = true
		}
	}
	if !reached && len(facts) == 0 {
		advHarness(t, "%s's roster does not hold the added device at leaf %d, and it said nothing: the addition never reached it", who, leaf)
	}
	if len(facts) == 0 {
		return []string{"alarm:none"}
	}
	return advSet(facts)
}

// A COPY OF ALICE'S FOLDER ADDS A DEVICE UNDER HER IDENTITY, AND THE ORIGINAL SAYS NOTHING. The
// copy is taken while the original runs, as a backup tool takes one, and is opened elsewhere. It
// is level with the original, so it reconciles, and through the production verb it adds a further
// leaf of Alice's identity, as R6a lets the identity's own device. The original follows that
// commit, holds the new device in its own roster, and answers nothing that says a copy of it
// acted. Under the identity layer it keeps a log of its own signatures, and a change signed with
// its key that it did not make raises the alarm.
//
// A COPY BEHIND THE ORIGINAL IS STOPPED ON THIS TREE, before it seals anything
// (TestACopiedAppDataFolderIsRefusedBeforeItSealsAnything): that is the other sequence. Here the
// original has sealed nothing in the group since the copy was taken, as when a device sits idle
// while its copy is used.
//
// THE CONTROL, FIRST: the original's own addition of a further leaf of its identity, read the same
// way, says nothing, and that stays true under the alarm.
func TestAdvSimACopyAddsADeviceAndTheOriginalSaysNothing(t *testing.T) {
	world := newWorld(t)
	ctx := context.Background()
	alice := world.newPersona(t, "alice")
	bob := world.newPersona(t, "bob")
	for _, who := range []*persona{alice, bob} {
		if err := who.device.Connect(ctx); err != nil {
			advHarness(t, "%s's Connect: %v", who.name, err)
		}
	}
	aliceGroup, bobGroup := openPair(t, ctx, alice, bob, newGroupId(t))
	groups := map[string]*urmessage.Group{"alice": aliceGroup, "bob": bobGroup}
	aliceId := rolesIdentityOf(t, aliceGroup)

	// THE CONTROL: the original adds a further device of its own
	refusedBefore := aliceGroup.Stats().CommitRefused
	tablet := advSiblingAdd(t, ctx, world, groups, "alice", "alice-tablet")
	if control := advSaysOf(t, ctx, "the original", aliceGroup, refusedBefore, tablet.handle.OwnLeafIndex(), aliceId); fmt.Sprint(control) != fmt.Sprint([]string{"alarm:none"}) {
		advHarness(t, "CONTROL FAILED: the original's own addition was read as %v, want [alarm:none]", control)
	}
	t.Logf("CONTROL: the original's own addition of its tablet says nothing")

	// THE COPY, taken while the original runs and holds both of its exclusions
	root := t.TempDir()
	copyState := filepath.Join(root, "alice-copy", "state")
	copyStream := filepath.Join(root, "alice-copy", "stream")
	copyAppData(t, alice.stateDir, copyState)
	copyAppData(t, alice.streamDir, copyStream)
	copied := world.durablePersona(t, "alice-copy", copyState, copyStream)
	if err := copied.device.Connect(ctx); err != nil {
		advHarness(t, "the copy's Connect: %v", err)
	}
	restored, err := copied.device.Restore(ctx)
	if err != nil || len(restored) != 1 {
		advHarness(t, "the copy's Restore answered %d group(s), %v", len(restored), err)
	}
	copyGroup := restored[0]
	// a restored group listens before it seals: its first walk reconciles its stream position
	if _, err := copyGroup.Receive(ctx); err != nil {
		advHarness(t, "the copy's reconciling Receive: %v", err)
	}
	advSettle(t, ctx, "the copy", copyGroup, aliceGroup.Epoch())
	if inUse := copyGroup.IdentityInUse(); inUse != nil {
		advHarness(t, "the copy was refused as a clone (%v), and this scene is the copy that is level", inUse)
	}

	// THE SCENARIO: the copy adds a device under Alice's identity
	refusedBefore = aliceGroup.Stats().CommitRefused
	phone := world.seamMemberClaiming(t, ctx, "alice-phone", aliceId)
	invite, err := copyGroup.AddMemberAndPublish(ctx, phone.keyPackage(t))
	if err != nil {
		advHarness(t, "the copy's AddMemberAndPublish of a device under Alice's identity: %v", err)
	}
	phone.join(t, gcReencodeInvite(t, invite))
	advSettle(t, ctx, "bob", bobGroup, copyGroup.Epoch())
	if held := removalLeavesOf(t, bobGroup, aliceId); len(held) != 3 {
		advHarness(t, "bob reads Alice's identity at %d leaves (%v) after the copy's addition, want 3", len(held), held)
	}
	advJudge(t, "I1-copy-adds-unnoticed", advSaysOf(t, ctx, "the original", aliceGroup, refusedBefore,
		phone.handle.OwnLeafIndex(), aliceId))
}

// ── 4. an unbound key package is admitted ────────────────────────────────────────────────────

// seamIdentityAt is the identity a seam member's own tree holds at one leaf.
func seamIdentityAt(t *testing.T, member *seamMember, leaf uint32) []byte {
	t.Helper()
	for at := 0; at < member.handle.MemberCount(); at += 1 {
		held, identity, _, err := member.handle.MemberAt(at)
		if err != nil {
			advHarness(t, "%s's member %d: %v", member.name, at, err)
		}
		if held == leaf {
			return append([]byte(nil), identity...)
		}
	}
	advHarness(t, "%s's tree holds no leaf %d", member.name, leaf)
	return nil
}

// THE HARNESS'S ATTACKER ADDS A KEY PACKAGE THAT NAMES NO IDENTITY, AND EVERY RECEIVER ADMITS IT.
// The attacker is a further leaf of the owner's own identity, which she added herself, with an
// altered app: the seam member, which skips the Add door and the sending check and publishes what
// it builds. No key package on this tree names an identity, since none carries the identity
// extension, so the one it adds -- a stranger's, made by the seam's own engine -- is admitted by
// Alice's first device and by Bob. Under R6e every receiver refuses a leaf that no identity binds.
// The attacker is the adder because an honest adder's Add door refuses such a package first once
// that door checks the binding, and R6e, the rule this pins, would then never be reached (the
// plan's red team, M3).
//
// THE CONTROL, FIRST, since a refused commit halts the group: the same attacker adds Carol's key
// package, a real device's, and both receivers admit it. On this tree that package is bound to
// nothing either. From the commit that makes every device's key package carry the identity
// extension (Task 12) it is a bound one, so this arm is the plan's control there with no edit here.
func TestAdvSimAnUnboundKeyPackageIsAdmittedByEveryReceiver(t *testing.T) {
	world := newWorld(t)
	ctx := context.Background()
	devices := advConnected(t, ctx, world, "alice", "bob", "carol")
	groups := advConverse(t, ctx,
		advNamedDevice{"alice", devices["alice"]},
		advNamedDevice{"bob", devices["bob"]})
	attacker := advSiblingAdd(t, ctx, world, groups, "alice", "alice-tablet")
	words := [2]string{"admitted", "refused"}

	// THE CONTROL: the attacker adds a real device's key package
	carolKeyPackage, err := devices["carol"].KeyPackage()
	if err != nil {
		advHarness(t, "carol's KeyPackage: %v", err)
	}
	// AND IT IS A BOUND ONE (identity phase 1's Task 12; LRI R62): it carries a 0xF005 binding its key
	// to the identity Carol's words made, and that identity's list names the key
	carolDecoded, carolVerified, err := keyPackageIdentity(t, carolKeyPackage)
	if err != nil {
		advHarness(t, "carol's key package does not bind: %v", err)
	}
	if named := world.identityClaimed(t, carolDecoded.LeafNode.Credential.Identity); named.name != "carol" {
		advHarness(t, "carol's key package names %s's identity", named.name)
	}
	if !slices.ContainsFunc(carolVerified.Devices, func(entry messagegroup.DeviceEntry) bool {
		return bytes.Equal(entry.DeviceKey, carolDecoded.LeafNode.SignatureKey)
	}) {
		advHarness(t, "carol's key package's list does not name the key it is signed with")
	}
	commit, _, _, err := attacker.handle.CommitAdd([][]byte{carolKeyPackage})
	if err != nil {
		advHarness(t, "the attacker's CommitAdd of carol's key package: %v", err)
	}
	added := attacker.publishRotated(t, ctx, "the attacker's addition of carol", commit)
	if len(added) != 1 {
		advHarness(t, "the attacker's addition of carol added leaves %v, want one", added)
	}
	carolLeaf, carolId := added[0], seamIdentityAt(t, attacker, added[0])
	control := advVerdictOf(t, ctx, "the attacker's addition of carol", words, groups, "",
		func(reader string, members []urmessage.Member) bool { return advHoldsAt(members, carolLeaf, carolId) })
	if fmt.Sprint(control) != fmt.Sprint([]string{"admitted"}) {
		advHarness(t, "CONTROL FAILED: the attacker's addition of a real device's key package was read as %v, want [admitted]", control)
	}
	t.Logf("CONTROL: the attacker's addition of carol's key package was admitted by Alice's first device and by Bob")

	// THE SCENARIO: the attacker adds a key package that names no identity. From identity phase 1's
	// Task 12 every seam member's package is bound, this one included, and Task 13 builds it without
	// 0xF005 on purpose and asserts so before the add (LRI R62)
	stranger := world.seamMember(t, ctx, "stranger")
	commit, _, _, err = attacker.handle.CommitAdd([][]byte{stranger.keyPackage(t)})
	if err != nil {
		advHarness(t, "the attacker's CommitAdd of the stranger's key package: %v", err)
	}
	added = attacker.publishRotated(t, ctx, "the attacker's addition of the stranger", commit)
	if len(added) != 1 {
		advHarness(t, "the attacker's addition of the stranger added leaves %v, want one", added)
	}
	strangerLeaf := added[0]
	advJudge(t, "I1-unbound-key-package-admitted", advVerdictOf(t, ctx, "the attacker's addition of the stranger",
		words, groups, "", func(reader string, members []urmessage.Member) bool {
			return advHoldsAt(members, strangerLeaf, stranger.identityPub)
		}))
}
