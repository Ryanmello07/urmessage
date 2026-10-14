package urmessage

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"sort"
	"strings"
	"testing"

	"github.com/urnetwork/message/messagegroup"
	"github.com/urnetwork/message/mls"
	"github.com/urnetwork/message/syntax"
)

// WHICH GROUPS THIS BUILD OPENS AT ALL. Every group this build founds requires the join seal of
// its members, and the engine does not let its caller choose otherwise; so a group that does not
// require it is made here by hand, through connect/mls, to stand for one an earlier build founded.

// handFounded is a group founded THROUGH connect/mls AND NOT THROUGH THIS PACKAGE OR THE ENGINE,
// with one joiner added, and the version 3 invite a member of it makes for that joiner.
type handFounded struct {
	invite         *Invite
	pqSecret       []byte
	groupHandleKey []byte
}

// foundByHand founds a group whose context REQUIRES exactly the capabilities the caller lists, and
// adds one join code to it. It exists because the engine does not let its caller choose that
// list: every group the engine founds requires the join seal, so a group that does not can only
// be made beside it.
func foundByHand(t *testing.T, groupId []byte, required []mls.ExtensionType, joinCode []byte) *handFounded {
	t.Helper()
	crypto, err := mls.NewCryptoProvider(deviceCipherSuite)
	if err != nil {
		t.Fatalf("the crypto provider: %v", err)
	}
	signer, signerPub, err := crypto.SignatureKeyPair()
	if err != nil {
		t.Fatalf("the signature key pair: %v", err)
	}
	leafKeysBody, _ := mintLeafKeys(t)
	leafKeys, err := mls.ParseLeafKeysExtension(leafKeysBody)
	if err != nil {
		t.Fatalf("the founder's leaf keys: %v", err)
	}
	policy := &mls.GroupPolicyExtension{Roles: []mls.RoleEntry{{MemberId: signerPub, Role: mls.RoleOwner}}}
	if err := policy.Canonicalize(); err != nil {
		t.Fatalf("the group policy: %v", err)
	}
	encodedPolicy, err := policy.Encode()
	if err != nil {
		t.Fatalf("the group policy: %v", err)
	}
	group, err := mls.NewGroup(&mls.GroupConfig{
		Suite:   crypto.Suite(),
		GroupId: groupId,
		Extensions: []mls.Extension{{
			ExtensionType: mls.ExtensionTypeUrmessageGroupPolicy,
			ExtensionData: encodedPolicy.ExtensionData,
		}},
		RequiredCaps: mls.RequiredCapabilities{ExtensionTypes: required},
		Crypto:       crypto,
		Store:        NewMemoryStateStore(),
		LeafKeys:     *leafKeys,
	}, signer, mls.BasicCredential(signerPub))
	if err != nil {
		t.Fatalf("mls.NewGroup requiring %v: %v", required, err)
	}
	t.Cleanup(func() { group.Close() })
	decoded := &mls.KeyPackage{}
	if err := syntax.Unmarshal(joinCode, decoded); err != nil {
		t.Fatalf("decoding the join code: %v", err)
	}
	result, err := group.CreateCommit([][]byte{}, []mls.Proposal{{
		ProposalType: mls.ProposalTypeAdd,
		Add:          &mls.Add{KeyPackage: *decoded},
	}}, nil)
	if err != nil {
		t.Fatalf("the hand founder's commit adding the join code: %v", err)
	}
	if err := group.MergePendingCommit(); err != nil {
		t.Fatalf("the hand founder's merge: %v", err)
	}
	leaf, err := joinerLeafIn(result.RatchetTree, decoded)
	if err != nil {
		t.Fatalf("joinerLeafIn: %v", err)
	}
	joinerLeafKeys, err := mls.LeafKeysOf(&decoded.LeafNode)
	if err != nil {
		t.Fatalf("the joiner's leaf keys: %v", err)
	}
	xwing, err := messagegroup.ParseXwingPublicKey(joinerLeafKeys.DeviceXwingPub)
	if err != nil {
		t.Fatalf("the joiner's x-wing key: %v", err)
	}
	pqSecret, groupHandleKey := make([]byte, 32), make([]byte, 32)
	if _, err := rand.Read(pqSecret); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(groupHandleKey); err != nil {
		t.Fatal(err)
	}
	mlsSecret, err := group.Export(storageExporterLabel, nil, storageExporterBytes)
	if err != nil {
		t.Fatalf("the hand founder's storage exporter: %v", err)
	}
	digest, err := epochKeysDigestOver(groupId, group.Epoch(), mlsSecret, pqSecret)
	if err != nil {
		t.Fatalf("epochKeysDigestOver: %v", err)
	}
	payload, err := encodeJoinSecrets(pqSecret, groupHandleKey, digest)
	if err != nil {
		t.Fatalf("encodeJoinSecrets: %v", err)
	}
	seal, err := messagegroup.SealWrapBody(rand.Reader, xwing, messagegroup.WrapEnvelope{
		FormatVersion: messagegroup.WrapFormatVersion,
		TargetType:    wrapTargetTypeJoiner,
		PayloadType:   wrapPayloadTypeJoinSecrets,
	}, groupId, joinerLeafId(leaf), payload)
	if err != nil {
		t.Fatalf("the hand founder's SealWrapBody: %v", err)
	}
	joinKey, err := group.Export(joinKeyExporterLabel, joinerLeafId(leaf), joinKeyBytes)
	if err != nil {
		t.Fatalf("the hand founder's join key: %v", err)
	}
	preimage, err := joinAuthPreimage(groupId, group.Epoch(), leaf, result.Welcome, result.RatchetTree, seal)
	if err != nil {
		t.Fatalf("joinAuthPreimage: %v", err)
	}
	return &handFounded{
		invite: &Invite{
			GroupId:     bytes.Clone(groupId),
			Welcome:     result.Welcome,
			RatchetTree: result.RatchetTree,
			JoinSeal:    seal,
			JoinAuth:    crypto.Mac(joinKey, preimage),
		},
		pqSecret:       pqSecret,
		groupHandleKey: groupHandleKey,
	}
}

var (
	requiredBeforeTheJoinSeal = []mls.ExtensionType{mls.ExtensionTypeUrmessageGroupPolicy, mls.ExtensionTypeUrmessageLeafKeys}
	requiredWithTheJoinSeal   = []mls.ExtensionType{mls.ExtensionTypeUrmessageGroupPolicy, mls.ExtensionTypeUrmessageLeafKeys, mls.ExtensionTypeUrmessageJoinSeal}
)

// ONLY A GROUP THAT REQUIRES THE JOIN SEAL IS JOINED. The invite is at version 3 and everything in
// it is right: a valid join_auth, a seal that opens, a digest that reproduces. The one thing wrong
// is the group, whose context requires what a build before the join seal required and no more. It
// is refused inside the window, by name, and the join code is not spent.
//
// THE CONTROL IS THE SAME FOUNDER REQUIRING THE SEAL, OVER THE SAME JOIN CODE: it joins. So the
// refusal above is the missing requirement and nothing else about a group founded by hand; and
// the join code was still there to be used.
func TestOnlyAGroupThatRequiresTheJoinSealIsJoined(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStateStore()
	joiner := newAnsweringDeviceOver(t, store, []byte("the joiner's nonce"))
	joinCode, err := joiner.KeyPackage()
	if err != nil {
		t.Fatalf("the joiner's KeyPackage: %v", err)
	}
	groupId := bytes.Repeat([]byte{0x47}, GroupIdBytes)

	before := foundByHand(t, groupId, requiredBeforeTheJoinSeal, joinCode)
	_, err = joiner.Join(ctx, before.invite)
	if !errors.Is(err, ErrGroupPredatesJoinSeal) {
		t.Fatalf("an invite into a group that does not require the join seal answered %v, want ErrGroupPredatesJoinSeal", err)
	}
	if !errors.Is(err, ErrJoinRefused) || errors.Is(err, ErrJoinCodeSpent) {
		t.Errorf("that refusal is %v, which is not one made inside the window that leaves the join code", err)
	}
	if held := len(joiner.Groups()); held != 0 {
		t.Fatalf("the refused invite left the joiner holding %d group(s)", held)
	}
	if _, err := store.GetGroupState(groupId, 1); !errors.Is(err, ErrStateNotFound) {
		t.Fatalf("the refused invite left a state in the store: %v", err)
	}

	sealed := foundByHand(t, groupId, requiredWithTheJoinSeal, joinCode)
	if _, err := joiner.Join(ctx, sealed.invite); err != nil {
		t.Fatalf("CONTROL FAILED: the same founder requiring the join seal, over the same join code, answered %v", err)
	}
}

// A GROUP FOUNDED BEFORE THE JOIN SEAL IS NOT RESTORED, AND IT CAN BE LEFT. The group is put on
// the disk the only way it can get there in this build, which is around [Device.Join]: the engine
// joins the hand founder's welcome and the record is written beside it. That is what a state
// directory an earlier build wrote looks like to this one. After a restart, Restore answers
// [ErrGroupPredatesJoinSeal] inside [ErrRestore] and holds nothing, and ForgetGroup leaves it.
//
// THE CONTROL IS THE FIRST ROW: the same planting for a group that requires the seal restores. So
// a planted group is restorable, and the second row's refusal is the requirement's.
func TestAGroupFoundedBeforeTheJoinSealIsNotRestoredAndCanBeLeft(t *testing.T) {
	ctx := context.Background()
	groupId := bytes.Repeat([]byte{0x47}, GroupIdBytes)
	for _, one := range []struct {
		name     string
		required []mls.ExtensionType
		want     error
	}{
		{"a group that requires the join seal", requiredWithTheJoinSeal, nil},
		{"a group founded before the join seal", requiredBeforeTheJoinSeal, ErrGroupPredatesJoinSeal},
	} {
		dir := t.TempDir()
		durable, err := OpenDurableStateStore(dir)
		if err != nil {
			t.Fatalf("%s: OpenDurableStateStore: %v", one.name, err)
		}
		device := newAnsweringDeviceOver(t, durable, []byte("the device's nonce"))
		joinCode, err := device.KeyPackage()
		if err != nil {
			t.Fatalf("%s: KeyPackage: %v", one.name, err)
		}
		founded := foundByHand(t, groupId, one.required, joinCode)
		handle, err := device.engine.JoinFromWelcomeInto(founded.invite.Welcome, founded.invite.RatchetTree, groupId)
		if err != nil {
			t.Fatalf("%s: planting the joined state through the engine: %v", one.name, err)
		}
		handle.Close()
		if err := durable.PutGroupRecord(&GroupRecord{
			GroupId:        groupId,
			Epoch:          1,
			PqSecret:       founded.pqSecret,
			GroupHandleKey: founded.groupHandleKey,
			Opened:         true,
		}); err != nil {
			t.Fatalf("%s: planting the record: %v", one.name, err)
		}
		device.Close()
		if err := durable.Close(); err != nil {
			t.Fatalf("%s: closing the store before the restart: %v", one.name, err)
		}

		reopened, err := OpenDurableStateStore(dir)
		if err != nil {
			t.Fatalf("%s: reopening the store: %v", one.name, err)
		}
		t.Cleanup(func() { reopened.Close() })
		restarted := newAnsweringDeviceOver(t, reopened, []byte("the device's nonce"))
		groups, err := restarted.Restore(ctx)
		if one.want == nil {
			if err != nil || len(groups) != 1 {
				t.Fatalf("CONTROL FAILED: %s restored %d group(s), %v: a planted group is not restorable, so the row below proves nothing", one.name, len(groups), err)
			}
			continue
		}
		if len(groups) != 0 || !errors.Is(err, ErrRestore) || !errors.Is(err, one.want) {
			t.Fatalf("%s restored %d group(s) and answered %v, want none and %v inside ErrRestore", one.name, len(groups), err, one.want)
		}
		if err := restarted.ForgetGroup(groupId); err != nil {
			t.Fatalf("%s: ForgetGroup of the group Restore refused: %v", one.name, err)
		}
		records, err := reopened.GroupRecords()
		if err != nil || len(records) != 0 {
			t.Fatalf("%s: the store holds %d record(s) after the group was left: %v", one.name, len(records), err)
		}
	}
}

// THE JOIN SEAL HELD FROM THE MEMBER'S SIDE. The cases in joinseal_test.go bend an honest invite or
// forge one from outside; a forger outside the group cannot make join_auth, so none of them gets
// past the authenticator. The checks behind it -- the open, the payload's shape and the digest --
// are reached only by an invite whose join_auth is VALID, and a valid one is made only by a member.
// So the invites below are made by one.

// memberInvite is an invite a MEMBER of the join epoch could make for the pair's joiner: the
// pair's own welcome and tree, a seal of the caller's payload to a key of the caller's, and a
// join_auth that IS valid for that seal, under the join epoch's own exporter off the founder's
// handle. With sealTo nil the seal is made to the joiner's own published key.
func memberInvite(t *testing.T, pair *sealPair, sealTo *messagegroup.XwingPublicKey, payload []byte) *Invite {
	t.Helper()
	joiner, err := pair.alice.joinerOf(pair.joinCode)
	if err != nil {
		t.Fatalf("joinerOf: %v", err)
	}
	leaf, err := joinerLeafIn(pair.invite.RatchetTree, joiner.keyPackage)
	if err != nil {
		t.Fatalf("joinerLeafIn: %v", err)
	}
	if sealTo == nil {
		sealTo = joiner.xwing
	}
	seal, err := messagegroup.SealWrapBody(pair.alice.random, sealTo, messagegroup.WrapEnvelope{
		FormatVersion: messagegroup.WrapFormatVersion,
		TargetType:    wrapTargetTypeJoiner,
		PayloadType:   wrapPayloadTypeJoinSecrets,
	}, pair.invite.GroupId, joinerLeafId(leaf), payload)
	if err != nil {
		t.Fatalf("the member's SealWrapBody: %v", err)
	}
	// the founder's handle stands at epoch one once AddMember has merged, so this is the exporter
	// of the epoch the joiner is admitted at
	joinKey, err := pair.aliceGroup.handle.Export(joinKeyExporterLabel, joinerLeafId(leaf), joinKeyBytes)
	if err != nil {
		t.Fatalf("the member's join key: %v", err)
	}
	preimage, err := joinAuthPreimage(pair.invite.GroupId, 1, leaf, pair.invite.Welcome, pair.invite.RatchetTree, seal)
	if err != nil {
		t.Fatalf("joinAuthPreimage: %v", err)
	}
	return &Invite{
		GroupId:     bytes.Clone(pair.invite.GroupId),
		Welcome:     bytes.Clone(pair.invite.Welcome),
		RatchetTree: bytes.Clone(pair.invite.RatchetTree),
		JoinSeal:    seal,
		JoinAuth:    pair.alice.crypto.Mac(joinKey, preimage),
	}
}

// A SEAL A MEMBER MADE IS STILL HELD TO ITS EPOCH, ITS SHAPE AND ITS ADDRESSEE, INSIDE THE WINDOW.
// Every invite here carries a valid join_auth, so each is refused by a check that stands BEHIND
// the authenticator: a secret that does not reproduce the digest sealed beside it, a digest that
// is not this epoch's, an all-zero secret, and a seal made to somebody else's key. After all of
// them the device holds nothing, and the join code is not spent.
//
// THE CONTROL IS THE LAST JOIN: a member-made invite carrying the three TRUE values joins, over the
// same join code. It proves two things at once: the authenticator this helper makes is one the
// joiner accepts, so every refusal above was made behind it; and five refusals cost nothing.
//
// WHAT WOULD GO RED: drop the comparison of the recomputed digest with the sealed one, and the
// first two rows install a secret that is not the epoch's, with the join code spent on it.
func TestAMemberMadeSealIsHeldToItsEpochItsShapeAndItsAddressee(t *testing.T) {
	pair := newSealPair(t)
	truePq := bytes.Clone(pair.aliceGroup.pqSecrets[1])
	trueGhk := bytes.Clone(pair.aliceGroup.groupHandleKey)
	trueDigest := bytes.Clone(pair.aliceGroup.foundingJoinDigest)
	if len(truePq) != 32 || len(trueGhk) != 32 || len(trueDigest) != sha256.Size {
		t.Fatalf("CONTROL FAILED: the founder holds %d, %d and %d octets for the secret, the handle key and the digest", len(truePq), len(trueGhk), len(trueDigest))
	}
	payload := func(pq []byte, ghk []byte, digest []byte) []byte {
		return append(append(bytes.Clone(pq), ghk...), digest...)
	}
	carol, _ := newAnsweringDevice(t, 0, []byte("carol's nonce"))
	carolCode, err := carol.KeyPackage()
	if err != nil {
		t.Fatalf("carol's KeyPackage: %v", err)
	}
	carolKeys, err := pair.alice.joinerOf(carolCode)
	if err != nil {
		t.Fatalf("joinerOf(carol): %v", err)
	}
	other := bytes.Repeat([]byte{0xA7}, 32)

	for _, one := range []struct {
		name   string
		invite *Invite
		want   error
	}{
		{"another secret beside this epoch's digest",
			memberInvite(t, pair, nil, payload(other, trueGhk, trueDigest)), ErrJoinSealWrongEpoch},
		{"this epoch's secret beside another digest",
			memberInvite(t, pair, nil, payload(truePq, trueGhk, other)), ErrJoinSealWrongEpoch},
		{"an all-zero secret",
			memberInvite(t, pair, nil, payload(make([]byte, 32), trueGhk, trueDigest)), ErrJoinSealUnreadable},
		{"an all-zero handle key",
			memberInvite(t, pair, nil, payload(truePq, make([]byte, 32), trueDigest)), ErrJoinSealUnreadable},
		{"the true values, sealed to another device's key",
			memberInvite(t, pair, carolKeys.xwing, payload(truePq, trueGhk, trueDigest)), ErrJoinSealUnreadable},
	} {
		_, err := pair.bob.Join(pair.ctx, one.invite)
		if !errors.Is(err, one.want) {
			t.Errorf("%s answered %v, want %v", one.name, err, one.want)
		}
		if !errors.Is(err, ErrJoinRefused) || errors.Is(err, ErrJoinCodeSpent) {
			t.Errorf("%s answered %v, which is not a refusal inside the window that leaves the join code", one.name, err)
		}
		if held := len(pair.bob.Groups()); held != 0 {
			t.Fatalf("%s left bob holding %d group(s)", one.name, held)
		}
	}
	// THE CONTROL, and the join code's survival
	group, err := pair.bob.Join(pair.ctx, memberInvite(t, pair, nil, payload(truePq, trueGhk, trueDigest)))
	if err != nil {
		t.Fatalf("CONTROL FAILED: a member-made invite carrying the true values answered %v, so the refusals above may be the authenticator's and not the checks behind it", err)
	}
	if !bytes.Equal(group.pqSecrets[1], truePq) || !bytes.Equal(group.groupHandleKey, trueGhk) {
		t.Fatalf("the joiner does not hold the two values the member sealed")
	}
}

// EVERY OCTET OF AN INVITE IS HELD BY SOME AUTHORITY, AND NO REFUSAL COSTS THE JOIN CODE. One bit
// of each octet of an encoded invite is flipped in turn, and the checksum is recomputed over the
// result, as anybody on the paste channel can: so the checksum, which is not an authentication,
// never does the refusing here. Each bent invite is parsed and joined, and four things are held
// for every one of them: it does not join; it is refused by a named authority; a refusal made
// inside the join's window says so and does not say the join code is spent; and the join code is
// still in the store. At the end the honest invite joins over it.
//
// ONE REFUSAL INSIDE THE WINDOW DOES NOT SAY SO, AND IS HELD TO ITS FIELD. A bit flipped in the
// reference by which the Welcome addresses a join code makes it a Welcome no join code of this
// device was made for. The engine takes nothing, and the answer is [ErrNoJoinCodeForInvite], which
// must NOT say the join code is not spent: the same answer is what an invite gets once its join
// code really has gone. Here the join code has not gone, and the count after it shows that.
//
// THE TABLE IT PRINTS is the authority that refused each field's octets. Five things in it are
// asserted: it accounts for every octet; every octet of the authenticator, and every octet of the
// seal past its envelope, is refused by the authenticator; every octet of the envelope is
// refused at the paste as the seal's shape; and the refusal for a join code this device does not
// hold comes from the welcome and from no other field, and does come.
func TestEveryOctetOfAnInviteIsHeldAndNoRefusalCostsTheJoinCode(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStateStore()
	joiner := newAnsweringDeviceOver(t, store, []byte("the joiner's nonce"))
	honest, groupId := windowInvite(t, joiner)
	encoded, err := honest.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	body := encoded[:len(encoded)-sha256.Size]
	// the fields, by where each begins: u16 version, then five u32-length-prefixed fields
	type span struct {
		name       string
		start, end int
	}
	spans := []span{{"version", 0, 2}}
	at := 2
	for _, field := range []struct {
		name   string
		octets []byte
	}{{"group id", honest.GroupId}, {"welcome", honest.Welcome}, {"ratchet tree", honest.RatchetTree},
		{"join seal", honest.JoinSeal}, {"join auth", honest.JoinAuth}} {
		spans = append(spans, span{"length of " + field.name, at, at + 4})
		spans = append(spans, span{field.name, at + 4, at + 4 + len(field.octets)})
		at += 4 + len(field.octets)
	}
	if at != len(body) {
		t.Fatalf("CONTROL FAILED: the fields end at octet %d and the invite's body is %d octets, so the table below would name the wrong fields", at, len(body))
	}
	fieldOf := func(index int) string {
		for _, one := range spans {
			if one.start <= index && index < one.end {
				return one.name
			}
		}
		return "?"
	}
	tally := map[string]map[string]int{}
	note := func(field string, authority string) {
		if tally[field] == nil {
			tally[field] = map[string]int{}
		}
		tally[field][authority] += 1
	}
	joinCodes := func() int {
		store.lock.Lock()
		defer store.lock.Unlock()
		return len(store.keyPackages)
	}
	if held := joinCodes(); held != 1 {
		t.Fatalf("CONTROL FAILED: the joiner's store holds %d join code(s) before anything was pasted, want 1", held)
	}
	for index := range body {
		bent := bytes.Clone(body)
		bent[index] ^= 0x01
		sum := sha256.Sum256(bent)
		field := fieldOf(index)
		invite, err := ParseInvite(append(bent, sum[:]...))
		if err != nil {
			switch {
			case errors.Is(err, ErrInviteVersion):
				note(field, "the paste: ErrInviteVersion")
			case errors.Is(err, ErrJoinSealShape):
				note(field, "the paste: ErrJoinSealShape")
			case errors.Is(err, ErrInviteDamaged):
				// the checksum was recomputed over the bent octets, so it holds, and "damaged" is
				// the checksum's own name
				t.Fatalf("octet %d (%s): refused as damaged under a checksum that covers it: %v", index, field, err)
			default:
				note(field, "the paste: its framing")
			}
			continue
		}
		_, err = joiner.Join(ctx, invite)
		if err == nil {
			t.Fatalf("octet %d (%s): an invite with one bit flipped JOINED", index, field)
		}
		if errors.Is(err, ErrJoinCodeSpent) {
			t.Fatalf("octet %d (%s): the refusal says the join code is spent: %v", index, field, err)
		}
		switch {
		case errors.Is(err, ErrNoJoinCodeForInvite):
			// THE ONE REFUSAL INSIDE THE WINDOW THAT DOES NOT CARRY ITS SENTENCE. The bit was in the
			// reference the Welcome addresses a join code by, so the Welcome now names a join code
			// this device does not hold, and the engine took nothing. It is held to the one field
			// it can come from, and it must not say the join code is not spent; the join code is
			// counted below like after every other refusal, and it is still there.
			if field != "welcome" {
				t.Fatalf("octet %d (%s): refused as an invite no join code of this device was made for, and only the welcome addresses one: %v", index, field, err)
			}
			if errors.Is(err, ErrJoinRefused) || strings.Contains(err.Error(), "the join code is not spent") {
				t.Fatalf("octet %d (%s): the refusal for a join code this device does not hold also says the join code is not spent: %v", index, field, err)
			}
			note(field, "in the window: no join code of this device is addressed")
		case !errors.Is(err, ErrJoinRefused):
			t.Fatalf("octet %d (%s): an invite that parsed was refused with %v, which is not a refusal inside the window", index, field, err)
		case !strings.HasPrefix(err.Error(), ErrJoinRefused.Error()+": "):
			t.Fatalf("octet %d (%s): the refusal %q does not begin with the window's sentence", index, field, err)
		case errors.Is(err, ErrJoinSealUnauthenticated):
			note(field, "in the window: ErrJoinSealUnauthenticated")
		case errors.Is(err, ErrJoinSealUnreadable), errors.Is(err, ErrJoinSealWrongEpoch):
			t.Fatalf("octet %d (%s): a bent invite got past the authenticator and was refused behind it: %v", index, field, err)
		default:
			note(field, "in the window: the engine")
		}
		if held := joinCodes(); held != 1 {
			t.Fatalf("octet %d (%s): the joiner's store holds %d join code(s) after the refusal, want 1: the refusal cost the join code", index, field, held)
		}
		if held := len(joiner.Groups()); held != 0 {
			t.Fatalf("octet %d (%s): the joiner holds %d group(s) after a refusal", index, field, held)
		}
	}
	if _, err := store.GetGroupState(groupId, 1); !errors.Is(err, ErrStateNotFound) {
		t.Fatalf("%d refused invites left a state in the store: %v", len(body), err)
	}

	total := 0
	for _, one := range spans {
		authorities := []string{}
		for authority, count := range tally[one.name] {
			authorities = append(authorities, authority)
			total += count
		}
		sort.Strings(authorities)
		for _, authority := range authorities {
			t.Logf("%-22s %5d octet(s)  %s", one.name, tally[one.name][authority], authority)
		}
	}
	if total != len(body) {
		t.Fatalf("the table accounts for %d octets and the invite's body is %d", total, len(body))
	}
	if got := tally["welcome"]["in the window: no join code of this device is addressed"]; got == 0 {
		t.Errorf("no octet of the welcome was refused as addressing a join code this device does not hold, so the arm above that holds that refusal to its field was never reached")
	}
	if got := tally["join auth"]["in the window: ErrJoinSealUnauthenticated"]; got != len(honest.JoinAuth) {
		t.Errorf("%d of the authenticator's %d octets were refused by the authenticator", got, len(honest.JoinAuth))
	}
	pastEnvelope := len(honest.JoinSeal) - messagegroup.WrapEnvelopeBytes
	if got := tally["join seal"]["in the window: ErrJoinSealUnauthenticated"]; got != pastEnvelope {
		t.Errorf("%d of the %d seal octets past its envelope were refused by the authenticator", got, pastEnvelope)
	}
	if got := tally["join seal"]["the paste: ErrJoinSealShape"]; got != messagegroup.WrapEnvelopeBytes {
		t.Errorf("%d of the envelope's %d octets were refused as the seal's shape", got, messagegroup.WrapEnvelopeBytes)
	}

	// THE JOIN CODE SURVIVED EVERY ONE OF THEM
	if _, err := joiner.Join(ctx, honest); err != nil {
		t.Fatalf("the honest invite after %d refused ones answered %v", len(body), err)
	}
}
