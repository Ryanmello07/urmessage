package urmessage

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
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
