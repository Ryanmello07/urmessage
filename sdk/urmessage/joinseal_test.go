package urmessage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"sync/atomic"
	"testing"
	"time"

	"github.com/urnetwork/connect"
	connectprotocol "github.com/urnetwork/connect/protocol"
	"github.com/urnetwork/message/mls"
	messageprotocol "github.com/urnetwork/message/protocol"
	"github.com/urnetwork/message/sdk"
	"github.com/urnetwork/message/syntax"
)

// THE JOIN SEAL'S FORMATS, as octets a second implementation can check, and the seal itself from
// the task that makes it on.

// THE PREIMAGE, AS OCTETS A SECOND IMPLEMENTATION CAN CHECK. Every input is fixed, the expected
// preimage is written out field by field here rather than produced by the function under test, and
// its SHA-256 is pinned beside it.
func TestTheJoinAuthPreimageIsThese181Octets(t *testing.T) {
	groupId := bytes.Repeat([]byte{0xA0}, GroupIdBytes)
	welcome := []byte("the welcome")
	ratchetTree := []byte("the ratchet tree")
	joinSeal := []byte("the join seal")
	got, err := joinAuthPreimage(groupId, 7, 3, welcome, ratchetTree, joinSeal)
	if err != nil {
		t.Fatalf("joinAuthPreimage: %v", err)
	}

	hashOf := func(octets []byte) []byte {
		sum := sha256.Sum256(octets)
		return sum[:]
	}
	lengthOf32 := []byte{0x00, 0x00, 0x00, 0x20}
	want := []byte("URmessage/v1/joinauth")
	want = append(want, 0x00, 0x41)                                    // alg_id: HMAC-SHA-256
	want = append(want, 0x00, 0x03)                                    // invite_version
	want = append(append(want, lengthOf32...), groupId...)             // LP(group_id)
	want = append(want, 0, 0, 0, 0, 0, 0, 0, 7)                        // u64(epoch)
	want = append(want, 0, 0, 0, 3)                                    // u32(joiner_leaf)
	want = append(append(want, lengthOf32...), hashOf(welcome)...)     // LP(H(welcome))
	want = append(append(want, lengthOf32...), hashOf(ratchetTree)...) // LP(H(ratchet_tree))
	want = append(append(want, lengthOf32...), hashOf(joinSeal)...)    // LP(H(join_seal))
	if len(want) != 181 {
		t.Fatalf("the preimage written out here is %d octets and the format fixes 181", len(want))
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("joinAuthPreimage answered\n %x\nand the format is\n %x", got, want)
	}
	const pinned = "a3e0125abc4ebf9e58b08469a2553db6aa3ef5145a217fe406424f673678dc56"
	if sum := sha256.Sum256(got); hex.EncodeToString(sum[:]) != pinned {
		t.Fatalf("the preimage hashes to %x and %s is pinned", sum, pinned)
	}
}

// join_secrets_v1 is three 32 octet values in one order, and an opener refuses any other length
// and an all-zero secret.
func TestJoinSecretsAreThreeValuesInOneOrderAndNothingElseOpens(t *testing.T) {
	pqSecret := bytes.Repeat([]byte{0x11}, 32)
	groupHandleKey := bytes.Repeat([]byte{0x22}, 32)
	digest := bytes.Repeat([]byte{0x33}, 32)
	payload, err := encodeJoinSecrets(pqSecret, groupHandleKey, digest)
	if err != nil {
		t.Fatalf("encodeJoinSecrets: %v", err)
	}
	if want := append(append(append([]byte{}, pqSecret...), groupHandleKey...), digest...); !bytes.Equal(payload, want) {
		t.Fatalf("join_secrets_v1 is %x, want pq_secret | group_handle_key | epoch_keys_digest", payload)
	}
	gotPq, gotGhk, gotDigest, err := decodeJoinSecrets(payload)
	if err != nil || !bytes.Equal(gotPq, pqSecret) || !bytes.Equal(gotGhk, groupHandleKey) || !bytes.Equal(gotDigest, digest) {
		t.Fatalf("decodeJoinSecrets answered %x %x %x, %v", gotPq, gotGhk, gotDigest, err)
	}
	for _, one := range []struct {
		name    string
		payload []byte
	}{
		{"one octet short", payload[:95]},
		{"one octet long", append(append([]byte{}, payload...), 0x00)},
		{"a bare pq_secret, which is what a device wrap carries", pqSecret},
		{"an all-zero pq_secret", append(make([]byte, 32), payload[32:]...)},
		{"an all-zero group_handle_key", append(append(append([]byte{}, pqSecret...), make([]byte, 32)...), digest...)},
	} {
		if _, _, _, err := decodeJoinSecrets(one.payload); !errors.Is(err, ErrJoinSealUnreadable) {
			t.Errorf("%s answered %v, want ErrJoinSealUnreadable", one.name, err)
		}
	}
	if _, err := encodeJoinSecrets(pqSecret[:31], groupHandleKey, digest); err == nil {
		t.Error("a 31 octet pq_secret was sealed")
	}
}

// THE SEAL IS MADE BEFORE ANYTHING OF THE EPOCH IS SUBMITTED, read off the source of
// publishCommitLocked: the one call of beforeSubmit stands above every submitLocked and above
// MergePendingCommit. A seal made after a submit is an epoch the server has taken and an invite
// nobody was handed, which no behaviour of a run in which the seal succeeds can show.
func TestTheJoinSealIsMadeBeforeAnythingOfTheEpochIsSubmitted(t *testing.T) {
	files := token.NewFileSet()
	parsed, err := parser.ParseFile(files, "group.go", nil, 0)
	if err != nil {
		t.Fatalf("parsing group.go: %v", err)
	}
	hook, later := []token.Pos{}, []token.Pos{}
	found := false
	for _, declaration := range parsed.Decls {
		function, isFunction := declaration.(*ast.FuncDecl)
		if !isFunction || function.Name.Name != "publishCommitLocked" {
			continue
		}
		found = true
		ast.Inspect(function.Body, func(node ast.Node) bool {
			call, isCall := node.(*ast.CallExpr)
			if !isCall {
				return true
			}
			switch callee := call.Fun.(type) {
			case *ast.Ident:
				if callee.Name == "beforeSubmit" {
					hook = append(hook, call.Pos())
				}
			case *ast.SelectorExpr:
				if callee.Sel.Name == "submitLocked" || callee.Sel.Name == "MergePendingCommit" {
					later = append(later, call.Pos())
				}
			}
			return true
		})
	}
	if !found || len(hook) != 1 || len(later) < 3 {
		t.Fatalf("publishCommitLocked found %v, with %d call(s) of beforeSubmit and %d submit or merge call(s); this gate reads one and at least three", found, len(hook), len(later))
	}
	for _, position := range later {
		if position < hook[0] {
			t.Errorf("%s submits or merges ahead of the join seal's hook at %s", files.Position(position), files.Position(hook[0]))
		}
	}
}

// frameCounter is an [answeringClient] that also counts every frame of a request it is handed,
// WHOLE OR IN FRAGMENTS. A request too large for one frame is cut into fragment frames, which the
// fake under it neither answers nor counts, and an epoch wrap is one of those.
type frameCounter struct {
	*answeringClient
	frames atomic.Int64
}

func (self *frameCounter) SendWithTimeout(frame *connectprotocol.Frame, destination connect.Id,
	ackCallback connect.AckFunction, timeout time.Duration, opts ...any) bool {

	switch frame.GetMessageType() {
	case connectprotocol.MessageType_MessageMessageServerRequest, connectprotocol.MessageType_MessageMessageServerFragment:
		self.frames.Add(1)
	}
	return self.answeringClient.SendWithTimeout(frame, destination, ackCallback, timeout, opts...)
}

// A HOOK THAT REFUSES LEAVES NOTHING STAGED AND NOTHING SENT. The hook is where a live add seals
// the join secrets, so its refusal is a seal that could not be made. The commit is staged through
// the real seam, publishCommitLocked is handed a hook that refuses, and four things are read: the
// server was sent no request, the staged commit was erased, the epoch did not move, and the SAME
// join code can be staged again.
//
// THE SERVER IS A FAKE THAT HAS ANSWERED A HELLO AND THAT COUNTS FRAMES, and both halves are
// load-bearing. The transport sends no submit before a Hello has issued its nonce, and a wrap is
// too large for one frame and goes out as fragments; a count that missed either would be zero
// whatever the hook did. Both were measured on the way to this test, and the control at the end
// is what says this count can be other than zero.
//
// THE SOURCE GATE ABOVE READS WHERE THE HOOK STANDS; THIS READS WHAT A REFUSAL DOES. A fan-out
// moved ahead of the hook inside a helper passes the gate, which counts the calls it can see in
// one function body, and is counted here as a request the server was sent.
//
// WHAT WOULD GO RED: return the hook's error without ClearPendingCommit, and the second staging is
// refused over the first; submit the epoch's wraps before the hook, by any route, and the server's
// count moves.
func TestAHookThatRefusesLeavesNothingStagedAndNothingSent(t *testing.T) {
	ctx := context.Background()
	world := newRoleWorld(t, "owner", "bob")
	owner := world.member("owner")
	server := &frameCounter{answeringClient: &answeringClient{
		reason: messageprotocol.Reason_REASON_OK, nonce: []byte("the nonce of the transport under test"),
	}}
	transport, err := sdk.NewMessageTransport(&sdk.MessageTransportConfig{
		Client:          server,
		Server:          connect.NewId(),
		ProtocolVersion: 1,
	})
	if err != nil {
		t.Fatalf("sdk.NewMessageTransport: %v", err)
	}
	t.Cleanup(transport.Close)
	streamStore, err := sdk.OpenStreamStore(t.TempDir())
	if err != nil {
		t.Fatalf("sdk.OpenStreamStore: %v", err)
	}
	t.Cleanup(func() { streamStore.Close() })
	connected, err := NewDevice(DeviceConfig{Transport: transport, Reserver: sdk.NewStreamIndexReserver(streamStore)})
	if err != nil {
		t.Fatalf("NewDevice: %v", err)
	}
	t.Cleanup(func() { connected.Close() })
	if err := connected.Connect(ctx); err != nil {
		t.Fatalf("the Hello of the transport under test: %v", err)
	}
	owner.group.device.transport = transport
	before := server.frames.Load()

	joiner, _ := newAnsweringDevice(t, messageprotocol.Reason_REASON_OK, []byte("the joiner's nonce"))
	joinCode, err := joiner.KeyPackage()
	if err != nil {
		t.Fatalf("the joiner's KeyPackage: %v", err)
	}
	wrapped := &pendingFailingHandle{GroupHandle: owner.handle}
	owner.group.handle = wrapped
	defer func() { owner.group.handle = owner.handle }()
	commit, _, _, err := owner.handle.CommitAdd([][]byte{joinCode})
	if err != nil {
		t.Fatalf("staging the add: %v", err)
	}

	injected := errors.New("the join seal could not be made")
	called := 0
	err = owner.group.publishCommitLocked(ctx, commit, func(opensEpoch uint64, pqSecret []byte, epochKeysDigest []byte) error {
		called += 1
		if opensEpoch != 2 || len(pqSecret) != 32 || len(epochKeysDigest) != sha256.Size {
			t.Errorf("the hook was handed epoch %d, a %d octet secret and a %d octet digest, want 2, 32 and 32",
				opensEpoch, len(pqSecret), len(epochKeysDigest))
		}
		return injected
	})
	if !errors.Is(err, injected) || called != 1 {
		t.Fatalf("publishCommitLocked answered %v after calling the hook %d time(s), want the hook's own refusal after one call", err, called)
	}
	if sent := server.frames.Load() - before; sent != 0 {
		t.Errorf("the server was sent %d frame(s) of an epoch whose join seal could not be made", sent)
	}
	if wrapped.cleared != 1 {
		t.Errorf("the refusal called ClearPendingCommit %d time(s), want 1: the staged commit was left behind", wrapped.cleared)
	}
	if owner.handle.Epoch() != 1 || owner.group.Epoch() != 1 {
		t.Errorf("the owner's handle is at epoch %d and its group at %d after the refusal, want 1 and 1", owner.handle.Epoch(), owner.group.Epoch())
	}
	// THE CONTROL, AND IT FIRES FOR ITS OWN REASON. The same join code is staged again, which the
	// seam refuses over a value left staged; and published with a hook that does NOT refuse, it
	// reaches the server. So the zero above is a refusal that came before the first submit, and
	// not a transport that sends nothing.
	commit, _, _, err = owner.handle.CommitAdd([][]byte{joinCode})
	if err != nil {
		t.Fatalf("the seam refused to stage the same add again after the refusal: %v", err)
	}
	brief, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	err = owner.group.publishCommitLocked(brief, commit, func(uint64, []byte, []byte) error { return nil })
	if err == nil {
		t.Fatalf("CONTROL FAILED: a publish to a fake that answers no submit answered nil")
	}
	if sent := server.frames.Load() - before; sent == 0 {
		t.Fatalf("CONTROL FAILED: a publish whose hook did not refuse sent the server no frame (%v), so the zero above proves nothing", err)
	}
}

// keyPackageWithout is a valid key package of bob's own device that does not list one capability.
func keyPackageListing(t *testing.T, extensions []mls.ExtensionType) []byte {
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
		t.Fatalf("the leaf keys body: %v", err)
	}
	extension, err := leafKeys.Encode()
	if err != nil {
		t.Fatalf("the leaf keys extension: %v", err)
	}
	keyPackage, initPrivate, encryptPrivate, err := mls.NewKeyPackageWithSigner(crypto, crypto.Suite(), signer,
		mls.BasicCredential(signerPub), mls.Capabilities{
			Versions:     []mls.ProtocolVersion{mls.ProtocolVersionMls10},
			CipherSuites: mls.Suites(),
			Extensions:   extensions,
			Proposals:    []mls.ProposalType{},
			Credentials:  []mls.CredentialType{mls.CredentialTypeBasic},
		}, []mls.Extension{extension})
	if err != nil {
		t.Fatalf("NewKeyPackageWithSigner: %v", err)
	}
	defer keyPackage.Zeroize()
	defer clear(initPrivate)
	defer clear(encryptPrivate)
	encoded, err := syntax.Marshal(keyPackage)
	if err != nil {
		t.Fatalf("encoding the key package: %v", err)
	}
	return encoded
}

// A join code is judged BEFORE anything is staged: a damaged one is told it is invalid, one from a
// build that cannot open a sealed invite is told so by name, and after either the founder is where
// it was and adds the honest join code.
func TestAnAdderRefusesAJoinCodeItCannotSealToBeforeAnythingIsStaged(t *testing.T) {
	ctx := context.Background()
	alice, _ := newAnsweringDevice(t, messageprotocol.Reason_REASON_OK, []byte("alice's nonce"))
	bob, _ := newAnsweringDevice(t, messageprotocol.Reason_REASON_OK, []byte("bob's nonce"))
	for _, device := range []*Device{alice, bob} {
		if err := device.Connect(ctx); err != nil {
			t.Fatalf("Connect: %v", err)
		}
	}
	group, err := alice.CreateGroup(ctx, bytes.Repeat([]byte{0x47}, GroupIdBytes))
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	honest, err := bob.KeyPackage()
	if err != nil {
		t.Fatalf("bob's KeyPackage: %v", err)
	}
	damaged := bytes.Clone(honest)
	damaged[len(damaged)-1] ^= 0x01 // the last octet of its signature
	withoutTheCapability := keyPackageListing(t, []mls.ExtensionType{
		mls.ExtensionTypeUrmessageGroupPolicy, mls.ExtensionTypeUrmessageLeafKeys,
	})
	// THE CONTROL for the capability row: the same fixture WITH the capability is not refused for it
	withTheCapability := keyPackageListing(t, []mls.ExtensionType{
		mls.ExtensionTypeUrmessageGroupPolicy, mls.ExtensionTypeUrmessageLeafKeys, mls.ExtensionTypeUrmessageJoinSeal,
	})
	if _, err := alice.joinerOf(withTheCapability); err != nil {
		t.Fatalf("CONTROL FAILED: the fixture's key package is refused with the capability listed: %v", err)
	}

	for _, one := range []struct {
		name     string
		joinCode []byte
		want     error
	}{
		{"a join code with one bit of its signature flipped", damaged, ErrKeyPackageInvalid},
		{"octets that are not a key package", []byte("not a key package"), ErrKeyPackageInvalid},
		{"a join code that does not list the join seal", withoutTheCapability, ErrJoinerCannotOpenSealedInvite},
	} {
		if _, err := group.AddMember(one.joinCode); !errors.Is(err, one.want) {
			t.Errorf("%s answered %v, want %v", one.name, err, one.want)
		}
		if epoch := group.handle.Epoch(); epoch != 0 {
			t.Fatalf("%s left the founder's handle at epoch %d", one.name, epoch)
		}
		if _, err := group.handle.PendingEpoch(); err == nil {
			t.Fatalf("%s left a commit staged on the founder", one.name)
		}
	}
	if _, err := group.AddMember(honest); err != nil {
		t.Fatalf("the honest join code after three refused ones: %v", err)
	}
}

// THE JOINER'S LEAF IS THE WHOLE LEAF THE JOIN CODE PUBLISHED, and not merely a leaf under its
// signature key. One device mints two join codes: they carry one signature key and two different
// leaves. The first is added; asked for the leaf of the SECOND in the tree that add returned, the
// search must refuse, because the leaf standing there is not the one that join code published.
//
// WHAT WOULD GO RED: find the leaf by signature key alone, and the second join code is answered
// the first one's leaf, which is a seal and an authenticator made for a leaf its holder never
// published.
func TestTheJoinersLeafIsTheWholeLeafTheJoinCodePublished(t *testing.T) {
	ctx := context.Background()
	alice, _ := newAnsweringDevice(t, messageprotocol.Reason_REASON_OK, []byte("alice's nonce"))
	bob, _ := newAnsweringDevice(t, messageprotocol.Reason_REASON_OK, []byte("bob's nonce"))
	for _, device := range []*Device{alice, bob} {
		if err := device.Connect(ctx); err != nil {
			t.Fatalf("Connect: %v", err)
		}
	}
	group, err := alice.CreateGroup(ctx, bytes.Repeat([]byte{0x47}, GroupIdBytes))
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	added, err := bob.KeyPackage()
	if err != nil {
		t.Fatalf("bob's first KeyPackage: %v", err)
	}
	other, err := bob.KeyPackage()
	if err != nil {
		t.Fatalf("bob's second KeyPackage: %v", err)
	}
	_, _, ratchetTree, err := group.handle.CommitAdd([][]byte{added})
	if err != nil {
		t.Fatalf("CommitAdd: %v", err)
	}
	defer group.handle.ClearPendingCommit()
	decode := func(joinCode []byte) *mls.KeyPackage {
		decoded := &mls.KeyPackage{}
		if err := syntax.Unmarshal(joinCode, decoded); err != nil {
			t.Fatalf("decoding a join code: %v", err)
		}
		return decoded
	}
	// THE CONTROL: the join code that WAS added is found, at the second leaf
	if leaf, err := joinerLeafIn(ratchetTree, decode(added)); err != nil || leaf != 1 {
		t.Fatalf("CONTROL FAILED: the added join code's leaf answered %d, %v, want 1", leaf, err)
	}
	if !bytes.Equal(decode(added).LeafNode.SignatureKey, decode(other).LeafNode.SignatureKey) {
		t.Fatalf("CONTROL FAILED: one device's two join codes carry two signature keys, so this is not the case it is written for")
	}
	if leaf, err := joinerLeafIn(ratchetTree, decode(other)); err == nil {
		t.Fatalf("a join code that was never added was answered leaf %d: the search matched its signature key and not its leaf", leaf)
	}
}
