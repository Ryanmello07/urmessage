// The contact rendezvous of spec A section 5.14, in the link box's form, kind 4: the box's id and
// its deposit key from the link code, the five signature preimages a box is registered, opened,
// deposited into, collected and retired under, and the five verifiers the message server checks
// them with (spec B section 4.3.11). Spec A section 12.1 publishes this surface to the server
// (A-1) for the reason section 5.14 gives: the server links the verifiers, the client signs, and
// two implementations of one preimage diverge. So the server builds no preimage of its own, and
// the client signs over the bytes these functions answer. Identity phase 1's Task 7b, LRI R70.
//
// THE LINK BOX IS THE ONE KIND THIS BUILD SERVES. A registration carries its kind, and its
// preimage appends u32(kind) ‖ LP(public_ct) after u16(alg_id), so that no registration is
// replayed under another kind or with another card (A-36). Kind 0, the contact card, has a
// preimage that ends at u16(alg_id), and no build of identity phase 1 serves it, nor kinds 1 to
// 3: the register preimage is refused for every kind but 4, and so is its verifier. The other
// four arms keep the card's forms and carry no kind. What tells a link box's request from a
// card's on those arms is the box's id, which the two derive under two different labels, and the
// keys the box pinned.
//
// THE DERIVATIONS ARE THE LINK CODE'S. RendezvousId and DepositVerifyKey take the octets the code
// stands for -- 60 bits from crypto/rand as a u64, its 4 high bits zero -- under the label
// "URmessage/v1/link", and not the card's token under "URmessage/v1/rendezvous". The server holds
// no code and derives nothing: it is handed the id and the deposit key at registration.
//
// The labels are raw ascii and never length prefixed, LP is WriteOpaqueLP's fixed thirty two bit
// big endian length, and H is SHA-256, all as in writeauth.go. Each preimage binds the
// connection's server_nonce, so that a captured frame does not replay onto another connection.
//
// THE COMPUTING HALF PANICS AND THE VERIFYING HALF ANSWERS FALSE, which is writeauth.go's split
// for writeauth.go's reason. The client builds a preimage over its own connection's nonce and its
// own box, so a refusal there is a bug in the caller; the server verifies a request a client
// sent, so a refusal there is an answer, and a panic would be a client that can stop the server.
//
// WHAT THESE VERIFIERS DO NOT CHECK, because the server does (spec B section 4.3.11): the card's
// and the deposit's lengths as equalities, LinkCardBytes and LinkDepositBytes; card_xwing_pub
// absent and alg_id 0x0014 on a registration; and every rule about a box's state. A verifier
// answers one question, whether this signature holds over this preimage under this key, and a
// length check inside it would turn a refusal the server answers by its own reason into a
// signature that failed.
package message

import (
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"fmt"

	"github.com/urnetwork/message/syntax"
)

// The labels of spec A section 5.14, raw ascii and never length prefixed. The first is the link
// code's: the id is a hash under it, and the deposit key's extract takes it as the salt. The five
// after the info string are the five preimages', one each, and none of them is computed from
// another, for writeauth.go's reason: a shared construction is one edit away from making two of
// them agree.
const (
	rendezvousLinkLabel      = "URmessage/v1/link"
	rendezvousDepositSigInfo = "depsig/v1"
	rendezvousRegisterLabel  = "URmessage/v1/rzvregister"
	rendezvousOpenLabel      = "URmessage/v1/rzvopen"
	rendezvousDepositLabel   = "URmessage/v1/rzvdeposit"
	rendezvousCollectLabel   = "URmessage/v1/rzvcollect"
	rendezvousRetireLabel    = "URmessage/v1/rzvretire"
)

// The link box's kind, the one kind identity phase 1 serves (spec B section 4.3.11).
const rendezvousKindLink uint32 = 4

// RendezvousRegistration is what a RendezvousRegisterRequest registers (spec B section 4.3.11),
// and what register_auth is a signature over beside the connection's server_nonce. For a link
// box: RendezvousId is RendezvousId(code), DepositVerifyPub is DepositVerifyKey(code),
// CollectVerifyPub is the new device's own key, CardXwingPub is empty, AlgId is 0x0014, Kind is 4
// and PublicCt is the sealed card, LinkCardBytes octets.
//
// AlgId is the preimage's u16. The request carries alg_id as a uint32, and a server converting it
// refuses a value above 0xFFFF rather than truncating it: a truncated 0x10014 would verify as
// 0x0014.
type RendezvousRegistration struct {
	RendezvousId     []byte
	DepositVerifyPub []byte
	CollectVerifyPub []byte
	CardXwingPub     []byte
	AlgId            uint16
	Kind             uint32
	PublicCt         []byte
}

// RendezvousCollectParams is what a RendezvousCollectRequest asks, beside the box's id, and what
// collect_auth is a signature over beside the connection's server_nonce.
type RendezvousCollectParams struct {
	RendezvousId        []byte
	SinceDepositId      uint64
	AckThroughDepositId uint64
	Limit               uint32
	Subscribe           bool
}

// RendezvousId is a link box's id, H("URmessage/v1/link" ‖ code_octets), where token is the eight
// octets the link code stands for (spec A section 5.14). The code is its holder's: the server is
// handed the id and never the code.
func RendezvousId(token []byte) [32]byte {
	return sha256.Sum256(append([]byte(rendezvousLinkLabel), token...))
}

// DepositVerifyKey is the public half of a link box's deposit_sig, the Ed25519 key the link code
// derives: its seed is HKDF-Expand(HKDF-Extract(salt = "URmessage/v1/link", ikm = code_octets),
// "depsig/v1", 32) (spec A section 5.14). A holder of the code signs Open and Deposit with the
// private half, and the box pins this one at registration.
//
// The error is the KDF's, and only a FIPS 140-only build reaches it: that mode refuses
// HKDF-Extract over a secret shorter than 112 bits, and a link code is 64.
//
// hkdf.Extract takes the secret first and the salt second, the reverse of the spec's
// HKDF-Extract(salt, ikm), so the call below passes the code as the secret and the label as the
// salt. TestTheRendezvousValuesAreTheKnownAnswers holds it to a key computed from RFC 5869's own
// equations outside Go, which is what keeps a transposition from passing.
func DepositVerifyKey(token []byte) ([]byte, error) {
	ikm, err := hkdf.Extract(sha256.New, token, []byte(rendezvousLinkLabel))
	if err != nil {
		return nil, fmt.Errorf("message: a link code's deposit key could not be extracted: %w", err)
	}
	defer clear(ikm)
	seed, err := hkdf.Expand(sha256.New, ikm, rendezvousDepositSigInfo, ed25519.SeedSize)
	if err != nil {
		return nil, fmt.Errorf("message: a link code's deposit key could not be expanded: %w", err)
	}
	defer clear(seed)
	private := ed25519.NewKeyFromSeed(seed)
	defer clear(private)
	return append([]byte(nil), private[ed25519.SeedSize:]...), nil
}

// RendezvousRegisterPreimage builds the bytes register_auth is an Ed25519 signature over, under
// collect_sig, in the link box's kinded form (spec A section 5.14 at A-36):
//
//	"URmessage/v1/rzvregister" ‖ LP(server_nonce) ‖ LP(rendezvous_id) ‖ LP(deposit_verify_pub)
//	‖ LP(collect_verify_pub) ‖ LP(card_xwing_pub) ‖ u16(alg_id) ‖ u32(kind) ‖ LP(public_ct)
//
// It panics on what it refuses, with the wrapped sentinel as the panic value: ErrRendezvousNil
// for no registration, ErrServerNonceEmpty for a nonce of no octets, and
// ErrRendezvousKindNotServed for any kind but 4. Kind 0's form, the card's, ends at u16(alg_id),
// and it is built by no build of identity phase 1. VerifyRendezvousRegister answers false on
// each instead.
func RendezvousRegisterPreimage(serverNonce []byte, r *RendezvousRegistration) []byte {
	preimage, err := rendezvousRegisterPreimage(serverNonce, r)
	if err != nil {
		panic(fmt.Errorf("message: the register_auth preimage cannot be built: %w", err))
	}
	return preimage
}

// RendezvousOpenPreimage builds the bytes open_auth is a signature over, under deposit_sig:
//
//	"URmessage/v1/rzvopen" ‖ LP(server_nonce) ‖ LP(rendezvous_id)
//
// It panics, with ErrServerNonceEmpty wrapped, on a nonce of no octets.
func RendezvousOpenPreimage(serverNonce []byte, rendezvousId []byte) []byte {
	preimage, err := rendezvousBoxPreimage(rendezvousOpenLabel, serverNonce, rendezvousId)
	if err != nil {
		panic(fmt.Errorf("message: the open_auth preimage cannot be built: %w", err))
	}
	return preimage
}

// RendezvousDepositPreimage builds the bytes deposit_auth is a signature over, under
// deposit_sig, which binds the deposit by its hash:
//
//	"URmessage/v1/rzvdeposit" ‖ LP(server_nonce) ‖ LP(rendezvous_id) ‖ LP(H(deposit_ct))
//
// It panics, with ErrServerNonceEmpty wrapped, on a nonce of no octets.
func RendezvousDepositPreimage(serverNonce []byte, rendezvousId []byte, depositCt []byte) []byte {
	preimage, err := rendezvousDepositPreimage(serverNonce, rendezvousId, depositCt)
	if err != nil {
		panic(fmt.Errorf("message: the deposit_auth preimage cannot be built: %w", err))
	}
	return preimage
}

// RendezvousCollectPreimage builds the bytes collect_auth is a signature over, under
// collect_sig:
//
//	"URmessage/v1/rzvcollect" ‖ LP(server_nonce) ‖ LP(rendezvous_id) ‖ u64(since_deposit_id)
//	‖ u64(ack_through_deposit_id) ‖ u32(limit) ‖ u8(subscribe)
//
// It panics, with the sentinel wrapped, on no parameters (ErrRendezvousNil) and on a nonce of no
// octets (ErrServerNonceEmpty).
func RendezvousCollectPreimage(serverNonce []byte, c *RendezvousCollectParams) []byte {
	preimage, err := rendezvousCollectPreimage(serverNonce, c)
	if err != nil {
		panic(fmt.Errorf("message: the collect_auth preimage cannot be built: %w", err))
	}
	return preimage
}

// RendezvousRetirePreimage builds the bytes retire_auth is a signature over, under collect_sig:
//
//	"URmessage/v1/rzvretire" ‖ LP(server_nonce) ‖ LP(rendezvous_id)
//
// It panics, with ErrServerNonceEmpty wrapped, on a nonce of no octets.
func RendezvousRetirePreimage(serverNonce []byte, rendezvousId []byte) []byte {
	preimage, err := rendezvousBoxPreimage(rendezvousRetireLabel, serverNonce, rendezvousId)
	if err != nil {
		panic(fmt.Errorf("message: the retire_auth preimage cannot be built: %w", err))
	}
	return preimage
}

// VerifyRendezvousRegister answers whether register_auth holds over the registration's preimage
// under the collect key the registration itself carries, which is the self-certification spec B
// section 4.3.11 states plainly. It answers false for any kind but the link box's, for no
// registration, for an empty nonce and for a key or a signature of the wrong width, and it never
// panics.
func VerifyRendezvousRegister(r *RendezvousRegistration, serverNonce []byte, sig []byte) bool {
	preimage, err := rendezvousRegisterPreimage(serverNonce, r)
	if err != nil {
		return false
	}
	return rendezvousSignatureHolds(r.CollectVerifyPub, preimage, sig)
}

// VerifyRendezvousOpen answers whether open_auth holds under the deposit key the box pinned. It
// answers false for an empty nonce and for a key or a signature of the wrong width, and it never
// panics.
func VerifyRendezvousOpen(depositVerifyPub []byte, serverNonce []byte, rendezvousId []byte, sig []byte) bool {
	preimage, err := rendezvousBoxPreimage(rendezvousOpenLabel, serverNonce, rendezvousId)
	if err != nil {
		return false
	}
	return rendezvousSignatureHolds(depositVerifyPub, preimage, sig)
}

// VerifyRendezvousDeposit answers whether deposit_auth holds under the deposit key the box pinned,
// over the deposit's hash. A verifying deposit_auth proves possession of the code and nothing
// else (spec B section 4.3.11). It answers false for an empty nonce and for a key or a signature
// of the wrong width, and it never panics.
func VerifyRendezvousDeposit(depositVerifyPub []byte, serverNonce []byte, rendezvousId []byte, depositCt []byte, sig []byte) bool {
	preimage, err := rendezvousDepositPreimage(serverNonce, rendezvousId, depositCt)
	if err != nil {
		return false
	}
	return rendezvousSignatureHolds(depositVerifyPub, preimage, sig)
}

// VerifyRendezvousCollect answers whether collect_auth holds under the collect key the box pinned.
// It answers false for no parameters, for an empty nonce and for a key or a signature of the
// wrong width, and it never panics.
func VerifyRendezvousCollect(collectVerifyPub []byte, serverNonce []byte, c *RendezvousCollectParams, sig []byte) bool {
	preimage, err := rendezvousCollectPreimage(serverNonce, c)
	if err != nil {
		return false
	}
	return rendezvousSignatureHolds(collectVerifyPub, preimage, sig)
}

// VerifyRendezvousRetire answers whether retire_auth holds under the collect key the box pinned.
// It answers false for an empty nonce and for a key or a signature of the wrong width, and it
// never panics.
func VerifyRendezvousRetire(collectVerifyPub []byte, serverNonce []byte, rendezvousId []byte, sig []byte) bool {
	preimage, err := rendezvousBoxPreimage(rendezvousRetireLabel, serverNonce, rendezvousId)
	if err != nil {
		return false
	}
	return rendezvousSignatureHolds(collectVerifyPub, preimage, sig)
}

// LinkCardBytes is the length of a link box's card, its registration's public_ct, which the server
// asserts as an equality (spec A section 5.14, frozen by ledger item 300): a 12 octet nonce, the
// card padded to 4,096 octets, and the AEAD's 16 octet tag.
func LinkCardBytes() int {
	return 4124
}

// LinkDepositBytes is the length of a link box's deposit, which the server asserts as an equality
// (spec A section 5.14, frozen by ledger item 300): u16(alg_id), LP(ct_xwing) of 4 and 1,120
// octets, and the invitation padded to 16,384 octets with the AEAD's 16 octet tag.
func LinkDepositBytes() int {
	return 17526
}

// The reporting half of the register preimage, and the one its verifier uses.
func rendezvousRegisterPreimage(serverNonce []byte, r *RendezvousRegistration) ([]byte, error) {
	if r == nil {
		return nil, ErrRendezvousNil
	}
	if len(serverNonce) == 0 {
		return nil, ErrServerNonceEmpty
	}
	if r.Kind != rendezvousKindLink {
		return nil, fmt.Errorf("%w: kind %d", ErrRendezvousKindNotServed, r.Kind)
	}
	writer := syntax.NewWriter()
	writer.WriteRaw([]byte(rendezvousRegisterLabel))
	writer.WriteOpaqueLP(serverNonce)
	writer.WriteOpaqueLP(r.RendezvousId)
	writer.WriteOpaqueLP(r.DepositVerifyPub)
	writer.WriteOpaqueLP(r.CollectVerifyPub)
	writer.WriteOpaqueLP(r.CardXwingPub)
	writer.WriteUint16(r.AlgId)
	writer.WriteUint32(r.Kind)
	writer.WriteOpaqueLP(r.PublicCt)
	return writer.Bytes()
}

// The open and the retire preimages, which have one form and two labels: label ‖ LP(server_nonce)
// ‖ LP(rendezvous_id). What keeps them apart is the label, and the keys they are signed under.
func rendezvousBoxPreimage(label string, serverNonce []byte, rendezvousId []byte) ([]byte, error) {
	if len(serverNonce) == 0 {
		return nil, ErrServerNonceEmpty
	}
	writer := syntax.NewWriter()
	writer.WriteRaw([]byte(label))
	writer.WriteOpaqueLP(serverNonce)
	writer.WriteOpaqueLP(rendezvousId)
	return writer.Bytes()
}

// The reporting half of the deposit preimage. It hashes the deposit and never carries it, so a
// preimage stays the same length whatever the box takes.
func rendezvousDepositPreimage(serverNonce []byte, rendezvousId []byte, depositCt []byte) ([]byte, error) {
	if len(serverNonce) == 0 {
		return nil, ErrServerNonceEmpty
	}
	depositHash := sha256.Sum256(depositCt)
	writer := syntax.NewWriter()
	writer.WriteRaw([]byte(rendezvousDepositLabel))
	writer.WriteOpaqueLP(serverNonce)
	writer.WriteOpaqueLP(rendezvousId)
	writer.WriteOpaqueLP(depositHash[:])
	return writer.Bytes()
}

// The reporting half of the collect preimage.
func rendezvousCollectPreimage(serverNonce []byte, c *RendezvousCollectParams) ([]byte, error) {
	if c == nil {
		return nil, ErrRendezvousNil
	}
	if len(serverNonce) == 0 {
		return nil, ErrServerNonceEmpty
	}
	writer := syntax.NewWriter()
	writer.WriteRaw([]byte(rendezvousCollectLabel))
	writer.WriteOpaqueLP(serverNonce)
	writer.WriteOpaqueLP(c.RendezvousId)
	writer.WriteUint64(c.SinceDepositId)
	writer.WriteUint64(c.AckThroughDepositId)
	writer.WriteUint32(c.Limit)
	writer.WriteUint8(rendezvousSubscribeOctet(c.Subscribe))
	return writer.Bytes()
}

// u8(subscribe): one for a collector that asks to be pushed to, zero for one that does not.
func rendezvousSubscribeOctet(subscribe bool) uint8 {
	if subscribe {
		return 1
	}
	return 0
}

// The rendezvous's one Ed25519 check, which every verifier above ends in. A key or a signature of
// the wrong width answers false here rather than reaching ed25519.Verify, which panics on a key
// that is not 32 octets: a server handed a short key by a client must not stop.
func rendezvousSignatureHolds(verifyPub []byte, preimage []byte, sig []byte) bool {
	if len(verifyPub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(verifyPub), preimage, sig)
}
