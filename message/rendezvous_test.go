package message

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"testing"
)

// Task 7b's two properties (identity phase 1's plan, LRI R70), over spec A section 5.14's link box,
// kind 4, at A-37, with Spec B revision 26's section 4.3.11 for what the server does with them.
//
// THE KNOWN ANSWERS ARE COMPUTED OUTSIDE GO, from the sources' text: SHA-256 and HMAC from Python's
// hashlib and hmac, HKDF from RFC 5869's two equations, and Ed25519 from RFC 8032 section 5.1's
// arithmetic, each checked first against its RFC's own vectors (RFC 5869 appendix A.1; RFC 8032
// section 7.1, tests 1 to 3). The signatures below were made there too, so a verifier accepting
// them is this package's preimage agreeing octet for octet with a second implementation's, which
// is the divergence A-1 exists to prevent.
const (
	// code_octets: 60 bits as a u64, its 4 high bits zero
	rendezvousKnownCode = "0f1e2d3c4b5a6978"
	// a server_nonce of 32 octets, 0x40 to 0x5f
	rendezvousKnownNonce = "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"
	// H("URmessage/v1/link" ‖ code_octets)
	rendezvousKnownId = "cb0b8b2c526a5e306c3ba65399c8a42f959f88da60e17bfb30c2b8725eab5541"
	// HKDF-Expand(HKDF-Extract(salt = "URmessage/v1/link", ikm = code_octets), "depsig/v1", 32),
	// and the public half of the Ed25519 key it seeds
	rendezvousKnownDepositSeed = "231d4987022f68561e533a5accae91568505add4618662d74b81e3ad90857817"
	rendezvousKnownDepositPub  = "a8778696b4b5a9b6d5b49268e6141727bfeead67f629eb0d70e351b829614203"
	// the new device's collect key, seeded by 32 octets of 0x5c
	rendezvousKnownCollectPub = "ed6a47a39da869b5446155e40b2d93f1e3f0167be26732bae7a3ef9d8e3a3fd3"
	// the card's (kind 0) box id for the same octets, H("URmessage/v1/rendezvous" ‖ code_octets)
	rendezvousKnownCardId = "9a3b2baeef2ee1f168ea718cb7937437e5ca71ae01126fbaee1cf7f972da2c99"

	// the register preimage over the registration below: its length, its hash, and every octet
	// before the card, since the card is 4,124 octets of the pattern rendezvousKnownPublicCt
	// makes
	rendezvousKnownRegisterBytes  = 4306
	rendezvousKnownRegisterSha256 = "b0f1091c56b5bf5f604eb1d07ad921c76395a13a76a73d89c8a5d79c52dd8ef8"
	rendezvousKnownRegisterHead   = "55526d6573736167652f76312f727a76726567697374657200000020404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f00000020cb0b8b2c526a5e306c3ba65399c8a42f959f88da60e17bfb30c2b8725eab554100000020a8778696b4b5a9b6d5b49268e6141727bfeead67f629eb0d70e351b82961420300000020ed6a47a39da869b5446155e40b2d93f1e3f0167be26732bae7a3ef9d8e3a3fd300000000001400000004" + "0000101c"
	// the other four, whole
	rendezvousKnownOpen    = "55526d6573736167652f76312f727a766f70656e00000020404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f00000020cb0b8b2c526a5e306c3ba65399c8a42f959f88da60e17bfb30c2b8725eab5541"
	rendezvousKnownDeposit = "55526d6573736167652f76312f727a766465706f73697400000020404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f00000020cb0b8b2c526a5e306c3ba65399c8a42f959f88da60e17bfb30c2b8725eab5541" +
		// LP(H(deposit_ct)) over the 17,526 octets rendezvousKnownDepositCt makes
		"00000020" + "b0402b9c0bc17d060ed5a347ce86ef57b2631efc32694ffa0d9953c593cb74e5"
	rendezvousKnownCollect = "55526d6573736167652f76312f727a76636f6c6c65637400000020404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f00000020cb0b8b2c526a5e306c3ba65399c8a42f959f88da60e17bfb30c2b8725eab5541" +
		"0000000000000007" + "0000000000000005" + "00000010" + "01"
	rendezvousKnownRetire = "55526d6573736167652f76312f727a7672657469726500000020404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f00000020cb0b8b2c526a5e306c3ba65399c8a42f959f88da60e17bfb30c2b8725eab5541"

	// the five signatures, made outside Go: register, collect and retire under the collect key,
	// open and deposit under the deposit key
	rendezvousKnownSigRegister = "e44cade37b3cbad6240f5ee96d0f51158b105e243295617c2921a7d38cb5662506c3fbe0a966cbb0e7bbaddb7e4b201cec12bf3b01df55cd7cecd296814a2707"
	rendezvousKnownSigOpen     = "9c325a384d8ee5b855e39d5de0c48fb40f091c744ff919b084faf1fbd80fc8cccdb3fe76d569dbf0cc111638d5b9fa4f2e5cc380b4afaa8827a09f271ffe8b07"
	rendezvousKnownSigDeposit  = "fb34fec29a707b863c0dbade1fdfe2b5307a7bde508fc54b06d81bb84e608bfa2aa487d292809f6184a73d54542de74bcc9ae274d90bc27649355d89cf74bc03"
	rendezvousKnownSigCollect  = "c3d148b382e1881d7ed4591a6093051a81059d3cce8b508dca0c6e45165401771390d2545008a0e84f223f9e91f4e76463b259614c30e6bf3cb335751e81db0e"
	rendezvousKnownSigRetire   = "36dbab755a0d3c259e842daeb228699a39e3c034816cc0542be63c5091e4789b27cee903eacf64c6ebf5d2598e297e6eb3314c3d3a5305e072427568238e1209"
)

func rendezvousHex(t *testing.T, value string) []byte {
	t.Helper()
	octets, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("a known answer is not hex: %v", err)
	}
	return octets
}

// The card the registration below carries: 4,124 octets of (i*7 + 3) mod 256.
func rendezvousKnownPublicCt() []byte {
	card := make([]byte, 4124)
	for i := range card {
		card[i] = byte((i*7 + 3) % 256)
	}
	return card
}

// The deposit the deposit preimage hashes: 17,526 octets of (i*11 + 5) mod 256.
func rendezvousKnownDepositCt() []byte {
	deposit := make([]byte, 17526)
	for i := range deposit {
		deposit[i] = byte((i*11 + 5) % 256)
	}
	return deposit
}

// The link box the known answers are about, as the new device registers it.
type rendezvousKnownBox struct {
	code        []byte
	nonce       []byte
	id          []byte
	cardId      []byte
	depositKey  ed25519.PrivateKey
	collectKey  ed25519.PrivateKey
	strangerKey ed25519.PrivateKey
	publicCt    []byte
	depositCt   []byte
	collect     RendezvousCollectParams
}

func rendezvousTheKnownBox(t *testing.T) rendezvousKnownBox {
	t.Helper()
	return rendezvousKnownBox{
		code:        rendezvousHex(t, rendezvousKnownCode),
		nonce:       rendezvousHex(t, rendezvousKnownNonce),
		id:          rendezvousHex(t, rendezvousKnownId),
		cardId:      rendezvousHex(t, rendezvousKnownCardId),
		depositKey:  ed25519.NewKeyFromSeed(rendezvousHex(t, rendezvousKnownDepositSeed)),
		collectKey:  ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x5c}, ed25519.SeedSize)),
		strangerKey: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0xa7}, ed25519.SeedSize)),
		publicCt:    rendezvousKnownPublicCt(),
		depositCt:   rendezvousKnownDepositCt(),
		collect: RendezvousCollectParams{
			RendezvousId:        rendezvousHex(t, rendezvousKnownId),
			SinceDepositId:      7,
			AckThroughDepositId: 5,
			Limit:               16,
			Subscribe:           true,
		},
	}
}

func (box rendezvousKnownBox) registration() *RendezvousRegistration {
	return &RendezvousRegistration{
		RendezvousId:     box.id,
		DepositVerifyPub: box.depositKey.Public().(ed25519.PublicKey),
		CollectVerifyPub: box.collectKey.Public().(ed25519.PublicKey),
		CardXwingPub:     nil,
		AlgId:            0x0014,
		Kind:             4,
		PublicCt:         box.publicCt,
	}
}

// Property 2: RendezvousId, DepositVerifyKey and each preimage are their known answers, and
// LinkCardBytes and LinkDepositBytes are ledger item 300's 4,124 and 17,526.
func TestTheRendezvousValuesAreTheKnownAnswers(t *testing.T) {
	box := rendezvousTheKnownBox(t)

	id := RendezvousId(box.code)
	if got := hex.EncodeToString(id[:]); got != rendezvousKnownId {
		t.Errorf("RendezvousId(code) = %s, want %s: H(\"URmessage/v1/link\" ‖ code_octets)", got, rendezvousKnownId)
	}
	depositPub, err := DepositVerifyKey(box.code)
	if err != nil {
		t.Fatalf("DepositVerifyKey(code): %v", err)
	}
	if got := hex.EncodeToString(depositPub); got != rendezvousKnownDepositPub {
		t.Errorf("DepositVerifyKey(code) = %s, want %s: the public half of HKDF-Expand(HKDF-Extract(salt = \"URmessage/v1/link\", ikm = code_octets), \"depsig/v1\", 32)",
			got, rendezvousKnownDepositPub)
	}
	// the fixture's own two keys, held to the answers made outside Go, so that the signatures
	// below are signatures by the keys the box names
	if got := hex.EncodeToString(box.depositKey.Public().(ed25519.PublicKey)); got != rendezvousKnownDepositPub {
		t.Errorf("the deposit seed's public half is %s, want %s", got, rendezvousKnownDepositPub)
	}
	if got := hex.EncodeToString(box.collectKey.Public().(ed25519.PublicKey)); got != rendezvousKnownCollectPub {
		t.Errorf("the collect seed's public half is %s, want %s", got, rendezvousKnownCollectPub)
	}
	// the two derivations take the code and nothing else: another code is another box
	otherCode := append([]byte(nil), box.code...)
	otherCode[7] ^= 0x01
	if otherId := RendezvousId(otherCode); bytes.Equal(otherId[:], id[:]) {
		t.Error("two codes one bit apart derive one box id")
	}
	if otherPub, err := DepositVerifyKey(otherCode); err != nil || bytes.Equal(otherPub, depositPub) {
		t.Errorf("two codes one bit apart derive one deposit key (%v)", err)
	}

	register := RendezvousRegisterPreimage(box.nonce, box.registration())
	if len(register) != rendezvousKnownRegisterBytes {
		t.Errorf("the register preimage is %d octets, want %d", len(register), rendezvousKnownRegisterBytes)
	}
	if sum := sha256.Sum256(register); hex.EncodeToString(sum[:]) != rendezvousKnownRegisterSha256 {
		t.Errorf("the register preimage hashes to %x, want %s", sum, rendezvousKnownRegisterSha256)
	}
	head := rendezvousHex(t, rendezvousKnownRegisterHead)
	if !bytes.HasPrefix(register, head) || !bytes.Equal(register[len(head):], box.publicCt) {
		t.Errorf("the register preimage is\n    %x…\nwant\n    %s ‖ the card", register[:min(len(register), len(head))], rendezvousKnownRegisterHead)
	}
	for _, one := range []struct {
		name string
		got  []byte
		want string
	}{
		{"open", RendezvousOpenPreimage(box.nonce, box.id), rendezvousKnownOpen},
		{"deposit", RendezvousDepositPreimage(box.nonce, box.id, box.depositCt), rendezvousKnownDeposit},
		{"collect", RendezvousCollectPreimage(box.nonce, &box.collect), rendezvousKnownCollect},
		{"retire", RendezvousRetirePreimage(box.nonce, box.id), rendezvousKnownRetire},
	} {
		if got := hex.EncodeToString(one.got); got != one.want {
			t.Errorf("the %s preimage is\n    %s\nwant\n    %s", one.name, got, one.want)
		}
	}

	// the signatures made outside Go verify over this package's preimages
	collectPub := box.collectKey.Public().(ed25519.PublicKey)
	for _, one := range []struct {
		name  string
		holds bool
	}{
		{"register", VerifyRendezvousRegister(box.registration(), box.nonce, rendezvousHex(t, rendezvousKnownSigRegister))},
		{"open", VerifyRendezvousOpen(depositPub, box.nonce, box.id, rendezvousHex(t, rendezvousKnownSigOpen))},
		{"deposit", VerifyRendezvousDeposit(depositPub, box.nonce, box.id, box.depositCt, rendezvousHex(t, rendezvousKnownSigDeposit))},
		{"collect", VerifyRendezvousCollect(collectPub, box.nonce, &box.collect, rendezvousHex(t, rendezvousKnownSigCollect))},
		{"retire", VerifyRendezvousRetire(collectPub, box.nonce, box.id, rendezvousHex(t, rendezvousKnownSigRetire))},
	} {
		if !one.holds {
			t.Errorf("the %s signature made outside Go does not verify over this package's preimage", one.name)
		}
	}

	// ledger item 300's two sizes, and the arithmetic each is (spec A section 5.14)
	if LinkCardBytes() != 4124 || LinkCardBytes() != 12+4096+16 {
		t.Errorf("LinkCardBytes() = %d, want 4,124: a 12 octet nonce, the card padded to 4,096, a 16 octet tag", LinkCardBytes())
	}
	if LinkDepositBytes() != 17526 || LinkDepositBytes() != 2+(4+1120)+(16384+16) {
		t.Errorf("LinkDepositBytes() = %d, want 17,526: u16(alg_id), LP(ct_xwing) of 1,120, the invitation padded to 16,384, a 16 octet tag", LinkDepositBytes())
	}
	if len(box.publicCt) != LinkCardBytes() || len(box.depositCt) != LinkDepositBytes() {
		t.Errorf("the fixture's card is %d octets and its deposit %d", len(box.publicCt), len(box.depositCt))
	}
}

// One arm of the rendezvous: its label, the key it is signed under, how its preimage is built for
// a box id and a nonce, and how it is verified.
type rendezvousArm struct {
	name   string
	label  string
	key    func(box rendezvousKnownBox) ed25519.PrivateKey
	build  func(box rendezvousKnownBox, nonce []byte, id []byte) []byte
	verify func(box rendezvousKnownBox, pub []byte, nonce []byte, id []byte, sig []byte) bool
}

func rendezvousArms() []rendezvousArm {
	depositKey := func(box rendezvousKnownBox) ed25519.PrivateKey { return box.depositKey }
	collectKey := func(box rendezvousKnownBox) ed25519.PrivateKey { return box.collectKey }
	registration := func(box rendezvousKnownBox, pub []byte, id []byte) *RendezvousRegistration {
		r := box.registration()
		r.RendezvousId = id
		r.CollectVerifyPub = pub
		return r
	}
	collecting := func(box rendezvousKnownBox, id []byte) *RendezvousCollectParams {
		c := box.collect
		c.RendezvousId = id
		return &c
	}
	return []rendezvousArm{{
		name:  "register",
		label: rendezvousRegisterLabel,
		key:   collectKey,
		build: func(box rendezvousKnownBox, nonce []byte, id []byte) []byte {
			return RendezvousRegisterPreimage(nonce, registration(box, box.collectKey.Public().(ed25519.PublicKey), id))
		},
		verify: func(box rendezvousKnownBox, pub []byte, nonce []byte, id []byte, sig []byte) bool {
			return VerifyRendezvousRegister(registration(box, pub, id), nonce, sig)
		},
	}, {
		name:  "open",
		label: rendezvousOpenLabel,
		key:   depositKey,
		build: func(box rendezvousKnownBox, nonce []byte, id []byte) []byte {
			return RendezvousOpenPreimage(nonce, id)
		},
		verify: func(box rendezvousKnownBox, pub []byte, nonce []byte, id []byte, sig []byte) bool {
			return VerifyRendezvousOpen(pub, nonce, id, sig)
		},
	}, {
		name:  "deposit",
		label: rendezvousDepositLabel,
		key:   depositKey,
		build: func(box rendezvousKnownBox, nonce []byte, id []byte) []byte {
			return RendezvousDepositPreimage(nonce, id, box.depositCt)
		},
		verify: func(box rendezvousKnownBox, pub []byte, nonce []byte, id []byte, sig []byte) bool {
			return VerifyRendezvousDeposit(pub, nonce, id, box.depositCt, sig)
		},
	}, {
		name:  "collect",
		label: rendezvousCollectLabel,
		key:   collectKey,
		build: func(box rendezvousKnownBox, nonce []byte, id []byte) []byte {
			return RendezvousCollectPreimage(nonce, collecting(box, id))
		},
		verify: func(box rendezvousKnownBox, pub []byte, nonce []byte, id []byte, sig []byte) bool {
			return VerifyRendezvousCollect(pub, nonce, collecting(box, id), sig)
		},
	}, {
		name:  "retire",
		label: rendezvousRetireLabel,
		key:   collectKey,
		build: func(box rendezvousKnownBox, nonce []byte, id []byte) []byte {
			return RendezvousRetirePreimage(nonce, id)
		},
		verify: func(box rendezvousKnownBox, pub []byte, nonce []byte, id []byte, sig []byte) bool {
			return VerifyRendezvousRetire(pub, nonce, id, sig)
		},
	}}
}

// The labels a preimage may be signed under instead of its own: the other four arms', and two of
// the record layer's own beside a near miss of a rendezvous label.
var rendezvousOtherLabels = []string{
	rendezvousRegisterLabel, rendezvousOpenLabel, rendezvousDepositLabel, rendezvousCollectLabel,
	rendezvousRetireLabel, rendezvousLinkLabel, writeAuthLabel, requestAuthLabel, "URmessage/v1/rzvopem",
}

// Property 1: each verifier accepts exactly the preimage section 5.14 defines, under its label and
// for kind 4, and refuses another label, another kind (kind 0 included), another box id and
// another key -- and another connection's nonce, since every preimage binds one.
func TestEveryRendezvousVerifierAcceptsOnlyItsOwnPreimage(t *testing.T) {
	box := rendezvousTheKnownBox(t)
	for _, arm := range rendezvousArms() {
		t.Run(arm.name, func(t *testing.T) {
			key := arm.key(box)
			pub := key.Public().(ed25519.PublicKey)
			own := arm.build(box, box.nonce, box.id)
			if !bytes.HasPrefix(own, []byte(arm.label)) {
				t.Fatalf("the %s preimage does not begin with its label %q", arm.name, arm.label)
			}
			// THE CONTROL: its own preimage, signed by its own key, verifies
			if !arm.verify(box, pub, box.nonce, box.id, ed25519.Sign(key, own)) {
				t.Fatalf("the %s verifier refuses its own preimage under its own key", arm.name)
			}

			// ANOTHER LABEL: the same fields under every other label
			for _, label := range rendezvousOtherLabels {
				if label == arm.label {
					continue
				}
				relabelled := append([]byte(label), own[len(arm.label):]...)
				if arm.verify(box, pub, box.nonce, box.id, ed25519.Sign(key, relabelled)) {
					t.Errorf("the %s verifier accepts its fields signed under the label %q", arm.name, label)
				}
			}
			// and its own label with nothing in front of the fields' first length prefix
			if arm.verify(box, pub, box.nonce, box.id, ed25519.Sign(key, own[len(arm.label):])) {
				t.Errorf("the %s verifier accepts its fields signed with no label at all", arm.name)
			}

			// ANOTHER BOX ID: one octet flipped, another code's id, and the card's id (kind 0's)
			// for the same code, which is how the four arms with no kind of their own tell a card
			// from a link box
			flipped := append([]byte(nil), box.id...)
			flipped[0] ^= 0x80
			otherCode := append([]byte(nil), box.code...)
			otherCode[0] ^= 0x01
			otherId := RendezvousId(otherCode)
			for _, one := range []struct {
				what string
				id   []byte
			}{{"its id with one octet flipped", flipped}, {"another code's id", otherId[:]}, {"kind 0's id for the same code", box.cardId}} {
				if arm.verify(box, pub, box.nonce, one.id, ed25519.Sign(key, own)) {
					t.Errorf("the %s verifier accepts a signature over its box's preimage for %s", arm.name, one.what)
				}
				if !arm.verify(box, pub, box.nonce, one.id, ed25519.Sign(key, arm.build(box, box.nonce, one.id))) {
					t.Errorf("the %s verifier refuses %s's own preimage, signed: the refusal above was about the key, not the id", arm.name, one.what)
				}
			}

			// ANOTHER KEY: the box's other key, and a stranger's
			other := box.depositKey
			if bytes.Equal(key, box.depositKey) {
				other = box.collectKey
			}
			for _, stranger := range []ed25519.PrivateKey{other, box.strangerKey} {
				if arm.verify(box, pub, box.nonce, box.id, ed25519.Sign(stranger, own)) {
					t.Errorf("the %s verifier accepts its preimage signed by another key", arm.name)
				}
				if arm.verify(box, stranger.Public().(ed25519.PublicKey), box.nonce, box.id, ed25519.Sign(key, own)) {
					t.Errorf("the %s verifier accepts its own key's signature under another key", arm.name)
				}
			}

			// ANOTHER CONNECTION: the nonce one octet off, and no nonce at all
			otherNonce := append([]byte(nil), box.nonce...)
			otherNonce[31] ^= 0x01
			if arm.verify(box, pub, otherNonce, box.id, ed25519.Sign(key, own)) {
				t.Errorf("the %s verifier accepts a signature made over another connection's nonce", arm.name)
			}
			if arm.verify(box, pub, nil, box.id, ed25519.Sign(key, own)) {
				t.Errorf("the %s verifier answers true with no nonce", arm.name)
			}

			// WIDTHS: a key or a signature of the wrong width is false, and not a panic
			if arm.verify(box, pub[:31], box.nonce, box.id, ed25519.Sign(key, own)) {
				t.Errorf("the %s verifier answers true under a 31 octet key", arm.name)
			}
			if arm.verify(box, pub, box.nonce, box.id, ed25519.Sign(key, own)[:63]) {
				t.Errorf("the %s verifier answers true on a 63 octet signature", arm.name)
			}
		})
	}

	// ANOTHER KIND, the register arm's own dimension: its preimage carries the kind, and only the
	// link box's verifies. Each other kind is signed properly in the form it would have, so what
	// refuses it is the kind and not the signature.
	t.Run("register/kind", func(t *testing.T) {
		linkBox := RendezvousRegisterPreimage(box.nonce, box.registration())
		kindAt := len(linkBox) - len(box.publicCt) - 4 - 4
		if got := binary.BigEndian.Uint32(linkBox[kindAt:]); got != 4 {
			t.Fatalf("the fixture's kind field reads %d", got)
		}
		for _, kind := range []uint32{0, 1, 2, 3, 5, 0x00000104} {
			r := box.registration()
			r.Kind = kind
			// the kinded form, with this kind where 4 was
			kinded := append([]byte(nil), linkBox...)
			binary.BigEndian.PutUint32(kinded[kindAt:], kind)
			if VerifyRendezvousRegister(r, box.nonce, ed25519.Sign(box.collectKey, kinded)) {
				t.Errorf("a kind %d registration signed in the kinded form verifies as a link box's", kind)
			}
			// the link box's own signature, presented as this kind
			if VerifyRendezvousRegister(r, box.nonce, ed25519.Sign(box.collectKey, linkBox)) {
				t.Errorf("the link box's signature verifies for a registration presented as kind %d", kind)
			}
		}
		// kind 0 in the card's own form, which ends at u16(alg_id)
		card := box.registration()
		card.Kind = 0
		cardForm := linkBox[:kindAt]
		if VerifyRendezvousRegister(card, box.nonce, ed25519.Sign(box.collectKey, cardForm)) {
			t.Error("a kind 0 registration signed in the card's form verifies")
		}
		// and no kind but 4 has a preimage at all: the computing half refuses it by name
		if err := rendezvousRefusal(func() { RendezvousRegisterPreimage(box.nonce, card) }); !errors.Is(err, ErrRendezvousKindNotServed) {
			t.Errorf("RendezvousRegisterPreimage over kind 0 answered %v, want a panic with ErrRendezvousKindNotServed", err)
		}
		// the control: the same registration as kind 4 still verifies
		if !VerifyRendezvousRegister(box.registration(), box.nonce, ed25519.Sign(box.collectKey, linkBox)) {
			t.Error("the link box's own registration does not verify")
		}
	})

	// THE REGISTRATION'S EVERY FIELD, AND THE COLLECT'S, AND THE DEPOSIT ITSELF: each one changed
	// after signing is a refusal
	t.Run("fields", func(t *testing.T) {
		registerSig := ed25519.Sign(box.collectKey, RendezvousRegisterPreimage(box.nonce, box.registration()))
		for _, change := range []struct {
			what  string
			apply func(r *RendezvousRegistration)
		}{
			{"the deposit key", func(r *RendezvousRegistration) { r.DepositVerifyPub = box.strangerKey.Public().(ed25519.PublicKey) }},
			{"card_xwing_pub", func(r *RendezvousRegistration) { r.CardXwingPub = []byte{0x00} }},
			{"alg_id", func(r *RendezvousRegistration) { r.AlgId = 0x0015 }},
			{"the card's last octet", func(r *RendezvousRegistration) {
				r.PublicCt = append([]byte(nil), r.PublicCt...)
				r.PublicCt[len(r.PublicCt)-1] ^= 0x01
			}},
			{"the card's length", func(r *RendezvousRegistration) { r.PublicCt = r.PublicCt[:len(r.PublicCt)-1] }},
		} {
			r := box.registration()
			change.apply(r)
			if VerifyRendezvousRegister(r, box.nonce, registerSig) {
				t.Errorf("a registration with %s changed after signing verifies", change.what)
			}
		}
		collectPub := box.collectKey.Public().(ed25519.PublicKey)
		collectSig := ed25519.Sign(box.collectKey, RendezvousCollectPreimage(box.nonce, &box.collect))
		for _, change := range []struct {
			what  string
			apply func(c *RendezvousCollectParams)
		}{
			{"since_deposit_id", func(c *RendezvousCollectParams) { c.SinceDepositId++ }},
			{"ack_through_deposit_id", func(c *RendezvousCollectParams) { c.AckThroughDepositId++ }},
			{"limit", func(c *RendezvousCollectParams) { c.Limit++ }},
			{"subscribe", func(c *RendezvousCollectParams) { c.Subscribe = !c.Subscribe }},
		} {
			c := box.collect
			change.apply(&c)
			if VerifyRendezvousCollect(collectPub, box.nonce, &c, collectSig) {
				t.Errorf("a collect with %s changed after signing verifies", change.what)
			}
		}
		depositPub := box.depositKey.Public().(ed25519.PublicKey)
		depositSig := ed25519.Sign(box.depositKey, RendezvousDepositPreimage(box.nonce, box.id, box.depositCt))
		otherDeposit := append([]byte(nil), box.depositCt...)
		otherDeposit[100] ^= 0x01
		if VerifyRendezvousDeposit(depositPub, box.nonce, box.id, otherDeposit, depositSig) {
			t.Error("a deposit with one octet changed after signing verifies")
		}
	})

	// NOTHING TO VERIFY OVER: false from the verifying half, the sentinel from the computing half
	t.Run("absent", func(t *testing.T) {
		sig := make([]byte, ed25519.SignatureSize)
		if VerifyRendezvousRegister(nil, box.nonce, sig) || VerifyRendezvousCollect(box.collectKey.Public().(ed25519.PublicKey), box.nonce, nil, sig) {
			t.Error("a verifier answers true over no registration or no collect parameters")
		}
		for _, one := range []struct {
			what  string
			build func()
			want  error
		}{
			{"a register preimage over no registration", func() { RendezvousRegisterPreimage(box.nonce, nil) }, ErrRendezvousNil},
			{"a collect preimage over no parameters", func() { RendezvousCollectPreimage(box.nonce, nil) }, ErrRendezvousNil},
			{"a register preimage over no nonce", func() { RendezvousRegisterPreimage(nil, box.registration()) }, ErrServerNonceEmpty},
			{"an open preimage over no nonce", func() { RendezvousOpenPreimage(nil, box.id) }, ErrServerNonceEmpty},
			{"a deposit preimage over no nonce", func() { RendezvousDepositPreimage(nil, box.id, box.depositCt) }, ErrServerNonceEmpty},
			{"a collect preimage over no nonce", func() { RendezvousCollectPreimage(nil, &box.collect) }, ErrServerNonceEmpty},
			{"a retire preimage over no nonce", func() { RendezvousRetirePreimage(nil, box.id) }, ErrServerNonceEmpty},
		} {
			if err := rendezvousRefusal(one.build); !errors.Is(err, one.want) {
				t.Errorf("%s answered %v, want a panic with %v", one.what, err, one.want)
			}
		}
	})
}

// What a computing half panicked with, as an error, or nil when it did not panic.
func rendezvousRefusal(build func()) (refusal error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			if err, isError := recovered.(error); isError {
				refusal = err
				return
			}
			refusal = fmt.Errorf("a panic that is not an error: %v", recovered)
		}
	}()
	build()
	return nil
}

// THE PUBLISHED PREDICATE (LRI R72): the server's Register asks it of a box's two keys. A key of
// small order is refused with either sign bit, an ordinary key is accepted, and every other width
// -- nil, empty, one octet short or long, and every length to twice the width -- answers false
// without a panic.
func TestRendezvousKeyIsAcceptableRefusesSmallOrderAndEveryOtherWidth(t *testing.T) {
	box := rendezvousTheKnownBox(t)
	for _, key := range []ed25519.PrivateKey{box.depositKey, box.collectKey, box.strangerKey} {
		pub := key.Public().(ed25519.PublicKey)
		if !RendezvousKeyIsAcceptable(pub) {
			t.Fatalf("the ordinary key %x is refused, so the refusals below observe nothing", pub)
		}
		for _, wrong := range [][]byte{pub[:ed25519.PublicKeySize-1], append(append([]byte(nil), pub...), 0x00)} {
			if RendezvousKeyIsAcceptable(wrong) {
				t.Errorf("a %d octet key cut or padded from %x is acceptable", len(wrong), pub)
			}
		}
	}
	for _, small := range rendezvousSmallOrderKeys {
		for _, signBit := range []byte{0x00, 0x80} {
			key := small
			key[31] |= signBit
			if RendezvousKeyIsAcceptable(key[:]) {
				t.Errorf("the small-order key %x is acceptable", key)
			}
		}
	}
	if RendezvousKeyIsAcceptable(nil) || RendezvousKeyIsAcceptable([]byte{}) {
		t.Error("no key at all is acceptable")
	}
	for length := range 2*ed25519.PublicKeySize + 1 {
		if length != ed25519.PublicKeySize && RendezvousKeyIsAcceptable(aadRamp(0x01, length)) {
			t.Errorf("a %d octet key is acceptable", length)
		}
	}
}

// A KEY OF SMALL ORDER VERIFIES NOTHING (LRI R72). Under the neutral point's encoding
// crypto/ed25519 accepts R = the neutral point, S = 0 over every message, and the control below
// holds that it still does, over each arm's own preimage; so a box pinned under that key would be a
// box anyone could open, deposit into, collect or retire, holding no secret at all. Each verifier
// refuses that forgery, and refuses every one of the seven small-order encodings, with either sign
// bit, whatever the signature.
func TestNoRendezvousVerifierAcceptsAKeyOfSmallOrder(t *testing.T) {
	box := rendezvousTheKnownBox(t)
	neutral := rendezvousSmallOrderKeys[1]
	forged := append(append([]byte(nil), neutral[:]...), make([]byte, 32)...)
	for _, arm := range rendezvousArms() {
		key := arm.key(box)
		real := ed25519.Sign(key, arm.build(box, box.nonce, box.id))
		// the positive control: the arm verifies its own signature under its own key
		if !arm.verify(box, key.Public().(ed25519.PublicKey), box.nonce, box.id, real) {
			t.Fatalf("the %s verifier refuses its own signature, so the refusals below observe nothing", arm.name)
		}
		// the control on the forgery: crypto/ed25519 accepts it, so the refusal is this package's
		if !ed25519.Verify(ed25519.PublicKey(neutral[:]), arm.build(box, box.nonce, box.id), forged) {
			t.Fatalf("crypto/ed25519 refuses R = identity, S = 0 under the identity key over the %s preimage: the refusal may have stopped being needed", arm.name)
		}
		if arm.verify(box, neutral[:], box.nonce, box.id, forged) {
			t.Errorf("the %s verifier accepts R = identity, S = 0 under the identity-point key", arm.name)
		}
		for _, small := range rendezvousSmallOrderKeys {
			for _, signBit := range []byte{0x00, 0x80} {
				smallKey := small
				smallKey[31] |= signBit
				for _, chosen := range [][]byte{forged, real, make([]byte, ed25519.SignatureSize)} {
					if arm.verify(box, smallKey[:], box.nonce, box.id, chosen) {
						t.Errorf("the %s verifier accepts a signature under the small-order key %x", arm.name, smallKey)
					}
				}
			}
		}
	}
}

// The seven small-order encodings this package refuses are the curve's own: derived here from
// edwards25519 with math/big -- y = 0, 1 and p-1, the two y of the points of order 8, and the
// non-canonical p and p+1 -- and held to the table both ways, as messagegroup's
// TestTheEdgeVectorsOfEd25519AreRefused holds identityVerify's copy. A key that is usable stays
// usable: the control.
func TestTheRendezvousSmallOrderKeysAreTheCurvesOwn(t *testing.T) {
	p := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	d := new(big.Int).Mod(new(big.Int).Mul(big.NewInt(-121665), new(big.Int).ModInverse(big.NewInt(121666), p)), p)
	sqrt := func(value *big.Int) *big.Int {
		root := new(big.Int).Exp(value, new(big.Int).Div(new(big.Int).Add(p, big.NewInt(3)), big.NewInt(8)), p)
		if new(big.Int).Mod(new(big.Int).Mul(root, root), p).Cmp(new(big.Int).Mod(value, p)) != 0 {
			i := new(big.Int).Exp(big.NewInt(2), new(big.Int).Div(new(big.Int).Sub(p, big.NewInt(1)), big.NewInt(4)), p)
			root.Mod(root.Mul(root, i), p)
		}
		if new(big.Int).Mod(new(big.Int).Mul(root, root), p).Cmp(new(big.Int).Mod(value, p)) != 0 {
			return nil
		}
		return root
	}
	// the points of order 8: y^2 = (-1 +- sqrt(1 + d)) / d, at the sign whose value is a square
	s := sqrt(new(big.Int).Add(d, big.NewInt(1)))
	if s == nil {
		t.Fatal("1 + d has no square root")
	}
	ys := []*big.Int{big.NewInt(0), big.NewInt(1), new(big.Int).Sub(p, big.NewInt(1)), new(big.Int).Set(p), new(big.Int).Add(p, big.NewInt(1))}
	inverseD := new(big.Int).ModInverse(d, p)
	for _, sign := range []int64{1, -1} {
		ySquared := new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Add(big.NewInt(-1), new(big.Int).Mul(big.NewInt(sign), s)), inverseD), p)
		if y := sqrt(ySquared); y != nil {
			ys = append(ys, y, new(big.Int).Sub(p, y))
		}
	}
	derived := map[string]bool{}
	for _, y := range ys {
		encoded := make([]byte, 32)
		y.FillBytes(encoded)
		slices.Reverse(encoded)
		derived[string(encoded)] = true
	}
	listed := map[string]bool{}
	for _, small := range rendezvousSmallOrderKeys {
		listed[string(small[:])] = true
	}
	if len(derived) != 7 || len(listed) != 7 {
		t.Fatalf("%d small-order encodings derived and %d listed, want 7 and 7", len(derived), len(listed))
	}
	for encoding := range derived {
		if !listed[encoding] {
			t.Errorf("the small-order encoding %x is derived and not listed", encoding)
		}
		if RendezvousKeyIsAcceptable([]byte(encoding)) {
			t.Errorf("the small-order encoding %x is usable", encoding)
		}
	}
	box := rendezvousTheKnownBox(t)
	for _, key := range []ed25519.PrivateKey{box.depositKey, box.collectKey, box.strangerKey} {
		if !RendezvousKeyIsAcceptable(key.Public().(ed25519.PublicKey)) {
			t.Errorf("the key %x is refused as of small order", key.Public())
		}
	}
}
