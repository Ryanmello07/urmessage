// The keys a recovery phrase derives, and the two IDs: MASTER section 5.2 at Revision 10, as
// ledger item 299's registry froze them (identity phase 1's plan, Task 10).
//
//	S            = Argon2id(password = P34, salt = "URmessage/v1/phrase-stretch",
//	                        t = 3, m = 262,144 KiB, p = 4, len = 32)
//	master_key   = HKDF-Extract(salt = "URmessage/v1", ikm = S)
//	identity     = HKDF-Expand(master_key, "identity/v1", 32)   -> Ed25519: IRK, the identity key
//	isk_root     = HKDF-Expand(master_key, "isk/v1", 32)
//	isk_seed[g]  = HKDF-Expand(isk_root, "iskgen/v1" ‖ u32(g), 32) -> Ed25519: ISK_g
//
// ONLY isk_seed[g] IS EVER KEPT, and only by a phrase device, in its phrase key record. The words,
// S, master_key, isk_root and IRK's private half exist only while a ceremony runs: here, inside
// one call of [WithPhraseKeys], which erases every one of them before it returns, whatever its
// ceremony did. isk_root goes before the ceremony starts, so no ceremony can mint key number g+1
// from what it was handed, and a device that keeps isk_seed[g] cannot either (F1:356).
//
// THE STRETCH'S PARAMETERS ARE NOT FROZEN until they are measured on the owner's computers
// (ledger item 299; M5 H.3). They are phraseStretchFrozen below, and production reads no other:
// every other test of this package stretches through a cheap value its tests declare, handed in
// as an argument, and TestProductionStretchesWithTheFrozenParametersOnly holds that no production
// path can construct or reach one.
//
// THE TWO IDs are taken over the identity's ROOT, the identity key of its first phrase, so a
// phrase change moves neither (MASTER section 5.5; D2 IL1). The account ID is D2's ID1 and the
// device ID D2's DID1, verbatim as item 299 carries them.
package messagegroup

import (
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"

	"github.com/urnetwork/message/syntax"
	"golang.org/x/crypto/argon2"
)

// The stretch's salt, the extraction's salt and the expansion labels (ledger item 299).
const (
	phraseStretchSalt   = "URmessage/v1/phrase-stretch"
	phraseMasterKeySalt = "URmessage/v1"
	identityKeyInfo     = "identity/v1"
	iskRootInfo         = "isk/v1"
	iskSeedInfoLabel    = "iskgen/v1"
)

const (
	// S, master_key, the identity key's seed, isk_root and isk_seed[g] are each thirty two octets
	phraseKeyOctets = 32
	// the salt an account ID is made with: sixteen random octets, made with the ID
	AccountIdSaltSize = 16
	// the account ID is the first sixteen octets of its hash; the device ID the first eight
	accountIdOctets = 16
	deviceIdOctets  = 8
	// id_version, the u16 ID1 hashes before the root
	accountIdVersion uint16 = 1
)

// The labels the two IDs are hashed under (ledger item 299; D2 ID1 and DID1).
const (
	accountIdLabel = "URmessage/v1/id"
	deviceIdLabel  = "URmessage/v1/device-id"
)

// One setting of Argon2id: passes, memory in KiB, and lanes.
type phraseStretchParameters struct {
	time      uint32
	memoryKiB uint32
	lanes     uint8
}

// The stretch's parameters, MASTER section 5.2 and M5 H.3: t = 3, m = 262,144 KiB, p = 4. NOT
// FROZEN until they are measured on the owner's computers, and the only parameters production
// stretches with.
var phraseStretchFrozen = phraseStretchParameters{time: 3, memoryKiB: 262144, lanes: 4}

// S = Argon2id(P34, "URmessage/v1/phrase-stretch", t, m, p, 32), Argon2 version 0x13 with no
// secret and no associated data.
func stretchPhrase(p34 []byte, parameters phraseStretchParameters) []byte {
	return argon2.IDKey(p34, []byte(phraseStretchSalt), parameters.time, parameters.memoryKiB,
		parameters.lanes, phraseKeyOctets)
}

// isk_seed[g] = HKDF-Expand(isk_root, "iskgen/v1" ‖ u32(g), 32). It depends on isk_root and g
// and on nothing else, and isk_root is not kept: so a holder of one key number cannot mint the
// next.
func iskSeedOf(iskRoot []byte, keyNumber uint32) []byte {
	writer := syntax.NewWriter()
	writer.WriteRaw([]byte(iskSeedInfoLabel))
	writer.WriteUint32(keyNumber)
	info, err := writer.Bytes()
	if err != nil {
		panic(fmt.Errorf("messagegroup: the info of a key number's seed could not be built: %w", err))
	}
	return keyScheduleExpand(iskRoot, info, phraseKeyOctets)
}

// PhraseKeys is what one stretch of a recovery phrase derives for key number g: the identity
// key IRK and the phrase's key ISK_g, with the seed isk_seed[g] it is made from.
//
// It is handed to a ceremony by [WithPhraseKeys] and is blank once that call returns. A ceremony
// that keeps the pointer keeps zeros.
type PhraseKeys struct {
	keyNumber uint32
	irk       ed25519.PrivateKey
	iskSeed   []byte
	isk       ed25519.PrivateKey
}

// KeyNumber is g.
func (self *PhraseKeys) KeyNumber() uint32 {
	return self.keyNumber
}

// IdentityKey is IRK's public half: the identity key, and for an identity's first phrase its
// root. It is a copy.
func (self *PhraseKeys) IdentityKey() ed25519.PublicKey {
	return phrasePublicHalf(self.irk)
}

// PhraseKey is ISK_g's public half, the key a base of key number g is checked under. It is a
// copy.
func (self *PhraseKeys) PhraseKey() ed25519.PublicKey {
	return phrasePublicHalf(self.isk)
}

// PhraseKeySeed is isk_seed[g], a copy, for the one place it may go: a phrase device's phrase
// key record (store kind 13). It is the only phrase secret that outlives a ceremony.
func (self *PhraseKeys) PhraseKeySeed() []byte {
	return append([]byte(nil), self.iskSeed...)
}

// The public half of an Ed25519 key, copied out of the expanded key rather than sliced from it,
// for mls.signaturePublicKeyOf's reason: a window onto the expanded key keeps its secret first
// half reachable from what the caller was told is a public key. A blank key answers nil.
func phrasePublicHalf(expanded ed25519.PrivateKey) ed25519.PublicKey {
	if len(expanded) != ed25519.PrivateKeySize {
		return nil
	}
	return append(ed25519.PublicKey(nil), expanded[ed25519.SeedSize:]...)
}

// SignIskCert answers IskCert(g): the identity key's signature over this key number's phrase key.
// IRK's private half exists only inside the ceremony, so this is where every certificate is signed:
// AD1's first, a lock-out's next, and a phrase change's first under the new key (MASTER sections
// 5.3 and 5.5).
func (self *PhraseKeys) SignIskCert() (*IskCert, error) {
	if len(self.irk) != ed25519.PrivateKeySize || len(self.isk) != ed25519.PrivateKeySize {
		return nil, ErrPhraseKeysErased
	}
	cert := &IskCert{IdentityKey: self.IdentityKey(), IskPub: self.PhraseKey(), KeyNumber: self.keyNumber}
	if err := signIskCert(self.irk, cert); err != nil {
		return nil, err
	}
	return cert, nil
}

// SignIdentityStep answers the form-1 step from this ceremony's identity key to next: the step a
// phrase change signs with the old words, before the new key takes over (MASTER section 5.5; V4
// F.0 (1)). It is signed here for the reason SignIskCert is.
func (self *PhraseKeys) SignIdentityStep(next ed25519.PublicKey) (*IdentityStep, error) {
	if len(self.irk) != ed25519.PrivateKeySize {
		return nil, ErrPhraseKeysErased
	}
	return signIdentityStep(self.irk, next)
}

// SignBase names this ceremony's identity key and key number in base, and signs it with ISK_g and
// with author's device key. A base that is not well formed, or that does not name its author as a
// phrase device, is refused before anything is signed.
func (self *PhraseKeys) SignBase(base *DeviceListBase, author ed25519.PrivateKey) error {
	if len(self.irk) != ed25519.PrivateKeySize || len(self.isk) != ed25519.PrivateKeySize {
		return ErrPhraseKeysErased
	}
	base.IdentityKey = self.IdentityKey()
	base.KeyNumber = self.keyNumber
	return signBase(self.isk, author, base)
}

// The erase at the end of a ceremony: every secret a PhraseKeys holds, in place.
//
//go:noinline
func (self *PhraseKeys) erase() {
	zeroize(self.irk)
	zeroize(self.iskSeed)
	zeroize(self.isk)
	self.irk = nil
	self.iskSeed = nil
	self.isk = nil
}

// WithPhraseKeys stretches the phrase once, under the frozen parameters, and runs ceremony with
// the identity key and key number g's phrase key.
//
// Everything the phrase derives is erased before it returns, whatever ceremony did: S,
// master_key and isk_root before ceremony runs, and the identity key, ISK_g and isk_seed[g] when
// it is done. ceremony's error is answered as it is.
func WithPhraseKeys(phrase *RecoveryPhrase, keyNumber uint32, ceremony func(keys *PhraseKeys) error) error {
	return withPhraseKeys(phrase, keyNumber, phraseStretchFrozen, ceremony)
}

// WithPhraseKeys under the stretch parameters it is handed. Production hands it the frozen ones
// and nothing else.
func withPhraseKeys(phrase *RecoveryPhrase, keyNumber uint32, parameters phraseStretchParameters,
	ceremony func(keys *PhraseKeys) error) error {

	if phrase == nil || ceremony == nil {
		return ErrPhraseKeysCeremony
	}
	keys := derivePhraseKeys(phrase, keyNumber, parameters)
	defer keys.erase()
	return ceremony(keys)
}

// The one stretch and the derivations under it. Every intermediate is erased in the body that
// made it, before the keys are handed back.
func derivePhraseKeys(phrase *RecoveryPhrase, keyNumber uint32, parameters phraseStretchParameters) *PhraseKeys {
	stretched := stretchPhrase(phrase.p34[:], parameters)
	defer zeroize(stretched)
	masterKey := keyScheduleExtract([]byte(phraseMasterKeySalt), stretched)
	defer zeroize(masterKey)
	irkSeed := keyScheduleExpand(masterKey, []byte(identityKeyInfo), phraseKeyOctets)
	defer zeroize(irkSeed)
	iskRoot := keyScheduleExpand(masterKey, []byte(iskRootInfo), phraseKeyOctets)
	defer zeroize(iskRoot)
	iskSeed := iskSeedOf(iskRoot, keyNumber)
	return &PhraseKeys{
		keyNumber: keyNumber,
		irk:       ed25519.NewKeyFromSeed(irkSeed),
		iskSeed:   iskSeed,
		isk:       ed25519.NewKeyFromSeed(iskSeed),
	}
}

// AccountId is an account ID, D2's ID1: sixteen octets of a hash over the identity's root and a
// salt, written as a UUID of version 8 (RFC 9562 section 5.8).
type AccountId [accountIdOctets]byte

// AccountIdOf is ID1:
//
//	id_hash = SHA-256("URmessage/v1/id" ‖ u16(id_version = 1) ‖ LP(root_pub) ‖ LP(salt))
//	id      = id_hash[0..16) with octet 6 = (id_hash[6] & 0x0F) | 0x80
//	                         and octet 8 = (id_hash[8] & 0x3F) | 0x80
//
// root is the identity's root, the identity key of its first phrase, and salt is the sixteen
// random octets made with the ID. It changes with either, and with nothing else.
func AccountIdOf(root ed25519.PublicKey, salt [AccountIdSaltSize]byte) (AccountId, error) {
	if len(root) != ed25519.PublicKeySize {
		return AccountId{}, fmt.Errorf("%w: the root is %d", ErrIdentityPublicKeyLength, len(root))
	}
	writer := syntax.NewWriter()
	writer.WriteRaw([]byte(accountIdLabel))
	writer.WriteUint16(accountIdVersion)
	writer.WriteOpaqueLP(root)
	writer.WriteOpaqueLP(salt[:])
	preimage, err := writer.Bytes()
	if err != nil {
		panic(fmt.Errorf("messagegroup: an account ID's preimage could not be built: %w", err))
	}
	return accountIdOfHash(sha256.Sum256(preimage)), nil
}

// The ID's sixteen octets out of its hash, with UUIDv8's version and variant set. Octet 6's low
// nibble is written idHash[6] % 16, which is ID1's (id_hash[6] & 0x0F) for an octet:
// message/record_test.go reserves the & 0x0F spelling for the record header's class and bucket.
func accountIdOfHash(idHash [sha256.Size]byte) AccountId {
	var id AccountId
	copy(id[:], idHash[:accountIdOctets])
	id[6] = idHash[6]%16 | 0x80
	id[8] = (idHash[8] & 0x3F) | 0x80
	return id
}

// String is the ID as the app shows it: 8-4-4-4-12 lowercase hex, 36 characters.
func (self AccountId) String() string {
	text := make([]byte, 0, 36)
	for at, octet := range self {
		if at == 4 || at == 6 || at == 8 || at == 10 {
			text = append(text, '-')
		}
		text = append(text, phraseHexDigits[octet/16], phraseHexDigits[octet%16])
	}
	return string(text)
}

// DeviceId is a device ID, D2's DID1: eight octets of a hash over the identity's root and the
// device's key.
type DeviceId [deviceIdOctets]byte

// DeviceIdOf is DID1:
//
//	device_id = SHA-256("URmessage/v1/device-id" ‖ LP(root_pub) ‖ LP(device_pub))[0..8)
//
// It changes with the device key and with the root, and with nothing else (D2 DID3): it takes
// no salt, so changing the account ID leaves it.
func DeviceIdOf(root ed25519.PublicKey, device ed25519.PublicKey) (DeviceId, error) {
	if len(root) != ed25519.PublicKeySize {
		return DeviceId{}, fmt.Errorf("%w: the root is %d", ErrIdentityPublicKeyLength, len(root))
	}
	if len(device) != ed25519.PublicKeySize {
		return DeviceId{}, fmt.Errorf("%w: the device key is %d", ErrIdentityPublicKeyLength, len(device))
	}
	writer := syntax.NewWriter()
	writer.WriteRaw([]byte(deviceIdLabel))
	writer.WriteOpaqueLP(root)
	writer.WriteOpaqueLP(device)
	preimage, err := writer.Bytes()
	if err != nil {
		panic(fmt.Errorf("messagegroup: a device ID's preimage could not be built: %w", err))
	}
	return deviceIdOfHash(sha256.Sum256(preimage)), nil
}

// The ID's eight octets out of its hash.
func deviceIdOfHash(idHash [sha256.Size]byte) DeviceId {
	return DeviceId(idHash[:deviceIdOctets])
}

// String is the ID as the app shows it: four groups of four lowercase hex characters, 19 in all,
// so that nobody takes it for an account ID.
func (self DeviceId) String() string {
	text := make([]byte, 0, 19)
	for at, octet := range self {
		if at == 2 || at == 4 || at == 6 {
			text = append(text, '-')
		}
		text = append(text, phraseHexDigits[octet/16], phraseHexDigits[octet%16])
	}
	return string(text)
}

// The lowercase hex digits both IDs are written in, one for each half of an octet: octet/16 and
// octet%16, which are the nibble shift and mask message/record_test.go reserves for the record
// header, spelled as the arithmetic they are.
const phraseHexDigits = "0123456789abcdef"
