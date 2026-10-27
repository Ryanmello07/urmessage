// The identity extensions and the checks over them: identity phase 1's plan, Task 11. MASTER
// sections 5.3 and 11 at Revision 10, Spec A A-36's section 3.4, and ledger items 299 and 300,
// whose registries freeze the labels, the bounds and the code points.
//
// urmessage_identity (0xF005) version 1 is carried by every leaf of every group but a link group's
// profile-1 leaf. It holds three things:
//
//   - the certificate IskCert(g), by which the identity key certifies the phrase's key ISK_g;
//   - the device list: a BASE signed by ISK_g and by the device that made it, then at most 16
//     AMENDMENTS, each an addition or a self-removal signed by a listed device's key;
//   - the CHAIN: the form-1 steps from the identity's root to the leaf's identity key, at most 4.
//
// urmessage_group_purpose (0xF006) version 1 is {version, purpose, identity_root}, in a system
// group's context: the root in a self group, the current identity key in a link group.
//
// THE FIELD SETS are F1 section 2.2's, less added_at_ms, added_by, not_after_ms, RetiredLegacy
// and the predecessor's form 2, with M5's base and amendments for the one list (Spec A A-36). In
// I1 the certificate carries no backup fingerprint, since I1 derives no backup key; the list
// carries no pending removals and no rejoin; the chain of form-1 steps stands where M5 has one
// predecessor (SCOPE X12); and no 16-octet device id stands anywhere, since an entry and an
// amendment name a device by its key, whose ID is derived (SCOPE X6; MASTER section 5.2). F1's
// successor_identity, the predecessor's other half, goes with the predecessor. An entry has two
// flags, phrase device and being removed (SCOPE C1); I1 never sets the second. The first base
// under a key number is base 1, and each later one the one before plus one (item 300).
//
// EVERY SIGNATURE IS Ed25519 OVER LP(label) ‖ encode(tbs), under one of four labels, and a step is
// Ed25519(old key, LP("URmessage/v1/identity-succession") ‖ LP(next key)). LP is a four-octet
// big-endian length, so every such preimage begins with the octet 0x00, and no MLS SignContent
// does: it begins with the varint length of "MLS 1.0 " and a label, at least 8. So a device key
// signs in two domains that never meet (F1:365-367).
//
// THE ENCODING is the MLS presentation language through syntax, as 0xF002's is: integers big
// endian, opaque<V> and every vector<V> behind a varint length.
package messagegroup

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"

	"github.com/urnetwork/message/mls"
	"github.com/urnetwork/message/syntax"
)

// The one version of every object here, and the one algorithm, Ed25519 (alg_id 0x0001).
const (
	identityObjectVersion uint16 = 1
	identityAlgEd25519    uint16 = 0x0001
)

// The signature labels: the four of the list (items 299 and 300) and the step's.
const (
	iskCertLabel            = "URmessage/v1/isk-cert"
	deviceListLabel         = "URmessage/v1/device-list"
	deviceListAuthorLabel   = "URmessage/v1/device-list-author"
	deviceAmendmentLabel    = "URmessage/v1/device-amendment"
	identitySuccessionLabel = "URmessage/v1/identity-succession"
)

// The bounds: the extension's size, the list's devices and amendments, and the chain's steps
// (item 299's registry; M5 TR12; SCOPE X5 and X12).
const (
	IdentityExtensionMaxOctets = 6144
	DeviceListMaxDevices       = 10
	DeviceListMaxAmendments    = 16
	IdentityChainMaxSteps      = 4
)

// The entry's flags. Being removed is reserved: I1 never sets it, and no rule of I1 reads it.
const (
	DeviceFlagPhraseDevice uint8 = 0x01
	DeviceFlagBeingRemoved uint8 = 0x02
	deviceFlagsKnown             = DeviceFlagPhraseDevice | DeviceFlagBeingRemoved
)

// An amendment's two kinds.
const (
	AmendmentAddition    uint8 = 1
	AmendmentSelfRemoval uint8 = 2
)

// A step's form. Form 1 is signed by the old identity key, which only the old phrase makes; form 2
// is the 7-day change's, which ships in a later release, and is refused (D2 VID2).
const IdentityStepForm1 uint8 = 1

// A system group's purpose, 0xF006.
const (
	GroupPurposeSelf uint8 = 1
	GroupPurposeLink uint8 = 2
)

// The width of a key and of a signature: Ed25519's, and every key here is one.
const (
	identityKeyOctets       = ed25519.PublicKeySize
	identitySignatureOctets = ed25519.SignatureSize
	identityHashOctets      = sha256.Size
)

// IskCert is IskCert(g): the identity key's signature over the phrase's key for key number g. It
// has no timestamp, so every holder of the phrase mints the same octets for one key number.
type IskCert struct {
	// the identity key that signs: the root for an identity's first phrase
	IdentityKey []byte
	// ISK_g's public half
	IskPub []byte
	// g, from 1
	KeyNumber uint32
	Signature []byte
}

// DeviceEntry is one device of a list: its key and its flags.
type DeviceEntry struct {
	DeviceKey []byte
	Flags     uint8
}

// DeviceListBase is a base: the devices under one identity key and key number, signed by ISK_g
// and by the device that made it, which the base names as a phrase device.
type DeviceListBase struct {
	IdentityKey []byte
	KeyNumber   uint32
	BaseNumber  uint64
	// informational: no rule reads a clock (F1 P-ID-DET)
	IssuedAtMs uint64
	// empty for an identity's first base; otherwise the 32-octet hash of the head of the list this
	// base replaces, its last amendment's hash or, with none, its base's. No rule of I1 reads it
	PrevHash []byte
	// 1 to 10, in ascending order of key, each key once
	Devices         []DeviceEntry
	AuthorKey       []byte
	AuthorSignature []byte
	Signature       []byte
}

// Amendment is one change on top of a base, signed by its author's device key: an addition, or a
// self-removal, whose author is the device that leaves.
type Amendment struct {
	BaseHash [identityHashOctets]byte
	// from 1
	Index uint16
	// the hash of the amendment before it, or the base's for the first
	PrevHash  [identityHashOctets]byte
	AuthorKey []byte
	// informational
	IssuedAtMs uint64
	Op         uint8
	// the device an addition adds, with no flags; empty for a self-removal
	Entry     DeviceEntry
	Signature []byte
}

// IdentityStep is one form-1 step of a chain: the old identity key, its form, and its signature
// over the next key. The next key is the next step's old key, or, for the last step, the key the
// chain ends at, so it is not carried twice.
type IdentityStep struct {
	OldKey    []byte
	Form      uint8
	Signature []byte
}

// UrmessageIdentity is the body of urmessage_identity (0xF005) version 1.
type UrmessageIdentity struct {
	IskCert    IskCert
	Base       DeviceListBase
	Amendments []Amendment
	// root first; empty until a phrase change (Task 43)
	Chain []IdentityStep
}

// GroupPurpose is the body of urmessage_group_purpose (0xF006) version 1.
type GroupPurpose struct {
	Purpose      uint8
	IdentityRoot []byte
}

// ListVersion is a list's version, (step, g, base, count), compared in that order: step counts
// the chain's steps, so a list under a later key of one root's chain is newer than every list
// under an earlier key, whatever their key numbers (Spec A A-36 section 3.4).
type ListVersion struct {
	Step      int
	KeyNumber uint32
	Base      uint64
	Count     int
}

// Compare answers -1, 0 or 1 as self is older than, the same version as, or newer than other.
func (self ListVersion) Compare(other ListVersion) int {
	switch {
	case self.Step != other.Step:
		return listVersionSign(self.Step < other.Step)
	case self.KeyNumber != other.KeyNumber:
		return listVersionSign(self.KeyNumber < other.KeyNumber)
	case self.Base != other.Base:
		return listVersionSign(self.Base < other.Base)
	case self.Count != other.Count:
		return listVersionSign(self.Count < other.Count)
	}
	return 0
}

func listVersionSign(older bool) int {
	if older {
		return -1
	}
	return 1
}

// Version is the list's version.
func (self *UrmessageIdentity) Version() ListVersion {
	return ListVersion{
		Step:      len(self.Chain),
		KeyNumber: self.Base.KeyNumber,
		Base:      self.Base.BaseNumber,
		Count:     len(self.Amendments),
	}
}

// ListOrder is how a candidate list stands to a stored one.
type ListOrder int

const (
	ListOlder ListOrder = -1
	ListSame  ListOrder = 0
	ListNewer ListOrder = 1
)

// ---------------------------------------------------------------------------------------------
// the encodings
// ---------------------------------------------------------------------------------------------

func encodeIskCertTbs(w *syntax.Writer, cert *IskCert) {
	w.WriteUint16(identityObjectVersion)
	w.WriteUint16(identityAlgEd25519)
	w.WriteOpaque(cert.IdentityKey)
	w.WriteOpaque(cert.IskPub)
	w.WriteUint32(cert.KeyNumber)
}

func encodeIskCert(w *syntax.Writer, cert *IskCert) {
	encodeIskCertTbs(w, cert)
	w.WriteOpaque(cert.Signature)
}

func encodeDeviceEntry(w *syntax.Writer, entry DeviceEntry) error {
	w.WriteOpaque(entry.DeviceKey)
	w.WriteUint8(entry.Flags)
	return w.Err()
}

func encodeBaseTbs(w *syntax.Writer, base *DeviceListBase) {
	w.WriteUint16(identityObjectVersion)
	w.WriteUint16(identityAlgEd25519)
	w.WriteOpaque(base.IdentityKey)
	w.WriteUint32(base.KeyNumber)
	w.WriteUint64(base.BaseNumber)
	w.WriteUint64(base.IssuedAtMs)
	w.WriteOpaque(base.PrevHash)
	syntax.WriteVector(w, base.Devices, encodeDeviceEntry)
	w.WriteOpaque(base.AuthorKey)
}

func encodeBase(w *syntax.Writer, base *DeviceListBase) {
	encodeBaseTbs(w, base)
	w.WriteOpaque(base.AuthorSignature)
	w.WriteOpaque(base.Signature)
}

func encodeAmendmentTbs(w *syntax.Writer, amendment *Amendment) {
	w.WriteUint16(identityObjectVersion)
	w.WriteRaw(amendment.BaseHash[:])
	w.WriteUint16(amendment.Index)
	w.WriteRaw(amendment.PrevHash[:])
	w.WriteOpaque(amendment.AuthorKey)
	w.WriteUint64(amendment.IssuedAtMs)
	w.WriteUint8(amendment.Op)
	if amendment.Op == AmendmentAddition {
		encodeDeviceEntry(w, amendment.Entry)
	}
}

func encodeAmendment(w *syntax.Writer, amendment Amendment) error {
	encodeAmendmentTbs(w, &amendment)
	w.WriteOpaque(amendment.Signature)
	return w.Err()
}

func encodeIdentityStep(w *syntax.Writer, step IdentityStep) error {
	w.WriteOpaque(step.OldKey)
	w.WriteUint8(step.Form)
	w.WriteOpaque(step.Signature)
	return w.Err()
}

// The octets one encoder writes, or the codec's error.
func identityEncoding(encode func(w *syntax.Writer)) ([]byte, error) {
	writer := syntax.NewWriter()
	encode(writer)
	return writer.Bytes()
}

// Encode is the 0xF005 extension: its tag and its body together, as mls's LeafKeysExtension.Encode
// hands back 0xF002's, so that no caller pairs the body with a tag of its own choosing.
func (self *UrmessageIdentity) Encode() (ExtensionBytes, error) {
	body, err := identityEncoding(func(w *syntax.Writer) {
		w.WriteUint16(identityObjectVersion)
		encodeIskCert(w, &self.IskCert)
		encodeBase(w, &self.Base)
		syntax.WriteVector(w, self.Amendments, encodeAmendment)
		syntax.WriteVector(w, self.Chain, encodeIdentityStep)
	})
	if err != nil {
		return ExtensionBytes{}, fmt.Errorf("%w: %v", ErrIdentityEncoding, err)
	}
	if IdentityExtensionMaxOctets < len(body) {
		return ExtensionBytes{}, fmt.Errorf("%w: the body is %d octets, the bound %d",
			ErrIdentityEncoding, len(body), IdentityExtensionMaxOctets)
	}
	return ExtensionBytes{Type: uint16(mls.ExtensionTypeUrmessageIdentity), Data: body}, nil
}

// Encode is the 0xF006 extension, its tag and its body together.
func (self *GroupPurpose) Encode() (ExtensionBytes, error) {
	if !groupPurposeKnown(self.Purpose) || len(self.IdentityRoot) != identityKeyOctets {
		return ExtensionBytes{}, fmt.Errorf("%w: purpose %d over a %d-octet root",
			ErrGroupPurposeEncoding, self.Purpose, len(self.IdentityRoot))
	}
	body, err := identityEncoding(func(w *syntax.Writer) {
		w.WriteUint16(identityObjectVersion)
		w.WriteUint8(self.Purpose)
		w.WriteOpaque(self.IdentityRoot)
	})
	if err != nil {
		return ExtensionBytes{}, fmt.Errorf("%w: %v", ErrGroupPurposeEncoding, err)
	}
	return ExtensionBytes{Type: uint16(mls.ExtensionTypeUrmessageGroupPurpose), Data: body}, nil
}

func groupPurposeKnown(purpose uint8) bool {
	return purpose == GroupPurposeSelf || purpose == GroupPurposeLink
}

// ParseGroupPurpose reads a 0xF006 extension, refusing any other tag, any other version, an
// unknown purpose, a root of the wrong width and a trailing octet.
func ParseGroupPurpose(extension ExtensionBytes) (*GroupPurpose, error) {
	if extension.Type != uint16(mls.ExtensionTypeUrmessageGroupPurpose) {
		return nil, fmt.Errorf("%w: extension type %#04x", ErrGroupPurposeEncoding, extension.Type)
	}
	reader := syntax.NewReader(extension.Data)
	version, _ := reader.ReadUint16()
	purpose, _ := reader.ReadUint8()
	root, _ := reader.ReadOpaque()
	if err := reader.Done(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrGroupPurposeEncoding, err)
	}
	if version != identityObjectVersion || !groupPurposeKnown(purpose) || len(root) != identityKeyOctets {
		return nil, fmt.Errorf("%w: version %d, purpose %d, a %d-octet root",
			ErrGroupPurposeEncoding, version, purpose, len(root))
	}
	return &GroupPurpose{Purpose: purpose, IdentityRoot: root}, nil
}

func decodeDeviceEntry(r *syntax.Reader) (DeviceEntry, error) {
	key, err := r.ReadOpaque()
	if err != nil {
		return DeviceEntry{}, err
	}
	flags, err := r.ReadUint8()
	return DeviceEntry{DeviceKey: key, Flags: flags}, err
}

func decodeAmendment(r *syntax.Reader) (Amendment, error) {
	var amendment Amendment
	version, _ := r.ReadUint16()
	baseHash, _ := r.ReadRaw(identityHashOctets)
	amendment.Index, _ = r.ReadUint16()
	prevHash, _ := r.ReadRaw(identityHashOctets)
	amendment.AuthorKey, _ = r.ReadOpaque()
	amendment.IssuedAtMs, _ = r.ReadUint64()
	amendment.Op, _ = r.ReadUint8()
	switch amendment.Op {
	case AmendmentAddition:
		entry, err := decodeDeviceEntry(r)
		if err != nil {
			return Amendment{}, err
		}
		amendment.Entry = entry
	case AmendmentSelfRemoval:
	default:
		return Amendment{}, fmt.Errorf("%w: an amendment of kind %d", ErrIdentityEncoding, amendment.Op)
	}
	signature, err := r.ReadOpaque()
	if err != nil {
		return Amendment{}, err
	}
	if version != identityObjectVersion {
		return Amendment{}, fmt.Errorf("%w: an amendment of version %d", ErrIdentityEncoding, version)
	}
	copy(amendment.BaseHash[:], baseHash)
	copy(amendment.PrevHash[:], prevHash)
	amendment.Signature = signature
	return amendment, nil
}

func decodeIdentityStep(r *syntax.Reader) (IdentityStep, error) {
	oldKey, _ := r.ReadOpaque()
	form, err := r.ReadUint8()
	if err != nil {
		return IdentityStep{}, err
	}
	// a form other than 1 has another body, which version 1 cannot read: form 2 exists only in
	// the release that ships the 7-day change (V4 F.0 (1)), so it is an encoding this version
	// does not have, and is refused here rather than read as a form-1 step
	if form != IdentityStepForm1 {
		return IdentityStep{}, fmt.Errorf("%w: a step of form %d: %w", ErrIdentityEncoding, form, ErrIdentityStepForm)
	}
	signature, err := r.ReadOpaque()
	return IdentityStep{OldKey: oldKey, Form: form, Signature: signature}, err
}

// ParseUrmessageIdentity reads a 0xF005 extension: its tag, its size, its version and every
// field, refusing a trailing octet. It checks no signature; VerifyLeafBinding does.
func ParseUrmessageIdentity(extension ExtensionBytes) (*UrmessageIdentity, error) {
	if extension.Type != uint16(mls.ExtensionTypeUrmessageIdentity) {
		return nil, fmt.Errorf("%w: extension type %#04x", ErrIdentityEncoding, extension.Type)
	}
	if IdentityExtensionMaxOctets < len(extension.Data) {
		return nil, fmt.Errorf("%w: the body is %d octets, the bound %d",
			ErrIdentityExtensionSize, len(extension.Data), IdentityExtensionMaxOctets)
	}
	reader := syntax.NewReader(extension.Data)
	identity := &UrmessageIdentity{}
	version, _ := reader.ReadUint16()
	certVersion, _ := reader.ReadUint16()
	certAlg, _ := reader.ReadUint16()
	identity.IskCert.IdentityKey, _ = reader.ReadOpaque()
	identity.IskCert.IskPub, _ = reader.ReadOpaque()
	identity.IskCert.KeyNumber, _ = reader.ReadUint32()
	identity.IskCert.Signature, _ = reader.ReadOpaque()
	baseVersion, _ := reader.ReadUint16()
	baseAlg, _ := reader.ReadUint16()
	base := &identity.Base
	base.IdentityKey, _ = reader.ReadOpaque()
	base.KeyNumber, _ = reader.ReadUint32()
	base.BaseNumber, _ = reader.ReadUint64()
	base.IssuedAtMs, _ = reader.ReadUint64()
	base.PrevHash, _ = reader.ReadOpaque()
	devices, err := syntax.ReadVector(reader, decodeDeviceEntry)
	if err != nil {
		return nil, fmt.Errorf("%w: the base's devices: %w", ErrIdentityEncoding, err)
	}
	base.Devices = devices
	base.AuthorKey, _ = reader.ReadOpaque()
	base.AuthorSignature, _ = reader.ReadOpaque()
	base.Signature, _ = reader.ReadOpaque()
	amendments, err := syntax.ReadVector(reader, decodeAmendment)
	if err != nil {
		return nil, fmt.Errorf("%w: the amendments: %w", ErrIdentityEncoding, err)
	}
	identity.Amendments = amendments
	chain, err := syntax.ReadVector(reader, decodeIdentityStep)
	if err != nil {
		return nil, fmt.Errorf("%w: the chain: %w", ErrIdentityEncoding, err)
	}
	identity.Chain = chain
	if err := reader.Done(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrIdentityEncoding, err)
	}
	for _, field := range []uint16{version, certVersion, baseVersion} {
		if field != identityObjectVersion {
			return nil, fmt.Errorf("%w: an object of version %d", ErrIdentityEncoding, field)
		}
	}
	if certAlg != identityAlgEd25519 || baseAlg != identityAlgEd25519 {
		return nil, fmt.Errorf("%w: alg_id %#04x and %#04x", ErrIdentityEncoding, certAlg, baseAlg)
	}
	return identity, nil
}

// ---------------------------------------------------------------------------------------------
// the hashes, the preimages and the one verifier
// ---------------------------------------------------------------------------------------------

// The base's hash, which every amendment on it names: SHA-256 of the whole signed base.
func deviceListBaseHash(base *DeviceListBase) ([identityHashOctets]byte, error) {
	encoded, err := identityEncoding(func(w *syntax.Writer) { encodeBase(w, base) })
	if err != nil {
		return [identityHashOctets]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}

// An amendment's hash, which the next one names: SHA-256 of the whole signed amendment.
func amendmentHash(amendment *Amendment) ([identityHashOctets]byte, error) {
	encoded, err := identityEncoding(func(w *syntax.Writer) { encodeAmendment(w, *amendment) })
	if err != nil {
		return [identityHashOctets]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}

// LP(label) ‖ tbs, the one preimage shape every signature of this file is over.
func identityPreimage(label string, tbs []byte) ([]byte, error) {
	writer := syntax.NewWriter()
	writer.WriteOpaqueLP([]byte(label))
	writer.WriteRaw(tbs)
	return writer.Bytes()
}

// The octets a step signs: LP(label) ‖ LP(next key).
func identityStepTbs(next []byte) ([]byte, error) {
	writer := syntax.NewWriter()
	writer.WriteOpaqueLP(next)
	return writer.Bytes()
}

// identitySign is the one signer of this file: Ed25519 over LP(label) ‖ tbs.
func identitySign(key ed25519.PrivateKey, label string, tbs []byte) ([]byte, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: a signing key of %d octets", ErrIdentitySigningKey, len(key))
	}
	preimage, err := identityPreimage(label, tbs)
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(key, preimage), nil
}

// identityVerify is the one verifier of this file: Ed25519 over LP(label) ‖ tbs, under a key that
// is 32 octets and not of small order.
//
// THE SMALL-ORDER REFUSAL IS WHAT crypto/ed25519 LEAVES TO ITS CALLER, measured on the pinned
// toolchain: ed25519.Verify accepts the signature R = the neutral point, S = 0 under the neutral
// point's encoding, for every message, and under its non-canonical encoding too. A list naming
// such a key names a device anyone can sign for. Go refuses a non-canonical S (S >= L), so that
// half of F1's edge vectors needs nothing here; the tests pin both.
func identityVerify(key []byte, label string, tbs []byte, signature []byte) bool {
	if !ed25519KeyIsUsable(key) || len(signature) != identitySignatureOctets {
		return false
	}
	preimage, err := identityPreimage(label, tbs)
	if err != nil {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(key), preimage, signature)
}

// The encodings of the points of small order on edwards25519, with the sign bit cleared: y = 0,
// 1 and p-1, the two y of the points of order 8, and y = p and p+1, the non-canonical encodings
// of 0 and 1 that a 255-bit field admits. They are libsodium's ge25519_has_small_order list. The
// test derives the set from the curve and holds this one to it.
var ed25519SmallOrderEncodings = [7][identityKeyOctets]byte{
	{0x00},
	{0x01},
	{0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0,
		0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05},
	{0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67, 0x0f,
		0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a},
	{0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
	{0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
	{0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
}

// ed25519KeyIsUsable answers whether a key is 32 octets and not of small order: its encoding, sign
// bit cleared, is none of the seven above.
func ed25519KeyIsUsable(key []byte) bool {
	if len(key) != identityKeyOctets {
		return false
	}
	var masked [identityKeyOctets]byte
	copy(masked[:], key)
	masked[identityKeyOctets-1] &= 0x7f
	for _, small := range ed25519SmallOrderEncodings {
		if subtle.ConstantTimeCompare(masked[:], small[:]) == 1 {
			return false
		}
	}
	return true
}

// sameOctets is the equality of two octet strings -- keys, signatures, hashes and encodings -- in
// constant time, as every comparison of octets in this tree is (mls/framing_guard_test.go).
func sameOctets(left []byte, right []byte) bool {
	return len(left) == len(right) && subtle.ConstantTimeCompare(left, right) == 1
}

// compareKeys orders two keys as bytes.Compare would, in constant time: mls/group_policy.go's
// compareMemberIds, the tree's one spelling of an ordering over public keys, written again here
// because mls's is unexported and this package's need is the same. -1, 0 or 1.
func compareKeys(left []byte, right []byte) int {
	shared := min(len(left), len(right))
	decided := 0
	answer := 0
	for i := 0; i < shared; i += 1 {
		same := subtle.ConstantTimeByteEq(left[i], right[i])
		notAfter := subtle.ConstantTimeLessOrEq(int(left[i]), int(right[i]))
		here := subtle.ConstantTimeSelect(same, 0, subtle.ConstantTimeSelect(notAfter, -1, 1))
		answer = subtle.ConstantTimeSelect(decided, answer, here)
		decided |= 1 ^ same
	}
	leftNotLonger := subtle.ConstantTimeLessOrEq(len(left), len(right))
	rightNotLonger := subtle.ConstantTimeLessOrEq(len(right), len(left))
	byLength := subtle.ConstantTimeSelect(leftNotLonger&rightNotLonger, 0,
		subtle.ConstantTimeSelect(leftNotLonger, -1, 1))
	return subtle.ConstantTimeSelect(decided, answer, byLength)
}

// ---------------------------------------------------------------------------------------------
// the signers
// ---------------------------------------------------------------------------------------------

// signIskCert fills the certificate's signature, by the identity key.
func signIskCert(irk ed25519.PrivateKey, cert *IskCert) error {
	tbs, err := identityEncoding(func(w *syntax.Writer) { encodeIskCertTbs(w, cert) })
	if err != nil {
		return err
	}
	signature, err := identitySign(irk, iskCertLabel, tbs)
	if err != nil {
		return err
	}
	cert.Signature = signature
	return nil
}

// SignBaseAuthor fills base's author signature: its author's device key, over
// LP("URmessage/v1/device-list-author") and the base's tbs. The base names author already, as a
// phrase device it lists; ISK_g's signature over the same tbs is the ceremony's,
// (*PhraseKeys).SignBase. The two may be made in either order, and both are needed.
func SignBaseAuthor(base *DeviceListBase, author ed25519.PrivateKey) error {
	if base == nil {
		return fmt.Errorf("%w: no base", ErrDeviceListShape)
	}
	return signBaseByAuthor(author, base)
}

// The base's tbs, once its form and its author are checked. A base that is not well formed is
// refused here as at every receiver, so a list of 11 devices is never signed by either key.
func baseTbsToSign(base *DeviceListBase) ([]byte, error) {
	if err := checkBaseForm(base); err != nil {
		return nil, err
	}
	if !baseNamesPhraseDevice(base, base.AuthorKey) {
		return nil, fmt.Errorf("%w: the base does not name its author as a phrase device", ErrDeviceListShape)
	}
	return identityEncoding(func(w *syntax.Writer) { encodeBaseTbs(w, base) })
}

// signBaseByAuthor is the author's half of a base's signatures.
func signBaseByAuthor(author ed25519.PrivateKey, base *DeviceListBase) error {
	if len(author) != ed25519.PrivateKeySize || !sameOctets(author[ed25519.SeedSize:], base.AuthorKey) {
		return fmt.Errorf("%w: an author key of %d octets, or not the key the base names", ErrIdentitySigningKey, len(author))
	}
	tbs, err := baseTbsToSign(base)
	if err != nil {
		return err
	}
	authorSignature, err := identitySign(author, deviceListAuthorLabel, tbs)
	if err != nil {
		return err
	}
	base.AuthorSignature = authorSignature
	return nil
}

// signBaseByPhraseKey is ISK_g's half.
func signBaseByPhraseKey(isk ed25519.PrivateKey, base *DeviceListBase) error {
	tbs, err := baseTbsToSign(base)
	if err != nil {
		return err
	}
	signature, err := identitySign(isk, deviceListLabel, tbs)
	if err != nil {
		return err
	}
	base.Signature = signature
	return nil
}

// signIdentityStep makes the form-1 step from an identity key to the next one.
func signIdentityStep(irk ed25519.PrivateKey, next []byte) (*IdentityStep, error) {
	if len(irk) != ed25519.PrivateKeySize || !ed25519KeyIsUsable(next) {
		return nil, fmt.Errorf("%w: a step from a %d-octet key to a %d-octet key",
			ErrIdentitySigningKey, len(irk), len(next))
	}
	oldPublic := irk[ed25519.SeedSize:]
	if sameOctets(oldPublic, next) {
		return nil, fmt.Errorf("%w: a step from a key to itself", ErrIdentityChain)
	}
	tbs, err := identityStepTbs(next)
	if err != nil {
		return nil, err
	}
	signature, err := identitySign(irk, identitySuccessionLabel, tbs)
	if err != nil {
		return nil, err
	}
	return &IdentityStep{OldKey: append([]byte(nil), oldPublic...), Form: IdentityStepForm1, Signature: signature}, nil
}

// SignAmendment fills an amendment's author and its signature, by the author's device key. It
// checks nothing about the list; NewAddition and NewSelfRemoval build one that fits.
func SignAmendment(amendment *Amendment, author ed25519.PrivateKey) error {
	if len(author) != ed25519.PrivateKeySize {
		return fmt.Errorf("%w: an author key of %d octets", ErrIdentitySigningKey, len(author))
	}
	amendment.AuthorKey = append([]byte(nil), author[ed25519.SeedSize:]...)
	tbs, err := identityEncoding(func(w *syntax.Writer) { encodeAmendmentTbs(w, amendment) })
	if err != nil {
		return err
	}
	signature, err := identitySign(author, deviceAmendmentLabel, tbs)
	if err != nil {
		return err
	}
	amendment.Signature = signature
	return nil
}

// The next amendment's place on a list: the base's hash, the index after the last, and the hash
// it follows.
func nextAmendmentPlace(identity *UrmessageIdentity) ([identityHashOctets]byte, uint16, [identityHashOctets]byte, error) {
	baseHash, err := deviceListBaseHash(&identity.Base)
	if err != nil {
		return baseHash, 0, baseHash, err
	}
	prevHash := baseHash
	if count := len(identity.Amendments); 0 < count {
		prevHash, err = amendmentHash(&identity.Amendments[count-1])
		if err != nil {
			return baseHash, 0, baseHash, err
		}
	}
	return baseHash, uint16(len(identity.Amendments) + 1), prevHash, nil
}

// NewAddition makes an addition of entry to identity's list, signed by author, a device the list
// names that is not being removed. It is refused when the list already names 10 devices, or when
// 16 changes already wait on the base: a full list takes no addition until a phrase device folds
// it into a new base.
func NewAddition(identity *UrmessageIdentity, entry DeviceEntry, author ed25519.PrivateKey, issuedAtMs uint64) (*Amendment, error) {
	if len(author) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: an author key of %d octets", ErrIdentitySigningKey, len(author))
	}
	devices := effectiveDevices(identity.Base.Devices, identity.Amendments)
	if DeviceListMaxAmendments <= len(identity.Amendments) {
		return nil, fmt.Errorf("%w: %d changes already wait on this base", ErrDeviceListFull, len(identity.Amendments))
	}
	if DeviceListMaxDevices <= len(devices) {
		return nil, fmt.Errorf("%w: the list names %d devices", ErrDeviceListFull, len(devices))
	}
	authorEntry, listed := findDevice(devices, author[ed25519.SeedSize:])
	if !listed || authorEntry.Flags&DeviceFlagBeingRemoved != 0 {
		return nil, fmt.Errorf("%w: the author is not a device this list names, or is being removed", ErrDeviceListShape)
	}
	if _, already := findDevice(devices, entry.DeviceKey); already || entry.Flags != 0 || !ed25519KeyIsUsable(entry.DeviceKey) {
		return nil, fmt.Errorf("%w: an addition of a device listed already, with flags, or with an unusable key", ErrDeviceListShape)
	}
	baseHash, index, prevHash, err := nextAmendmentPlace(identity)
	if err != nil {
		return nil, err
	}
	amendment := &Amendment{BaseHash: baseHash, Index: index, PrevHash: prevHash, IssuedAtMs: issuedAtMs,
		Op: AmendmentAddition, Entry: DeviceEntry{DeviceKey: append([]byte(nil), entry.DeviceKey...)}}
	if err := SignAmendment(amendment, author); err != nil {
		return nil, err
	}
	return amendment, nil
}

// NewSelfRemoval makes author's self-removal from identity's list. IT IS NEVER REFUSED FOR WANT
// OF A PLACE (M5 TR12): where 16 changes already wait on the base, it takes the index after them
// and waits, in the self group, for the next base, which a phrase device folds it into. It is
// refused only when the list does not name the author, or names nobody else.
func NewSelfRemoval(identity *UrmessageIdentity, author ed25519.PrivateKey, issuedAtMs uint64) (*Amendment, error) {
	if len(author) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: an author key of %d octets", ErrIdentitySigningKey, len(author))
	}
	devices := effectiveDevices(identity.Base.Devices, identity.Amendments)
	if _, listed := findDevice(devices, author[ed25519.SeedSize:]); !listed {
		return nil, fmt.Errorf("%w: the author is not a device this list names", ErrDeviceListShape)
	}
	if len(devices) == 1 {
		return nil, fmt.Errorf("%w: the list names no device but its author", ErrDeviceListShape)
	}
	baseHash, index, prevHash, err := nextAmendmentPlace(identity)
	if err != nil {
		return nil, err
	}
	amendment := &Amendment{BaseHash: baseHash, Index: index, PrevHash: prevHash, IssuedAtMs: issuedAtMs,
		Op: AmendmentSelfRemoval}
	if err := SignAmendment(amendment, author); err != nil {
		return nil, err
	}
	return amendment, nil
}

// ---------------------------------------------------------------------------------------------
// the list's shape
// ---------------------------------------------------------------------------------------------

// findDevice answers the entry naming key, if the devices hold one.
func findDevice(devices []DeviceEntry, key []byte) (DeviceEntry, bool) {
	for _, entry := range devices {
		if sameOctets(entry.DeviceKey, key) {
			return entry, true
		}
	}
	return DeviceEntry{}, false
}

// baseNamesPhraseDevice answers whether a base names key as a phrase device.
func baseNamesPhraseDevice(base *DeviceListBase, key []byte) bool {
	entry, listed := findDevice(base.Devices, key)
	return listed && entry.Flags&DeviceFlagPhraseDevice != 0
}

// effectiveDevices is the list a base and its amendments make, in key order: each addition adds
// its entry, and each self-removal drops its author. It refuses nothing; checkListForm does.
func effectiveDevices(base []DeviceEntry, amendments []Amendment) []DeviceEntry {
	devices := append([]DeviceEntry(nil), base...)
	for _, amendment := range amendments {
		switch amendment.Op {
		case AmendmentAddition:
			at := len(devices)
			for i, entry := range devices {
				if compareKeys(amendment.Entry.DeviceKey, entry.DeviceKey) < 0 {
					at = i
					break
				}
			}
			devices = append(devices[:at], append([]DeviceEntry{amendment.Entry}, devices[at:]...)...)
		case AmendmentSelfRemoval:
			kept := devices[:0:0]
			for _, entry := range devices {
				if !sameOctets(entry.DeviceKey, amendment.AuthorKey) {
					kept = append(kept, entry)
				}
			}
			devices = kept
		}
	}
	return devices
}

// checkBaseForm is a base's own shape: 1 to 10 devices in ascending order of key, each once, each
// key usable, and only the known flags.
func checkBaseForm(base *DeviceListBase) error {
	if len(base.Devices) == 0 || DeviceListMaxDevices < len(base.Devices) {
		return fmt.Errorf("%w: a base of %d devices", ErrDeviceListShape, len(base.Devices))
	}
	for i, entry := range base.Devices {
		if !ed25519KeyIsUsable(entry.DeviceKey) || entry.Flags&^deviceFlagsKnown != 0 {
			return fmt.Errorf("%w: device %d has an unusable key or flags %#02x", ErrDeviceListShape, i, entry.Flags)
		}
		if 0 < i && 0 <= compareKeys(base.Devices[i-1].DeviceKey, entry.DeviceKey) {
			return fmt.Errorf("%w: device %d is out of order or repeated", ErrDeviceListShape, i)
		}
	}
	if len(base.PrevHash) != 0 && len(base.PrevHash) != identityHashOctets {
		return fmt.Errorf("%w: a prev_hash of %d octets", ErrDeviceListShape, len(base.PrevHash))
	}
	if base.BaseNumber == 0 {
		return fmt.Errorf("%w: base number 0; the first base under a key number is base 1", ErrDeviceListShape)
	}
	return nil
}

// checkListForm is the whole list's shape: the base's, at most 16 amendments, each addition of a
// new device with no flags, never more than 10 devices, and never none.
func checkListForm(base *DeviceListBase, amendments []Amendment) error {
	if err := checkBaseForm(base); err != nil {
		return err
	}
	if DeviceListMaxAmendments < len(amendments) {
		return fmt.Errorf("%w: %d amendments", ErrDeviceListShape, len(amendments))
	}
	devices := append([]DeviceEntry(nil), base.Devices...)
	for i, amendment := range amendments {
		if amendment.Op == AmendmentAddition {
			if _, already := findDevice(devices, amendment.Entry.DeviceKey); already ||
				amendment.Entry.Flags != 0 || !ed25519KeyIsUsable(amendment.Entry.DeviceKey) {
				return fmt.Errorf("%w: amendment %d adds a listed device, flags or an unusable key", ErrDeviceListShape, i+1)
			}
		}
		devices = effectiveDevices(devices, amendments[i:i+1])
		if len(devices) == 0 || DeviceListMaxDevices < len(devices) {
			return fmt.Errorf("%w: amendment %d leaves %d devices", ErrDeviceListShape, i+1, len(devices))
		}
	}
	return nil
}

// ---------------------------------------------------------------------------------------------
// the checks
// ---------------------------------------------------------------------------------------------

// VerifyIdentityChain checks a chain of form-1 steps from root to key, purely: a stranger can run
// it with no store (D2 IL5). An empty chain verifies only when root is key. Otherwise the first
// step's old key is root; each step is form 1 and is signed by its old key over the next key,
// which is the next step's old key and, after the last step, key; there are at most 4 steps; and
// no key of the chain appears twice.
func VerifyIdentityChain(root []byte, chain []IdentityStep, key []byte) error {
	if !ed25519KeyIsUsable(root) || !ed25519KeyIsUsable(key) {
		return fmt.Errorf("%w: a root or an end key that is not a usable Ed25519 key", ErrIdentityChain)
	}
	if IdentityChainMaxSteps < len(chain) {
		return fmt.Errorf("%w: %d steps", ErrIdentityChain, len(chain))
	}
	if len(chain) == 0 {
		if !sameOctets(root, key) {
			return fmt.Errorf("%w: an empty chain, and the key is not the root", ErrIdentityChain)
		}
		return nil
	}
	if !sameOctets(chain[0].OldKey, root) {
		return fmt.Errorf("%w: the first step is not the root's", ErrIdentityChain)
	}
	seen := [][]byte{}
	for i, step := range chain {
		if step.Form != IdentityStepForm1 {
			return fmt.Errorf("%w: step %d is of form %d: %w", ErrIdentityChain, i+1, step.Form, ErrIdentityStepForm)
		}
		next := key
		if i+1 < len(chain) {
			next = chain[i+1].OldKey
		}
		for _, earlier := range append(seen, step.OldKey) {
			if sameOctets(earlier, next) {
				return fmt.Errorf("%w: step %d leads to a key the chain has already held", ErrIdentityChain, i+1)
			}
		}
		tbs, err := identityStepTbs(next)
		if err != nil {
			return fmt.Errorf("%w: step %d: %v", ErrIdentityChain, i+1, err)
		}
		if !identityVerify(step.OldKey, identitySuccessionLabel, tbs, step.Signature) {
			return fmt.Errorf("%w: step %d is not signed by its old key", ErrIdentityChain, i+1)
		}
		seen = append(seen, step.OldKey)
	}
	return nil
}

// The chain's root: the first step's old key, or, with no step, the identity key itself.
func identityRootOf(identity *UrmessageIdentity) []byte {
	if 0 < len(identity.Chain) {
		return identity.Chain[0].OldKey
	}
	return identity.IskCert.IdentityKey
}

// VerifiedIdentity is what a binding check answers: the identity's root and current key, the key
// number, the list's version and the devices the list names after its amendments.
type VerifiedIdentity struct {
	Root        []byte
	IdentityKey []byte
	KeyNumber   uint32
	Version     ListVersion
	Devices     []DeviceEntry
	Identity    *UrmessageIdentity
}

// verifyIdentityList runs the binding's steps 2 to 5 over one 0xF005 body, for the identity key
// named, and answers the verified list. Each refusal names its step's sentinel.
func verifyIdentityList(identity *UrmessageIdentity, identityKey []byte) (*VerifiedIdentity, error) {
	cert := &identity.IskCert
	// (2) the certificate's identity key is the leaf's, and its signature holds
	if !sameOctets(cert.IdentityKey, identityKey) {
		return nil, fmt.Errorf("%w: the certificate is another identity key's", ErrBindingCertificate)
	}
	certTbs, err := identityEncoding(func(w *syntax.Writer) { encodeIskCertTbs(w, cert) })
	if err != nil || cert.KeyNumber == 0 || !ed25519KeyIsUsable(cert.IskPub) ||
		!identityVerify(cert.IdentityKey, iskCertLabel, certTbs, cert.Signature) {
		return nil, fmt.Errorf("%w: the identity key's signature over the certificate does not hold", ErrBindingCertificate)
	}
	// (3) the chain verifies from its root to that key
	root := identityRootOf(identity)
	if err := VerifyIdentityChain(root, identity.Chain, identityKey); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBindingChain, err)
	}
	// (4) the list names that key and key number, and the signatures over the base and every
	// amendment hold, each under a key the list names at that point
	base := &identity.Base
	if !sameOctets(base.IdentityKey, identityKey) || base.KeyNumber != cert.KeyNumber {
		return nil, fmt.Errorf("%w: the base names another identity key or key number", ErrBindingList)
	}
	baseTbs, err := identityEncoding(func(w *syntax.Writer) { encodeBaseTbs(w, base) })
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBindingList, err)
	}
	if !identityVerify(cert.IskPub, deviceListLabel, baseTbs, base.Signature) {
		return nil, fmt.Errorf("%w: the phrase key's signature over the base does not hold", ErrBindingList)
	}
	if !baseNamesPhraseDevice(base, base.AuthorKey) ||
		!identityVerify(base.AuthorKey, deviceListAuthorLabel, baseTbs, base.AuthorSignature) {
		return nil, fmt.Errorf("%w: the base's author is not a phrase device it names, or its signature does not hold", ErrBindingList)
	}
	baseHash, err := deviceListBaseHash(base)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBindingList, err)
	}
	prevHash := baseHash
	devices := append([]DeviceEntry(nil), base.Devices...)
	for i := range identity.Amendments {
		amendment := &identity.Amendments[i]
		if !sameOctets(amendment.BaseHash[:], baseHash[:]) || !sameOctets(amendment.PrevHash[:], prevHash[:]) ||
			int(amendment.Index) != i+1 {
			return nil, fmt.Errorf("%w: amendment %d is not the next on this base", ErrBindingList, i+1)
		}
		author, listed := findDevice(devices, amendment.AuthorKey)
		if !listed || (amendment.Op == AmendmentAddition && author.Flags&DeviceFlagBeingRemoved != 0) {
			return nil, fmt.Errorf("%w: amendment %d's author is not a device the list names", ErrBindingList, i+1)
		}
		tbs, err := identityEncoding(func(w *syntax.Writer) { encodeAmendmentTbs(w, amendment) })
		if err != nil || !identityVerify(amendment.AuthorKey, deviceAmendmentLabel, tbs, amendment.Signature) {
			return nil, fmt.Errorf("%w: amendment %d's signature does not hold", ErrBindingList, i+1)
		}
		if prevHash, err = amendmentHash(amendment); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrBindingList, err)
		}
		devices = effectiveDevices(devices, identity.Amendments[i:i+1])
	}
	// (5) the list is well formed
	if err := checkListForm(base, identity.Amendments); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBindingWellFormed, err)
	}
	return &VerifiedIdentity{
		Root:        append([]byte(nil), root...),
		IdentityKey: append([]byte(nil), identityKey...),
		KeyNumber:   cert.KeyNumber,
		Version:     identity.Version(),
		Devices:     devices,
		Identity:    identity,
	}, nil
}

// VerifyLeafBinding checks a leaf's binding to its identity, in Spec A A-36's order, and the first
// failure is the answer:
//
//  1. the leaf carries 0xF005 once, of at most 6,144 octets, and it decodes as version 1;
//  2. the certificate's identity key is the leaf's credential, and its signature holds;
//  3. the chain verifies from its root to that key;
//  4. the list names that key and key number, and the signatures over the base and every
//     amendment hold;
//  5. the list is well formed: sorted, unique, 1 to 10 devices, at most 16 amendments, known
//     flags only;
//  6. the leaf's signature key is a device the list names;
//  7. no identity key of the chain is the phrase key or the signature key.
//
// It reads the leaf as Spec A section 6's LeafView carries it: the credential, the signature key
// and the extensions.
func VerifyLeafBinding(credential []byte, signatureKey []byte, extensions []ExtensionBytes) (*VerifiedIdentity, error) {
	// (1)
	var body *ExtensionBytes
	for i := range extensions {
		if extensions[i].Type != uint16(mls.ExtensionTypeUrmessageIdentity) {
			continue
		}
		if body != nil {
			return nil, fmt.Errorf("%w: the leaf carries 0xF005 twice", ErrBindingExtension)
		}
		body = &extensions[i]
	}
	if body == nil {
		return nil, fmt.Errorf("%w: the leaf carries no 0xF005", ErrBindingExtension)
	}
	identity, err := ParseUrmessageIdentity(*body)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBindingExtension, err)
	}
	// (2) to (5)
	verified, err := verifyIdentityList(identity, credential)
	if err != nil {
		return nil, err
	}
	// (6)
	if _, named := findDevice(verified.Devices, signatureKey); !named {
		return nil, fmt.Errorf("%w: the leaf's signature key is not a device the list names", ErrBindingSignatureKey)
	}
	// (7)
	chainKeys := [][]byte{credential}
	for _, step := range identity.Chain {
		chainKeys = append(chainKeys, step.OldKey)
	}
	for _, key := range chainKeys {
		if sameOctets(key, identity.IskCert.IskPub) || sameOctets(key, signatureKey) {
			return nil, fmt.Errorf("%w: an identity key of the chain is the phrase key or the signature key", ErrBindingKeyReuse)
		}
	}
	return verified, nil
}

// VerifyDeviceList decides between a stored list and a candidate, both 0xF005 bodies of one root,
// each checked as VerifyLeafBinding's steps 2 to 5 check it for its own identity key (D2 IL5).
//
// A list under a later key of the root's chain is newer than every list under an earlier key,
// whatever their key numbers; under one key, a higher key number retires a lower one, and a higher
// base number a lower one; and on one base, a chain of amendments only extends. Anything else is
// a fork: two chains that part at one step, two bases of one number, two certificates of one key
// number, and two lists of one version with different octets.
func VerifyDeviceList(stored *UrmessageIdentity, candidate *UrmessageIdentity) (ListOrder, error) {
	storedVerified, err := verifyIdentityList(stored, stored.IskCert.IdentityKey)
	if err != nil {
		return ListSame, fmt.Errorf("%w: the stored list: %w", ErrDeviceListInvalid, err)
	}
	candidateVerified, err := verifyIdentityList(candidate, candidate.IskCert.IdentityKey)
	if err != nil {
		return ListSame, fmt.Errorf("%w: the candidate: %w", ErrDeviceListInvalid, err)
	}
	if !sameOctets(storedVerified.Root, candidateVerified.Root) {
		return ListSame, fmt.Errorf("%w: the two lists are of two roots", ErrDeviceListRoot)
	}
	// the chains: the shorter is the longer's prefix, and its key is the longer's next old key
	shorter, longer := stored, candidate
	if len(candidate.Chain) < len(stored.Chain) {
		shorter, longer = candidate, stored
	}
	for i := range shorter.Chain {
		if !sameStep(shorter.Chain[i], longer.Chain[i]) {
			return ListSame, fmt.Errorf("%w: the two chains part at step %d", ErrDeviceListFork, i+1)
		}
	}
	if len(shorter.Chain) < len(longer.Chain) {
		if !sameOctets(longer.Chain[len(shorter.Chain)].OldKey, shorter.IskCert.IdentityKey) {
			return ListSame, fmt.Errorf("%w: the two chains part after step %d", ErrDeviceListFork, len(shorter.Chain))
		}
	} else if !sameOctets(stored.IskCert.IdentityKey, candidate.IskCert.IdentityKey) {
		return ListSame, fmt.Errorf("%w: one chain ends at two identity keys", ErrDeviceListFork)
	}
	storedVersion, candidateVersion := stored.Version(), candidate.Version()
	order := storedVersion.Compare(candidateVersion)
	// under one key and one key number, the certificates are the same octets
	if storedVersion.Step == candidateVersion.Step && storedVersion.KeyNumber == candidateVersion.KeyNumber &&
		!sameEncoding(func(w *syntax.Writer) { encodeIskCert(w, &stored.IskCert) },
			func(w *syntax.Writer) { encodeIskCert(w, &candidate.IskCert) }) {
		return ListSame, fmt.Errorf("%w: two certificates of one key number", ErrDeviceListFork)
	}
	// on one base number, one base, and amendments that only extend
	if storedVersion.Step == candidateVersion.Step && storedVersion.KeyNumber == candidateVersion.KeyNumber &&
		storedVersion.Base == candidateVersion.Base {
		if !sameEncoding(func(w *syntax.Writer) { encodeBase(w, &stored.Base) },
			func(w *syntax.Writer) { encodeBase(w, &candidate.Base) }) {
			return ListSame, fmt.Errorf("%w: two bases of one number", ErrDeviceListFork)
		}
		shorterAmendments, longerAmendments := stored.Amendments, candidate.Amendments
		if len(longerAmendments) < len(shorterAmendments) {
			shorterAmendments, longerAmendments = longerAmendments, shorterAmendments
		}
		for i := range shorterAmendments {
			if !sameEncoding(func(w *syntax.Writer) { encodeAmendment(w, shorterAmendments[i]) },
				func(w *syntax.Writer) { encodeAmendment(w, longerAmendments[i]) }) {
				return ListSame, fmt.Errorf("%w: the two lists' amendments part at %d", ErrDeviceListFork, i+1)
			}
		}
	}
	return ListOrder(-order), nil
}

// sameStep is two steps' equality: the same old key, form and signature.
func sameStep(left IdentityStep, right IdentityStep) bool {
	return sameOctets(left.OldKey, right.OldKey) && left.Form == right.Form && sameOctets(left.Signature, right.Signature)
}

// sameEncoding answers whether two encoders write the same octets.
func sameEncoding(left func(w *syntax.Writer), right func(w *syntax.Writer)) bool {
	leftOctets, leftErr := identityEncoding(left)
	rightOctets, rightErr := identityEncoding(right)
	return leftErr == nil && rightErr == nil && sameOctets(leftOctets, rightOctets)
}
