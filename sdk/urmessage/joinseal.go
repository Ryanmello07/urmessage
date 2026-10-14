package urmessage

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"time"

	"github.com/urnetwork/message/message"
	"github.com/urnetwork/message/messagegroup"
	"github.com/urnetwork/message/mls"
	"github.com/urnetwork/message/syntax"
)

// THE JOIN SEAL: how the two secrets a joiner needs reach it, since invite version 3.
//
// WHAT IT REPLACES. Until version 3 an [Invite] carried pq_secret and group_handle_key as two
// length-prefixed fields IN THE CLEAR, beside a Welcome whose own protection is classical X25519.
// A recorder of both pasted codes with a later quantum computer therefore read the epoch a member
// joined at, and in a two-person chat that never commits again that epoch is the whole chat. A
// classical observer of one pasted invite recovered group_handle_key, which maps every
// sender_handle to a leaf for the life of the group. Both were measured in sdk/cp3b.
//
// WHAT IT IS. The adder seals the two secrets to the X-Wing key the JOINER'S OWN LEAF publishes,
// through the wrap door every later epoch's delivery already uses, and authenticates the result
// with a MAC only a member of the join epoch can make:
//
//	join_secrets_v1 = pq_secret[e] (32) | group_handle_key (32) | epoch_keys_digest[e] (32)
//	join_seal       = wrap_body over join_secrets_v1, with the envelope
//	                  u8(0x01) | u8(target_type 0x03 JOINER) | u8(payload_type 0x04) | u64(0)
//	                  and target_id = u32(joiner_leaf)                          -- 1,253 octets
//	join_key        = MLS-Exporter("URmessage/v1/joinkey", u32(joiner_leaf), 32)  at epoch e
//	join_auth       = HMAC-SHA-256(join_key, preimage)                          -- 32 octets
//	preimage        = "URmessage/v1/joinauth" | u16(alg_id 0x0041) | u16(invite_version 0x0003)
//	                  | LP(group_id) | u64(e) | u32(joiner_leaf) | LP(H(welcome))
//	                  | LP(H(ratchet_tree)) | LP(H(join_seal))                  -- 181 octets
//
// CONFIDENTIALITY RESTS ON X-WING ALONE. The exporter keys join_auth and nothing else, so breaking
// the classical Welcome yields the MAC key and not the secrets.
//
// THE CONTENT EPOCH IN THE ENVELOPE IS ZERO, A CONSTANT, so the epoch a member joined at is not in
// the clear. The epoch is bound where it cannot be read: join_key is that epoch's exporter, the
// preimage carries it, and the sealed digest is over it.
//
// WHAT join_auth SAYS AND DOES NOT SAY. It says a member of the epoch this Welcome opened made
// this seal for this leaf, this Welcome and this tree. It does not say WHO: a Welcome authenticates
// nobody, and an adder the user did not mean to talk to makes a perfectly valid one (MG-1).
const (
	// The three MASTER section 7 octets of a join seal. The device wrap takes target 0x01 and
	// payloads 0x01 and 0x02 (pqepoch.go); target 0x02 and payload 0x03 are left for the recovery
	// wrap. Like those, these are provisional until MG-7 is ruled.
	wrapTargetTypeJoiner       uint8 = 0x03
	wrapPayloadTypeJoinSecrets uint8 = 0x04

	joinSecretsBytes = messagegroup.PqSecretBytes + groupHandleKeyBytes + sha256.Size
	// envelope | u16(alg_id) | LP(ct_xwing) | LP(aead_ct), the AEAD adding its 16 octet tag
	joinSealBytes = messagegroup.WrapEnvelopeBytes + 2 + 4 + messagegroup.XwingCiphertextSize + 4 + joinSecretsBytes + 16
	joinAuthBytes = sha256.Size

	// HMAC-SHA-256, as MASTER section 7.1 would register it. Proposed, with the code points above.
	joinAuthAlgId uint16 = 0x0041

	// THE INVITE VERSION join_auth IS OVER, AND IT IS THIS FORMAT'S OWN CONSTANT. The preimage
	// names the one invite version these 181 octets belong to, so it is written here and is not
	// read off [InviteVersion]: a build whose invites were at another version would otherwise
	// authenticate a different preimage with nothing saying so. The codec holds the two equal.
	joinAuthInviteVersion uint16 = 0x0003

	joinKeyExporterLabel = "URmessage/v1/joinkey"
	joinKeyBytes         = 32
	joinAuthLabel        = "URmessage/v1/joinauth"

	groupHandleKeyBytes = 32
)

// joinerKeys is what an adder reads off a join code before it stages anything: the decoded key
// package, and the X-Wing key its leaf publishes.
type joinerKeys struct {
	keyPackage *mls.KeyPackage
	xwing      *messagegroup.XwingPublicKey
}

// joinerOf judges a join code, in this order, BEFORE a commit is staged: it decodes, it is a valid
// key package of this suite today, it lists the join seal capability, and its leaf publishes an
// X-Wing key a seal can be made to.
//
// VALIDITY BEFORE CAPABILITY, so that a damaged join code is told it is damaged and not that it is
// old. The capability is also required by every group this build founds, so connect/mls refuses a
// key package without it at CommitAdd; it is asked here as well so that the refusal has a name of
// its own and is made before anything is built.
func (self *Device) joinerOf(keyPackage []byte) (*joinerKeys, error) {
	decoded := &mls.KeyPackage{}
	if err := syntax.Unmarshal(keyPackage, decoded); err != nil {
		return nil, fmt.Errorf("%w: it does not decode: %w", ErrKeyPackageInvalid, err)
	}
	// THE WALL CLOCK, AND NOT THE DEVICE'S OWN: it is the clock connect/mls judges the same key
	// package's lifetime by at CommitAdd, so this check and that one cannot come to disagree.
	if err := decoded.Validate(self.crypto, deviceCipherSuite, time.Now()); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrKeyPackageInvalid, err)
	}
	if !decoded.LeafNode.Capabilities.SupportsExtension(mls.ExtensionTypeUrmessageJoinSeal) {
		return nil, ErrJoinerCannotOpenSealedInvite
	}
	leafKeys, err := mls.LeafKeysOf(&decoded.LeafNode)
	if err != nil {
		return nil, fmt.Errorf("%w: its leaf publishes no key a join seal can be made to: %w", ErrKeyPackageInvalid, err)
	}
	xwing, err := messagegroup.ParseXwingPublicKey(leafKeys.DeviceXwingPub)
	if err != nil {
		return nil, fmt.Errorf("%w: its leaf's x-wing key: %w", ErrKeyPackageInvalid, err)
	}
	return &joinerKeys{keyPackage: decoded, xwing: xwing}, nil
}

// joinerLeafIn is the leaf of a ratchet tree the joiner's key package was installed at: the one
// leaf whose signature key AND whole leaf node are the key package's. It is read off the tree the
// commit returned, which is the tree the joiner is handed, so the adder and the joiner cannot come
// to name two different leaves.
func joinerLeafIn(ratchetTree []byte, keyPackage *mls.KeyPackage) (uint32, error) {
	tree, err := mls.UnmarshalRatchetTree(ratchetTree)
	if err != nil {
		return 0, fmt.Errorf("urmessage: the tree the add returned: %w", err)
	}
	leaf, found := tree.FindLeafBySignatureKey(keyPackage.LeafNode.SignatureKey)
	if !found {
		return 0, fmt.Errorf("urmessage: the tree the add returned holds no leaf with the joiner's signature key")
	}
	inTree, err := syntax.Marshal(tree.Leaf(leaf))
	if err != nil {
		return 0, err
	}
	published, err := syntax.Marshal(&keyPackage.LeafNode)
	if err != nil {
		return 0, err
	}
	if subtle.ConstantTimeCompare(inTree, published) != 1 {
		return 0, fmt.Errorf("urmessage: leaf %d of the tree the add returned is not the leaf the join code published", leaf)
	}
	return uint32(leaf), nil
}

// joinerAlreadyHasALeaf gives the two refusals of an add that mean "this identity already has a
// leaf in this group" the one name an adder can act on, and hands every other error back as it
// came. The role model refuses first ([ErrCommitIdentityClaimed]: an added leaf claims an identity
// that is in the group), and connect/mls refuses a signature key the tree already holds. Either is
// what an adder sees when an invitation it made was never opened and it tries again; the remedy is
// in the name's own sentence.
func joinerAlreadyHasALeaf(err error) error {
	if errors.Is(err, ErrCommitIdentityClaimed) || errors.Is(err, mls.ErrAddDuplicateSignatureKey) {
		return fmt.Errorf("%w: %w", ErrJoinerAlreadyHasALeaf, err)
	}
	return err
}

// joinerLeafId is u32(joiner_leaf): the wrap's target_id and the join key's exporter context.
func joinerLeafId(leaf uint32) []byte {
	return []byte{byte(leaf >> 24), byte(leaf >> 16), byte(leaf >> 8), byte(leaf)}
}

// encodeJoinSecrets is join_secrets_v1, exactly 96 octets.
func encodeJoinSecrets(pqSecret []byte, groupHandleKey []byte, epochKeysDigest []byte) ([]byte, error) {
	if len(pqSecret) != messagegroup.PqSecretBytes || len(groupHandleKey) != groupHandleKeyBytes ||
		len(epochKeysDigest) != sha256.Size {
		return nil, fmt.Errorf("urmessage: join_secrets_v1 is three 32 octet values, and these are %d, %d and %d",
			len(pqSecret), len(groupHandleKey), len(epochKeysDigest))
	}
	payload := make([]byte, 0, joinSecretsBytes)
	payload = append(payload, pqSecret...)
	payload = append(payload, groupHandleKey...)
	payload = append(payload, epochKeysDigest...)
	return payload, nil
}

// decodeJoinSecrets cuts an opened payload into its three values, as copies, and refuses any other
// length and an all-zero secret. An all-zero value is not what any adder draws, and it is exactly
// what a buffer that was erased before it was sealed looks like.
func decodeJoinSecrets(payload []byte) (pqSecret []byte, groupHandleKey []byte, epochKeysDigest []byte, err error) {
	if len(payload) != joinSecretsBytes {
		return nil, nil, nil, fmt.Errorf("%w: the seal opened to %d octets and join_secrets_v1 is %d",
			ErrJoinSealUnreadable, len(payload), joinSecretsBytes)
	}
	zero := make([]byte, messagegroup.PqSecretBytes)
	pqSecret = append([]byte(nil), payload[:messagegroup.PqSecretBytes]...)
	groupHandleKey = append([]byte(nil), payload[messagegroup.PqSecretBytes:messagegroup.PqSecretBytes+groupHandleKeyBytes]...)
	epochKeysDigest = append([]byte(nil), payload[messagegroup.PqSecretBytes+groupHandleKeyBytes:]...)
	if subtle.ConstantTimeCompare(pqSecret, zero) == 1 || subtle.ConstantTimeCompare(groupHandleKey, zero) == 1 {
		zeroizeState(pqSecret)
		zeroizeState(groupHandleKey)
		return nil, nil, nil, fmt.Errorf("%w: the seal opened to an all-zero secret", ErrJoinSealUnreadable)
	}
	return pqSecret, groupHandleKey, epochKeysDigest, nil
}

// joinAuthPreimage is the 181 octets join_auth is a MAC over. Every value in it is the CALLER'S
// OWN: an adder passes what it built, and a joiner passes what its own joined group answers and
// the octets it received, never a value read back out of the seal.
func joinAuthPreimage(groupId []byte, epoch uint64, leaf uint32, welcome []byte, ratchetTree []byte,
	joinSeal []byte) ([]byte, error) {

	welcomeHash := sha256.Sum256(welcome)
	treeHash := sha256.Sum256(ratchetTree)
	sealHash := sha256.Sum256(joinSeal)
	writer := syntax.NewWriter()
	writer.WriteRaw([]byte(joinAuthLabel))
	writer.WriteUint16(joinAuthAlgId)
	writer.WriteUint16(joinAuthInviteVersion)
	writer.WriteOpaqueLP(groupId)
	writer.WriteUint64(epoch)
	writer.WriteUint32(leaf)
	writer.WriteOpaqueLP(welcomeHash[:])
	writer.WriteOpaqueLP(treeHash[:])
	writer.WriteOpaqueLP(sealHash[:])
	preimage, err := writer.Bytes()
	if err != nil {
		return nil, fmt.Errorf("urmessage: the join_auth preimage: %w", err)
	}
	return preimage, nil
}

// epochKeysDigestOver is H(epoch_keys) of one epoch as a holder of that epoch's exporter and a
// candidate pq_secret computes it: the storage root, the two server keys off it, and the digest
// the commit that opened the epoch publishes. Every intermediate is erased here.
func epochKeysDigestOver(groupId []byte, epoch uint64, mlsSecret []byte, pqSecret []byte) ([]byte, error) {
	group, err := epochDigestGroupId(groupId)
	if err != nil {
		return nil, err
	}
	root := messagegroup.StorageRoot(mlsSecret, pqSecret)
	writeKey := message.WriteKey(root)
	readKey := message.ReadKey(root)
	zeroizeState(root)
	digest, err := message.EpochKeysDigest(group, epoch, writeKey, readKey)
	zeroizeState(writeKey)
	zeroizeState(readKey)
	return digest, err
}

// sameDigest compares two H(epoch_keys) values, and answers false for one that is absent. The
// values are published, so nothing here is secret; it goes through subtle because every comparison
// of key-derived octets in this package does.
func sameDigest(sealed []byte, published []byte) bool {
	return len(sealed) == sha256.Size && subtle.ConstantTimeCompare(sealed, published) == 1
}
