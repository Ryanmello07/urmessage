package urmessage

import (
	"bytes"
	"crypto/sha256"
	"fmt"

	"github.com/urnetwork/message/messagegroup"
	"github.com/urnetwork/message/syntax"
)

// InviteVersion is the version every [Invite] this build encodes carries, and the only one it
// reads. A blob at any other version is refused by [ParseInvite] with [ErrInviteVersion].
//
// 0x0003 SEALS THE JOIN SECRETS. Version two carried pq_secret and group_handle_key as two fields
// in the clear; version three carries a join seal and its authenticator in their place, and
// nothing secret in the clear. See joinseal.go. A version two blob is refused BY VERSION and is
// never read: reading one would be installing two secrets whoever pasted it chose.
//
// 0x0002 ADDED THE CHECKSUM, AND AN 0x0001 BLOB IS REFUSED BY VERSION. Version one was framing and
// nothing else, so a damaged invite PARSED and JOINED and the damage surfaced one call later: a
// review flipped one bit at each of 3,408 positions of a real invite and 3,386 parsed. See
// [ParseInvite].
const InviteVersion uint16 = 0x0003

// inviteChecksumBytes is the width of the SHA-256 an encoded invite ends with.
const inviteChecksumBytes = sha256.Size

// Invite is everything a second device needs in order to join a group, and it is a HAND-OFF rather
// than a message: this package has no channel to carry it and does not invent one.
//
// NOTHING IN IT IS A SECRET IN THE CLEAR. The two secrets a joiner needs are inside JoinSeal,
// sealed under X-Wing to the key the joiner's own leaf publishes, so only the device whose join
// code was added can open it. What a third party who obtains an invite DOES learn is the group's
// id, its ratchet tree -- who is in it, by credential -- and that this joiner was added.
//
// IT IS STILL NOT AUTHENTICATED, and it must still travel over a channel the two people trust.
// Whoever controls that channel can substitute a different join code on the way out or a different
// invite on the way back, and the joiner then joins a group that is real and is not the one it
// meant (MG-1). The seal does not change that and does not claim to.
//
// WHAT EACH FIELD IS.
//
//   - GroupId: the 32 octets the server keys its rows by, and the group this device's join is
//     BOUND to: a Welcome describing any other group is refused before anything is written.
//   - Welcome and RatchetTree: the MLS hand-off, from the commit that added the joiner.
//   - JoinSeal: join_secrets_v1 -- pq_secret of the epoch joined, group_handle_key, and the digest
//     of that epoch's published keys -- as a MASTER section 7 wrap body addressed to the joiner's
//     leaf. Exactly 1,253 octets.
//   - JoinAuth: the 32 octet MAC over all of the above that only a member of the join epoch can
//     make.
type Invite struct {
	GroupId     []byte
	Welcome     []byte
	RatchetTree []byte
	JoinSeal    []byte
	JoinAuth    []byte
}

// check refuses an invite that is not the shape version three fixes. It reads no key and opens
// nothing, so it runs at the paste, before a join code is touched.
func (self *Invite) check() error {
	if len(self.GroupId) != GroupIdBytes {
		return fmt.Errorf("urmessage: an invite names a %d octet group id, want %d", len(self.GroupId), GroupIdBytes)
	}
	if len(self.Welcome) == 0 {
		return fmt.Errorf("urmessage: an invite carries no welcome, and there is nothing else to join from")
	}
	if len(self.RatchetTree) == 0 {
		return fmt.Errorf("urmessage: an invite carries no ratchet tree")
	}
	if len(self.JoinSeal) != joinSealBytes {
		return fmt.Errorf("%w: it is %d octets and invite version %#04x carries exactly %d",
			ErrJoinSealShape, len(self.JoinSeal), InviteVersion, joinSealBytes)
	}
	if len(self.JoinAuth) != joinAuthBytes {
		return fmt.Errorf("%w: its authenticator is %d octets, want %d", ErrJoinSealShape, len(self.JoinAuth), joinAuthBytes)
	}
	// THE ENVELOPE IS FOUR CONSTANTS. The content epoch is zero by construction, so that the epoch
	// a member joined at is not in the clear; a seal carrying any other envelope is some other
	// wrap, and is refused here rather than at the open.
	envelope, err := messagegroup.ParseWrapEnvelope(self.JoinSeal[:messagegroup.WrapEnvelopeBytes])
	if err != nil {
		return fmt.Errorf("%w: %w", ErrJoinSealShape, err)
	}
	if envelope.FormatVersion != messagegroup.WrapFormatVersion || envelope.TargetType != wrapTargetTypeJoiner ||
		envelope.PayloadType != wrapPayloadTypeJoinSecrets || envelope.ContentEpoch != 0 {
		return fmt.Errorf("%w: its envelope is version %#02x, target %#02x, payload %#02x, content epoch %d",
			ErrJoinSealShape, envelope.FormatVersion, envelope.TargetType, envelope.PayloadType, envelope.ContentEpoch)
	}
	return nil
}

// Encode is the invite as octets a caller can move.
//
// The encoding is this corpus's one length prefix, five fields, followed by the SHA-256 of every
// octet before it. See [ParseInvite] for what the checksum is and is not.
func (self *Invite) Encode() ([]byte, error) {
	if err := self.check(); err != nil {
		return nil, err
	}
	writer := syntax.NewWriter()
	writer.WriteUint16(InviteVersion)
	writer.WriteOpaqueLP(self.GroupId)
	writer.WriteOpaqueLP(self.Welcome)
	writer.WriteOpaqueLP(self.RatchetTree)
	writer.WriteOpaqueLP(self.JoinSeal)
	writer.WriteOpaqueLP(self.JoinAuth)
	encoded, err := writer.Bytes()
	if err != nil {
		return nil, fmt.Errorf("urmessage: encoding an invite: %w", err)
	}
	sum := sha256.Sum256(encoded)
	return append(encoded, sum[:]...), nil
}

// ParseInvite reads back what [Invite.Encode] wrote, and refuses a blob that is not exactly that.
//
// A DAMAGED INVITE IS REFUSED HERE, AT THE PASTE, AND NOT ONE CALL AFTER THE JOIN. The last 32
// octets are the SHA-256 of everything before them, and a blob whose checksum does not match is
// [ErrInviteDamaged] before any field is read.
//
// THE CHECKSUM IS NOT AN AUTHENTICATION AND MUST NOT BE READ AS ONE. Anybody who can change an
// invite can recompute it. What stands between a hostile carrier and this device is the join's own
// checks: the Welcome must be addressed to a key package this device published, it must describe
// the group the invite names, and the seal must carry a MAC made under that group's own epoch.
func ParseInvite(encoded []byte) (*Invite, error) {
	reader := syntax.NewReader(encoded)
	version, err := reader.ReadUint16()
	if err != nil {
		return nil, fmt.Errorf("%w: it has no version: %w", ErrInviteDamaged, err)
	}
	if version != InviteVersion {
		return nil, fmt.Errorf("%w: it is at version %#04x, and this build reads only %#04x",
			ErrInviteVersion, version, InviteVersion)
	}
	if len(encoded) < 2+inviteChecksumBytes {
		return nil, fmt.Errorf("%w: %d octets is shorter than a version and a checksum", ErrInviteDamaged, len(encoded))
	}
	body := encoded[:len(encoded)-inviteChecksumBytes]
	sum := sha256.Sum256(body)
	if !bytes.Equal(sum[:], encoded[len(encoded)-inviteChecksumBytes:]) {
		return nil, fmt.Errorf("%w: its last %d octets are not the SHA-256 of the %d before them",
			ErrInviteDamaged, inviteChecksumBytes, len(body))
	}
	reader = syntax.NewReader(body)
	if _, err := reader.ReadUint16(); err != nil {
		return nil, fmt.Errorf("%w: it has no version: %w", ErrInviteDamaged, err)
	}
	invite := &Invite{}
	for _, field := range []struct {
		name string
		into *[]byte
	}{
		{"group_id", &invite.GroupId},
		{"welcome", &invite.Welcome},
		{"ratchet_tree", &invite.RatchetTree},
		{"join_seal", &invite.JoinSeal},
		{"join_auth", &invite.JoinAuth},
	} {
		value, err := reader.ReadOpaqueLP()
		if err != nil {
			return nil, fmt.Errorf("urmessage: an invite with no %s: %w", field.name, err)
		}
		*field.into = value
	}
	if err := reader.Done(); err != nil {
		return nil, fmt.Errorf("urmessage: an invite with octets after its last field: %w", err)
	}
	if err := invite.check(); err != nil {
		return nil, err
	}
	return invite, nil
}
