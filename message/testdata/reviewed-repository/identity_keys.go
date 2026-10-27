//go:build ignore

// Reviewed: messagegroup/identity_keys.go's accountIdOfHash, whole (LRI R65 item 7; the review of
// identity phase 1's Tasks 8 to 10, L2-07). Its one shape of this gate is ID1's octet 6,
// (id_hash[6] & 0x0F) | 0x80 as D2 and MASTER section 5.2 write it: UUIDv8's version nibble set
// over an octet of a SHA-256, and no retention byte. Matched by its complete AST, so a changed
// body is under every rule again.
package messagegroup

import "crypto/sha256"

func accountIdOfHash(idHash [sha256.Size]byte) AccountId {
	var id AccountId
	copy(id[:], idHash[:accountIdOctets])
	id[6] = (idHash[6] & 0x0F) | 0x80
	id[8] = (idHash[8] & 0x3F) | 0x80
	return id
}
