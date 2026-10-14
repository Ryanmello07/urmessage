package urmessage

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
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
