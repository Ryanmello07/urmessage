package urmessage

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/message/messagegroup"
	"github.com/urnetwork/message/mls"
)

// THE LISTS THE TESTS MAKE (identity phase 1's Task 13). Every leaf a commit adds or updates, and its
// committer's, must now carry a 0xF005 that binds it (R6e), and a list must name every device that
// stands under it (R8-CUR), so a test that puts a second device of one identity in a group needs that
// identity's words to sign the list that names both. These helpers keep the words of the identities the
// tests make, and sign lists with them, always under the test seam's stretch (LRI R76 item 10).

// testIdentityRecord is what the tests know of one identity they made: its words, the devices its
// newest list names, in the order they joined it, and that list's base number.
type testIdentityRecord struct {
	words   []string
	devices [][]byte
	base    uint64
}

// testIdentities is every identity [testIdentify] made in this process, by identity key.
var testIdentities = struct {
	sync.Mutex
	byKey map[string]*testIdentityRecord
}{byKey: map[string]*testIdentityRecord{}}

// testRememberIdentity keeps an identity's words and its first device, as [testIdentify] makes it.
func testRememberIdentity(identityKey []byte, phrase *messagegroup.RecoveryPhrase, device []byte) {
	testIdentities.Lock()
	defer testIdentities.Unlock()
	testIdentities.byKey[string(identityKey)] = &testIdentityRecord{
		words:   slices.Clone(phrase.Words()),
		devices: [][]byte{bytes.Clone(device)},
		base:    1,
	}
}

// testPhraseOf answers the words of an identity the tests made, parsed, which the caller erases, or nil
// for an identity no test made.
func testPhraseOf(t testing.TB, identityKey []byte) *messagegroup.RecoveryPhrase {
	t.Helper()
	testIdentities.Lock()
	record, held := testIdentities.byKey[string(identityKey)]
	testIdentities.Unlock()
	if !held {
		return nil
	}
	phrase, _, err := messagegroup.ParseRecoveryPhrase(strings.Join(record.words, " "))
	if err != nil {
		t.Fatalf("the words the tests kept for %x: %v", identityKey, err)
	}
	return phrase
}

// testSiblingList is the list a further device of an identity the tests made carries: the next base,
// naming every device the identity's newest list names and this one, signed by the identity's phrase
// key and, as its author, by the new device, which it marks a phrase device. It answers false for an
// identity no test made.
func testSiblingList(t testing.TB, identityKey []byte, signer mls.SignaturePrivateKey, signerPub []byte) (messagegroup.ExtensionBytes, bool) {
	t.Helper()
	testIdentities.Lock()
	record, held := testIdentities.byKey[string(identityKey)]
	var devices [][]byte
	if held {
		devices = append(slices.Clone(record.devices), bytes.Clone(signerPub))
	}
	testIdentities.Unlock()
	if !held {
		return messagegroup.ExtensionBytes{}, false
	}
	return testNextList(t, identityKey, signer, signerPub, devices...), true
}

// testNextList is the next base of an identity the tests made, naming the devices given, signed by the
// identity's phrase key and by its author, which it marks a phrase device; the tests hold it as that
// identity's newest list from then on.
func testNextList(t testing.TB, identityKey []byte, author mls.SignaturePrivateKey, authorPub []byte,
	devices ...[]byte) messagegroup.ExtensionBytes {

	t.Helper()
	phrase := testPhraseOf(t, identityKey)
	if phrase == nil {
		t.Fatalf("no test made the identity %x, so no test holds its words", identityKey)
	}
	defer phrase.Erase()
	testIdentities.Lock()
	record := testIdentities.byKey[string(identityKey)]
	record.base += 1
	record.devices = nil
	for _, device := range devices {
		record.devices = append(record.devices, bytes.Clone(device))
	}
	base := record.base
	testIdentities.Unlock()
	return testBaseList(t, phrase, base, author, authorPub, devices...)
}

// testPublicOf is the public half of a device seed.
func testPublicOf(seed mls.SignaturePrivateKey) []byte {
	return bytes.Clone(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))
}

// testHoldIdentity gives a device that was built field by field -- a member of the role world -- the
// identity its fixture's leaves carry, as [NewDevice] reads one back: the identity record over the
// fixture's identity key, its own list, and the heads holding that list, so that the heads rise as a
// device's do. The record is this process's; nothing is written.
func testHoldIdentity(t testing.TB, device *Device, identityKey []byte, own messagegroup.ExtensionBytes,
	signer mls.SignaturePrivateKey) {

	t.Helper()
	parsed, err := messagegroup.ParseUrmessageIdentity(own)
	if err != nil {
		t.Fatalf("the fixture's own list: %v", err)
	}
	devicePub := ed25519.PublicKey(testPublicOf(signer))
	state, err := newDeviceIdentityState(IdentityRecord{Root: bytes.Clone(identityKey), CurrentKey: bytes.Clone(identityKey)},
		parsed, devicePub)
	if err != nil {
		t.Fatalf("the fixture's identity: %v", err)
	}
	device.identityLock.Lock()
	defer device.identityLock.Unlock()
	device.identity = state
	device.heads = map[string][]byte{string(identityKey): bytes.Clone(own.Data)}
	device.devicePub = devicePub
}

// testHeadOf is a device's head for one root as it holds it in memory, and as its store holds it: the
// two 0xF005 bodies, nil for none.
func testHeadOf(t testing.TB, device *Device, root []byte) ([]byte, []byte) {
	t.Helper()
	device.identityLock.RLock()
	held := bytes.Clone(device.heads[string(root)])
	device.identityLock.RUnlock()
	var stored []byte
	if store, durable := device.stateStore.(DeviceStore); durable {
		rows, err := store.IdentityHeads()
		if err != nil && !errors.Is(err, ErrStateNotFound) {
			t.Fatalf("the store's heads: %v", err)
		}
		for _, row := range rows {
			if bytes.Equal(row.Root, root) {
				stored = bytes.Clone(row.Identity)
			}
		}
	}
	return held, stored
}

// testBaseList is a list of one base under key number 1: the phrase's certificate and a base of the
// number given naming the devices given, signed by the phrase key and by its author, which the base
// names as a phrase device. The devices are put in the order of their keys, as a base names them.
func testBaseList(t testing.TB, phrase *messagegroup.RecoveryPhrase, baseNumber uint64, author mls.SignaturePrivateKey,
	authorPub []byte, devices ...[]byte) messagegroup.ExtensionBytes {

	t.Helper()
	entries := []messagegroup.DeviceEntry{}
	for _, device := range devices {
		flags := uint8(0)
		if bytes.Equal(device, authorPub) {
			flags = messagegroup.DeviceFlagPhraseDevice
		}
		entries = append(entries, messagegroup.DeviceEntry{DeviceKey: bytes.Clone(device), Flags: flags})
	}
	slices.SortFunc(entries, func(left messagegroup.DeviceEntry, right messagegroup.DeviceEntry) int {
		return bytes.Compare(left.DeviceKey, right.DeviceKey)
	})
	authorKey := ed25519.NewKeyFromSeed(author)
	defer zeroizeState(authorKey)
	var own *messagegroup.UrmessageIdentity
	if err := messagegroup.WithPhraseKeysUnder(messagegroup.FastPhraseStretchForTests(), phrase, []uint32{1},
		func(keys *messagegroup.PhraseKeys) error {
			cert, err := keys.SignIskCert(1)
			if err != nil {
				return err
			}
			base := &messagegroup.DeviceListBase{
				IdentityKey: keys.IdentityKey(),
				KeyNumber:   1,
				BaseNumber:  baseNumber,
				IssuedAtMs:  uint64(time.Now().UnixMilli()),
				Devices:     entries,
				AuthorKey:   bytes.Clone(authorPub),
			}
			if err := messagegroup.SignBaseAuthor(base, authorKey); err != nil {
				return err
			}
			if err := keys.SignBase(1, base); err != nil {
				return err
			}
			own = &messagegroup.UrmessageIdentity{IskCert: *cert, Base: *base}
			return nil
		}); err != nil {
		t.Fatalf("base %d naming %d device(s): %v", baseNumber, len(devices), err)
	}
	extension, err := own.Encode()
	if err != nil {
		t.Fatalf("base %d's identity extension: %v", baseNumber, err)
	}
	return extension
}

// testIdentityKeyOf is the identity key a phrase makes.
func testIdentityKeyOf(t testing.TB, phrase *messagegroup.RecoveryPhrase) []byte {
	t.Helper()
	var identityKey []byte
	if err := messagegroup.WithPhraseKeysUnder(messagegroup.FastPhraseStretchForTests(), phrase, []uint32{1},
		func(keys *messagegroup.PhraseKeys) error {
			identityKey = bytes.Clone(keys.IdentityKey())
			return nil
		}); err != nil {
		t.Fatalf("the identity key of a phrase: %v", err)
	}
	return identityKey
}

// testDeviceKey is a device key derived from a name, for a leaf no device stands behind: its seed and
// its public half.
func testDeviceKey(name string) (mls.SignaturePrivateKey, []byte) {
	seed := sha256.Sum256([]byte("a test device: " + name))
	private := ed25519.NewKeyFromSeed(seed[:])
	return mls.SignaturePrivateKey(bytes.Clone(seed[:])), bytes.Clone(private.Public().(ed25519.PublicKey))
}
