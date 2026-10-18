package cp3b

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/message/messagegroup"
	"github.com/urnetwork/message/mls"
	"github.com/urnetwork/message/sdk/urmessage"
	"github.com/urnetwork/message/syntax"
)

// EVERY DEVICE OF THIS WORLD HAS AN IDENTITY (identity phase 1's Task 12). Every group this build
// founds requires urmessage_identity of every member, and a device with no identity publishes no join
// code and founds no group, so a device is given one as a person sets one up: connected, the words
// offered, typed back, and the identity made, its self group founded under that connection. The words
// are kept here, as a test keeps its own entropy, so that a seam member can be a further device of an
// identity this world made (LRI R62).

// worldIdentity is one identity this world made: the device that made it, and the words it was made from.
type worldIdentity struct {
	name string
	// the device that holds it now: the one that made it, or the one a restart of it opened
	device    *urmessage.Device
	accountId string
	words     string
	// the identity key, derived from the words when a seam member first claims it
	key []byte
	// the newest list a seam member of this identity carries, once one does: the next seam device of
	// the identity takes the base after it (identity phase 1's Task 13), since two lists of one base
	// that name different devices are a fork, which R8-EQ refuses in any tree they meet in
	newest *messagegroup.UrmessageIdentity
}

// identifyDevice gives a device its identity as a person sets one up, connected, and answers the
// words it was made from: a device of any world, this one's or another's.
func identifyDevice(t *testing.T, name string, device *urmessage.Device) string {
	t.Helper()
	ctx := context.Background()
	if err := device.Connect(ctx); err != nil {
		t.Fatalf("%s: Connect, which the identity's self group is founded under: %v", name, err)
	}
	words, err := device.CreateIdentity()
	if err != nil {
		t.Fatalf("%s: CreateIdentity: %v", name, err)
	}
	typed := strings.Join(words, " ")
	clear(words)
	if err := device.ConfirmWords(ctx, typed); err != nil {
		t.Fatalf("%s: ConfirmWords: %v", name, err)
	}
	return typed
}

// identify gives a device of this world its identity, unless it has one already -- a restart reads it
// back -- and keeps the words it was made from.
func (self *world) identify(t *testing.T, name string, device *urmessage.Device) {
	t.Helper()
	if held, err := device.Identity(); err == nil {
		// a restart reads it back, and the restarted device is the one that holds it now
		self.identityMutex.Lock()
		defer self.identityMutex.Unlock()
		for _, one := range self.identities {
			if one.accountId == held.AccountId {
				one.device = device
			}
		}
		return
	} else if !errors.Is(err, urmessage.ErrNoIdentity) {
		t.Fatalf("%s: Identity: %v", name, err)
	}
	typed := identifyDevice(t, name, device)
	made, err := device.Identity()
	if err != nil {
		t.Fatalf("%s: Identity after ConfirmWords: %v", name, err)
	}
	self.identityMutex.Lock()
	defer self.identityMutex.Unlock()
	self.identities = append(self.identities, &worldIdentity{name: name, device: device, accountId: made.AccountId, words: typed})
}

// identityKeyOf is the identity key the words make: key number 1's, the credential every leaf of the
// identity names.
func identityKeyOf(t *testing.T, words string) []byte {
	t.Helper()
	phrase, _, err := messagegroup.ParseRecoveryPhrase(words)
	if err != nil {
		t.Fatalf("the world's words do not read back: %v", err)
	}
	defer phrase.Erase()
	var key []byte
	if err := messagegroup.WithPhraseKeysUnder(messagegroup.FastPhraseStretchForTests(), phrase, []uint32{1}, func(keys *messagegroup.PhraseKeys) error {
		key = keys.IdentityKey()
		return nil
	}); err != nil {
		t.Fatalf("the world's identity key: %v", err)
	}
	return key
}

// identityClaimed is the identity this world made whose key is claimed.
func (self *world) identityClaimed(t *testing.T, claimed []byte) *worldIdentity {
	t.Helper()
	self.identityMutex.Lock()
	held := slices.Clone(self.identities)
	self.identityMutex.Unlock()
	for _, one := range held {
		if one.key == nil {
			one.key = identityKeyOf(t, one.words)
		}
		if bytes.Equal(one.key, claimed) {
			return one
		}
	}
	t.Fatalf("no identity this world made has the key %x", claimed)
	return nil
}

// keyPackageIdentity is the identity a key package's leaf carries, checked as every receiver checks
// it: its credential, its signature key, and the 0xF005 that binds the one to the other.
func keyPackageIdentity(t *testing.T, keyPackage []byte) (*mls.KeyPackage, *messagegroup.VerifiedIdentity, error) {
	t.Helper()
	decoded := &mls.KeyPackage{}
	if err := syntax.Unmarshal(keyPackage, decoded); err != nil {
		t.Fatalf("decoding a key package: %v", err)
	}
	extensions := []messagegroup.ExtensionBytes{}
	for _, extension := range decoded.LeafNode.Extensions {
		extensions = append(extensions, messagegroup.ExtensionBytes{Type: uint16(extension.ExtensionType), Data: extension.ExtensionData})
	}
	verified, err := messagegroup.VerifyLeafBinding(decoded.LeafNode.Credential.Identity, decoded.LeafNode.SignatureKey, extensions)
	return decoded, verified, err
}

// seamIdentity is the identity a seam member's leaves carry, made from words by the ceremony a device
// runs, with the seam's own key signing the base as its author. With no sibling it is an identity of
// the seam's own: a first base naming the seam alone. With a sibling -- a device of the claimed
// identity, whose own list is read off a key package it publishes -- it is a further device of that
// identity: the next base, naming the sibling's devices and the seam, each a phrase device as the
// sibling list marks it and the seam one too, since a base's author is a phrase device of it. It
// answers the identity key, which is the seam's credential, and the 0xF005 its leaves carry.
func seamIdentity(t *testing.T, name string, words string, signer mls.SignaturePrivateKey, signerPub []byte,
	sibling *messagegroup.UrmessageIdentity) ([]byte, messagegroup.ExtensionBytes) {

	t.Helper()
	phrase, _, err := messagegroup.ParseRecoveryPhrase(words)
	if err != nil {
		t.Fatalf("%s: the words do not read back: %v", name, err)
	}
	defer phrase.Erase()
	author := ed25519.NewKeyFromSeed(signer)
	defer clear(author)
	devices := []messagegroup.DeviceEntry{{DeviceKey: bytes.Clone(signerPub), Flags: messagegroup.DeviceFlagPhraseDevice}}
	baseNumber := uint64(1)
	if sibling != nil {
		devices = append(slices.Clone(sibling.Base.Devices), devices...)
		slices.SortFunc(devices, func(a, b messagegroup.DeviceEntry) int { return bytes.Compare(a.DeviceKey, b.DeviceKey) })
		baseNumber = sibling.Base.BaseNumber + 1
	}
	var identityKey []byte
	var own *messagegroup.UrmessageIdentity
	if err := messagegroup.WithPhraseKeysUnder(messagegroup.FastPhraseStretchForTests(), phrase, []uint32{1}, func(keys *messagegroup.PhraseKeys) error {
		cert, err := keys.SignIskCert(1)
		if err != nil {
			return err
		}
		base := &messagegroup.DeviceListBase{
			IdentityKey: keys.IdentityKey(),
			KeyNumber:   1,
			BaseNumber:  baseNumber,
			IssuedAtMs:  uint64(time.Now().UnixMilli()),
			Devices:     devices,
			AuthorKey:   bytes.Clone(signerPub),
		}
		if err := messagegroup.SignBaseAuthor(base, author); err != nil {
			return err
		}
		if err := keys.SignBase(1, base); err != nil {
			return err
		}
		identityKey = keys.IdentityKey()
		own = &messagegroup.UrmessageIdentity{IskCert: *cert, Base: *base}
		return nil
	}); err != nil {
		t.Fatalf("%s: the seam's identity: %v", name, err)
	}
	extension, err := own.Encode()
	if err != nil {
		t.Fatalf("%s: the seam's identity extension: %v", name, err)
	}
	if _, err := messagegroup.VerifyLeafBinding(identityKey, signerPub, []messagegroup.ExtensionBytes{extension}); err != nil {
		t.Fatalf("%s: the seam's own identity does not bind it: %v", name, err)
	}
	return identityKey, extension
}

// newestList is the newest list a seam device of this identity took, or nil before any did.
func (self *worldIdentity) newestList() *messagegroup.UrmessageIdentity {
	worldIdentities.Lock()
	defer worldIdentities.Unlock()
	return self.newest
}

// tookList records the list a seam device of this identity took, which the next one builds on.
func (self *worldIdentity) tookList(t *testing.T, extension messagegroup.ExtensionBytes) {
	t.Helper()
	parsed, err := messagegroup.ParseUrmessageIdentity(extension)
	if err != nil {
		t.Fatalf("a seam device's list does not read back: %v", err)
	}
	worldIdentities.Lock()
	defer worldIdentities.Unlock()
	self.newest = parsed
}

// worldIdentities guards every world identity's newest list, which seam members of one identity in
// one world take in turn.
var worldIdentities sync.Mutex

// newWords are the words of a new identity, for a seam member of its own.
func newWords(t *testing.T) string {
	t.Helper()
	phrase, err := messagegroup.NewRecoveryPhrase()
	if err != nil {
		t.Fatalf("a recovery phrase: %v", err)
	}
	defer phrase.Erase()
	words := phrase.Words()
	defer clear(words)
	return strings.Join(words, " ")
}

// siblingIdentity is the claimed identity's newest list this world knows: the one a seam device of it
// last took, or, before any did, its list as one of its devices publishes it -- read off a key package
// that device makes, which is the one place outside urmessage a device's 0xF005 is public.
func siblingIdentity(t *testing.T, claimed *worldIdentity) *messagegroup.UrmessageIdentity {
	t.Helper()
	if newest := claimed.newestList(); newest != nil {
		return newest
	}
	keyPackage, err := claimed.device.KeyPackage()
	if err != nil {
		t.Fatalf("%s's KeyPackage, for its list: %v", claimed.name, err)
	}
	decoded, verified, err := keyPackageIdentity(t, keyPackage)
	if err != nil {
		t.Fatalf("%s's key package does not bind: %v", claimed.name, err)
	}
	if !bytes.Equal(decoded.LeafNode.Credential.Identity, claimed.key) {
		t.Fatalf("%s's key package names %x, and its identity is %x", claimed.name, decoded.LeafNode.Credential.Identity, claimed.key)
	}
	return verified.Identity
}
