package urmessage

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/message/messagegroup"
	"github.com/urnetwork/message/mls"
	"github.com/urnetwork/message/syntax"
)

// Task 12's properties (identity phase 1's plan; Spec A A-36 sections 6, 7.2 and 8.1).

// testIdentify gives a device an identity through the making ConfirmWords runs -- the ceremony, the
// salt, the three records and the engine under the identity key -- over words of its own. It founds no
// self group, which needs a connection; a device that is restored later founds its own. Every group this
// build founds is bound, so a test whose device founds one, or makes a key package, gives it an identity
// first.
func testIdentify(t testing.TB, device *Device) {
	t.Helper()
	// a device over a store that holds one already has it: a restart reads it back
	if _, err := device.requireIdentity(); err == nil {
		return
	}
	phrase, err := messagegroup.NewRecoveryPhrase()
	if err != nil {
		t.Fatalf("a recovery phrase: %v", err)
	}
	defer phrase.Erase()
	device.admitMutex.Lock()
	defer device.admitMutex.Unlock()
	// a test's identity is made under the test seam's stretch (LRI R76 item 10), whatever the device
	// was built with
	device.phraseStretch = messagegroup.FastPhraseStretchForTests()
	if err := device.makeIdentity(phrase); err != nil {
		t.Fatalf("the device's identity: %v", err)
	}
}

// testFixtureIdentity gives a fixture that drives the engine without a Device -- the cross-process
// device and the worlds built on it -- the identity a Device would have, made by the same making over
// the fixture's own store, so that a Device restored over that store later reads it back; a store that
// holds one answers it. It answers the identity key, which is the credential every leaf of the fixture
// names, and the fixture's own 0xF005.
func testFixtureIdentity(t testing.TB, crypto mls.CryptoProvider, store *DurableStateStore,
	signer mls.SignaturePrivateKey, signerPub []byte, leafKeys []byte) ([]byte, messagegroup.ExtensionBytes) {

	t.Helper()
	identity, _, err := loadIdentity(store, ed25519.PublicKey(signerPub))
	if err != nil {
		t.Fatalf("the fixture's identity, read back: %v", err)
	}
	if identity == nil {
		device := &Device{
			crypto:     crypto,
			stateStore: store,
			joinStage:  newJoinStage(store),
			leafKeys:   leafKeys,
			signer:     append(mls.SignaturePrivateKey(nil), signer...),
			devicePub:  ed25519.PublicKey(append([]byte(nil), signerPub...)),
			random:     rand.Reader,
			nowMs:      func() int64 { return time.Now().UnixMilli() },
			groups:     map[string]*Group{},
		}
		testIdentify(t, device)
		identity = device.identity
		zeroizeState(device.signer)
	}
	return append([]byte(nil), identity.record.CurrentKey...), identity.extension
}

// testSignerIdentity makes an identity for a signer that is no Device's -- a hand founder, a fixture's
// member -- by the ceremony the making runs: new words, key number 1, and a first base naming the signer
// as its only device, a phrase device, signed by it as the author and by the identity's signing key. It
// answers the identity key, which is the credential the signer's leaves name, and the 0xF005 that binds
// them to it.
func testSignerIdentity(t testing.TB, signer mls.SignaturePrivateKey, signerPub []byte) ([]byte, messagegroup.ExtensionBytes) {
	t.Helper()
	phrase, err := messagegroup.NewRecoveryPhrase()
	if err != nil {
		t.Fatalf("a recovery phrase: %v", err)
	}
	defer phrase.Erase()
	return testListIdentity(t, phrase, 1, signer, signerPub)
}

// testListIdentity is testSignerIdentity over words and a base number of the caller's: the list a
// phrase's key number 1 signs under that base number, naming the signer alone, a phrase device, as
// its author. Two signers handed one phrase and two base numbers carry two lists of one root.
func testListIdentity(t testing.TB, phrase *messagegroup.RecoveryPhrase, baseNumber uint64, signer mls.SignaturePrivateKey,
	signerPub []byte) ([]byte, messagegroup.ExtensionBytes) {

	t.Helper()
	author := ed25519.NewKeyFromSeed(signer)
	defer zeroizeState(author)
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
			Devices:     []messagegroup.DeviceEntry{{DeviceKey: signerPub, Flags: messagegroup.DeviceFlagPhraseDevice}},
			AuthorKey:   signerPub,
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
		t.Fatalf("a signer's identity under base %d: %v", baseNumber, err)
	}
	extension, err := own.Encode()
	if err != nil {
		t.Fatalf("a signer's identity extension: %v", err)
	}
	return identityKey, extension
}

// identityOrderStore is a durable store that writes down the order of the writes Property 1 is about:
// the identity layer's three records, and the first epoch state and group record of any group.
type identityOrderStore struct {
	*DurableStateStore
	mutex sync.Mutex
	order []string
}

func (self *identityOrderStore) note(what string) {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	self.order = append(self.order, what)
}

func (self *identityOrderStore) written() []string {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	return slices.Clone(self.order)
}

func (self *identityOrderStore) PutIdentity(record *IdentityRecord) error {
	self.note("identity")
	return self.DurableStateStore.PutIdentity(record)
}

func (self *identityOrderStore) PutIdentityHeads(heads []IdentityHead) error {
	self.note("identity-heads")
	return self.DurableStateStore.PutIdentityHeads(heads)
}

func (self *identityOrderStore) PutPhraseKey(record *PhraseKeyRecord) error {
	self.note("phrase-key")
	return self.DurableStateStore.PutPhraseKey(record)
}

func (self *identityOrderStore) PutGroupState(groupId []byte, epoch uint64, state []byte) error {
	self.note("group-state")
	return self.DurableStateStore.PutGroupState(groupId, epoch, state)
}

func (self *identityOrderStore) PutGroupRecord(record *GroupRecord) error {
	self.note("group-record")
	return self.DurableStateStore.PutGroupRecord(record)
}

// PROPERTY 1 (MI21): no identity, record, key or group exists until the words are typed back, and the
// identity's records are written before the self group is founded. CreateIdentity answers the words and
// makes nothing; asked again it answers the same words, which is Back; one wrong word makes nothing and
// is named by its position; and the words typed back make the identity, its three records first and the
// self group after them.
func TestNoIdentityExistsUntilTheWordsAreTypedBack(t *testing.T) {
	ctx := context.Background()
	store := &identityOrderStore{DurableStateStore: openTestStore(t, t.TempDir())}
	device := newAnsweringDeviceOver(t, store, []byte("the identity's nonce"))
	identityNames := []string{stateRootIdentityName, stateRootHeadsName, stateRootPhraseKeyName}

	nothingMade := func(when string) {
		t.Helper()
		held, err := stateRootNamesHeld(store.dataDir)
		if err != nil {
			t.Fatalf("%s: the store's root: %v", when, err)
		}
		for _, name := range identityNames {
			if slices.Contains(held, name) {
				t.Errorf("%s: the store holds %s", when, name)
			}
		}
		if slices.Contains(held, stateRootGroupsName) {
			t.Errorf("%s: the store holds a group", when)
		}
		if written := store.written(); len(written) != 0 {
			t.Errorf("%s: the store was written %v", when, written)
		}
		if _, err := device.Identity(); !errors.Is(err, ErrNoIdentity) {
			t.Errorf("%s: Identity answered %v, want ErrNoIdentity", when, err)
		}
		if _, err := device.KeyPackage(); !errors.Is(err, ErrNoIdentity) {
			t.Errorf("%s: KeyPackage answered %v, want ErrNoIdentity", when, err)
		}
		if device.holdsSystemGroup() || len(device.Groups()) != 0 {
			t.Errorf("%s: the device holds a group", when)
		}
	}
	nothingMade("before the words are offered")
	if err := device.ConfirmWords(ctx, "abandon"); !errors.Is(err, ErrNoWordsOffered) {
		t.Errorf("ConfirmWords before any words were offered answered %v, want ErrNoWordsOffered", err)
	}
	nothingMade("after words were typed back with none offered")

	words, err := device.CreateIdentity()
	if err != nil {
		t.Fatalf("CreateIdentity: %v", err)
	}
	if len(words) != 25 {
		t.Fatalf("CreateIdentity answered %d words, want 25", len(words))
	}
	again, err := device.CreateIdentity()
	if err != nil || !slices.Equal(again, words) {
		t.Errorf("CreateIdentity asked again answered other words (%v): Back must show the same words", err)
	}
	clear(again)
	nothingMade("after the words are offered")

	// ONE WRONG WORD makes nothing, and is named by its position
	wrong := slices.Clone(words)
	for _, other := range words {
		if other != wrong[6] {
			wrong[6] = other
			break
		}
	}
	err = device.ConfirmWords(ctx, strings.Join(wrong, " "))
	if !errors.Is(err, ErrWordsDoNotMatch) || !strings.Contains(err.Error(), "[7]") {
		t.Errorf("a wrong seventh word answered %v, want ErrWordsDoNotMatch naming position 7", err)
	}
	clear(wrong)
	nothingMade("after a wrong word")

	// THE WORDS TYPED BACK, in another case and spacing, which the reading folds
	typed := "  " + strings.ToUpper(strings.Join(words, "   ")) + "\n"
	clear(words)
	if err := device.ConfirmWords(ctx, typed); err != nil {
		t.Fatalf("ConfirmWords: %v", err)
	}
	written := store.written()
	firstGroup := slices.IndexFunc(written, func(what string) bool { return strings.HasPrefix(what, "group-") })
	if firstGroup < 0 {
		t.Fatalf("the store was written %v and no group of the self group's", written)
	}
	for _, name := range identityNames {
		at := slices.Index(written, name)
		if at < 0 || at > firstGroup {
			t.Errorf("the store was written %v: %s is not written before the self group's first write", written, name)
		}
	}
	held, err := stateRootNamesHeld(store.dataDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range identityNames {
		if !slices.Contains(held, name) {
			t.Errorf("after the words were typed back the store holds %v, without %s", held, name)
		}
	}
	if _, err := device.Identity(); err != nil {
		t.Errorf("Identity after the words were typed back: %v", err)
	}
	if !device.holdsSystemGroup() {
		t.Error("the words typed back founded no self group")
	}
	if _, err := device.CreateIdentity(); !errors.Is(err, ErrIdentityExists) {
		t.Errorf("CreateIdentity after the identity answered %v, want ErrIdentityExists", err)
	}
}

// PROPERTY 2, THE JOIN CODE (MI22): a device with no identity publishes no join code through
// KeyPackage, and founds no group; with one, its key package carries 0xF005, which binds it.
func TestADeviceWithNoIdentityPublishesNoJoinCode(t *testing.T) {
	ctx := context.Background()
	device := newAnsweringDeviceOver(t, NewMemoryStateStore(), []byte("the join code's nonce"))
	if code, err := device.KeyPackage(); !errors.Is(err, ErrNoIdentity) || code != nil {
		t.Errorf("KeyPackage with no identity answered %d octets and %v, want nothing and ErrNoIdentity", len(code), err)
	}
	if _, err := device.CreateGroup(ctx, bytes.Repeat([]byte{0x31}, GroupIdBytes)); !errors.Is(err, ErrNoIdentity) {
		t.Errorf("CreateGroup with no identity answered %v, want ErrNoIdentity", err)
	}

	testIdentify(t, device)
	code, err := device.KeyPackage()
	if err != nil {
		t.Fatalf("KeyPackage with an identity: %v", err)
	}
	keyPackage := &mls.KeyPackage{}
	if err := syntax.Unmarshal(code, keyPackage); err != nil {
		t.Fatalf("decode the key package: %v", err)
	}
	extensions := []messagegroup.ExtensionBytes{}
	for _, extension := range keyPackage.LeafNode.Extensions {
		extensions = append(extensions, messagegroup.ExtensionBytes{Type: uint16(extension.ExtensionType), Data: extension.ExtensionData})
	}
	verified, err := messagegroup.VerifyLeafBinding(keyPackage.LeafNode.Credential.Identity, keyPackage.LeafNode.SignatureKey, extensions)
	if err != nil {
		t.Fatalf("the key package's leaf does not bind: %v", err)
	}
	devicePub := device.devicePublic()
	if !slices.ContainsFunc(verified.Devices, func(entry messagegroup.DeviceEntry) bool { return bytes.Equal(entry.DeviceKey, devicePub) }) {
		t.Error("the key package's list does not name the device that made it")
	}
}

// PROPERTY 2, THE GROUPS (MI23): every group this build founds requires 0xF004 and 0xF005 of every
// member, and the self group 0xF006 as well, and carries 0xF006 {1, root}; the founder's leaf binds.
func TestEveryGroupThisBuildFoundsRequiresTheIdentityExtension(t *testing.T) {
	ctx := context.Background()
	device := newAnsweringDeviceOver(t, NewMemoryStateStore(), []byte("the founding's nonce"))
	words, err := device.CreateIdentity()
	if err != nil {
		t.Fatalf("CreateIdentity: %v", err)
	}
	if err := device.ConfirmWords(ctx, strings.Join(words, " ")); err != nil {
		t.Fatalf("ConfirmWords: %v", err)
	}
	clear(words)
	conversation, err := device.CreateGroup(ctx, bytes.Repeat([]byte{0x32}, GroupIdBytes))
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	var self *Group
	device.mutex.Lock()
	for _, group := range device.groups {
		if group.system {
			self = group
		}
	}
	device.mutex.Unlock()
	if self == nil {
		t.Fatal("the device holds no self group")
	}
	identity, err := device.requireIdentity()
	if err != nil {
		t.Fatal(err)
	}
	conversationWant := []mls.ExtensionType{mls.ExtensionTypeUrmessageGroupPolicy, mls.ExtensionTypeUrmessageLeafKeys,
		mls.ExtensionTypeUrmessageJoinSeal, mls.ExtensionTypeUrmessageIdentity}
	for _, one := range []struct {
		name   string
		group  *Group
		want   []mls.ExtensionType
		system bool
	}{
		{"the conversation", conversation, conversationWant, false},
		{"the self group", self, append(slices.Clone(conversationWant), mls.ExtensionTypeUrmessageGroupPurpose), true},
	} {
		extensions, err := groupContextExtensions(one.group.handle)
		if err != nil {
			t.Fatalf("%s's context: %v", one.name, err)
		}
		body, found, err := mls.FindExtension(extensions, mls.ExtensionTypeRequiredCapabilities)
		if err != nil || !found {
			t.Fatalf("%s's context requires nothing (%v, %v)", one.name, found, err)
		}
		required := &mls.RequiredCapabilities{}
		if err := syntax.Unmarshal(body, required); err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(required.ExtensionTypes, one.want) {
			t.Errorf("%s requires %#04x, want %#04x", one.name, required.ExtensionTypes, one.want)
		}
		purpose, carried, err := mls.FindExtension(extensions, mls.ExtensionTypeUrmessageGroupPurpose)
		if err != nil || carried != one.system {
			t.Errorf("%s carries 0xF006: %v (%v), want %v", one.name, carried, err, one.system)
		}
		if one.system {
			parsed, err := messagegroup.ParseGroupPurpose(messagegroup.ExtensionBytes{Type: uint16(mls.ExtensionTypeUrmessageGroupPurpose), Data: purpose})
			if err != nil || parsed.Purpose != 1 || !bytes.Equal(parsed.IdentityRoot, identity.record.Root) {
				t.Errorf("the self group's 0xF006 is %+v (%v), want {1, root}", parsed, err)
			}
		}
		view, err := one.group.handle.LeafAt(one.group.handle.OwnLeafIndex())
		if err != nil {
			t.Fatalf("%s's founder leaf: %v", one.name, err)
		}
		if _, err := messagegroup.VerifyLeafBinding(view.Credential, view.SignatureKey, view.Extensions); err != nil {
			t.Errorf("%s's founder leaf does not bind: %v", one.name, err)
		}
		if !bytes.Equal(view.Credential, identity.record.CurrentKey) {
			t.Errorf("%s's founder leaf names %x, want the identity key", one.name, view.Credential)
		}
	}
}

// PROPERTY 3 (MI24): no list this device answers holds a system group, at any call and after a
// restart. The self group is held and restored, and Groups and Restore answer conversations only.
func TestNoListThisDeviceAnswersHoldsAGroupOfItsOwnDevices(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	store, err := OpenDurableStateStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	device := newAnsweringDeviceOver(t, store, []byte("the first process's nonce"))
	words, err := device.CreateIdentity()
	if err != nil {
		t.Fatalf("CreateIdentity: %v", err)
	}
	if err := device.ConfirmWords(ctx, strings.Join(words, " ")); err != nil {
		t.Fatalf("ConfirmWords: %v", err)
	}
	clear(words)
	if !device.holdsSystemGroup() {
		t.Fatal("the device holds no self group")
	}
	if groups := device.Groups(); len(groups) != 0 {
		t.Errorf("Groups answers %d groups and this device holds its self group alone", len(groups))
	}
	conversation, err := device.CreateGroup(ctx, bytes.Repeat([]byte{0x33}, GroupIdBytes))
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if groups := device.Groups(); len(groups) != 1 || groups[0] != conversation {
		t.Errorf("Groups answers %d groups, want the one conversation", len(groups))
	}
	before, err := device.Identity()
	if err != nil {
		t.Fatal(err)
	}
	// WHAT IDENTITY ANSWERS: an account ID of 36 characters, this device's ID of 19, and the one device
	// the first list names, which is this one, a phrase device
	if len(before.AccountId) != 36 || len(before.DeviceId) != 19 || !before.PhraseDevice || len(before.Devices) != 1 ||
		before.Devices[0].DeviceId != before.DeviceId || !before.Devices[0].ThisDevice || !before.Devices[0].PhraseDevice {
		t.Errorf("Identity answered %+v, want a 36 character account ID, a 19 character device ID, and this device alone, a phrase device", before)
	}
	device.Close()
	store.Close()

	// THE RESTART: the identity comes back, the self group is restored, and neither list holds it
	reopened, err := OpenDurableStateStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { reopened.Close() })
	restarted := newAnsweringDeviceOver(t, reopened, []byte("the second process's nonce"))
	after, err := restarted.Identity()
	if err != nil || after.AccountId != before.AccountId || after.DeviceId != before.DeviceId {
		t.Fatalf("the identity came back as %+v (%v), want %+v", after, err, before)
	}
	restored, err := restarted.Restore(ctx)
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	for _, group := range restored {
		if group.system {
			t.Error("Restore answers the self group")
		}
	}
	if !restarted.holdsSystemGroup() {
		t.Error("the restart restored no self group")
	}
	for _, group := range restarted.Groups() {
		if group.system {
			t.Error("Groups answers the self group after the restart")
		}
	}
}

// PROPERTY 4 (MI25): only a phrase device holds the phrase key record, and it holds only the current
// key number's.
func TestOnlyAPhraseDeviceKeepsThePhrasesKey(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, t.TempDir())
	device := newAnsweringDeviceOver(t, store, []byte("the phrase key's nonce"))
	words, err := device.CreateIdentity()
	if err != nil {
		t.Fatalf("CreateIdentity: %v", err)
	}
	typed := strings.Join(words, " ")
	clear(words)
	if err := device.ConfirmWords(ctx, typed); err != nil {
		t.Fatalf("ConfirmWords: %v", err)
	}
	identity, err := device.requireIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if !identity.phrase {
		t.Fatal("the first device is not a phrase device")
	}
	kept, err := store.PhraseKey()
	if err != nil {
		t.Fatalf("the phrase device's phrase key: %v", err)
	}
	phrase, _, err := messagegroup.ParseRecoveryPhrase(typed)
	if err != nil {
		t.Fatal(err)
	}
	defer phrase.Erase()
	var want []byte
	if err := messagegroup.WithPhraseKeysUnder(messagegroup.FastPhraseStretchForTests(), phrase, []uint32{1}, func(keys *messagegroup.PhraseKeys) error {
		want, err = keys.PhraseKeySeed(1)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	defer zeroizeState(want)
	if kept.KeyNumber != 1 || !bytes.Equal(kept.IdentityKey, identity.record.CurrentKey) || !bytes.Equal(kept.Seed, want) {
		t.Errorf("the phrase key names key number %d and key %x, or its seed is not isk_seed[1]", kept.KeyNumber, kept.IdentityKey)
	}
	zeroizeState(kept.Seed)

	// A DEVICE THAT IS NOT A PHRASE DEVICE keeps none: the same records, written for the same identity
	// as a device the list names without the mark
	linked := *identity
	linked.phrase = false
	other := &Device{stateStore: openTestStore(t, t.TempDir())}
	if err := other.putIdentityRecords(&linked, want); err != nil {
		t.Fatalf("a linked device's records: %v", err)
	}
	otherStore := other.stateStore.(*DurableStateStore)
	if _, err := otherStore.Identity(); err != nil {
		t.Errorf("a linked device keeps no identity record: %v", err)
	}
	if _, err := otherStore.PhraseKey(); !errors.Is(err, ErrStateNotFound) {
		t.Errorf("a linked device's store answers its phrase key with %v, want ErrStateNotFound", err)
	}

	// AND ONLY THE CURRENT KEY NUMBER'S: a second key number's record takes the first's place
	seed := bytes.Repeat([]byte{0x5a}, ed25519.SeedSize)
	if err := store.PutPhraseKey(&PhraseKeyRecord{IdentityKey: identity.record.CurrentKey, KeyNumber: 2, Seed: seed}); err != nil {
		t.Fatal(err)
	}
	if kept, err := store.PhraseKey(); err != nil || kept.KeyNumber != 2 {
		t.Errorf("after key number 2's record the store answers %+v (%v), want key number 2's alone", kept, err)
	}
}

// THE WORDS LEAVE THE DEVICE ONCE THE IDENTITY STANDS, AND AT CLOSE (identity phase 1's Task 12). The
// offered phrase is the one phrase secret this package keeps past a call; ConfirmWords erases it once
// the identity is made, and Close erases it on a device whose words were never typed back. Either way
// the phrase the device held is blank, and no field holds it. Close erases the device's signing key
// too, which the device holds beside the engine's copy for the lists it signs.
//
// THE CONTROL: before either road the device holds a phrase that is not blank, and a signer.
func TestTheWordsLeaveTheDeviceOnceTheIdentityStandsAndAtClose(t *testing.T) {
	ctx := context.Background()
	blank := &messagegroup.RecoveryPhrase{}
	for _, road := range []string{"ConfirmWords", "Close"} {
		device := newAnsweringDeviceOver(t, NewMemoryStateStore(), []byte("the words' nonce"))
		words, err := device.CreateIdentity()
		if err != nil {
			t.Fatalf("%s: CreateIdentity: %v", road, err)
		}
		typed := strings.Join(words, " ")
		clear(words)
		device.identityLock.RLock()
		held := device.offered
		device.identityLock.RUnlock()
		device.mutex.Lock()
		signer := device.signer
		device.mutex.Unlock()
		if held == nil || held.Equal(blank) || len(signer) == 0 {
			t.Fatalf("CONTROL FAILED: %s: the device holds no offered phrase, a blank one, or no signer", road)
		}
		switch road {
		case "ConfirmWords":
			if err := device.ConfirmWords(ctx, typed); err != nil {
				t.Fatalf("ConfirmWords: %v", err)
			}
		case "Close":
			device.Close()
			if !bytes.Equal(signer, make([]byte, len(signer))) {
				t.Error("after Close the signing key the device held is not blank")
			}
			device.mutex.Lock()
			if device.signer != nil {
				t.Error("after Close the device still holds a signing key")
			}
			device.mutex.Unlock()
		}
		device.identityLock.RLock()
		after := device.offered
		device.identityLock.RUnlock()
		if after != nil {
			t.Errorf("after %s the device still holds the offered phrase", road)
		}
		if !held.Equal(blank) {
			t.Errorf("after %s the phrase the device held is not blank", road)
		}
	}
}

// A RESTART OFFERS NEW WORDS (AD1; M5:405). The words are never stored, so a device that offered them
// and closed before they were typed back offers other words when it starts again, and nothing of the
// first offer is on the disk.
func TestARestartOffersNewWords(t *testing.T) {
	store := openTestStore(t, t.TempDir())
	first := newAnsweringDeviceOver(t, store, []byte("the first process's nonce"))
	offered, err := first.CreateIdentity()
	if err != nil {
		t.Fatalf("CreateIdentity: %v", err)
	}
	shown := strings.Join(offered, " ")
	clear(offered)
	first.Close()

	second := newAnsweringDeviceOver(t, store, []byte("the second process's nonce"))
	again, err := second.CreateIdentity()
	if err != nil {
		t.Fatalf("CreateIdentity after the restart: %v", err)
	}
	if strings.Join(again, " ") == shown {
		t.Error("the restarted device offered the words the first process showed")
	}
	clear(again)
	held, err := stateRootNamesHeld(store.dataDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{stateRootIdentityName, stateRootHeadsName, stateRootPhraseKeyName} {
		if slices.Contains(held, name) {
			t.Errorf("an offer that was never typed back left %s on the disk", name)
		}
	}
}

// THE RESTORE RAISES THE HEADS, AND A HEAD ONLY RISES (identity phase 1's Task 12: Restore "loads the
// identity, re-verifies every leaf, raises the heads"). A group holds two members of one other
// identity, the first carrying that identity's base 2 and the second its base 1, in that order, so
// the older list is the last one read. After the restore the store's heads hold that root at base 2
// -- the newest list, not the last one -- beside this device's own root, at its own list.
//
// THE CONTROL: before the restore the store holds this device's own root alone.
func TestARestoreRaisesTheHeadsToTheNewestListOfEachRoot(t *testing.T) {
	dir := t.TempDir()
	groupId := bytes.Repeat([]byte{0x48}, GroupIdBytes)
	alice := openRestoreDevice(t, filepath.Join(dir, "alice"))
	own, err := alice.device.requireIdentity()
	if err != nil {
		t.Fatal(err)
	}

	// two members of one other identity: base 2 at the first leaf added, base 1 at the second
	phrase, err := messagegroup.NewRecoveryPhrase()
	if err != nil {
		t.Fatal(err)
	}
	defer phrase.Erase()
	member := func(name string, baseNumber uint64) ([]byte, messagegroup.ExtensionBytes) {
		store := openTestStore(t, filepath.Join(dir, name))
		crypto, err := mls.NewCryptoProvider(deviceCipherSuite)
		if err != nil {
			t.Fatal(err)
		}
		signer, signerPub, leafKeys, _, err := deviceIdentity(crypto, store, rand.Reader)
		if err != nil {
			t.Fatalf("%s's device identity: %v", name, err)
		}
		identityKey, list := testListIdentity(t, phrase, baseNumber, signer, signerPub)
		engine, err := messagegroup.NewConnectMlsEngine(crypto, store, signer, mls.BasicCredential(identityKey), leafKeys)
		if err != nil {
			t.Fatalf("%s's engine: %v", name, err)
		}
		keyPackage, err := engine.NewBoundKeyPackage([]messagegroup.ExtensionBytes{list})
		if err != nil {
			t.Fatalf("%s's key package: %v", name, err)
		}
		return keyPackage, list
	}
	newer, newerList := member("bob-phone", 2)
	older, olderList := member("bob-laptop", 1)
	if bytes.Equal(newerList.Data, olderList.Data) {
		t.Fatal("the two lists are one list")
	}

	handle, err := alice.device.createMlsGroup(groupId, false)
	if err != nil {
		t.Fatalf("createMlsGroup: %v", err)
	}
	pqSecret, err := messagegroup.NewPqSecret(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	mlsSecret, err := handle.Export(storageExporterLabel, nil, storageExporterBytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := handle.CommitAdd([][]byte{newer, older}); err != nil {
		t.Fatalf("CommitAdd: %v", err)
	}
	if err := handle.MergePendingCommit(); err != nil {
		t.Fatalf("MergePendingCommit: %v", err)
	}
	if err := alice.store.PutGroupRecord(&GroupRecord{
		GroupId:        groupId,
		PqSecret:       pqSecret,
		GroupHandleKey: messagegroup.GroupHandleKey(messagegroup.StorageRoot(mlsSecret, pqSecret)),
		Epoch:          1,
		Opened:         true,
	}); err != nil {
		t.Fatalf("PutGroupRecord: %v", err)
	}
	handle.Close()
	alice.close()

	revived := openRestoreDevice(t, filepath.Join(dir, "alice"))
	defer revived.close()
	headsOf := func() map[string][]byte {
		t.Helper()
		rows, err := revived.store.IdentityHeads()
		if err != nil {
			t.Fatalf("IdentityHeads: %v", err)
		}
		heads := map[string][]byte{}
		for _, row := range rows {
			heads[string(row.Root)] = row.Identity
		}
		return heads
	}
	before := headsOf()
	if len(before) != 1 || !bytes.Equal(before[string(own.record.Root)], own.extension.Data) {
		t.Fatalf("CONTROL FAILED: before the restore the store holds %d head(s), and it holds this device's own root alone", len(before))
	}
	record := epochPersistTheOneRecord(t, revived.store, groupId)
	if _, err := revived.device.restoreOne(revived.store, record, restoreTestNonce(), 1); err != nil {
		t.Fatalf("restoreOne: %v", err)
	}
	after := headsOf()
	if len(after) != 2 || !bytes.Equal(after[string(own.record.Root)], own.extension.Data) {
		t.Errorf("after the restore the store holds %d head(s), and this device's own root's is not its own list", len(after))
	}
	other, err := messagegroup.ParseUrmessageIdentity(newerList)
	if err != nil {
		t.Fatal(err)
	}
	if held := after[string(other.Base.IdentityKey)]; !bytes.Equal(held, newerList.Data) {
		t.Errorf("after the restore the other root's head is the list of %d octets, want base 2's: the newest list, and not the last one read",
			len(held))
	}
}

// recordRefusingStore is a durable store that takes no group record: a founding whose record cannot
// be written, which is where a ConfirmWords that stopped between the identity's records and its
// self group leaves the disk.
type recordRefusingStore struct {
	*DurableStateStore
}

func (self *recordRefusingStore) PutGroupRecord(record *GroupRecord) error {
	return fmt.Errorf("%w: this store takes no group record", ErrStateStoreState)
}

// selfGroupOf answers the id of the system group a device holds, and the root its 0xF006 names.
func selfGroupOf(t *testing.T, device *Device) ([]byte, []byte) {
	t.Helper()
	device.mutex.Lock()
	var self *Group
	for _, group := range device.groups {
		if group.system {
			self = group
		}
	}
	device.mutex.Unlock()
	if self == nil {
		return nil, nil
	}
	extensions, err := groupContextExtensions(self.handle)
	if err != nil {
		t.Fatal(err)
	}
	body, found, err := mls.FindExtension(extensions, mls.ExtensionTypeUrmessageGroupPurpose)
	if err != nil || !found {
		t.Fatalf("the system group carries no 0xF006 (%v, %v)", found, err)
	}
	purpose, err := messagegroup.ParseGroupPurpose(messagegroup.ExtensionBytes{Type: uint16(mls.ExtensionTypeUrmessageGroupPurpose), Data: body})
	if err != nil {
		t.Fatal(err)
	}
	return bytes.Clone(self.id), purpose.IdentityRoot
}

// A SELF GROUP WHOSE FOUNDING DID NOT FINISH IS FOUNDED AGAIN AT START (LRI R76 item 2). The setup
// stops between the identity's records and the self group: the store takes no group record, so the
// founding's record is refused, ConfirmWords answers the refusal, and the identity stands with no
// self group on the disk. The next process's Restore founds the self group again, from the device
// key and the identity's own list, with no words; and the process after that restores it rather
// than founding another.
//
// THE CONTROL: before the restart the identity stands, and the store holds no group record.
func TestASelfGroupWhoseFoundingDidNotFinishIsFoundedAgainAtStart(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	store, err := OpenDurableStateStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	device := newAnsweringDeviceOver(t, &recordRefusingStore{DurableStateStore: store}, []byte("the first process's nonce"))
	words, err := device.CreateIdentity()
	if err != nil {
		t.Fatalf("CreateIdentity: %v", err)
	}
	typed := strings.Join(words, " ")
	clear(words)
	if err := device.ConfirmWords(ctx, typed); !errors.Is(err, ErrStateStoreState) {
		t.Fatalf("CONTROL FAILED: ConfirmWords over a store that takes no group record answered %v, want the refusal", err)
	}
	made, err := device.Identity()
	if err != nil {
		t.Fatalf("CONTROL FAILED: the identity does not stand after its records were written: %v", err)
	}
	if records, err := store.GroupRecords(); err != nil || len(records) != 0 {
		t.Fatalf("CONTROL FAILED: the store holds %d group record(s) (%v), and the self group's was refused", len(records), err)
	}
	device.Close()
	store.Close()

	restart := func(nonce string) (*DurableStateStore, *Device) {
		t.Helper()
		reopened, err := OpenDurableStateStore(dir)
		if err != nil {
			t.Fatal(err)
		}
		restarted := newAnsweringDeviceOver(t, reopened, []byte(nonce))
		restored, err := restarted.Restore(ctx)
		if err != nil || len(restored) != 0 {
			t.Fatalf("Restore answered %d group(s) and %v; want none and no error", len(restored), err)
		}
		return reopened, restarted
	}
	reopened, restarted := restart("the second process's nonce")
	again, err := restarted.Identity()
	if err != nil || again.AccountId != made.AccountId {
		t.Fatalf("the identity came back as %+v (%v)", again, err)
	}
	selfId, root := selfGroupOf(t, restarted)
	identity, err := restarted.requireIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if selfId == nil || !bytes.Equal(root, identity.record.Root) {
		t.Fatalf("after the restart the device holds no self group of its own root (%x)", root)
	}
	records, err := reopened.GroupRecords()
	if err != nil || len(records) != 1 || !bytes.Equal(records[0].GroupId, selfId) {
		t.Fatalf("after the restart the store holds %d group record(s) (%v), want the self group's alone", len(records), err)
	}
	restarted.Close()
	reopened.Close()

	// AND THE PROCESS AFTER THAT RESTORES IT, rather than founding another
	reopened, restarted = restart("the third process's nonce")
	defer reopened.Close()
	if id, _ := selfGroupOf(t, restarted); !bytes.Equal(id, selfId) {
		t.Errorf("the third process holds self group %x, and the second founded %x", id, selfId)
	}
	if records, err := reopened.GroupRecords(); err != nil || len(records) != 1 {
		t.Errorf("the third process's store holds %d group record(s) (%v), want the one self group's", len(records), err)
	}
}

// A SELF GROUP WHOSE RECORD DOES NOT READ IS NOT FOUNDED AGAIN BESIDE IT (LRI R76 item 2). The
// repair founds the self group only when every record came back, since a record that did not may
// be the self group's own. Here it is: its record is cut in half, Restore reports it, and no
// second self group is founded beside the one the store cannot read.
//
// THE CONTROL: before the damage the device holds its self group, and its record reads.
func TestASelfGroupWhoseRecordDoesNotReadIsNotFoundedAgainBesideIt(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	store, err := OpenDurableStateStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	device := newAnsweringDeviceOver(t, store, []byte("the first process's nonce"))
	words, err := device.CreateIdentity()
	if err != nil {
		t.Fatalf("CreateIdentity: %v", err)
	}
	typed := strings.Join(words, " ")
	clear(words)
	if err := device.ConfirmWords(ctx, typed); err != nil {
		t.Fatalf("ConfirmWords: %v", err)
	}
	selfId, _ := selfGroupOf(t, device)
	if records, err := store.GroupRecords(); selfId == nil || err != nil || len(records) != 1 {
		t.Fatalf("CONTROL FAILED: the device holds self group %x and the store %d record(s) (%v)", selfId, len(records), err)
	}
	device.Close()
	octets, err := os.ReadFile(store.groupRecordPath(selfId))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(store.groupRecordPath(selfId), octets[:len(octets)/2], 0o600); err != nil {
		t.Fatal(err)
	}
	store.Close()

	reopened, err := OpenDurableStateStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { reopened.Close() })
	restarted := newAnsweringDeviceOver(t, reopened, []byte("the second process's nonce"))
	if _, err := restarted.Restore(ctx); !errors.Is(err, ErrGroupRecordDamaged) {
		t.Errorf("Restore answered %v, want the damaged record reported", err)
	}
	if restarted.holdsSystemGroup() {
		t.Error("the restart founded a self group beside the one whose record does not read")
	}
	if records, _ := reopened.GroupRecords(); len(records) != 0 {
		t.Errorf("the store holds %d group record(s) that read, and the only record of a group on it is the damaged one", len(records))
	}
}
