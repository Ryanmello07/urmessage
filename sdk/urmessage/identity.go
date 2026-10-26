package urmessage

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"slices"

	"github.com/urnetwork/glog"
	"github.com/urnetwork/message/messagegroup"
	"github.com/urnetwork/message/mls"
	"github.com/urnetwork/message/syntax"
)

// THE IDENTITY AT THE DEVICE, AND THE SELF GROUP (identity phase 1's Task 12; Spec A A-36 sections 6,
// 7.2 and 8.1; MASTER sections 5.1 to 5.3 at Revision 10).
//
// AD1's ORDER (M5 H.4). [Device.CreateIdentity] answers the 25 words and makes nothing: no record, no
// key, no group; asked again before the identity is made, it answers the same words. [Device.ConfirmWords], with all 25 typed back, then makes the identity --
// key number 1, the first base naming this device as a phrase device, the account ID's salt -- writes
// its three records, and only then founds the self group, with 0xF006 {1, root} in its context. Back
// shows the same words; a restart makes new ones, since the words are never stored.
//
// ONE IDENTITY KEY IS THE CREDENTIAL OF EVERY LEAF THIS DEVICE MAKES FROM THEN ON, and the engine is
// rebuilt under it: a leaf's credential is the identity key, its signature key is this device's own,
// and its 0xF005 binds the one to the other. Until an identity exists every call that needs one
// answers [ErrNoIdentity] -- [Device.KeyPackage] and [Device.CreateGroup] among them -- and every
// group this build founds requires 0xF004 and 0xF005 of every member, and a system group 0xF006 as
// well (Spec A A-36 section 3.4).
//
// THE SELF GROUP IS NEVER A CONVERSATION. [Device.Groups] and [Device.Restore] answer conversations
// only, which closes SCOPE G11's trap: the app opens the first group it is answered.

// Identity is what [Device.Identity] answers: the account ID, of 36 characters; this device's ID, of
// 19; whether this device is a phrase device; and the devices the newest list names, with their marks.
// The notices, the alarm, the phrase changes and the removed state join it in the tasks that make them
// (Spec A A-36 section 7.2).
type Identity struct {
	AccountId    string
	DeviceId     string
	PhraseDevice bool
	Devices      []IdentityDevice
}

// IdentityDevice is one device of the newest list.
type IdentityDevice struct {
	DeviceId     string
	PhraseDevice bool
	ThisDevice   bool
}

// deviceIdentityState is the identity this device runs under, once it has one: the record, this
// device's own 0xF005 body, decoded and encoded, and what the binding check of it answered.
type deviceIdentityState struct {
	record    IdentityRecord
	own       *messagegroup.UrmessageIdentity
	extension messagegroup.ExtensionBytes
	verified  *messagegroup.VerifiedIdentity
	accountId messagegroup.AccountId
	deviceId  messagegroup.DeviceId
	phrase    bool
}

// newDeviceIdentityState checks this device's own 0xF005 as every receiver will -- VerifyLeafBinding
// over the identity key as the credential and this device's key as the signature key -- and answers
// the state built from it. An identity whose own list does not bind this device is refused rather than
// run under: every leaf this device made would fail the check every member makes.
func newDeviceIdentityState(record IdentityRecord, own *messagegroup.UrmessageIdentity,
	devicePub ed25519.PublicKey) (*deviceIdentityState, error) {

	extension, err := own.Encode()
	if err != nil {
		return nil, fmt.Errorf("urmessage: this device's identity extension: %w", err)
	}
	verified, err := messagegroup.VerifyLeafBinding(record.CurrentKey, devicePub, []messagegroup.ExtensionBytes{extension})
	if err != nil {
		return nil, fmt.Errorf("urmessage: this device's own identity does not bind it: %w", err)
	}
	if !bytes.Equal(verified.Root, record.Root) {
		return nil, fmt.Errorf("urmessage: this device's list is under root %x and its identity record names %x", verified.Root, record.Root)
	}
	accountId, err := messagegroup.AccountIdOf(record.Root, record.Salt)
	if err != nil {
		return nil, err
	}
	deviceId, err := messagegroup.DeviceIdOf(record.Root, devicePub)
	if err != nil {
		return nil, err
	}
	state := &deviceIdentityState{
		record:    record,
		own:       own,
		extension: extension,
		verified:  verified,
		accountId: accountId,
		deviceId:  deviceId,
	}
	for _, device := range verified.Devices {
		if bytes.Equal(device.DeviceKey, devicePub) {
			state.phrase = device.Flags&messagegroup.DeviceFlagPhraseDevice != 0
		}
	}
	return state, nil
}

// CreateIdentity answers the 25 words of a new recovery phrase and makes nothing (AD1). Asked again
// before [Device.ConfirmWords] makes the identity, it answers the same words, which is Back; a restart
// makes new ones (LRI R84's G-8: not "once"). The caller shows the words and clears the slice once they are shown (clear(words)).
func (self *Device) CreateIdentity() ([]string, error) {
	if self.identityUnreadable != nil {
		return nil, self.identityUnreadable
	}
	self.identityLock.Lock()
	defer self.identityLock.Unlock()
	if self.identity != nil {
		return nil, ErrIdentityExists
	}
	if self.offered == nil {
		phrase, err := messagegroup.NewRecoveryPhrase()
		if err != nil {
			return nil, fmt.Errorf("urmessage: a recovery phrase: %w", err)
		}
		self.offered = phrase
	}
	return self.offered.Words(), nil
}

// ConfirmWords takes the 25 words typed back and makes the identity (AD1). Input is read as
// messagegroup.ParseRecoveryPhrase reads it; a word that is not the word shown is named by its position
// -- a missing or an extra word included -- and nothing is corrected ([ErrWordsDoNotMatch]). The device
// must be connected, since the self group is founded under the connection's nonce, and that is asked
// before anything is made.
//
// IN THIS ORDER, AND ONLY THEN (Property 1): the ceremony over key number 1; the identity record, the
// heads and the phrase key, written; the engine, rebuilt under the identity key; the self group,
// founded with 0xF006 {1, root}, its record written. The words leave this device's memory once the
// identity stands.
func (self *Device) ConfirmWords(ctx context.Context, phraseTyped string) error {
	if self.identityUnreadable != nil {
		return self.identityUnreadable
	}
	self.admitMutex.Lock()
	defer self.admitMutex.Unlock()
	self.identityLock.RLock()
	offered, exists := self.offered, self.identity != nil
	self.identityLock.RUnlock()
	if exists {
		return ErrIdentityExists
	}
	if offered == nil {
		return ErrNoWordsOffered
	}
	// THE WORDS SHOWN, COMPARED POSITION BY POSITION: the parser cannot name a list word whose checksum
	// fails, and this device, which showed the words, can
	if differing := offered.WordsDiffering(phraseTyped); len(differing) != 0 {
		return &WrongWords{Positions: differing}
	}
	parsed, _, err := messagegroup.ParseRecoveryPhrase(phraseTyped)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrWordsDoNotMatch, err)
	}
	defer parsed.Erase()
	if !parsed.Equal(offered) {
		return ErrWordsDoNotMatch
	}
	nonce, nonceEpoch, err := self.nonce()
	if err != nil {
		return err
	}
	if err := self.makeIdentity(parsed); err != nil {
		return err
	}
	// THE WORDS LEAVE THIS DEVICE'S MEMORY ONCE THE IDENTITY STANDS, whatever the founding below answers:
	// from here CreateIdentity and ConfirmWords answer ErrIdentityExists, so nothing would read them again
	self.identityLock.Lock()
	if self.offered != nil {
		self.offered.Erase()
		self.offered = nil
	}
	self.identityLock.Unlock()

	// THE SELF GROUP
	return self.foundSelfGroupLocked(ctx, nonce, nonceEpoch)
}

// WrongWords is ConfirmWords' answer when the words typed back are not the words shown (Spec A A-36
// section 7.2: "a wrong word is named by its position and nothing is corrected"): the positions, from
// 1, of the words that differ, a missing word and an extra one among them, as data a screen marks
// its fields by. It carries no word. It is [ErrWordsDoNotMatch], and says the positions.
type WrongWords struct {
	Positions []int
}

func (self *WrongWords) Error() string {
	return fmt.Sprintf("%s: the words at positions %v", ErrWordsDoNotMatch.Error(), self.Positions)
}

// Unwrap answers [ErrWordsDoNotMatch], so that errors.Is reads a WrongWords as that refusal.
func (self *WrongWords) Unwrap() error {
	return ErrWordsDoNotMatch
}

// makeIdentity is the identity's making, from the phrase typed back, and everything of it but the self
// group: the ceremony over key number 1, the account ID's salt, the three records, and the engine
// rebuilt under the identity key, in that order (Property 1). [Device.ConfirmWords] founds the self
// group after it. Called with admitMutex held.
func (self *Device) makeIdentity(parsed *messagegroup.RecoveryPhrase) error {
	signer, devicePub := self.deviceSigner()
	defer zeroizeState(signer)
	if len(signer) != ed25519.SeedSize {
		return fmt.Errorf("urmessage: this device holds no signing key of %d octets, so it signs no list", ed25519.SeedSize)
	}
	// the author's key, expanded from the device's seed for the one signature, and erased after it
	author := ed25519.NewKeyFromSeed(signer)
	defer zeroizeState(author)
	var record IdentityRecord
	var own *messagegroup.UrmessageIdentity
	var seed []byte
	defer func() { zeroizeState(seed) }()
	err := messagegroup.WithPhraseKeysUnder(self.phraseStretch, parsed, []uint32{1}, func(keys *messagegroup.PhraseKeys) error {
		identityKey := keys.IdentityKey()
		cert, err := keys.SignIskCert(1)
		if err != nil {
			return err
		}
		base := &messagegroup.DeviceListBase{
			IdentityKey: identityKey,
			KeyNumber:   1,
			BaseNumber:  1,
			IssuedAtMs:  uint64(self.nowMs()),
			Devices:     []messagegroup.DeviceEntry{{DeviceKey: devicePub, Flags: messagegroup.DeviceFlagPhraseDevice}},
			AuthorKey:   devicePub,
		}
		if err := messagegroup.SignBaseAuthor(base, author); err != nil {
			return err
		}
		if err := keys.SignBase(1, base); err != nil {
			return err
		}
		if seed, err = keys.PhraseKeySeed(1); err != nil {
			return err
		}
		record = IdentityRecord{Root: identityKey, CurrentKey: identityKey}
		own = &messagegroup.UrmessageIdentity{IskCert: *cert, Base: *base}
		return nil
	})
	if err != nil {
		return fmt.Errorf("urmessage: the identity's ceremony: %w", err)
	}
	if _, err := io.ReadFull(self.random, record.Salt[:]); err != nil {
		return fmt.Errorf("urmessage: the account ID's salt: %w", err)
	}
	state, err := newDeviceIdentityState(record, own, devicePub)
	if err != nil {
		return err
	}

	// THE RECORDS, BEFORE THE SELF GROUP
	if err := self.putIdentityRecords(state, seed); err != nil {
		return err
	}
	// THE ENGINE, UNDER THE IDENTITY KEY
	engine, err := messagegroup.NewConnectMlsEngine(self.crypto, self.joinStage, signer,
		mls.BasicCredential(record.CurrentKey), self.leafKeys)
	if err != nil {
		return fmt.Errorf("urmessage: the mls engine under the identity key: %w", err)
	}
	self.identityLock.Lock()
	replaced := self.engine
	self.engine = engine
	self.identityPub = append([]byte(nil), record.CurrentKey...)
	self.identity = state
	self.heads = map[string][]byte{string(record.Root): state.extension.Data}
	self.identityLock.Unlock()
	// THE ENGINE THIS ONE REPLACES ERASES ITS COPY OF device_sig (LRI R85; review L-5's second half).
	// Nothing founds, joins or restores through it after the swap above: each asks
	// [Device.currentEngine] under admitMutex, which the making holds; a key package needs the
	// identity, set in the same swap; and a past epoch loads through the engine that stands when it is
	// asked. An engine that declares no erase has nothing to erase here.
	if erasable, erases := replaced.(interface{ Zeroize() }); erases {
		erasable.Zeroize()
	}

	return nil
}

// putIdentityRecords writes the identity layer's three records, on a durable store, between the two
// halves of the setup mark: the mark, then the heads, then -- on a phrase device only, for its current
// key number only (Property 4) -- the phrase key, then the identity record, and the mark's removal
// LAST. A store that is not durable keeps nothing, as for every other record.
//
// THE IDENTITY RECORD IS THE COMMIT POINT (LRI R84 item 1; review L-1). Each record is written
// atomically, and the record a start reads first is the identity record ([loadIdentity]). So a
// process stopped before the identity record leaves a device with no identity, over which setup runs
// again; and a process stopped after it leaves a whole identity, whose self group is founded again
// at start if its founding did not finish (R76 item 2). Written in the other order, a stop between the
// identity record and the heads left a store no start would open again, and a stop before the phrase
// key a phrase device without its phrase key.
//
// THE SETUP MARK IS WHAT A STOP BEFORE THE COMMIT POINT IS SWEPT ON (LRI R86). Such a stop leaves the
// heads and, on a phrase device, a phrase key record of an identity that was never made, beside the
// mark this making wrote first: the next start erases them under erase authority (j)
// ([DurableStateStore.SweepIdentityOrphans]), and nothing reads either before it. The mark goes only
// once the identity record stands, so a stop between the two leaves a whole identity and its mark,
// and the next start takes the mark alone. A removal of the mark that fails here fails nothing: the
// identity record already stands, and the next start takes the mark away beside it.
func (self *Device) putIdentityRecords(state *deviceIdentityState, seed []byte) error {
	store, durable := self.stateStore.(DeviceStore)
	if !durable {
		return nil
	}
	// THE SETUP MARK, FIRST
	if err := store.PutSetupMark(state.record.Root); err != nil {
		return fmt.Errorf("urmessage: the setup mark: %w", err)
	}
	if err := store.PutIdentityHeads([]IdentityHead{{Root: state.record.Root, Identity: state.extension.Data}}); err != nil {
		return fmt.Errorf("urmessage: the heads: %w", err)
	}
	if state.phrase {
		if err := store.PutPhraseKey(&PhraseKeyRecord{
			IdentityKey: state.record.CurrentKey,
			KeyNumber:   state.own.IskCert.KeyNumber,
			Seed:        seed,
		}); err != nil {
			return fmt.Errorf("urmessage: the phrase key: %w", err)
		}
	}
	// THE COMMIT POINT
	if err := store.PutIdentity(&state.record); err != nil {
		return fmt.Errorf("urmessage: the identity record: %w", err)
	}
	// THE MARK GOES, ONLY NOW THAT THE IDENTITY RECORD STANDS. A removal that fails fails nothing, and says
	// so in one line with no key or word (LRI R89 item 3; review D2L-4, L-D2)
	if err := store.ClearSetupMark(); err != nil {
		glog.Warningf("urmessage: the setup mark could not be removed beside the identity record that stands, and the next start removes it: %v", err)
	}
	return nil
}

// loadIdentity reads this device's identity back from a durable store at start, with its heads:
// nothing for a store that holds no identity record, and a refusal for one whose records do not
// stand together.
func loadIdentity(store DeviceStore, devicePub ed25519.PublicKey) (*deviceIdentityState, map[string][]byte, error) {
	record, err := store.Identity()
	if errors.Is(err, ErrStateNotFound) {
		return nil, map[string][]byte{}, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("urmessage: the identity record: %w", err)
	}
	rows, err := store.IdentityHeads()
	if err != nil {
		return nil, nil, fmt.Errorf("urmessage: the heads beside the identity record: %w", err)
	}
	heads := map[string][]byte{}
	for _, row := range rows {
		heads[string(row.Root)] = row.Identity
	}
	body, found := heads[string(record.Root)]
	if !found {
		return nil, nil, fmt.Errorf("%w: the heads hold no list of this identity's own root", ErrStateStoreFormat)
	}
	own, err := messagegroup.ParseUrmessageIdentity(messagegroup.ExtensionBytes{
		Type: uint16(mls.ExtensionTypeUrmessageIdentity), Data: body,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("urmessage: this identity's own list: %w", err)
	}
	state, err := newDeviceIdentityState(*record, own, devicePub)
	if err != nil {
		return nil, nil, err
	}
	return state, heads, nil
}

// Identity answers this device's identity, or [ErrNoIdentity] before it has one.
func (self *Device) Identity() (*Identity, error) {
	if self.identityUnreadable != nil {
		return nil, self.identityUnreadable
	}
	self.identityLock.RLock()
	state := self.identity
	self.identityLock.RUnlock()
	if state == nil {
		return nil, ErrNoIdentity
	}
	devicePub := self.devicePublic()
	answer := &Identity{
		AccountId:    state.accountId.String(),
		DeviceId:     state.deviceId.String(),
		PhraseDevice: state.phrase,
	}
	for _, device := range state.verified.Devices {
		id, err := messagegroup.DeviceIdOf(state.record.Root, device.DeviceKey)
		if err != nil {
			return nil, err
		}
		answer.Devices = append(answer.Devices, IdentityDevice{
			DeviceId:     id.String(),
			PhraseDevice: device.Flags&messagegroup.DeviceFlagPhraseDevice != 0,
			ThisDevice:   bytes.Equal(device.DeviceKey, devicePub),
		})
	}
	return answer, nil
}

// requireIdentity answers the identity this device runs under, or [ErrNoIdentity].
func (self *Device) requireIdentity() (*deviceIdentityState, error) {
	if self.identityUnreadable != nil {
		return nil, self.identityUnreadable
	}
	self.identityLock.RLock()
	defer self.identityLock.RUnlock()
	if self.identity == nil {
		return nil, ErrNoIdentity
	}
	return self.identity, nil
}

// currentEngine is the engine this device founds, joins and restores through: the one built at start,
// and the one rebuilt under the identity key once the identity is made.
func (self *Device) currentEngine() messagegroup.GroupEngine {
	self.identityLock.RLock()
	defer self.identityLock.RUnlock()
	return self.engine
}

// credentialIdentity is the credential this device's leaves name: its own key until it has an
// identity, and the identity key from then on.
func (self *Device) credentialIdentity() []byte {
	self.identityLock.RLock()
	defer self.identityLock.RUnlock()
	return self.identityPub
}

// deviceSigner answers a copy of this device's signing key, which the caller erases, and its public
// half. A copy, because [Device.Close] erases the device's own under the mutex while a caller may still
// be signing with it.
func (self *Device) deviceSigner() (mls.SignaturePrivateKey, ed25519.PublicKey) {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	return append(mls.SignaturePrivateKey(nil), self.signer...), self.devicePub
}

// devicePublic answers this device's public half, the key its lists name: no copy of the private one.
func (self *Device) devicePublic() ed25519.PublicKey {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	return self.devicePub
}

// foundSelfGroupLocked founds the self group: a group of this identity's devices, founded with 0xF006
// {1, root} in its context, which requires 0xF006 of every member (Spec A A-36 section 3.4) and is never
// in a conversation list. Its record is written at once, though it is opened on the server only when a
// second device joins it, so that a restart restores it as the system group it is. Called with
// admitMutex held.
func (self *Device) foundSelfGroupLocked(ctx context.Context, nonce []byte, nonceEpoch uint64) error {
	groupId := make([]byte, GroupIdBytes)
	if _, err := io.ReadFull(self.random, groupId); err != nil {
		return fmt.Errorf("urmessage: the self group's id: %w", err)
	}
	group, err := self.foundGroupLocked(groupId, true, nonce, nonceEpoch)
	if err != nil {
		return fmt.Errorf("urmessage: the self group: %w", err)
	}
	group.mutex.Lock()
	record := group.groupRecordLocked(false)
	group.mutex.Unlock()
	if err := self.persistGroup(record); err != nil {
		return fmt.Errorf("urmessage: the self group's record: %w", err)
	}
	return nil
}

// selfGroupPurpose is the 0xF006 body of this identity's self group: purpose 1, the root.
func selfGroupPurpose(root []byte) (messagegroup.ExtensionBytes, error) {
	return (&messagegroup.GroupPurpose{Purpose: 1, IdentityRoot: root}).Encode()
}

// groupIsSystem answers whether a group's context carries 0xF006, which is what makes it a system
// group, read off the group's own context and never off a caller's claim about it.
func groupIsSystem(handle messagegroup.GroupHandle) (bool, error) {
	extensions, err := groupContextExtensions(handle)
	if err != nil {
		return false, err
	}
	_, found, err := mls.FindExtension(extensions, mls.ExtensionTypeUrmessageGroupPurpose)
	return found, err
}

// requireIdentityExtension answers [ErrGroupPredatesIdentity] for a group whose context does not
// REQUIRE urmessage_identity of every member, which is how a group says it was founded by a build
// with no identity layer, and nil for one that does. It is requireJoinSeal's twin.
func requireIdentityExtension(handle messagegroup.GroupHandle) error {
	extensions, err := groupContextExtensions(handle)
	if err != nil {
		return err
	}
	body, found, err := mls.FindExtension(extensions, mls.ExtensionTypeRequiredCapabilities)
	if err != nil {
		return err
	}
	if found {
		required := &mls.RequiredCapabilities{}
		if err := syntax.Unmarshal(body, required); err != nil {
			return fmt.Errorf("urmessage: the group's required capabilities: %w", err)
		}
		if slices.Contains(required.ExtensionTypes, mls.ExtensionTypeUrmessageIdentity) {
			return nil
		}
	}
	return ErrGroupPredatesIdentity
}

// groupContextExtensions is a group's context's extensions, read off its own context.
func groupContextExtensions(handle messagegroup.GroupHandle) ([]mls.Extension, error) {
	contextBytes, err := handle.GroupContextBytes()
	if err != nil {
		return nil, fmt.Errorf("urmessage: the group context: %w", err)
	}
	context := &mls.GroupContext{}
	if err := syntax.Unmarshal(contextBytes, context); err != nil {
		return nil, fmt.Errorf("urmessage: decoding the group context: %w", err)
	}
	return context.Extensions, nil
}

// verifyEveryLeaf reads a group's whole tree as it stands, as the Join door and the restore read one
// (identity phase 1's Tasks 12 and 13): every leaf binds, or is the one profile-1 leaf a link group may
// hold ([ErrGroupLeafUnbound]); no two lists of one identity fork ([ErrDeviceListEquivocation]); and
// where the context carries 0xF006, R9's membership holds ([ErrSystemGroupViolation]). It answers the
// lists the leaves carry, verified, for the heads.
func verifyEveryLeaf(handle messagegroup.GroupHandle) ([]*messagegroup.VerifiedIdentity, error) {
	members, err := treeMembersOf(handle)
	if err != nil {
		return nil, err
	}
	extensions, err := groupContextExtensions(handle)
	if err != nil {
		return nil, err
	}
	return checkTreeBinding(members, seamExtensionsOf(extensions))
}
