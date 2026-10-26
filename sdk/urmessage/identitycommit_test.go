package urmessage

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/message/messagegroup"
	"github.com/urnetwork/message/mls"
	messageprotocol "github.com/urnetwork/message/protocol"
	"github.com/urnetwork/message/sdk"
)

// THE IDENTITY RECORD IS THE COMMIT POINT (LRI R84 item 1; review L-1). ConfirmWords writes the
// setup mark first, then the heads and the phrase key, then the identity record, each atomically, and
// takes the mark away last; the record a start reads first is the identity record. So a process
// killed anywhere in the making leaves one of two disks: no identity, over which setup runs again, or
// a whole identity -- its heads, its phrase key, and a self group founded again at start if its
// founding did not finish (R76 item 2).
//
// AND EVERY START LEAVES NO SETUP MARK, AND NO ORPHAN (LRI R85, R86). With no identity, the start
// erases the heads and the phrase key the killed making left beside its mark, and the mark; with a
// whole identity, a mark the making did not live to take away is taken alone.
//
// THE KILL IS A COPY. killPointStore copies the store's whole data directory at the call of every
// write the making makes, the mark's write and its removal included, before the write lands, which is
// the disk a process killed at that instant leaves behind. Every copy is then opened as the next
// process opens its directory, and every one must start.
//
// THE CONTROL: the copies span both outcomes, at least one with no identity and one with a whole
// identity, so that neither arm is held vacuously, and the folder nothing killed starts too.
func TestASetupKilledBetweenAnyTwoWritesStartsWithNoIdentityOrAWholeOne(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	kills := &killPointStore{DurableStateStore: openTestStore(t, dir), t: t, root: t.TempDir()}
	device := newAnsweringDeviceOver(t, kills, []byte("the first process's nonce"))
	words, err := device.CreateIdentity()
	if err != nil {
		t.Fatalf("CreateIdentity: %v", err)
	}
	typed := strings.Join(words, " ")
	clear(words)
	if err := device.ConfirmWords(ctx, typed); err != nil {
		t.Fatalf("ConfirmWords: %v", err)
	}
	made, err := device.Identity()
	if err != nil {
		t.Fatalf("Identity: %v", err)
	}
	points := kills.points()
	written := []string{}
	for _, point := range points {
		written = append(written, point.before)
	}
	// THE MARK FIRST AND ITS REMOVAL AFTER THE COMMIT POINT: the order the kills are taken in
	order := []string{stateRootSetupMarkName, stateRootHeadsName, stateRootPhraseKeyName, stateRootIdentityName, killBeforeMarkRemoval}
	at := 0
	for _, write := range written {
		if at < len(order) && write == order[at] {
			at += 1
		}
	}
	if at != len(order) || !containsString(written, "group-record") {
		t.Fatalf("the making wrote %v: want %v in that order, and a group record, so the kill points do not cover the making", written, order)
	}
	device.Close()

	noIdentity, whole := 0, 0
	takenBy := map[string][]string{}
	for _, point := range points {
		outcome, taken := restartFromKill(t, point)
		switch outcome {
		case killLeftNoIdentity:
			noIdentity += 1
		case killLeftAWholeIdentity:
			whole += 1
		}
		takenBy[point.before] = taken
	}
	// THE CONTROL: the folder nothing killed starts, with the identity it made
	untouched := killPoint{before: "nothing", dir: dir}
	kills.DurableStateStore.Close()
	if outcome, _ := restartFromKill(t, untouched); outcome != killLeftAWholeIdentity {
		t.Errorf("CONTROL FAILED: the folder nothing killed did not start with its identity whole")
	}
	if noIdentity == 0 || whole == 0 {
		t.Errorf("CONTROL FAILED: of %d kill(s), %d left no identity and %d a whole one; the kills must reach both",
			len(points), noIdentity, whole)
	}
	// THE SWEEP'S CONTROLS (LRI R85, R86), so that restartFromKill's assertions were not held over
	// disks with nothing to take: the kill just before the identity record left the phrase key, the
	// heads and the mark, and the start erased all three; the kill just before the mark's removal left
	// a whole identity with its mark, and the start took the mark alone
	if taken := takenBy[stateRootIdentityName]; !slices.Equal(taken, []string{stateRootPhraseKeyName, stateRootHeadsName, stateRootSetupMarkName}) {
		t.Errorf("CONTROL FAILED: the start after the kill before the identity record took %v, want the phrase key, the heads and the setup mark", taken)
	}
	if taken := takenBy[killBeforeMarkRemoval]; !slices.Equal(taken, []string{stateRootSetupMarkName}) {
		t.Errorf("CONTROL FAILED: the start after the kill before the mark's removal took %v, want the setup mark alone", taken)
	}
	t.Logf("%d kill points over the writes %v: %d left no identity, %d a whole identity; what each start took: %v (account digest %s)",
		len(points), written, noIdentity, whole, takenBy, digestForTest(made.AccountId))
}

// killBeforeMarkRemoval names the kill at the call that takes the setup mark away, which comes after
// the identity record stands.
const killBeforeMarkRemoval = "the setup mark's removal"

type killOutcome int

const (
	killLeftNothingThatStarts killOutcome = iota
	killLeftNoIdentity
	killLeftAWholeIdentity
)

// restartFromKill opens one kill's disk as the next process opens its directory, and says what it
// holds: no identity, its setup's orphans and its mark swept by the start, over which setup runs again
// to an identity that itself restarts whole; or a whole identity, its heads naming its own list, its
// phrase key held, no setup mark left beside it, and a self group held once Restore has run. Anything
// else is a failure of the test, named by the write the kill came before. It also answers what the
// start took of the setup's records -- the phrase key, the heads and the setup mark -- that stood on
// the kill's disk.
func restartFromKill(t *testing.T, point killPoint) (killOutcome, []string) {
	t.Helper()
	ctx := context.Background()
	stood := setupRecordsOn(point.dir)
	store, err := OpenDurableStateStore(point.dir)
	if err != nil {
		t.Errorf("killed before %s: the store does not open: %v", point.before, err)
		return killLeftNothingThatStarts, nil
	}
	defer store.Close()
	device, err := newKillRestartDevice(t, store, "the restart after a kill before "+point.before)
	if err != nil {
		t.Errorf("killed before %s: the next start refuses the device: %v", point.before, err)
		return killLeftNothingThatStarts, nil
	}
	defer device.Close()
	left := setupRecordsOn(point.dir)
	taken := []string{}
	for _, name := range stood {
		if !containsString(left, name) {
			taken = append(taken, name)
		}
	}
	// NO START LEAVES A SETUP MARK (LRI R86): with no identity it went with the orphans it authorized,
	// and beside a whole identity it went alone
	if containsString(left, stateRootSetupMarkName) {
		t.Errorf("killed before %s: the start left the setup mark standing (%v stood before it)", point.before, stood)
		return killLeftNothingThatStarts, nil
	}
	identity, err := device.Identity()
	if errors.Is(err, ErrNoIdentity) {
		// A SETUP'S ORPHANS ARE SWEPT BY THE START (LRI R85, R86; erase authority (j)): whatever of the
		// heads and the phrase key the kill left beside its mark and no identity record is gone, from
		// the disk and from the store's reads, before setup runs again
		if len(left) != 0 {
			t.Errorf("killed before %s: the start left %v standing beside no identity record (%v stood before it): a setup's orphans were not swept",
				point.before, left, stood)
			return killLeftNothingThatStarts, nil
		}
		if _, err := store.IdentityHeads(); !errors.Is(err, ErrStateNotFound) {
			t.Errorf("killed before %s: after the start the store's heads read answers %v, want ErrStateNotFound", point.before, err)
			return killLeftNothingThatStarts, nil
		}
		if _, err := store.PhraseKey(); !errors.Is(err, ErrStateNotFound) {
			t.Errorf("killed before %s: after the start the store's phrase key read answers %v, want ErrStateNotFound", point.before, err)
			return killLeftNothingThatStarts, nil
		}
		// SETUP RUNS AGAIN, and its identity stands
		words, err := device.CreateIdentity()
		if err != nil {
			t.Errorf("killed before %s: no identity, and CreateIdentity answers %v", point.before, err)
			return killLeftNothingThatStarts, nil
		}
		typed := strings.Join(words, " ")
		clear(words)
		if err := device.ConfirmWords(ctx, typed); err != nil {
			t.Errorf("killed before %s: no identity, and setting up again answers %v", point.before, err)
			return killLeftNothingThatStarts, nil
		}
		if _, err := device.Identity(); err != nil {
			t.Errorf("killed before %s: setting up again made no identity: %v", point.before, err)
			return killLeftNothingThatStarts, nil
		}
		if _, err := store.PhraseKey(); err != nil {
			t.Errorf("killed before %s: setting up again left no phrase key: %v", point.before, err)
			return killLeftNothingThatStarts, nil
		}
		if again := setupRecordsOn(point.dir); containsString(again, stateRootSetupMarkName) {
			t.Errorf("killed before %s: setting up again left its setup mark standing beside the identity it made", point.before)
			return killLeftNothingThatStarts, nil
		}
		return killLeftNoIdentity, taken
	}
	if err != nil {
		t.Errorf("killed before %s: the restarted device's identity answers %v", point.before, err)
		return killLeftNothingThatStarts, nil
	}
	// A WHOLE IDENTITY: its phrase key held, as a first device's is, and its self group held once
	// Restore has run
	if !identity.PhraseDevice {
		t.Errorf("killed before %s: the identity came back without its phrase device mark", point.before)
		return killLeftNothingThatStarts, nil
	}
	if _, err := store.PhraseKey(); err != nil {
		t.Errorf("killed before %s: the identity came back as a phrase device with no phrase key: %v", point.before, err)
		return killLeftNothingThatStarts, nil
	}
	if _, err := device.Restore(ctx); err != nil {
		t.Errorf("killed before %s: Restore answered %v", point.before, err)
		return killLeftNothingThatStarts, nil
	}
	if !device.holdsSystemGroup() {
		t.Errorf("killed before %s: the identity came back and Restore holds no self group", point.before)
		return killLeftNothingThatStarts, nil
	}
	return killLeftAWholeIdentity, taken
}

// setupRecordsOn is which of the records a making writes around its commit point -- the phrase key,
// the heads and the setup mark -- stand as files in the store directory under dir, in that order,
// whatever stands beside them.
func setupRecordsOn(dir string) []string {
	standing := []string{}
	for _, name := range []string{stateRootPhraseKeyName, stateRootHeadsName, stateRootSetupMarkName} {
		if info, err := os.Lstat(filepath.Join(dir, stateDataDirName, name)); err == nil && info.Mode().IsRegular() {
			standing = append(standing, name)
		}
	}
	return standing
}

// newKillRestartDevice is newAnsweringDeviceOver with NewDevice's refusal answered rather than fatal,
// so that a kill whose disk no start opens is named by its write.
func newKillRestartDevice(t *testing.T, store mls.StateStore, nonce string) (*Device, error) {
	t.Helper()
	client := &answeringClient{reason: messageprotocol.Reason_REASON_OK, nonce: []byte(nonce)}
	transport, err := sdk.NewMessageTransport(&sdk.MessageTransportConfig{
		Client:          client,
		Server:          connect.NewId(),
		ProtocolVersion: 1,
	})
	if err != nil {
		t.Fatalf("sdk.NewMessageTransport: %v", err)
	}
	t.Cleanup(transport.Close)
	streamStore, err := sdk.OpenStreamStore(t.TempDir())
	if err != nil {
		t.Fatalf("sdk.OpenStreamStore: %v", err)
	}
	t.Cleanup(func() { streamStore.Close() })
	device, err := NewDevice(DeviceConfig{
		PhraseStretch: messagegroup.FastPhraseStretchForTests(),
		Transport:     transport,
		Reserver:      sdk.NewStreamIndexReserver(streamStore),
		StateStore:    store,
		Connect: ConnectPolicy{
			Budget:         30 * time.Second,
			AttemptTimeout: 2 * time.Second,
			FirstBackoff:   200 * time.Millisecond,
			MaxBackoff:     200 * time.Millisecond,
		},
	})
	if err != nil {
		return nil, err
	}
	if err := device.Connect(context.Background()); err != nil {
		device.Close()
		t.Fatalf("Connect: %v", err)
	}
	return device, nil
}

// killPoint is one kill: the write it came before, and the copy of the disk it left.
type killPoint struct {
	before string
	dir    string
}

// killPointStore is a durable store that copies its whole data directory at the call of every write
// of the identity's making, before the write lands.
type killPointStore struct {
	*DurableStateStore
	t      *testing.T
	root   string
	mutex  sync.Mutex
	copies []killPoint
}

func (self *killPointStore) kill(before string) {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	dir := filepath.Join(self.root, fmt.Sprintf("%02d-before-%s", len(self.copies), before))
	copyStateTree(self.t, self.DurableStateStore.dataDir, filepath.Join(dir, stateDataDirName))
	self.copies = append(self.copies, killPoint{before: before, dir: dir})
}

func (self *killPointStore) points() []killPoint {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	return append([]killPoint(nil), self.copies...)
}

func (self *killPointStore) PutSetupMark(identityKey []byte) error {
	self.kill(stateRootSetupMarkName)
	return self.DurableStateStore.PutSetupMark(identityKey)
}

func (self *killPointStore) ClearSetupMark() error {
	self.kill(killBeforeMarkRemoval)
	return self.DurableStateStore.ClearSetupMark()
}

func (self *killPointStore) PutIdentity(record *IdentityRecord) error {
	self.kill(stateRootIdentityName)
	return self.DurableStateStore.PutIdentity(record)
}

func (self *killPointStore) PutIdentityHeads(heads []IdentityHead) error {
	self.kill(stateRootHeadsName)
	return self.DurableStateStore.PutIdentityHeads(heads)
}

func (self *killPointStore) PutPhraseKey(record *PhraseKeyRecord) error {
	self.kill(stateRootPhraseKeyName)
	return self.DurableStateStore.PutPhraseKey(record)
}

func (self *killPointStore) PutGroupState(groupId []byte, epoch uint64, state []byte) error {
	self.kill("group-state")
	return self.DurableStateStore.PutGroupState(groupId, epoch, state)
}

func (self *killPointStore) PutGroupRecord(record *GroupRecord) error {
	self.kill("group-record")
	return self.DurableStateStore.PutGroupRecord(record)
}

// copyStateTree copies a store's data directory, file by file, to a directory of the test's.
func copyStateTree(t *testing.T, from string, to string) {
	t.Helper()
	err := filepath.WalkDir(from, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(from, path)
		if err != nil {
			return err
		}
		target := filepath.Join(to, relative)
		if entry.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		octets, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, octets, 0o600)
	})
	if err != nil {
		t.Fatalf("copying the store's data directory: %v", err)
	}
}

func containsString(values []string, value string) bool {
	for _, one := range values {
		if one == value {
			return true
		}
	}
	return false
}

// digestForTest is what a test prints of a value made from words: its SHA-256's first octets, never
// the value.
func digestForTest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(sum[:8])
}

// CONNECT REBINDS EVERY GROUP THE DEVICE HOLDS, ITS SELF GROUP INCLUDED (LRI R84 item 11; review
// L-4). Groups answers conversations only, so a rebind that walked it moved no system group onto a
// new Hello: the self group's sessions stayed bound to a nonce the server had dropped, and only its
// own lazy rebind, at its next use, would have moved them.
//
// THE CONTROL: the conversation beside it is rebound, and the Hello count moved.
func TestConnectRebindsEveryHeldGroupTheSelfGroupIncluded(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, t.TempDir())
	device := newAnsweringDeviceOver(t, store, []byte("the nonce"))
	words, err := device.CreateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	typed := strings.Join(words, " ")
	clear(words)
	if err := device.ConfirmWords(ctx, typed); err != nil {
		t.Fatalf("ConfirmWords: %v", err)
	}
	conversation, err := device.CreateGroup(ctx, []byte(strings.Repeat("c", GroupIdBytes)))
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	var selfGroup *Group
	device.mutex.Lock()
	for _, group := range device.groups {
		if group.system {
			selfGroup = group
		}
	}
	device.mutex.Unlock()
	if selfGroup == nil {
		t.Fatal("the device holds no self group")
	}
	before := device.transport.NonceEpoch()
	if err := device.Connect(ctx); err != nil {
		t.Fatalf("the second Connect: %v", err)
	}
	after := device.transport.NonceEpoch()
	bound := func(group *Group) uint64 {
		group.mutex.Lock()
		defer group.mutex.Unlock()
		return group.foundingBound
	}
	if before == after || bound(conversation) != after {
		t.Fatalf("CONTROL FAILED: the Hello count went %d -> %d and the conversation is bound at %d", before, after, bound(conversation))
	}
	if got := bound(selfGroup); got != after {
		t.Errorf("after Connect the self group's founding session is bound at Hello %d, and the connection is at %d", got, after)
	}
}

// NEWDEVICE'S REFUSAL ERASES THE SIGNING KEY IT READ (LRI R84 item 12; review L-5), as it erases the
// wrap seed: a device that is never built is never closed, so the refusal is the last place the key
// is held. The store answers the key the start reads, and the test keeps that same array.
//
// THE CONTROL: a start that is not refused hands the key on unerased, and Close erases it.
func TestNewDevicesRefusalErasesTheSigningKeyItRead(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	store, err := OpenDurableStateStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	device := newAnsweringDeviceOver(t, store, []byte("the first process's nonce"))
	words, err := device.CreateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	typed := strings.Join(words, " ")
	clear(words)
	if err := device.ConfirmWords(ctx, typed); err != nil {
		t.Fatalf("ConfirmWords: %v", err)
	}
	device.Close()
	store.Close()

	// THE CONTROL: a start that is not refused keeps the key, and its Close erases it
	reopened, err := OpenDurableStateStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	keeping := &signerKeepingStore{DurableStateStore: reopened}
	started, err := newKillRestartDevice(t, keeping, "the second process's nonce")
	if err != nil {
		t.Fatalf("CONTROL FAILED: the undamaged store does not start: %v", err)
	}
	if allZero(keeping.signer) {
		t.Fatalf("CONTROL FAILED: a start that was not refused erased the key it hands the device")
	}
	started.Close()
	if !allZero(keeping.signer) {
		t.Errorf("CONTROL FAILED: Close did not erase the signing key")
	}
	reopened.Close()

	// THE REFUSAL: the heads are gone from beside the identity record, which no start opens
	if err := os.Remove(filepath.Join(dir, stateDataDirName, stateRootHeadsName)); err != nil {
		t.Fatalf("damaging the store: %v", err)
	}
	damaged, err := OpenDurableStateStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer damaged.Close()
	keeping = &signerKeepingStore{DurableStateStore: damaged}
	if refused, err := newKillRestartDevice(t, keeping, "the third process's nonce"); err == nil {
		refused.Close()
		t.Fatalf("CONTROL FAILED: a store with an identity record and no heads started")
	}
	if len(keeping.signer) == 0 {
		t.Fatalf("CONTROL FAILED: the refused start read no signing key")
	}
	if !allZero(keeping.signer) {
		t.Errorf("NewDevice refused the start and left the signing key it read unerased in the heap")
	}
}

// signerKeepingStore keeps the signing key array the store answers a start with.
type signerKeepingStore struct {
	*DurableStateStore
	signer []byte
}

func (self *signerKeepingStore) GetDeviceIdentity() ([]byte, []byte, []byte, []byte, error) {
	pub, priv, leafKeys, wrapSeed, err := self.DurableStateStore.GetDeviceIdentity()
	self.signer = priv
	return pub, priv, leafKeys, wrapSeed, err
}

func allZero(octets []byte) bool {
	for _, octet := range octets {
		if octet != 0 {
			return false
		}
	}
	return true
}

// THE SWEEP ERASES ONLY ON ITS MARK, BESIDE NO IDENTITY RECORD (LRI R85, R86; erase authority (j)).
// Its premise is read at the erase, so a direct call answers it too:
//   - with no setup mark, nothing is erased, whether the identity record stands or not: an absence
//     alone decides nothing;
//   - a mark beside a standing identity record goes alone, and the records stay;
//   - a mark beside no identity record takes the phrase key, then the heads, then itself;
//   - a mark that does not read as this store's decides nothing;
//   - a stray at a record's name, which is not this store's record, is left standing.
//
// THE CONTROL: the records each sweep must not take are read back whole after it.
func TestTheSetupOrphanSweepErasesOnlyOnItsMarkBesideNoIdentityRecord(t *testing.T) {
	dir := t.TempDir()
	store := openTestStore(t, dir)
	root := filepath.Join(dir, stateDataDirName)
	record := filepath.Join(root, stateRootIdentityName)
	key := bytes.Repeat([]byte{0x11}, ed25519.PublicKeySize)
	putOrphans := func() {
		t.Helper()
		if err := store.PutIdentityHeads([]IdentityHead{{Root: key, Identity: []byte("the root's list")}}); err != nil {
			t.Fatalf("PutIdentityHeads: %v", err)
		}
		if err := store.PutPhraseKey(&PhraseKeyRecord{IdentityKey: key, KeyNumber: 1, Seed: bytes.Repeat([]byte{0x22}, ed25519.SeedSize)}); err != nil {
			t.Fatalf("PutPhraseKey: %v", err)
		}
	}
	bothRead := func(when string) {
		t.Helper()
		if _, err := store.IdentityHeads(); err != nil {
			t.Fatalf("%s the heads read answers %v", when, err)
		}
		if _, err := store.PhraseKey(); err != nil {
			t.Fatalf("%s the phrase key read answers %v", when, err)
		}
	}
	sweep := func(want []string, when string) {
		t.Helper()
		if erased, err := store.SweepIdentityOrphans(); err != nil || !slices.Equal(erased, want) {
			t.Fatalf("%s the sweep erased %v (%v), want %v", when, erased, err, want)
		}
	}
	putOrphans()
	if err := store.PutIdentity(&IdentityRecord{Root: key, CurrentKey: key}); err != nil {
		t.Fatalf("PutIdentity: %v", err)
	}

	// NO MARK: nothing, whether the identity record stands or not
	sweep([]string{}, "with no setup mark, beside a standing identity record,")
	bothRead("CONTROL FAILED: with no setup mark, beside a standing identity record,")
	aside := filepath.Join(t.TempDir(), "quarantined")
	if err := os.Rename(record, aside); err != nil {
		t.Fatalf("moving the identity record away: %v", err)
	}
	if erased, err := store.SweepIdentityOrphans(); err != nil || len(erased) != 0 {
		t.Fatalf("with no setup mark and no identity record the sweep erased %v (%v): an absence alone decided an erase", erased, err)
	}
	bothRead("CONTROL FAILED: with no setup mark and no identity record,")
	if err := os.Rename(aside, record); err != nil {
		t.Fatalf("putting the identity record back: %v", err)
	}

	// A MARK BESIDE A STANDING IDENTITY RECORD: the mark alone
	plantSetupMark(t, store, key)
	sweep([]string{stateRootSetupMarkName}, "with the setup mark beside a standing identity record")
	bothRead("CONTROL FAILED: with the setup mark beside a standing identity record,")
	if _, err := store.Identity(); err != nil {
		t.Fatalf("CONTROL FAILED: the identity record beside the setup mark answers %v", err)
	}

	// A MARK BESIDE NO IDENTITY RECORD: the phrase secret first, then the heads, and the mark last
	plantSetupMark(t, store, key)
	if err := os.Remove(record); err != nil {
		t.Fatalf("removing the identity record: %v", err)
	}
	sweep([]string{stateRootPhraseKeyName, stateRootHeadsName, stateRootSetupMarkName}, "with the setup mark and no identity record")
	if _, err := store.PhraseKey(); !errors.Is(err, ErrStateNotFound) {
		t.Errorf("after the sweep the phrase key read answers %v, want ErrStateNotFound", err)
	}
	if _, err := store.IdentityHeads(); !errors.Is(err, ErrStateNotFound) {
		t.Errorf("after the sweep the heads read answers %v, want ErrStateNotFound", err)
	}
	if regularFileStands(filepath.Join(root, stateRootSetupMarkName)) {
		t.Errorf("after the sweep the setup mark still stands")
	}

	// A MARK THAT DOES NOT READ AS THIS STORE'S decides nothing
	putOrphans()
	if err := os.WriteFile(filepath.Join(root, stateRootSetupMarkName), []byte("not a record this store wrote"), 0o600); err != nil {
		t.Fatalf("planting the false mark: %v", err)
	}
	if erased, err := store.SweepIdentityOrphans(); err == nil || len(erased) != 0 {
		t.Fatalf("with a setup mark that does not read as this store's the sweep erased %v (%v): want nothing, and the refusal", erased, err)
	}
	bothRead("CONTROL FAILED: beside a setup mark that does not read as this store's,")
	if err := os.Remove(filepath.Join(root, stateRootSetupMarkName)); err != nil {
		t.Fatalf("removing the false mark: %v", err)
	}

	// A STRAY: a directory standing at the heads' name is not this store's record, and stays
	if err := os.Remove(filepath.Join(root, stateRootHeadsName)); err != nil {
		t.Fatalf("removing the heads: %v", err)
	}
	stray := filepath.Join(root, stateRootHeadsName)
	if err := os.Mkdir(stray, 0o700); err != nil {
		t.Fatalf("planting the stray: %v", err)
	}
	plantSetupMark(t, store, key)
	sweep([]string{stateRootPhraseKeyName, stateRootSetupMarkName}, "with a stray directory at the heads' name")
	if info, err := os.Lstat(stray); err != nil || !info.IsDir() {
		t.Errorf("the stray directory at the heads' name was taken by the sweep (%v)", err)
	}
}

// AN IDENTITY RECORD MOVED AWAY AND PUT BACK STARTS WHOLE, A SETUP ATTEMPTED MEANWHILE INCLUDED (LRI
// R86, R89 item 1; review D2L-1, L-D1, G-D1). A quarantine that moves the identity record away while
// the app starts leaves the heads and the phrase key beside no identity record and no setup mark. That
// start erases nothing, since an absence alone decides nothing, and it answers that the identity
// cannot be read -- never "no identity", which sends the app to setup. A setup attempted then is
// refused before anything is written, so that once the record is put back the next start opens the
// identity whole, its phrase key included.
//
// THE CONTROL: the making left no setup mark, and the records the away start found are byte for byte
// the ones the making wrote.
func TestAnIdentityRecordMovedAwayAndPutBackStartsWhole(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	store, err := OpenDurableStateStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	device := newAnsweringDeviceOver(t, store, []byte("the first start's nonce"))
	words, err := device.CreateIdentity()
	if err != nil {
		t.Fatalf("CreateIdentity: %v", err)
	}
	typed := strings.Join(words, " ")
	clear(words)
	if err := device.ConfirmWords(ctx, typed); err != nil {
		t.Fatalf("ConfirmWords: %v", err)
	}
	made, err := device.Identity()
	if err != nil {
		t.Fatalf("Identity: %v", err)
	}
	device.Close()
	store.Close()
	whole := []string{stateRootPhraseKeyName, stateRootHeadsName}
	if standing := setupRecordsOn(dir); !slices.Equal(standing, whole) {
		t.Fatalf("CONTROL FAILED: the making left %v, want the phrase key and the heads and no setup mark", standing)
	}

	// THE QUARANTINE: the identity record moved away, and a start
	record := filepath.Join(dir, stateDataDirName, stateRootIdentityName)
	aside := filepath.Join(t.TempDir(), "quarantined")
	if err := os.Rename(record, aside); err != nil {
		t.Fatalf("moving the identity record away: %v", err)
	}
	away, err := OpenDurableStateStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	before := setupRecordDigests(t, dir)
	started, err := newKillRestartDevice(t, away, "the start with the record away")
	if err != nil {
		t.Fatalf("the start with the identity record away refused: %v", err)
	}
	if _, err := started.Identity(); !errors.Is(err, ErrIdentityUnreadable) || errors.Is(err, ErrNoIdentity) {
		t.Fatalf("the start with the identity record away answers %v, want ErrIdentityUnreadable and not ErrNoIdentity: the app would offer setup over a live identity", err)
	}
	if standing := setupRecordsOn(dir); !slices.Equal(standing, whole) {
		t.Errorf("the start with the identity record away and no setup mark left %v of %v: an absence alone decided an erase", standing, whole)
	}
	// THE SETUP ATTEMPT WHILE THE RECORD IS AWAY: refused, and nothing written
	if _, err := started.CreateIdentity(); !errors.Is(err, ErrIdentityUnreadable) {
		t.Errorf("CreateIdentity with the identity record away answers %v, want ErrIdentityUnreadable", err)
	}
	if err := started.ConfirmWords(ctx, typed); !errors.Is(err, ErrIdentityUnreadable) {
		t.Errorf("ConfirmWords with the identity record away answers %v, want ErrIdentityUnreadable", err)
	}
	if _, err := started.Restore(ctx); !errors.Is(err, ErrIdentityUnreadable) {
		t.Errorf("Restore with the identity record away answers %v, want ErrIdentityUnreadable", err)
	}
	if after := setupRecordDigests(t, dir); !slices.Equal(after, before) {
		t.Errorf("with the identity record away the records went from %v to %v: something wrote over a live identity", before, after)
	}
	started.Close()
	away.Close()

	// THE RECORD PUT BACK: the identity starts whole, its phrase key included
	if err := os.Rename(aside, record); err != nil {
		t.Fatalf("putting the identity record back: %v", err)
	}
	back, err := OpenDurableStateStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer back.Close()
	again, err := newKillRestartDevice(t, back, "the start after the record is put back")
	if err != nil {
		t.Fatalf("the start after the identity record is put back refused: %v", err)
	}
	defer again.Close()
	identity, err := again.Identity()
	if err != nil {
		t.Fatalf("after the put-back the identity answers %v", err)
	}
	if identity.AccountId != made.AccountId || !identity.PhraseDevice {
		t.Fatalf("after the put-back the identity is another (the same account: %v; a phrase device: %v)",
			identity.AccountId == made.AccountId, identity.PhraseDevice)
	}
	phraseKey, err := back.PhraseKey()
	if err != nil {
		t.Fatalf("after the put-back the phrase key read answers %v: the phrase device's key was lost", err)
	}
	clear(phraseKey.Seed)
	if _, err := again.Restore(ctx); err != nil || !again.holdsSystemGroup() {
		t.Errorf("after the put-back Restore answers %v and holds a self group: %v", err, again.holdsSystemGroup())
	}
}

// THE ENGINE AN IDENTITY REPLACES ERASES ITS COPY OF THE SIGNING KEY (LRI R85; review L-5's second
// half). A device runs under its own key until its identity is made, and the making then builds its
// engine again under the identity key. The engine it replaces holds a copy of device_sig that nothing
// uses again, and nothing else would erase. The test keeps that copy's own array, read off the engine
// before the making.
//
// THE CONTROL: before the making the array is the device's signing key, and after it the engine that
// replaced it still holds the key it signs with.
func TestTheEngineAnIdentityReplacesErasesItsCopyOfTheSigningKey(t *testing.T) {
	ctx := context.Background()
	device := newAnsweringDeviceOver(t, openTestStore(t, t.TempDir()), []byte("the device's nonce"))
	replaced := device.currentEngine()
	held := engineSignerForTest(t, replaced)
	if allZero(held) || !bytes.Equal(held, device.signer) {
		t.Fatalf("CONTROL FAILED: the engine built at the start does not hold the device's signing key (%d octets)", len(held))
	}
	words, err := device.CreateIdentity()
	if err != nil {
		t.Fatalf("CreateIdentity: %v", err)
	}
	typed := strings.Join(words, " ")
	clear(words)
	if err := device.ConfirmWords(ctx, typed); err != nil {
		t.Fatalf("ConfirmWords: %v", err)
	}
	standing := device.currentEngine()
	if standing == replaced {
		t.Fatal("CONTROL FAILED: the making did not replace the engine")
	}
	if kept := engineSignerForTest(t, standing); allZero(kept) || !bytes.Equal(kept, device.signer) {
		t.Fatalf("CONTROL FAILED: the engine under the identity key does not hold the device's signing key (%d octets)", len(kept))
	}
	if !allZero(held) {
		t.Errorf("the engine the identity replaced still holds its copy of the device's signing key (%d octets)", len(held))
	}
}

// A MAKING NEVER WRITES OVER RECORDS IT DID NOT WRITE (LRI R89 item 1; review D2L-1, G-D1). A device
// starts with no identity, offers its words, and before they are typed back another identity's heads
// and phrase key appear in its folder -- a quarantine giving back what it took, or a copied folder.
// ConfirmWords refuses, with [ErrIdentityUnreadable], and writes nothing: those records are a live
// identity's, and a making replacing them would erase it by rename under no authority.
//
// THE CONTROL: with them gone, the same words make the identity.
func TestAMakingNeverWritesOverRecordsItDidNotWrite(t *testing.T) {
	ctx := context.Background()
	// THE OTHER IDENTITY: its heads and its phrase key, as a making writes them
	other := t.TempDir()
	otherStore := openTestStore(t, other)
	otherDevice := newAnsweringDeviceOver(t, otherStore, []byte("the other identity's nonce"))
	otherWords, err := otherDevice.CreateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	otherTyped := strings.Join(otherWords, " ")
	clear(otherWords)
	if err := otherDevice.ConfirmWords(ctx, otherTyped); err != nil {
		t.Fatalf("the other identity's ConfirmWords: %v", err)
	}
	otherDevice.Close()

	dir := t.TempDir()
	store := openTestStore(t, dir)
	device := newAnsweringDeviceOver(t, store, []byte("this device's nonce"))
	words, err := device.CreateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	typed := strings.Join(words, " ")
	clear(words)
	planted := []string{}
	for _, name := range []string{stateRootPhraseKeyName, stateRootHeadsName} {
		octets, err := os.ReadFile(filepath.Join(other, stateDataDirName, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, stateDataDirName, name), octets, 0o600); err != nil {
			t.Fatal(err)
		}
		planted = append(planted, name)
	}
	before := setupRecordDigests(t, dir)
	if err := device.ConfirmWords(ctx, typed); !errors.Is(err, ErrIdentityUnreadable) {
		t.Fatalf("ConfirmWords over another identity's %v answers %v, want ErrIdentityUnreadable", planted, err)
	}
	if after := setupRecordDigests(t, dir); !slices.Equal(after, before) {
		t.Errorf("the refused making changed the records from %v to %v: it wrote over records it did not write", before, after)
	}
	if _, err := device.Identity(); !errors.Is(err, ErrNoIdentity) {
		t.Errorf("after the refused making the device answers %v, want ErrNoIdentity: nothing was made", err)
	}
	// THE CONTROL: the planted records gone, the same words make the identity
	for _, name := range planted {
		if err := os.Remove(filepath.Join(dir, stateDataDirName, name)); err != nil {
			t.Fatal(err)
		}
	}
	if err := device.ConfirmWords(ctx, typed); err != nil {
		t.Fatalf("CONTROL FAILED: with the planted records gone the same words answer %v", err)
	}
}

// THE SWEEP TAKES ONLY ITS OWN MAKING'S RECORDS (LRI R89 item 2; review D2L-3). A mark names the
// identity key its making was writing. Beside a mark of another key, and no identity record, the heads
// and the phrase key of an identity whose record is away are not that making's: the sweep takes the
// mark alone, and the start answers the identity unreadable.
//
// THE CONTROL: the same records beside a mark of their own key are taken.
func TestTheSweepTakesOnlyTheRecordsOfItsMarksKey(t *testing.T) {
	dir := t.TempDir()
	store := openTestStore(t, dir)
	mine := bytes.Repeat([]byte{0x11}, ed25519.PublicKeySize)
	another := bytes.Repeat([]byte{0x33}, ed25519.PublicKeySize)
	mintDeviceRecord(t, store)
	putOrphansOf(t, store, mine)
	plantSetupMark(t, store, another)
	if erased, err := store.SweepIdentityOrphans(); err != nil || !slices.Equal(erased, []string{stateRootSetupMarkName}) {
		t.Fatalf("beside a mark of another key the sweep erased %v (%v), want the mark alone", erased, err)
	}
	if standing := setupRecordsOn(dir); !slices.Equal(standing, []string{stateRootPhraseKeyName, stateRootHeadsName}) {
		t.Fatalf("beside a mark of another key the sweep left %v, want the phrase key and the heads", standing)
	}
	if standing, err := store.UnexplainedIdentityRecords(); err != nil || len(standing) != 2 {
		t.Errorf("after the sweep the records stand unexplained as %v (%v), want both", standing, err)
	}
	store.Close()
	reopened, err := OpenDurableStateStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	device, err := newKillRestartDevice(t, reopened, "the start after a mark of another key")
	if err != nil {
		t.Fatalf("the start refused: %v", err)
	}
	if _, err := device.Identity(); !errors.Is(err, ErrIdentityUnreadable) {
		t.Errorf("the start after a mark of another key answers %v, want ErrIdentityUnreadable", err)
	}
	device.Close()
	// THE CONTROL: a mark of their own key takes them
	plantSetupMark(t, reopened, mine)
	if erased, err := reopened.SweepIdentityOrphans(); err != nil || len(erased) != 3 {
		t.Errorf("CONTROL FAILED: beside a mark of their own key the sweep erased %v (%v), want all three", erased, err)
	}
}

// A HELD ERASE LEAVES THE MARK, AND THE NEXT START FINISHES THE SWEEP (LRI R89 item 4; review D2L-2,
// G-D2). The phrase key's removal is held -- a handle that does not share delete on Windows, a
// directory without write permission elsewhere, an immutable file for root -- so the sweep stops at
// the phrase secret: the heads and the mark stay, the mark last of all, and once the hold goes the next
// start takes all three.
//
// THE CONTROL: the hold is real, since removing the held file directly fails.
func TestAHeldEraseLeavesTheMarkAndTheNextStartFinishes(t *testing.T) {
	dir := t.TempDir()
	store := openTestStore(t, dir)
	key := bytes.Repeat([]byte{0x11}, ed25519.PublicKeySize)
	mintDeviceRecord(t, store)
	putOrphansOf(t, store, key)
	plantSetupMark(t, store, key)
	phraseKey := filepath.Join(dir, stateDataDirName, stateRootPhraseKeyName)
	release := holdRemoval(t, phraseKey)
	if err := os.Remove(phraseKey); err == nil {
		release()
		t.Fatalf("CONTROL FAILED: the held phrase key was removed directly, so nothing held it")
	}
	erased, err := store.SweepIdentityOrphans()
	if standing := setupRecordsOn(dir); !slices.Equal(standing, []string{stateRootPhraseKeyName, stateRootHeadsName, stateRootSetupMarkName}) {
		t.Errorf("a held erase left %v standing, want the phrase key, the heads and the mark: the sweep went on past the phrase secret, or took the mark first", standing)
	}
	if err == nil {
		t.Errorf("the sweep over a held phrase key answered %v and no error: a held erase must be reported, so the next start tries again", erased)
	}
	release()
	store.Close()
	reopened, err := OpenDurableStateStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	device, err := newKillRestartDevice(t, reopened, "the start after the hold went")
	if err != nil {
		t.Fatalf("the start after the hold refused: %v", err)
	}
	defer device.Close()
	if standing := setupRecordsOn(dir); len(standing) != 0 {
		t.Errorf("the next start left %v standing: the held sweep was never finished", standing)
	}
	if _, err := device.Identity(); !errors.Is(err, ErrNoIdentity) {
		t.Errorf("after the finished sweep the device answers %v, want ErrNoIdentity", err)
	}
}

// A STRAY AT THE PHRASE KEY'S NAME, AND AN IDENTITY RECORD WHOSE STATE CANNOT BE READ, DECIDE NOTHING
// (LRI R89 item 4; review D2L-2). A directory at the phrase key's name is not this store's record: the
// sweep leaves it, and takes the heads and the mark. And where asking whether the identity record
// stands fails for any reason but its absence, the sweep erases nothing at all.
func TestAStrayAtThePhraseKeysNameAndAnUnreadableAbsenceDecideNothing(t *testing.T) {
	dir := t.TempDir()
	store := openTestStore(t, dir)
	key := bytes.Repeat([]byte{0x11}, ed25519.PublicKeySize)
	putOrphansOf(t, store, key)
	plantSetupMark(t, store, key)

	// THE IDENTITY RECORD'S STATE, UNREADABLE: nothing is erased
	record := filepath.Join(dir, stateDataDirName, stateRootIdentityName)
	stateLstat = func(path string) (os.FileInfo, error) {
		if path == record {
			return nil, os.ErrPermission
		}
		return os.Lstat(path)
	}
	erased, err := store.SweepIdentityOrphans()
	stateLstat = os.Lstat
	if err == nil || len(erased) != 0 {
		t.Errorf("where the identity record's state could not be read the sweep erased %v (%v), want nothing and a refusal", erased, err)
	}
	if standing := setupRecordsOn(dir); len(standing) != 3 {
		t.Fatalf("where the identity record's state could not be read %v stand, want all three", standing)
	}

	// A STRAY AT THE PHRASE KEY'S NAME stays
	phraseKey := filepath.Join(dir, stateDataDirName, stateRootPhraseKeyName)
	if err := os.Remove(phraseKey); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(phraseKey, 0o700); err != nil {
		t.Fatal(err)
	}
	if erased, err := store.SweepIdentityOrphans(); err != nil || !slices.Equal(erased, []string{stateRootHeadsName, stateRootSetupMarkName}) {
		t.Errorf("with a stray directory at the phrase key's name the sweep erased %v (%v), want the heads and the mark", erased, err)
	}
	if info, err := os.Lstat(phraseKey); err != nil || !info.IsDir() {
		t.Errorf("the stray directory at the phrase key's name was taken by the sweep (%v)", err)
	}
}

// mintDeviceRecord starts a device over store once, so that its device record stands before any
// identity record is planted beside it, as on every real device.
func mintDeviceRecord(t *testing.T, store *DurableStateStore) {
	t.Helper()
	device, err := newKillRestartDevice(t, store, "the device record's first start")
	if err != nil {
		t.Fatalf("the first start: %v", err)
	}
	device.Close()
}

// putOrphansOf writes the heads and a phrase key of one identity key, as a making does before its
// commit point.
func putOrphansOf(t *testing.T, store *DurableStateStore, key []byte) {
	t.Helper()
	if err := store.PutIdentityHeads([]IdentityHead{{Root: key, Identity: []byte("the root's list")}}); err != nil {
		t.Fatalf("PutIdentityHeads: %v", err)
	}
	if err := store.PutPhraseKey(&PhraseKeyRecord{IdentityKey: key, KeyNumber: 1, Seed: bytes.Repeat([]byte{0x22}, ed25519.SeedSize)}); err != nil {
		t.Fatalf("PutPhraseKey: %v", err)
	}
}

// plantSetupMark writes a setup mark naming key whatever stands, as a making that stopped leaves it:
// PutSetupMark itself refuses beside records it did not write.
func plantSetupMark(t *testing.T, store *DurableStateStore, key []byte) {
	t.Helper()
	store.lock.Lock()
	defer store.lock.Unlock()
	if err := store.writeRecord(store.setupMarkPath(), stateKindSetupMark, key); err != nil {
		t.Fatalf("planting the setup mark: %v", err)
	}
}

// setupRecordDigests is each of the setup's records standing in the store directory under dir, by its
// name and a digest of its octets, never the octets.
func setupRecordDigests(t *testing.T, dir string) []string {
	t.Helper()
	digests := []string{}
	for _, name := range []string{stateRootPhraseKeyName, stateRootHeadsName, stateRootSetupMarkName, stateRootIdentityName} {
		octets, err := os.ReadFile(filepath.Join(dir, stateDataDirName, name))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			t.Fatalf("reading %s: %v", name, err)
		}
		digests = append(digests, name+"="+digestForTest(string(octets)))
	}
	return digests
}

// engineSignerForTest is the signing key array an engine holds. The engine keeps it in a field of its
// own package, so the test reads it by reflection: a test that cannot see the array cannot see it
// erased. A field renamed or retyped fails the test, rather than passing it blind.
func engineSignerForTest(t *testing.T, engine messagegroup.GroupEngine) []byte {
	t.Helper()
	value := reflect.ValueOf(engine)
	if value.Kind() != reflect.Pointer || value.Elem().Kind() != reflect.Struct {
		t.Fatalf("the engine is a %T, not a pointer to a struct this test can read", engine)
	}
	field := value.Elem().FieldByName("signer")
	if !field.IsValid() || field.Kind() != reflect.Slice || field.Type().Elem().Kind() != reflect.Uint8 {
		t.Fatalf("the engine %T keeps no signer array this test can read", engine)
	}
	return field.Bytes()
}
