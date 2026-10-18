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
// heads and the phrase key first and the identity record last, each atomically, and the record a
// start reads first is the identity record. So a process killed anywhere in the making leaves one of
// two disks: no identity, over which setup runs again, or a whole identity -- its heads, its phrase
// key, and a self group founded again at start if its founding did not finish (R76 item 2).
//
// THE KILL IS A COPY. killPointStore copies the store's whole data directory at the call of every
// write the making makes, before the write lands, which is the disk a process killed at that instant
// leaves behind. Every copy is then opened as the next process opens its directory, and every one
// must start.
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
	for _, write := range []string{stateRootHeadsName, stateRootPhraseKeyName, stateRootIdentityName, "group-record"} {
		if !containsString(written, write) {
			t.Fatalf("the making wrote %v, and no %s: the kill points do not cover the making", written, write)
		}
	}
	device.Close()

	noIdentity, whole := 0, 0
	sweptBy := map[string][]string{}
	for _, point := range points {
		outcome, swept := restartFromKill(t, point)
		switch outcome {
		case killLeftNoIdentity:
			noIdentity += 1
			sweptBy[point.before] = swept
		case killLeftAWholeIdentity:
			whole += 1
		}
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
	// THE SWEEP'S CONTROL (LRI R85): the kill just before the identity record left the phrase key and
	// the heads standing beside no identity record, and the start that followed erased both, so the
	// sweep's assertion in restartFromKill was not held over a disk with nothing to sweep
	if swept := sweptBy[stateRootIdentityName]; len(swept) != 2 {
		t.Errorf("CONTROL FAILED: the kill before the identity record left %v of the heads and the phrase key to sweep, want both", swept)
	}
	t.Logf("%d kill points over the writes %v: %d left no identity, %d a whole identity; swept at each start with no identity: %v (account digest %s)",
		len(points), written, noIdentity, whole, sweptBy, digestForTest(made.AccountId))
}

type killOutcome int

const (
	killLeftNothingThatStarts killOutcome = iota
	killLeftNoIdentity
	killLeftAWholeIdentity
)

// restartFromKill opens one kill's disk as the next process opens its directory, and says what it
// holds: no identity, its setup's orphans swept by the start, over which setup runs again to an
// identity that itself restarts whole; or a whole identity, its heads naming its own list, its phrase
// key held, and a self group held once Restore has run. Anything else is a failure of the test, named
// by the write the kill came before. With no identity, it also answers the orphans the start swept:
// those of the heads and the phrase key that stood on the kill's disk.
func restartFromKill(t *testing.T, point killPoint) (killOutcome, []string) {
	t.Helper()
	ctx := context.Background()
	stood := setupOrphansOn(point.dir)
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
	identity, err := device.Identity()
	if errors.Is(err, ErrNoIdentity) {
		// A SETUP'S ORPHANS ARE SWEPT BY THE START (LRI R85; erase authority (j)): whatever of the
		// heads and the phrase key the kill left beside no identity record is gone, from the disk and
		// from the store's reads, before setup runs again
		if left := setupOrphansOn(point.dir); len(left) != 0 {
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
		return killLeftNoIdentity, stood
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
	return killLeftAWholeIdentity, nil
}

// setupOrphansOn is which of the two records a setup writes before its commit point -- the phrase key
// and the heads -- stand as files in the store directory under dir, whatever stands beside them.
func setupOrphansOn(dir string) []string {
	standing := []string{}
	for _, name := range []string{stateRootPhraseKeyName, stateRootHeadsName} {
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

// THE SWEEP ERASES ONLY BESIDE NO IDENTITY RECORD (LRI R85; erase authority (j)). Its premise is read
// at the erase, so a direct call answers it too: a store whose identity record stands erases nothing,
// since its heads and its phrase key are a whole identity's; the same store with its identity record
// gone erases both, the phrase secret first. A stray at a record's name, which is not this store's
// record, is left standing.
//
// THE CONTROL: the records the first sweep must not take are read back whole after it.
func TestTheSetupOrphanSweepErasesOnlyBesideNoIdentityRecord(t *testing.T) {
	dir := t.TempDir()
	store := openTestStore(t, dir)
	key := bytes.Repeat([]byte{0x11}, ed25519.PublicKeySize)
	if err := store.PutIdentityHeads([]IdentityHead{{Root: key, Identity: []byte("the root's list")}}); err != nil {
		t.Fatalf("PutIdentityHeads: %v", err)
	}
	if err := store.PutPhraseKey(&PhraseKeyRecord{IdentityKey: key, KeyNumber: 1, Seed: bytes.Repeat([]byte{0x22}, ed25519.SeedSize)}); err != nil {
		t.Fatalf("PutPhraseKey: %v", err)
	}
	if err := store.PutIdentity(&IdentityRecord{Root: key, CurrentKey: key}); err != nil {
		t.Fatalf("PutIdentity: %v", err)
	}
	if erased, err := store.SweepIdentityOrphans(); err != nil || len(erased) != 0 {
		t.Errorf("beside a standing identity record the sweep erased %v (%v): a whole identity's records are no orphans", erased, err)
	}
	if _, err := store.IdentityHeads(); err != nil {
		t.Fatalf("CONTROL FAILED: beside a standing identity record the heads read answers %v", err)
	}
	if _, err := store.PhraseKey(); err != nil {
		t.Fatalf("CONTROL FAILED: beside a standing identity record the phrase key read answers %v", err)
	}

	// THE IDENTITY RECORD GONE: what stands beside no identity record is a setup's orphans
	if err := os.Remove(filepath.Join(dir, stateDataDirName, stateRootIdentityName)); err != nil {
		t.Fatalf("removing the identity record: %v", err)
	}
	erased, err := store.SweepIdentityOrphans()
	if err != nil || !slices.Equal(erased, []string{stateRootPhraseKeyName, stateRootHeadsName}) {
		t.Fatalf("beside no identity record the sweep erased %v (%v), want the phrase key and then the heads", erased, err)
	}
	if _, err := store.PhraseKey(); !errors.Is(err, ErrStateNotFound) {
		t.Errorf("after the sweep the phrase key read answers %v, want ErrStateNotFound", err)
	}
	if _, err := store.IdentityHeads(); !errors.Is(err, ErrStateNotFound) {
		t.Errorf("after the sweep the heads read answers %v, want ErrStateNotFound", err)
	}

	// A STRAY: a directory standing at the heads' name is not this store's record, and stays
	stray := filepath.Join(dir, stateDataDirName, stateRootHeadsName)
	if err := os.Mkdir(stray, 0o700); err != nil {
		t.Fatalf("planting the stray: %v", err)
	}
	if erased, err := store.SweepIdentityOrphans(); err != nil || len(erased) != 0 {
		t.Errorf("with a stray directory at the heads' name the sweep erased %v (%v): want nothing", erased, err)
	}
	if info, err := os.Lstat(stray); err != nil || !info.IsDir() {
		t.Errorf("the stray directory at the heads' name was taken by the sweep (%v)", err)
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
