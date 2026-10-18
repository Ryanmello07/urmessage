package urmessage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
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
	for _, point := range points {
		switch restartFromKill(t, point) {
		case killLeftNoIdentity:
			noIdentity += 1
		case killLeftAWholeIdentity:
			whole += 1
		}
	}
	// THE CONTROL: the folder nothing killed starts, with the identity it made
	untouched := killPoint{before: "nothing", dir: dir}
	kills.DurableStateStore.Close()
	if outcome := restartFromKill(t, untouched); outcome != killLeftAWholeIdentity {
		t.Errorf("CONTROL FAILED: the folder nothing killed did not start with its identity whole")
	}
	if noIdentity == 0 || whole == 0 {
		t.Errorf("CONTROL FAILED: of %d kill(s), %d left no identity and %d a whole one; the kills must reach both",
			len(points), noIdentity, whole)
	}
	t.Logf("%d kill points over the writes %v: %d left no identity, %d a whole identity (account digest %s)",
		len(points), written, noIdentity, whole, digestForTest(made.AccountId))
}

type killOutcome int

const (
	killLeftNothingThatStarts killOutcome = iota
	killLeftNoIdentity
	killLeftAWholeIdentity
)

// restartFromKill opens one kill's disk as the next process opens its directory, and says what it
// holds: no identity, over which setup runs again to an identity that itself restarts whole; or a
// whole identity, its heads naming its own list, its phrase key held, and a self group held once
// Restore has run. Anything else is a failure of the test, named by the write the kill came before.
func restartFromKill(t *testing.T, point killPoint) killOutcome {
	t.Helper()
	ctx := context.Background()
	store, err := OpenDurableStateStore(point.dir)
	if err != nil {
		t.Errorf("killed before %s: the store does not open: %v", point.before, err)
		return killLeftNothingThatStarts
	}
	defer store.Close()
	device, err := newKillRestartDevice(t, store, "the restart after a kill before "+point.before)
	if err != nil {
		t.Errorf("killed before %s: the next start refuses the device: %v", point.before, err)
		return killLeftNothingThatStarts
	}
	defer device.Close()
	identity, err := device.Identity()
	if errors.Is(err, ErrNoIdentity) {
		// SETUP RUNS AGAIN, and its identity stands
		words, err := device.CreateIdentity()
		if err != nil {
			t.Errorf("killed before %s: no identity, and CreateIdentity answers %v", point.before, err)
			return killLeftNothingThatStarts
		}
		typed := strings.Join(words, " ")
		clear(words)
		if err := device.ConfirmWords(ctx, typed); err != nil {
			t.Errorf("killed before %s: no identity, and setting up again answers %v", point.before, err)
			return killLeftNothingThatStarts
		}
		if _, err := device.Identity(); err != nil {
			t.Errorf("killed before %s: setting up again made no identity: %v", point.before, err)
			return killLeftNothingThatStarts
		}
		if _, err := store.PhraseKey(); err != nil {
			t.Errorf("killed before %s: setting up again left no phrase key: %v", point.before, err)
			return killLeftNothingThatStarts
		}
		return killLeftNoIdentity
	}
	if err != nil {
		t.Errorf("killed before %s: the restarted device's identity answers %v", point.before, err)
		return killLeftNothingThatStarts
	}
	// A WHOLE IDENTITY: its phrase key held, as a first device's is, and its self group held once
	// Restore has run
	if !identity.PhraseDevice {
		t.Errorf("killed before %s: the identity came back without its phrase device mark", point.before)
		return killLeftNothingThatStarts
	}
	if _, err := store.PhraseKey(); err != nil {
		t.Errorf("killed before %s: the identity came back as a phrase device with no phrase key: %v", point.before, err)
		return killLeftNothingThatStarts
	}
	if _, err := device.Restore(ctx); err != nil {
		t.Errorf("killed before %s: Restore answered %v", point.before, err)
		return killLeftNothingThatStarts
	}
	if !device.holdsSystemGroup() {
		t.Errorf("killed before %s: the identity came back and Restore holds no self group", point.before)
		return killLeftNothingThatStarts
	}
	return killLeftAWholeIdentity
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
