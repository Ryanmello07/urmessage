package cp3b

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/urnetwork/message/sdk"
	"github.com/urnetwork/message/sdk/urmessage"
)

// freshLeaveStore is a durable store whose reads of one group's epoch states answer, while it is
// armed, the error it is armed with: what a disk says about a group at one moment, changed by the
// case between one call and the next.
type freshLeaveStore struct {
	*urmessage.DurableStateStore
	mutex     sync.Mutex
	groupId   []byte
	failWith  error
	markFails error
}

// armMark makes the leave mark's write fail with markFails, writing nothing, while it is set.
func (self *freshLeaveStore) armMark(markFails error) {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	self.markFails = markFails
}

func (self *freshLeaveStore) MarkGroupForgetting(groupId []byte) error {
	self.mutex.Lock()
	fail := self.markFails
	self.mutex.Unlock()
	if fail != nil {
		return fail
	}
	return self.DurableStateStore.MarkGroupForgetting(groupId)
}

func (self *freshLeaveStore) arm(groupId []byte, failWith error) {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	self.groupId, self.failWith = groupId, failWith
}

func (self *freshLeaveStore) GetGroupState(groupId []byte, epoch uint64) ([]byte, error) {
	self.mutex.Lock()
	fail := self.failWith
	matches := bytes.Equal(groupId, self.groupId)
	self.mutex.Unlock()
	if fail != nil && matches {
		return nil, fail
	}
	return self.DurableStateStore.GetGroupState(groupId, epoch)
}

// freshLeaveRestart is [world.restart] over a [freshLeaveStore]: the previous persona is killed and a
// new device opens the same two directories, through the wrapper.
func (self *world) freshLeaveRestart(t *testing.T, previous *persona) (*persona, *freshLeaveStore) {
	t.Helper()
	name, stateDir, streamDir := previous.name, previous.stateDir, previous.streamDir
	previous.kill()
	client := self.connectClient(t)
	transport := self.transport(t, client)
	streamStore, err := sdk.OpenStreamStore(streamDir)
	if err != nil {
		t.Fatalf("%s: sdk.OpenStreamStore: %v", name, err)
	}
	durable, err := urmessage.OpenDurableStateStore(stateDir)
	if err != nil {
		streamStore.Close()
		t.Fatalf("%s: urmessage.OpenDurableStateStore: %v", name, err)
	}
	wrapper := &freshLeaveStore{DurableStateStore: durable}
	device, err := urmessage.NewDevice(urmessage.DeviceConfig{
		Transport:  transport,
		Reserver:   sdk.NewStreamIndexReserver(streamStore),
		StateStore: wrapper,
	})
	if err != nil {
		durable.Close()
		streamStore.Close()
		t.Fatalf("%s: urmessage.NewDevice: %v", name, err)
	}
	current := &persona{
		name: name, stateDir: stateDir, streamDir: streamDir,
		client: client, transport: transport,
		streamStore: streamStore, stateStore: durable, device: device,
	}
	t.Cleanup(current.kill)
	if err := device.Connect(t.Context()); err != nil {
		t.Fatalf("the restarted %s's Connect: %v", name, err)
	}
	return current, wrapper
}

// freshLeaveRead is an OS error as the durable store wraps one, with this platform's errno for it.
func freshLeaveRead(windows syscall.Errno, other syscall.Errno) error {
	errno := other
	if runtime.GOOS == "windows" {
		errno = windows
	}
	return fmt.Errorf("%w: epoch/0000000000000001 could not be read: %w", urmessage.ErrStateStoreState,
		&os.PathError{Op: "open", Path: "epoch/0000000000000001", Err: errno})
}

// freshLeaveOwner is alice, the OWNER of a group bob is in, restarted over a [freshLeaveStore] and
// connected, not yet restored; and the group's files on her disk, as they were.
func freshLeaveOwner(t *testing.T) (*persona, *freshLeaveStore, []byte, map[string][]byte) {
	t.Helper()
	return freshLeavePair(t, false)
}

// freshLeaveMember is the same pair with BOB restarted that way: a member, not the owner.
func freshLeaveMember(t *testing.T) (*persona, *freshLeaveStore, []byte, map[string][]byte) {
	t.Helper()
	return freshLeavePair(t, true)
}

func freshLeavePair(t *testing.T, member bool) (*persona, *freshLeaveStore, []byte, map[string][]byte) {
	t.Helper()
	world := newWorld(t)
	alice := world.newPersona(t, "alice")
	bob := world.newPersona(t, "bob")
	for _, who := range []*persona{alice, bob} {
		if err := who.device.Connect(t.Context()); err != nil {
			t.Fatalf("%s's Connect: %v", who.name, err)
		}
	}
	groupId := newGroupId(t)
	openPair(t, t.Context(), alice, bob, groupId)
	who := alice
	if member {
		who = bob
	}
	who, wrapper := world.freshLeaveRestart(t, who)
	return who, wrapper, groupId, advGroupFiles(t, who.stateDir, groupId)
}

// freshLeaveUnchanged fails the case if any file of the group changed or went.
func freshLeaveUnchanged(t *testing.T, alice *persona, groupId []byte, before map[string][]byte) {
	t.Helper()
	after := advGroupFiles(t, alice.stateDir, groupId)
	if len(after) != len(before) {
		t.Fatalf("the owner's group's files went %d to %d", len(before), len(after))
	}
	for name, content := range before {
		if !bytes.Equal(after[name], content) {
			t.Errorf("%s of the owner's group changed or went", name)
		}
	}
}

// A STALE NOTE IS NEVER THE REASON FOR AN ERASE (R30). What a Restore saw at startup is not what the
// disk says at the moment of the leave, and the erase without the owner's question is decided on
// the latter. Alice owns a group bob is in. Two startups, each followed by a leave over a disk that
// has changed since:
//   - a PERMISSION refused at startup (the shape a deny ACL has), then a lock at the leave: the leave
//     tries the restore again, meets the lock, and is refused with the not-read-now sentence; then,
//     nothing in the way, the leave's fresh restore brings the group back and asks the owner;
//   - a PROVEN-PERMANENT verdict at startup (a format verdict), so the group IS noted as one that
//     will not come back -- then nothing in the way at the leave: the fresh restore brings it back,
//     and the leave asks the owner's question instead of erasing it on the note.
//
// In every round nothing of the group changes, and after the refused leave alice holds no group, as
// before it: the next Restore hands the group back. THIS CASE WAS CHANGED BY R33's X2, TRUTHFULLY:
// it asserted that the leave's fresh restore left the group live and held, which was the defect.
// THE R9 CONTROL is the next case.
//
// WHAT WOULD GO RED: a leave that decides on the startup note -- measured by the Task 58 writer on a
// runner: a deny ACL at startup, lifted, a lock at the press, and the group was erased -- or a
// classifier that calls a refused permission damage.
func TestAStaleNoteIsNeverTheReasonForAnErase(t *testing.T) {
	ctx := t.Context()
	permission := freshLeaveRead(5, syscall.EACCES)
	held := freshLeaveRead(32, syscall.EAGAIN)
	for _, one := range []struct {
		name    string
		startup error
	}{
		{"a permission refused at startup", permission},
		{"a format verdict at startup", fmt.Errorf("%w: the record's checksum is not the hash of the record", urmessage.ErrStateStoreFormat)},
	} {
		t.Run(one.name, func(t *testing.T) {
			alice, wrapper, groupId, before := freshLeaveOwner(t)
			wrapper.arm(groupId, one.startup)
			restored, err := alice.device.Restore(ctx)
			t.Logf("the startup Restore: %d group(s), %v", len(restored), err)
			if len(restored) != 0 || !errors.Is(err, urmessage.ErrRestore) {
				t.Fatalf("the startup Restore answered %d group(s), %v, want none and ErrRestore", len(restored), err)
			}
			// THE LEAVE, OVER A LOCK
			wrapper.arm(groupId, held)
			err = alice.device.ForgetGroup(groupId)
			t.Logf("the leave over a lock: %v", err)
			if !errors.Is(err, urmessage.ErrGroupRecordNotReadNow) || !strings.Contains(err.Error(), "so nothing was left") {
				t.Errorf("the leave over a lock answered %v, want ErrGroupRecordNotReadNow and that nothing was left", err)
			}
			freshLeaveUnchanged(t, alice, groupId, before)
			// THE LEAVE, NOTHING IN THE WAY
			wrapper.arm(nil, nil)
			err = alice.device.ForgetGroup(groupId)
			t.Logf("the leave with nothing in the way: %v", err)
			if !errors.Is(err, urmessage.ErrOwnerMustTransfer) {
				t.Errorf("the leave with nothing in the way answered %v, want the owner's question", err)
			}
			freshLeaveUnchanged(t, alice, groupId, before)
			if held := len(alice.device.Groups()); held != 0 {
				t.Errorf("after the refused leave alice holds %d group(s), and she held none before it", held)
			}
			if restored, err := alice.device.Restore(ctx); err != nil || len(restored) != 1 {
				t.Errorf("the Restore after the refused leave answered %d group(s), %v, want the group handed back", len(restored), err)
			}
		})
	}
}

// A LEAVE REFUSED AFTER ITS FRESH RESTORE CHANGES NOTHING, WHATEVER REFUSED IT, AND THE NEXT RESTORE
// HANDS THE GROUP BACK (R33's X2). The startup Restore is refused a permission on the group's epoch
// state, so the group is in the not-read set. With nothing in the way any more, the leave tries the
// restore again (R30), which succeeds, and the leave is then refused by each refusal closeToForget
// can give that a test can drive:
//   - alice, the OWNER, is asked the owner's question;
//   - bob, a member, cannot have his leave recorded: the mark's write fails and nothing stands.
//
// Either way that refusal changed nothing: the device holds no group after it, as it held none
// before it, no file of the group changed, and the next Restore hands the group back, live.
//
// WHAT WOULD GO RED: the fresh restore's group HELD by the leave, which a refusal then leaves in the
// map -- measured by the round-3 review: held 0 -> 1, and the next Restore handed back nothing,
// because it skips a group already held, while the export says a refused leave changed nothing.
func TestALeaveRefusedAfterItsFreshRestoreChangesNothingAndRestoreHandsTheGroupBack(t *testing.T) {
	ctx := t.Context()
	for _, one := range []struct {
		name   string
		member bool
		want   string
	}{
		{"the owner's question", false, "hand it over first"},
		{"a leave that could not be recorded", true, "the leave could not be recorded on the disk, so nothing was left"},
	} {
		t.Run(one.name, func(t *testing.T) {
			who, wrapper, groupId, before := freshLeavePair(t, one.member)
			wrapper.arm(groupId, freshLeaveRead(5, syscall.EACCES))
			restored, err := who.device.Restore(ctx)
			if len(restored) != 0 || !errors.Is(err, urmessage.ErrGroupReadUnproven) {
				t.Fatalf("CONTROL FAILED: the startup Restore answered %d group(s), %v, want none and ErrGroupReadUnproven", len(restored), err)
			}
			wrapper.arm(nil, nil)
			if one.member {
				wrapper.armMark(errors.New("the store this case sits on refused the leave mark"))
			}
			err = who.device.ForgetGroup(groupId)
			t.Logf("the leave after the fresh restore: %v", err)
			if err == nil || !strings.Contains(err.Error(), one.want) {
				t.Fatalf("the leave answered %v, want the refusal %q", err, one.want)
			}
			if held := len(who.device.Groups()); held != 0 {
				t.Errorf("after the refused leave the device holds %d group(s), and it held none before it", held)
			}
			freshLeaveUnchanged(t, who, groupId, before)
			wrapper.armMark(nil)
			restored, err = who.device.Restore(ctx)
			if err != nil || len(restored) != 1 {
				t.Fatalf("the Restore after the refused leave answered %d group(s), %v, want the group handed back", len(restored), err)
			}
			if held := who.device.Groups(); len(held) != 1 || held[0] != restored[0] {
				t.Errorf("after that Restore the device holds %d group(s), want the one it handed back", len(held))
			}
		})
	}
}

// A FRESH PROVEN-PERMANENT VERDICT AT THE LEAVE STILL LEAVES THE GROUP (R30's R9 control). The same
// owner, the same startup note -- a format verdict -- and the same verdict again when the leave
// tries the restore: the leave goes through without the owner's question, as R9 rules for a group
// this build can never read, and the group's directory goes.
//
// WHAT WOULD GO RED: a fresh attempt that never leaves anything, and a group that will never read
// can never be left, restored or joined again.
func TestAFreshProvenPermanentVerdictAtTheLeaveStillLeavesTheGroup(t *testing.T) {
	ctx := t.Context()
	alice, wrapper, groupId, _ := freshLeaveOwner(t)
	verdict := fmt.Errorf("%w: the record's checksum is not the hash of the record", urmessage.ErrStateStoreFormat)
	wrapper.arm(groupId, verdict)
	if restored, err := alice.device.Restore(ctx); len(restored) != 0 || !errors.Is(err, urmessage.ErrRestore) {
		t.Fatalf("the startup Restore answered %d group(s), %v, want none and ErrRestore", len(restored), err)
	}
	if err := alice.device.ForgetGroup(groupId); err != nil {
		t.Fatalf("the leave over a fresh proven-permanent verdict answered %v, want the group left", err)
	}
	if after := advGroupFiles(t, alice.stateDir, groupId); len(after) != 0 {
		t.Errorf("the group still has %d file(s) on the disk after it was left", len(after))
	}
}
