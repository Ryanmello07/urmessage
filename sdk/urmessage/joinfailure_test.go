package urmessage

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"
)

// A JOIN THAT FAILED AFTER ITS COMMIT IS CLOSED AS A GROUP, AND ITS TABLE IS ERASED (Task 57, F6).
// [Device.abandonJoined] is the one exit both of Join's failures past the commit take. It is handed
// a joined group here and must leave it closed, with no entry in its pq_secret table and the
// octets of the one it held overwritten, and with the joined epoch's state gone from the store.
//
// WHAT WOULD GO RED: close the session and the handle and not the group, and the group's own copy
// of the join epoch's pq_secret stays in the heap, never erased.
func TestAJoinAbandonedAfterItsCommitIsClosedWithItsTableErased(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStateStore()
	joiner := newAnsweringDeviceOver(t, store, []byte("the joiner's nonce"))
	honest, groupId := windowInvite(t, joiner)
	group, err := joiner.Join(ctx, honest)
	if err != nil {
		t.Fatalf("the honest join: %v", err)
	}
	group.mutex.Lock()
	held := group.pqSecrets[group.epoch]
	epoch := group.epoch
	group.mutex.Unlock()
	if len(held) == 0 || bytes.Equal(held, make([]byte, len(held))) {
		t.Fatalf("CONTROL FAILED: the joined group holds no pq_secret for its epoch")
	}
	if _, err := store.GetGroupState(groupId, epoch); err != nil {
		t.Fatalf("CONTROL FAILED: the store holds no state for the joined epoch: %v", err)
	}
	joiner.drop(groupId, group)

	cause := errors.New("the cause this test hands over")
	if err := joiner.abandonJoined(group, false, cause); !errors.Is(err, cause) {
		t.Errorf("abandonJoined answered %v, want the cause it was handed", err)
	}
	group.mutex.Lock()
	closed, left := group.closed, len(group.pqSecrets)
	group.mutex.Unlock()
	if !closed {
		t.Errorf("the abandoned group is not closed")
	}
	if left != 0 {
		t.Errorf("the abandoned group's pq_secret table still holds %d entry(ies)", left)
	}
	if !bytes.Equal(held, make([]byte, len(held))) {
		t.Errorf("the abandoned group's pq_secret was dropped without being erased: its octets are still there")
	}
	if _, err := store.GetGroupState(groupId, epoch); !errors.Is(err, ErrStateNotFound) {
		t.Errorf("the joined epoch's state is still in the store: %v", err)
	}
}

// holdBlockingStore is a durable store that, once armed, files a group of its own under the id of
// the record it has just written, as an admission that ran past the admission mutex would. That
// makes [Device.holdReplacing] refuse, after the join's commit and its record.
type holdBlockingStore struct {
	*DurableStateStore
	device *Device
	armed  bool
}

func (self *holdBlockingStore) PutGroupRecord(record *GroupRecord) error {
	if err := self.DurableStateStore.PutGroupRecord(record); err != nil {
		return err
	}
	if self.armed {
		self.device.mutex.Lock()
		self.device.groups[string(record.GroupId)] = &Group{id: append([]byte(nil), record.GroupId...), closed: true}
		self.device.mutex.Unlock()
	}
	return nil
}

// A HOLD REFUSED AFTER THE COMMIT SAYS THE JOIN CODE IS SPENT (Task 57, F6). The refusal comes
// after the join code was taken and the state committed, so the one sentence that is true of it is
// [ErrJoinCodeSpent]'s; and nothing of the join is left in the store.
//
// WHAT WOULD GO RED: answer the hold's refusal bare, and an app has no sentence that tells a
// person the join code is gone.
func TestAHoldRefusedAfterTheCommitSaysTheJoinCodeIsSpent(t *testing.T) {
	ctx := context.Background()
	store := &holdBlockingStore{DurableStateStore: openTestStore(t, t.TempDir())}
	joiner := newAnsweringDeviceOver(t, store, []byte("the joiner's nonce"))
	store.device = joiner
	honest, groupId := windowInvite(t, joiner)
	store.armed = true
	_, err := joiner.Join(ctx, honest)
	if !errors.Is(err, ErrGroupAlreadyHeld) {
		t.Fatalf("CONTROL FAILED: the join answered %v, so the hold did not refuse", err)
	}
	if !errors.Is(err, ErrJoinCodeSpent) || errors.Is(err, ErrJoinRefused) {
		t.Errorf("a hold refused after the commit answered %v, want ErrJoinCodeSpent and not ErrJoinRefused", err)
	}
	if _, err := store.GetGroupState(groupId, 1); !errors.Is(err, ErrStateNotFound) {
		t.Errorf("the joined epoch's state is still in the store: %v", err)
	}
}

// A LEAVE WAITS FOR AN ADMISSION IN PROGRESS (Task 57, F6). ForgetGroup takes the admission mutex,
// so a leave cannot run between a Join's commit and its hold, or between a Restore's question and
// its answer. The mutex is held here as an admission would hold it, and the leave must not answer
// until it is released.
//
// WHAT WOULD GO RED: a ForgetGroup outside the mutex, which answers at once.
func TestForgetGroupWaitsForAnAdmissionInProgress(t *testing.T) {
	device := newAnsweringDeviceOver(t, NewMemoryStateStore(), []byte("the device's nonce"))
	device.admitMutex.Lock()
	answered := make(chan error, 1)
	go func() { answered <- device.ForgetGroup(bytes.Repeat([]byte{0x71}, GroupIdBytes)) }()
	select {
	case err := <-answered:
		device.admitMutex.Unlock()
		t.Fatalf("the leave answered %v while an admission held the mutex", err)
	case <-time.After(300 * time.Millisecond):
	}
	device.admitMutex.Unlock()
	select {
	case err := <-answered:
		if !errors.Is(err, ErrGroupNotHeld) {
			t.Errorf("the leave, once the admission finished, answered %v, want ErrGroupNotHeld", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("the leave did not answer after the admission released the mutex")
	}
}
