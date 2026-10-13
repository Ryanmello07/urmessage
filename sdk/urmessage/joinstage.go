package urmessage

import (
	"bytes"
	"errors"
	"fmt"
	"sync"

	"github.com/urnetwork/message/mls"
)

// joinStage is the [mls.StateStore] a device's engine is built over: the device's own store, with
// ONE JOIN AT A TIME held in memory until this package has finished judging it.
//
// WHY A JOIN IS STAGED. mls persists the epoch it joined as the last statement of the join, and
// the engine takes the join code's private halves out of the store before that, so by the time
// [Device.Join] holds a group to judge, the state is on the disk and the join code is spent. Two
// defects followed, both measured in sdk/cp3b before this file existed. An invite refused after
// that point had cost the device its join code, and the honest invite that followed could not be
// opened. And an invite into a group the device ALREADY HELD had replaced that group's epoch state
// before anything could refuse it.
//
// WHAT IT DOES. Between begin and commit, the epoch state the engine writes for the group being
// joined is kept here and does not reach the store, and the key package the engine took is
// remembered. commit writes the state CREATE-ONLY: a store that already holds a state for that
// group and epoch is left as it is, and the commit is refused. abort erases the staged state and
// puts the key package back, so a refused join leaves the store exactly as it was. Outside a join,
// and for every other group during one, every method is the device's store, call for call.
//
// THE GROUP ID IS THE ONE [Device.Join] WAS HANDED IN THE INVITE, and the engine's
// JoinFromWelcomeInto has already refused a Welcome that describes any other group, so a write for
// this id during the join is the join's own: the device holds no live group under it (the
// held-group gate), and a group a commit removed it from is closed and writes nothing.
type joinStage struct {
	store mls.StateStore

	mutex   sync.Mutex
	joining bool
	groupId []byte

	held        bool
	stagedEpoch uint64
	state       []byte

	taken        bool
	takenRef     []byte
	takenPackage []byte
	takenInit    []byte
	takenEncrypt []byte
}

var _ mls.StateStore = (*joinStage)(nil)

func newJoinStage(store mls.StateStore) *joinStage {
	return &joinStage{store: store}
}

// begin opens the stage for one join. A second begin before the first has committed or aborted is
// refused: [Device.Join] holds [Device.admitMutex] across the whole of a join, so a second one is a
// caller that is not inside it.
func (self *joinStage) begin(groupId []byte) error {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	if self.joining {
		return fmt.Errorf("urmessage: a join into group %x is still staged, and a device stages one join at a time", self.groupId)
	}
	self.joining = true
	self.groupId = append([]byte(nil), groupId...)
	return nil
}

// commit writes the staged epoch state into the device's store, CREATE-ONLY, and closes the stage.
//
// THE PROBE READS NOTHING AND ERASES NOTHING. What GetGroupState answers is the STORE'S OWN ARRAY,
// which is [mls.StateStore]'s contract, so the answer is dropped unread: a probe that wiped it
// would destroy the held group's state in the act of deciding to leave it alone.
//
// ONLY [ErrStateNotFound] IS READ AS "NOTHING THERE". Every store this package ships answers that
// sentinel for an absent state, and the walk already depends on it. Any other answer, a state or a
// failed read alike, refuses the commit: a store that cannot say whether it holds this group is
// not written over.
func (self *joinStage) commit() error {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	if !self.joining || !self.held {
		return fmt.Errorf("urmessage: no join is staged, or the engine wrote no epoch state for it")
	}
	_, err := self.store.GetGroupState(self.groupId, self.stagedEpoch)
	if err == nil {
		return fmt.Errorf("%w: group %x epoch %d", ErrJoinWouldOverwrite, self.groupId, self.stagedEpoch)
	}
	if !errors.Is(err, ErrStateNotFound) {
		return fmt.Errorf("%w: whether group %x epoch %d is already held could not be read: %w",
			ErrJoinWouldOverwrite, self.groupId, self.stagedEpoch, err)
	}
	if err := self.store.PutGroupState(self.groupId, self.stagedEpoch, self.state); err != nil {
		return err
	}
	self.closeLocked()
	return nil
}

// abort erases the staged state, puts back the key package the engine took, and closes the stage.
// It is safe after a commit and after an engine refusal, where it finds nothing to do: the engine
// puts the key package back itself on its own refusals, and PutKeyPackage below sees that.
func (self *joinStage) abort() error {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	if !self.joining {
		return nil
	}
	var err error
	if self.taken {
		err = self.store.PutKeyPackage(self.takenRef, self.takenPackage, self.takenInit, self.takenEncrypt)
	}
	self.closeLocked()
	return err
}

// closeLocked erases everything the stage holds and ends the join.
func (self *joinStage) closeLocked() {
	zeroizeState(self.state)
	zeroizeState(self.takenInit)
	zeroizeState(self.takenEncrypt)
	self.state, self.groupId = nil, nil
	self.takenRef, self.takenPackage, self.takenInit, self.takenEncrypt = nil, nil, nil, nil
	self.joining, self.held, self.taken = false, false, false
}

// staging reports whether a write for this group belongs to the join in progress.
func (self *joinStage) stagingLocked(groupId []byte) bool {
	return self.joining && bytes.Equal(groupId, self.groupId)
}

func (self *joinStage) PutGroupState(groupId []byte, epoch uint64, state []byte) error {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	if !self.stagingLocked(groupId) {
		return self.store.PutGroupState(groupId, epoch, state)
	}
	if self.held && epoch != self.stagedEpoch {
		return fmt.Errorf("urmessage: the join into group %x staged epoch %d and then wrote epoch %d", groupId, self.stagedEpoch, epoch)
	}
	// COPIED: mls erases the buffer it handed over as soon as this returns
	zeroizeState(self.state)
	self.state = append([]byte(nil), state...)
	self.stagedEpoch = epoch
	self.held = true
	return nil
}

func (self *joinStage) GetGroupState(groupId []byte, epoch uint64) ([]byte, error) {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	if self.stagingLocked(groupId) && self.held && epoch == self.stagedEpoch {
		return append([]byte(nil), self.state...), nil
	}
	return self.store.GetGroupState(groupId, epoch)
}

// DeleteGroupStateBefore does nothing for the group being joined: nothing of the join is in the
// store yet, and what IS there under that id is not the join's to delete.
func (self *joinStage) DeleteGroupStateBefore(groupId []byte, epoch uint64) error {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	if self.stagingLocked(groupId) {
		return nil
	}
	return self.store.DeleteGroupStateBefore(groupId, epoch)
}

func (self *joinStage) PutPrivateKey(pub []byte, priv []byte) error {
	return self.store.PutPrivateKey(pub, priv)
}

func (self *joinStage) GetPrivateKey(pub []byte) ([]byte, error) {
	return self.store.GetPrivateKey(pub)
}

func (self *joinStage) DeletePrivateKey(pub []byte) error {
	return self.store.DeletePrivateKey(pub)
}

// PutKeyPackage forwards, and forgets the key package this join took when it is the one being put
// back: the engine does that itself on every refusal of its own.
func (self *joinStage) PutKeyPackage(ref []byte, kp []byte, initPriv []byte, encPriv []byte) error {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	if err := self.store.PutKeyPackage(ref, kp, initPriv, encPriv); err != nil {
		return err
	}
	if self.joining && self.taken && bytes.Equal(ref, self.takenRef) {
		zeroizeState(self.takenInit)
		zeroizeState(self.takenEncrypt)
		self.takenRef, self.takenPackage, self.takenInit, self.takenEncrypt = nil, nil, nil, nil
		self.taken = false
	}
	return nil
}

// TakeKeyPackage forwards, and during a join REMEMBERS what was taken, as copies, so that a refusal
// this package makes after the engine has joined can put the join code back.
func (self *joinStage) TakeKeyPackage(ref []byte) ([]byte, []byte, []byte, error) {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	kp, initPriv, encPriv, err := self.store.TakeKeyPackage(ref)
	if err != nil || !self.joining {
		return kp, initPriv, encPriv, err
	}
	zeroizeState(self.takenInit)
	zeroizeState(self.takenEncrypt)
	self.takenRef = append([]byte(nil), ref...)
	self.takenPackage = append([]byte(nil), kp...)
	self.takenInit = append([]byte(nil), initPriv...)
	self.takenEncrypt = append([]byte(nil), encPriv...)
	self.taken = true
	return kp, initPriv, encPriv, nil
}
