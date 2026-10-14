package urmessage

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/urnetwork/message/mls"
)

// ForgetGroup is THIS DEVICE'S HALF OF LEAVING A GROUP, and it is the only half a device can do by
// itself. The other half, taking its leaf out of the tree, is a [Group.RemoveMember] some admin or
// the owner makes: no identity's last leaf ever leaves in its own commit (msgrepo ledger 257, ruling
// 48, which also makes a leave PRODUCT SURFACE and not an MLS proposal). The owner's ruling of
// 2026-10-02 asked for "one party can just locally delete and leave"; this is that, built as ledger
// item 273 decided it.
//
// WHAT IT ERASES, IN THIS ORDER. A durable mark goes down first, saying this group is being left.
// Then the group is closed, which erases its pq_secret table and its staged wrap candidates and
// closes the MLS session; from then on every call that reaches the server or the disk refuses, and
// nothing it does writes the disk (Messages, Epoch and Stats still answer, from memory). Then it
// leaves this device's map, so [Device.Groups] stops naming it. Then
// [DeviceStore.DeleteGroupRecord] takes every epoch state (this device's leaf private key and its
// whole path-secret ladder), every copy of a line this device sent (its own plaintext), the
// peer-head table, the group's record, and the mark last.
//
// AN ERASE THAT STOPS PART WAY IS FINISHED, NOT LOST (msgrepo ledger §7, 2026-10-03, review H1). A
// file another process holds open, or a crash, can stop it after the epoch states are gone, and
// without the mark that group could be neither restored nor named again. With it, ForgetGroup
// answers [ErrForgetUnfinished] -- the device HAS left -- and calling it again, or the next
// [Device.Restore], finishes the erase. A group being left is never restored.
//
// WHAT IT DOES NOT DO, and a caller that says otherwise to a person is overclaiming:
//   - it tells nobody. There is no content kind for "left", so the others go on seeing this device
//     as a member, and go on sealing to its leaf, until somebody removes it;
//   - it does not remove the leaf, so until somebody does, this identity cannot be added back (R6a
//     refuses to add an identity while any leaf of the tree carries it). An admin is removed only by
//     the owner, and an owner's leaf by nobody;
//   - it does not touch the server's ciphertext or anybody else's copy, and there is no Unsubscribe,
//     so the server may go on announcing the group to this connection;
//   - it keeps the stream-index reservations, which are not secret, because a reserver that never
//     rewinds is the one that never reuses a nonce if this device is ever added back.
//
// AN OWNER IS REFUSED, by [ErrOwnerMustTransfer], when this device is its identity's last leaf and
// somebody else is in the group: nobody removes an owner's leaf (ruling 11), so leaving would strand
// every other member with an owner who is gone for good, and could never be removed or added back.
// MASTER §11: "the leave action is refused for an OWNER until ownership has been transferred". An
// owner alone, or one with another device of its own still in the group, strands nobody and may go.
// A refusal changes nothing: no mark, no close, no file.
//
// A GROUP THE LAST RESTORE COULD NOT BRING BACK IS LEFT TOO, and it is the one group this call
// leaves without holding it. Its record is on the disk, so [Device.Join] refuses an invite into it
// ([ErrGroupAlreadyHeld], whose own sentence sends the caller here); its state does not load, so
// it can never be held; and until this paragraph such a group could be neither restored, left nor
// joined again. It is marked and erased like any other. THE OWNER'S REFUSAL IS NOT ASKED OF IT,
// because it cannot be: the roster is read off a live group and this one has none, and a device
// that cannot load a group's state strands nobody by erasing it that it had not already. A group
// on the disk that no Restore has tried is NOT left this way: it answers [ErrGroupNotRestored],
// so that a device that has merely restarted is asked the owner's question like any other.
//
// AND SO IS A GROUP WHOSE RECORD DOES NOT READ ([ErrGroupRecordDamaged]), with no Restore having
// to try first: the read this call makes of that one record IS the attempt, a record that does
// not read never restores, and the reasoning above holds of it word for word. Without this, the
// gate's refusal of an invite into such a group named a remedy that failed for the gate's own
// reason, and the group could be neither restored, left nor joined again.
//
// A RECORD WHOSE FILE COULD NOT BE READ AT ALL IS NOT ONE THAT DOES NOT READ (Task 57, F1). A file
// another process holds, or an I/O error, is no finding about the record, so it is the store
// failing to answer, and that is refused before anything is written: "whether this device holds
// group %x on its disk could not be read, so nothing was left". The damage rule above is for
// PERMANENT damage only. Read as damage, one lock at the moment of the leave erased an owner's
// group with others in it, without the owner's question; refused, the same leave asked again once
// the file reads is asked it.
//
// IT IS AN ADMISSION'S PEER, UNDER [Device.admitMutex] (Task 57, F6). A Join, a CreateGroup or a
// Restore of the same group on another goroutine waits for the leave, and the leave for it: a Join
// between this call's map drop and its erase would build a group the erase then deletes under it,
// and a leave between a Join's commit and its hold made that hold refuse after the join code was
// spent. The mutex covers local work only, as for the admissions.
func (self *Device) ForgetGroup(groupId []byte) error {
	self.admitMutex.Lock()
	defer self.admitMutex.Unlock()
	store, durable := self.stateStore.(DeviceStore)
	self.mutex.Lock()
	group, held := self.groups[string(groupId)]
	self.mutex.Unlock()

	// A LEAVE ALREADY UNDER WAY is finished whatever state it stopped in: closed or not, held or
	// not. The owner question was asked when the mark went down, and is not asked again of a group
	// whose keys may already be gone.
	if durable {
		marked, err := store.GroupBeingForgotten(groupId)
		if err != nil {
			return err
		}
		if marked {
			if held {
				group.Close()
				self.drop(groupId, group)
			}
			if err := store.DeleteGroupRecord(groupId); err != nil {
				return fmt.Errorf("%w: %w", ErrForgetUnfinished, err)
			}
			return nil
		}
	}
	if !held {
		if durable {
			onDisk, reads, err := recordOnDisk(store, groupId)
			if err != nil {
				return err
			}
			if onDisk && (!reads || self.didNotRestore(groupId)) {
				return self.forgetUnrestored(store, groupId)
			}
			if onDisk {
				return fmt.Errorf("%w: %x", ErrGroupNotRestored, groupId)
			}
		}
		return fmt.Errorf("%w: %x", ErrGroupNotHeld, groupId)
	}

	mark := func() error {
		if !durable {
			return nil
		}
		return store.MarkGroupForgetting(groupId)
	}
	stands := func() bool {
		if !durable {
			return false
		}
		marked, err := store.GroupBeingForgotten(groupId)
		return err == nil && marked
	}
	closed, err := group.closeToForget(mark, stands)
	if !closed {
		return err
	}
	// FROM HERE THIS DEVICE HAS LEFT. A close that reported an error still closed the group and
	// still erased its secrets in memory ([Group.closeLocked] is unconditional about both), so the
	// leave goes on, and that error is not the leave's: the device did leave. On a store that is not
	// durable there is nothing on the disk to erase, and leaving is the close and the drop.
	self.drop(groupId, group)
	if !durable {
		return nil
	}
	if err := store.DeleteGroupRecord(groupId); err != nil {
		return fmt.Errorf("%w: %w", ErrForgetUnfinished, err)
	}
	return nil
}

// recordOnDisk asks the store about ONE group: whether it holds a record for it, and whether that
// record reads. A group being left is not on the disk for this purpose:
// [DurableStateStore.GroupRecord] answers it as not found, and ForgetGroup has finished that one
// before it asks this.
//
// IT ASKS ABOUT THE ONE GROUP AND NOT FOR THE LIST. It used to ask for every record the store
// holds, so a record of another group that did not read made this an error, and ForgetGroup, the
// remedy every held-group refusal names, failed for the reason the refusal was given.
func recordOnDisk(store DeviceStore, groupId []byte) (onDisk bool, reads bool, err error) {
	_, err = store.GroupRecord(groupId)
	switch {
	case err == nil:
		return true, true, nil
	case errors.Is(err, ErrStateNotFound):
		return false, false, nil
	case errors.Is(err, ErrGroupRecordDamaged):
		return true, false, nil
	}
	return false, false, fmt.Errorf("urmessage: whether this device holds group %x on its disk could not be read, so nothing was left: %w", groupId, err)
}

// forgetUnrestored leaves a group that is on the disk and that will not come back, because the
// last Restore could not bring it back or because its record does not read: the mark, then the
// erase, as for a live group, with nothing to close.
func (self *Device) forgetUnrestored(store DeviceStore, groupId []byte) error {
	if err := store.MarkGroupForgetting(groupId); err != nil {
		// the same rule as [Group.closeToForget]'s: a mark that stands although its write
		// reported a failure is an instruction to erase, so the leave goes on
		marked, readErr := store.GroupBeingForgotten(groupId)
		if readErr != nil || !marked {
			return fmt.Errorf("urmessage: the leave could not be recorded on the disk, so nothing was left: %w", err)
		}
	}
	if err := store.DeleteGroupRecord(groupId); err != nil {
		return fmt.Errorf("%w: %w", ErrForgetUnfinished, err)
	}
	self.mutex.Lock()
	delete(self.unrestored, string(groupId))
	self.mutex.Unlock()
	return nil
}

// finishLeaveBefore is what [Device.Join] and [Device.CreateGroup] owe a leave of the same group
// id that has not finished erasing (msgrepo ledger §7, 2026-10-03, re-check R1). The mark is the
// erase's own instruction, so state written beside it is erased with it at the next Restore: a
// group re-joined over a standing mark worked until the restart and was then gone, with no
// warning. The erase is finished first, or the join is refused.
func (self *Device) finishLeaveBefore(groupId []byte) error {
	store, durable := self.stateStore.(DeviceStore)
	if !durable {
		return nil
	}
	marked, err := store.GroupBeingForgotten(groupId)
	if err != nil {
		return err
	}
	if !marked {
		return nil
	}
	if err := store.DeleteGroupRecord(groupId); err != nil {
		return fmt.Errorf("%w: group %x cannot be joined or made until the erase of the leave before it has finished: %w",
			ErrForgetUnfinished, groupId, err)
	}
	return nil
}

// drop takes one group out of this device's map, if it is still the one there.
func (self *Device) drop(groupId []byte, group *Group) {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	if self.groups[string(groupId)] == group {
		delete(self.groups, string(groupId))
	}
}

// closeToForget is the owner's refusal, the leave mark and [Group.Close], IN ONE CRITICAL SECTION,
// and it answers whether the group is closed now. Released between the refusal and the close, an
// ingest could make this device the owner after the check said it was not -- a transfer to it
// arriving in the Receive a UI runs beside the button -- and the group would be stranded exactly as
// the refusal exists to prevent. A group already closed is not one this call can judge, and is
// refused as not held: a leave that closed it and stopped has left its mark, and ForgetGroup
// finishes that one before it gets here.
func (self *Group) closeToForget(mark func() error, stands func() bool) (bool, error) {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	if self.closed {
		return false, fmt.Errorf("%w: it is already closed", ErrGroupNotHeld)
	}
	if err := self.ownerMayNotLeaveLocked(); err != nil {
		return false, err
	}
	if err := mark(); err != nil {
		// A MARK CAN BE ON THE DISK ALTHOUGH ITS WRITE REPORTED A FAILURE (re-check R2): the store
		// renames, then syncs the directory, and answers the sync's error. A mark that stands is an
		// instruction to erase this group at the next Restore, so refusing here would leave a group
		// that works now and is gone at the next launch. Where it stands, the leave goes on.
		if !stands() {
			return false, fmt.Errorf("urmessage: the leave could not be recorded on the disk, so nothing was left: %w", err)
		}
	}
	return true, self.closeLocked()
}

// ownerMayNotLeaveLocked is the refusal, under the lock. A roster that cannot be read is a refusal
// rather than a pass: it is the one reading that says whether this device owns the group, and
// guessing "no" is the guess that strands. A device a valid commit has REMOVED needs no case of
// its own: an owner is never removed (ruling 11), and its roster still reads at the epoch it was
// removed at, so it answers "not the owner" like any member (TestARemovedDeviceMayLeave).
func (self *Group) ownerMayNotLeaveLocked() error {
	members, err := self.membersLocked()
	if err != nil {
		return fmt.Errorf("urmessage: who owns this group could not be read, so leaving it is refused: %w", err)
	}
	var own *Member
	for at := range members {
		if members[at].Mine {
			own = &members[at]
			break
		}
	}
	if own == nil || own.Role != mls.RoleOwner.String() {
		return nil
	}
	somebodyElse := false
	for _, member := range members {
		if member.Mine {
			continue
		}
		if bytes.Equal(member.IdentityPub, own.IdentityPub) {
			// another device of the owner's own: the identity stays, and so does its ownership
			return nil
		}
		somebodyElse = true
	}
	if somebodyElse {
		return fmt.Errorf("%w: %d other leaf/leaves", ErrOwnerMustTransfer, len(members)-1)
	}
	return nil
}
