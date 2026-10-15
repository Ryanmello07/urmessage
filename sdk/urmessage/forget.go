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
// A GROUP WHOSE READ FAILED FOR A REASON NOT PROVEN PERMANENT IS NOT LEFT (Task 57's F1, R26,
// R29, R30, R33). The damage rule above is for PROVEN-permanent damage only ([classifyRead]), a
// fact about the data: a verdict this code made on the octets, or a path of the wrong type. A
// permission refused or the medium is a fact about the environment and not proof, and so is an
// absence: a file an antivirus quarantine, a sync tool or a backup tool moved away can come back
// (R33). A read another process blocked for a moment, or one this build cannot classify, is
// no finding about the group, so it is the store failing to answer, and the leave is refused
// before anything is written, with the class's own sentence and "so nothing was left". The rule had
// been the other way round, damage unless proven transient, and it leaked three times: an owner's
// group with others in it was erased, without the owner's question, over a lock on its record, then
// on an epoch state, then on its `sent` directory, where one site had dropped the errno the proof
// needed.
//
// AND THE PROOF IS FRESH (R30). An erase without the owner's question is irreversible, so it is
// never decided on what an EARLIER Restore saw: a permission refused at startup and lifted since,
// then a lock at the moment of the leave, erased a group on a stale note. So a group the last
// Restore could not bring back is RESTORED AGAIN here, now, under the admission mutex, and what that
// attempt finds decides ([Device.restoreForLeave]): a fresh proven-permanent verdict leaves it
// unasked (R9); a fresh success rebuilds it, NOT held, and the ordinary leave below asks the
// owner's question -- and a leave refused there, for any reason, closes it again, so the refusal
// changed nothing and the next Restore hands the group back (R33's X2); a fresh transient or
// unproven failure is refused with that class's sentence, and nothing is left. A record that does not read needs no second attempt: this call's own read of it,
// just made, IS the fresh verdict.
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
	//
	// WHILE THE MARK STILL NAMES THE JOIN OF THE GROUP THAT STANDS (R36, item 2). A mark naming an
	// earlier join than what stands -- put back by another program after this device was removed and
	// joined again -- is no instruction: the store removes it, and this leave goes on below as the
	// leave of the group that stands, with the owner's question. A mark that cannot be held against
	// what stands decides nothing, and the leave is refused with that class's sentence.
	if durable {
		marked, err := store.GroupBeingForgotten(groupId)
		if err != nil {
			if errors.Is(err, ErrGroupReadUnproven) || errors.Is(err, ErrGroupRecordNotReadNow) {
				return fmt.Errorf("urmessage: a leave of group %x this device recorded could not be held against what stands beside it on the disk, so nothing was left: %w", groupId, err)
			}
			return err
		}
		if marked {
			if held {
				group.Close()
				self.drop(groupId, group)
			}
			if err := store.DeleteGroupRecord(groupId); err != nil {
				return leaveUnfinished(groupId, err)
			}
			return nil
		}
	}
	if !held {
		if !durable {
			return fmt.Errorf("%w: %x", ErrGroupNotHeld, groupId)
		}
		onDisk, reads, err := recordOnDisk(store, groupId)
		if err != nil {
			return err
		}
		switch {
		case !onDisk:
			// A RECORD MISSING FROM A FOLDER THAT HOLDS NOTHING OF A GROUP IS "NOTHING IS HERE" (R33;
			// R34, item 8), and erases nothing: no folder; a folder holding none of the store's own
			// names, whose files are not the store's (a desktop.ini, a sync tool's copy); or a folder
			// in the creating state, which the sweep owns. A record missing from a folder where the
			// store's own files STAND is a file gone missing, which proves nothing (R33): refused, as
			// unproven, and nothing is written.
			if folder, asks := store.(interface{ groupFolder([]byte) groupFolderState }); asks && folder.groupFolder(groupId) == groupFolderStands {
				return fmt.Errorf("urmessage: whether this device holds group %x on its disk could not be read, so nothing was left: %w: its directory stands and its record is not in it",
					groupId, ErrGroupReadUnproven)
			}
			return fmt.Errorf("%w: %x", ErrGroupNotHeld, groupId)
		case !reads:
			// the record's own read, just made, is a fresh proven-permanent verdict (R9, R30)
			return self.forgetUnrestored(store, groupId)
		case !self.didNotRestore(groupId) && !self.lastRestoreCouldNotRead(groupId):
			// no Restore has tried it: the owner's question is asked of a live group
			return fmt.Errorf("%w: %x", ErrGroupNotRestored, groupId)
		}
		// THE LAST RESTORE TRIED IT AND FAILED, so it is tried again, now (R30)
		fresh, err := self.restoreForLeave(store, groupId)
		if fresh == nil {
			return err
		}
		group = fresh
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
		// A GROUP REBUILT FOR THIS LEAVE IS CLOSED AGAIN WHEN THE LEAVE IS REFUSED (R33's X2), by
		// whatever refused it: the owner's question, a roster that does not read, a leave that
		// could not be recorded. It was never held, so the refusal changed nothing -- this device
		// held no group under the id before the call and holds none after it -- and the next
		// Restore hands the group back. Held, a refused leave left it in the map, and the next
		// Restore, which skips a held group, handed back nothing, measured.
		if !held {
			group.Close()
		}
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
		return leaveUnfinished(groupId, err)
	}
	return nil
}

// leaveUnfinished is what a leave answers when the erase that finishes it does not: the erase stopped
// part way ([ErrForgetUnfinished]), or, at the erase, the leave mark named an earlier join of the
// group than what stood on the disk (R36, item 2). Then the store removed the mark and erased nothing:
// the group that stands was not left, it is on the disk and not restored, and the next Restore hands
// it back ([ErrGroupNotRestored]).
func leaveUnfinished(groupId []byte, err error) error {
	if errors.Is(err, errLeaveMarkStale) {
		return fmt.Errorf("%w: %x: %w", ErrGroupNotRestored, groupId, err)
	}
	return fmt.Errorf("%w: %w", ErrForgetUnfinished, err)
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
	// a record that could not be read for a reason not proven permanent, said by its class (R29)
	return false, false, fmt.Errorf("urmessage: whether this device holds group %x on its disk could not be read, so nothing was left: %w: %w",
		groupId, notReadSentinel(classifyRead(err)), err)
}

// restoreForLeave is R30's fresh evidence: the restore of ONE group the last Restore could not
// bring back, tried again now, by the caller that holds [Device.admitMutex] and is about to leave
// it. It answers the group, rebuilt and NOT HELD, when the attempt succeeds, and the leave goes on
// as for any live group, the owner's question included; [Device.ForgetGroup] closes it again if
// that leave is refused (R33's X2). Otherwise it answers no group and what the leave answers: the
// erase without the owner's question on a FRESH proven-permanent verdict, and otherwise that
// class's refusal, "so nothing was left". Every answer re-decides the group's note, so the latest
// attempt is the one that stands: a success takes both notes away.
func (self *Device) restoreForLeave(store DeviceStore, groupId []byte) (*Group, error) {
	record, err := store.GroupRecord(groupId)
	if err != nil {
		return nil, fmt.Errorf("urmessage: group %x's record could not be read again for the leave, so nothing was left: %w: %w",
			groupId, notReadSentinel(classifyRead(err)), err)
	}
	nonce, nonceEpoch, err := self.nonce()
	if err != nil {
		return nil, fmt.Errorf("urmessage: group %x's restore could not be tried again for the leave, so nothing was left: %w", groupId, err)
	}
	group, err := self.restoreOne(store, record, nonce, nonceEpoch)
	if err == nil {
		self.clearNotes(groupId)
		return group, nil
	}
	class := classifyRead(err)
	if class == readPermanent {
		self.noteUnrestored(groupId)
		return nil, self.forgetUnrestored(store, groupId)
	}
	self.noteNotRead(groupId, class)
	return nil, fmt.Errorf("%w; so nothing was left: group %x: %w", notReadSentinel(class), groupId, err)
}

// forgetUnrestored leaves a group that is on the disk and that will not come back, on a fresh
// proven-permanent verdict: its restore, tried again by this leave, failed for good, or its record
// does not read. The mark, then the erase, as for a live group, with nothing to close.
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
		return leaveUnfinished(groupId, err)
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
// warning. The erase is finished first, or the join is refused. refused says what is refused, in
// the caller's words.
//
// A MARK NAMING AN EARLIER JOIN THAN WHAT STANDS IS NO LEAVE UNDER WAY (R36, item 2): the store
// removes it, here or at the erase, nothing is erased, and the caller's own gate decides on what
// stands. A mark that cannot be held against what stands decides nothing, and refuses the call with
// that class's sentence.
func (self *Device) finishLeaveBefore(groupId []byte, refused string) error {
	store, durable := self.stateStore.(DeviceStore)
	if !durable {
		return nil
	}
	marked, err := store.GroupBeingForgotten(groupId)
	if err != nil {
		if errors.Is(err, ErrGroupReadUnproven) || errors.Is(err, ErrGroupRecordNotReadNow) {
			return fmt.Errorf("urmessage: a leave of group %x this device recorded could not be held against what stands beside it on the disk, so %s: %w", groupId, refused, err)
		}
		return err
	}
	if !marked {
		return nil
	}
	if err := store.DeleteGroupRecord(groupId); err != nil {
		if errors.Is(err, errLeaveMarkStale) {
			return nil
		}
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
