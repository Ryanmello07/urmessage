package urmessage

import (
	"errors"
	"fmt"
)

// joinOverHeldGroup is the held-group gate of [Device.Join]: it answers whether an invite into
// groupId may be joined at all, and for the one case that may, the group the join replaces and the
// epoch it has to exceed.
//
// A DEVICE HOLDS A GROUP when it has a live [Group] for it in memory, or a record of it on its
// disk. Either is refused with [ErrGroupAlreadyHeld], before the join code is touched and before
// anything is written. The disk is asked as well as the map because a device that has restarted
// and not yet restored holds every one of its groups on the disk and none of them in memory.
//
// THE ONE EXCEPTION is a group a commit REMOVED this device from: being added back is a join over
// a held id, and it is the repair [ErrRemovedFromGroup] itself names. It is honoured only above the
// epoch the device was removed at, which the caller holds the joined epoch against.
//
// THE EXCEPTION AUTHENTICATES NOBODY. An invite does not say who made it, so this gate cannot tell
// the group that removed this device from another founder's group under the same id that stands
// at a later epoch: that invite is honoured too, and it replaces the removed group's record. That
// is measured and pinned open in sdk/cp3b (S7g) until a join names its inviter.
//
// IT IS ASKED UNDER [Device.admitMutex], AND ITS ANSWER HOLDS UNTIL THE HOLD. Asked outside it,
// two joins into one group id that overlap both read "not held"; the second then wrote its record
// over the first's. Measured in sdk/cp3b, with the two invites at two epochs, before the mutex
// stood above this call.
//
// EPOCH STATES WITH NO RECORD ARE NOT A HELD GROUP. A founder that died before Open, or a join
// whose record did not persist, leaves them, and refusing here would refuse the join that repairs
// it. The engine's create-only commit is what protects those: it never writes over a state that is
// already there.
//
// THE DISK IS ASKED ABOUT THIS ONE GROUP, AND ABOUT NO OTHER ([DeviceStore.GroupRecord]). It used
// to be asked for every record it holds, and one record of ANOTHER group that did not read then
// refused every invite on the device, with no call that cleared it. Measured, before this was one
// read: a device with one damaged record joined nothing, founded nothing and left nothing.
//
// A RECORD THAT DOES NOT READ IS A HELD GROUP, and a store that cannot answer is a refusal: neither
// is "not held", which is the one answer that lets a join write. The first is refused as held
// ([ErrGroupAlreadyHeld], carrying [ErrGroupRecordDamaged]), because the remedy is the same and it
// exists: [Device.ForgetGroup] leaves a group whose record does not read.
func (self *Device) joinOverHeldGroup(groupId []byte) (replaces *Group, readd bool, removedEpoch uint64, err error) {
	self.mutex.Lock()
	live := self.groups[string(groupId)]
	self.mutex.Unlock()
	if live != nil {
		epoch, removal := live.Removal()
		if removal == nil {
			return nil, false, 0, fmt.Errorf("%w: group %x is live on this device", ErrGroupAlreadyHeld, groupId)
		}
		replaces, readd, removedEpoch = live, true, epoch
	}
	store, durable := self.stateStore.(DeviceStore)
	if !durable {
		return replaces, readd, removedEpoch, nil
	}
	record, err := store.GroupRecord(groupId)
	if errors.Is(err, ErrStateNotFound) {
		return replaces, readd, removedEpoch, nil
	}
	if err != nil {
		return nil, false, 0, heldUnread(groupId, err, "the invite into it is refused")
	}
	if record.RemovedKind == removedNone {
		return nil, false, 0, fmt.Errorf("%w: group %x has a record on this device's disk", ErrGroupAlreadyHeld, groupId)
	}
	readd = true
	if removedEpoch < record.RemovedEpoch {
		removedEpoch = record.RemovedEpoch
	}
	return replaces, readd, removedEpoch, nil
}

// heldUnread is what the gate and a founding answer when the store said anything about a group but
// "here is its record" or "I hold none". A record that does not read is a group this device holds,
// refused as one, with the remedy [ErrGroupAlreadyHeld]'s own sentence names. A store that could
// not answer is refused as that, and names no remedy, because it has none to name.
func heldUnread(groupId []byte, err error, refused string) error {
	if errors.Is(err, ErrGroupRecordDamaged) {
		return fmt.Errorf("%w: group %x has a record on this device's disk that does not read: %w", ErrGroupAlreadyHeld, groupId, err)
	}
	// AND IT SAYS WHICH OF THE TWO NOT-READ CLASSES THIS IS (R29), by the sentinel [Device.Restore]
	// reports the same failure under, so an app reads one sentence for each
	return fmt.Errorf("urmessage: whether this device already holds group %x could not be read, so %s: %w: %w",
		groupId, refused, notReadSentinel(classifyRead(err)), err)
}

// foundOverHeldGroup is the same question for [Device.CreateGroup], and it has no exception: a
// group is founded under an id this device holds nothing for, removed or not. An id is 32 random
// octets of the caller's, so this refuses a caller's mistake and never an honest founding. It asks
// the disk about that one id, as the gate does and for the gate's reason: a record of another
// group that does not read is no reason to refuse a founding under a fresh id.
func (self *Device) foundOverHeldGroup(groupId []byte) error {
	if self.holdsGroup(groupId) {
		return fmt.Errorf("%w: group %x is live on this device", ErrGroupAlreadyHeld, groupId)
	}
	store, durable := self.stateStore.(DeviceStore)
	if !durable {
		return nil
	}
	_, err := store.GroupRecord(groupId)
	if errors.Is(err, ErrStateNotFound) {
		return nil
	}
	if err != nil {
		return heldUnread(groupId, err, "no group is founded under it")
	}
	return fmt.Errorf("%w: group %x has a record on this device's disk", ErrGroupAlreadyHeld, groupId)
}

// hold files a group on this device that is NEW TO ITS MAP: one founded here, or one restored off
// the disk. It never replaces. An id that is already in the map is refused, because the group
// sitting there is live, with a session and an epoch's secrets, and nothing asked whether it may
// go. The callers are under [Device.admitMutex] and have asked first, so this refusal is the
// second line and not the gate.
func (self *Device) hold(group *Group) error {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	if held := self.groups[string(group.id)]; held != nil && held != group {
		return fmt.Errorf("%w: group %x is live on this device", ErrGroupAlreadyHeld, group.id)
	}
	self.groups[string(group.id)] = group
	delete(self.unrestored, string(group.id))
	delete(self.notRead, string(group.id))
	return nil
}

// holdReplacing files a JOINED group on this device, in place of exactly the group the gate judged
// and of nothing else. judged is what [Device.joinOverHeldGroup] answered: nil when the device
// held no live group under the id, and otherwise the group a commit removed this device from. That
// group is closed here, because its session and its MLS handle are still open: left alone they are
// a loop and an epoch's secrets nothing will ever close.
//
// A MAP ENTRY THAT IS NOT THE ONE THE GATE JUDGED IS REFUSED. Under [Device.admitMutex] it cannot
// happen, which is the point of the mutex; an admission that ever runs outside it fails here,
// loudly, and does not replace a group nobody judged.
func (self *Device) holdReplacing(group *Group, judged *Group) error {
	self.mutex.Lock()
	if held := self.groups[string(group.id)]; held != judged {
		self.mutex.Unlock()
		return fmt.Errorf("%w: the group this device holds under %x is not the one this join was judged against", ErrGroupAlreadyHeld, group.id)
	}
	self.groups[string(group.id)] = group
	delete(self.unrestored, string(group.id))
	delete(self.notRead, string(group.id))
	self.mutex.Unlock()
	if judged != nil {
		judged.Close()
	}
	return nil
}

// noteUnrestored records that [Device.Restore] could not bring one group back, and didNotRestore
// answers it. It is what lets [Device.ForgetGroup] leave such a group: a record on the disk whose
// state does not load is a group this device can neither use nor, without this, be rid of.
func (self *Device) noteUnrestored(groupId []byte) {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	self.unrestored[string(groupId)] = true
	delete(self.notRead, string(groupId))
}

// notReadEntry is one group the last [Device.Restore] could not read: the class [classifyRead]
// gave the failure, which is never [readPermanent], and the failure.
type notReadEntry struct {
	class readClass
	cause error
}

// noteNotRead records that [Device.Restore] could not READ one group, for a reason it cannot
// prove permanent (R29, the second review's W2). Such a group is NOT left without the owner's
// question; what [Device.ForgetGroup] answers for it is [Device.notReadRefusal].
func (self *Device) noteNotRead(groupId []byte, class readClass, cause error) {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	self.notRead[string(groupId)] = notReadEntry{class: class, cause: cause}
	delete(self.unrestored, string(groupId))
}

// clearNotRead empties the not-read set at the start of a Restore: it is the last Restore's.
func (self *Device) clearNotRead() {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	clear(self.notRead)
}

// notReadRefusal is what [Device.ForgetGroup] answers for a group the last Restore could not
// read, and nil for any other group. It is the TRUE sentence: the class's own sentinel, the same
// one Restore reported, and that nothing was left. The remedy [ErrGroupNotRestored] names --
// Restore, then leave -- loops while the hold lasts, so it is not the answer here (W2).
func (self *Device) notReadRefusal(groupId []byte) error {
	self.mutex.Lock()
	entry, found := self.notRead[string(groupId)]
	self.mutex.Unlock()
	if !found {
		return nil
	}
	return fmt.Errorf("%w; so nothing was left: group %x: %w", notReadSentinel(entry.class), groupId, entry.cause)
}

// notReadSentinel is the sentinel each not-read class is reported under. Anything but transient
// is unproven here: a proven-permanent failure is damage, and is never a refusal of a leave.
func notReadSentinel(class readClass) error {
	if class == readTransient {
		return ErrGroupRecordNotReadNow
	}
	return ErrGroupReadUnproven
}

func (self *Device) didNotRestore(groupId []byte) bool {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	return self.unrestored[string(groupId)]
}
