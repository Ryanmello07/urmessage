package urmessage

import (
	"bytes"
	"fmt"
	"slices"

	"github.com/urnetwork/message/messagegroup"
	"github.com/urnetwork/message/mls"
)

// THE HEADS (identity phase 1's Tasks 12 and 13; store kind 12): the newest list of every root this
// device has seen in a tree it holds, as 0xF005 bodies by root, beside this identity's own.
//
// THEY DRIVE THE DOORS, AND NEVER VALIDITY (F1:337). The Add door reads them ([Group.addDoorLocked]):
// a join code whose list is older than this device's head for its identity, and which that head no
// longer names, is a device its own person has removed. No rule of [authorizeCommit] reads them, so
// two members whose heads differ decide every commit alike (identityrules.go).
//
// THEY ONLY RISE (Property 4). A list is taken only when it is newer than the stored one, by
// messagegroup.VerifyDeviceList's order; an older list, the same list, or a fork of it leaves the stored
// one where it is, whatever a server serves and in whatever order. R8-EQ refuses a fork in any tree.
//
// THIS IDENTITY'S OWN HEAD MOVES ONLY FROM ITS SELF GROUP (Property 9; REDTEAM M4; M5 TR8). A list of
// this identity that this device meets in a conversation moves nothing of this identity's: not its
// head, and not the removed state when that state comes (Task 34). It is a list this device cannot
// explain, which Task 34's alarm reports. Every other root's head rises from any tree.
//
// WHERE THEY RISE: the restore, from every tree it re-verifies; a join, from the tree it joined; and
// every epoch a group enters, its own commits and those it follows, from the tree it enters
// ([Group.raiseHeadsLocked]). Each reads the lists of a tree that has passed this device's own reading
// of it, never a list off a key package or a refused commit.
//
// A WRITE THAT FAILED IS RETRIED, AND FAILS NOTHING BUT THE RESTORE. The heads are derived: every start
// raises them again from every tree the device holds, and a raise is taken in memory, which is what the
// doors read, before it is written. So a raise after a group has moved -- an epoch entered, a join
// committed -- does not answer a failed write as a failure of that move, which could not be undone; the
// next raise writes again. The restore, which runs before its group is held, keeps Task 12's answer.

// raiseHeadsFrom raises the heads off the lists one tree carries, verified, and writes them when one
// rose, or when an earlier write did not land. fromOwnSelfGroup says whether the tree is this
// identity's self group, the one place this identity's own head moves from. It answers the write's
// error, and the error of a stored head that does not read, which leaves that root's head as it is.
//
// A DEVICE WITH NO IDENTITY KEEPS NO HEADS: they are written beside the identity's records, and no
// device holds a group before it has an identity ([ErrNoIdentity]).
func (self *Device) raiseHeadsFrom(verified []*messagegroup.VerifiedIdentity, fromOwnSelfGroup bool) error {
	self.identityLock.Lock()
	defer self.identityLock.Unlock()
	if self.identity == nil {
		return nil
	}
	if self.heads == nil {
		self.heads = map[string][]byte{}
	}
	var damaged error
	raised := false
	for _, one := range verified {
		if !self.headMayMoveLocked(one.Root, fromOwnSelfGroup) {
			continue
		}
		candidate, err := one.Identity.Encode()
		if err != nil {
			return err
		}
		stored, found := self.heads[string(one.Root)]
		if found {
			current, err := messagegroup.ParseUrmessageIdentity(messagegroup.ExtensionBytes{Type: candidate.Type, Data: stored})
			if err != nil {
				damaged = fmt.Errorf("urmessage: the stored head of root %x: %w", one.Root, err)
				continue
			}
			// ONLY A NEWER LIST: an older one, the same one, and a fork of the stored one all leave it
			order, err := messagegroup.VerifyDeviceList(current, one.Identity)
			if err != nil || order != messagegroup.ListNewer {
				continue
			}
		}
		self.heads[string(one.Root)] = candidate.Data
		raised = true
	}
	if raised || self.headsUnwritten {
		if err := self.writeHeadsLocked(); err != nil {
			self.headsUnwritten = true
			return err
		}
		self.headsUnwritten = false
	}
	return damaged
}

// headMayMoveLocked answers whether a list of this root may move its head from the tree at hand: always
// for another identity's root, and for this identity's own only from its self group. Called with
// identityLock held.
func (self *Device) headMayMoveLocked(root []byte, fromOwnSelfGroup bool) bool {
	if !bytes.Equal(root, self.identity.record.Root) {
		return true
	}
	return fromOwnSelfGroup
}

// writeHeadsLocked writes every head, in order of root, on a durable store; a store that is not durable
// keeps nothing, as for every other record. Called with identityLock held.
func (self *Device) writeHeadsLocked() error {
	store, durable := self.stateStore.(DeviceStore)
	if !durable {
		return nil
	}
	rows := make([]IdentityHead, 0, len(self.heads))
	for root, body := range self.heads {
		rows = append(rows, IdentityHead{Root: []byte(root), Identity: body})
	}
	slices.SortFunc(rows, func(left IdentityHead, right IdentityHead) int { return bytes.Compare(left.Root, right.Root) })
	return store.PutIdentityHeads(rows)
}

// headOf answers this device's head for one root, decoded, or nil when it holds none or the one it
// holds does not read.
func (self *Device) headOf(root []byte) *messagegroup.UrmessageIdentity {
	self.identityLock.RLock()
	defer self.identityLock.RUnlock()
	stored, found := self.heads[string(root)]
	if !found {
		return nil
	}
	head, err := messagegroup.ParseUrmessageIdentity(messagegroup.ExtensionBytes{
		Type: uint16(mls.ExtensionTypeUrmessageIdentity), Data: stored,
	})
	if err != nil {
		return nil
	}
	return head
}

// isOwnSelfGroup answers whether a group's context names it this identity's self group: 0xF006 of
// purpose 1, under this identity's own root. A device with no identity has no self group.
func (self *Device) isOwnSelfGroup(extensions []messagegroup.ExtensionBytes) bool {
	purpose, err := groupPurposeIn(extensions)
	if err != nil || purpose == nil || purpose.Purpose != groupPurposeSelf {
		return false
	}
	self.identityLock.RLock()
	defer self.identityLock.RUnlock()
	return self.identity != nil && bytes.Equal(purpose.IdentityRoot, self.identity.record.Root)
}

// raiseHeadsLocked raises the heads from the tree this group stands at: every epoch it enters, its own
// commits and those it follows, and the tree a join enters. The tree has passed this device's reading
// of it, the rules on a commit or the Join door on a join, so every leaf reads; one that does not is
// skipped rather than taken. A failed write is the next raise's to retry (see the file header).
func (self *Group) raiseHeadsLocked() {
	members, err := treeMembersOf(self.handle)
	if err != nil {
		return
	}
	extensions, err := self.contextExtensionsLocked()
	if err != nil {
		return
	}
	bound := boundLeavesOf(members)
	verified := []*messagegroup.VerifiedIdentity{}
	for _, leaf := range sortedLeavesOf(bound) {
		if one := bound[leaf]; one.verified != nil {
			verified = append(verified, one.verified)
		}
	}
	// a write that failed is retried by the next raise, and the next start raises from every tree held
	_ = self.device.raiseHeadsFrom(verified, self.device.isOwnSelfGroup(extensions))
}
