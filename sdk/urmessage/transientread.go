package urmessage

import (
	"errors"
	"slices"
	"syscall"

	"github.com/urnetwork/message/syntax"
)

// readClass is what [classifyRead] answers about one failed read of this device's disk.
type readClass uint8

const (
	// readUnproven is the ZERO VALUE AND THE DEFAULT: nothing proves the failure will pass, and
	// nothing proves it will not. A group whose restore failed this way is NOT left without the
	// owner's question ([ErrGroupReadUnproven]).
	readUnproven readClass = iota
	// readTransient is a sharing or lock violation: another process holds the file for a moment.
	// Not left either ([ErrGroupRecordNotReadNow]).
	readTransient
	// readPermanent is PROOF that this build can never read the group: the one class
	// [Device.ForgetGroup] may leave without the owner's question (R9).
	readPermanent
)

// classifyRead is THE ONE CLASSIFIER of a failed read of this device's disk, and IT IS
// FAIL-CLOSED (R29, amended by R30): only a failure it can PROVE permanent is permanent, and the
// proof is about the DATA, never about the environment.
//
// WHY THE RULE IS INVERTED: ONE PROMISE LEAKED THREE TIMES. [Device.ForgetGroup] leaves a group
// WITHOUT the owner's question only when that group failed to restore for a PERMANENT reason, and
// the erase is irreversible: an owner's copy gone without the transfer can leave the group without
// an owner for every member. The promise broke on the record file (Task 57's F1), then on an epoch
// state (the fix review's V1), then on the `sent` directory (the second review's W1). The first two
// fixes moved the rule from a file to the group's restore, which is the right subject; the third
// leak was in the rule's INPUT. The rule then was fail-open -- transient only on proof, a two- or
// three-item errno list, and everything else damage -- so the promise held only while every read
// site on the restore path kept its errno, and one `%v` (SentRecords) dropped it and made a held
// directory "damage". The same rule called damage every transient failure outside its list: too
// many open files, out of memory, a device not ready. The transient list is incomplete by nature,
// so the proof has to be on the other side: an erase without the owner's question needs proof that
// this build can never read the group, and everything this code cannot prove is UNPROVEN, which is
// never erased.
//
// AND THE PROOF IS ABOUT THE DATA (R30). A permission refused and the medium were on the first
// allow-list, and a deny ACL at startup, lifted, then a lock at the moment of the leave, erased a
// group on what startup had seen. A permission or a medium can change while the data is intact, so
// both are unproven; and the erase is decided on a FRESH attempt, never on an earlier note
// ([Device.restoreForLeave]).
//
// AND AN ABSENCE IS NEVER PROOF (R33), THE FOURTH LEAK. "A required file absent" was on the list:
// an owner's epoch state moved away by an antivirus quarantine read as "holds no such value", the
// leave erased the group unasked, and when the file came back the sweep erased it as an orphan. A
// file that is not there says nothing about whether it will be there again, so on the restore and
// leave roads an absence -- [ErrStateNotFound] for a group's own file, ENOENT, Windows 2, 3 and 53
// -- is unproven. Where an absence only answers "nothing is there" and erases nothing (a group with
// neither a record nor a directory, a join code with no such ref, an epoch this device never stood
// in), it still answers that, and none of those callers asks this classifier.
//
// THE THREE CLASSES.
//   - PERMANENT, an explicit allow-list, each a fact about the data:
//     (1) a verdict this code made on bytes it read: [ErrStateStoreFormat] (a checksum, a format, a
//     record whose decode or id does not match), and an epoch state that does not decode (the
//     syntax package's decode sentinels, which are its whole error contract);
//     (2) a refusal by name: [ErrGroupPredatesJoinSeal];
//     (3) a path of the wrong type: one of the platform's errnos for it ([permanentErrnos]), and only
//     when the store's own Lstat of that name, at the verdict, showed a type the store never writes
//     there ([stateWrongType], R36, item 4). Every one of those codes can also be answered for an
//     intact file -- a mount type, or a filter driver that does not implement a request -- so a
//     wrong-type code on an entry whose own type is right is UNPROVEN.
//   - TRANSIENT: a failure of this store's carrying a sharing or lock violation
//     ([transientErrnos], R26's list, unchanged).
//   - UNPROVEN: everything else -- an absence (ErrStateNotFound, ENOENT; Windows 2, 3, 53), a
//     permission refused (EACCES, EPERM; Windows 5), the medium (EIO; Windows 23, 27, 30), a
//     failure of this store's with no errno, an errno in neither list (EMFILE, ENOMEM; Windows 4,
//     8, 1450), and a failure that is not the store's (a cancelled context, an engine error).
//
// AN ERRNO IS JUDGED ONLY WHEN THE STORE CARRIED IT ([ErrStateStoreState]), and it is judged
// before any sentinel: it is the OS's own account of that read, the most specific evidence there
// is. An errno anybody else carried proves nothing about this disk.
//
// IT IS APPLIED where a restore failure is recorded ([Device.Restore], and the leave's own fresh
// attempt), where the list classifies a record ([DurableStateStore.GroupRecords], through
// groupRecordInLocked), where [Device.ForgetGroup] decides (recordOnDisk), and where a failed take
// of a join code is worded ([Device.Join]).
func classifyRead(err error) readClass {
	if err == nil {
		return readUnproven
	}
	if errors.Is(err, ErrStateStoreState) {
		var errno syscall.Errno
		if errors.As(err, &errno) {
			switch {
			case slices.Contains(transientErrnos, errno):
				return readTransient
			case slices.Contains(permanentErrnos, errno):
				// AND ONLY BESIDE THE TYPE IT CLAIMS (R36, item 4): the store's own Lstat of the name,
				// at the verdict, showed a type the store never writes there
				var confirmed *stateWrongType
				if errors.As(err, &confirmed) {
					return readPermanent
				}
			}
			return readUnproven
		}
	}
	if errors.Is(err, ErrStateStoreFormat) || errors.Is(err, ErrGroupPredatesJoinSeal) ||
		epochStateDoesNotDecode(err) {
		return readPermanent
	}
	return readUnproven
}

// epochStateDoesNotDecode answers whether err carries one of the syntax package's DECODE sentinels,
// which that package states is its complete error contract. On the restore path the only octets
// decoded by it are an epoch state this store handed back, so this is a verdict on bytes this code
// read. The two sentinels that are not about input -- an overflow on encode, and a negative length,
// which is API misuse -- are not here.
func epochStateDoesNotDecode(err error) bool {
	for _, decode := range []error{
		syntax.ErrTruncated, syntax.ErrTrailingBytes, syntax.ErrVarintReserved, syntax.ErrVarintNotMinimal,
		syntax.ErrLengthExceedsInput, syntax.ErrLengthExceedsMax, syntax.ErrOptionalPresence,
		syntax.ErrZeroLengthElement, syntax.ErrRoundTripNotByteExact, syntax.ErrRoundTripNotStable,
	} {
		if errors.Is(err, decode) {
			return true
		}
	}
	return false
}
