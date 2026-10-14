package urmessage

import (
	"errors"
	"syscall"
)

// transientRead is THE ONE CLASSIFIER of a failed read of this device's disk (R26): it answers
// whether the store could not read a file FOR A MOMENT -- another process holds it, with a sharing
// or lock violation -- or for a reason that will not pass.
//
// IT EXISTS BECAUSE ONE PROMISE LEAKED TWICE. [Device.ForgetGroup] leaves a group WITHOUT the
// owner's question only when that group failed to restore for a PERMANENT reason. The promise
// broke first on the record file (Task 57's F1), then on the epoch-state file (the fix review's
// V1): each fix had been made at one file, and the subject is not a file. It is "this group's
// restore failed", whichever file failed. So the rule is made once, here, and applied wherever a
// restore failure is recorded and wherever the list classifies a record.
//
// THE RULE. Transient is ONLY the platform's sharing and lock violations ([transientErrnos]): on
// Windows ERROR_SHARING_VIOLATION and ERROR_LOCK_VIOLATION, which is what a scanner or a backup
// tool holding a file causes; elsewhere EAGAIN, EINTR and EBUSY. Everything else is PERMANENT and
// is damage, R9's: EACCES, ELOOP, ENOENT inside a group, EIO, a file that is not a regular file,
// and every checksum, decode or id mismatch. An error that is not this store's
// ([ErrStateStoreState]) or that carries no errno is not transient either: this classifier never
// guesses "for a moment", because that is the answer that keeps a group a device can never leave.
func transientRead(err error) bool {
	if !errors.Is(err, ErrStateStoreState) {
		return false
	}
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return false
	}
	for _, transient := range transientErrnos {
		if errno == transient {
			return true
		}
	}
	return false
}
