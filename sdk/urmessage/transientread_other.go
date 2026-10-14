//go:build !windows

package urmessage

import "syscall"

// transientErrnos is [classifyRead]'s transient set off Windows: the call would block, was
// interrupted, or the file is busy.
var transientErrnos = []syscall.Errno{syscall.EAGAIN, syscall.EINTR, syscall.EBUSY}

// permanentErrnos is [classifyRead]'s allow-list of errnos that PROVE a read will never succeed off
// Windows, and each is a fact about the DATA (R29, amended by R30 and R33): a path of the wrong type.
// A permission refused (EACCES, EPERM) and the medium (EIO) are NOT here: they are facts about the
// environment, which can change while the data is intact (R30). And ENOENT is not here either: AN
// ABSENCE IS NEVER PROOF (R33), because software on the machine can move a file away and back.
var permanentErrnos = []syscall.Errno{
	syscall.EISDIR, syscall.ENOTDIR, syscall.ELOOP,
}

// stateNotADirectory is the errno this store carries for a path its Lstat found NOT to be a
// directory where it keeps one.
const stateNotADirectory = syscall.ENOTDIR
