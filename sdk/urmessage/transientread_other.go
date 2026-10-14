//go:build !windows

package urmessage

import "syscall"

// transientErrnos is [classifyRead]'s transient set off Windows: the call would block, was
// interrupted, or the file is busy.
var transientErrnos = []syscall.Errno{syscall.EAGAIN, syscall.EINTR, syscall.EBUSY}

// permanentErrnos is [classifyRead]'s allow-list of errnos that PROVE a read will never succeed off
// Windows, and each is a fact about the DATA (R29, amended by R30): a required file absent, or a path
// of the wrong type. A permission refused (EACCES, EPERM) and the medium (EIO) are NOT here: they are
// facts about the environment, which can change while the data is intact.
var permanentErrnos = []syscall.Errno{
	syscall.ENOENT,
	syscall.EISDIR, syscall.ENOTDIR, syscall.ELOOP,
}
