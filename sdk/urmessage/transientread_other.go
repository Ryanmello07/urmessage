//go:build !windows

package urmessage

import "syscall"

// transientErrnos is [classifyRead]'s transient set off Windows: the call would block, was
// interrupted, or the file is busy.
var transientErrnos = []syscall.Errno{syscall.EAGAIN, syscall.EINTR, syscall.EBUSY}

// permanentErrnos is [classifyRead]'s allow-list of errnos that PROVE a read will never succeed off
// Windows (R29): a required file absent, a path of the wrong type, a permission this device has not
// got, and the medium.
var permanentErrnos = []syscall.Errno{
	syscall.ENOENT,
	syscall.EISDIR, syscall.ENOTDIR, syscall.ELOOP,
	syscall.EACCES, syscall.EPERM,
	syscall.EIO,
}
