//go:build !windows

package urmessage

import "syscall"

// transientErrnos is [transientRead]'s set off Windows: the call would block, was interrupted, or
// the file is busy.
var transientErrnos = []syscall.Errno{syscall.EAGAIN, syscall.EINTR, syscall.EBUSY}
