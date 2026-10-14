//go:build windows

package urmessage

import "syscall"

// transientErrnos is [transientRead]'s set on Windows: another process holds the file. Package
// syscall names neither, so they are spelled by number.
var transientErrnos = []syscall.Errno{
	32, // ERROR_SHARING_VIOLATION
	33, // ERROR_LOCK_VIOLATION
}
