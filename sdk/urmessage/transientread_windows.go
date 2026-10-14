//go:build windows

package urmessage

import "syscall"

// transientErrnos is [classifyRead]'s transient set on Windows: another process holds the file.
// Package syscall names neither, so they are spelled by number.
var transientErrnos = []syscall.Errno{
	32, // ERROR_SHARING_VIOLATION
	33, // ERROR_LOCK_VIOLATION
}

// permanentErrnos is [classifyRead]'s allow-list of errnos that PROVE a read will never succeed on
// Windows, and each is a fact about the DATA (R29, amended by R30): a required file absent, or a path
// of the wrong type. The numbered ones are what the OS answers; the named ones are the values package
// syscall defines on Windows, which package os itself returns, each meaning what its name says
// (ENOENT is 2 and ENOTDIR is 3 there). A permission refused (5) and the medium (23, 27, 30) are NOT
// here: they are facts about the environment, which can change while the data is intact.
var permanentErrnos = []syscall.Errno{
	2, 3, // ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND: a required file absent
	1, 267, 1921, // ERROR_INVALID_FUNCTION, ERROR_DIRECTORY, ERROR_CANT_RESOLVE_FILENAME: the wrong type
	syscall.ENOENT, syscall.EISDIR, syscall.ENOTDIR, syscall.ELOOP,
}
