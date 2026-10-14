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
// Windows (R29). The numbered ones are what the OS answers; the named ones are the values package
// syscall invents on Windows and package os itself returns (a listing of a regular file answers
// ENOTDIR), each meaning exactly what its name says.
var permanentErrnos = []syscall.Errno{
	2, 3, // ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND: a required file absent
	1, 267, 1921, // ERROR_INVALID_FUNCTION, ERROR_DIRECTORY, ERROR_CANT_RESOLVE_FILENAME: the wrong type
	5,          // ERROR_ACCESS_DENIED: a permission this device has not got
	23, 27, 30, // ERROR_CRC, ERROR_SECTOR_NOT_FOUND, ERROR_READ_FAULT: the medium
	syscall.ENOENT, syscall.EISDIR, syscall.ENOTDIR, syscall.ELOOP, syscall.EACCES, syscall.EPERM, syscall.EIO,
}
