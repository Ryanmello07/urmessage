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
// Windows, and each is a fact about the DATA (R29, amended by R30 and R33): a path of the wrong type.
// The numbered ones are what the OS answers; the named ones are the values package syscall defines on
// Windows, which package os itself returns, each meaning what its name says.
//
// AND EACH IS PROOF ONLY BESIDE THE TYPE IT CLAIMS (R36, item 4). ERROR_INVALID_FUNCTION (1) is what
// ReadFile answers on a directory, and also what a WinFsp or Dokan mount (rclone, Cryptomator,
// SSHFS-Win) or a minifilter answers for an intact file whose request it does not implement. So
// [classifyRead] takes any of these as proof only inside a [stateWrongType]: the store's own Lstat of
// the name, at the verdict, showed a type the store never writes there -- and never a reparse point
// Go reports as irregular, a cloud placeholder of the store's own file or a junction among them
// (R38, item 2).
//
// NOT HERE, AND WHY. A permission refused (5) and the medium (23, 27, 30) are facts about the
// environment, which can change while the data is intact (R30). And AN ABSENCE IS NEVER PROOF (R33):
// ERROR_FILE_NOT_FOUND (2), ERROR_PATH_NOT_FOUND (3) and ERROR_BAD_NETPATH (53) are what a file
// moved away by an antivirus quarantine, a sync tool or a backup tool answers, and the file can come
// back. Package syscall's ENOENT is 2 and its ENOTDIR is 3 on this platform, so neither is here
// either: a listing of a regular file answers 3 as well, and [stateNotADirectory] is the unambiguous
// spelling this store uses once an Lstat has said which it was.
var permanentErrnos = []syscall.Errno{
	1, 267, 1921, // ERROR_INVALID_FUNCTION, ERROR_DIRECTORY, ERROR_CANT_RESOLVE_FILENAME: the wrong type
	syscall.EISDIR, syscall.ELOOP,
}

// stateNotADirectory is the errno this store carries for a path its Lstat found NOT to be a
// directory where it keeps one: ERROR_DIRECTORY, "the directory name is invalid", which nothing on
// this platform answers for an absence.
const stateNotADirectory syscall.Errno = 267
