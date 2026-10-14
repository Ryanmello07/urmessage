// THROWAWAY (ruling R31): what a read of one file answers on a GitHub runner, and why.
//
// Usage: denyprobe <path>
//
// It prints this process's token privileges (name and state), then three reads of the file:
// os.ReadFile, which opens with FILE_FLAG_BACKUP_SEMANTICS on Windows; CreateFile with GENERIC_READ
// and no backup semantics; and CreateFile with GENERIC_READ and backup semantics.
package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

var lookupPrivilegeName = syscall.NewLazyDLL("advapi32.dll").NewProc("LookupPrivilegeNameW")

type luid struct {
	low  uint32
	high int32
}

type luidAndAttributes struct {
	luid       luid
	attributes uint32
}

func privileges() string {
	process, _ := syscall.GetCurrentProcess()
	var token syscall.Token
	if err := syscall.OpenProcessToken(process, syscall.TOKEN_QUERY, &token); err != nil {
		return "OpenProcessToken: " + err.Error()
	}
	defer token.Close()
	const tokenPrivileges = 3
	var size uint32
	syscall.GetTokenInformation(token, tokenPrivileges, nil, 0, &size)
	buffer := make([]byte, size)
	if err := syscall.GetTokenInformation(token, tokenPrivileges, &buffer[0], size, &size); err != nil {
		return "GetTokenInformation: " + err.Error()
	}
	count := *(*uint32)(unsafe.Pointer(&buffer[0]))
	out := []string{}
	for at := uint32(0); at < count; at++ {
		entry := (*luidAndAttributes)(unsafe.Pointer(&buffer[4+at*12]))
		name := make([]uint16, 256)
		length := uint32(len(name))
		lookupPrivilegeName.Call(0, uintptr(unsafe.Pointer(&entry.luid)), uintptr(unsafe.Pointer(&name[0])), uintptr(unsafe.Pointer(&length)))
		state := "Disabled"
		if entry.attributes&2 != 0 {
			state = "Enabled"
		}
		out = append(out, syscall.UTF16ToString(name[:length])+"="+state)
	}
	return strings.Join(out, " ")
}

func answer(err error) string {
	if err == nil {
		return "READ (no error)"
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return fmt.Sprintf("errno %d: %v", uint(errno), err)
	}
	return err.Error()
}

func open(path string, flags uint32) error {
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	handle, err := syscall.CreateFile(name, syscall.GENERIC_READ, syscall.FILE_SHARE_READ, nil, syscall.OPEN_EXISTING, flags, 0)
	if err != nil {
		return err
	}
	buffer := make([]byte, 16)
	var read uint32
	readErr := syscall.ReadFile(handle, buffer, &read, nil)
	syscall.CloseHandle(handle)
	return readErr
}

func main() {
	path := os.Args[1]
	fmt.Printf("  denyprobe privileges: %s\n", privileges())
	_, err := os.ReadFile(path)
	fmt.Printf("  denyprobe os.ReadFile: %s\n", answer(err))
	fmt.Printf("  denyprobe CreateFile, no backup semantics: %s\n", answer(open(path, syscall.FILE_ATTRIBUTE_NORMAL)))
	const backupSemantics = 0x02000000
	fmt.Printf("  denyprobe CreateFile, backup semantics: %s\n", answer(open(path, backupSemantics)))
}
