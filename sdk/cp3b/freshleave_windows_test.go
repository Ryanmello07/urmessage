//go:build windows

package cp3b

import (
	"errors"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"unsafe"

	"github.com/urnetwork/message/sdk/urmessage"
)

var (
	freshLeaveLookupPrivilegeValue = syscall.NewLazyDLL("advapi32.dll").NewProc("LookupPrivilegeValueW")
	freshLeaveAdjustTokenPrivilege = syscall.NewLazyDLL("advapi32.dll").NewProc("AdjustTokenPrivileges")
)

// freshLeavePrivilege is one LUID_AND_ATTRIBUTES, and freshLeavePrivileges a TOKEN_PRIVILEGES of one.
type freshLeavePrivilege struct {
	low, high  uint32
	attributes uint32
}

type freshLeavePrivileges struct {
	count     uint32
	privilege freshLeavePrivilege
}

// freshLeaveBackupEnabled answers whether SeBackupPrivilege is ENABLED in this process's token.
func freshLeaveBackupEnabled(t *testing.T, token syscall.Token, backup freshLeavePrivilege) bool {
	t.Helper()
	const tokenPrivileges = 3
	var size uint32
	syscall.GetTokenInformation(token, tokenPrivileges, nil, 0, &size)
	buffer := make([]byte, size)
	if err := syscall.GetTokenInformation(token, tokenPrivileges, &buffer[0], size, &size); err != nil {
		t.Fatalf("reading this process's privileges: %v", err)
	}
	count := *(*uint32)(unsafe.Pointer(&buffer[0]))
	for at := uint32(0); at < count; at++ {
		one := (*freshLeavePrivilege)(unsafe.Pointer(&buffer[4+at*12]))
		if one.low == backup.low && one.high == backup.high {
			return one.attributes&2 != 0 // SE_PRIVILEGE_ENABLED
		}
	}
	return false
}

// freshLeaveWithoutBackupPrivilege DISABLES SeBackupPrivilege in this test process's own token for
// the case's duration, and puts its earlier state back when the case ends (R31).
//
// WHY, MEASURED. On fork-ci's windows leg (run 38598995529) this case's control failed: a read of the
// denied file answered nil. The throwaway branch ci/t1fix3-deny (run 38611636518) measured why: under
// the Git Bash that fork-ci and test.sh run in, the runner account's token has SeBackupPrivilege and
// SeRestorePrivilege ENABLED (under pwsh both are present and disabled), and package os opens every
// file with FILE_FLAG_BACKUP_SEMANTICS, which with SeBackupPrivilege enabled reads THROUGH a deny
// entry. Under bash, os.ReadFile read the file under (R) and under (RD), on C: and on D:, while a
// CreateFile without backup semantics, and pwsh's Get-Content, were refused with access denied; under
// pwsh every read was refused. So the deny is real and the privilege overrides it, and with the
// privilege disabled the deny holds for this process's reads as it does for a person's.
//
// THE CONTROL is that the privilege is not enabled once this returns. A token without it -- a
// developer's own shell -- has nothing to disable, and that is the same state.
func freshLeaveWithoutBackupPrivilege(t *testing.T) {
	t.Helper()
	process, _ := syscall.GetCurrentProcess()
	var token syscall.Token
	const adjustPrivileges = 0x0020 // TOKEN_ADJUST_PRIVILEGES
	if err := syscall.OpenProcessToken(process, adjustPrivileges|syscall.TOKEN_QUERY, &token); err != nil {
		t.Fatalf("opening this process's token: %v", err)
	}
	name, _ := syscall.UTF16PtrFromString("SeBackupPrivilege")
	var backup freshLeavePrivilege
	if found, _, err := freshLeaveLookupPrivilegeValue.Call(0, uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(&backup))); found == 0 {
		token.Close()
		t.Fatalf("looking up SeBackupPrivilege: %v", err)
	}
	wasEnabled := freshLeaveBackupEnabled(t, token, backup)
	disable := freshLeavePrivileges{count: 1, privilege: freshLeavePrivilege{low: backup.low, high: backup.high}}
	if adjusted, _, err := freshLeaveAdjustTokenPrivilege.Call(uintptr(token), 0, uintptr(unsafe.Pointer(&disable)), 0, 0, 0); adjusted == 0 {
		token.Close()
		t.Fatalf("disabling SeBackupPrivilege: %v", err)
	}
	if freshLeaveBackupEnabled(t, token, backup) {
		token.Close()
		t.Fatalf("CONTROL FAILED: SeBackupPrivilege is still enabled in this process's token, so a read through backup semantics would read through the deny")
	}
	t.Logf("SeBackupPrivilege in this process's token: was enabled=%v, disabled for this case", wasEnabled)
	t.Cleanup(func() {
		defer token.Close()
		if !wasEnabled {
			return
		}
		enable := freshLeavePrivileges{count: 1, privilege: freshLeavePrivilege{low: backup.low, high: backup.high, attributes: 2}}
		if adjusted, _, err := freshLeaveAdjustTokenPrivilege.Call(uintptr(token), 0, uintptr(unsafe.Pointer(&enable)), 0, 0, 0); adjusted == 0 {
			t.Errorf("putting SeBackupPrivilege back: %v", err)
		}
	})
}

// freshLeaveDeny puts a DENY-read entry for this process's own user on one file, as a backup
// restore or a hand-edited permission leaves one, with icacls; the function it answers lifts it.
// THE CONTROLS are that a read of the file is refused with access denied while the entry stands, and
// reads again once it is lifted: a deny that did not take, or did not lift, would make every
// assertion after it about something else. The deny is held for this process too: see
// [freshLeaveWithoutBackupPrivilege], which this calls first.
func freshLeaveDeny(t *testing.T, path string) func() {
	t.Helper()
	freshLeaveWithoutBackupPrivilege(t)
	me, err := user.Current()
	if err != nil {
		t.Fatalf("who this process runs as: %v", err)
	}
	icacls := func(args ...string) error {
		output, err := exec.Command("icacls", args...).CombinedOutput()
		if err != nil {
			return errors.New(strings.TrimSpace(string(output)) + ": " + err.Error())
		}
		return nil
	}
	if err := icacls(path, "/deny", "*"+me.Uid+":(R)"); err != nil {
		t.Fatalf("denying %s to %s: %v", path, me.Username, err)
	}
	var errno syscall.Errno
	if _, readErr := os.ReadFile(path); !errors.As(readErr, &errno) || errno != 5 {
		icacls(path, "/remove:d", "*"+me.Uid)
		t.Fatalf("CONTROL FAILED: a read of %s under the deny answered %v, want access denied (5)", path, readErr)
	}
	lifted := false
	lift := func() {
		if lifted {
			return
		}
		lifted = true
		if err := icacls(path, "/remove:d", "*"+me.Uid); err != nil {
			t.Errorf("lifting the deny on %s: %v", path, err)
			return
		}
		if _, readErr := os.ReadFile(path); readErr != nil {
			t.Errorf("CONTROL FAILED: %s does not read after the deny was lifted: %v", path, readErr)
		}
	}
	t.Cleanup(lift)
	return lift
}

// A DENY AT STARTUP, LIFTED, THEN A LOCK AT THE LEAVE, ERASES NOTHING (R30; the Task 58 writer's
// measurement on a runner, mutant M19c, kept as the library's own regression). Alice owns a group
// bob is in. Her group's current epoch state is DENIED to her by an ACL entry when she starts and
// restores; the entry is lifted; and the same file is LOCKED by another process at the moment she
// leaves. A refused permission is a fact about the environment, so the startup Restore reports the
// group as unproven and notes it nowhere as damage; the leave tries the restore again, meets the
// lock, and is refused with the not-read-now sentence, "so nothing was left". Every file stays.
// Once the lock is released, a Restore brings the group back and the owner is asked.
//
// WHAT WOULD GO RED: a refused permission read as damage, or a leave decided on what startup saw:
// on the library before R30 this erased the owner's group, with bob in it, without the question.
func TestADenyAtStartupLiftedThenALockAtTheLeaveErasesNothing(t *testing.T) {
	ctx := t.Context()
	alice, groupId := transientOwnerPair(t)
	path := filepath.Join(anyFileGroupDir(t, alice.stateDir, groupId), "epoch", "0000000000000001")
	before := advGroupFiles(t, alice.stateDir, groupId)
	lift := freshLeaveDeny(t, path)
	restored, err := alice.device.Restore(ctx)
	t.Logf("the startup Restore under the deny: %d group(s), %v", len(restored), err)
	if len(restored) != 0 || !errors.Is(err, urmessage.ErrGroupReadUnproven) || errors.Is(err, urmessage.ErrGroupRecordDamaged) {
		t.Errorf("the startup Restore under the deny answered %d group(s), %v, want none and ErrGroupReadUnproven, and not damage", len(restored), err)
	}
	lift()
	release := transientHold(t, path)
	err = alice.device.ForgetGroup(groupId)
	t.Logf("the leave over the lock: %v", err)
	if !errors.Is(err, urmessage.ErrGroupRecordNotReadNow) || !strings.Contains(err.Error(), "so nothing was left") {
		t.Errorf("the leave over the lock answered %v, want ErrGroupRecordNotReadNow and that nothing was left", err)
	}
	release()
	freshLeaveUnchanged(t, alice, groupId, before)
	if restored, err := alice.device.Restore(ctx); err != nil || len(restored) != 1 {
		t.Fatalf("the Restore after the release answered %d group(s), %v, want the group back", len(restored), err)
	}
	if err := alice.device.ForgetGroup(groupId); !errors.Is(err, urmessage.ErrOwnerMustTransfer) {
		t.Errorf("the restored owner's leave answered %v, want ErrOwnerMustTransfer", err)
	}
}
