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

	"github.com/urnetwork/message/sdk/urmessage"
)

// freshLeaveDeny puts a DENY-read entry for this process's own user on one file, as a backup
// restore or a hand-edited permission leaves one, with icacls; the function it answers lifts it.
// THE CONTROLS are that a read of the file is refused with access denied while the entry stands, and
// reads again once it is lifted: a deny that did not take, or did not lift, would make every
// assertion after it about something else.
func freshLeaveDeny(t *testing.T, path string) func() {
	t.Helper()
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
