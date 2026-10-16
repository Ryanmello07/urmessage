package urmessage

import (
	"context"
	"errors"
	"os"
	"syscall"
	"testing"
)

// A `sent` PATH THAT IS A FILE IS PROVEN PERMANENT, AND ITS GROUP IS LEFT (R29, the second review's
// W1, its own case). The group's `sent` directory -- the one W1 found, whose listing formatted the OS
// error with %v and so dropped its errno -- is replaced by a regular file: a path of the wrong type,
// which no later read will ever list. Restore must carry the OS's own errno out of that listing,
// prove the failure permanent from it, and note the group; and the leave must then go through
// without the owner's question and take the group's directory, `sent` included.
//
// THIS IS WHAT HOLDS THE CHAIN NOW THAT THE ERASE IS FAIL-CLOSED. With the errno dropped, the same
// failure reads as unproven, which erases nothing -- so a lost errno no longer costs an owner's
// group, it costs a damaged group its way out. That is the regression this case catches.
//
// WHAT WOULD GO RED: a %v at SentRecords' listing, and this group is never left; or an erase that
// cannot take a file at `sent`, and its leave never finishes.
func TestASentPathThatIsAFileIsProvenPermanentAndItsGroupIsLeft(t *testing.T) {
	ctx := context.Background()
	dir, groupId := failClosedScene(t)
	store, device := failClosedRestart(t, dir, groupId, nil)
	sent := store.sentDir(groupId)
	if _, err := os.Lstat(sent); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("CONTROL FAILED: the scene already has something at %s: %v", sent, err)
	}
	if err := os.WriteFile(sent, []byte("a file where the sent directory goes"), 0o600); err != nil {
		t.Fatalf("standing a file where the sent directory goes: %v", err)
	}
	restored, err := device.Restore(ctx)
	t.Logf("the Restore over a sent path that is a file: %d group(s), %v", len(restored), err)
	if len(restored) != 0 || !errors.Is(err, ErrRestore) {
		t.Fatalf("the Restore answered %d group(s), %v, want none and ErrRestore", len(restored), err)
	}
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		t.Errorf("the Restore's failure carries no errno, so its chain was dropped on the way: %v", err)
	}
	if errors.Is(err, ErrGroupReadUnproven) || errors.Is(err, ErrGroupRecordNotReadNow) {
		t.Errorf("a sent path that is a file was reported as not read, which a path of the wrong type is not: %v", err)
	}
	if !device.didNotRestore(groupId) {
		t.Errorf("the Restore did not note the group as one that will not come back")
	}
	if err := device.ForgetGroup(groupId); err != nil {
		t.Errorf("the leave of the group answered %v, want it left", err)
	}
	if _, err := os.Lstat(store.groupDir(groupId)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the group's directory is still on the disk after the leave: %v", err)
	}
}
