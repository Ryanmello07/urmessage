package urmessage

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
	"testing"
)

// A RECORD THAT CAN NEVER BE READ IS DAMAGE, AND ITS GROUP CAN BE LEFT (R26, the fix review's V2).
// One group's record is made unreadable without touching its octets: the file is moved aside and a
// directory stands under its name, so a read of it fails, and fails for good. That is not a
// sharing or lock violation, so it is not "not read now": the one-id read and the list answer
// damage, and the leave goes through without a Restore and without the owner's question, which is
// R9's choice for permanent damage. The other group's record still reads beside it.
//
// THIS CASE USED TO ASSERT THE OPPOSITE. Written for Task 57's F1, it said a directory at the
// record's name was "not damage", and so a group whose record would never read could never be
// left, restored or joined again -- the stranding R9 exists to prevent. The transient case it was
// standing in for needs a real sharing or lock violation, which sdk/cp3b holds on Windows; the rule
// that tells the two apart has its own case below.
//
// WHAT WOULD GO RED: read every failed read as transient, and this group is held for good.
func TestARecordThatCanNeverBeReadIsDamageAndItsGroupCanBeLeft(t *testing.T) {
	store := openTestStore(t, t.TempDir())
	unread := bytes.Repeat([]byte{0x51}, GroupIdBytes)
	other := bytes.Repeat([]byte{0x52}, GroupIdBytes)
	for _, groupId := range [][]byte{unread, other} {
		if err := store.PutGroupRecord(&GroupRecord{
			GroupId: groupId, PqSecret: bytes.Repeat([]byte{0x2A}, 32), GroupHandleKey: bytes.Repeat([]byte{0x5C}, 32), Epoch: 1, Opened: true,
		}); err != nil {
			t.Fatalf("PutGroupRecord: %v", err)
		}
	}
	path := store.groupRecordPath(unread)
	if err := os.Rename(path, path+".aside"); err != nil {
		t.Fatalf("moving the record aside: %v", err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatalf("standing a directory under the record's name: %v", err)
	}

	// THE ONE-ID READ: damage, and not "not read now"
	_, err := store.GroupRecord(unread)
	if !errors.Is(err, ErrGroupRecordDamaged) || errors.Is(err, ErrStateNotFound) {
		t.Fatalf("the one-id read of a record that can never be read answered %v, want ErrGroupRecordDamaged", err)
	}
	if transientRead(err) {
		t.Errorf("a record that can never be read is classed as a transient read: %v", err)
	}
	// THE LIST: the other record, and this one reported as damage, by its directory
	records, err := store.GroupRecords()
	if len(records) != 1 || !bytes.Equal(records[0].GroupId, other) {
		t.Errorf("the list answered %d record(s) beside a record that can never be read, want the other one", len(records))
	}
	if !errors.Is(err, ErrGroupRecordDamaged) || errors.Is(err, ErrGroupRecordNotReadNow) {
		t.Errorf("the list's report answered %v, want ErrGroupRecordDamaged and not ErrGroupRecordNotReadNow", err)
	} else if !strings.Contains(err.Error(), stateNameOf(unread)) || strings.Contains(err.Error(), stateNameOf(other)) {
		t.Errorf("the list's report does not name the directory that cannot be read, and that one alone: %v", err)
	}
	// THE LEAVE: the group is left, with no Restore having tried, and the other group is untouched
	device := newAnsweringDeviceOver(t, store, []byte("the device's nonce"))
	if err := device.ForgetGroup(unread); err != nil {
		t.Errorf("the leave of a group whose record can never be read answered %v, want it left", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the record's name still stands on the disk after the leave: %v", err)
	}
	if _, err := store.GroupRecord(other); err != nil {
		t.Errorf("the other group's record does not read after the leave: %v", err)
	}
}

// ONLY A SHARING OR LOCK VIOLATION IS A TRANSIENT READ (R26). [transientRead] is held over the
// errno set both ways: each of the platform's transient errnos, wrapped as the store wraps an OS
// error, is transient; every errno R26 names as permanent is not; and neither is a store error
// that carries no errno, nor an errno that is not the store's.
//
// WHAT WOULD GO RED: a classifier that calls every [ErrStateStoreState] transient, and a record
// that will never read is held for good; one that calls none transient, and F1 is back.
func TestOnlyASharingOrLockViolationIsATransientRead(t *testing.T) {
	asStore := func(errno syscall.Errno) error {
		return fmt.Errorf("%w: meta could not be read: %w", ErrStateStoreState,
			&os.PathError{Op: "open", Path: "meta", Err: errno})
	}
	if len(transientErrnos) == 0 {
		t.Fatalf("CONTROL FAILED: this platform's transient set is empty, so nothing below is held")
	}
	for _, errno := range transientErrnos {
		if !transientRead(asStore(errno)) {
			t.Errorf("errno %d (%v) is in the transient set and is not classed transient", uint(errno), errno)
		}
		if transientRead(&os.PathError{Op: "open", Path: "meta", Err: errno}) {
			t.Errorf("errno %d outside the store's sentinel is classed transient", uint(errno))
		}
	}
	for _, errno := range []syscall.Errno{syscall.EACCES, syscall.ELOOP, syscall.ENOENT, syscall.EIO, syscall.EISDIR,
		syscall.Errno(5), syscall.Errno(1)} { // 5 and 1: Windows ERROR_ACCESS_DENIED and ERROR_INVALID_FUNCTION
		if transientRead(asStore(errno)) {
			t.Errorf("errno %d (%v) is permanent and is classed transient", uint(errno), errno)
		}
	}
	if transientRead(fmt.Errorf("%w: this store is closed", ErrStateStoreState)) {
		t.Errorf("a store error that carries no errno is classed transient")
	}
}

// A DAMAGED RECORD IS SAID TO NOT READ, AND NOT TO BE ANOTHER BUILD'S (Task 57, F9). A record this
// store wrote is cut to half its length, and the refusal for it says that it does not read as a
// record this store writes. It does not say that this build did not write it, which a checksum
// cannot know and which is false here.
//
// WHAT WOULD GO RED: the old sentence, "this is not a state record this build wrote", over a record
// this build wrote one line earlier.
func TestADamagedRecordIsSaidToNotReadAndNotToBeAnotherBuilds(t *testing.T) {
	store := openTestStore(t, t.TempDir())
	groupId := bytes.Repeat([]byte{0x53}, GroupIdBytes)
	if err := store.PutGroupRecord(&GroupRecord{
		GroupId: groupId, PqSecret: bytes.Repeat([]byte{0x2A}, 32), GroupHandleKey: bytes.Repeat([]byte{0x5C}, 32), Epoch: 1, Opened: true,
	}); err != nil {
		t.Fatalf("PutGroupRecord: %v", err)
	}
	path := store.groupRecordPath(groupId)
	octets, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, octets[:len(octets)/2], 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = store.GroupRecord(groupId)
	if !errors.Is(err, ErrGroupRecordDamaged) || !errors.Is(err, ErrStateStoreFormat) {
		t.Fatalf("CONTROL FAILED: the cut record answered %v, want ErrGroupRecordDamaged carrying ErrStateStoreFormat", err)
	}
	if !strings.Contains(err.Error(), "does not read as a record this store writes") {
		t.Errorf("the refusal for a damaged record does not say that it does not read as a record this store writes: %v", err)
	}
	if strings.Contains(err.Error(), "this build wrote") {
		t.Errorf("the refusal for a record this build wrote says this build did not write it: %v", err)
	}
}
