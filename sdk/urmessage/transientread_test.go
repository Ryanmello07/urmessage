package urmessage

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

// A RECORD WHOSE FILE COULD NOT BE READ JUST NOW IS NOT DAMAGE (Task 57, F1), at the store and at
// the device, on every platform. Two groups' records are on the disk, and one of them is made
// unreadable without touching its octets: the file is moved aside and a directory stands under its
// name, so a read of it fails with an I/O error and not with "not found" -- the shape a file another
// process holds has on Windows, where sdk/cp3b drives the real lock.
//
// Then: the one-id read answers the store's own failure and not damage; the list answers the other
// record and reports this one apart, as not read NOW; a leave of the group is refused and writes
// nothing; a Restore reports it the same way; and once the file is back, the group is one no Restore
// has tried, as it was. THE CONTROL is R9's other half, which stands: a record whose octets are
// damaged is still left without a Restore and without the owner's question.
//
// WHAT WOULD GO RED: wrap a failed read as [ErrGroupRecordDamaged], and the leave made while the
// file could not be read erases the group, owner's question unasked.
func TestARecordThatCannotBeReadJustNowIsNotDamageAndNothingIsLeftOverIt(t *testing.T) {
	ctx := context.Background()
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
	aside := path + ".aside"
	if err := os.Rename(path, aside); err != nil {
		t.Fatalf("moving the record aside: %v", err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatalf("standing a directory under the record's name: %v", err)
	}
	release := func() {
		if err := os.Remove(path); err != nil {
			t.Fatalf("removing the directory: %v", err)
		}
		if err := os.Rename(aside, path); err != nil {
			t.Fatalf("putting the record back: %v", err)
		}
	}

	// THE ONE-ID READ: the store could not answer, which is not damage and not "none"
	_, err := store.GroupRecord(unread)
	if !errors.Is(err, ErrStateStoreState) || errors.Is(err, ErrGroupRecordDamaged) || errors.Is(err, ErrStateNotFound) {
		t.Fatalf("the one-id read of a record that cannot be read answered %v, want ErrStateStoreState and neither ErrGroupRecordDamaged nor ErrStateNotFound", err)
	}
	// THE LIST: the other record, and this one reported apart, by its directory
	records, err := store.GroupRecords()
	if len(records) != 1 || !bytes.Equal(records[0].GroupId, other) {
		t.Errorf("the list answered %d record(s) beside a record that cannot be read, want the other one", len(records))
	}
	if !errors.Is(err, ErrGroupRecordNotReadNow) || errors.Is(err, ErrGroupRecordDamaged) {
		t.Errorf("the list's report answered %v, want ErrGroupRecordNotReadNow and not ErrGroupRecordDamaged", err)
	} else if !strings.Contains(err.Error(), stateNameOf(unread)) || strings.Contains(err.Error(), stateNameOf(other)) {
		t.Errorf("the list's report does not name the directory that could not be read, and that one alone: %v", err)
	}

	// THE LEAVE: refused, and nothing was written
	device := newAnsweringDeviceOver(t, store, []byte("the device's nonce"))
	err = device.ForgetGroup(unread)
	t.Logf("the leave of a group whose record cannot be read: %v", err)
	if err == nil || errors.Is(err, ErrForgetUnfinished) || errors.Is(err, ErrGroupNotHeld) || errors.Is(err, ErrGroupNotRestored) {
		t.Errorf("the leave answered %v, want a refusal that changed nothing", err)
	} else if !strings.Contains(err.Error(), "could not be read, so nothing was left") {
		t.Errorf("the leave's refusal does not say that nothing was left: %v", err)
	}
	if marked, err := store.GroupBeingForgotten(unread); err != nil || marked {
		t.Errorf("the refused leave left a leave mark: %v, %v", marked, err)
	}
	if _, err := os.Stat(aside); err != nil {
		t.Errorf("the refused leave took the record: %v", err)
	}
	// THE RESTORE: reported as not read now, and not as damage
	_, err = device.Restore(ctx)
	if !errors.Is(err, ErrRestore) || !errors.Is(err, ErrGroupRecordNotReadNow) || errors.Is(err, ErrGroupRecordDamaged) {
		t.Errorf("the Restore answered %v, want ErrRestore and ErrGroupRecordNotReadNow, and not ErrGroupRecordDamaged", err)
	}

	// ONCE THE FILE READS AGAIN, the group is one no Restore has tried, as it was
	release()
	if err := device.ForgetGroup(unread); !errors.Is(err, ErrGroupNotRestored) {
		t.Errorf("the leave once the record reads again answered %v, want ErrGroupNotRestored", err)
	}

	// THE CONTROL, R9's other half: a record whose octets are damaged is left without a Restore
	octets, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the record: %v", err)
	}
	if err := os.WriteFile(path, octets[:len(octets)/2], 0o600); err != nil {
		t.Fatalf("cutting the record to half its length: %v", err)
	}
	if _, err := store.GroupRecord(unread); !errors.Is(err, ErrGroupRecordDamaged) {
		t.Fatalf("CONTROL FAILED: the cut record answered %v, want ErrGroupRecordDamaged", err)
	}
	if err := device.ForgetGroup(unread); err != nil {
		t.Errorf("CONTROL FAILED: the leave of a group whose record is damaged answered %v, want it left", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("CONTROL FAILED: the damaged record is still on the disk after the leave: %v", err)
	}
}
