package urmessage

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
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
	if classifyRead(err) != readPermanent {
		t.Errorf("a record that can never be read is not classed proven permanent: %v", err)
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

// ONLY A SHARING OR LOCK VIOLATION IS A TRANSIENT READ (R26). [classifyRead]'s transient class is
// held over the errno set both ways: each of the platform's transient errnos, wrapped as the store
// wraps an OS error, is transient; every errno R26 names as permanent is not; and neither is a
// store error that carries no errno, nor an errno that is not the store's.
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
		if classifyRead(asStore(errno)) != readTransient {
			t.Errorf("errno %d (%v) is in the transient set and is not classed transient", uint(errno), errno)
		}
		if classifyRead(&os.PathError{Op: "open", Path: "meta", Err: errno}) == readTransient {
			t.Errorf("errno %d outside the store's sentinel is classed transient", uint(errno))
		}
	}
	for _, errno := range []syscall.Errno{syscall.EACCES, syscall.ELOOP, syscall.ENOENT, syscall.EIO, syscall.EISDIR,
		syscall.Errno(5), syscall.Errno(1)} { // 5 and 1: Windows ERROR_ACCESS_DENIED and ERROR_INVALID_FUNCTION
		if classifyRead(asStore(errno)) == readTransient {
			t.Errorf("errno %d (%v) is permanent and is classed transient", uint(errno), errno)
		}
	}
	if classifyRead(fmt.Errorf("%w: this store is closed", ErrStateStoreState)) == readTransient {
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

// A WRONG-TYPE CODE IS PROOF ONLY BESIDE THE TYPE IT CLAIMS (R36, item 4: the round-5 review's L2).
// Each of this platform's wrong-type errnos ([permanentErrnos]) is answered for a group's record, as
// the store's read carries one:
//   - with the RECORD ITSELF standing there, a regular file and intact -- what a WinFsp or Dokan mount
//     (rclone, Cryptomator, SSHFS-Win) or a minifilter answers ERROR_INVALID_FUNCTION for -- the
//     store's own Lstat confirms nothing, and the failure is UNPROVEN;
//   - with a DIRECTORY standing at the record's name, the Lstat confirms the type, and the failure is
//     proven permanent, as the store's own read of that directory is, end to end: a group whose
//     record can never be read stays one a device can leave;
//   - with nothing standing there, nothing confirms it.
//
// AND A NAME THAT CANNOT BE ASKED ABOUT is judged by the nearest name above it, inside the store's
// directory: a file standing where the store keeps a group's `epoch` folder confirms a code answered
// for an epoch state below it, and that folder standing as a folder confirms nothing.
//
// WHAT WOULD GO RED: a wrong-type code taken for proof without the Lstat -- an owner's intact group
// erased without the owner's question, over a mount type.
func TestAWrongTypeCodeIsProofOnlyBesideTheTypeItClaims(t *testing.T) {
	store := openTestStore(t, t.TempDir())
	groupId := bytes.Repeat([]byte{0x79}, GroupIdBytes)
	if err := store.PutGroupRecord(&GroupRecord{
		GroupId: groupId, PqSecret: bytes.Repeat([]byte{0x2A}, 32), GroupHandleKey: bytes.Repeat([]byte{0x5C}, 32), Epoch: 1, Opened: true,
	}); err != nil {
		t.Fatalf("PutGroupRecord: %v", err)
	}
	if len(permanentErrnos) == 0 {
		t.Fatalf("CONTROL FAILED: this platform's wrong-type set is empty, so nothing below is held")
	}
	carried := func(path string, errno syscall.Errno) error {
		cause := store.confirmWrongType(path, false, &os.PathError{Op: "read", Path: path, Err: errno})
		return fmt.Errorf("%w: %s could not be read: %w", ErrStateStoreState, path, cause)
	}
	record := store.groupRecordPath(groupId)

	// THE RECORD ITSELF, intact
	if _, err := store.GroupRecord(groupId); err != nil {
		t.Fatalf("CONTROL FAILED: the record does not read: %v", err)
	}
	for _, errno := range permanentErrnos {
		if got := classifyRead(carried(record, errno)); got != readUnproven {
			t.Errorf("errno %d (%v), answered for an intact regular file at the record's name, is classed %d, want unproven", uint(errno), errno, got)
		}
	}

	// A DIRECTORY at the record's name
	if err := os.Rename(record, record+".aside"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(record, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, errno := range permanentErrnos {
		if got := classifyRead(carried(record, errno)); got != readPermanent {
			t.Errorf("errno %d (%v), answered for a directory at the record's name, is classed %d, want proven permanent", uint(errno), errno, got)
		}
	}
	if _, err := store.GroupRecord(groupId); !errors.Is(err, ErrGroupRecordDamaged) || classifyRead(err) != readPermanent {
		t.Errorf("the store's own read of a directory at the record's name answered %v, want damage, proven permanent", err)
	}

	// NOTHING at the record's name
	if err := os.Remove(record); err != nil {
		t.Fatal(err)
	}
	for _, errno := range permanentErrnos {
		if got := classifyRead(carried(record, errno)); got != readUnproven {
			t.Errorf("errno %d (%v), answered for a name nothing stands at, is classed %d, want unproven", uint(errno), errno, got)
		}
	}

	// THE NEAREST NAME ABOVE: a file where the `epoch` folder goes, and then that folder as a folder
	state := filepath.Join(store.epochDir(groupId), stateEpochName(1))
	if err := os.WriteFile(store.epochDir(groupId), []byte("a file where the epoch folder goes"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := classifyRead(carried(state, permanentErrnos[0])); got != readPermanent {
		t.Errorf("a wrong-type code below a file standing where the epoch folder goes is classed %d, want proven permanent", got)
	}
	if err := os.Remove(store.epochDir(groupId)); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(store.epochDir(groupId), 0o700); err != nil {
		t.Fatal(err)
	}
	if got := classifyRead(carried(state, permanentErrnos[0])); got != readUnproven {
		t.Errorf("a wrong-type code below an epoch folder that is a folder is classed %d, want unproven", got)
	}
	// and never above the store's own directory
	outside := filepath.Join(t.TempDir(), "a file", "below it")
	if err := os.WriteFile(filepath.Dir(outside), []byte("not the store's"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := classifyRead(carried(outside, permanentErrnos[0])); got != readUnproven {
		t.Errorf("a wrong-type code below a file outside the store's directory is classed %d, want unproven", got)
	}
}

// irregularInfo is an Lstat answer of one type, for the store's injected Lstat.
type irregularInfo struct {
	name string
	mode os.FileMode
}

func (self irregularInfo) Name() string       { return self.name }
func (self irregularInfo) Size() int64        { return 0 }
func (self irregularInfo) Mode() os.FileMode  { return self.mode }
func (self irregularInfo) ModTime() time.Time { return time.Time{} }
func (self irregularInfo) IsDir() bool        { return self.mode.IsDir() }
func (self irregularInfo) Sys() any           { return nil }

// A TYPE GO REPORTS AS IRREGULAR NEVER CONFIRMS A WRONG-TYPE CODE (R38, item 2, amending R36's item 4;
// on every platform, through the store's injected Lstat, since nothing off Windows makes such a type).
// A cloud placeholder is the store's own file, dehydrated, and Go reports it as irregular, as it does
// a WOF-compressed file, a junction, a mount point and every reparse tag it does not name. For each of
// the six wrong-type codes -- Windows 1, 267 and 1921, and EISDIR, ELOOP and ENOTDIR -- carried as the
// store carries a read's failure, the classifier answers UNPROVEN beside an irregular type: at a name
// the store writes a file at, at a name it keeps a directory at, and as the nearest name above one
// that cannot be asked about; a directory reparse point (irregular and a directory) included.
//
// THE CONTROLS, so the injected Lstat is what decides: beside a PLAIN directory where the store
// writes a file, a PLAIN regular file where it keeps a directory, or a symbolic link, each of this
// platform's own wrong-type codes is proven permanent; and the six codes include every one of them.
//
// WHAT WOULD GO RED: an irregular type taken for a wrong type again -- an owner's group erased without
// the owner's question over a placeholder whose filter answered ERROR_INVALID_FUNCTION.
func TestAnIrregularTypeNeverConfirmsAWrongTypeCode(t *testing.T) {
	store := openTestStore(t, t.TempDir())
	groupId := bytes.Repeat([]byte{0x7F}, GroupIdBytes)
	six := []syscall.Errno{syscall.Errno(1), syscall.Errno(267), syscall.Errno(1921), syscall.EISDIR, syscall.ELOOP, syscall.ENOTDIR}
	for _, errno := range permanentErrnos {
		found := false
		for _, one := range six {
			found = found || one == errno
		}
		if !found {
			t.Fatalf("CONTROL FAILED: this platform's wrong-type errno %d (%v) is not among the six this case holds", uint(errno), errno)
		}
	}
	file := store.groupRecordPath(groupId)
	folder := store.sentDir(groupId)
	below := filepath.Join(store.epochDir(groupId), stateEpochName(1))
	classed := func(path string, wantDir bool, errno syscall.Errno, answers map[string]os.FileMode) readClass {
		store.lstat = func(name string) (os.FileInfo, error) {
			if mode, stands := answers[name]; stands {
				return irregularInfo{name: filepath.Base(name), mode: mode}, nil
			}
			return nil, &os.PathError{Op: "lstat", Path: name, Err: os.ErrNotExist}
		}
		defer func() { store.lstat = nil }()
		cause := store.confirmWrongType(path, wantDir, &os.PathError{Op: "read", Path: path, Err: errno})
		return classifyRead(fmt.Errorf("%w: %s could not be read: %w", ErrStateStoreState, path, cause))
	}
	for _, one := range []struct {
		name    string
		path    string
		wantDir bool
		answers map[string]os.FileMode
	}{
		{"an irregular file at a name the store writes a file at", file, false, map[string]os.FileMode{file: os.ModeIrregular}},
		{"a directory reparse point at a name the store writes a file at", file, false, map[string]os.FileMode{file: os.ModeIrregular | os.ModeDir}},
		{"an irregular file at a name the store keeps a directory at", folder, true, map[string]os.FileMode{folder: os.ModeIrregular}},
		{"a directory reparse point at a name the store keeps a directory at", folder, true, map[string]os.FileMode{folder: os.ModeIrregular | os.ModeDir}},
		{"an irregular file as the nearest name above one that cannot be asked about", below, false, map[string]os.FileMode{filepath.Dir(below): os.ModeIrregular}},
	} {
		for _, errno := range six {
			if got := classed(one.path, one.wantDir, errno, one.answers); got != readUnproven {
				t.Errorf("%s, errno %d (%v): classed %d, want unproven", one.name, uint(errno), errno, got)
			}
		}
	}
	// THE CONTROLS
	for _, one := range []struct {
		name    string
		path    string
		wantDir bool
		answers map[string]os.FileMode
	}{
		{"a plain directory at a name the store writes a file at", file, false, map[string]os.FileMode{file: os.ModeDir}},
		{"a plain regular file at a name the store keeps a directory at", folder, true, map[string]os.FileMode{folder: 0}},
		{"a symbolic link at a name the store writes a file at", file, false, map[string]os.FileMode{file: os.ModeSymlink}},
		{"a plain regular file as the nearest name above", below, false, map[string]os.FileMode{filepath.Dir(below): 0}},
	} {
		for _, errno := range permanentErrnos {
			if got := classed(one.path, one.wantDir, errno, one.answers); got != readPermanent {
				t.Errorf("CONTROL FAILED: %s, errno %d (%v): classed %d, want proven permanent", one.name, uint(errno), errno, got)
			}
		}
	}
}
