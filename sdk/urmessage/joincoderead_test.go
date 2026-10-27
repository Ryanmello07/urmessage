package urmessage

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
	"testing"
)

// unreadKeyPackageStore is a durable store whose take of the join codes it holds fails, while it
// is armed, with the error it is armed with. The join code stays on the disk.
type unreadKeyPackageStore struct {
	*DurableStateStore
	armed    bool
	failWith error
}

func (self *unreadKeyPackageStore) TakeKeyPackage(ref []byte) ([]byte, []byte, []byte, error) {
	if self.armed {
		return nil, nil, nil, self.failWith
	}
	return self.DurableStateStore.TakeKeyPackage(ref)
}

// heldKeyPackage is the error the durable store answers for a key-package file another process
// holds for a moment: its own sentinel, wrapping the platform's sharing violation.
func heldKeyPackage() error {
	return fmt.Errorf("%w: the key package could not be read: %w", ErrStateStoreState,
		&os.PathError{Op: "open", Path: "kp", Err: transientErrnos[0]})
}

// A JOIN CODE THE STORE FAILED TO READ IS NOT A MISSING ONE (Task 57, F4; the red team's
// measurement (d), kept as the regression it found). The joiner's store holds the join code an
// honest invite was made for and fails to read it once, FOR A MOMENT: another process holds the
// file (R26: the failure is a sharing violation; it used to be a bare error, which R26's
// classifier now reads as permanent, and that case has its own test below). The join is refused with the window's
// sentence, which says the join code is still good, and it is: the same invite, pasted again once
// the store reads, joins. THE OTHER HALF is the store's not-found, which keeps its own sentence:
// an invite made for another device's join code answers [ErrNoJoinCodeForInvite].
//
// WHAT WOULD GO RED: lose the store's refusal's type in the engine (%v), or answer every engine
// refusal "no join code", and a person whose join code is on the disk is told to make a new one.
func TestAJoinCodeTheStoreFailedToReadIsStillGoodAndOneItDoesNotHoldIsNot(t *testing.T) {
	ctx := context.Background()
	store := &unreadKeyPackageStore{DurableStateStore: openTestStore(t, t.TempDir()), failWith: heldKeyPackage()}
	joiner := newAnsweringDeviceOver(t, store, []byte("the joiner's nonce"))
	testIdentify(t, joiner)
	honest, _ := windowInvite(t, joiner)

	store.armed = true
	_, err := joiner.Join(ctx, honest)
	if !errors.Is(err, ErrJoinRefused) || errors.Is(err, ErrNoJoinCodeForInvite) || errors.Is(err, ErrJoinCodeSpent) {
		t.Errorf("an invite whose join code the store failed to read answered %v, want ErrJoinRefused and neither ErrNoJoinCodeForInvite nor ErrJoinCodeSpent", err)
	} else if !strings.HasPrefix(err.Error(), ErrJoinRefused.Error()+": ") {
		t.Errorf("the refusal %q does not BEGIN with the sentence an app reads", err)
	}
	store.armed = false
	if _, err := joiner.Join(ctx, honest); err != nil {
		t.Errorf("the same invite, once the store reads, answered %v: the sentence that said the join code is still good was false", err)
	}

	// THE OTHER HALF: no join code of this device's was the invite made for
	other := newAnsweringDeviceOver(t, NewMemoryStateStore(), []byte("another device's nonce"))
	testIdentify(t, other)
	elsewhere, _ := windowInvite(t, other)
	stranger := newAnsweringDeviceOver(t, openTestStore(t, t.TempDir()), []byte("a stranger's nonce"))
	testIdentify(t, stranger)
	_, err = stranger.Join(ctx, elsewhere)
	if !errors.Is(err, ErrNoJoinCodeForInvite) || errors.Is(err, ErrJoinRefused) {
		t.Errorf("an invite made for another device's join code answered %v, want ErrNoJoinCodeForInvite and not ErrJoinRefused", err)
	}
}

// A FAILED TAKE OF A JOIN CODE GETS THE SENTENCE THAT IS TRUE OF IT, AND AN UNPROVEN ONE IS STILL
// GOOD (R26, the fix review's V3; R33's X1). Failed takes of the join code an honest invite was
// made for, each with the sentence that is true of it:
//   - a read this build cannot prove will pass -- a permission refused (the shape of a deny ACL),
//     the medium, a store failure with no errno, too many open files: nothing was removed, so the
//     join code is NOT spent, and the window's sentence is true: the same invite joins once the
//     store reads it. THIS ROW WAS CHANGED BY R33's X1: it said "no join code", and the round-3
//     review put a real deny ACL on a join code, was told to make a new one, and joined with the
//     same invite once the deny was lifted;
//   - the store holds no such join code (the file absent): no join code. An absence that erases
//     nothing answers "nothing is there" (R33 (1)), and a new join code makes it true;
//   - a record whose octets are damaged: no join code, for the same reason;
//   - a take that removed the file and then failed (its directory sync): the join code is SPENT,
//     since nothing will put it back.
//
// WHAT WOULD GO RED: answer an unproven take "no join code", and a person whose join code is on
// the disk is told to make a new one; or answer every store refusal "the join code is not spent",
// and a person is told to paste an invitation that can never join again.
func TestAJoinCodeThatWillNeverReadOrWasRemovedIsNotSaidToBeStillGood(t *testing.T) {
	ctx := context.Background()
	asTake := func(errno syscall.Errno) error {
		return fmt.Errorf("%w: the key package could not be read: %w", ErrStateStoreState,
			&os.PathError{Op: "open", Path: "kp", Err: errno})
	}
	for _, one := range []struct {
		name     string
		failWith error
		want     error
	}{
		{"a permission refused", asTake(syscall.EACCES), ErrJoinRefused},
		{"the medium", asTake(syscall.EIO), ErrJoinRefused},
		{"too many open files", asTake(tooManyOpenFiles()), ErrJoinRefused},
		{"a store failure with no errno", fmt.Errorf("%w: the key package could not be read", ErrStateStoreState), ErrJoinRefused},
		{"no such join code", fmt.Errorf("%w: kp", ErrStateNotFound), ErrNoJoinCodeForInvite},
		{"a record whose octets are damaged", fmt.Errorf("%w: the record's checksum is not the hash of the record",
			ErrStateStoreFormat), ErrNoJoinCodeForInvite},
		{"a take whose remove landed", fmt.Errorf("%w: %w: the directory could not be synced", errKeyPackageRemoved,
			ErrStateStoreState), ErrJoinCodeSpent},
	} {
		store := &unreadKeyPackageStore{DurableStateStore: openTestStore(t, t.TempDir()), failWith: one.failWith}
		joiner := newAnsweringDeviceOver(t, store, []byte("the joiner's nonce"))
		testIdentify(t, joiner)
		honest, _ := windowInvite(t, joiner)
		store.armed = true
		_, err := joiner.Join(ctx, honest)
		others := 0
		for _, sentinel := range []error{ErrJoinRefused, ErrNoJoinCodeForInvite, ErrJoinCodeSpent} {
			if sentinel != one.want && errors.Is(err, sentinel) {
				others += 1
			}
		}
		if !errors.Is(err, one.want) || others != 0 {
			t.Errorf("%s answered %v, want %v and neither of the other two", one.name, err, one.want)
		} else if !strings.HasPrefix(err.Error(), one.want.Error()+": ") {
			t.Errorf("%s answered %q, which does not BEGIN with the sentence an app reads", one.name, err)
		}
		if held := len(joiner.Groups()); held != 0 {
			t.Errorf("%s left the joiner holding %d group(s)", one.name, held)
		}
		// AND THE SENTENCE IS TRUE: a join code said to be still good joins, once the store reads
		if one.want == ErrJoinRefused {
			store.armed = false
			if _, err := joiner.Join(ctx, honest); err != nil {
				t.Errorf("%s: the same invite, once the store reads, answered %v: the sentence that said the join code is still good was false", one.name, err)
			}
		}
	}
}
