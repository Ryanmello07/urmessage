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
	elsewhere, _ := windowInvite(t, other)
	stranger := newAnsweringDeviceOver(t, openTestStore(t, t.TempDir()), []byte("a stranger's nonce"))
	_, err = stranger.Join(ctx, elsewhere)
	if !errors.Is(err, ErrNoJoinCodeForInvite) || errors.Is(err, ErrJoinRefused) {
		t.Errorf("an invite made for another device's join code answered %v, want ErrNoJoinCodeForInvite and not ErrJoinRefused", err)
	}
}

// A JOIN CODE THAT WILL NEVER READ, OR THAT A TAKE REMOVED, IS NOT SAID TO BE STILL GOOD (R26, the
// fix review's V3). Three failed takes of the join code an honest invite was made for, each with
// the sentence that is true of it:
//   - a read this build cannot prove will pass (a deny ACL; R30 calls it unproven, and only a
//     sharing or lock violation is the window's "still good"): no join code, which is the sentence
//     a new join code makes true whatever happens to the old one;
//   - a record whose octets are damaged: no join code, for the same reason;
//   - a take that removed the file and then failed (its directory sync): the join code is SPENT,
//     since nothing will put it back.
//
// WHAT WOULD GO RED: answer every store refusal but not-found "the join code is not spent", and a
// person is told to paste an invitation that can never join again.
func TestAJoinCodeThatWillNeverReadOrWasRemovedIsNotSaidToBeStillGood(t *testing.T) {
	ctx := context.Background()
	for _, one := range []struct {
		name     string
		failWith error
		want     error
	}{
		{"a read this build cannot prove will pass", fmt.Errorf("%w: the key package could not be read: %w", ErrStateStoreState,
			&os.PathError{Op: "open", Path: "kp", Err: syscall.EACCES}), ErrNoJoinCodeForInvite},
		{"a record whose octets are damaged", fmt.Errorf("%w: the record's checksum is not the hash of the record",
			ErrStateStoreFormat), ErrNoJoinCodeForInvite},
		{"a take whose remove landed", fmt.Errorf("%w: %w: the directory could not be synced", errKeyPackageRemoved,
			ErrStateStoreState), ErrJoinCodeSpent},
	} {
		store := &unreadKeyPackageStore{DurableStateStore: openTestStore(t, t.TempDir()), failWith: one.failWith}
		joiner := newAnsweringDeviceOver(t, store, []byte("the joiner's nonce"))
		honest, _ := windowInvite(t, joiner)
		store.armed = true
		_, err := joiner.Join(ctx, honest)
		if !errors.Is(err, one.want) || errors.Is(err, ErrJoinRefused) {
			t.Errorf("%s answered %v, want %v and not ErrJoinRefused", one.name, err, one.want)
		} else if !strings.HasPrefix(err.Error(), one.want.Error()+": ") {
			t.Errorf("%s answered %q, which does not BEGIN with the sentence an app reads", one.name, err)
		}
		if held := len(joiner.Groups()); held != 0 {
			t.Errorf("%s left the joiner holding %d group(s)", one.name, held)
		}
	}
}
