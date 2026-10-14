package urmessage

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// unreadKeyPackageStore is a durable store that fails to read the join codes it holds, while it
// is armed, as a disk that will not hand a file over does. The join code stays on the disk.
type unreadKeyPackageStore struct {
	*DurableStateStore
	armed bool
}

func (self *unreadKeyPackageStore) TakeKeyPackage(ref []byte) ([]byte, []byte, []byte, error) {
	if self.armed {
		return nil, nil, nil, errors.New("the store this test sits on would not hand the join code over this time")
	}
	return self.DurableStateStore.TakeKeyPackage(ref)
}

// A JOIN CODE THE STORE FAILED TO READ IS NOT A MISSING ONE (Task 57, F4; the red team's
// measurement (d), kept as the regression it found). The joiner's store holds the join code an
// honest invite was made for and fails to read it once. The join is refused with the window's
// sentence, which says the join code is still good, and it is: the same invite, pasted again once
// the store reads, joins. THE OTHER HALF is the store's not-found, which keeps its own sentence:
// an invite made for another device's join code answers [ErrNoJoinCodeForInvite].
//
// WHAT WOULD GO RED: lose the store's refusal's type in the engine (%v), or answer every engine
// refusal "no join code", and a person whose join code is on the disk is told to make a new one.
func TestAJoinCodeTheStoreFailedToReadIsStillGoodAndOneItDoesNotHoldIsNot(t *testing.T) {
	ctx := context.Background()
	store := &unreadKeyPackageStore{DurableStateStore: openTestStore(t, t.TempDir())}
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
