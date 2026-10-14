package urmessage

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	messageprotocol "github.com/urnetwork/message/protocol"
)

// THE JOIN'S WINDOW, FROM OUTSIDE: what each refusal says, and what it costs. The staging store
// has its own cases in joinstage_test.go; these drive [Device.Join] itself, over stores that
// misbehave at one named call.

// windowInvite founds a group on a device of its own and adds joiner's join code: the honest
// invite, and the group id it is for.
func windowInvite(t *testing.T, joiner *Device) (*Invite, []byte) {
	t.Helper()
	ctx := context.Background()
	founder, _ := newAnsweringDevice(t, messageprotocol.Reason_REASON_OK, []byte("the founder's nonce"))
	if err := founder.Connect(ctx); err != nil {
		t.Fatalf("the founder's Connect: %v", err)
	}
	groupId := bytes.Repeat([]byte{0x47}, GroupIdBytes)
	group, err := founder.CreateGroup(ctx, groupId)
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	joinCode, err := joiner.KeyPackage()
	if err != nil {
		t.Fatalf("the joiner's KeyPackage: %v", err)
	}
	invite, err := group.AddMember(joinCode)
	if err != nil {
		t.Fatalf("AddMember: %v", err)
	}
	return invite, groupId
}

// bentInvite is a copy of an invite with one thing changed.
func bentInvite(invite *Invite, change func(*Invite)) *Invite {
	bent := &Invite{
		GroupId:     bytes.Clone(invite.GroupId),
		Welcome:     bytes.Clone(invite.Welcome),
		RatchetTree: bytes.Clone(invite.RatchetTree),
		JoinSeal:    bytes.Clone(invite.JoinSeal),
		JoinAuth:    bytes.Clone(invite.JoinAuth),
	}
	change(bent)
	return bent
}

// EVERY REFUSAL INSIDE THE JOIN'S WINDOW BEGINS WITH ONE SENTENCE, AND COSTS NOTHING. Three
// refusals, made at the three places the window can refuse: the engine (a Welcome for another
// group), this package's own checks (a join seal whose authenticator is not a member's), and the
// create-only commit (a state already held at the joined epoch). Each answers [ErrJoinRefused] and begins with
// its sentence; none answers [ErrJoinCodeSpent]; the device holds no group; and the honest invite
// then joins OVER THE SAME JOIN CODE, which is what "not spent" means.
//
// ONE REFUSAL INSIDE THE WINDOW DOES NOT CARRY THE SENTENCE, AND MUST NOT: an invite whose join
// code is ALREADY GONE. It is driven both ways a join code goes with no group to show for it (a
// join whose record could not be written, and a refusal whose put-back failed), each of which said
// [ErrJoinCodeSpent] once; the SAME honest invite pasted again then answers
// [ErrNoJoinCodeForInvite], which does not say the join code is not spent, because it is.
//
// THE CONTROL is a refusal made BEFORE the window, which must not carry the sentence: a sentence
// every refusal carried would say nothing about where the join code is.
//
// WHAT WOULD GO RED: return a cause from inside the window without the deferred exit, or hand the
// engine the store and not the stage, and a row's honest invite no longer joins; or give the
// window's sentence to an invite whose join code is gone, and an app tells a person to ask for an
// invitation again that can never be joined.
func TestEveryRefusalInsideTheJoinWindowSaysTheJoinCodeIsNotSpent(t *testing.T) {
	ctx := context.Background()
	orphan := []byte("an epoch state with no record: a join whose record did not persist")
	for _, one := range []struct {
		name   string
		bend   func(*Invite)
		plant  bool
		within error
	}{
		{"a welcome for another group, refused by the engine",
			func(invite *Invite) { invite.GroupId = bytes.Repeat([]byte{0x5D}, GroupIdBytes) }, false, nil},
		{"a join seal whose authenticator has one bit flipped, refused by this package",
			func(invite *Invite) { invite.JoinAuth[0] ^= 0x01 }, false, ErrJoinSealUnauthenticated},
		{"a state already held at the joined epoch, refused by the commit",
			func(invite *Invite) {}, true, ErrJoinWouldOverwrite},
	} {
		store := NewMemoryStateStore()
		joiner := newAnsweringDeviceOver(t, store, []byte("the joiner's nonce"))
		honest, groupId := windowInvite(t, joiner)
		if one.plant {
			if err := store.PutGroupState(groupId, 1, orphan); err != nil {
				t.Fatalf("%s: planting the orphan state: %v", one.name, err)
			}
		}
		_, err := joiner.Join(ctx, bentInvite(honest, one.bend))
		if !errors.Is(err, ErrJoinRefused) {
			t.Errorf("%s answered %v, want ErrJoinRefused", one.name, err)
			continue
		}
		if !strings.HasPrefix(err.Error(), ErrJoinRefused.Error()+": ") {
			t.Errorf("%s answered %q, which does not BEGIN with the window's sentence", one.name, err)
		}
		if errors.Is(err, ErrJoinCodeSpent) {
			t.Errorf("%s also answers ErrJoinCodeSpent: %v", one.name, err)
		}
		if one.within != nil && !errors.Is(err, one.within) {
			t.Errorf("%s answered %v, which does not carry its cause %v", one.name, err, one.within)
		}
		if held := len(joiner.Groups()); held != 0 {
			t.Errorf("%s left the joiner holding %d group(s)", one.name, held)
		}
		kept, stateErr := store.GetGroupState(groupId, 1)
		switch {
		case one.plant && !bytes.Equal(kept, orphan):
			t.Errorf("%s: the state the store already held reads %q, %v after the refusal", one.name, kept, stateErr)
		case !one.plant && !errors.Is(stateErr, ErrStateNotFound):
			t.Errorf("%s left a state in the store for the group it refused: %v", one.name, stateErr)
		}
		// THE JOIN CODE IS NOT SPENT: the honest invite joins over the same one
		if one.plant {
			if err := store.DeleteGroupStateBefore(groupId, 2); err != nil {
				t.Fatalf("%s: removing the orphan state: %v", one.name, err)
			}
		}
		if _, err := joiner.Join(ctx, honest); err != nil {
			t.Errorf("%s: the honest invite after the refusal answered %v, so the refusal spent the join code", one.name, err)
		}
	}

	// THE ROW THAT IS NOT LIKE THE OTHERS: an invite whose join code is already gone
	for _, one := range []struct {
		name  string
		spend func(t *testing.T) (*Device, *Invite, func())
	}{
		{"after a join whose record could not be written", func(t *testing.T) (*Device, *Invite, func()) {
			durable, err := OpenDurableStateStore(t.TempDir())
			if err != nil {
				t.Fatalf("OpenDurableStateStore: %v", err)
			}
			t.Cleanup(func() { durable.Close() })
			store := &recordSink{DurableStateStore: durable}
			joiner := newAnsweringDeviceOver(t, store, []byte("the joiner's nonce"))
			honest, _ := windowInvite(t, joiner)
			store.armed = true
			_, err = joiner.Join(ctx, honest)
			if !errors.Is(err, ErrJoinCodeSpent) {
				t.Fatalf("CONTROL FAILED: the join whose record could not be written answered %v, want ErrJoinCodeSpent", err)
			}
			return joiner, honest, func() { store.armed = false }
		}},
		{"after a refusal whose put-back failed", func(t *testing.T) (*Device, *Invite, func()) {
			store := &keyPackageSink{MemoryStateStore: NewMemoryStateStore()}
			joiner := newAnsweringDeviceOver(t, store, []byte("the joiner's nonce"))
			honest, _ := windowInvite(t, joiner)
			store.armed = true
			_, err := joiner.Join(ctx, bentInvite(honest, func(invite *Invite) { invite.GroupId = bytes.Repeat([]byte{0x5D}, GroupIdBytes) }))
			if !errors.Is(err, ErrJoinCodeSpent) {
				t.Fatalf("CONTROL FAILED: the refusal whose put-back failed answered %v, want ErrJoinCodeSpent", err)
			}
			return joiner, honest, func() { store.armed = false }
		}},
	} {
		joiner, honest, heal := one.spend(t)
		heal()
		_, err := joiner.Join(ctx, honest)
		if !errors.Is(err, ErrNoJoinCodeForInvite) {
			t.Errorf("the same invite again, %s, answered %v, want ErrNoJoinCodeForInvite", one.name, err)
			continue
		}
		if errors.Is(err, ErrJoinRefused) || strings.Contains(err.Error(), "the join code is not spent") {
			t.Errorf("the same invite again, %s, says the join code is not spent, and it is gone: %v", one.name, err)
		}
		if !strings.HasPrefix(err.Error(), ErrNoJoinCodeForInvite.Error()+": ") {
			t.Errorf("the same invite again, %s, answered %q, which does not BEGIN with the sentence an app reads", one.name, err)
		}
		if errors.Is(err, ErrJoinCodeSpent) {
			t.Errorf("the same invite again, %s, says THIS join spent the join code, and it was gone before it: %v", one.name, err)
		}
		if held := len(joiner.Groups()); held != 0 {
			t.Errorf("the same invite again, %s, left the joiner holding %d group(s)", one.name, held)
		}
	}

	// THE CONTROL: a refusal made before the window does not carry the window's sentence
	joiner := newAnsweringDeviceOver(t, NewMemoryStateStore(), []byte("the joiner's nonce"))
	honest, _ := windowInvite(t, joiner)
	if _, err := joiner.Join(ctx, honest); err != nil {
		t.Fatalf("CONTROL: the honest invite: %v", err)
	}
	if _, err := joiner.Join(ctx, honest); !errors.Is(err, ErrGroupAlreadyHeld) || errors.Is(err, ErrJoinRefused) {
		t.Errorf("CONTROL FAILED: an invite into a held group answered %v, want ErrGroupAlreadyHeld and not the window's sentence", err)
	}
}

// keyPackageSink is a memory store that will not take a key package back once it is armed.
type keyPackageSink struct {
	*MemoryStateStore
	armed bool
}

func (self *keyPackageSink) PutKeyPackage(ref []byte, kp []byte, initPriv []byte, encPriv []byte) error {
	if self.armed {
		return errors.New("the store this test sits on will not take a key package")
	}
	return self.MemoryStateStore.PutKeyPackage(ref, kp, initPriv, encPriv)
}

// A REFUSAL WHOSE PUT-BACK FAILS SAYS THE JOIN CODE IS SPENT, AND DOES NOT SAY IT IS NOT. It is the
// first of the two ways a join costs its join code, and both of the roads to it are driven: a
// refusal this package makes, and a refusal the engine makes, whose own put-back fails first.
//
// WHAT WOULD GO RED: discard the abort's error, and a join code the store did not take back is
// reported as one that is still good.
func TestARefusalThatCannotPutTheJoinCodeBackSaysItIsSpent(t *testing.T) {
	ctx := context.Background()
	for _, one := range []struct {
		name string
		bend func(*Invite)
	}{
		{"this package's refusal", func(invite *Invite) { invite.JoinAuth[0] ^= 0x01 }},
		{"the engine's refusal", func(invite *Invite) { invite.GroupId = bytes.Repeat([]byte{0x5D}, GroupIdBytes) }},
	} {
		store := &keyPackageSink{MemoryStateStore: NewMemoryStateStore()}
		joiner := newAnsweringDeviceOver(t, store, []byte("the joiner's nonce"))
		honest, _ := windowInvite(t, joiner)
		store.armed = true
		_, err := joiner.Join(ctx, bentInvite(honest, one.bend))
		if !errors.Is(err, ErrJoinCodeSpent) {
			t.Errorf("%s, with a store that takes no key package back, answered %v, want ErrJoinCodeSpent", one.name, err)
		}
		if errors.Is(err, ErrJoinRefused) {
			t.Errorf("%s says the join code is not spent although it could not be put back: %v", one.name, err)
		}
		if held := len(joiner.Groups()); held != 0 {
			t.Errorf("%s left the joiner holding %d group(s)", one.name, held)
		}
		// THE CONTROL: it IS spent. With the store working again the honest invite does not join.
		store.armed = false
		if _, err := joiner.Join(ctx, honest); err == nil {
			t.Errorf("CONTROL FAILED: %s: the honest invite joined afterwards, so the join code was never lost and nothing above is about a failed put-back", one.name)
		}
	}
}

// recordSink is a durable store that will not write a group record once it is armed.
type recordSink struct {
	*DurableStateStore
	armed bool
}

func (self *recordSink) PutGroupRecord(record *GroupRecord) error {
	if self.armed {
		return errors.New("the store this test sits on will not write a group record")
	}
	return self.DurableStateStore.PutGroupRecord(record)
}

// A JOIN WHOSE RECORD CANNOT BE WRITTEN SAYS THE JOIN CODE IS SPENT. It is the second way, and the
// only one that is past the window: every check passed, the joined state was committed, and the
// record that a restart would come back through then could not be written.
//
// WHAT WOULD GO RED: answer that failure without [ErrJoinCodeSpent], and an app tells a person
// whose join code is gone to paste the same invitation again.
func TestAJoinWhoseRecordCannotBeWrittenSaysTheJoinCodeIsSpent(t *testing.T) {
	ctx := context.Background()
	durable, err := OpenDurableStateStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenDurableStateStore: %v", err)
	}
	t.Cleanup(func() { durable.Close() })
	store := &recordSink{DurableStateStore: durable}
	joiner := newAnsweringDeviceOver(t, store, []byte("the joiner's nonce"))
	honest, groupId := windowInvite(t, joiner)
	store.armed = true
	_, err = joiner.Join(ctx, honest)
	if !errors.Is(err, ErrJoinCodeSpent) {
		t.Fatalf("a join whose record could not be written answered %v, want ErrJoinCodeSpent", err)
	}
	if errors.Is(err, ErrJoinRefused) {
		t.Errorf("it also says the join code is not spent: %v", err)
	}
	if held := len(joiner.Groups()); held != 0 {
		t.Errorf("the device holds %d group(s) after a join that did not complete", held)
	}
	// what "past the window" means: the joined state did reach the store
	if _, err := durable.GetGroupState(groupId, 1); err != nil {
		t.Errorf("CONTROL FAILED: the store holds no state for the joined epoch (%v), so this failure was inside the window and not after it", err)
	}
}
