package urmessage

import (
	"bytes"
	"context"
	"errors"
	"testing"

	messageprotocol "github.com/urnetwork/message/protocol"
)

// THE HELD-GROUP GATE, at the device: an invite into a group this device holds is refused before
// the join code is touched, whoever built it, and the group it holds is the same object afterwards.
func TestAnInviteIntoAGroupThisDeviceHoldsIsRefused(t *testing.T) {
	ctx := context.Background()
	alice, _ := newAnsweringDevice(t, messageprotocol.Reason_REASON_OK, []byte("alice's nonce"))
	bob, _ := newAnsweringDevice(t, messageprotocol.Reason_REASON_OK, []byte("bob's nonce"))
	mallory, _ := newAnsweringDevice(t, messageprotocol.Reason_REASON_OK, []byte("mallory's nonce"))
	for _, device := range []*Device{alice, bob, mallory} {
		if err := device.Connect(ctx); err != nil {
			t.Fatalf("Connect: %v", err)
		}
	}
	groupId := bytes.Repeat([]byte{0x47}, GroupIdBytes)
	add := func(founder *Device) *Invite {
		group, err := founder.CreateGroup(ctx, groupId)
		if err != nil {
			t.Fatalf("CreateGroup: %v", err)
		}
		joinCode, err := bob.KeyPackage()
		if err != nil {
			t.Fatalf("bob's KeyPackage: %v", err)
		}
		invite, err := group.AddMember(joinCode)
		if err != nil {
			t.Fatalf("AddMember: %v", err)
		}
		return invite
	}
	honest := add(alice)
	held, err := bob.Join(ctx, honest)
	if err != nil {
		t.Fatalf("bob's Join over the honest invite: %v", err)
	}

	// the same invite again, and then a hostile founder's invite under the same group id
	if _, err := bob.Join(ctx, honest); !errors.Is(err, ErrGroupAlreadyHeld) {
		t.Errorf("the same invite a second time answered %v, want ErrGroupAlreadyHeld", err)
	}
	if _, err := bob.Join(ctx, add(mallory)); !errors.Is(err, ErrGroupAlreadyHeld) {
		t.Errorf("a second founder's invite under a held group id answered %v, want ErrGroupAlreadyHeld", err)
	}
	groups := bob.Groups()
	if len(groups) != 1 || groups[0] != held {
		t.Fatalf("bob holds %d group(s) after two refused invites, and the one it joined is no longer among them", len(groups))
	}
	if epoch := held.Epoch(); epoch != 1 {
		t.Errorf("the held group stands at epoch %d after two refused invites, want 1", epoch)
	}
}

// A MAP ENTRY IS REPLACED ONLY BY THE JOIN THAT JUDGED IT. hold never replaces, and holdReplacing
// replaces the one group it is told the gate judged and no other. Both are the second line behind
// the admission mutex: what they refuse cannot happen while every admission is inside that mutex,
// and this is the case that says they do refuse it.
//
// WHAT WOULD GO RED: let either write the map without looking, which is what both did before, and
// a group nobody judged takes the place of a live one.
func TestAMapEntryIsReplacedOnlyByTheJoinThatJudgedIt(t *testing.T) {
	ctx := context.Background()
	device, _ := newAnsweringDevice(t, messageprotocol.Reason_REASON_OK, []byte("a nonce"))
	if err := device.Connect(ctx); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	groupId := bytes.Repeat([]byte{0x47}, GroupIdBytes)
	held, err := device.CreateGroup(ctx, groupId)
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	incoming := &Group{id: bytes.Clone(groupId)}
	bystander := &Group{id: bytes.Clone(groupId)}
	for _, one := range []struct {
		name string
		file func() error
	}{
		{"hold, over a live group", func() error { return device.hold(incoming) }},
		{"holdReplacing, judged against no group", func() error { return device.holdReplacing(incoming, nil) }},
		{"holdReplacing, judged against some other group", func() error { return device.holdReplacing(incoming, bystander) }},
	} {
		if err := one.file(); !errors.Is(err, ErrGroupAlreadyHeld) {
			t.Errorf("%s answered %v, want ErrGroupAlreadyHeld", one.name, err)
		}
		if groups := device.Groups(); len(groups) != 1 || groups[0] != held {
			t.Fatalf("%s: the device no longer holds the group it held", one.name)
		}
	}

	// THE CONTROL: judged against the group that IS there, it replaces it and closes it.
	if err := device.holdReplacing(incoming, held); err != nil {
		t.Fatalf("CONTROL FAILED: holdReplacing judged against the held group answered %v", err)
	}
	if groups := device.Groups(); len(groups) != 1 || groups[0] != incoming {
		t.Fatalf("CONTROL FAILED: the device does not hold the group that replaced the held one")
	}
	held.mutex.Lock()
	closed := held.closed
	held.mutex.Unlock()
	if !closed {
		t.Errorf("the replaced group was left open: its session and its epoch's secrets are still live")
	}
	// the stand-in has no session to close, so it leaves the map before the device closes
	device.drop(groupId, incoming)
}

// NOTHING IS FOUNDED UNDER AN ID THIS DEVICE HOLDS. Founding writes an epoch-zero state under the
// id and files a group in the map, so a second founding under one id is the first group replaced.
func TestNoGroupIsFoundedUnderAnIdThisDeviceHolds(t *testing.T) {
	ctx := context.Background()
	device, _ := newAnsweringDevice(t, messageprotocol.Reason_REASON_OK, []byte("a nonce"))
	if err := device.Connect(ctx); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	groupId := bytes.Repeat([]byte{0x47}, GroupIdBytes)
	held, err := device.CreateGroup(ctx, groupId)
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	before, err := device.stateStore.GetGroupState(groupId, 0)
	if err != nil || len(before) == 0 {
		t.Fatalf("CONTROL FAILED: the store holds no epoch-zero state for the group just founded: %v", err)
	}
	before = bytes.Clone(before)
	if _, err := device.CreateGroup(ctx, groupId); !errors.Is(err, ErrGroupAlreadyHeld) {
		t.Fatalf("a second founding under a held id answered %v, want ErrGroupAlreadyHeld", err)
	}
	if groups := device.Groups(); len(groups) != 1 || groups[0] != held {
		t.Fatalf("the device no longer holds the group it founded first")
	}
	// REFUSED BEFORE THE MLS GROUP WAS MADE, which is the half the map cannot show: a founding
	// refused only at the hold has already written a second group's epoch zero over the first's.
	if after, err := device.stateStore.GetGroupState(groupId, 0); err != nil || !bytes.Equal(after, before) {
		t.Fatalf("the refused founding replaced the held group's epoch-zero state in the store (%v)", err)
	}
	// THE CONTROL: any other id founds
	if _, err := device.CreateGroup(ctx, bytes.Repeat([]byte{0x48}, GroupIdBytes)); err != nil {
		t.Fatalf("CONTROL FAILED: founding under an id the device does not hold answered %v", err)
	}
}
