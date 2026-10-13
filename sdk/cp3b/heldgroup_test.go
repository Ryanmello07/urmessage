package cp3b

import (
	"bytes"
	"errors"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/urnetwork/message/sdk"
	"github.com/urnetwork/message/sdk/urmessage"
)

// THE HELD-GROUP GATE AGAINST THE REAL SERVER: the cases the adversary scenarios cannot hold,
// because each needs something a scenario does not have. Two admissions that overlap need a store
// that says where each of them is; the stale re-add needs a removal at one epoch and an invitation
// below it; and the group that does not restore, and the one whose record does not read, need
// each of ForgetGroup's answers read.

// gateWatch is a durable store that says when an ADMISSION reads the disk, and holds that read
// where it stands until it is let go. Two reads are watched, and every other method is the
// store's own: the one-id read the held-group gate and a founding make, and the first read a
// Restore makes, which is for the leaves it has to finish. It is how a case puts one join INSIDE
// the gate and then starts a second admission, with no sleep deciding who got where.
type gateWatch struct {
	*urmessage.DurableStateStore
	armed   atomic.Bool
	asked   chan struct{}
	release chan struct{}
}

func (self *gateWatch) hold() {
	if self.armed.Load() {
		self.asked <- struct{}{}
		<-self.release
	}
}

func (self *gateWatch) GroupRecord(groupId []byte) (*urmessage.GroupRecord, error) {
	self.hold()
	return self.DurableStateStore.GroupRecord(groupId)
}

func (self *gateWatch) GroupsBeingForgotten() ([][]byte, error) {
	self.hold()
	return self.DurableStateStore.GroupsBeingForgotten()
}

// watchedDevice is a device over a gateWatch, against the world's real server.
func watchedDevice(t *testing.T, world *world, name string) (*urmessage.Device, *gateWatch) {
	t.Helper()
	root := t.TempDir()
	client := world.connectClient(t)
	transport := world.transport(t, client)
	streamStore, err := sdk.OpenStreamStore(filepath.Join(root, name, "stream"))
	if err != nil {
		t.Fatalf("%s: sdk.OpenStreamStore: %v", name, err)
	}
	inner, err := urmessage.OpenDurableStateStore(filepath.Join(root, name, "state"))
	if err != nil {
		t.Fatalf("%s: urmessage.OpenDurableStateStore: %v", name, err)
	}
	watch := &gateWatch{DurableStateStore: inner, asked: make(chan struct{}, 8), release: make(chan struct{})}
	device, err := urmessage.NewDevice(urmessage.DeviceConfig{
		Transport:  transport,
		Reserver:   sdk.NewStreamIndexReserver(streamStore),
		StateStore: watch,
	})
	if err != nil {
		t.Fatalf("%s: urmessage.NewDevice: %v", name, err)
	}
	t.Cleanup(func() {
		device.Close()
		inner.Close()
		streamStore.Close()
		transport.Close()
		client.Close()
	})
	return device, watch
}

// TWO JOINS INTO ONE GROUP ID THAT OVERLAP ADMIT EXACTLY ONE. The honest invitation is a live add,
// at epoch 2; the other is a second founder's group under the same id, at epoch 1. They stand at
// two epochs on purpose: the create-only commit refuses a second join only at an epoch the first
// already wrote, so at two epochs the gate is the only thing in the way.
//
// THE ORDER IS FORCED AND NOT TIMED. The first join is stopped inside the gate, at its reading of
// the disk. The second is then started. If it too reaches the gate while the first is still in it,
// both have read "not held" and the case fails there, by name. If it does not, it is waiting for
// the first, which is let go; the second then finds the group held.
//
// WHAT WOULD GO RED: ask the gate above the admission mutex, and both joins are in the gate at
// once; whichever writes its record second writes over the first.
func TestTwoJoinsIntoOneGroupIdThatOverlapAdmitExactlyOne(t *testing.T) {
	scene := advFounding(t, true)
	dave, watch := watchedDevice(t, scene.world, "dave")
	if err := dave.Connect(scene.ctx); err != nil {
		t.Fatalf("dave's Connect: %v", err)
	}
	joinCode, err := dave.KeyPackage()
	if err != nil {
		t.Fatalf("dave's KeyPackage: %v", err)
	}
	added, err := scene.aliceGroup.AddMemberAndPublish(scene.ctx, joinCode)
	if err != nil {
		t.Fatalf("alice's AddMemberAndPublish: %v", err)
	}
	honest := gcReencodeInvite(t, added)
	hostile, err := urmessage.ParseInvite(advHostile(t, scene, dave))
	if err != nil {
		t.Fatalf("the second founder's invite does not parse: %v", err)
	}

	type answer struct {
		group *urmessage.Group
		err   error
	}
	first, second := make(chan answer, 1), make(chan answer, 1)
	watch.armed.Store(true)
	go func() {
		group, err := dave.Join(scene.ctx, honest)
		first <- answer{group, err}
	}()
	select {
	case <-watch.asked:
	case <-time.After(10 * time.Second):
		t.Fatal("the first join never reached the gate's reading of the disk, so nothing below is about two joins")
	}
	go func() {
		group, err := dave.Join(scene.ctx, hostile)
		second <- answer{group, err}
	}()
	select {
	case <-watch.asked:
		t.Errorf("the second join reached the held-group gate while the first was still inside it: both have read \"not held\"")
	case <-time.After(500 * time.Millisecond):
		// the second join is waiting for the first, which is the property
	}
	watch.armed.Store(false)
	close(watch.release)
	honestAnswer, hostileAnswer := <-first, <-second

	if honestAnswer.err != nil {
		t.Fatalf("the honest invite, which was first, answered %v", honestAnswer.err)
	}
	if !errors.Is(hostileAnswer.err, urmessage.ErrGroupAlreadyHeld) {
		t.Errorf("the second founder's invite, which overlapped the first, answered %v, want ErrGroupAlreadyHeld", hostileAnswer.err)
	}
	if held := dave.Groups(); len(held) != 1 || held[0] != honestAnswer.group {
		t.Fatalf("dave holds %d group(s) and the one the honest invite joined is not the one he holds", len(held))
	}
	// THE DISK, which is where the second join's damage would be: one record, at the honest epoch
	records, err := watch.DurableStateStore.GroupRecords()
	if err != nil || len(records) != 1 {
		t.Fatalf("dave's store holds %d record(s): %v", len(records), err)
	}
	if !bytes.Equal(records[0].GroupId, scene.groupId) || records[0].Epoch != 2 {
		t.Fatalf("dave's record names epoch %d, and the honest invite joined epoch 2: the second join wrote its record over the first's", records[0].Epoch)
	}
	// and the group he holds is the real one: it reads what the real founder seals next
	canary := scene.say(t, "alice", scene.aliceGroup)
	gcReceiveText(t, scene.ctx, "dave", honestAnswer.group, canary)
}

// overlapping puts one join INSIDE the held-group gate and then starts a second admission. Dave is
// added to the scene's group by a live add; his join of that invitation is started and is stopped
// at the gate's reading of the disk, where it holds the admission mutex; `second` is then started.
// It answers whether the second admission ALSO reached a reading of the disk while the join was
// still inside, which is two admissions in one critical section. Both are then let go, and it
// returns when both have returned, with the join's own answer.
func overlapping(t *testing.T, scene *advJoin, second func(dave *urmessage.Device)) (dave *urmessage.Device, joined *urmessage.Group, joinErr error, overlapped bool) {
	t.Helper()
	dave, watch := watchedDevice(t, scene.world, "dave")
	if err := dave.Connect(scene.ctx); err != nil {
		t.Fatalf("dave's Connect: %v", err)
	}
	joinCode, err := dave.KeyPackage()
	if err != nil {
		t.Fatalf("dave's KeyPackage: %v", err)
	}
	added, err := scene.aliceGroup.AddMemberAndPublish(scene.ctx, joinCode)
	if err != nil {
		t.Fatalf("alice's AddMemberAndPublish: %v", err)
	}
	honest := gcReencodeInvite(t, added)
	done := make(chan struct{}, 2)
	watch.armed.Store(true)
	go func() {
		joined, joinErr = dave.Join(scene.ctx, honest)
		done <- struct{}{}
	}()
	select {
	case <-watch.asked:
	case <-time.After(10 * time.Second):
		t.Fatal("the join never reached the gate's reading of the disk, so nothing below is about two admissions")
	}
	go func() {
		second(dave)
		done <- struct{}{}
	}()
	select {
	case <-watch.asked:
		overlapped = true
	case <-time.After(500 * time.Millisecond):
		// the second admission is waiting for the join, which is the property
	}
	watch.armed.Store(false)
	close(watch.release)
	<-done
	<-done
	return dave, joined, joinErr, overlapped
}

// A RESTORE THAT STARTS WHILE A JOIN IS INSIDE THE GATE WAITS FOR IT. Restore puts groups onto the
// device as a join does, so it is an admission and takes the same mutex. Outside it, a join judged
// against "not held" can meet a group Restore filed meanwhile, and is then refused at the hold,
// AFTER its state and its record were written.
//
// THE ORDER IS FORCED, as in the case above. The join is stopped inside the gate, and Restore is
// then started; the first thing it does under the mutex is read the disk for leaves to finish,
// which the same store watches.
//
// WHAT WOULD GO RED: take the admission mutex away from Restore, and it reads the disk while the
// join is still between its question and its hold.
func TestARestoreThatOverlapsAJoinWaitsForIt(t *testing.T) {
	scene := advFounding(t, true)
	var restored []*urmessage.Group
	var restoreErr error
	dave, joined, joinErr, overlapped := overlapping(t, scene, func(dave *urmessage.Device) {
		restored, restoreErr = dave.Restore(scene.ctx)
	})
	if overlapped {
		t.Fatalf("Restore read the disk while a join was still inside the held-group gate: two admissions are in one critical section")
	}
	if joinErr != nil {
		t.Fatalf("the join, which was first, answered %v", joinErr)
	}
	// IT WAITED, SO IT SAW WHAT THE JOIN LEFT: the group is held, and there is nothing to restore
	if restoreErr != nil || len(restored) != 0 {
		t.Errorf("the Restore that waited answered %d group(s) and %v, want none and no error: the join had filed the group before it looked", len(restored), restoreErr)
	}
	if held := dave.Groups(); len(held) != 1 || held[0] != joined {
		t.Fatalf("dave holds %d group(s) and the one the join filed is not the one he holds", len(held))
	}
	canary := scene.say(t, "alice", scene.aliceGroup)
	gcReceiveText(t, scene.ctx, "dave", joined, canary)
}

// A FOUNDING THAT STARTS WHILE A JOIN IS INSIDE THE GATE WAITS FOR IT, AND THEN FINDS THE GROUP
// HELD. The founding is under the id the join is admitting, which is the case the mutex is for:
// outside it both read "not held", and the founding's epoch zero is written under an id a join
// is staging.
//
// WHAT WOULD GO RED: take the admission mutex away from CreateGroup, and its question reaches the
// disk while the join is still between its own question and its hold.
func TestAFoundingThatOverlapsAJoinWaitsForItAndFindsTheGroupHeld(t *testing.T) {
	scene := advFounding(t, true)
	var foundErr error
	dave, joined, joinErr, overlapped := overlapping(t, scene, func(dave *urmessage.Device) {
		_, foundErr = dave.CreateGroup(scene.ctx, scene.groupId)
	})
	if overlapped {
		t.Fatalf("a founding asked the disk about its group id while a join into that id was still inside the held-group gate: both have read \"not held\"")
	}
	if joinErr != nil {
		t.Fatalf("the join, which was first, answered %v", joinErr)
	}
	if !errors.Is(foundErr, urmessage.ErrGroupAlreadyHeld) {
		t.Errorf("the founding that waited answered %v, want ErrGroupAlreadyHeld: the join had filed the group before it asked", foundErr)
	}
	if held := dave.Groups(); len(held) != 1 || held[0] != joined {
		t.Fatalf("dave holds %d group(s) and the one the join filed is not the one he holds", len(held))
	}
	canary := scene.say(t, "alice", scene.aliceGroup)
	gcReceiveText(t, scene.ctx, "dave", joined, canary)
}

// A RE-ADD AT OR BELOW THE EPOCH OF THE REMOVAL IS REFUSED, AND THE REAL RE-ADD STILL JOINS. The
// victim joined at epoch 2 and was removed there, so a second founder's invitation at epoch 1
// stands BELOW the removal and at an epoch the victim holds no state for: nothing on its disk is
// in the way of it, and this rule is the only thing that refuses it.
//
// WHAT WOULD GO RED: drop the comparison of the joined epoch with the removal's, and the stale
// invitation joins and replaces the removed group.
func TestAReaddBelowTheRemovalIsRefusedAndTheRealReaddStillJoins(t *testing.T) {
	scene := advFounding(t, true)
	carol := scene.world.newPersona(t, "carol")
	carolGroup := hsAddAndJoin(t, scene.ctx, scene.aliceGroup, carol)
	if err := scene.aliceGroup.RemoveMember(scene.ctx, rolesIdentityOf(t, carolGroup)); err != nil {
		t.Fatalf("alice's RemoveMember of carol: %v", err)
	}
	if _, err := carolGroup.Receive(scene.ctx); !errors.Is(err, urmessage.ErrRemovedFromGroup) {
		t.Fatalf("CONTROL FAILED: the removed device's Receive answered %v, want ErrRemovedFromGroup", err)
	}
	removedAt, removal := carolGroup.Removal()
	if removal == nil || removedAt != 2 {
		t.Fatalf("CONTROL FAILED: carol reads (%d, %v) from Removal, want (2, non-nil)", removedAt, removal)
	}

	stale, err := urmessage.ParseInvite(advHostile(t, scene, carol.device))
	if err != nil {
		t.Fatalf("the second founder's invite does not parse: %v", err)
	}
	before := advGroupFiles(t, carol.stateDir, scene.groupId)
	if _, held := before["epoch/0000000000000001"]; held {
		t.Fatalf("CONTROL FAILED: carol holds a state at epoch 1, so something other than the re-add rule could refuse this")
	}
	if _, err := carol.device.Join(scene.ctx, stale); !errors.Is(err, urmessage.ErrReaddStale) {
		t.Fatalf("an invitation at epoch 1 over a group carol was removed from at epoch %d answered %v, want ErrReaddStale", removedAt, err)
	}
	after := advGroupFiles(t, carol.stateDir, scene.groupId)
	for name, content := range before {
		if !bytes.Equal(after[name], content) {
			t.Errorf("the refused invitation changed %s of the removed group", name)
		}
	}
	held := carol.device.Groups()
	if len(held) != 1 || held[0] != carolGroup {
		t.Fatalf("carol holds %d group(s) after the refused invitation, and the removed group is not the one she holds", len(held))
	}
	if _, removal := carolGroup.Removal(); removal == nil {
		t.Fatalf("the removed group no longer reads as removed after an invitation that was refused")
	}

	// THE CONTROL, and the other half of the rule: the founder's own re-add, a later commit, joins.
	rejoined := removalAdd(t, scene.ctx, "alice", scene.aliceGroup, carol.device, "carol")
	if epoch := rejoined.Epoch(); epoch <= removedAt {
		t.Fatalf("the re-added group stands at epoch %d and the removal was at %d", epoch, removedAt)
	}
	if _, removal := rejoined.Removal(); removal != nil {
		t.Fatalf("the re-added group still reads as removed: %v", removal)
	}
}

// FORGETGROUP OVER A GROUP THAT IS ON THE DISK AND NOT IN MEMORY ANSWERS BY WHAT RESTORE SAID. A
// group no Restore has tried is not left: the owner's question is asked of a live group, and a
// device that has merely restarted is not let past it. A group Restore could not bring back is
// left, record and all, and after that the device holds nothing under the id.
//
// WHAT WOULD GO RED: refuse the group that did not restore, and a record is on the disk for good,
// refusing every invitation into it; or leave any group that is on the disk, and a restart is a
// way round the owner's refusal.
func TestForgetGroupOverAGroupOnTheDiskAnswersByWhatRestoreSaid(t *testing.T) {
	scene := advFounding(t, true)
	scene.bob.kill()
	if err := advRemoveEpochStates(scene.bob.stateDir, scene.groupId); err != nil {
		t.Fatalf("removing bob's epoch states: %v", err)
	}
	bob := scene.world.durablePersona(t, scene.bob.name, scene.bob.stateDir, scene.bob.streamDir)
	if err := bob.device.Connect(scene.ctx); err != nil {
		t.Fatalf("the restarted bob's Connect: %v", err)
	}

	// BEFORE ANY RESTORE: on the disk, and not left
	if err := bob.device.ForgetGroup(scene.groupId); !errors.Is(err, urmessage.ErrGroupNotRestored) {
		t.Fatalf("ForgetGroup of a group no Restore has tried answered %v, want ErrGroupNotRestored", err)
	}
	if record := advGroupFiles(t, bob.stateDir, scene.groupId)["meta"]; len(record) == 0 {
		t.Fatalf("a ForgetGroup that was refused erased the group's record")
	}

	// AFTER A RESTORE THAT COULD NOT BRING IT BACK: left, and nothing of it stays
	restored, err := bob.device.Restore(scene.ctx)
	if len(restored) != 0 || !errors.Is(err, urmessage.ErrRestore) {
		t.Fatalf("CONTROL FAILED: Restore answered %d group(s) and %v, want none and ErrRestore", len(restored), err)
	}
	if err := bob.device.ForgetGroup(scene.groupId); err != nil {
		t.Fatalf("ForgetGroup of a group Restore could not bring back: %v", err)
	}
	if files := advGroupFiles(t, bob.stateDir, scene.groupId); len(files) != 0 {
		t.Fatalf("the group still has %d file(s) on the disk after it was left", len(files))
	}

	// AND AFTER THAT: nothing is held under the id
	if err := bob.device.ForgetGroup(scene.groupId); !errors.Is(err, urmessage.ErrGroupNotHeld) {
		t.Fatalf("ForgetGroup of a group already left answered %v, want ErrGroupNotHeld", err)
	}
}

// FORGETGROUP LEAVES A GROUP WHOSE RECORD DOES NOT READ, AND THAT GROUP ALONE. No Restore has to
// try first: the read ForgetGroup makes of that one record is the attempt, a record that does not
// read never restores, and there is no roster to ask the owner's question of. It is the remedy the
// gate's refusal of an invitation into such a group names, so it has to work when nothing else
// about the group does.
//
// AND IT IS ONE GROUP'S ANSWER. Bob holds a second group whose record reads. With the first
// group's record damaged beside it, that second group is still a group no Restore has tried, and
// is not left.
//
// WHAT WOULD GO RED: refuse the damaged group, and it can be neither restored, left nor joined
// again; or ask the store for every record to answer about one, and the damaged record of one
// group is the answer for the other.
func TestForgetGroupLeavesAGroupWhoseRecordDoesNotReadAndThatGroupAlone(t *testing.T) {
	scene := advFounding(t, true)
	carol := scene.world.newPersona(t, "carol")
	if err := carol.device.Connect(scene.ctx); err != nil {
		t.Fatalf("carol's Connect: %v", err)
	}
	otherId := newGroupId(t)
	openPair(t, scene.ctx, carol, scene.bob, otherId)
	scene.bob.kill()
	advDamageRecord(t, scene.bob.stateDir, scene.groupId)
	bob := scene.world.durablePersona(t, scene.bob.name, scene.bob.stateDir, scene.bob.streamDir)
	if err := bob.device.Connect(scene.ctx); err != nil {
		t.Fatalf("the restarted bob's Connect: %v", err)
	}
	if _, err := bob.stateStore.GroupRecord(scene.groupId); !errors.Is(err, urmessage.ErrGroupRecordDamaged) {
		t.Fatalf("CONTROL FAILED: bob's record of the first group answers %v, so this is not a record that does not read", err)
	}
	if _, err := bob.stateStore.GroupRecord(otherId); err != nil {
		t.Fatalf("CONTROL FAILED: bob's record of the second group answers %v, and it is the one that reads", err)
	}
	if len(advGroupFiles(t, bob.stateDir, scene.groupId)) < 2 {
		t.Fatalf("CONTROL FAILED: the damaged group has nothing on the disk but its record, so the erase below would be of one file")
	}

	// THE OTHER GROUP FIRST: its record reads and no Restore has tried it, so it is not left
	whole := advGroupFiles(t, bob.stateDir, otherId)
	if err := bob.device.ForgetGroup(otherId); !errors.Is(err, urmessage.ErrGroupNotRestored) {
		t.Fatalf("ForgetGroup of a group whose record reads, beside another group's damaged record, answered %v, want ErrGroupNotRestored", err)
	}
	if after := advGroupFiles(t, bob.stateDir, otherId); len(after) != len(whole) {
		t.Fatalf("a ForgetGroup that was refused left %d of the group's %d file(s)", len(after), len(whole))
	}

	// THE DAMAGED GROUP, BEFORE ANY RESTORE: left, and nothing of it stays
	if err := bob.device.ForgetGroup(scene.groupId); err != nil {
		t.Fatalf("ForgetGroup of a group whose record does not read, before any Restore: %v", err)
	}
	if files := advGroupFiles(t, bob.stateDir, scene.groupId); len(files) != 0 {
		t.Fatalf("the damaged group still has %d file(s) on the disk after it was left", len(files))
	}
	if err := bob.device.ForgetGroup(scene.groupId); !errors.Is(err, urmessage.ErrGroupNotHeld) {
		t.Fatalf("ForgetGroup of a group already left answered %v, want ErrGroupNotHeld", err)
	}
	// and the Restore that follows brings the other group back and has nothing to report
	restored, err := bob.device.Restore(scene.ctx)
	if err != nil || len(restored) != 1 || !bytes.Equal(restored[0].Id(), otherId) {
		t.Fatalf("Restore after the damaged group was left answered %d group(s) and %v, want the other group and no error", len(restored), err)
	}
}
