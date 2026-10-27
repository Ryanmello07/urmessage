package cp3b

import (
	"bytes"
	"errors"
	"path/filepath"
	"testing"

	"github.com/urnetwork/message/messagegroup"
	"github.com/urnetwork/message/sdk"
	"github.com/urnetwork/message/sdk/urmessage"
)

// readdRecordSink is a durable store that will not write a group record while it is armed.
type readdRecordSink struct {
	*urmessage.DurableStateStore
	armed bool
}

func (self *readdRecordSink) PutGroupRecord(record *urmessage.GroupRecord) error {
	if self.armed {
		return errors.New("the store this test sits on will not write a group record")
	}
	return self.DurableStateStore.PutGroupRecord(record)
}

// readdSinkPersona is [world.newPersona] over a [readdRecordSink], so a case can make one join's
// record fail to write.
func (self *world) readdSinkPersona(t *testing.T, name string) (*persona, *readdRecordSink) {
	t.Helper()
	root := t.TempDir()
	stateDir, streamDir := filepath.Join(root, name, "state"), filepath.Join(root, name, "stream")
	client := self.connectClient(t)
	transport := self.transport(t, client)
	streamStore, err := sdk.OpenStreamStore(streamDir)
	if err != nil {
		t.Fatalf("%s: sdk.OpenStreamStore: %v", name, err)
	}
	durable, err := urmessage.OpenDurableStateStore(stateDir)
	if err != nil {
		streamStore.Close()
		t.Fatalf("%s: urmessage.OpenDurableStateStore: %v", name, err)
	}
	sink := &readdRecordSink{DurableStateStore: durable}
	device, err := urmessage.NewDevice(urmessage.DeviceConfig{
		PhraseStretch: messagegroup.FastPhraseStretchForTests(),
		Transport:     transport,
		Reserver:      sdk.NewStreamIndexReserver(streamStore),
		StateStore:    sink,
	})
	if err != nil {
		durable.Close()
		streamStore.Close()
		t.Fatalf("%s: urmessage.NewDevice: %v", name, err)
	}
	current := &persona{
		name: name, stateDir: stateDir, streamDir: streamDir,
		client: client, transport: transport,
		streamStore: streamStore, stateStore: durable, device: device,
	}
	t.Cleanup(current.kill)
	self.identify(t, name, device)
	return current, sink
}

// A RE-ADD THAT FAILS AFTER ITS COMMIT KEEPS THE REMOVED GROUP'S EPOCHS AND RECORD (R26, the fix
// review's V4a). Carol is in alice's group and is removed; alice adds her back, and carol's join
// commits and then cannot write its record. The join answers [urmessage.ErrJoinCodeSpent] and
// erases the epoch it committed, and NOTHING ELSE: every file the removed group had on carol's
// disk is there afterwards, byte for byte, and nothing else is.
//
// WHAT WOULD GO RED: a failed join that erases every epoch at or below the one it joined, and the
// removed group's history, and its record's ground, go with the join that failed.
func TestAReaddThatFailsAfterItsCommitKeepsTheRemovedGroupsEpochsAndRecord(t *testing.T) {
	scene := advFounding(t, true)
	carol, sink := scene.world.readdSinkPersona(t, "carol")
	carolGroup := hsAddAndJoin(t, scene.ctx, scene.aliceGroup, carol)
	if err := scene.aliceGroup.RemoveMember(scene.ctx, rolesIdentityOf(t, carolGroup)); err != nil {
		t.Fatalf("alice's RemoveMember of carol: %v", err)
	}
	if _, err := carolGroup.Receive(scene.ctx); !errors.Is(err, urmessage.ErrRemovedFromGroup) {
		t.Fatalf("CONTROL FAILED: the removed device's Receive answered %v, want ErrRemovedFromGroup", err)
	}
	before := advGroupFiles(t, carol.stateDir, scene.groupId)
	if len(before["meta"]) == 0 {
		t.Fatalf("CONTROL FAILED: carol holds no record of the removed group")
	}
	epochs := 0
	for name := range before {
		if filepath.Dir(name) == "epoch" {
			epochs += 1
		}
	}
	if epochs == 0 {
		t.Fatalf("CONTROL FAILED: carol holds no epoch state of the removed group")
	}

	keyPackage, err := carol.device.KeyPackage()
	if err != nil {
		t.Fatalf("carol's KeyPackage: %v", err)
	}
	invite, err := scene.aliceGroup.AddMemberAndPublish(scene.ctx, keyPackage)
	if err != nil {
		t.Fatalf("alice's re-add of carol: %v", err)
	}
	sink.armed = true
	_, err = carol.device.Join(scene.ctx, gcReencodeInvite(t, invite))
	sink.armed = false
	if !errors.Is(err, urmessage.ErrJoinCodeSpent) {
		t.Fatalf("a re-add whose record could not be written answered %v, want ErrJoinCodeSpent", err)
	}
	after := advGroupFiles(t, carol.stateDir, scene.groupId)
	for name, content := range before {
		if !bytes.Equal(after[name], content) {
			t.Errorf("the failed re-add changed or took %s of the removed group", name)
		}
	}
	for name := range after {
		if _, was := before[name]; !was {
			t.Errorf("the failed re-add left %s behind", name)
		}
	}
	t.Logf("the removed group's %d file(s), %d of them epoch states, stood through the failed re-add", len(before), epochs)
}
