package cp3b

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/urnetwork/message/sdk/urmessage"
)

// quarantineOwner is alice, the OWNER of a group bob is in, restarted over her own disk and
// connected, not yet restored; her group's directory; and the group's files, as they were.
func quarantineOwner(t *testing.T) (*persona, []byte, string, map[string][]byte) {
	t.Helper()
	world := newWorld(t)
	alice := world.newPersona(t, "alice")
	bob := world.newPersona(t, "bob")
	for _, who := range []*persona{alice, bob} {
		if err := who.device.Connect(t.Context()); err != nil {
			t.Fatalf("%s's Connect: %v", who.name, err)
		}
	}
	groupId := newGroupId(t)
	openPair(t, t.Context(), alice, bob, groupId)
	alice = world.restart(t, alice)
	if err := alice.device.Connect(t.Context()); err != nil {
		t.Fatalf("the restarted alice's Connect: %v", err)
	}
	sum := sha256.Sum256(groupId)
	dir := filepath.Join(alice.stateDir, "state", "group", hex.EncodeToString(sum[:]))
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		t.Fatalf("CONTROL FAILED: alice's group directory is not at %s: %v", dir, err)
	}
	return alice, groupId, dir, advGroupFiles(t, alice.stateDir, groupId)
}

// quarantine moves one file of the group out of its folder and into one of the case's own, as an
// antivirus quarantine, a sync tool or a backup tool does, and answers the call that puts it back.
// Nothing is injected: every read the store makes meets the disk as it is.
func quarantine(t *testing.T, dir string, name string) func() {
	t.Helper()
	path := filepath.Join(dir, filepath.FromSlash(name))
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("CONTROL FAILED: %s is not in the group's folder, so moving it away moves nothing: %v", name, err)
	}
	away := filepath.Join(t.TempDir(), "quarantined-"+filepath.Base(path))
	if err := os.Rename(path, away); err != nil {
		t.Fatalf("moving %s away: %v", name, err)
	}
	return func() {
		t.Helper()
		if err := os.Rename(away, path); err != nil {
			t.Fatalf("putting %s back: %v", name, err)
		}
	}
}

// quarantineUnchanged fails the case unless every file of the group is as it was, but the ones
// named away, which must still be away, and nothing was written beside them.
func quarantineUnchanged(t *testing.T, alice *persona, groupId []byte, before map[string][]byte, away ...string) {
	t.Helper()
	after := advGroupFiles(t, alice.stateDir, groupId)
	gone := map[string]bool{}
	for _, name := range away {
		gone[name] = true
	}
	for name, content := range before {
		got, stands := after[name]
		switch {
		case gone[name] && stands:
			t.Errorf("%s of the owner's group stands while it is moved away", name)
		case !gone[name] && !stands:
			t.Errorf("%s of the owner's group went", name)
		case !gone[name] && !bytes.Equal(got, content):
			t.Errorf("%s of the owner's group changed", name)
		}
	}
	for name := range after {
		if _, was := before[name]; !was {
			t.Errorf("%s was written into the owner's group's folder", name)
		}
	}
}

// AN EPOCH STATE MOVED AWAY IS NEVER THE REASON FOR AN ERASE, AND THE GROUP COMES BACK WITH IT (R33,
// (7)(b): the round-3 review's quarantine probe, made real and run on every platform, a rename
// standing in for the quarantine). Alice owns a group bob is in. She restarts, and her epoch state of
// the group is moved out of its folder. Restore reports the group UNPROVEN; her leave is refused "so
// nothing was left", and nothing of the group changes. The file is put back: the next Restore brings
// the group back, and her leave is the owner's question, with nothing of the group changed.
//
// WHAT WOULD GO RED: an absence read as proof, measured at 907109f with a real file move: Restore
// noted the group as one that will not come back, the leave answered nil and took the group's
// files with bob still in it, and the file put back was then erased by the next Restore's sweep.
func TestAnEpochStateMovedAwayIsNeverTheReasonForAnErase(t *testing.T) {
	ctx := t.Context()
	alice, groupId, dir, before := quarantineOwner(t)
	const state = "epoch/0000000000000001"
	if _, held := before[state]; !held || len(before["meta"]) == 0 {
		t.Fatalf("CONTROL FAILED: alice's group has no record or no state at epoch 1 (%d file(s)), so nothing below moves what a restore reads", len(before))
	}
	putBack := quarantine(t, dir, state)

	restored, err := alice.device.Restore(ctx)
	t.Logf("Restore while the epoch state is away: %d group(s), %v", len(restored), err)
	if len(restored) != 0 || !errors.Is(err, urmessage.ErrRestore) || !errors.Is(err, urmessage.ErrGroupReadUnproven) {
		t.Errorf("Restore while the epoch state is away answered %d group(s), %v, want none and ErrGroupReadUnproven", len(restored), err)
	}
	if errors.Is(err, urmessage.ErrGroupRecordDamaged) {
		t.Errorf("Restore called a moved-away epoch state damage: %v", err)
	}
	err = alice.device.ForgetGroup(groupId)
	t.Logf("the owner's leave while the epoch state is away: %v", err)
	if !errors.Is(err, urmessage.ErrGroupReadUnproven) || !strings.Contains(err.Error(), "so nothing was left") {
		t.Errorf("the leave while the epoch state is away answered %v, want ErrGroupReadUnproven and that nothing was left", err)
	}
	quarantineUnchanged(t, alice, groupId, before, state)
	if erased := alice.stateStore.ErasedWithNoRecord(); len(erased) != 0 {
		t.Errorf("the sweep erased %v while the epoch state was away", erased)
	}

	// PUT BACK
	putBack()
	restored, err = alice.device.Restore(ctx)
	t.Logf("Restore after the epoch state is back: %d group(s), %v", len(restored), err)
	if err != nil || len(restored) != 1 {
		t.Fatalf("Restore after the epoch state is back answered %d group(s), %v, want the group back", len(restored), err)
	}
	err = alice.device.ForgetGroup(groupId)
	t.Logf("the owner's leave after it is back: %v", err)
	if !errors.Is(err, urmessage.ErrOwnerMustTransfer) {
		t.Errorf("the owner's leave after the epoch state is back answered %v, want the owner's question", err)
	}
	quarantineUnchanged(t, alice, groupId, before)
	if erased := alice.stateStore.ErasedWithNoRecord(); len(erased) != 0 {
		t.Errorf("the sweep erased %v after the epoch state came back", erased)
	}
}
