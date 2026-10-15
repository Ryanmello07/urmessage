package cp3b

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/urnetwork/message/sdk/urmessage"
)

// erasescopeFolder is one group's folder under a durable store's directory: the store names it by
// the SHA-256 of the group id, which is all this reads of its layout.
func erasescopeFolder(stateDir string, groupId []byte) string {
	sum := sha256.Sum256(groupId)
	return filepath.Join(stateDir, "state", "group", hex.EncodeToString(sum[:]))
}

// THE RECORD WRITTEN WHILE NEITHER THE CREATION MARK'S REMOVAL NOR ITS RETRACTION COULD BE IS
// ANSWERED, NOT SWALLOWED (R34, item 3: the double failure, produced with no injected error). Alice
// founds a group, and before its Open two paths of the wrong type stand where the store keeps its
// marks: a folder with a file in it at `pending`, which a removal cannot take, and a folder at
// `recorded`, onto which no file can be renamed. Open writes the record, cannot remove the mark and
// cannot write its retraction: it answers that the record is on this device's disk and that the
// store could not record that the group's creation finished. The record is there.
//
// WHAT WOULD GO RED: the double failure answered nil -- a founding whose mark stands beside its
// record with nothing retracting it, told that it is open, and swept as a creation that never
// finished if its record then goes missing.
func TestTheDoubleFailureToRetractACreationMarkIsAnsweredAtOpen(t *testing.T) {
	ctx := t.Context()
	world := newWorld(t)
	alice := world.newPersona(t, "alice")
	bob := world.newPersona(t, "bob")
	for _, who := range []*persona{alice, bob} {
		if err := who.device.Connect(ctx); err != nil {
			t.Fatalf("%s's Connect: %v", who.name, err)
		}
	}
	groupId := newGroupId(t)
	aliceGroup, err := alice.device.CreateGroup(ctx, groupId)
	if err != nil {
		t.Fatalf("alice's CreateGroup: %v", err)
	}
	dir := erasescopeFolder(alice.stateDir, groupId)
	pending := filepath.Join(dir, "pending")
	if _, err := os.Stat(pending); err != nil {
		t.Fatalf("CONTROL FAILED: no creation mark after CreateGroup: %v", err)
	}
	// the two paths of the wrong type
	if err := os.Remove(pending); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(pending, "a file the removal cannot take"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "recorded"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(pending); err == nil {
		t.Fatalf("CONTROL FAILED: the folder at the mark's name could be removed")
	}
	keyPackage, err := bob.device.KeyPackage()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := aliceGroup.AddMember(keyPackage); err != nil {
		t.Fatalf("alice's AddMember: %v", err)
	}
	err = aliceGroup.Open(ctx)
	t.Logf("alice's Open: %v", err)
	if !errors.Is(err, urmessage.ErrStateStoreState) || !strings.Contains(err.Error(), "this store could not record that the group's creation finished") {
		t.Errorf("alice's Open answered %v, want the record said to be on the disk and the creation said to be unrecorded", err)
	}
	if record := advGroupFiles(t, alice.stateDir, groupId)["meta"]; len(record) == 0 {
		t.Errorf("CONTROL FAILED: the record is not on the disk, so this is not the double failure")
	}
}
