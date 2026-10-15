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

// A FOLDER THAT OUTLIVED ITS ERASE HOLDS NOTHING OF A GROUP (R34, items 7 to 9: the round-4 review's
// probe of Y3, made a real test, both halves). Bob holds a group with alice, and a file the store did
// not write stands in his group's folder, as a desktop.ini or a sync tool's conflict copy does. His
// leave erases the group, and the folder stays, kept by that file.
//   - (i) Asked again, his leave answers ErrGroupNotHeld: the folder holds none of the store's own
//     names, so nothing of the group is there, and nothing is erased.
//   - (ii) A state written into that folder -- as a join's commit writes one, with the record never
//     following -- is marked as a creation, so the next Restore erases it as it erases the same orphan
//     in a fresh folder, the control. The stray file is not the store's, and stays.
//
// WHAT WOULD GO RED, measured at fdc1b0a: (i) answered ErrGroupReadUnproven, "cannot tell whether
// that will pass", for a group already left, a sentence that never becomes true; (ii) the state in
// the folder that stood got no mark and outlived the Restore, a stranded leaf's private keys.
func TestT1V4AFolderThatOutlivedItsErase(t *testing.T) {
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
	openPair(t, ctx, alice, bob, groupId)
	dir := erasescopeFolder(bob.stateDir, groupId)
	stray := filepath.Join(dir, "desktop.ini")
	if err := os.WriteFile(stray, []byte("[.ShellClassInfo]\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := bob.device.ForgetGroup(groupId); err != nil {
		t.Fatalf("bob's leave: %v", err)
	}
	if files := advGroupFiles(t, bob.stateDir, groupId); len(files) != 1 {
		t.Fatalf("CONTROL FAILED: after the leave bob's folder holds %d file(s), want the stray one alone, so the folder did not outlive the erase as this case needs", len(files))
	}

	// (i)
	err := bob.device.ForgetGroup(groupId)
	t.Logf("(i) bob's leave asked again: %v", err)
	if !errors.Is(err, urmessage.ErrGroupNotHeld) || errors.Is(err, urmessage.ErrGroupReadUnproven) {
		t.Errorf("(i) the leave of a group already left, over a folder holding only a stray file, answered %v, want ErrGroupNotHeld", err)
	}
	if _, err := os.Stat(stray); err != nil {
		t.Errorf("(i) the stray file, which is not the store's, went: %v", err)
	}

	// (ii)
	orphan := []byte("a joined leaf's private keys")
	if err := bob.stateStore.PutGroupState(groupId, 7, orphan); err != nil {
		t.Fatalf("PutGroupState into the folder that stood: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "pending")); err != nil {
		t.Errorf("(ii) the state written into a folder holding none of the store's names is not marked as a creation: %v", err)
	}
	control := newGroupId(t)
	if err := bob.stateStore.PutGroupState(control, 7, orphan); err != nil {
		t.Fatalf("PutGroupState into a fresh folder: %v", err)
	}
	controlDir := erasescopeFolder(bob.stateDir, control)
	bob = world.restart(t, bob)
	if err := bob.device.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	restored, err := bob.device.Restore(ctx)
	t.Logf("(ii) the next Restore: %d group(s), %v; erased %v", len(restored), err, bob.stateStore.ErasedWithNoRecord())
	if _, err := os.Stat(filepath.Join(controlDir, "epoch", "0000000000000007")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("CONTROL FAILED: the orphan in a fresh folder outlived the Restore: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "epoch", "0000000000000007")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("(ii) the orphan in the folder that outlived its erase outlived the Restore: %v", err)
	}
	if _, err := os.Stat(stray); err != nil {
		t.Errorf("(ii) the stray file, which is not the store's, went: %v", err)
	}
}
