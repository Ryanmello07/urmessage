package cp3b

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/urnetwork/message/sdk/urmessage"
)

// ONE STORE FILE PUT BACK (R36, the table's column 7: the round-5 review's probes, made real tests).
// R33's adversary does not only move a group's files away: it puts single files BACK, as a
// quarantine restored or a sync tool's re-download does, and every authority but (b) and (e) is a
// fact the store reads from one small file. These cases move and put back the store's own files with
// plain renames, and hold them only where a Windows case needs to; nothing is injected.

// putBackAway moves one entry of a group's folder out of it, as a quarantine does, and answers the
// call that puts it back, re-creating the folders above it if something removed them meanwhile.
func putBackAway(t *testing.T, dir string, name string) func() {
	t.Helper()
	path := filepath.Join(dir, filepath.FromSlash(name))
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("CONTROL FAILED: %s is not in the group's folder, so moving it away moves nothing: %v", name, err)
	}
	away := filepath.Join(t.TempDir(), "quarantined-"+filepath.Base(path))
	if err := os.Rename(path, away); err != nil {
		t.Fatalf("moving %s away: %v", name, err)
	}
	return func() {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatalf("re-creating %s: %v", filepath.Dir(path), err)
		}
		if err := os.Rename(away, path); err != nil {
			t.Fatalf("putting %s back: %v", name, err)
		}
	}
}

// putBackListing is every entry under a group's folder, directories marked with a slash.
func putBackListing(dir string) []string {
	names := []string{}
	filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err == nil && path != dir {
			relative, _ := filepath.Rel(dir, path)
			if entry.IsDir() {
				relative += "/"
			}
			names = append(names, filepath.ToSlash(relative))
		}
		return nil
	})
	sort.Strings(names)
	return names
}

// putBackFounding is a founder alice and a member bob, both connected, and alice's group created and
// not yet opened, with its folder.
func putBackFounding(t *testing.T) (*world, *persona, *persona, *urmessage.Group, []byte, string) {
	t.Helper()
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
	if _, err := os.Stat(filepath.Join(dir, "pending")); err != nil {
		t.Fatalf("CONTROL FAILED: no creation mark after CreateGroup: %v", err)
	}
	return world, alice, bob, aliceGroup, groupId, dir
}

// putBackAddBobAndOpen adds bob, opens the group, and has bob join it.
func putBackAddBobAndOpen(t *testing.T, aliceGroup *urmessage.Group, bob *persona) {
	t.Helper()
	ctx := t.Context()
	keyPackage, err := bob.device.KeyPackage()
	if err != nil {
		t.Fatal(err)
	}
	invite, err := aliceGroup.AddMember(keyPackage)
	if err != nil {
		t.Fatalf("alice's AddMember: %v", err)
	}
	encoded, err := invite.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if err := aliceGroup.Open(ctx); err != nil {
		t.Fatalf("alice's Open: %v", err)
	}
	carried, err := urmessage.ParseInvite(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bob.device.Join(ctx, carried); err != nil {
		t.Fatalf("bob's Join: %v", err)
	}
}

// putBackRecordAwayAtTheNextStart is the last act of each case on the creation mark: the creation mark
// is back in the folder of alice's live group, with bob in it. At her next start her record is moved
// away: her leave is refused as unproven -- the folder stands, and it is not "nothing is here" -- and
// the Restore erases nothing. With the record back, the group comes back, the mark is gone, the
// retraction stays, and her leave is the owner's question.
func putBackRecordAwayAtTheNextStart(t *testing.T, world *world, alice *persona, groupId []byte, dir string) {
	t.Helper()
	ctx := t.Context()
	alice = world.restart(t, alice)
	if err := alice.device.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	before := advGroupFiles(t, alice.stateDir, groupId)
	if _, marked := before["pending"]; !marked {
		t.Fatalf("CONTROL FAILED: the creation mark is not back in the folder: %v", putBackListing(dir))
	}
	putBack := putBackAway(t, dir, "meta")
	t.Logf("the folder with the record away: %v", putBackListing(dir))
	err := alice.device.ForgetGroup(groupId)
	t.Logf("the owner's leave of her live group, its record away: %v", err)
	if !errors.Is(err, urmessage.ErrGroupReadUnproven) || errors.Is(err, urmessage.ErrGroupNotHeld) ||
		!strings.Contains(err.Error(), "its directory stands and its record is not in it") {
		t.Errorf("the leave of a live group whose record is away answered %v, want the unproven refusal and not ErrGroupNotHeld", err)
	}
	restored, err := alice.device.Restore(ctx)
	t.Logf("Restore with the record away: %d group(s), %v; erased %v; the folder now: %v",
		len(restored), err, alice.stateStore.ErasedWithNoRecord(), putBackListing(dir))
	if erased := alice.stateStore.ErasedWithNoRecord(); len(erased) != 0 {
		t.Errorf("the sweep erased %v: the owner's live group, on a creation mark another program put back", erased)
	}
	quarantineUnchanged(t, alice, groupId, before, "meta")
	putBack()
	restored, err = alice.device.Restore(ctx)
	t.Logf("Restore with the record back: %d group(s), %v; the folder now: %v", len(restored), err, putBackListing(dir))
	if err != nil || len(restored) != 1 {
		t.Fatalf("with the record back the owner's live group answered %d group(s), %v, want it restored", len(restored), err)
	}
	if _, err := os.Stat(filepath.Join(dir, "pending")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the creation mark stands beside a record that read: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "recorded")); err != nil {
		t.Errorf("the retraction is gone from beside a record that read: %v", err)
	}
	if err := alice.device.ForgetGroup(groupId); !errors.Is(err, urmessage.ErrOwnerMustTransfer) {
		t.Errorf("the owner's leave answered %v, want the owner's question", err)
	}
}

// A CREATION MARK THAT WAS AWAY WHEN THE RECORD LANDED, AND IS PUT BACK, IS NEVER A REASON FOR AN ERASE
// (R36, item 1: the round-5 review's Z1, form A, on every platform). Alice founds a group; before Open,
// her creation mark is moved out of the folder. Open writes the record, and the retraction beside it,
// although the mark is nowhere to be removed. The mark is put back. At her next start the record is
// moved away: the folder still holds the retraction, so it is not in the creating state.
//
// WHAT WOULD GO RED, measured at 93cc0af: no retraction was written, because the missing mark read
// as removed; with the record away her leave answered "this device holds no such group" for her live
// group, and the Restore erased the folder; with the record back, the group named states that were
// gone, and never came back.
func TestT1V5AMarkAwayWhenTheRecordLanded(t *testing.T) {
	world, alice, bob, aliceGroup, groupId, dir := putBackFounding(t)
	putBackMark := putBackAway(t, dir, "pending")
	putBackAddBobAndOpen(t, aliceGroup, bob)
	t.Logf("after Open with the mark away: %v", putBackListing(dir))
	if _, err := os.Stat(filepath.Join(dir, "recorded")); err != nil {
		t.Errorf("Open wrote the record with the creation mark away, and no retraction beside it: %v", err)
	}
	putBackMark()
	t.Logf("the mark put back: %v", putBackListing(dir))
	putBackRecordAwayAtTheNextStart(t, world, alice, groupId, dir)
}
