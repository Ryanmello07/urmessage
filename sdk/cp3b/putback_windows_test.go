//go:build windows

package cp3b

import (
	"os"
	"path/filepath"
	"testing"
)

// A RETRACTION IS NOT UNDONE BY A CREATION MARK THAT WAS AWAY WHILE A RESTORE READ THE RECORD (R36,
// item 1: the round-5 review's Z1, form B). Alice founds a group, and while Open writes its record a
// scanner holds the creation mark with share mode 0 and a lock: the mark's removal fails, and the
// retraction is written beside it. At her next start the mark is out of the folder while the Restore
// reads the record: the retraction stays, for the group's life. The mark is put back.
//
// WHAT WOULD GO RED, measured at 93cc0af: that Restore took the retraction away, because the missing
// mark read as removed; with the mark back and the record away at the following start, her leave
// answered "this device holds no such group" for her live group, the Restore erased the folder, and
// with the record back the group never came back.
func TestT1V5ARetractionUndoneByAMarkAway(t *testing.T) {
	ctx := t.Context()
	world, alice, bob, aliceGroup, groupId, dir := putBackFounding(t)
	release := transientHold(t, filepath.Join(dir, "pending"))
	putBackAddBobAndOpen(t, aliceGroup, bob)
	release()
	t.Logf("after Open with the mark held: %v", putBackListing(dir))
	for _, name := range []string{"pending", "recorded"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("CONTROL FAILED: %s does not stand after Open with the mark held: %v", name, err)
		}
	}
	alice = world.restart(t, alice)
	if err := alice.device.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	putBackMark := putBackAway(t, dir, "pending")
	restored, err := alice.device.Restore(ctx)
	t.Logf("a Restore that reads the record while the mark is away: %d group(s), %v; the folder now: %v",
		len(restored), err, putBackListing(dir))
	if err != nil || len(restored) != 1 {
		t.Fatalf("the Restore with the mark away answered %d group(s), %v, want the group", len(restored), err)
	}
	if _, err := os.Stat(filepath.Join(dir, "recorded")); err != nil {
		t.Errorf("the Restore that read the record took the retraction away while the mark was elsewhere: %v", err)
	}
	putBackMark()
	t.Logf("the mark put back: %v", putBackListing(dir))
	putBackRecordAwayAtTheNextStart(t, world, alice, groupId, dir)
}
