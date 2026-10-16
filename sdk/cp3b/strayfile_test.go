package cp3b

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/urnetwork/message/sdk/urmessage"
)

// A STRAY FILE IN THE OWNER'S `sent` FOLDER IS NO VERDICT, AND HER LEAVE IS STILL THE OWNER'S QUESTION
// (R38, item 1: the writer's F1 at T1 FIX 6, made a real test, on every platform; real files only).
// Alice owns a group bob is in, and has sent a line in it, so her `sent` folder holds a copy of it. At
// her next start a file the store did not write stands beside that copy, as a desktop.ini the shell
// writes or a sync tool's conflict copy does. Her Restore brings the group back; her leave of it is
// the owner's question; and nothing of the group is erased -- the stray is not the store's either,
// and stays.
//
// WHAT WOULD GO RED, measured at 93cc0af and at 9df6fca: SentRecords refused the stray as a copy this
// store did not write, a format verdict, so Restore reported the owner's group damaged and her leave
// took it without the owner's question while bob was still in it: her epoch states and her own line
// were erased, and the erase then stopped at the stray.
func TestAStrayInTheSentFolderIsNoVerdictAndTheOwnerIsStillAsked(t *testing.T) {
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
	aliceGroup, _ := openPair(t, ctx, alice, bob, groupId)
	if _, err := aliceGroup.Send(ctx, "a line alice wrote"); err != nil {
		t.Fatalf("alice's Send: %v", err)
	}
	alice = world.restart(t, alice)
	if err := alice.device.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	before := advGroupFiles(t, alice.stateDir, groupId)
	copies := 0
	for name := range before {
		if strings.HasPrefix(name, "sent/") {
			copies += 1
		}
	}
	if copies == 0 {
		t.Fatalf("CONTROL FAILED: alice's folder holds no copy of her line, so a stray beside it proves nothing: %v", putBackListing(erasescopeFolder(alice.stateDir, groupId)))
	}
	stray := filepath.Join(erasescopeFolder(alice.stateDir, groupId), "sent", "desktop.ini")
	if err := os.WriteFile(stray, []byte("[.ShellClassInfo]\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	restored, err := alice.device.Restore(ctx)
	t.Logf("alice's Restore with a stray in her sent folder: %d group(s), %v", len(restored), err)
	if err != nil || len(restored) != 1 {
		t.Errorf("the owner's group with a stray in its sent folder answered %d group(s), %v, want it restored", len(restored), err)
	}
	err = alice.device.ForgetGroup(groupId)
	t.Logf("the owner's leave: %v", err)
	if !errors.Is(err, urmessage.ErrOwnerMustTransfer) {
		t.Errorf("the owner's leave of a live group with bob in it answered %v, want the owner's question", err)
	}
	after := advGroupFiles(t, alice.stateDir, groupId)
	for name, content := range before {
		if !bytes.Equal(after[name], content) {
			t.Errorf("%s of the owner's group went or changed", name)
		}
	}
	if _, err := os.Stat(stray); err != nil {
		t.Errorf("the stray file, which is not the store's, went: %v", err)
	}
}
