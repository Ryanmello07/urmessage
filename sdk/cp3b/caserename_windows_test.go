//go:build windows

package cp3b

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/urnetwork/message/sdk/urmessage"
)

// caseRenameFiles is every file under one folder, by its path inside it, with its octets.
func caseRenameFiles(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	files := map[string][]byte{}
	err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		octets, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		relative, _ := filepath.Rel(dir, path)
		files[filepath.ToSlash(relative)] = octets
		return nil
	})
	if err != nil {
		t.Fatalf("listing %s: %v", dir, err)
	}
	return files
}

// A GROUP'S FOLDER RENAMED TO ANOTHER CASE IS STILL THE GROUP'S, AND EVERY ANSWER ABOUT IT IS TRUE
// (R42, item 1: the round-6 add-on's Y1, made a real test, on NTFS, which keeps the case of a name and
// folds case when it finds one). Bob is in alice's group. At a start, one of them finds the group's
// folder renamed to upper case, as a sync tool from a case-sensitive source or the shell can rename
// it; the folder the store's own lowercase name reaches is the same file.
//   - The owner, alice: Restore brings the group back, and her leave is the owner's question, with
//     nothing of the group changed.
//   - The member, bob: Restore brings the group back; his leave is a leave, and takes the folder;
//     alice removes him and adds him again, and his re-join joins.
//
// WHAT WOULD GO RED, measured at e4eb247 (and at 9df6fca, where Restore reported the folder DAMAGED):
// the root's listings read only lowercase names, so Restore answered no group and nothing; the leave
// answered ErrGroupNotRestored, "call Restore", every time; and the join gate's ErrGroupAlreadyHeld
// sent the person to that leave, which could never happen -- a false remedy. Nothing was erased.
func TestAGroupFolderRenamedToAnotherCaseRestoresAndAnswersTruly(t *testing.T) {
	for _, whose := range []string{"owner", "member"} {
		t.Run(whose, func(t *testing.T) {
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
			subject := bob
			if whose == "owner" {
				subject = alice
			}
			dir := erasescopeFolder(subject.stateDir, groupId)
			subject = world.restart(t, subject)
			if err := subject.device.Connect(ctx); err != nil {
				t.Fatal(err)
			}
			upper := filepath.Join(filepath.Dir(dir), strings.ToUpper(filepath.Base(dir)))
			if err := os.Rename(dir, upper); err != nil {
				t.Fatalf("renaming the group's folder to upper case: %v", err)
			}
			entries, err := os.ReadDir(filepath.Dir(dir))
			if err != nil {
				t.Fatal(err)
			}
			listed := false
			for _, entry := range entries {
				listed = listed || entry.Name() == filepath.Base(upper)
			}
			if !listed {
				t.Fatalf("CONTROL FAILED: the groups' root does not list the folder under its upper-case name")
			}
			before := caseRenameFiles(t, upper)
			restored, err := subject.device.Restore(ctx)
			t.Logf("%s's Restore with the folder renamed to upper case: %d group(s), %v", whose, len(restored), err)
			if err != nil || len(restored) != 1 {
				t.Fatalf("the %s's group in a folder renamed to upper case answered %d group(s), %v, want it restored", whose, len(restored), err)
			}
			err = subject.device.ForgetGroup(groupId)
			t.Logf("%s's leave: %v", whose, err)
			if whose == "owner" {
				if !errors.Is(err, urmessage.ErrOwnerMustTransfer) {
					t.Errorf("the owner's leave answered %v, want the owner's question", err)
				}
				after := caseRenameFiles(t, upper)
				for name, content := range before {
					if !bytes.Equal(after[name], content) {
						t.Errorf("%s of the owner's group went or changed", name)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("the member's leave answered %v, want it left", err)
			}
			if _, err := os.Stat(upper); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("the member's leave left the folder standing: %v", err)
			}
			members, err := aliceGroup.Members()
			if err != nil {
				t.Fatal(err)
			}
			for _, member := range members {
				if !member.Mine {
					if err := aliceGroup.RemoveMember(ctx, member.IdentityPub); err != nil {
						t.Fatalf("alice's RemoveMember of bob: %v", err)
					}
				}
			}
			keyPackage, err := subject.device.KeyPackage()
			if err != nil {
				t.Fatal(err)
			}
			invite, err := aliceGroup.AddMemberAndPublish(ctx, keyPackage)
			if err != nil {
				t.Fatalf("alice's re-add of bob: %v", err)
			}
			_, err = subject.device.Join(ctx, gcReencodeInvite(t, invite))
			t.Logf("bob's re-join: %v", err)
			if err != nil {
				t.Errorf("the member's re-join after his leave answered %v, want it joined", err)
			}
		})
	}
}
