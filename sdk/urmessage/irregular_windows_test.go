//go:build windows

package urmessage

import (
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// irregularRegularFiles is every regular file under one group's folder with its octets, passing over
// anything else: a walk that read a junction as a file would fail at it.
func irregularRegularFiles(t *testing.T, root string) map[string]string {
	t.Helper()
	files := map[string]string{}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		octets, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		relative, _ := filepath.Rel(root, path)
		files[filepath.ToSlash(relative)] = string(octets)
		return nil
	})
	if err != nil {
		t.Fatalf("listing the group's files: %v", err)
	}
	return files
}

// A JUNCTION AT THE RECORD'S NAME IS NO PROOF, AND NOTHING IS LEFT ON IT (R38, item 2, on Windows,
// with a real junction: `mklink /J`, which needs no privilege). A junction is a reparse point Go
// reports as irregular, as it reports a cloud placeholder of the store's own file. The joined group's
// record is moved aside and a junction to a folder stands at its name. Reading it answers
// ERROR_INVALID_FUNCTION, a wrong-type code, and the store's own Lstat finds a type that does not
// confirm one: the record is reported as not read, unproven, and not as damage, and the leave of the
// group is refused "so nothing was left", with every file of the group as it was.
//
// THE CONTROL: a PLAIN directory standing at the same name answers the same code, confirms it, and is
// damage.
//
// WHAT WOULD GO RED, measured at 9df6fca: the junction confirmed the code, the record read as damage,
// and the leave took the group without the owner's question.
func TestAJunctionAtTheRecordsNameIsNoProofAndNothingIsLeft(t *testing.T) {
	dir, groupId := failClosedScene(t)
	store := openTestStore(t, dir)
	path := store.groupRecordPath(groupId)
	if err := os.Rename(path, filepath.Join(t.TempDir(), "meta")); err != nil {
		t.Fatal(err)
	}
	target := t.TempDir()
	// cmd reads a forward slash as a switch, so both paths go to mklink in the platform's own spelling
	if output, err := exec.Command("cmd", "/c", "mklink", "/J", filepath.Clean(path), filepath.Clean(target)).CombinedOutput(); err != nil {
		t.Fatalf("CONTROL FAILED: this runner could not make a junction: %v: %s", err, strings.TrimSpace(string(output)))
	}
	t.Cleanup(func() { os.Remove(path) })
	if info, err := os.Lstat(path); err != nil || info.Mode()&os.ModeIrregular == 0 {
		t.Fatalf("CONTROL FAILED: the junction at the record's name is not reported as irregular: %v, %v", info, err)
	}
	before := irregularRegularFiles(t, store.groupDir(groupId))
	if len(before) == 0 {
		t.Fatalf("CONTROL FAILED: the group's folder holds no file beside the junction")
	}

	_, err := store.GroupRecord(groupId)
	t.Logf("the one-id read over the junction: %v", err)
	if err == nil || errors.Is(err, ErrGroupRecordDamaged) || classifyRead(err) != readUnproven {
		t.Errorf("the record's read over a junction answered %v, class %d, want unproven and not damage", err, classifyRead(err))
	}
	device := newAnsweringDeviceOver(t, store, []byte("the restarted device's nonce"))
	err = device.ForgetGroup(groupId)
	t.Logf("the leave over the junction: %v", err)
	if !errors.Is(err, ErrGroupReadUnproven) || !strings.Contains(err.Error(), "so nothing was left") || errors.Is(err, ErrForgetUnfinished) {
		t.Errorf("the leave over a junction at the record's name answered %v, want it refused as unproven, with nothing left", err)
	}
	if info, err := os.Lstat(path); err != nil || info.Mode()&os.ModeIrregular == 0 {
		t.Errorf("the junction at the record's name went: %v", err)
	}
	after := irregularRegularFiles(t, store.groupDir(groupId))
	for name, octets := range before {
		if after[name] != octets {
			t.Errorf("%s of the group changed or went", name)
		}
	}

	// THE CONTROL
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GroupRecord(groupId); !errors.Is(err, ErrGroupRecordDamaged) || classifyRead(err) != readPermanent {
		t.Errorf("CONTROL FAILED: a plain directory at the record's name answered %v, want damage, proven permanent", err)
	}
}
