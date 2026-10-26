package urmessage

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/urnetwork/glog"
)

// THE START AND THE MAKING EACH SAY, IN ONE LINE, WHAT THEY DID WITH THE SETUP MARK (LRI R89 item 3;
// review D2L-4, L-D2). A sweep that took something, and a removal of the mark that failed, are not
// silent: each writes one line to the library's log, which the app routes to its log directory, and
// neither line carries a key or a word.
//   - The start over a setup's leftovers names what it erased.
//   - A making whose mark could not be removed beside the identity record says so.
//
// THE CONTROL: the identity key's hex and two consecutive words of the phrase are needles of both
// lines, and the needles fire on a planted line.
func TestTheStartAndTheMakingSayWhatTheyDidWithTheMarkInOneLine(t *testing.T) {
	ctx := context.Background()
	logDir, err := os.MkdirTemp("", "urmessage-marklog-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { glog.Flush(); os.RemoveAll(logDir) })
	if err := glog.SetLogDir(logDir); err != nil {
		t.Fatalf("SetLogDir: %v", err)
	}

	// THE START OVER A SETUP'S LEFTOVERS
	dir := t.TempDir()
	store := openTestStore(t, dir)
	key := bytes.Repeat([]byte{0x5a}, ed25519.PublicKeySize)
	mintDeviceRecord(t, store)
	putOrphansOf(t, store, key)
	plantSetupMark(t, store, key)
	started, err := newKillRestartDevice(t, store, "the start over a setup's leftovers")
	if err != nil {
		t.Fatalf("the start: %v", err)
	}
	started.Close()
	glog.Flush()
	swept := logLinesContaining(t, logDir, "the start erased what a setup that stopped part way left")
	if len(swept) != 1 {
		t.Errorf("the start that swept a setup's leftovers wrote %d line(s) saying so, want 1", len(swept))
	}

	// THE MAKING WHOSE MARK COULD NOT BE REMOVED
	failing := &markClearFailingStore{DurableStateStore: openTestStore(t, t.TempDir())}
	device := newAnsweringDeviceOver(t, failing, []byte("the making's nonce"))
	words, err := device.CreateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	needlePair := words[0] + " " + words[1]
	typed := strings.Join(words, " ")
	clear(words)
	if err := device.ConfirmWords(ctx, typed); err != nil {
		t.Fatalf("ConfirmWords with a mark that cannot be removed answered %v: a failed removal fails nothing", err)
	}
	made, err := failing.Identity()
	if err != nil {
		t.Fatal(err)
	}
	device.Close()
	glog.Flush()
	stuck := logLinesContaining(t, logDir, "the setup mark could not be removed")
	if len(stuck) != 1 {
		t.Errorf("the making whose mark could not be removed wrote %d line(s) saying so, want 1", len(stuck))
	}

	// NEITHER LINE CARRIES A KEY OR A WORD
	needles := []string{hex.EncodeToString(key[:4]), hex.EncodeToString(made.Root[:4]), needlePair}
	for _, line := range append(swept, stuck...) {
		for _, needle := range needles {
			if strings.Contains(strings.ToLower(line), strings.ToLower(needle)) {
				t.Errorf("a mark line carries a needle (%d octets of it): a key or two of the words", len(needle))
			}
		}
	}
	planted := "a planted line " + hex.EncodeToString(made.Root[:4]) + " and " + needlePair
	fired := 0
	for _, needle := range needles[1:] {
		if strings.Contains(planted, needle) {
			fired++
		}
	}
	if fired != 2 {
		t.Errorf("CONTROL FAILED: the needles fired %d time(s) on a planted line, want 2", fired)
	}
}

// markClearFailingStore is a durable store whose setup mark cannot be removed by the making.
type markClearFailingStore struct {
	*DurableStateStore
}

func (self *markClearFailingStore) ClearSetupMark() error {
	return errors.New("the test's store holds the setup mark")
}

// logLinesContaining answers every line of the log files in dir that contains text.
func logLinesContaining(t *testing.T, dir string, text string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	lines := []string{}
	seen := map[string]bool{}
	for _, entry := range entries {
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			continue
		}
		octets, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(string(octets), "\n") {
			if strings.Contains(line, text) && !seen[line] {
				seen[line] = true
				lines = append(lines, line)
			}
		}
	}
	return lines
}
