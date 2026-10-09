package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// THIS PACKAGE HAS TESTS SO THAT ITS TEST BINARY EXISTS AND STARTS. A main package with no test is
// built and vetted by test.sh and never run, and a defect that shows only when a binary starts -- two
// copies of message.proto linked into one binary, which protobuf refuses at init -- is invisible to
// build and to vet. `go test` runs this package's init before its first case, so every run of these
// cases is also that check; the module census requires every main package to have one. What
// the cases themselves hold is the file handshake the peers rest on: the invite is written so a
// poller never reads half of it, and the waits see it arrive and see it go.

func TestAnInviteIsWrittenWholeAndPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "invite")
	content := []byte("an invite, all of it")
	if err := writeSecret(path, content); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, content) {
		t.Fatalf("read back %q, %v; want %q", got, err, content)
	}
	if _, err := os.Stat(path + ".partial"); !os.IsNotExist(err) {
		t.Errorf("the temp file is still there after the rename: %v", err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if mode := info.Mode().Perm(); mode != 0o600 {
			t.Errorf("the invite is mode %o, want 600", mode)
		}
	}
}

func TestTheWaitsSeeAFileArriveAndGo(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "invite")
	if _, err := awaitFile(ctx, path, 50*time.Millisecond, 10*time.Millisecond); err == nil {
		t.Fatal("awaitFile answered for a file that never appeared")
	}
	go func() {
		time.Sleep(30 * time.Millisecond)
		writeSecret(path, []byte("arrived"))
	}()
	got, err := awaitFile(ctx, path, 5*time.Second, 10*time.Millisecond)
	if err != nil || string(got) != "arrived" {
		t.Fatalf("awaitFile answered %q, %v; want the content once it stopped changing", got, err)
	}
	if awaitGone(ctx, path, 30*time.Millisecond, 10*time.Millisecond) {
		t.Fatal("awaitGone answered true for a file that is still there")
	}
	go func() {
		time.Sleep(30 * time.Millisecond)
		os.Remove(path)
	}()
	if !awaitGone(ctx, path, 5*time.Second, 10*time.Millisecond) {
		t.Fatal("awaitGone did not see the file go")
	}
}

func TestTheReportShortensIdentitiesAndClipsText(t *testing.T) {
	if got := short(nil); got != "-" {
		t.Errorf("short(nil) = %q, want -", got)
	}
	if got := short([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}); got != "0102030405060708" {
		t.Errorf("short of ten octets = %q, want the first eight in hex", got)
	}
	long := strings.Repeat("x", 150)
	if got := clip(long); !strings.HasPrefix(got, strings.Repeat("x", 100)) || !strings.HasSuffix(got, "(150 octets)") {
		t.Errorf("clip of 150 octets = %q", got)
	}
	if got := clip("short"); got != "short" {
		t.Errorf("clip changed a short text: %q", got)
	}
}
