package main

import (
	"fmt"
	"io"
	"strings"
	"testing"
)

// THIS PACKAGE HAS TESTS SO THAT ITS TEST BINARY EXISTS AND STARTS. A main package with no test is
// built and vetted by test.sh and never run, and a defect that shows only when a binary starts -- two
// copies of message.proto linked into one binary, which protobuf refuses at init -- is invisible to
// build and to vet. `go test` runs this package's init before its first case, so every run of these
// cases is also that check; the module census requires every main package to have one. What
// the cases themselves hold is the probe's own instruments: the credential scan over its transcript
// and the difference it reports when a text comes back changed.

func TestTheTranscriptCountsANeedleAndAnnouncesItOnce(t *testing.T) {
	log := &transcriptLog{}
	writer := log.tee(io.Discard)
	fmt.Fprintf(writer, "a line with %s in it, and %s again\n", credentialNeedle, credentialNeedle)
	held, announce := log.count(credentialNeedle)
	if held != 2 || !announce {
		t.Fatalf("count answered %d, announce %v; want 2 and the first caller announcing", held, announce)
	}
	held, announce = log.count(credentialNeedle)
	if held != 2 || announce {
		t.Fatalf("a second count answered %d, announce %v; want 2 and no second announcement", held, announce)
	}
	if want := len(fmt.Sprintf("a line with %s in it, and %s again\n", credentialNeedle, credentialNeedle)); log.octets() != want {
		t.Errorf("octets() = %d, want %d", log.octets(), want)
	}
	clean := &transcriptLog{}
	fmt.Fprint(clean.tee(io.Discard), "nothing secret here\n")
	if held, announce := clean.count(credentialNeedle); held != 0 || announce {
		t.Errorf("a clean transcript answered %d, announce %v", held, announce)
	}
}

// the scan's control is a fabricated value its needle finds, so "no credential in the log" is a
// measurement and not the silence of a scanner that matches nothing
func TestTheCredentialControlIsWhatTheScanLooksFor(t *testing.T) {
	if !strings.HasPrefix(credentialControl, credentialNeedle) {
		t.Fatalf("the control %q does not begin with the needle, so it cannot show the scan works", credentialControl)
	}
}

func TestFirstDifferencePointsAtTheFirstOctetThatDiffers(t *testing.T) {
	for _, row := range []struct {
		want, got string
		at        int
	}{
		{"same", "same", -1},
		{"abc", "abd", 2},
		{"abc", "ab", 2},
		{"ab", "abc", 2},
		{"", "x", 0},
		{"x", "y", 0},
	} {
		if at := firstDifference(row.want, row.got); at != row.at {
			t.Errorf("firstDifference(%q, %q) = %d, want %d", row.want, row.got, at, row.at)
		}
	}
}
