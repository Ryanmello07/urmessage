package mls

import (
	"os"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"
)

// THE PIN FILE SAYS ONLY WHAT EXISTS.
//
// interop/PINS.md is read by people deciding what this package has been held against, and until
// this test it named three peer images under digests nobody had computed, a weekly job that exists
// nowhere, a CI service this repository does not have and its own path in a repository it has
// left; and two of its octets were Windows-1252 dashes, so the file was not UTF-8. None of that
// was checked by anything, which is how it stayed.
//
// WHAT WOULD GO RED: any of the six retired phrases coming back; a peer that is not built being
// described as anything else; one of the four machine-readable pins losing its `key=<40 hex>`
// shape, which other tests in this package grep.
func TestThePinFileNamesNothingThatDoesNotExist(t *testing.T) {
	raw, err := os.ReadFile("interop/PINS.md")
	if err != nil {
		t.Fatalf("reading the pin file: %v", err)
	}
	if !utf8.Valid(raw) {
		t.Errorf("the pin file is not UTF-8: it holds an octet that is a dash in Windows-1252 and nothing in UTF-8")
	}
	text := strings.ReplaceAll(string(raw), "\r\n", "\n")
	if len(text) < 1000 {
		t.Fatalf("the pin file is %d octets, so every absence below would be over nothing", len(text))
	}
	for _, retired := range []struct{ phrase, why string }{
		{"sha256:<...>", "a digest nobody has computed is not a pin"},
		{"peer-image-bump", "no such job exists, here or in any sibling repository"},
		{"CI never compiles", "this repository has no CI service: test.sh is the whole run"},
		{"green interop matrix", "there is no interop matrix"},
		{"connect/mls/interop/PINS.md", "this file's own path, before the package moved"},
		{"runs every vector family", "six of the sixteen families have no runner; the pending list in vectors_test.go says which"},
	} {
		if strings.Contains(text, retired.phrase) {
			t.Errorf("the pin file still says %q: %s", retired.phrase, retired.why)
		}
	}
	for _, peer := range []string{"openmls peer", "mlspp", "mls-rs"} {
		named := false
		for _, line := range strings.Split(text, "\n") {
			named = named || (strings.Contains(line, peer) && strings.Contains(line, "NOT BUILT"))
		}
		if !named {
			t.Errorf("the pin file does not say on one line that the %s is NOT BUILT", peer)
		}
	}
	// THE SENTENCE ABOUT WHAT RUNS POINTS AT THE LIST THAT IS HELD, and carries no count of its own:
	// vectors_test.go's expectedPendingFamilies is compared with the manifest on every run, and a
	// number written here would be a second copy nothing compares.
	if !strings.Contains(text, "`expectedPendingFamilies`") {
		t.Errorf("the pin file does not name expectedPendingFamilies, the one held list of the families with no runner")
	}
	for _, key := range []string{"mlswg", "openmls", "hpke", "xwing"} {
		pin := regexp.MustCompile(`(?m)^` + key + `=[0-9a-f]{40}$`)
		if found := len(pin.FindAllString(text, -1)); found != 1 {
			t.Errorf("the pin file holds %d line(s) of the shape %s=<40 hex>, want exactly 1", found, key)
		}
	}
}
