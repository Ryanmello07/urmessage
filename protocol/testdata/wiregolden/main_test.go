package main

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"
)

// The emitter covers the schema it links, by construction rather than by a list: three rows
// per message, one per oneof arm, one canonical row per request carrying req_auth, and the
// descriptor. Run with -tags orig (connect's copy) and with -tags new (this repository's).
func TestTheEmitterCoversEveryMessageOfTheSchema(t *testing.T) {
	var out bytes.Buffer
	emit(&out, io.Discard)
	counts := map[string]int{}
	for _, line := range strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n") {
		kind, _, _ := strings.Cut(line, "\t")
		counts[kind]++
	}
	messages, arms, requests := fileDesc.Messages().Len(), 0, 0
	for i := 0; i < messages; i++ {
		md := fileDesc.Messages().Get(i)
		for o := 0; o < md.Oneofs().Len(); o++ {
			arms += md.Oneofs().Get(o).Fields().Len()
		}
		if md.Fields().ByName(protoreflect.Name("req_auth")) != nil {
			requests++
		}
	}
	want := map[string]int{"msg": 3 * messages, "arm": arms, "canonical": requests, "descriptor-without-go_package": 1}
	for kind, n := range want {
		if counts[kind] != n {
			t.Errorf("%d %s rows, want %d", counts[kind], kind, n)
		}
	}
	if len(counts) != len(want) {
		t.Errorf("row kinds %v, want exactly %v", counts, want)
	}
	if messages == 0 || arms == 0 || requests == 0 {
		t.Fatalf("the schema linked here has %d messages, %d arms and %d authenticated requests; a corpus over nothing proves nothing", messages, arms, requests)
	}
}

// The cross-decode check reports an item whose bytes do not survive a decode and re-encode in
// this build's types, and counts the rest.
func TestTheCrossDecodeCheckReportsAChangedItem(t *testing.T) {
	var corpus bytes.Buffer
	emit(&corpus, io.Discard)
	lines := strings.Split(strings.TrimSuffix(corpus.String(), "\n"), "\n")
	decoded, identical := check(strings.NewReader(corpus.String()), io.Discard)
	if decoded != len(lines)-1 || identical != decoded {
		t.Fatalf("the corpus cross-decodes %d of %d items identically, want all %d (the descriptor row is not decoded)", identical, decoded, len(lines)-1)
	}
	// a field number moved: the item still decodes, as an unknown field, and is reported
	for i, line := range lines {
		parts := strings.Split(line, "\t")
		if parts[0] != "msg" || parts[2] != "depth=0" || len(parts[3]) < 4 || parts[3][:2] != "08" {
			continue
		}
		parts[3] = "f8ff03" + parts[3][2:] // field 1 varint -> field 8191 varint
		lines[i] = strings.Join(parts, "\t")
		var report bytes.Buffer
		decoded, identical := check(strings.NewReader(strings.Join(lines, "\n")+"\n"), &report)
		if identical != decoded-1 || !strings.Contains(report.String(), parts[1]) {
			t.Fatalf("a renumbered field in %s was not reported: %d of %d identical, report %q", parts[1], identical, decoded, report.String())
		}
		return
	}
	t.Fatal("the corpus holds no depth=0 row starting with field 1 as a varint, so the control planted nothing")
}
