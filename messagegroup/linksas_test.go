// The seven emoji (identity phase 1's plan, Task 11): Property 4. They are the known answer, and
// change with every input, the group id and the epoch included.
package messagegroup

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"testing"

	"github.com/urnetwork/message/syntax"
)

// The vendored m.sas.v1 list's pin, written out here, and the source the NOTICE row names.
const linkSasEmojiListSha256 = "2b4defb276d61f11cb9cbfb0ba326b96a8dbd9e768e6bc53fa0f565cd598e887"

// The tests' exporter: SHA-256(LP(label) ‖ LP(context)), a pure function of what it is asked,
// so the emoji depend on the group id and the epoch only through the context LinkSas builds. It
// records what it was asked.
type linkSasTestExporter struct {
	label   string
	context []byte
	length  int
}

func (self *linkSasTestExporter) Export(label string, context []byte, length int) ([]byte, error) {
	self.label, self.context, self.length = label, append([]byte(nil), context...), length
	writer := syntax.NewWriter()
	writer.WriteOpaqueLP([]byte(label))
	writer.WriteOpaqueLP(context)
	preimage, err := writer.Bytes()
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(preimage)
	return sum[:length], nil
}

func linkSasRepeated(octet byte) []byte {
	return deviceListRepeatedSeed(octet)
}

func TestTheSevenEmojiAreTheKnownAnswerAndMoveWithEveryInput(t *testing.T) {
	// the index rule's two answers, round 4's X3:E1
	for _, known := range []struct {
		sas  []byte
		want [LinkSasEmojiCount]int
	}{
		{func() []byte {
			octets := make([]byte, 32)
			for at := range octets {
				octets[at] = byte(at)
			}
			return octets
		}(), [LinkSasEmojiCount]int{0, 0, 4, 2, 0, 48, 16}},
		{linkSasRepeated(0xff), [LinkSasEmojiCount]int{63, 63, 63, 63, 63, 63, 63}},
	} {
		if got := linkSasIndicesOf(known.sas); got != known.want {
			t.Errorf("the indices of %x are %v, want %v", known.sas, got, known.want)
		}
	}

	// the known answer for fixed inputs, through the tests' exporter
	groupId, keyPackageRef, nonceE, nonceN := linkSasRepeated(0x21), linkSasRepeated(0x33), linkSasRepeated(0x44), linkSasRepeated(0x55)
	exporter := &linkSasTestExporter{}
	emoji, err := LinkSas(exporter, groupId, 1, keyPackageRef, nonceE, nonceN)
	if err != nil {
		t.Fatal(err)
	}
	wantIndices := []int{3, 55, 30, 32, 19, 5, 4}
	wantNames := []string{"Horse", "Trophy", "Smiley", "Hat", "Globe", "Pig", "Unicorn"}
	for position, one := range emoji {
		if one.Index != wantIndices[position] || one.Name != wantNames[position] || one.Emoji != linkSasEmojiList[wantIndices[position]].emoji {
			t.Errorf("emoji %d is %+v, want index %d, %s", position, one, wantIndices[position], wantNames[position])
		}
	}
	// what was asked of the exporter: the label, 32 octets, and the context F1 section 2.2 names
	context := syntax.NewWriter()
	context.WriteOpaqueLP(groupId)
	context.WriteUint64(1)
	context.WriteOpaqueLP(keyPackageRef)
	context.WriteOpaqueLP(nonceE)
	context.WriteOpaqueLP(nonceN)
	wantContext, _ := context.Bytes()
	if exporter.label != "URmessage/v1/link-sas-emoji" || exporter.length != 32 || string(exporter.context) != string(wantContext) {
		t.Errorf("the exporter was asked %q, %d octets, over %x", exporter.label, exporter.length, exporter.context)
	}

	// every input moves them: the group id, the epoch, the key package ref, and each nonce
	for _, moved := range []struct {
		name                    string
		group                   []byte
		epoch                   uint64
		ref, nonceOfE, nonceOfN []byte
	}{
		{"the group id", linkSasRepeated(0x22), 1, keyPackageRef, nonceE, nonceN},
		{"the epoch", groupId, 2, keyPackageRef, nonceE, nonceN},
		{"the key package ref", groupId, 1, linkSasRepeated(0x34), nonceE, nonceN},
		{"E's nonce", groupId, 1, keyPackageRef, linkSasRepeated(0x45), nonceN},
		{"N's nonce", groupId, 1, keyPackageRef, nonceE, linkSasRepeated(0x56)},
	} {
		other, err := LinkSas(&linkSasTestExporter{}, moved.group, moved.epoch, moved.ref, moved.nonceOfE, moved.nonceOfN)
		if err != nil {
			t.Fatal(err)
		}
		if other == emoji {
			t.Errorf("changing %s leaves the emoji as they were", moved.name)
		}
	}

	// inputs that make no emoji
	for name, call := range map[string]func() error{
		"no exporter":          func() error { _, err := LinkSas(nil, groupId, 1, keyPackageRef, nonceE, nonceN); return err },
		"no group id":          func() error { _, err := LinkSas(exporter, nil, 1, keyPackageRef, nonceE, nonceN); return err },
		"no key package ref":   func() error { _, err := LinkSas(exporter, groupId, 1, nil, nonceE, nonceN); return err },
		"a short nonce of E's": func() error { _, err := LinkSas(exporter, groupId, 1, keyPackageRef, nonceE[:31], nonceN); return err },
		"a short nonce of N's": func() error { _, err := LinkSas(exporter, groupId, 1, keyPackageRef, nonceE, nonceN[:31]); return err },
	} {
		if err := call(); !errors.Is(err, ErrLinkSasInput) {
			t.Errorf("%s: %v", name, err)
		}
	}

	// the list is the vendored m.sas.v1 file, entry by entry, and the file is the pinned one
	file, err := os.ReadFile("testdata/vectors/matrix/sas-emoji.json")
	if err != nil {
		t.Fatal(err)
	}
	if sum := sha256.Sum256(file); phraseHexText(sum[:]) != linkSasEmojiListSha256 {
		t.Fatalf("the vendored sas-emoji.json hashes to %x, want the pin %s", sum, linkSasEmojiListSha256)
	}
	var vendored []struct {
		Number      int    `json:"number"`
		Emoji       string `json:"emoji"`
		Description string `json:"description"`
	}
	if err := json.Unmarshal(file, &vendored); err != nil {
		t.Fatal(err)
	}
	if len(vendored) != len(linkSasEmojiList) {
		t.Fatalf("the vendored list has %d entries and the package's %d", len(vendored), len(linkSasEmojiList))
	}
	for index, entry := range vendored {
		if entry.Number != index || entry.Emoji != linkSasEmojiList[index].emoji || entry.Description != linkSasEmojiList[index].name {
			t.Errorf("entry %d is %q %q in the vendored list and %q %q in the package's",
				index, entry.Emoji, entry.Description, linkSasEmojiList[index].emoji, linkSasEmojiList[index].name)
		}
	}
	names := []string{}
	for _, entry := range linkSasEmojiList {
		names = append(names, entry.name)
	}
	if len(slices.Compact(slices.Sorted(slices.Values(names)))) != 64 {
		t.Error("two emoji of the list share a name")
	}
}
