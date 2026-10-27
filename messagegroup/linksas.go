// The seven emoji of a link session: identity phase 1's plan, Task 11. MASTER section 5.4 at
// Revision 10, Spec A A-36's section 7.5, and ledger item 300, which freezes the label.
//
//	sas   = the link group's Export("URmessage/v1/link-sas-emoji",
//	          LP(group_id) ‖ u64(epoch) ‖ LP(KeyPackageRef_N) ‖ LP(n_E) ‖ LP(n_N), 32), at epoch 1
//	emoji = the first 42 bits of sas, most significant first, six to an emoji, as 7 indices into
//	        the Matrix specification's m.sas.v1 list of 64
//
// That is F1 section 2.2's SAS input, under the label of round 4's F1, which turned its six digits
// into emoji. The new device commits to n_N before E's nonce exists, and the emoji are exported at
// epoch 1 over the group id and the epoch, so an interceptor passes one session with probability
// 2^-42 (F1 section 2.8; SCOPE E4). The session that shows them is the sdk's (Tasks 22 and 23).
package messagegroup

import (
	"fmt"

	"github.com/urnetwork/message/syntax"
)

// LinkSasEmojiCount is how many emoji a session shows.
const LinkSasEmojiCount = 7

const (
	// the exporter label (item 300)
	linkSasExporterLabel = "URmessage/v1/link-sas-emoji"
	// the exported octets, of which the first 42 bits are used
	linkSasExportOctets = 32
	// each side's nonce: 32 octets of crypto/rand
	linkSasNonceOctets = 32
	// the bits of one emoji, and so the size of the list
	linkSasBitsPerEmoji = 6
)

// LinkEmoji is one emoji of a session: its index in the m.sas.v1 list, the emoji, and its name.
type LinkEmoji struct {
	Index int
	Emoji string
	Name  string
}

// LinkSasExporter is what the emoji are read through: the link group's MLS exporter at epoch 1,
// which GroupHandle.Export is.
type LinkSasExporter interface {
	Export(label string, context []byte, length int) ([]byte, error)
}

// LinkSas answers a session's seven emoji, from the link group's exporter over the group id, the
// epoch, the new device's key package ref and both nonces. Both devices compute them and show the
// same row; every input moves them.
func LinkSas(exporter LinkSasExporter, groupId []byte, epoch uint64, keyPackageRef []byte,
	nonceE []byte, nonceN []byte) ([LinkSasEmojiCount]LinkEmoji, error) {

	var emoji [LinkSasEmojiCount]LinkEmoji
	if exporter == nil || len(groupId) == 0 || len(keyPackageRef) == 0 ||
		len(nonceE) != linkSasNonceOctets || len(nonceN) != linkSasNonceOctets {
		return emoji, fmt.Errorf("%w: a group id of %d octets, a key package ref of %d, nonces of %d and %d",
			ErrLinkSasInput, len(groupId), len(keyPackageRef), len(nonceE), len(nonceN))
	}
	writer := syntax.NewWriter()
	writer.WriteOpaqueLP(groupId)
	writer.WriteUint64(epoch)
	writer.WriteOpaqueLP(keyPackageRef)
	writer.WriteOpaqueLP(nonceE)
	writer.WriteOpaqueLP(nonceN)
	context, err := writer.Bytes()
	if err != nil {
		return emoji, fmt.Errorf("%w: %v", ErrLinkSasInput, err)
	}
	sas, err := exporter.Export(linkSasExporterLabel, context, linkSasExportOctets)
	if err != nil {
		return emoji, err
	}
	defer zeroize(sas)
	if len(sas) != linkSasExportOctets {
		return emoji, fmt.Errorf("%w: the exporter answered %d octets", ErrLinkSasInput, len(sas))
	}
	for position, index := range linkSasIndicesOf(sas) {
		emoji[position] = LinkEmoji{Index: index, Emoji: linkSasEmojiList[index].emoji, Name: linkSasEmojiList[index].name}
	}
	return emoji, nil
}

// The seven indices: the first 42 bits of sas, most significant first, six at a time.
func linkSasIndicesOf(sas []byte) [LinkSasEmojiCount]int {
	var indices [LinkSasEmojiCount]int
	for position := range indices {
		index := 0
		for bit := linkSasBitsPerEmoji * position; bit < linkSasBitsPerEmoji*(position+1); bit++ {
			index = index<<1 | int(sas[bit/8]>>(7-bit%8)&1)
		}
		indices[position] = index
	}
	return indices
}

// linkSasEmojiList is the Matrix specification's m.sas.v1 list, in its order: the "emoji" and
// "description" fields of data-definitions/sas-emoji.json at github.com/matrix-org/matrix-spec
// commit 7aaeac07608f97942eff88634a56b630a745ce56, whose SHA-256 is
// 2b4defb276d61f11cb9cbfb0ba326b96a8dbd9e768e6bc53fa0f565cd598e887.
// That file is vendored whole as testdata/vectors/matrix/sas-emoji.json, pinned there by that
// digest, and linksas_test.go holds this list to it, entry by entry.
var linkSasEmojiList = [1 << linkSasBitsPerEmoji]struct {
	emoji string
	name  string
}{
	{"\U0001f436", "Dog"},         // 0
	{"\U0001f431", "Cat"},         // 1
	{"\U0001f981", "Lion"},        // 2
	{"\U0001f40e", "Horse"},       // 3
	{"\U0001f984", "Unicorn"},     // 4
	{"\U0001f437", "Pig"},         // 5
	{"\U0001f418", "Elephant"},    // 6
	{"\U0001f430", "Rabbit"},      // 7
	{"\U0001f43c", "Panda"},       // 8
	{"\U0001f413", "Rooster"},     // 9
	{"\U0001f427", "Penguin"},     // 10
	{"\U0001f422", "Turtle"},      // 11
	{"\U0001f41f", "Fish"},        // 12
	{"\U0001f419", "Octopus"},     // 13
	{"\U0001f98b", "Butterfly"},   // 14
	{"\U0001f337", "Flower"},      // 15
	{"\U0001f333", "Tree"},        // 16
	{"\U0001f335", "Cactus"},      // 17
	{"\U0001f344", "Mushroom"},    // 18
	{"\U0001f30f", "Globe"},       // 19
	{"\U0001f319", "Moon"},        // 20
	{"\u2601\ufe0f", "Cloud"},     // 21
	{"\U0001f525", "Fire"},        // 22
	{"\U0001f34c", "Banana"},      // 23
	{"\U0001f34e", "Apple"},       // 24
	{"\U0001f353", "Strawberry"},  // 25
	{"\U0001f33d", "Corn"},        // 26
	{"\U0001f355", "Pizza"},       // 27
	{"\U0001f382", "Cake"},        // 28
	{"\u2764\ufe0f", "Heart"},     // 29
	{"\U0001f600", "Smiley"},      // 30
	{"\U0001f916", "Robot"},       // 31
	{"\U0001f3a9", "Hat"},         // 32
	{"\U0001f453", "Glasses"},     // 33
	{"\U0001f527", "Spanner"},     // 34
	{"\U0001f385", "Santa"},       // 35
	{"\U0001f44d", "Thumbs Up"},   // 36
	{"\u2602\ufe0f", "Umbrella"},  // 37
	{"\u231b", "Hourglass"},       // 38
	{"\u23f0", "Clock"},           // 39
	{"\U0001f381", "Gift"},        // 40
	{"\U0001f4a1", "Light Bulb"},  // 41
	{"\U0001f4d5", "Book"},        // 42
	{"\u270f\ufe0f", "Pencil"},    // 43
	{"\U0001f4ce", "Paperclip"},   // 44
	{"\u2702\ufe0f", "Scissors"},  // 45
	{"\U0001f512", "Lock"},        // 46
	{"\U0001f511", "Key"},         // 47
	{"\U0001f528", "Hammer"},      // 48
	{"\u260e\ufe0f", "Telephone"}, // 49
	{"\U0001f3c1", "Flag"},        // 50
	{"\U0001f682", "Train"},       // 51
	{"\U0001f6b2", "Bicycle"},     // 52
	{"\u2708\ufe0f", "Aeroplane"}, // 53
	{"\U0001f680", "Rocket"},      // 54
	{"\U0001f3c6", "Trophy"},      // 55
	{"\u26bd", "Ball"},            // 56
	{"\U0001f3b8", "Guitar"},      // 57
	{"\U0001f3ba", "Trumpet"},     // 58
	{"\U0001f514", "Bell"},        // 59
	{"\u2693", "Anchor"},          // 60
	{"\U0001f3a7", "Headphones"},  // 61
	{"\U0001f4c1", "Folder"},      // 62
	{"\U0001f4cc", "Pin"},         // 63
}
