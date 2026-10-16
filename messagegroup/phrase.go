// The recovery phrase, version 1: MASTER section 5.1 at Revision 10, as ledger item 299's
// registry froze it (identity phase 1's plan, Task 10).
//
//	P      = 267 bits from crypto/rand, the ONLY source; no call takes entropy from its caller
//	P34    = P as 34 octets, its 5 high bits zero
//	CS8    = the top 8 bits of SHA-256("URmessage/v1/phrase-checksum" ‖ P34)
//	phrase = the 275 bits P ‖ CS8, as 25 × 11-bit indices, most significant bit first,
//	         into the BIP-39 English list (vendored, and pinned by its SHA-256)
//
// The phrase is shown once when it is made, typed back in full, and never stored. Input is
// normalized: NFKD, lowercase, whitespace collapsed. A word not in the list is named by its
// position, and a checksum that fails says that one or more words are wrong. NOTHING IS EVER
// CORRECTED (OD section 3, "an 8-bit checksum, with no typo repair"): there is no search for a
// likely word, no prefix that stands for a word, and no accent folded away, so a wrong word is
// never guessed into a right one. About one single-word slip in 256 passes the checksum, and
// MASTER section 5.5's words check refuses it before it changes anything.
//
// WHAT THE NORMALIZATION IS, EXACTLY, AND WHY IT NEEDS A TABLE. Every word of the list is ASCII
// a to z, so of NFKD's whole effect only two things can change an answer: a code point whose
// decomposition is ASCII letters (a fullwidth letter, a ligature, a mathematical letter, a
// squared abbreviation, the Kelvin sign), which must read as those letters, and a code point
// whose decomposition holds white space (a no-break space, an ideographic space, a spacing
// diaeresis), which must split a word where NFKD would. Everything else NFKD can produce holds a
// character outside a to z, and a word holding one is not a list word whatever else it holds.
// So the fold is read per code point off phrase_nfkd.go's spans, and that is exact rather than
// approximate: NFKD is each code point's full decomposition followed by a canonical reordering
// that moves combining marks only among themselves, so it never moves one across a space or a
// letter, and lowercasing after it can reach ASCII only from A to Z. The standard library has no
// NFKD, and golang.org/x/text is not in this module's go.mod, which no task of this plan changes;
// the spans were generated from x/text's unicode/norm at the pinned toolchain's Unicode edition
// and checked against whole-string NFKD over every code point (see phrase_nfkd.go).
package messagegroup

import (
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"fmt"

	"github.com/urnetwork/message/mls"
)

// RecoveryPhraseWordCount is the number of words a recovery phrase has: 25, the owner's "25
// words, max strength" (OD section 3).
const RecoveryPhraseWordCount = 25

const (
	// the octets P is carried in: 267 bits and five zero bits above them
	phraseOctets = 34
	// the five high bits of P34's first octet that are always zero
	phraseHighBitsMask = 0xF8
	// the bits each word carries, and so the size of the list
	phraseWordBits = 11
	phraseListSize = 1 << phraseWordBits
	// the longest word of the list, which bounds a token that can still be a list word
	phraseLongestWord = 8
)

// The label the checksum's hash is taken under (ledger item 299).
const phraseChecksumLabel = "URmessage/v1/phrase-checksum"

// The BIP-39 English list, vendored as bip39_english.txt: 2048 lines, each one word and a line
// feed, exactly as github.com/bitcoin/bips publishes bip-0039/english.txt.
//
//go:embed bip39_english.txt
var bip39EnglishFile string

// The list's SHA-256 (F3 X1), the pin the list is held to before a word of it is used. It is the
// digest of the file whose CRC32 go-bip39 pins as c1dbd296.
var bip39EnglishSha256 = [sha256.Size]byte{
	0x2f, 0x5e, 0xed, 0x53, 0xa4, 0x72, 0x7b, 0x4b, 0xf8, 0x88, 0x0d, 0x8f, 0x3f, 0x19, 0x9e, 0xfc,
	0x90, 0xe5, 0x85, 0x03, 0x64, 0x6d, 0x9f, 0xf8, 0xef, 0xf3, 0xa2, 0xed, 0x3b, 0x24, 0xdb, 0xda,
}

// The list in order, and each word's index. Both are read once, out of the pinned file.
var phraseList, phraseListIndex = mustReadPhraseList(bip39EnglishFile)

// The list, or a stopped process. A file that is not the pinned list -- a checkout that rewrote
// its line endings is the likely cause -- would make phrases nobody else can read, so it stops
// the process at initialisation rather than write a word from it.
func mustReadPhraseList(file string) ([phraseListSize]string, map[string]uint16) {
	if sha256.Sum256([]byte(file)) != bip39EnglishSha256 {
		panic(fmt.Errorf("messagegroup: bip39_english.txt is not the BIP-39 English list its SHA-256 pins: %w", ErrRecoveryPhraseList))
	}
	var list [phraseListSize]string
	index := make(map[string]uint16, phraseListSize)
	count := 0
	start := 0
	for at := 0; at < len(file); at++ {
		if file[at] != '\n' {
			continue
		}
		if count == phraseListSize {
			panic(fmt.Errorf("messagegroup: bip39_english.txt holds more than %d words: %w", phraseListSize, ErrRecoveryPhraseList))
		}
		list[count] = file[start:at]
		index[file[start:at]] = uint16(count)
		count += 1
		start = at + 1
	}
	if count != phraseListSize || start != len(file) || len(index) != phraseListSize {
		panic(fmt.Errorf("messagegroup: bip39_english.txt holds %d words, %d of them distinct, want %d: %w",
			count, len(index), phraseListSize, ErrRecoveryPhraseList))
	}
	return list, index
}

// RecoveryPhrase is a recovery phrase, version 1: its 267 bits, held as P34.
//
// It is a phrase secret. It exists only while a ceremony runs -- it is shown, typed back, and
// stretched -- and Erase blanks it when the ceremony ends. Nothing in this package stores one.
type RecoveryPhrase struct {
	p34 [phraseOctets]byte
}

// The provider the phrase's bits are drawn through: mls's provider over the process entropy
// source, crypto/rand, which MASTER section 5.1 makes the ONLY source of a phrase. Every other
// draw in this package takes an injected io.Reader; this one takes none, by the same section's
// "no call takes entropy from its caller". It reaches crypto/rand through mls because this
// package does not import it.
var phraseDraw = mustPhraseDraw()

// The provider, or a stopped process, as mustKeyScheduleCrypto has it.
func mustPhraseDraw() mls.CryptoProvider {
	crypto, err := mls.NewCryptoProvider(mls.CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		panic(fmt.Errorf("messagegroup: the phrase's crypto provider names an unregistered suite: %w", err))
	}
	return crypto
}

// NewRecoveryPhrase makes a recovery phrase: 267 bits from crypto/rand. It takes no entropy from
// its caller, so no caller can hand it a weak source.
func NewRecoveryPhrase() (*RecoveryPhrase, error) {
	phraseDrawn := phraseDraw.Random(phraseOctets)
	defer zeroize(phraseDrawn)
	phrase := &RecoveryPhrase{}
	copy(phrase.p34[:], phraseDrawn)
	phrase.p34[0] &^= phraseHighBitsMask
	return phrase, nil
}

// Words answers the phrase's 25 words, for the one time it is shown. Each is a string of the list
// itself, so answering them makes no copy of a word; but the slice that orders them IS the phrase
// -- its 25 string headers point into the list at its words -- so the caller clears it,
// clear(words), when the words are off the screen. A slice dropped without that holds the phrase
// in freed heap until the memory is reused (the review of Tasks 8 to 10, L1-6).
func (self *RecoveryPhrase) Words() []string {
	phraseIndices := phraseIndicesOf(&self.p34)
	defer clear(phraseIndices[:])
	phraseWords := make([]string, RecoveryPhraseWordCount)
	for position, phraseIndex := range phraseIndices {
		phraseWords[position] = phraseList[phraseIndex]
	}
	return phraseWords
}

// Format writes a fixed redaction under every verb, so that no fmt call -- a log line, a wrapped
// error -- carries an octet of P34 (the review of Tasks 8 to 10, L1-4). fmt.Formatter rather than
// String, because fmt consults a Stringer only for v, s, x, X and q, and %d of P34 would print it;
// and a value receiver, so that a RecoveryPhrase value is covered as a pointer is. It writes the
// same text whatever the verb.
func (self RecoveryPhrase) Format(state fmt.State, verb rune) {
	fmt.Fprint(state, recoveryPhraseRedacted)
}

// What every fmt verb writes for a RecoveryPhrase.
const recoveryPhraseRedacted = "messagegroup.RecoveryPhrase{redacted}"

// CheckRecoveryPhraseWord answers whether typed is one word of the list, read through the same
// fold a phrase is: NFKD, lowercase, white space collapsed. Spec A section 9.3a's check_word, for
// a screen that marks each word as it is typed (Task 14). Two list words, or none, answer false.
func CheckRecoveryPhraseWord(typed string) bool {
	phraseIndices, count, notInTheList := phraseTokensOf(typed)
	clear(phraseIndices[:])
	return count == 1 && len(notInTheList) == 0
}

// Equal answers whether two phrases are the same phrase, in constant time: it is what "typed back
// in full" compares.
func (self *RecoveryPhrase) Equal(other *RecoveryPhrase) bool {
	if self == nil || other == nil {
		return false
	}
	return subtle.ConstantTimeCompare(self.p34[:], other.p34[:]) == 1
}

// Erase blanks the phrase, at the end of the ceremony that made or read it.
//
//go:noinline
func (self *RecoveryPhrase) Erase() {
	if self == nil {
		return
	}
	zeroize(self.p34[:])
}

// ParseRecoveryPhrase reads typed words as a recovery phrase.
//
// The input is normalized -- NFKD, lowercase, whitespace collapsed -- and then, in this order:
// every word that is not one of the list's is named by its position, from 1, in the second
// result, beside [ErrRecoveryPhraseWord]; a count other than 25 is [ErrRecoveryPhraseWordCount];
// and 25 list words whose checksum fails are [ErrRecoveryPhraseChecksum], which says that one or
// more words are wrong and never which. Nothing is corrected, and no refusal carries a word.
func ParseRecoveryPhrase(phraseTyped string) (*RecoveryPhrase, []int, error) {
	phraseIndices, count, notInTheList := phraseTokensOf(phraseTyped)
	defer clear(phraseIndices[:])
	if len(notInTheList) != 0 {
		return nil, notInTheList, fmt.Errorf("%w: at %v", ErrRecoveryPhraseWord, notInTheList)
	}
	if count != RecoveryPhraseWordCount {
		return nil, nil, fmt.Errorf("%w: it has %d", ErrRecoveryPhraseWordCount, count)
	}
	phrase := &RecoveryPhrase{}
	if !phraseFromIndices(&phraseIndices, &phrase.p34) {
		phrase.Erase()
		return nil, nil, ErrRecoveryPhraseChecksum
	}
	return phrase, nil, nil
}

// CS8: the first octet of SHA-256("URmessage/v1/phrase-checksum" ‖ P34). The label and P34 are
// written into the hash one after the other, so no preimage holding P34 is assembled.
func phraseChecksumOf(p34 *[phraseOctets]byte) byte {
	digest := sha256.New()
	digest.Write([]byte(phraseChecksumLabel))
	digest.Write(p34[:])
	sum := digest.Sum(nil)
	checksum := sum[0]
	zeroize(sum)
	return checksum
}

// The 25 indices of P ‖ CS8: the 280 bits of P34 ‖ CS8 less their five zero high bits, eleven at
// a time, most significant first.
func phraseIndicesOf(p34 *[phraseOctets]byte) [RecoveryPhraseWordCount]uint16 {
	phraseCarried := phraseCarriedOf(p34)
	var phraseIndices [RecoveryPhraseWordCount]uint16
	for position := range phraseIndices {
		phraseIndices[position] = phraseBitsAt(&phraseCarried, 5+phraseWordBits*position)
	}
	zeroize(phraseCarried[:])
	return phraseIndices
}

// P34 ‖ CS8, the 280 bits the indices are read from.
func phraseCarriedOf(p34 *[phraseOctets]byte) [phraseOctets + 1]byte {
	var phraseCarried [phraseOctets + 1]byte
	copy(phraseCarried[:], p34[:])
	phraseCarried[phraseOctets] = phraseChecksumOf(p34)
	return phraseCarried
}

// Eleven bits of the carried octets, from the bit at offset, most significant first.
func phraseBitsAt(phraseCarried *[phraseOctets + 1]byte, offset int) uint16 {
	var value uint16
	for bit := offset; bit < offset+phraseWordBits; bit++ {
		value = value<<1 | uint16(phraseCarried[bit/8]>>(7-bit%8)&1)
	}
	return value
}

// P34 from 25 indices, and whether their checksum holds.
func phraseFromIndices(phraseIndices *[RecoveryPhraseWordCount]uint16, p34 *[phraseOctets]byte) bool {
	phraseCarried := phraseCarriedFromIndices(phraseIndices)
	copy(p34[:], phraseCarried[:phraseOctets])
	holds := subtle.ConstantTimeByteEq(phraseCarried[phraseOctets], phraseChecksumOf(p34)) == 1
	zeroize(phraseCarried[:])
	return holds
}

// P34 ‖ CS8 out of 25 indices: each fills its eleven bits of bits 5 to 279, so P34's five high
// bits are zero by construction. Every bit is written, one or zero, with no branch on its value.
func phraseCarriedFromIndices(phraseIndices *[RecoveryPhraseWordCount]uint16) [phraseOctets + 1]byte {
	var phraseCarried [phraseOctets + 1]byte
	for position, phraseIndex := range phraseIndices {
		for bit := 0; bit < phraseWordBits; bit++ {
			at := 5 + phraseWordBits*position + bit
			phraseCarried[at/8] |= byte(phraseIndex>>(phraseWordBits-1-bit)&1) << (7 - at%8)
		}
	}
	return phraseCarried
}

// The words of typed input, normalized: the list index of each of the first 25 words, how many
// words there are, and the position, from 1, of every word that is not one of the list's.
//
// A word is a maximal run between white space, after NFKD and lowercase. A run holding anything
// but a to z, or longer than the list's longest word, is not a list word, and neither is a run of
// letters the list does not hold: a prefix is not its word and nothing is looked up near it.
func phraseTokensOf(phraseTyped string) ([RecoveryPhraseWordCount]uint16, int, []int) {
	reading := phraseReading{notInTheList: []int{}}
	for _, phraseCharacter := range phraseTyped {
		reading.take(phraseFoldOf(phraseCharacter))
	}
	reading.end()
	phraseIndices := reading.phraseIndices
	clear(reading.phraseIndices[:])
	return phraseIndices, reading.count, reading.notInTheList
}

// One reading of typed input, a word at a time. Its typed letters are the only copy of a typed
// word this package makes, and they are blanked at the end of every word.
type phraseReading struct {
	phraseIndices [RecoveryPhraseWordCount]uint16
	typedLetters  [phraseLongestWord]byte
	length        int
	open          bool
	junk          bool
	count         int
	notInTheList  []int
}

// One code point's fold, symbol by symbol: a letter extends the word, a space ends it, and a mark
// outside a to z makes it a word that is not on the list.
func (self *phraseReading) take(phraseFold string) {
	for at := 0; at < len(phraseFold); at++ {
		symbol := phraseFold[at]
		switch {
		case symbol == ' ':
			self.end()
		case 'a' <= symbol && symbol <= 'z':
			if self.length < phraseLongestWord {
				self.typedLetters[self.length] = symbol
			}
			self.length += 1
			self.open = true
		default:
			self.junk = true
			self.open = true
		}
	}
}

// The end of a word: it is counted, and it is either a list word, whose index is kept if it is
// among the first 25, or a word that is not, whose position is kept. The typed letters are blanked
// either way.
//
//go:noinline
func (self *phraseReading) end() {
	if !self.open {
		return
	}
	self.count += 1
	phraseIndex, listed := uint16(0), false
	if !self.junk && self.length <= phraseLongestWord {
		phraseIndex, listed = phraseListIndex[string(self.typedLetters[:self.length])]
	}
	switch {
	case !listed:
		self.notInTheList = append(self.notInTheList, self.count)
	case self.count <= RecoveryPhraseWordCount:
		self.phraseIndices[self.count-1] = phraseIndex
	}
	zeroize(self.typedLetters[:])
	self.length = 0
	self.open = false
	self.junk = false
}

// The letters of the alphabet, which a fold of one letter is a window onto.
const phraseLetters = "abcdefghijklmnopqrstuvwxyz"

// A fold that is one mark outside a to z: what every code point the spans do not list folds to.
const phraseFoldJunk = "#"

// A fold is written in three symbols: a to z, a space for any white space, and '#' for anything
// else. take reads them, and mustReadPhraseList reads the list file's line feeds, as the decoders
// they are, octet by octet with go's comparisons: neither compares a secret with anything, and a
// table of classes would buy no constant time, since the word a fold spells is looked up in a map
// in any case. mls/framing_guard_test.go's octet comparison gate holds the two as a decoder's, in
// rows scoped to these two declarations (LRI R65 item 7).

// The ASCII white space characters, which are unicode.IsSpace's below U+0080.
const phraseAsciiSpaces = "\t\n\v\f\r "

// The fold of each ASCII code point. NFKD changes none of them, so the fold is lowercase over the
// three symbols: a letter is its lowercase self, white space is a space, and anything else a mark.
var phraseAsciiFolds = phraseAsciiFoldTable()

func phraseAsciiFoldTable() [0x80]string {
	var table [0x80]string
	for octet := range table {
		table[octet] = phraseFoldJunk
	}
	for letter := range len(phraseLetters) {
		table['a'+letter] = phraseLetters[letter : letter+1]
		table['A'+letter] = phraseLetters[letter : letter+1]
	}
	for _, space := range phraseAsciiSpaces {
		table[space] = " "
	}
	return table
}

// phraseFoldSpan is one span of phrase_nfkd.go's table: the code points lo to hi, each of whose
// NFKD, lowercased, holds an ASCII letter or white space. When step is false every one of them
// folds to fold; when it is true fold is one letter and lo+i folds to the letter i places after
// it. A fold is written over three symbols: a to z, a space for any white space, and '#' for a
// run of anything else.
type phraseFoldSpan struct {
	lo   rune
	hi   rune
	fold string
	step bool
}

// The fold of one code point: NFKD, then lowercase, over the three symbols.
func phraseFoldOf(character rune) string {
	if character < 0x80 {
		return phraseAsciiFolds[character]
	}
	low, high := 0, len(phraseFoldSpans)
	for low < high {
		middle := low + (high-low)/2
		span := &phraseFoldSpans[middle]
		switch {
		case character < span.lo:
			high = middle
		case span.hi < character:
			low = middle + 1
		case span.step:
			letter := int(span.fold[0]-'a') + int(character-span.lo)
			return phraseLetters[letter : letter+1]
		default:
			return span.fold
		}
	}
	return phraseFoldJunk
}
