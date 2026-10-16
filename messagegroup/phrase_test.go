// The recovery phrase's Property 1 (identity phase 1's plan, Task 10): a phrase round-trips; one
// word changed, or two swapped, is refused; a word not in the list is named by its position; and
// no input is ever corrected.
//
// THE ANSWERS HERE WERE NOT READ OUT OF THE CODE THEY CHECK. The two known phrases' words were
// computed from MASTER section 5.1's four lines by a script that shares no code with this package
// -- Python's hashlib and integer arithmetic over the same pinned list -- and every checksum
// verdict below is the test's own: phraseOracleOf decodes 25 indices with math/big and hashes the
// result itself, so a parser that stopped checking, or checked the wrong bits, disagrees with it.
package messagegroup

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"unicode"
)

// The two phrases of the known answers. A is the all-zero phrase; B's 34 octets are the first 34
// of SHA-512("URmessage/v1 known-answer phrase B") with the five high bits cleared.
const (
	phraseAP34Hex = "00000000000000000000000000000000000000000000000000000000000000000000"
	phraseBP34Hex = "014cf3e8c2ab71cdcefe8cd43d97d10f2503f44e7a79c889c96bbbeb39c2b290ed37"
)

var (
	phraseAWords = strings.Fields("abandon abandon abandon abandon abandon abandon abandon abandon " +
		"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon " +
		"abandon abandon abandon abandon abandon admit")
	phraseBWords = strings.Fields("civil view ecology print toe table leg crew marble oak mask sing " +
		"among eager diamond transfer bachelor siren fruit width inform clinic embody regular various")
)

// The pin, written out here from F3 X1 rather than read off phrase.go's own constant, so a pin
// edited there fails here.
const bip39EnglishSha256Hex = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"

func phraseHexOctets(t *testing.T, text string) []byte {
	t.Helper()
	octets := make([]byte, len(text)/2)
	for at := range octets {
		high := strings.IndexByte(phraseHexDigits, text[2*at])
		low := strings.IndexByte(phraseHexDigits, text[2*at+1])
		if high < 0 || low < 0 || len(text)%2 != 0 {
			t.Fatalf("%q is not lowercase hex", text)
		}
		octets[at] = byte(high*16 + low)
	}
	return octets
}

func phraseHexText(octets []byte) string {
	text := make([]byte, 0, 2*len(octets))
	for _, octet := range octets {
		text = append(text, phraseHexDigits[octet/16], phraseHexDigits[octet%16])
	}
	return string(text)
}

// The test's own decoding of 25 indices: P34, the checksum the words carry, and whether it is
// the checksum P34 has. It is math/big over the 275 bits, which shares nothing with phrase.go's
// bit loops.
func phraseOracleOf(t *testing.T, words []string) ([]byte, bool) {
	t.Helper()
	list := phraseListFromDisk(t)
	carried := new(big.Int)
	for _, word := range words {
		index := slices.Index(list, word)
		if index < 0 {
			t.Fatalf("%q is not on the list", word)
		}
		carried.Lsh(carried, 11)
		carried.Or(carried, big.NewInt(int64(index)))
	}
	if len(words) != 25 {
		t.Fatalf("the oracle reads 25 words, not %d", len(words))
	}
	checksum := byte(new(big.Int).And(carried, big.NewInt(0xFF)).Int64())
	p := new(big.Int).Rsh(carried, 8)
	p34 := p.FillBytes(make([]byte, 34))
	sum := sha256.Sum256(append([]byte("URmessage/v1/phrase-checksum"), p34...))
	return p34, sum[0] == checksum
}

// The list as the file on disk holds it, read and split here rather than through phrase.go.
func phraseListFromDisk(t *testing.T) []string {
	t.Helper()
	file, err := os.ReadFile("bip39_english.txt")
	if err != nil {
		t.Fatalf("read the vendored list: %v", err)
	}
	if !strings.HasSuffix(string(file), "\n") {
		t.Fatal("the vendored list does not end in a line feed")
	}
	return strings.Split(strings.TrimSuffix(string(file), "\n"), "\n")
}

func phraseMustParse(t *testing.T, typed string) *RecoveryPhrase {
	t.Helper()
	phrase, positions, err := ParseRecoveryPhrase(typed)
	if err != nil || positions != nil {
		t.Fatalf("ParseRecoveryPhrase(%q): %v, positions %v", typed, err, positions)
	}
	return phrase
}

// The positions a refusal names, with the refusal checked to be exactly ErrRecoveryPhraseWord
// and those positions: the text has no room for a word, and no phrase comes back.
func phraseRefusedAt(t *testing.T, typed string) []int {
	t.Helper()
	phrase, positions, err := ParseRecoveryPhrase(typed)
	if phrase != nil || len(positions) == 0 {
		t.Fatalf("ParseRecoveryPhrase answers %v and positions %v, want a refusal naming positions", phrase, positions)
	}
	if errors.Unwrap(err) != ErrRecoveryPhraseWord || err.Error() != ErrRecoveryPhraseWord.Error()+": at "+fmt.Sprint(positions) {
		t.Errorf("the refusal is %q, want exactly ErrRecoveryPhraseWord and the positions %v", err, positions)
	}
	return positions
}

func TestAPhraseRoundTripsAndOneWrongWordIsRefusedByItsPosition(t *testing.T) {
	t.Run("the list is the vendored BIP-39 English list, pinned by its SHA-256", func(t *testing.T) {
		file, err := os.ReadFile("bip39_english.txt")
		if err != nil {
			t.Fatal(err)
		}
		if got := phraseHexText(func() []byte { sum := sha256.Sum256(file); return sum[:] }()); got != bip39EnglishSha256Hex {
			t.Fatalf("bip39_english.txt hashes to %s on disk, want F3's pin %s; a checkout that rewrote its line endings is the likeliest cause", got, bip39EnglishSha256Hex)
		}
		if string(file) != bip39EnglishFile {
			t.Error("the list built into the package is not the file on disk")
		}
		if phraseHexText(bip39EnglishSha256[:]) != bip39EnglishSha256Hex {
			t.Errorf("phrase.go pins %x, F3 X1 pins %s", bip39EnglishSha256, bip39EnglishSha256Hex)
		}
		list := phraseListFromDisk(t)
		if len(list) != 2048 || !slices.IsSorted(list) || len(slices.Compact(slices.Clone(list))) != 2048 {
			t.Fatalf("the list holds %d words, sorted %v; want 2048 distinct words in order", len(list), slices.IsSorted(list))
		}
		prefixes := map[string]bool{}
		longest := 0
		for at, word := range list {
			if strings.Trim(word, "abcdefghijklmnopqrstuvwxyz") != "" || word == "" {
				t.Errorf("word %d, %q, is not a to z", at, word)
			}
			prefixes[word[:min(4, len(word))]] = true
			longest = max(longest, len(word))
			if phraseList[at] != word || phraseListIndex[word] != uint16(at) {
				t.Errorf("the package reads word %d as %q, index %d; the file has %q", at, phraseList[at], phraseListIndex[word], word)
			}
		}
		if len(prefixes) != 2048 {
			t.Errorf("%d distinct 4-letter prefixes, want 2048 (F3 X1)", len(prefixes))
		}
		if longest != phraseLongestWord {
			t.Errorf("the longest word has %d letters and phrase.go bounds a word at %d", longest, phraseLongestWord)
		}
	})

	t.Run("the two known phrases are their words, both ways", func(t *testing.T) {
		for _, known := range []struct {
			name  string
			p34   string
			words []string
		}{{"A", phraseAP34Hex, phraseAWords}, {"B", phraseBP34Hex, phraseBWords}} {
			phrase := &RecoveryPhrase{}
			copy(phrase.p34[:], phraseHexOctets(t, known.p34))
			if got := phrase.Words(); !slices.Equal(got, known.words) {
				t.Errorf("phrase %s writes %v, want %v", known.name, got, known.words)
			}
			read := phraseMustParse(t, strings.Join(known.words, " "))
			if phraseHexText(read.p34[:]) != known.p34 {
				t.Errorf("phrase %s's words read as %x, want %s", known.name, read.p34, known.p34)
			}
			if p34, holds := phraseOracleOf(t, known.words); !holds || phraseHexText(p34) != known.p34 {
				t.Errorf("the oracle reads phrase %s as %x, checksum holding %v", known.name, p34, holds)
			}
		}
	})

	t.Run("a phrase made here round-trips, with its five high bits zero", func(t *testing.T) {
		if reflect.TypeOf(NewRecoveryPhrase).NumIn() != 0 {
			t.Fatal("NewRecoveryPhrase takes an argument; MASTER section 5.1: no call takes entropy from its caller")
		}
		seen := map[string]bool{}
		for range 256 {
			phrase, err := NewRecoveryPhrase()
			if err != nil {
				t.Fatal(err)
			}
			if phrase.p34[0]&0xF8 != 0 {
				t.Fatalf("a phrase made here has P34[0]'s five high bits %#x, not zero", phrase.p34[0]&0xF8)
			}
			words := phrase.Words()
			if len(words) != 25 {
				t.Fatalf("a phrase has %d words", len(words))
			}
			read := phraseMustParse(t, strings.Join(words, " "))
			if !read.Equal(phrase) {
				t.Fatal("a phrase made here does not read back as the phrase its words were written from")
			}
			if p34, holds := phraseOracleOf(t, words); !holds || string(p34) != string(phrase.p34[:]) {
				t.Fatalf("a phrase made here reads otherwise through the oracle: the same octets %v, its checksum holding %v",
					string(p34) == string(phrase.p34[:]), holds)
			}
			seen[string(phrase.p34[:])] = true
			read.Erase()
			if read.p34 != [phraseOctets]byte{} {
				t.Fatal("Erase left the phrase's octets")
			}
		}
		if len(seen) != 256 {
			t.Errorf("256 phrases made here are %d distinct ones", len(seen))
		}
	})

	t.Run("a word not on the list is named by its position, and only by it", func(t *testing.T) {
		words := slices.Clone(phraseBWords)
		words[11] = "apricott"
		if got := phraseRefusedAt(t, strings.Join(words, " ")); !slices.Equal(got, []int{12}) {
			t.Errorf("the refusal names %v, want [12]", got)
		}
		if _, _, err := ParseRecoveryPhrase(strings.Join(words, " ")); err.Error() != "messagegroup: a word of the recovery phrase is not one of the 2048 words: at [12]" {
			t.Errorf("the refusal reads %q", err.Error())
		}
		words[2], words[24] = "xyzzy", "\u00dcnder"
		if got := phraseRefusedAt(t, strings.Join(words, " ")); !slices.Equal(got, []int{3, 12, 25}) {
			t.Errorf("the refusal names %v, want [3 12 25]", got)
		}
		// the count is not what is named when a word is not on the list: 26 words, one of them
		// not on the list, name that one
		long := append(slices.Clone(phraseBWords), "qq")
		if got := phraseRefusedAt(t, strings.Join(long, " ")); !slices.Equal(got, []int{26}) {
			t.Errorf("the refusal names %v, want [26]", got)
		}
	})

	t.Run("one word changed is refused exactly when its checksum fails", func(t *testing.T) {
		list := phraseListFromDisk(t)
		for _, position := range []int{0, 6, 24} {
			accepted, refused := 0, 0
			for _, word := range list {
				if word == phraseBWords[position] {
					continue
				}
				changed := slices.Clone(phraseBWords)
				changed[position] = word
				phrase, _, err := ParseRecoveryPhrase(strings.Join(changed, " "))
				p34, holds := phraseOracleOf(t, changed)
				switch {
				case holds && err == nil && string(phrase.p34[:]) == string(p34):
					accepted += 1
				case !holds && phrase == nil && err == ErrRecoveryPhraseChecksum:
					refused += 1
				default:
					t.Fatalf("word %d changed to %q: the parser answers a phrase %v, %v and the checksum holds %v", position+1, word, phrase != nil, err, holds)
				}
			}
			// an 8-bit checksum passes about one change in 256, so about 8 of these 2047
			if refused == 0 || accepted+refused != 2047 || 32 < accepted {
				t.Errorf("word %d: %d of 2047 changes accepted and %d refused", position+1, accepted, refused)
			}
			t.Logf("word %d changed: %d of 2047 pass the 8-bit checksum, %d are refused by it", position+1, accepted, refused)
		}
	})

	t.Run("two words swapped are refused exactly when the checksum fails", func(t *testing.T) {
		refused := 0
		for position := 0; position < 24; position++ {
			swapped := slices.Clone(phraseBWords)
			swapped[position], swapped[position+1] = swapped[position+1], swapped[position]
			phrase, _, err := ParseRecoveryPhrase(strings.Join(swapped, " "))
			_, holds := phraseOracleOf(t, swapped)
			switch {
			case holds && err == nil:
			case !holds && phrase == nil && err == ErrRecoveryPhraseChecksum:
				refused += 1
			default:
				t.Fatalf("words %d and %d swapped: the parser answers a phrase %v, %v and the checksum holds %v", position+1, position+2, phrase != nil, err, holds)
			}
		}
		if refused < 20 {
			t.Errorf("%d of 24 adjacent swaps refused", refused)
		}
	})

	t.Run("a count other than 25 is refused", func(t *testing.T) {
		for _, count := range []int{0, 1, 12, 24, 26, 50} {
			words := []string{}
			for len(words) < count {
				words = append(words, phraseBWords...)
			}
			_, _, err := ParseRecoveryPhrase(strings.Join(words[:count], " "))
			if !errors.Is(err, ErrRecoveryPhraseWordCount) {
				t.Errorf("%d words: %v, want ErrRecoveryPhraseWordCount", count, err)
			}
		}
	})

	t.Run("input is normalized: NFKD, lowercase, white space collapsed", func(t *testing.T) {
		want := phraseMustParse(t, strings.Join(phraseBWords, " "))
		forms := map[string]string{
			"upper case":              strings.ToUpper(strings.Join(phraseBWords, " ")),
			"tabs, line feeds, edges": "\t\n " + strings.Join(phraseBWords, "\t\r\n  ") + " \n",
			"a no-break space, an ideographic space, a line separator": strings.Join(phraseBWords[:8], "\u00a0") + "\u3000" +
				strings.Join(phraseBWords[8:16], "\u2028") + "\u205f" + strings.Join(phraseBWords[16:], "\u2009"),
			"fullwidth letters": phraseFullwidth(strings.Join(phraseBWords, " ")),
			"mathematical bold": phraseMathBold(strings.Join(phraseBWords[:5], " ")) + " " + strings.Join(phraseBWords[5:], " "),
			"a long s, which NFKD reads as s": strings.Join(phraseBWords[:11], " ") + " " + "\u017f" +
				phraseBWords[11][1:] + " " + strings.Join(phraseBWords[12:], " "),
		}
		if phraseBWords[11][0] != 's' {
			t.Fatal("phrase B's word 12 no longer begins with s, so the long s form no longer spells it")
		}
		for name, typed := range forms {
			read, _, err := ParseRecoveryPhrase(typed)
			if err != nil || !read.Equal(want) {
				t.Errorf("%s: the form reads as phrase B %v, %v", name, read != nil && read.Equal(want), err)
			}
		}
		// the ligature and the Kelvin sign, each inside one word
		for typed, word := range map[string]string{"\ufb01nd": "find", "\u212ait": "kit", "\ufb02": ""} {
			reading := phraseReading{}
			for _, character := range typed {
				reading.take(phraseFoldOf(character))
			}
			reading.end()
			if word == "" {
				if len(reading.notInTheList) != 1 {
					t.Errorf("%q reads as a list word", typed)
				}
				continue
			}
			if len(reading.notInTheList) != 0 || phraseList[reading.phraseIndices[0]] != word {
				t.Errorf("%q reads as word %d, refused %v; want %q", typed, reading.phraseIndices[0], reading.notInTheList, word)
			}
		}
		// NFKD SPLITS where it puts a space: U+00A8 is a space and a combining diaeresis, so
		// "civil¨ view ..." is 26 words, the second of them a lone mark that is not on the list
		if got := phraseRefusedAt(t, phraseBWords[0]+"\u00a8 "+strings.Join(phraseBWords[1:], " ")); !slices.Equal(got, []int{2}) {
			t.Errorf("a spacing diaeresis after word 1 names %v, want [2]: NFKD writes U+00A8 as a space and a mark", got)
		}
	})

	t.Run("the fold table is well formed and at the toolchain's Unicode edition", func(t *testing.T) {
		if phraseFoldUnicodeVersion != unicode.Version {
			t.Errorf("phrase_nfkd.go was generated at Unicode %s and the toolchain's unicode package is at %s; regenerate it by the rule its header states",
				phraseFoldUnicodeVersion, unicode.Version)
		}
		codePoints := 0
		for at, span := range phraseFoldSpans {
			if span.lo < 0x80 || span.hi < span.lo || (0 < at && span.lo <= phraseFoldSpans[at-1].hi) {
				t.Errorf("span %d, %U to %U, is out of order or below U+0080", at, span.lo, span.hi)
			}
			if 0xD800 <= span.hi && span.lo <= 0xDFFF {
				t.Errorf("span %d holds a surrogate", at)
			}
			if span.fold == "" || strings.Trim(span.fold, "abcdefghijklmnopqrstuvwxyz #") != "" || span.fold == "#" {
				t.Errorf("span %d folds to %q", at, span.fold)
			}
			if span.step && (len(span.fold) != 1 || 'z' < rune(span.fold[0])+(span.hi-span.lo) || span.fold == " ") {
				t.Errorf("step span %d, %U to %U from %q, runs off the alphabet", at, span.lo, span.hi, span.fold)
			}
			codePoints += int(span.hi-span.lo) + 1
		}
		if len(phraseFoldSpans) != 300 || codePoints != 1132 {
			t.Errorf("%d spans over %d code points; the generated table is 300 over 1132", len(phraseFoldSpans), codePoints)
		}
		// members of every class the rule lists, each read off the Unicode standard's own
		// decomposition rather than off the table
		for character, want := range map[rune]string{
			0x00A0: " ", 0x2002: " ", 0x3000: " ", 0x0085: " ", 0x2028: " ", 0x1680: " ",
			0x00A8: " #", 0x00B4: " #", 0xFE49: " #", 0xFDFA: "# # # #",
			0xFF21: "a", 0xFF5A: "z", 0x1D400: "a", 0x1D7C3: "#", 0x24B6: "a", 0x24E9: "z",
			0xFB01: "fi", 0xFB06: "st", 0x0132: "ij", 0x01C6: "#", 0x01C9: "lj",
			0x212A: "k", 0x2160: "i", 0x2173: "iv", 0x217F: "m", 0x33C4: "cc", 0x017F: "s",
			0x00E9: "#", 0x0130: "#", 0x0301: "#", 0xAC00: "#", 0x200B: "#", 0xFEFF: "#", 0xFFFD: "#",
			0x2126: "#", 0x00AA: "a", 0x2071: "i", 0x1D43: "a",
		} {
			if got := phraseFoldOf(character); got != want {
				t.Errorf("%U folds to %q, want %q", character, got, want)
			}
		}
	})

	t.Run("every code point reads the table as it is written", func(t *testing.T) {
		written := map[rune]string{}
		for _, span := range phraseFoldSpans {
			for character := span.lo; character <= span.hi; character++ {
				if span.step {
					written[character] = string(rune(span.fold[0]) + (character - span.lo))
				} else {
					written[character] = span.fold
				}
			}
		}
		for character := rune(0); character <= unicode.MaxRune; character++ {
			if 0xD800 <= character && character <= 0xDFFF {
				continue
			}
			want := "#"
			switch {
			case 'a' <= character && character <= 'z':
				want = string(character)
			case 'A' <= character && character <= 'Z':
				want = string(character - 'A' + 'a')
			case strings.ContainsRune(" \t\n\v\f\r", character):
				want = " "
			case 0x80 <= character:
				if fold, listed := written[character]; listed {
					want = fold
				}
			}
			if got := phraseFoldOf(character); got != want {
				t.Fatalf("%U folds to %q, and the table as written says %q", character, got, want)
			}
		}
	})
}

// The same text in fullwidth letters, U+FF21 to U+FF5A, with its spaces left alone.
func phraseFullwidth(text string) string {
	out := []rune{}
	for _, character := range text {
		switch {
		case 'a' <= character && character <= 'z':
			out = append(out, 0xFF41+character-'a')
		case 'A' <= character && character <= 'Z':
			out = append(out, 0xFF21+character-'A')
		default:
			out = append(out, character)
		}
	}
	return string(out)
}

// The same text in mathematical bold small letters, U+1D41A to U+1D433.
func phraseMathBold(text string) string {
	out := []rune{}
	for _, character := range text {
		if 'a' <= character && character <= 'z' {
			out = append(out, 0x1D41A+character-'a')
		} else {
			out = append(out, character)
		}
	}
	return string(out)
}

// Property 1's last clause, held as its own test because it is the one MI7 attacks: NOTHING IS
// EVER CORRECTED (OD section 3; MASTER section 5.1). F3's design searched single substitutions and
// adjacent swaps and offered what it found; with an 8-bit checksum about 200 of the 51,175 single
// substitutions of any phrase pass, so a search finds a "repair" for nearly every slip and almost
// all of them are wrong. So every near miss below is refused, the refusal is EXACTLY its sentinel
// or exactly the word error -- there is no field or text in either for a candidate to ride in --
// and no phrase comes back.
func TestNoInputIsEverCorrected(t *testing.T) {
	list := phraseListFromDisk(t)
	// a substitution and a swap the oracle shows fail their checksum
	substituted := slices.Clone(phraseBWords)
	for _, word := range list {
		substituted[8] = word
		if _, holds := phraseOracleOf(t, substituted); !holds {
			break
		}
	}
	swapped := slices.Clone(phraseBWords)
	swapped[3], swapped[4] = swapped[4], swapped[3]
	if _, holds := phraseOracleOf(t, swapped); holds {
		t.Fatal("phrase B with words 4 and 5 swapped passes its checksum; pick another pair")
	}
	accented := slices.Clone(phraseBWords)
	accented[0] = "civ\u00edl"
	decomposed := slices.Clone(phraseBWords)
	decomposed[0] = "civi\u0301l"
	prefixed := slices.Clone(phraseBWords)
	prefixed[0] = "civi"
	typo := slices.Clone(phraseBWords)
	typo[3] = "prinx"
	joined := slices.Clone(phraseBWords)
	joined[5] = "tableleg"
	joined = slices.Delete(joined, 6, 7)

	for _, near := range []struct {
		name      string
		typed     []string
		sentinel  error
		positions []int
	}{
		{"one word substituted by another on the list", substituted, ErrRecoveryPhraseChecksum, nil},
		{"two adjacent words swapped", swapped, ErrRecoveryPhraseChecksum, nil},
		{"an accent on a letter, precomposed", accented, nil, []int{1}},
		{"an accent on a letter, as a combining mark", decomposed, nil, []int{1}},
		{"the word's unique four-letter prefix", prefixed, nil, []int{1}},
		{"one letter wrong", typo, nil, []int{4}},
		{"two words run together", joined, nil, []int{6}},
		{"one word missing", phraseBWords[:24], ErrRecoveryPhraseWordCount, nil},
		{"one word too many", append(slices.Clone(phraseBWords), phraseBWords[0]), ErrRecoveryPhraseWordCount, nil},
		{"the 24 words of a BIP-39 mnemonic", strings.Fields("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"), ErrRecoveryPhraseWordCount, nil},
	} {
		phrase, positions, err := ParseRecoveryPhrase(strings.Join(near.typed, " "))
		if phrase != nil {
			t.Errorf("%s: a phrase came back; nothing is corrected", near.name)
			continue
		}
		if near.positions != nil {
			if got := phraseRefusedAt(t, strings.Join(near.typed, " ")); !slices.Equal(got, near.positions) {
				t.Errorf("%s: the refusal names %v, want %v", near.name, got, near.positions)
			}
			continue
		}
		if positions != nil {
			t.Errorf("%s: the refusal names positions %v beside %v", near.name, positions, err)
		}
		switch near.sentinel {
		case ErrRecoveryPhraseChecksum:
			if err != ErrRecoveryPhraseChecksum {
				t.Errorf("%s: the refusal is %#v, want exactly ErrRecoveryPhraseChecksum, which names no word and no candidate", near.name, err)
			}
		default:
			if !errors.Is(err, near.sentinel) || errors.Unwrap(err) != near.sentinel {
				t.Errorf("%s: the refusal is %v, want %v", near.name, err, near.sentinel)
			}
		}
	}
}
