// nfkdgen writes messagegroup/phrase_nfkd.go, the recovery phrase's input fold, from
// golang.org/x/text's unicode/norm (LRI R65 item 1). It is a module of its own, under testdata so
// that the repository's module builds nothing of it and never requires x/text; test.sh runs it,
// `go run . gofile`, and requires its output to be the committed table byte for byte, so the table
// can be neither edited by hand nor stale (the review of identity phase 1's Tasks 8 to 10, L2-10).
//
// For every code point at or above U+0080 it computes NFKD, then lowercase, and writes the
// result over a three-symbol alphabet: an ASCII letter a-z, a space (any White_Space rune, as
// unicode.IsSpace reads it), and '#' (anything else). A code point whose result is all '#' is
// left out: that is the default. Runs of '#' collapse to one.
//
// Modes:
//
//	nfkdgen table   -> the Go table on stdout
//	nfkdgen check   -> the equivalence check: per-rune folding against whole-string NFKD
//	nfkdgen stats   -> counts
package main

import (
	"fmt"
	"math/rand/v2"
	"os"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// the class string of one rune's NFKD, lowercased
func foldOf(r rune) string {
	d := norm.NFKD.String(string(r))
	var b strings.Builder
	lastJunk := false
	for _, c := range d {
		switch {
		case 'A' <= c && c <= 'Z':
			b.WriteByte(byte(c - 'A' + 'a'))
			lastJunk = false
		case 'a' <= c && c <= 'z':
			b.WriteByte(byte(c))
			lastJunk = false
		case unicode.IsSpace(c):
			b.WriteByte(' ')
			lastJunk = false
		default:
			if !lastJunk {
				b.WriteByte('#')
			}
			lastJunk = true
		}
	}
	return canonical(b.String())
}

// canonical: a segment between spaces that holds any '#' is junk whatever letters it also holds,
// so it is written as one '#'. Only letters and spaces then remain meaningful.
func canonical(f string) string {
	parts := strings.Split(f, " ")
	for i, part := range parts {
		if strings.Contains(part, "#") {
			parts[i] = "#"
		}
	}
	return strings.Join(parts, " ")
}

type entry struct {
	r    rune
	fold string
}

func entries() []entry {
	out := []entry{}
	for r := rune(0x80); r <= unicode.MaxRune; r++ {
		if 0xD800 <= r && r <= 0xDFFF {
			continue
		}
		f := foldOf(r)
		if f == "#" {
			continue
		}
		out = append(out, entry{r, f})
	}
	return out
}

type span struct {
	lo, hi rune
	fold   string
	step   bool
}

// ranges: a run of consecutive code points that fold to consecutive single letters is a
// step span; a run that folds to one identical string is a same span.
func spans(es []entry) []span {
	out := []span{}
	for _, e := range es {
		if n := len(out); n > 0 {
			last := &out[n-1]
			if last.hi+1 == e.r {
				if !last.step && last.fold == e.fold {
					last.hi = e.r
					continue
				}
				if len(e.fold) == 1 && 'a' <= e.fold[0] && e.fold[0] <= 'z' && len(last.fold) == 1 && 'a' <= last.fold[0] && last.fold[0] <= 'z' {
					offset := int(e.r - last.lo)
					if (last.step || last.lo == last.hi) && int(last.fold[0])+offset == int(e.fold[0]) {
						last.step = true
						last.hi = e.r
						continue
					}
				}
			}
		}
		out = append(out, span{e.r, e.r, e.fold, false})
	}
	return out
}

// the reference: NFKD over the whole string, lowercase, split on white space, each token
// either its letters or "#" when it holds anything that is not a-z
func reference(s string) []string {
	d := norm.NFKD.String(s)
	tokens := []string{}
	for _, field := range strings.FieldsFunc(d, unicode.IsSpace) {
		var b strings.Builder
		junk := false
		for _, c := range field {
			switch {
			case 'A' <= c && c <= 'Z':
				b.WriteByte(byte(c - 'A' + 'a'))
			case 'a' <= c && c <= 'z':
				b.WriteByte(byte(c))
			default:
				junk = true
			}
		}
		if junk {
			tokens = append(tokens, "#")
		} else {
			tokens = append(tokens, b.String())
		}
	}
	return tokens
}

// the per-rune method the library uses, over the table
func perRune(s string, table map[rune]string) []string {
	tokens := []string{}
	var b strings.Builder
	junk := false
	open := false
	flush := func() {
		if !open {
			return
		}
		if junk {
			tokens = append(tokens, "#")
		} else {
			tokens = append(tokens, b.String())
		}
		b.Reset()
		junk = false
		open = false
	}
	emit := func(f string) {
		for i := 0; i < len(f); i++ {
			c := f[i]
			switch {
			case c == ' ':
				flush()
			case 'a' <= c && c <= 'z':
				b.WriteByte(c)
				open = true
			default:
				junk = true
				open = true
			}
		}
	}
	for _, r := range s {
		switch {
		case 'A' <= r && r <= 'Z':
			emit(string(rune(r - 'A' + 'a')))
		case 'a' <= r && r <= 'z':
			emit(string(r))
		case r == ' ' || r == '\t' || r == '\n' || r == '\v' || r == '\f' || r == '\r':
			emit(" ")
		case r < 0x80:
			emit("#")
		default:
			if f, ok := table[r]; ok {
				emit(f)
			} else {
				emit("#")
			}
		}
	}
	flush()
	return tokens
}

func main() {
	mode := "stats"
	if len(os.Args) > 1 {
		mode = os.Args[1]
	}
	es := entries()
	table := map[rune]string{}
	for _, e := range es {
		table[e.r] = e.fold
	}
	switch mode {
	case "stats":
		letters, spaces, mixed := 0, 0, 0
		for _, e := range es {
			switch {
			case strings.Trim(e.fold, "abcdefghijklmnopqrstuvwxyz") == "":
				letters++
			case strings.Trim(e.fold, " ") == "":
				spaces++
			default:
				mixed++
			}
		}
		sp := spans(es)
		steps := 0
		for _, s := range sp {
			if s.step {
				steps++
			}
		}
		fmt.Printf("unicode %s (norm) / %s (unicode pkg); entries %d: letters-only %d, space-only %d, mixed %d; spans %d (step %d)\n",
			norm.Version, unicode.Version, len(es), letters, spaces, mixed, len(sp), steps)
		// ASCII sanity: NFKD of every ASCII rune is itself
		for r := rune(0); r < 0x80; r++ {
			if norm.NFKD.String(string(r)) != string(r) {
				fmt.Printf("ASCII %U is not NFKD-invariant\n", r)
			}
		}
		// lowercase of a non-ASCII rune that survives NFKD is never ASCII
		bad := 0
		for r := rune(0x80); r <= unicode.MaxRune; r++ {
			if 0xD800 <= r && r <= 0xDFFF {
				continue
			}
			if norm.NFKD.String(string(r)) != string(r) {
				continue
			}
			if l := unicode.ToLower(r); l < 0x80 {
				fmt.Printf("%U survives NFKD and lowercases to ASCII %q\n", r, l)
				bad++
			}
			if unicode.IsSpace(r) {
				fmt.Printf("non-ASCII white space that survives NFKD: %U\n", r)
			}
		}
		fmt.Printf("survivors lowercasing to ASCII: %d\n", bad)
		mixedList := []string{}
		for _, e := range es {
			if strings.Trim(e.fold, "abcdefghijklmnopqrstuvwxyz") != "" && strings.Trim(e.fold, " ") != "" {
				mixedList = append(mixedList, fmt.Sprintf("%U=%q", e.r, e.fold))
			}
		}
		sort.Strings(mixedList)
		fmt.Printf("mixed: %v\n", mixedList)
	case "gofile":
		sp := spans(es)
		letters, spaces, mixed := 0, 0, 0
		for _, e := range es {
			switch {
			case strings.Trim(e.fold, "abcdefghijklmnopqrstuvwxyz") == "":
				letters++
			case strings.Trim(e.fold, " ") == "":
				spaces++
			default:
				mixed++
			}
		}
		fmt.Printf("// Code generated by messagegroup/testdata/nfkdgen (go run . gofile) from golang.org/x/text v0.43.0's unicode/norm at Unicode %s. DO NOT EDIT.\n\n", norm.Version)
		fmt.Print(`// The recovery phrase's input fold, one code point at a time: phrase.go's reading of NFKD.
//
// THE RULE THE SPANS WERE GENERATED BY, so that any implementation of NFKD can regenerate them.
// For every code point at or above U+0080, other than a surrogate: take its NFKD; lowercase A to
// Z; write each character of the result as itself when it is a to z, as a space when it is white
// space (Unicode's White_Space, which is Go's unicode.IsSpace), and as '#' otherwise, a run of
// '#' as one; then write every space-separated segment that holds a '#' as one '#'. A code point
// whose result is "#" is left out, since that is what phraseFoldOf answers for a code point no
// span holds. Below U+0080, NFKD changes nothing and phraseFoldOf reads ASCII directly.
//
// WHY THAT IS EXACT, and it is the argument phrase.go's header gives: NFKD is each code point's
// full decomposition followed by a canonical reordering that moves combining marks only among
// themselves, never across a starter, so it never moves one across a space or a letter; and no
// code point that survives NFKD lowercases to ASCII. So a word read off these folds is a list word
// exactly when the NFKD of the whole input, lowercased and split on white space, gives it.
//
// HOW IT WAS CHECKED, before this file was written: against x/text's whole-string NFKD for every
// one of the 1,112,064 code points, each alone, between letters, between spaces and doubled, and
// over 2,000,000 random strings drawn from these code points, the combining marks, letters, white
// space, Hangul, U+0130, U+212A and U+FFFD. Mismatches: 0. The spans expand to exactly the code
// points the rule lists. The pinned toolchain's unicode package is at the same edition, which the
// phrase's tests hold.

`)
		fmt.Printf("package messagegroup\n\n")
		fmt.Printf("// phraseFoldUnicodeVersion is the Unicode edition the spans below were generated from: the\n")
		fmt.Printf("// edition of the pinned toolchain's own unicode package, which the phrase's tests hold it to.\n")
		fmt.Printf("const phraseFoldUnicodeVersion = %q\n\n", norm.Version)
		fmt.Printf("// phraseFoldSpans: %d spans over %d code points, %d of which fold to letters only, %d to\n", len(sp), len(es), letters, spaces)
		fmt.Printf("// white space only and %d to white space beside a mark. phraseFoldSpan says how a span reads.\n", mixed)
		fmt.Printf("var phraseFoldSpans = [...]phraseFoldSpan{\n")
		for _, s := range sp {
			fmt.Printf("\t{0x%04X, 0x%04X, %q, %v},\n", s.lo, s.hi, s.fold, s.step)
		}
		fmt.Printf("}\n")
	case "table":
		sp := spans(es)
		fmt.Printf("// %d spans, %d code points, Unicode %s\n", len(sp), len(es), norm.Version)
		for _, s := range sp {
			fmt.Printf("{0x%04X, 0x%04X, %q, %v},\n", s.lo, s.hi, s.fold, s.step)
		}
	case "check":
		// 0. the table under check is the SPANS, expanded, which is what the library reads, and
		// the expansion must equal the entries exactly
		expanded := map[rune]string{}
		for _, s := range spans(es) {
			for r := s.lo; r <= s.hi; r++ {
				if s.step {
					expanded[r] = string(rune(int(s.fold[0]) + int(r-s.lo)))
				} else {
					expanded[r] = s.fold
				}
			}
		}
		if len(expanded) != len(table) {
			fmt.Printf("SPANS expand to %d code points, the entries are %d\n", len(expanded), len(table))
		}
		for r, f := range table {
			if expanded[r] != f {
				fmt.Printf("SPANS give %U %q, the entry is %q\n", r, expanded[r], f)
			}
		}
		table = expanded
		fmt.Printf("spans expand to %d code points\n", len(expanded))
		// 1. every single code point, alone and between two letters, against the reference
		mismatches := 0
		for r := rune(0); r <= unicode.MaxRune; r++ {
			if 0xD800 <= r && r <= 0xDFFF {
				continue
			}
			for _, s := range []string{string(r), "ab" + string(r) + "cd", " " + string(r) + " ", string(r) + string(r)} {
				want := reference(s)
				got := perRune(s, table)
				if strings.Join(want, "|") != strings.Join(got, "|") {
					if mismatches < 20 {
						fmt.Printf("MISMATCH %U in %q: reference %v, per-rune %v\n", r, s, want, got)
					}
					mismatches++
				}
			}
		}
		// 2. random strings over a pool biased to the table, combining marks, letters and spaces
		pool := []rune{}
		for _, e := range es {
			pool = append(pool, e.r)
		}
		for r := rune(0x300); r <= 0x36F; r++ {
			pool = append(pool, r)
		}
		for r := 'a'; r <= 'z'; r++ {
			pool = append(pool, r, r, r)
		}
		for r := 'A'; r <= 'Z'; r++ {
			pool = append(pool, r)
		}
		pool = append(pool, ' ', ' ', ' ', '\t', '\n', 0xAC00, 0x1100, 0x0130, 0x212A, 0x00E9, 0x0065, 0x0301, 0xFFFD)
		rng := rand.New(rand.NewPCG(20261016, 299))
		randoms := 2000000
		for i := 0; i < randoms; i++ {
			n := 1 + rng.IntN(12)
			rs := make([]rune, n)
			for j := range rs {
				rs[j] = pool[rng.IntN(len(pool))]
			}
			s := string(rs)
			if !utf8.ValidString(s) {
				continue
			}
			want := reference(s)
			got := perRune(s, table)
			if strings.Join(want, "|") != strings.Join(got, "|") {
				if mismatches < 40 {
					fmt.Printf("MISMATCH random %q: reference %v, per-rune %v\n", s, want, got)
				}
				mismatches++
			}
		}
		// 3. invalid UTF-8: the reference treats bytes NFKD passes through; the per-rune walk
		// reads U+FFFD. Both must make the token junk.
		for _, s := range []string{"ab\xffcd", "\xc3", "abandon\x80", "\xed\xa0\x80"} {
			want := reference(s)
			got := perRune(s, table)
			fmt.Printf("invalid %q: reference %v, per-rune %v\n", s, want, got)
		}
		fmt.Printf("check: %d code points x 4 contexts and %d random strings; mismatches %d\n", unicode.MaxRune+1-0x800, randoms, mismatches)
	}
}
