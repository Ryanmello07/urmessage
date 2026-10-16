package messagegroup

import (
	"testing"
)

// ══════════════════════════════════════════════════════════════════════════════════════════════
// THE PHRASE-SECRET CENSUS: EVERY SECRET A RECOVERY PHRASE DERIVES GOES WHERE ITS DISPOSITION SAYS
// ══════════════════════════════════════════════════════════════════════════════════════════════
//
// Identity phase 1's plan, Task 10, Property 5: every phrase-derived secret goes only where its
// disposition says. The words, the stretch output, isk_root and IRK's private half are erased at
// the end of the call that made them, and isk_seed[g] reaches only the phrase key record. It is
// built like sdk/urmessage/pqsecretgate_test.go's census, on the same engine, ported for this
// package as census_test.go, and it is held the same four ways: the producer sites, the sink sites
// and the VALUES each sink carries, the counted-not-carried sites the one narrowing removes, and
// the horizon where the walk stops knowing. Every one of the four in both directions.
//
// WHAT THE SECRETS ARE. A recovery phrase is 267 bits, P34, and everything below it is a function
// of them: the 25 indices and the words they name, CS8, the typed letters a word is read into, the
// stretch output S, master_key, IRK's seed and private half, isk_root, isk_seed[g] and ISK_g. Not
// one of them may reach a field that outlives its ceremony, an error string, or anything that logs
// one, save isk_seed[g]'s copy for the phrase key record, which is store kind 13 and Task 12's.
//
// WHERE ERASURE IS HELD. A disposition that says a value is erased is a sink site of its own -- a
// call of zeroize or clear carrying exactly that value -- and it is held both ways like every other:
// an erase that is deleted is a site the disposition names and the census no longer finds.
//
// GO CANNOT PROMISE ZEROED MEMORY (PLAN's promise table: a residual, stated in Spec A section 8).
// What this census holds is the dataflow the source spells; a copy the runtime makes -- a stack
// frame, a moved array, Argon2id's own working memory, the SHA-256 and HMAC states -- is outside
// any census, and the dispositions below name the ones this package's own source makes visible.

// The names that PRODUCE a phrase secret, in every position a name can produce one: the callee of
// a call, a field read, a parameter, or a result of a function this net names. It is the SEARCH
// NET, and it is wider than the secrets on purpose: a name here that no site uses costs nothing.
var phraseSecretProducerNames = map[string]bool{
	// THE DRAW AND THE TWO DOORS IN. P34 comes into existence at the draw or at the parse.
	"Random":              true,
	"NewRecoveryPhrase":   true,
	"ParseRecoveryPhrase": true,
	// THE PHRASE ITSELF AND EVERYTHING ITS WORDS ARE MADE OF
	"p34":                      true,
	"Words":                    true,
	"phraseIndicesOf":          true,
	"phraseIndices":            true,
	"phraseBitsAt":             true,
	"phraseCarried":            true,
	"phraseCarriedOf":          true,
	"phraseCarriedFromIndices": true,
	"phraseChecksumOf":         true,
	// THE TYPED INPUT, AS IT IS READ: the string, each code point's fold, and the letters a word
	// is gathered into before it is looked up
	"phraseTyped":    true,
	"phraseTokensOf": true,
	"phraseFold":     true,
	"typedLetters":   true,
	// THE STRETCH AND THE KEYS UNDER IT
	"stretchPhrase":    true,
	"derivePhraseKeys": true,
	"iskSeedOf":        true,
	"iskRoot":          true,
	"irk":              true,
	"isk":              true,
	"iskSeed":          true,
	"PhraseKeySeed":    true,
}

// The four dispositions, each held both ways. A site with no entry is a phrase secret landing
// somewhere nobody weighed; an entry with no site is a disposition that has stopped describing the
// code, or a rename this census has gone blind to.
var phraseSecretProducerSites = map[string]string{
	"Equal|other.p34":                                  "the other side of it",
	"Equal|self.p34":                                   "one side of the constant time comparison that is 'typed back in full'",
	"Erase|self.p34":                                   "P34, read only to be blanked",
	"IdentityKey|self.irk":                             "IRK, read only for its public half",
	"NewRecoveryPhrase|phrase.p34":                     "the new phrase's own P34, written from the draw and its five high bits cleared",
	"NewRecoveryPhrase|phraseDraw.Random":              "THE DRAW: 34 octets from mls's provider over crypto/rand, MASTER section 5.1's only source of P",
	"NewRecoveryPhrase|result phrase":                  "the phrase NewRecoveryPhrase answers, holding P34",
	"ParseRecoveryPhrase|parameter phraseTyped":        "THE TYPED WORDS, as the caller hands them in: the caller's string, which this package cannot erase (Go strings are immutable)",
	"ParseRecoveryPhrase|phrase.p34":                   "the parsed phrase's own P34, filled from the indices",
	"ParseRecoveryPhrase|phraseTokensOf":               "the typed words read into 25 list indices, a count and the positions of words not on the list",
	"ParseRecoveryPhrase|result notInTheList":          "the positions of the words not on the list: positions, never words. In the net only because every result of a net function is",
	"ParseRecoveryPhrase|result phrase":                "the phrase ParseRecoveryPhrase answers, holding P34",
	"PhraseKeySeed|self.iskSeed":                       "ISK_SEED[g], copied for the phrase key record",
	"PhraseKey|self.isk":                               "ISK_g, read only for its public half",
	"SignBase|self.irk":                                "IRK, read for its length, which says whether the ceremony is still running",
	"SignBase|self.isk":                                "ISK_g's private half, read to sign a base inside the ceremony",
	"SignIdentityStep|self.irk":                        "IRK's private half, read to sign the step to the next identity key inside the ceremony",
	"SignIskCert|self.irk":                             "IRK's private half, read to sign IskCert(g) inside the ceremony, and its length to refuse a call after it",
	"SignIskCert|self.isk":                             "ISK_g, read for its length and its public half, which the certificate names",
	"Words|phraseIndicesOf":                            "the 25 indices of P ‖ CS8",
	"Words|result phraseWords":                         "THE WORDS, answered for the one time they are shown",
	"Words|self.p34":                                   "P34, read to write its 25 words the one time they are shown",
	"derivePhraseKeys|iskSeedOf":                       "isk_seed[g], the phrase's key's seed for key number g",
	"derivePhraseKeys|phrase.p34":                      "P34, handed to the one stretch",
	"derivePhraseKeys|stretchPhrase":                   "S, THE STRETCH OUTPUT",
	"end|self.phraseIndices":                           "the reading's indices, the one a listed word's index is written into",
	"end|self.typedLetters":                            "the gathered word, looked up and then blanked",
	"erase|self.irk":                                   "IRK's private half, read to be blanked and dropped",
	"erase|self.isk":                                   "ISK_g's private half, read to be blanked and dropped",
	"erase|self.iskSeed":                               "isk_seed[g], read to be blanked and dropped",
	"iskSeedOf|parameter iskRoot":                      "ISK_ROOT, which no device keeps: isk_seed[g] is expanded from it and g alone",
	"phraseBitsAt|parameter phraseCarried":             "the 280 bits an index is read out of",
	"phraseBitsAt|result value":                        "one index",
	"phraseCarriedFromIndices|parameter phraseIndices": "the 25 indices",
	"phraseCarriedFromIndices|result phraseCarried":    "P34 ‖ CS8, answered to phraseFromIndices, which erases it",
	"phraseCarriedOf|parameter p34":                    "P34",
	"phraseCarriedOf|phraseChecksumOf":                 "CS8, the checksum the last word carries",
	"phraseCarriedOf|result phraseCarried":             "P34 ‖ CS8, answered to phraseIndicesOf, which erases it",
	"phraseChecksumOf|parameter p34":                   "P34, the checksum's preimage after its label",
	"phraseChecksumOf|result checksum":                 "CS8, the one octet of the hash a phrase carries in its last word",
	"phraseFromIndices|parameter p34":                  "the parsed phrase's P34, written here",
	"phraseFromIndices|parameter phraseIndices":        "the 25 indices a phrase is read back from",
	"phraseFromIndices|phraseCarriedFromIndices":       "P34 ‖ CS8 assembled from the indices",
	"phraseFromIndices|phraseChecksumOf":               "the checksum P34 has, which CS8 is compared against",
	"phraseIndicesOf|parameter p34":                    "P34, the phrase the indices are read from",
	"phraseIndicesOf|phraseBitsAt":                     "one index, eleven of those bits",
	"phraseIndicesOf|phraseCarriedOf":                  "P34 ‖ CS8, the 280 bits the indices are cut from",
	"phraseIndicesOf|result phraseIndices":             "the 25 indices it answers",
	"phraseTokensOf|parameter phraseTyped":             "the typed words, read a code point at a time",
	"phraseTokensOf|reading.phraseIndices":             "the indices the reading gathered, copied out and then blanked",
	"phraseTokensOf|result phraseIndices":              "the 25 indices it answers",
	"phraseTokensOf|result reading":                    "the reading's count and positions. reading is a root of two results that are not secret, and the walk cannot tell its fields apart",
	"signBase|parameter isk":                           "ISK_g's private half, as the base's signer takes it",
	"signIdentityStep|parameter irk":                   "IRK's private half, as the step's signer takes it",
	"signIskCert|parameter irk":                        "IRK's private half, as the certificate's signer takes it",
	"stretchPhrase|parameter p34":                      "P34, the stretch's password",
	"take|parameter phraseFold":                        "one typed code point's fold",
	"take|self.typedLetters":                           "THE ONE BUFFER A TYPED WORD IS GATHERED INTO",
	"withPhraseKeys|derivePhraseKeys":                  "the keys of one ceremony: IRK, ISK_g and isk_seed[g]",
}

type phraseSecretSink struct {
	carries []string
	why     string
}

var phraseSecretSinks = map[string]phraseSecretSink{
	"Equal|call subtle.ConstantTimeCompare":              {carries: []string{"other.p34", "self.p34"}, why: "the two phrases compared in constant time"},
	"Equal|return":                                       {carries: []string{"other.p34", "self.p34"}, why: "a bool, whether the two are one phrase. The walk cannot tell the answer from what was compared"},
	"Erase|call zeroize":                                 {carries: []string{"self.p34"}, why: "ERASED: P34, at the end of its ceremony"},
	"IdentityKey|call phrasePublicHalf":                  {carries: []string{"self.irk"}, why: "IRK into its public half, copied out of octets 32 to 63"},
	"IdentityKey|return":                                 {carries: []string{"self.irk"}, why: "IRK's PUBLIC half, a copy: the identity key contacts remember. The walk cannot tell it from the private key it was cut from"},
	"NewRecoveryPhrase|call copy":                        {carries: []string{"phrase", "phrase.p34", "phraseDrawn"}, why: "the draw copied into the new phrase's own P34, the one place it is kept"},
	"NewRecoveryPhrase|call zeroize":                     {carries: []string{"phraseDrawn"}, why: "ERASED: the draw's own octets, once copied, at the end of the call that drew them"},
	"NewRecoveryPhrase|return":                           {carries: []string{"phrase"}, why: "the phrase, to its ceremony, which shows it once and erases it with Erase"},
	"ParseRecoveryPhrase|call clear":                     {carries: []string{"phraseIndices"}, why: "ERASED: the indices, at the end of the call that read them"},
	"ParseRecoveryPhrase|call fmt.Errorf":                {carries: []string{"count", "notInTheList"}, why: "the POSITIONS of the words not on the list, and the count of words: an error string holds numbers and never a word"},
	"ParseRecoveryPhrase|call phraseFromIndices":         {carries: []string{"phrase", "phrase.p34", "phraseIndices"}, why: "the indices read back into the parsed phrase's own P34"},
	"ParseRecoveryPhrase|call phraseTokensOf":            {carries: []string{"phraseTyped"}, why: "the typed words, read"},
	"ParseRecoveryPhrase|return":                         {carries: []string{"count", "notInTheList", "phrase"}, why: "the phrase to its ceremony, or the positions and the count of a refusal, which name no word"},
	"PhraseKeySeed|call append":                          {carries: []string{"self.iskSeed"}, why: "isk_seed[g] copied"},
	"PhraseKeySeed|return":                               {carries: []string{"self.iskSeed"}, why: "ISK_SEED[g], THE ONE PHRASE SECRET THAT OUTLIVES A CEREMONY, for the one place it may go: a phrase device's phrase key record, store kind 13 (MASTER section 5.2; Task 12)"},
	"PhraseKey|call phrasePublicHalf":                    {carries: []string{"self.isk"}, why: "ISK_g into its public half, copied out"},
	"PhraseKey|return":                                   {carries: []string{"self.isk"}, why: "ISK_g's PUBLIC half, a copy, the key a base is checked under"},
	"SignBase|call signBase":                             {carries: []string{"self.isk"}, why: "ISK_g's private half to the base's signer, inside the ceremony; it signs and keeps nothing"},
	"SignBase|return":                                    {carries: []string{"self.isk"}, why: "the base signer's error. The walk cannot tell it from the key the signer was called with"},
	"SignIdentityStep|call signIdentityStep":             {carries: []string{"self.irk"}, why: "IRK's private half to the step's signer, inside the ceremony; it signs and keeps nothing"},
	"SignIdentityStep|return":                            {carries: []string{"self.irk"}, why: "the step: IRK's public half and a signature. The walk cannot tell the step from the key that signed it"},
	"SignIskCert|call signIskCert":                       {carries: []string{"self.irk"}, why: "IRK's private half to the certificate's signer, inside the ceremony; it signs and keeps nothing"},
	"Words|assign phraseWords[position]":                 {carries: []string{"phraseIndex"}, why: "each word, a string of the list itself, into the slice Words answers"},
	"Words|call clear":                                   {carries: []string{"phraseIndices"}, why: "ERASED: the indices, at the end of the call that read them"},
	"Words|call phraseIndicesOf":                         {carries: []string{"self.p34"}, why: "P34 read into its 25 indices"},
	"Words|return":                                       {carries: []string{"phraseWords"}, why: "THE WORDS, to the screen that shows them once. They are strings of the list, so no copy of a word is made; the slice is the caller's to drop"},
	"derivePhraseKeys|call ed25519.NewKeyFromSeed":       {carries: []string{"irkSeed", "iskSeed"}, why: "the two seeds into IRK and ISK_g"},
	"derivePhraseKeys|call iskSeedOf":                    {carries: []string{"iskRoot"}, why: "isk_root into isk_seed[g]"},
	"derivePhraseKeys|call keyScheduleExpand":            {carries: []string{"masterKey"}, why: "master_key into IRK's seed and isk_root"},
	"derivePhraseKeys|call keyScheduleExtract":           {carries: []string{"stretched"}, why: "S into master_key, HKDF-Extract(\"URmessage/v1\", S)"},
	"derivePhraseKeys|call stretchPhrase":                {carries: []string{"phrase.p34"}, why: "P34 into the one stretch"},
	"derivePhraseKeys|call zeroize":                      {carries: []string{"irkSeed", "iskRoot", "masterKey", "stretched"}, why: "ERASED: S, master_key, IRK's seed and isk_root, at the end of the call that made them and before any ceremony runs, so no ceremony holds isk_root"},
	"derivePhraseKeys|literal PhraseKeys.irk":            {carries: []string{"irkSeed"}, why: "IRK into the ceremony's keys, erased by erase when the ceremony ends"},
	"derivePhraseKeys|literal PhraseKeys.isk":            {carries: []string{"iskSeed"}, why: "ISK_g into the ceremony's keys, erased the same way"},
	"derivePhraseKeys|literal PhraseKeys.iskSeed":        {carries: []string{"iskSeed"}, why: "isk_seed[g] into the ceremony's keys, erased the same way"},
	"end|assign self.phraseIndices[?]":                   {carries: []string{"phraseIndex"}, why: "a listed word's index into the reading"},
	"end|call string":                                    {carries: []string{"self.typedLetters"}, why: "the gathered word as a map key, for the lookup: Go does not allocate a string for m[string(b)], so no copy of the word is made"},
	"end|call zeroize":                                   {carries: []string{"self.typedLetters"}, why: "ERASED: the gathered word, at the end of every word"},
	"erase|call zeroize":                                 {carries: []string{"self.irk", "self.isk", "self.iskSeed"}, why: "ERASED: IRK's private half, ISK_g and isk_seed[g], when the ceremony returns"},
	"iskSeedOf|call keyScheduleExpand":                   {carries: []string{"iskRoot"}, why: "HKDF-Expand(isk_root, \"iskgen/v1\" ‖ u32(g), 32)"},
	"iskSeedOf|return":                                   {carries: []string{"iskRoot"}, why: "isk_seed[g], to derivePhraseKeys. The walk cannot tell the expansion from its key"},
	"phraseBitsAt|call uint16":                           {carries: []string{"phraseCarried"}, why: "a bit of P34 ‖ CS8, widened into the index being built"},
	"phraseBitsAt|return":                                {carries: []string{"value"}, why: "the index, to phraseIndicesOf"},
	"phraseCarriedFromIndices|assign phraseCarried[?]":   {carries: []string{"at", "phraseIndex"}, why: "that bit into P34 ‖ CS8. at is the bit's offset, tainted by the loop index it is computed from"},
	"phraseCarriedFromIndices|call byte":                 {carries: []string{"phraseIndex"}, why: "one bit of an index"},
	"phraseCarriedFromIndices|return":                    {carries: []string{"phraseCarried"}, why: "P34 ‖ CS8, to phraseFromIndices, which erases it"},
	"phraseCarriedOf|assign phraseCarried[phraseOctets]": {carries: []string{"p34", "phraseChecksumOf"}, why: "CS8 as the 35th octet"},
	"phraseCarriedOf|call copy":                          {carries: []string{"p34", "phraseCarried"}, why: "P34 into the 35 octets"},
	"phraseCarriedOf|call phraseChecksumOf":              {carries: []string{"p34"}, why: "P34 into its checksum"},
	"phraseCarriedOf|return":                             {carries: []string{"phraseCarried"}, why: "P34 ‖ CS8, to phraseIndicesOf, which erases it"},
	"phraseChecksumOf|call digest.Write":                 {carries: []string{"p34"}, why: "P34 into the SHA-256 state after the label; the state is a residual, see the horizon below"},
	"phraseChecksumOf|return":                            {carries: []string{"checksum"}, why: "CS8, one octet, which the phrase's last word writes in any case"},
	"phraseFromIndices|call copy":                        {carries: []string{"p34", "phraseCarried"}, why: "P34 out of P34 ‖ CS8 into the parsed phrase"},
	"phraseFromIndices|call phraseCarriedFromIndices":    {carries: []string{"phraseIndices"}, why: "the indices into P34 ‖ CS8"},
	"phraseFromIndices|call phraseChecksumOf":            {carries: []string{"p34"}, why: "the parsed P34 into its checksum"},
	"phraseFromIndices|call subtle.ConstantTimeByteEq":   {carries: []string{"p34", "phraseCarried", "phraseChecksumOf"}, why: "the carried CS8 against P34's own, in constant time"},
	"phraseFromIndices|call zeroize":                     {carries: []string{"phraseCarried"}, why: "ERASED: P34 ‖ CS8, at the end of the call that assembled it"},
	"phraseFromIndices|return":                           {carries: []string{"holds"}, why: "a bool, whether the checksum holds"},
	"phraseIndicesOf|assign phraseIndices[position]":     {carries: []string{"phraseBitsAt", "phraseCarried", "position"}, why: "each index into the array the function answers"},
	"phraseIndicesOf|call phraseBitsAt":                  {carries: []string{"phraseCarried", "position"}, why: "eleven bits at a time out of P34 ‖ CS8. position is the loop's index, tainted by the range"},
	"phraseIndicesOf|call phraseCarriedOf":               {carries: []string{"p34"}, why: "P34 into P34 ‖ CS8"},
	"phraseIndicesOf|call zeroize":                       {carries: []string{"phraseCarried"}, why: "ERASED: P34 ‖ CS8, at the end of the call that assembled it"},
	"phraseIndicesOf|return":                             {carries: []string{"phraseIndices"}, why: "the 25 indices, to Words, which erases them"},
	"phraseTokensOf|call clear":                          {carries: []string{"reading", "reading.phraseIndices"}, why: "ERASED: the reading's indices, once copied out"},
	"phraseTokensOf|call phraseFoldOf":                   {carries: []string{"phraseCharacter"}, why: "each typed code point into its fold"},
	"phraseTokensOf|call reading.take":                   {carries: []string{"phraseCharacter"}, why: "the fold into the reading"},
	"phraseTokensOf|return":                              {carries: []string{"phraseIndices", "reading"}, why: "the indices, the count and the positions, to ParseRecoveryPhrase, which erases the indices"},
	"signBase|assign base.Signature":                     {carries: []string{"signature"}, why: "the base's signature, which is public"},
	"signBase|call identitySign":                         {carries: []string{"isk"}, why: "ISK_g's private half to the one signer"},
	"signIdentityStep|call append":                       {carries: []string{"oldPublic"}, why: "IRK's public half, copied into the step"},
	"signIdentityStep|call identitySign":                 {carries: []string{"irk"}, why: "IRK's private half to the one signer"},
	"signIdentityStep|call sameOctets":                   {carries: []string{"oldPublic"}, why: "IRK's PUBLIC half, compared with the next key so that no key succeeds itself"},
	"signIdentityStep|literal IdentityStep.OldKey":       {carries: []string{"oldPublic"}, why: "the step's old key: IRK's public half"},
	"signIdentityStep|literal IdentityStep.Signature":    {carries: []string{"signature"}, why: "the step's signature, which is public"},
	"signIskCert|assign cert.Signature":                  {carries: []string{"signature"}, why: "the certificate's signature, which is public; the walk follows it because IRK made it"},
	"signIskCert|call identitySign":                      {carries: []string{"irk"}, why: "IRK's private half to the one signer, Ed25519 over LP(label) ‖ tbs; ed25519.Sign keeps nothing"},
	"stretchPhrase|call argon2.IDKey":                    {carries: []string{"p34"}, why: "P34 into Argon2id. Its 256 MiB of working memory is a function of P34 and is not erased by the library, the residual Spec A section 8 states"},
	"stretchPhrase|return":                               {carries: []string{"p34"}, why: "S, to derivePhraseKeys, which erases it"},
	"take|assign self.typedLetters[self.length]":         {carries: []string{"symbol"}, why: "a typed letter into the one buffer a word is gathered in"},
	"withPhraseKeys|call ceremony":                       {carries: []string{"keys"}, why: "the ceremony's keys, handed to it for the length of this call; erase runs when it returns, whatever it did"},
	"withPhraseKeys|return":                              {carries: []string{"keys"}, why: "the ceremony's error, answered as it is. The walk cannot tell the error from the keys the ceremony was called with"},
}

var phraseSecretCountedNotCarriedSites = map[string]string{
	"ParseRecoveryPhrase|len notInTheList": "whether any word is not on the list",
	"SignBase|len self.irk":                "whether IRK is still whole, for the same reason",
	"SignBase|len self.isk":                "whether ISK_g is still whole, for the same reason",
	"SignIdentityStep|len self.irk":        "whether IRK is still whole, for the same reason",
	"SignIskCert|len self.irk":             "whether IRK is still whole: a call after the ceremony is refused",
	"SignIskCert|len self.isk":             "whether ISK_g is still whole, for the same reason",
	"signIdentityStep|len irk":             "whether the key handed in is a whole Ed25519 private key",
	"take|len phraseFold":                  "the length of one code point's fold, which the loop runs over",
}

var phraseSecretAccumulatorSites = map[string]string{
	"phraseChecksumOf|accumulate digest.Write": "P34 written into SHA-256's state. The state is not a byte slice and cannot be erased, the residual primitiveerase_test.go's row for phraseChecksumOf.digest states; what it answers is erased in the same body, and the one octet kept is CS8",
}

func TestEveryPhraseSecretInThisPackageGoesWhereTheDispositionSaysItGoes(t *testing.T) {
	census := runCensus(t, phraseSecretProducerNames)

	// ── THE COMPLEMENT, PRINTED: what this search covered and what it left out ────────────────
	t.Logf("production sources read (%d): %v", len(census.sources), census.sources)
	t.Logf("producer net: %v", censusSortedKeys(phraseSecretProducerNames))
	t.Logf("producer sites found (%d):", len(census.producers))
	for _, site := range censusSortedSites(census.producers) {
		t.Logf("    %s  at %v", site, census.producers[site])
	}
	t.Logf("sink sites found (%d), each with THE VALUES IT CARRIES:", len(census.sinks))
	for _, site := range censusSortedSites(census.sinks) {
		t.Logf("    %s  carries %v  at %v", site, censusSortedKeys(census.carried[site]), census.sinks[site])
	}
	t.Logf("COUNTED AND NOT CARRIED (%d):", len(census.counted))
	for _, site := range censusSortedSites(census.counted) {
		t.Logf("    %s  at %v", site, census.counted[site])
	}
	t.Logf("THE WALK'S HORIZON (%d):", len(census.accumulated))
	for _, site := range censusSortedSites(census.accumulated) {
		t.Logf("    %s  at %v", site, census.accumulated[site])
	}
	t.Logf("EXCLUDED, and excluded is not the same as absent -- tainted values that reach no sink "+
		"in their own function: %v", census.unspent)

	// ── AND ASSERTED, IN BOTH DIRECTIONS ──────────────────────────────────────────────────────
	censusHold(t, "producer site", census.producers, phraseSecretProducerSites,
		"A name that produces a phrase secret is where this census begins. A site with no entry is a "+
			"phrase secret coming from somewhere nobody weighed; an entry with no site is this census "+
			"gone BLIND, a producer respelled, and every sink clause below searching a value nothing "+
			"tainted.")
	sinkWhy := map[string]string{}
	for site, entry := range phraseSecretSinks {
		sinkWhy[site] = entry.why
	}
	sinkNarrowing := "A recovery phrase is the root of an identity: whoever holds P34 holds the " +
		"identity key, every key number's phrase key, and so the power to sign a device list that " +
		"names any device at all. The shape this census exists to refuse is the words, or anything " +
		"under them, kept past the ceremony that needed them -- in a field, in an error string, in a " +
		"log -- and the erase that ends a ceremony going missing. A site with no entry is a phrase " +
		"secret landing somewhere nobody weighed. An entry with no site is a disposition that has " +
		"stopped describing the code."
	censusHold(t, "sink site", census.sinks, sinkWhy, sinkNarrowing)
	for _, site := range censusSortedSites(census.sinks) {
		entry, dispositioned := phraseSecretSinks[site]
		if !dispositioned {
			continue
		}
		allowed := map[string]bool{}
		for _, spelled := range entry.carries {
			allowed[spelled] = true
		}
		for _, spelled := range censusSortedKeys(census.carried[site]) {
			if !allowed[spelled] {
				t.Errorf("sink site %q carries %q and its disposition entry does not list it "+
					"(it lists %v).\n%s", site, spelled, entry.carries, sinkNarrowing)
			}
		}
		for _, spelled := range entry.carries {
			if !census.carried[site][spelled] {
				t.Errorf("the disposition says sink site %q carries %q and the census finds only "+
					"%v there. A value that has stopped arriving is a fix nobody deleted the entry for, "+
					"a rename this census is blind to, or an erase that went missing.\n%s",
					site, spelled, censusSortedKeys(census.carried[site]), sinkNarrowing)
			}
		}
	}
	censusHold(t, "counted-not-carried site", census.counted, phraseSecretCountedNotCarriedSites,
		"A COUNT OF A PHRASE SECRET IS NOT A PHRASE SECRET, and that single exclusion is a narrowing: "+
			"every site it removed is named here, so a count nobody weighed fails, and so does a count "+
			"the tree no longer takes.")
	censusHold(t, "accumulator site", census.accumulated, phraseSecretAccumulatorSites,
		"A TAINT WALK OVER NAMES STOPS WHERE A VALUE IS HANDED TO A METHOD AND LIVES ON INSIDE THE "+
			"RECEIVER, and this is that stopping place written down. A site with no entry is a new "+
			"blind spot; an entry with no site is a limit lifted or moved.")
}
