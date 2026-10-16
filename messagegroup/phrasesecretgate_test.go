package messagegroup

import (
	"sort"
	"strings"
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
// package as census_test.go, and it is held the same ways: the producer sites; the sink sites, the
// VALUES each sink carries and, since LRI R68, each value's OCCURRENCES there (L2-01); the
// counted-not-carried sites the one narrowing removes; and the horizon where the walk stops
// knowing. Every one in both directions. Since R68 the walk also follows a value into this
// package's own functions it is handed to (L1-1), and a map's key is a carried value (L2-02); the
// mutation table at the foot of this file drives each of those at the phrase's secrets.
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
// GO CANNOT PROMISE ZEROED MEMORY (PLAN's promise table: a residual, which Spec A section 8 states as
// LRI R68 has it stated, with its measured scope: the words, S, master_key, isk_root and IRK's private
// half can survive in freed heap, in Argon2id's working memory and in hash and HMAC states, even
// after a collection; the review of Tasks 8 to 10 measured it, L1-2). What this census holds is the
// dataflow the source spells; a copy the runtime makes -- a stack frame, a moved array, Argon2id's
// own working memory, the SHA-256 and HMAC states -- is outside any census, and the dispositions
// below name the ones this package's own source makes visible.

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
	"CheckRecoveryPhraseWord|phraseTokensOf":           "the typed word read into the reading's indices, its count and the positions of the words not on the list",
	"DeriveIdentityKeyed|self.irk":                     "IRK's seed, the first 32 octets of its private half, read as the key of D2 IL8's derivation; and its length, which says whether the ceremony is still running",
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
	"PhraseKeySeed|number.iskSeed":                     "ISK_SEED[g], copied for the phrase key record",
	"PhraseKey|number.isk":                             "ISK_g, read only for its public half",
	"SignBase|number.isk":                              "ISK_g's private half, read to sign a base inside the ceremony",
	"SignIdentityStep|self.irk":                        "IRK's private half, read to sign the step to the next identity key inside the ceremony",
	"SignIskCert|number.isk":                           "ISK_g, read for its public half, which the certificate names",
	"SignIskCert|self.irk":                             "IRK's private half, read to sign IskCert(g) inside the ceremony, and its length to refuse a call after it",
	"Words|phraseIndicesOf":                            "the 25 indices of P ‖ CS8",
	"Words|result phraseWords":                         "THE WORDS, answered for the one time they are shown",
	"Words|self.p34":                                   "P34, read to write its 25 words the one time they are shown",
	"derivePhraseKeys|iskSeedOf":                       "isk_seed[g], the phrase's key's seed for key number g",
	"derivePhraseKeys|phrase.p34":                      "P34, handed to the one stretch",
	"derivePhraseKeys|stretchPhrase":                   "S, THE STRETCH OUTPUT",
	"encodeIskCertTbs|parameter cert":                  "the certificate being signed, handed by signIskCert: IRK's and ISK_g's PUBLIC halves and g. The walk follows it because it was built inside the ceremony",
	"end|self.phraseIndices":                           "the reading's indices, the one a listed word's index is written into",
	"end|self.typedLetters":                            "the gathered word, looked up and then blanked",
	"erase|self.irk":                                   "IRK's private half, read to be blanked and dropped",
	"erase|self.isk":                                   "ISK_g's private half, read to be blanked and dropped by its key number's erase",
	"erase|self.iskSeed":                               "isk_seed[g], read to be blanked and dropped by its key number's erase",
	"identityEncoding|parameter encode":                "the encoder of an identity object's tbs, a closure over the object being signed; it writes public halves and numbers",
	"identityPreimage|parameter tbs":                   "the tbs a signature is over, handed by identitySign: public halves, numbers and hashes",
	"identitySign|parameter key":                       "IRK's or ISK_g's private half, handed to the one signer by the ceremony's signers",
	"identitySign|parameter tbs":                       "the tbs a signature is over, handed with the key",
	"iskSeedOf|parameter iskRoot":                      "ISK_ROOT, which no device keeps: isk_seed[g] is expanded from it and g alone",
	"keyNumberOf|self.irk":                             "IRK, read for its length, which says whether the ceremony is still running",
	"keyScheduleExpand|parameter prk":                  "the expansion's key: master_key, isk_root, and IRK's seed for D2 IL8, handed by derivePhraseKeys, iskSeedOf and DeriveIdentityKeyed",
	"keyScheduleExtract|parameter ikm":                 "S, handed by derivePhraseKeys into master_key = HKDF-Extract(\"URmessage/v1\", S)",
	"phraseBitsAt|parameter offset":                    "an offset into P34 ‖ CS8, tainted by the loop index it is computed from: a position, not a secret",
	"phraseBitsAt|parameter phraseCarried":             "the 280 bits an index is read out of",
	"phraseBitsAt|result value":                        "one index",
	"phraseCarriedFromIndices|parameter phraseIndices": "the 25 indices",
	"phraseCarriedFromIndices|result phraseCarried":    "P34 ‖ CS8, answered to phraseFromIndices, which erases it",
	"phraseCarriedOf|parameter p34":                    "P34",
	"phraseCarriedOf|phraseChecksumOf":                 "CS8, the checksum the last word carries",
	"phraseCarriedOf|result phraseCarried":             "P34 ‖ CS8, answered to phraseIndicesOf, which erases it",
	"phraseChecksumOf|parameter p34":                   "P34, the checksum's preimage after its label",
	"phraseChecksumOf|result checksum":                 "CS8, the one octet of the hash a phrase carries in its last word",
	"phraseFoldOf|parameter character":                 "one typed code point, handed by phraseTokensOf: the typed phrase, a code point at a time",
	"phraseFromIndices|parameter p34":                  "the parsed phrase's P34, written here",
	"phraseFromIndices|parameter phraseIndices":        "the 25 indices a phrase is read back from",
	"phraseFromIndices|phraseCarriedFromIndices":       "P34 ‖ CS8 assembled from the indices",
	"phraseFromIndices|phraseChecksumOf":               "the checksum P34 has, which CS8 is compared against",
	"phraseIndicesOf|parameter p34":                    "P34, the phrase the indices are read from",
	"phraseIndicesOf|phraseBitsAt":                     "one index, eleven of those bits",
	"phraseIndicesOf|phraseCarriedOf":                  "P34 ‖ CS8, the 280 bits the indices are cut from",
	"phraseIndicesOf|result phraseIndices":             "the 25 indices it answers",
	"phrasePublicHalf|parameter expanded":              "IRK's or ISK_g's private key, or IL8's derived one, handed to have its public half copied out",
	"phraseTokensOf|parameter phraseTyped":             "the typed words, read a code point at a time",
	"phraseTokensOf|reading.phraseIndices":             "the indices the reading gathered, copied out and then blanked",
	"phraseTokensOf|result phraseIndices":              "the 25 indices it answers",
	"phraseTokensOf|result reading":                    "the reading's count and positions. reading is a root of two results that are not secret, and the walk cannot tell its fields apart",
	"sameOctets|parameter left":                        "IRK's PUBLIC half, handed by signIdentityStep to be compared with the next key",
	"signBaseByPhraseKey|parameter isk":                "ISK_g's private half, as the base's ISK signer takes it",
	"signIdentityStep|parameter irk":                   "IRK's private half, as the step's signer takes it",
	"signIskCert|parameter cert":                       "the certificate SignIskCert builds inside the ceremony and hands to be signed: public halves and g",
	"signIskCert|parameter irk":                        "IRK's private half, as the certificate's signer takes it",
	"stretchPhrase|parameter p34":                      "P34, the stretch's password",
	"take|parameter phraseFold":                        "one typed code point's fold",
	"take|self.typedLetters":                           "THE ONE BUFFER A TYPED WORD IS GATHERED INTO",
	"withPhraseKeys|derivePhraseKeys":                  "the keys of one ceremony: IRK, ISK_g and isk_seed[g]",
	"zeroize|parameter secret":                         "every phrase secret this package erases, each handed here: S, master_key, isk_root, IRK's seed buffer, IL8's derived seed and key, IRK, ISK_g and isk_seed[g] at the ceremony's end, P34, the typed letters, and the indices",
}

type phraseSecretSink struct {
	carries []string
	occurs  []string
	why     string
}

var phraseSecretSinks = map[string]phraseSecretSink{
	"CheckRecoveryPhraseWord|call clear":                 {carries: []string{"phraseIndices"}, occurs: []string{"phraseIndices[:]"}, why: "ERASED: the reading's indices, at the end of the call that read them"},
	"CheckRecoveryPhraseWord|return":                     {carries: []string{"count"}, occurs: []string{"?"}, why: "a bool: whether exactly one listed word was read. The walk cannot tell the answer from the count and the positions it is decided by"},
	"DeriveIdentityKeyed|call ed25519.NewKeyFromSeed":    {carries: []string{"derivedSeed"}, occurs: []string{"derivedSeed"}, why: "the derived seed into the derived key"},
	"DeriveIdentityKeyed|call keyScheduleExpand":         {carries: []string{"self.irk"}, occurs: []string{"self.irk[:]"}, why: "IRK's seed into D2 IL8's derivation, HKDF-Expand(IRK's seed, label, 32)"},
	"DeriveIdentityKeyed|call phrasePublicHalf":          {carries: []string{"derived"}, occurs: []string{"derived"}, why: "the derived key into its public half, copied out"},
	"DeriveIdentityKeyed|call zeroize":                   {carries: []string{"derived", "derivedSeed"}, occurs: []string{"derived", "derivedSeed"}, why: "ERASED: the derived seed and private key, before the public half is answered"},
	"DeriveIdentityKeyed|return":                         {carries: []string{"derived"}, occurs: []string{"phrasePublicHalf(...)"}, why: "the derived key's PUBLIC half, a copy: D2 IL8's answer. The walk cannot tell it from the private key it was cut from; TestTheCeremonySignsTheCertificateTheStepAndTheBaseAndNothingAfterIt holds it to its known answer"},
	"Equal|call subtle.ConstantTimeCompare":              {carries: []string{"other.p34", "self.p34"}, occurs: []string{"other.p34[:]", "self.p34[:]"}, why: "the two phrases compared in constant time"},
	"Equal|return":                                       {carries: []string{"other.p34", "self.p34"}, occurs: []string{"?"}, why: "a bool, whether the two are one phrase. The walk cannot tell the answer from what was compared"},
	"Erase|call zeroize":                                 {carries: []string{"self.p34"}, occurs: []string{"self.p34[:]"}, why: "ERASED: P34, at the end of its ceremony"},
	"IdentityKey|call phrasePublicHalf":                  {carries: []string{"self.irk"}, occurs: []string{"self.irk"}, why: "IRK into its public half, copied out of octets 32 to 63"},
	"IdentityKey|return":                                 {carries: []string{"self.irk"}, occurs: []string{"phrasePublicHalf(...)"}, why: "IRK's PUBLIC half, a copy: the identity key contacts remember. The walk cannot tell it from the private key it was cut from"},
	"NewRecoveryPhrase|call copy":                        {carries: []string{"phrase", "phrase.p34", "phraseDrawn"}, occurs: []string{"phrase.p34[:]", "phraseDrawn"}, why: "the draw copied into the new phrase's own P34, the one place it is kept"},
	"NewRecoveryPhrase|call zeroize":                     {carries: []string{"phraseDrawn"}, occurs: []string{"phraseDrawn"}, why: "ERASED: the draw's own octets, once copied, at the end of the call that drew them"},
	"NewRecoveryPhrase|return":                           {carries: []string{"phrase"}, occurs: []string{"phrase"}, why: "the phrase, to its ceremony, which shows it once and erases it with Erase"},
	"ParseRecoveryPhrase|call clear":                     {carries: []string{"phraseIndices"}, occurs: []string{"phraseIndices[:]"}, why: "ERASED: the indices, at the end of the call that read them"},
	"ParseRecoveryPhrase|call fmt.Errorf":                {carries: []string{"count", "notInTheList"}, occurs: []string{"count", "notInTheList"}, why: "the POSITIONS of the words not on the list, and the count of words: an error string holds numbers and never a word"},
	"ParseRecoveryPhrase|call phraseFromIndices":         {carries: []string{"phrase", "phrase.p34", "phraseIndices"}, occurs: []string{"phrase.p34", "phraseIndices"}, why: "the indices read back into the parsed phrase's own P34"},
	"ParseRecoveryPhrase|call phraseTokensOf":            {carries: []string{"phraseTyped"}, occurs: []string{"phraseTyped"}, why: "the typed words, read"},
	"ParseRecoveryPhrase|return":                         {carries: []string{"count", "notInTheList", "phrase"}, occurs: []string{"fmt.Errorf(...)", "fmt.Errorf(...)", "notInTheList", "phrase"}, why: "the phrase to its ceremony, or the positions and the count of a refusal, which name no word"},
	"PhraseKeySeed|call append":                          {carries: []string{"number.iskSeed"}, occurs: []string{"number.iskSeed"}, why: "isk_seed[g] copied"},
	"PhraseKeySeed|return":                               {carries: []string{"number.iskSeed"}, occurs: []string{"append(...)"}, why: "ISK_SEED[g], THE ONE PHRASE SECRET THAT OUTLIVES A CEREMONY, for the one place it may go: a phrase device's phrase key record, store kind 13 (MASTER section 5.2; Task 12)"},
	"PhraseKey|call phrasePublicHalf":                    {carries: []string{"number.isk"}, occurs: []string{"number.isk"}, why: "ISK_g into its public half, copied out"},
	"PhraseKey|return":                                   {carries: []string{"number.isk"}, occurs: []string{"phrasePublicHalf(...)"}, why: "ISK_g's PUBLIC half, a copy, the key a base is checked under"},
	"SignBase|call signBaseByPhraseKey":                  {carries: []string{"number.isk"}, occurs: []string{"number.isk"}, why: "ISK_g's private half to the base's ISK signer, inside the ceremony; it signs and keeps nothing"},
	"SignBase|return":                                    {carries: []string{"number.isk"}, occurs: []string{"signBaseByPhraseKey(...)"}, why: "the base signer's error. The walk cannot tell it from the key the signer was called with"},
	"SignIdentityStep|call signIdentityStep":             {carries: []string{"self.irk"}, occurs: []string{"self.irk"}, why: "IRK's private half to the step's signer, inside the ceremony; it signs and keeps nothing"},
	"SignIdentityStep|return":                            {carries: []string{"self.irk"}, occurs: []string{"signIdentityStep(...)"}, why: "the step: IRK's public half and a signature. The walk cannot tell the step from the key that signed it"},
	"SignIskCert|call phrasePublicHalf":                  {carries: []string{"number.isk"}, occurs: []string{"number.isk"}, why: "ISK_g into its public half, copied out"},
	"SignIskCert|call signIskCert":                       {carries: []string{"cert", "self.irk"}, occurs: []string{"cert", "self.irk"}, why: "IRK's private half to the certificate's signer, inside the ceremony, with the certificate it fills; it signs and keeps nothing"},
	"SignIskCert|literal IskCert.IskPub":                 {carries: []string{"number.isk"}, occurs: []string{"phrasePublicHalf(...)"}, why: "ISK_g's public half, which the certificate names. The walk cannot tell the public half from the key it was copied out of"},
	"SignIskCert|return":                                 {carries: []string{"cert"}, occurs: []string{"cert"}, why: "IskCert(g): IRK's and ISK_g's public halves, g and IRK's signature, every one public. The walk cannot tell the certificate from the keys it names"},
	"Words|assign phraseWords[position]":                 {carries: []string{"phraseIndex", "position"}, occurs: []string{"phraseList[phraseIndex]"}, why: "each word, a string of the list itself, into the slice Words answers"},
	"Words|call clear":                                   {carries: []string{"phraseIndices"}, occurs: []string{"phraseIndices[:]"}, why: "ERASED: the indices, at the end of the call that read them"},
	"Words|call phraseIndicesOf":                         {carries: []string{"self.p34"}, occurs: []string{"self.p34"}, why: "P34 read into its 25 indices"},
	"Words|return":                                       {carries: []string{"phraseWords"}, occurs: []string{"phraseWords"}, why: "THE WORDS, to the screen that shows them once. They are strings of the list, so no copy of a word is made; but the slice's string headers point at the list's words, so the caller clears it, clear(words)"},
	"derivePhraseKeys|call append":                       {carries: []string{"numbers"}, occurs: []string{"numbers"}, why: "each key number's seed and key into the ceremony's set, erased by erase when the ceremony ends"},
	"derivePhraseKeys|call ed25519.NewKeyFromSeed":       {carries: []string{"irkSeed", "iskSeed"}, occurs: []string{"irkSeed", "iskSeed"}, why: "the two seeds into IRK and ISK_g"},
	"derivePhraseKeys|call iskSeedOf":                    {carries: []string{"iskRoot"}, occurs: []string{"iskRoot"}, why: "isk_root into isk_seed[g]"},
	"derivePhraseKeys|call keyScheduleExpand":            {carries: []string{"masterKey"}, occurs: []string{"masterKey", "masterKey"}, why: "master_key into IRK's seed and isk_root"},
	"derivePhraseKeys|call keyScheduleExtract":           {carries: []string{"stretched"}, occurs: []string{"stretched"}, why: "S into master_key, HKDF-Extract(\"URmessage/v1\", S)"},
	"derivePhraseKeys|call stretchPhrase":                {carries: []string{"phrase.p34"}, occurs: []string{"phrase.p34[:]"}, why: "P34 into the one stretch"},
	"derivePhraseKeys|call zeroize":                      {carries: []string{"irkSeed", "iskRoot", "masterKey", "stretched"}, occurs: []string{"irkSeed", "iskRoot", "masterKey", "stretched"}, why: "ERASED: S, master_key, isk_root and the buffer IRK's seed was expanded into, at the end of the call that made them and before any ceremony runs, so no ceremony holds isk_root. IRK's private key, its seed in its first 32 octets, is in the ceremony's keys until the ceremony returns"},
	"derivePhraseKeys|literal PhraseKeys.irk":            {carries: []string{"irkSeed"}, occurs: []string{"ed25519.NewKeyFromSeed(...)"}, why: "IRK into the ceremony's keys, erased by erase when the ceremony ends"},
	"derivePhraseKeys|literal PhraseKeys.numbers":        {carries: []string{"numbers"}, occurs: []string{"numbers"}, why: "the set into the ceremony's keys, erased by erase when the ceremony ends"},
	"derivePhraseKeys|literal phraseKeyNumber.isk":       {carries: []string{"iskSeed"}, occurs: []string{"ed25519.NewKeyFromSeed(...)"}, why: "ISK_g into the ceremony's set, erased by erase when the ceremony ends"},
	"derivePhraseKeys|literal phraseKeyNumber.iskSeed":   {carries: []string{"iskSeed"}, occurs: []string{"iskSeed"}, why: "isk_seed[g] into the ceremony's set, erased the same way"},
	"encodeIskCertTbs|call w.WriteOpaque":                {carries: []string{"cert"}, occurs: []string{"cert.IdentityKey", "cert.IskPub"}, why: "the certificate's two PUBLIC halves into its tbs. The walk cannot tell a public half from the private key it was cut from"},
	"encodeIskCertTbs|call w.WriteUint32":                {carries: []string{"cert"}, occurs: []string{"cert.KeyNumber"}, why: "g into the tbs, a number"},
	"end|assign self.phraseIndices[?]":                   {carries: []string{"phraseIndex"}, occurs: []string{"phraseIndex"}, why: "a listed word's index into the reading"},
	"end|call string":                                    {carries: []string{"self.typedLetters"}, occurs: []string{"self.typedLetters[:]"}, why: "the gathered word as a map key, for the lookup: Go does not allocate a string for m[string(b)], so no copy of the word is made"},
	"end|call zeroize":                                   {carries: []string{"self.typedLetters"}, occurs: []string{"self.typedLetters[:]"}, why: "ERASED: the gathered word, at the end of every word"},
	"erase|call zeroize":                                 {carries: []string{"self.irk", "self.isk", "self.iskSeed"}, occurs: []string{"self.irk", "self.isk", "self.iskSeed"}, why: "ERASED: IRK's private half, by the ceremony's erase, and each key number's ISK_g and isk_seed[g], by that number's erase, which the ceremony's calls for each, when the ceremony returns. The walk names the two erases as one, by their name"},
	"identityPreimage|call writer.WriteRaw":              {carries: []string{"tbs"}, occurs: []string{"tbs"}, why: "the tbs after LP(label): the preimage a signature is over, public"},
	"identitySign|call ed25519.Sign":                     {carries: []string{"key", "preimage"}, occurs: []string{"key", "preimage"}, why: "the private half and the preimage to Ed25519, which keeps nothing: the package's one signer"},
	"identitySign|call identityPreimage":                 {carries: []string{"tbs"}, occurs: []string{"tbs"}, why: "the tbs into LP(label) ‖ tbs"},
	"identitySign|return":                                {carries: []string{"key", "preimage"}, occurs: []string{"ed25519.Sign(...)"}, why: "the signature, which is public. The walk cannot tell it from the key that made it"},
	"iskSeedOf|call keyScheduleExpand":                   {carries: []string{"iskRoot"}, occurs: []string{"iskRoot"}, why: "HKDF-Expand(isk_root, \"iskgen/v1\" ‖ u32(g), 32)"},
	"iskSeedOf|return":                                   {carries: []string{"iskRoot"}, occurs: []string{"keyScheduleExpand(...)"}, why: "isk_seed[g], to derivePhraseKeys. The walk cannot tell the expansion from its key"},
	"keyScheduleExpand|call keyScheduleCrypto.Expand":    {carries: []string{"prk"}, occurs: []string{"prk"}, why: "the key into mls's HKDF-Expand; HMAC's state holds it and is a residual, see the horizon"},
	"keyScheduleExpand|return":                           {carries: []string{"prk"}, occurs: []string{"keyScheduleCrypto.Expand(...)"}, why: "the expansion, to its caller, which erases what of it is secret (derivePhraseKeys, iskSeedOf, DeriveIdentityKeyed). The walk cannot tell the expansion from its key"},
	"keyScheduleExtract|call keyScheduleCrypto.Extract":  {carries: []string{"ikm"}, occurs: []string{"ikm"}, why: "S into mls's HKDF-Extract; HMAC's state holds it and is a residual, see the horizon"},
	"keyScheduleExtract|return":                          {carries: []string{"ikm"}, occurs: []string{"keyScheduleCrypto.Extract(...)"}, why: "master_key, to derivePhraseKeys, which erases it"},
	"phraseBitsAt|call uint16":                           {carries: []string{"bit", "phraseCarried"}, occurs: []string{"?"}, why: "a bit of P34 ‖ CS8, widened into the index being built"},
	"phraseBitsAt|return":                                {carries: []string{"value"}, occurs: []string{"value"}, why: "the index, to phraseIndicesOf"},
	"phraseCarriedFromIndices|assign phraseCarried[?]":   {carries: []string{"at", "phraseIndex"}, occurs: []string{"?"}, why: "that bit into P34 ‖ CS8. at is the bit's offset, tainted by the loop index it is computed from"},
	"phraseCarriedFromIndices|call byte":                 {carries: []string{"phraseIndex"}, occurs: []string{"?"}, why: "one bit of an index"},
	"phraseCarriedFromIndices|return":                    {carries: []string{"phraseCarried"}, occurs: []string{"phraseCarried"}, why: "P34 ‖ CS8, to phraseFromIndices, which erases it"},
	"phraseCarriedOf|assign phraseCarried[phraseOctets]": {carries: []string{"p34", "phraseChecksumOf"}, occurs: []string{"phraseChecksumOf(...)"}, why: "CS8 as the 35th octet"},
	"phraseCarriedOf|call copy":                          {carries: []string{"p34", "phraseCarried"}, occurs: []string{"p34[:]", "phraseCarried[:]"}, why: "P34 into the 35 octets"},
	"phraseCarriedOf|call phraseChecksumOf":              {carries: []string{"p34"}, occurs: []string{"p34"}, why: "P34 into its checksum"},
	"phraseCarriedOf|return":                             {carries: []string{"phraseCarried"}, occurs: []string{"phraseCarried"}, why: "P34 ‖ CS8, to phraseIndicesOf, which erases it"},
	"phraseChecksumOf|call digest.Write":                 {carries: []string{"p34"}, occurs: []string{"p34[:]"}, why: "P34 into the SHA-256 state after the label; the state is a residual, see the horizon below"},
	"phraseChecksumOf|return":                            {carries: []string{"checksum"}, occurs: []string{"checksum"}, why: "CS8, one octet, which the phrase's last word writes in any case"},
	"phraseFoldOf|call int":                              {carries: []string{"character"}, occurs: []string{"?"}, why: "a code point's offset into its span's letters: the fold's own arithmetic, a number"},
	"phraseFoldOf|return":                                {carries: []string{"character", "letter"}, occurs: []string{"phraseAsciiFolds[character]", "phraseLetters[:]"}, why: "the code point's fold, a to z, a space or '#': the typed phrase, a code point at a time, to the reading, which blanks each word's letters at its end"},
	"phraseFromIndices|call copy":                        {carries: []string{"p34", "phraseCarried"}, occurs: []string{"p34[:]", "phraseCarried[:]"}, why: "P34 out of P34 ‖ CS8 into the parsed phrase"},
	"phraseFromIndices|call phraseCarriedFromIndices":    {carries: []string{"phraseIndices"}, occurs: []string{"phraseIndices"}, why: "the indices into P34 ‖ CS8"},
	"phraseFromIndices|call phraseChecksumOf":            {carries: []string{"p34"}, occurs: []string{"p34"}, why: "the parsed P34 into its checksum"},
	"phraseFromIndices|call subtle.ConstantTimeByteEq":   {carries: []string{"p34", "phraseCarried", "phraseChecksumOf"}, occurs: []string{"phraseCarried[phraseOctets]", "phraseChecksumOf(...)"}, why: "the carried CS8 against P34's own, in constant time"},
	"phraseFromIndices|call zeroize":                     {carries: []string{"phraseCarried"}, occurs: []string{"phraseCarried[:]"}, why: "ERASED: P34 ‖ CS8, at the end of the call that assembled it"},
	"phraseFromIndices|return":                           {carries: []string{"holds"}, occurs: []string{"holds"}, why: "a bool, whether the checksum holds"},
	"phraseIndicesOf|assign phraseIndices[position]":     {carries: []string{"phraseBitsAt", "phraseCarried", "position"}, occurs: []string{"phraseBitsAt(...)"}, why: "each index into the array the function answers"},
	"phraseIndicesOf|call phraseBitsAt":                  {carries: []string{"phraseCarried", "position"}, occurs: []string{"?", "phraseCarried"}, why: "eleven bits at a time out of P34 ‖ CS8. position is the loop's index, tainted by the range"},
	"phraseIndicesOf|call phraseCarriedOf":               {carries: []string{"p34"}, occurs: []string{"p34"}, why: "P34 into P34 ‖ CS8"},
	"phraseIndicesOf|call zeroize":                       {carries: []string{"phraseCarried"}, occurs: []string{"phraseCarried[:]"}, why: "ERASED: P34 ‖ CS8, at the end of the call that assembled it"},
	"phraseIndicesOf|return":                             {carries: []string{"phraseIndices"}, occurs: []string{"phraseIndices"}, why: "the 25 indices, to Words, which erases them"},
	"phrasePublicHalf|call append":                       {carries: []string{"expanded"}, occurs: []string{"expanded[:]"}, why: "the public half copied out of the expanded key, octets 32 to 63"},
	"phrasePublicHalf|return":                            {carries: []string{"expanded"}, occurs: []string{"append(...)"}, why: "the PUBLIC half, a copy. The walk cannot tell it from the private key it was cut from; the known answers (TestTheKeysAreTheKnownAnswersForTwoPhrases and TestTheCeremonySignsTheCertificateTheStepAndTheBaseAndNothingAfterIt) hold that it is the public half"},
	"phraseTokensOf|call clear":                          {carries: []string{"reading", "reading.phraseIndices"}, occurs: []string{"reading.phraseIndices[:]"}, why: "ERASED: the reading's indices, once copied out"},
	"phraseTokensOf|call phraseFoldOf":                   {carries: []string{"phraseCharacter"}, occurs: []string{"phraseCharacter"}, why: "each typed code point into its fold"},
	"phraseTokensOf|call reading.take":                   {carries: []string{"phraseCharacter"}, occurs: []string{"phraseFoldOf(...)"}, why: "the fold into the reading"},
	"phraseTokensOf|return":                              {carries: []string{"phraseIndices", "reading"}, occurs: []string{"phraseIndices", "reading.count", "reading.notInTheList"}, why: "the indices, the count and the positions, to ParseRecoveryPhrase, which erases the indices"},
	"sameOctets|call subtle.ConstantTimeCompare":         {carries: []string{"left"}, occurs: []string{"left"}, why: "IRK's public half compared in constant time with the next key"},
	"sameOctets|return":                                  {carries: []string{"left"}, occurs: []string{"?"}, why: "a bool, whether the two keys are one"},
	"signBaseByPhraseKey|assign base.Signature":          {carries: []string{"signature"}, occurs: []string{"signature"}, why: "the base's ISK_g signature, which is public"},
	"signBaseByPhraseKey|call identitySign":              {carries: []string{"isk"}, occurs: []string{"isk"}, why: "ISK_g's private half to the one signer"},
	"signIdentityStep|call append":                       {carries: []string{"oldPublic"}, occurs: []string{"oldPublic"}, why: "IRK's public half, copied into the step"},
	"signIdentityStep|call identitySign":                 {carries: []string{"irk"}, occurs: []string{"irk"}, why: "IRK's private half to the one signer"},
	"signIdentityStep|call sameOctets":                   {carries: []string{"oldPublic"}, occurs: []string{"oldPublic"}, why: "IRK's PUBLIC half, compared with the next key so that no key succeeds itself"},
	"signIdentityStep|literal IdentityStep.OldKey":       {carries: []string{"oldPublic"}, occurs: []string{"append(...)"}, why: "the step's old key: IRK's public half"},
	"signIdentityStep|literal IdentityStep.Signature":    {carries: []string{"signature"}, occurs: []string{"signature"}, why: "the step's signature, which is public"},
	"signIskCert|assign cert.Signature":                  {carries: []string{"signature"}, occurs: []string{"signature"}, why: "the certificate's signature, which is public; the walk follows it because IRK made it"},
	"signIskCert|call encodeIskCertTbs":                  {carries: []string{"cert"}, occurs: []string{"cert"}, why: "the certificate into its tbs"},
	"signIskCert|call identitySign":                      {carries: []string{"irk", "tbs"}, occurs: []string{"irk", "tbs"}, why: "IRK's private half to the one signer, Ed25519 over LP(label) ‖ tbs; ed25519.Sign keeps nothing"},
	"stretchPhrase|call argon2.IDKey":                    {carries: []string{"p34"}, occurs: []string{"p34"}, why: "P34 into Argon2id. Its 256 MiB of working memory is a function of P34 and is not erased by the library: the residual Spec A section 8 states, as LRI R68 has it stated (the words, S, master_key, isk_root and IRK's private half can survive in freed heap, in Argon2id's working memory and in hash and HMAC states)"},
	"stretchPhrase|return":                               {carries: []string{"p34"}, occurs: []string{"argon2.IDKey(...)"}, why: "S, to derivePhraseKeys, which erases it"},
	"take|assign self.typedLetters[self.length]":         {carries: []string{"symbol"}, occurs: []string{"symbol"}, why: "a typed letter into the one buffer a word is gathered in"},
	"withPhraseKeys|call ceremony":                       {carries: []string{"keys"}, occurs: []string{"keys"}, why: "the ceremony's keys, handed to it for the length of this call; erase runs when it returns, whatever it did"},
	"withPhraseKeys|return":                              {carries: []string{"keys"}, occurs: []string{"ceremony(...)"}, why: "the ceremony's error, answered as it is. The walk cannot tell the error from the keys the ceremony was called with"},
	"zeroize|assign secret[i]":                           {carries: []string{"i"}, occurs: []string{"0"}, why: "ERASED: the zero written over each octet of a secret. i is the loop's index, tainted by ranging over the secret; it is a position"},
}

var phraseSecretCountedNotCarriedSites = map[string]string{
	"CheckRecoveryPhraseWord|len notInTheList": "whether the one token read is not on the list",
	"DeriveIdentityKeyed|len self.irk":         "whether IRK is still whole, for the same reason",
	"ParseRecoveryPhrase|len notInTheList":     "whether any word is not on the list",
	"SignIdentityStep|len self.irk":            "whether IRK is still whole, for the same reason",
	"identitySign|len key":                     "whether the key is a whole Ed25519 private key",
	"keyNumberOf|len self.irk":                 "whether IRK is still whole: a call after the ceremony is refused",
	"phrasePublicHalf|len expanded":            "whether the key is a whole Ed25519 private key",
	"sameOctets|len left":                      "the length of a public key, compared before its octets",
	"signIdentityStep|len irk":                 "whether the key handed in is a whole Ed25519 private key",
	"take|len phraseFold":                      "the length of one code point's fold, which the loop runs over",
}

var phraseSecretAccumulatorSites = map[string]string{
	"encodeIskCertTbs|accumulate w.WriteOpaque":               "the certificate's public halves into the syntax writer the tbs is built in; its buffer is the tbs, which is public",
	"encodeIskCertTbs|accumulate w.WriteUint32":               "g into the same writer",
	"identityPreimage|accumulate writer.WriteRaw":             "the tbs into the preimage's writer, which is public",
	"keyScheduleExpand|accumulate keyScheduleCrypto.Expand":   "the key into mls's provider: HMAC-SHA256's state holds it and is not erased, the residual Spec A section 8 states as LRI R68 has it stated",
	"keyScheduleExtract|accumulate keyScheduleCrypto.Extract": "S into mls's provider: the same residual",
	"phraseChecksumOf|accumulate digest.Write":                "P34 written into SHA-256's state. The state is not a byte slice and cannot be erased, the residual primitiveerase_test.go's row for phraseChecksumOf.digest states; what it answers is erased in the same body, and the one octet kept is CS8",
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
	t.Logf("sink sites found (%d), each with THE VALUES IT CARRIES and each OCCURRENCE:", len(census.sinks))
	for _, site := range censusSortedSites(census.sinks) {
		occurs := append([]string(nil), census.occurrences[site]...)
		sort.Strings(occurs)
		t.Logf("    %s  carries %v  occurs [%s]  at %v", site, censusSortedKeys(census.carried[site]),
			strings.Join(occurs, " | "), census.sinks[site])
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
	occursListed := map[string][]string{}
	for site, entry := range phraseSecretSinks {
		occursListed[site] = entry.occurs
	}
	censusHoldOccurrences(t, census.occurrences, occursListed, sinkNarrowing)
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

// ══════════════════════════════════════════════════════════════════════════════════════════════
// THE MUTATION TABLE, MEASURED (LRI R68)
// ══════════════════════════════════════════════════════════════════════════════════════════════
//
// THE REVIEW OF TASKS 8 TO 10 FOUND THIS CENSUS WITH NO MUTATION TABLE, AND ITS MUTANTS WALKED
// THROUGH IT. Each of the reviewers' rows below was reproduced against the engine before R68's fixes
// (the tree at 51815a7b, its working tree clean), and every one but M1b SURVIVED it, this census
// PASS: L1-1a, L1-1b and L1-1c, a secret handed to a function of this package and kept there (L1-1);
// M1, a second copy of P34 in a function that already copied it once (L2-01); M2 and M2b, the typed
// indices kept as a map's key and as a keyed literal's (L2-02); V5a and V5b, the two functions the
// walk did not reach (L2-05). Rows P1 to P8 are sdk/urmessage/pqsecretgate_test.go's eight
// mechanism rows, its M1 to M8, driven at the phrase's secrets; each was KILLED before R68 too.
//
// Applied one at a time to an overlay worktree of the tree this table lands in, by exact
// replacements each asserted to occur once, and run as `go test ./messagegroup/ -count=1 -v -run
// TestEveryPhraseSecretInThisPackageGoesWhereTheDispositionSaysItGoes`; the clean overlay, the
// control, passed. A SURVIVING MUTANT IS FIRST A CLAIM ABOUT THE QUERY, so each row names the failure
// text it produced, and the one that survives says what kills it instead.
//
//	L1-1a THE WALK INTO A CALLEE: keyScheduleExtract keeps a copy of its ikm, S, in a package
//	      variable. Before R68 the walk never followed S into keyScheduleExtract.
//	      -> sink site "keyScheduleExtract|assign censusKeptIkm" has no entry in the disposition
//	      -> AND sink site "keyScheduleExtract|call append" has no entry
//	L1-1b the same at keyScheduleExpand, keeping every expansion it answers: isk_root, IRK's seed,
//	      isk_seed[g] and D2 IL8's derived seed
//	      -> sink site "keyScheduleExpand|assign censusKeptExpand" has no entry
//	      -> AND "keyScheduleExpand|call append" has no entry
//	      -> AND "keyScheduleExpand|return" occurs as ["out"] where its disposition lists
//	         ["keyScheduleCrypto.Expand(...)"], carries "out", which its entry does not list, and
//	         no longer carries "prk" -- three clauses, independently
//	L1-1c zeroize keeps a copy of every secret it is handed, before it blanks it
//	      -> sink site "zeroize|call append" has no entry
//	      -> AND "zeroize|assign censusKeptZeroized" has no entry
//	M1    THE OCCURRENCE: `copy(phraseLastMade[:], phrase.p34[:])`, a second copy of P34 into package
//	      storage, in NewRecoveryPhrase, which already copies P34 once at the same callee. The site's
//	      key and its carried set do not move, so before R68 nothing did:
//	      -> sink site "NewRecoveryPhrase|call copy" occurs as ["phrase.p34[:]" "phrase.p34[:]"
//	         "phraseDrawn"] and its disposition lists ["phrase.p34[:]" "phraseDrawn"] -- the
//	         occurrence clause, and it alone
//	M1b   isk_seed[g] appended to a package slice in PhraseKeySeed
//	      -> sink site "PhraseKeySeed|assign phraseSeedsSeen" has no entry
//	      -> AND "PhraseKeySeed|call append" occurs as a third value and carries "phraseSeedsSeen",
//	         which its entry does not list
//	M2    THE MAP KEY: each listed word's index kept as a map's key, `phraseIndicesTyped[phraseIndex]
//	      = true`. Before R68 a map's key was not a carried value.
//	      -> sink site "end|assign phraseIndicesTyped[phraseIndex]" has no entry
//	M2b   the same index as a keyed literal's key, `map[uint16]bool{phraseIndex: true}`, appended to a
//	      package slice
//	      -> sink site "end|assign phraseIndexSets" has no entry
//	      -> AND "end|call append" has no entry, AND "end|literal ?.phraseIndex" has no entry
//	V5a   phraseFoldOf, WALKED: each typed code point kept in a package slice
//	      -> sink site "phraseFoldOf|assign phraseFoldTyped" has no entry
//	      -> AND "phraseFoldOf|call append" has no entry
//	V5b   phrasePublicHalf answers the SEED for the public half, `expanded[:32]` for `expanded[32:]`.
//	      THIS CENSUS SURVIVES IT, BY DESIGN: a slice is spelled `X[:]` whatever its bounds, and the
//	      same value reaches the same sinks. What kills it is the known answers, the whole package
//	      FAIL: TestTheKeysAreTheKnownAnswersForTwoPhrases,
//	      TestEveryKeyNumbersSeedIsTheKnownAnswerAndNoneIsTheRoot,
//	      TestTheCeremonySignsTheCertificateTheStepAndTheBaseAndNothingAfterIt and
//	      TestWhatTheCeremonySignsBindsAndVerifies.
//	P1    THE FINDING'S OWN SHAPE (pq M1): the 25 indices formatted in ParseRecoveryPhrase's word
//	      count refusal
//	      -> sink site "ParseRecoveryPhrase|call fmt.Errorf" occurs as ["count" "notInTheList"
//	         "phraseIndices"] and lists ["count" "notInTheList"]
//	      -> AND it carries "phraseIndices", which its entry does not list, AND
//	         "ParseRecoveryPhrase|return" the same
//	P2    THE VALUE WITH NO NAME OF ITS OWN (pq M2): `%x` of `self.typedLetters[:self.length]` in a
//	      panic inside end
//	      -> sink site "end|call fmt.Errorf" has no entry, AND "end|call panic" has no entry
//	P3    THE NARROWING AS A PERMIT (pq M3): `len(irk)` -> `irk` in signIdentityStep's key refusal
//	      -> sink site "signIdentityStep|call fmt.Errorf" has no entry
//	      -> AND "signIdentityStep|return" has no entry
//	P4    THE SPELLING (pq M4): `self.numbers[0].isk[:]` added to keyNumberOf's refusal, a slice of
//	      an index of a field
//	      -> producer site "keyNumberOf|self.numbers.isk" has no entry
//	      -> AND sink sites "keyNumberOf|call fmt.Errorf" and "keyNumberOf|return" have no entry
//	P5    THE BINDING FORM (pq M5): `var parked = derivedSeed` in DeriveIdentityKeyed, kept in a
//	      package variable
//	      -> sink site "DeriveIdentityKeyed|assign phraseParkedSeed" has no entry
//	P6    A CHANGE OF MECHANISM RATHER THAN AN ATTACK (pq M6): the draw moved behind `drawPhrase()`.
//	      Every direction fires at once, which is the census reporting that it has gone blind:
//	      -> producer site "drawPhrase|phraseDraw.Random" has no entry
//	      -> AND producer site "NewRecoveryPhrase|phraseDraw.Random" is allowed and not found
//	      -> AND sink site "drawPhrase|return" has no entry, "NewRecoveryPhrase|call zeroize" is
//	         allowed and not found, and "NewRecoveryPhrase|call copy" occurs as ["phrase.p34[:]"],
//	         its "phraseDrawn" no longer arriving
//	P7    THE COUNTED CENSUS'S SECOND DIRECTION (pq M7): `_ = len(self.irk[:ed25519.SeedSize])` in
//	      SignIdentityStep, which counts nothing today
//	      -> counted-not-carried site "SignIdentityStep|len self.irk[:]" has no entry
//	P8    THE CARRIES LIST (pq M8): the word count refusal's `%d` of count changed to `%x` of
//	      phraseTyped. The site is dispositioned, so a census keyed on sites alone passes it
//	      -> sink site "ParseRecoveryPhrase|call fmt.Errorf" occurs as ["notInTheList" "phraseTyped"]
//	         and lists ["count" "notInTheList"]
//	      -> AND it carries "phraseTyped", which its entry does not list, and "count" no longer
//	         arrives; AND "ParseRecoveryPhrase|return" the same two
